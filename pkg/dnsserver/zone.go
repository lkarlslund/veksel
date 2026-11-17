package dnsserver

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/miekg/dns"
)

// SOA timers of every hosted zone. negativeTTL also bounds the TTL of
// denial responses (RFC 2308).
const (
	soaRefresh  = 3600
	soaRetry    = 900
	soaExpire   = 1209600
	negativeTTL = 300
	apexTTL     = 3600
)

// typeNXNAME marks a compact denial NSEC record as proving that the name
// does not exist (RFC 9824).
const typeNXNAME = 128

// snapshot is the compiled answer data for one generation of the hosted
// zones and one set of server settings.
type snapshot struct {
	generation uint64
	settings   *Settings
	fallback   string
	zones      map[string]*zone // by lower-case FQDN apex
}

// zone is one compiled hosted zone.
type zone struct {
	apex string
	soa  *dns.SOA
	// nodes maps every owner name, including empty non-terminals, to its
	// RRsets by type.
	nodes  map[string]map[uint16][]dns.RR
	signer *dnsprovider.SigningKey // nil when unsigned
	err    error                   // a zone that cannot be signed answers SERVFAIL
	sigMu  sync.Mutex
	sigs   map[string]cachedSig
}

type cachedSig struct {
	sig     *dns.RRSIG
	refresh time.Time
}

// current returns the snapshot for the live settings, default nameserver,
// and zone generation, compiling a new one when any changed.
func (s *Server) current() *snapshot {
	settings, fallback, generation := s.settings.Load(), s.defaultNameserver(), s.hosted.Generation()
	fresh := func(snap *snapshot) bool {
		return snap != nil && snap.settings == settings && snap.fallback == fallback && snap.generation == generation
	}
	if snap := s.snap.Load(); fresh(snap) {
		return snap
	}
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if snap := s.snap.Load(); fresh(snap) {
		return snap
	}
	snap := &snapshot{generation: generation, settings: settings, fallback: fallback, zones: map[string]*zone{}}
	for _, hosted := range s.hosted.Zones() {
		apex := dns.Fqdn(dnsprovider.NormalizeName(hosted.Zone))
		servers := nameservers(settings.Nameservers, fallback)
		if len(servers) == 0 {
			servers = []string{"ns1." + apex}
		}
		z := compileZone(hosted, servers)
		if settings.DNSSEC {
			z.sign(s.hosted, hosted)
		}
		snap.zones[z.apex] = z
	}
	s.snap.Store(snap)
	return snap
}

func (s *Server) defaultNameserver() string {
	if s.DefaultNameserver == nil {
		return ""
	}
	return s.DefaultNameserver()
}

// nameservers returns the configured NS names as FQDNs, or the fallback
// name when none are configured.
func nameservers(configured []string, fallback string) []string {
	var out []string
	for _, name := range configured {
		if name = dnsprovider.NormalizeName(name); name != "" {
			out = append(out, dns.Fqdn(name))
		}
	}
	if fallback = dnsprovider.NormalizeName(fallback); len(out) == 0 && strings.Contains(fallback, ".") {
		out = []string{dns.Fqdn(fallback)}
	}
	return out
}

// compileZone builds a zone's answer data with servers as its NS names.
func compileZone(hosted model.DNSHostedZone, servers []string) *zone {
	apex := dns.Fqdn(dnsprovider.NormalizeName(hosted.Zone))
	z := &zone{apex: apex, nodes: map[string]map[uint16][]dns.RR{}, sigs: map[string]cachedSig{}}
	z.soa = &dns.SOA{Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: apexTTL},
		Ns: servers[0], Mbox: "hostmaster." + apex, Serial: hosted.Serial, Refresh: soaRefresh, Retry: soaRetry, Expire: soaExpire, Minttl: negativeTTL}
	z.addRR(z.soa)
	for _, server := range servers {
		z.addRR(&dns.NS{Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: apexTTL}, Ns: server})
	}
	for _, rec := range hosted.Records {
		rr, err := dnsprovider.RecordRR(dnsprovider.Record{Type: rec.Type, Name: rec.Name, Value: rec.Value, TTL: rec.TTL})
		if err != nil {
			log.Warn("dns: skipping invalid stored record", "zone", hosted.Zone, "name", rec.Name, "type", rec.Type, "error", err)
			continue
		}
		z.addRR(rr)
	}
	return z
}

// addRR adds rr and the empty non-terminals between its owner and the apex.
func (z *zone) addRR(rr dns.RR) {
	h := rr.Header()
	h.Name = strings.ToLower(h.Name)
	node := z.node(h.Name)
	node[h.Rrtype] = append(node[h.Rrtype], rr)
	for name := h.Name; name != z.apex; {
		next, end := dns.NextLabel(name, 0)
		if end {
			break
		}
		name = name[next:]
		z.node(name)
	}
}

func (z *zone) node(name string) map[uint16][]dns.RR {
	node, ok := z.nodes[name]
	if !ok {
		node = map[uint16][]dns.RR{}
		z.nodes[name] = node
	}
	return node
}

// sign publishes the zone's DNSKEY RRset and selects the active key.
func (z *zone) sign(hosted *dnsprovider.Hosted, stored model.DNSHostedZone) {
	keys, err := hosted.SigningKeys(stored)
	if err == nil && !slices.ContainsFunc(keys, func(k dnsprovider.SigningKey) bool { return k.Active }) {
		err = fmt.Errorf("zone %s has no active DNSSEC key", stored.Zone)
	}
	if err != nil {
		log.Error("dns: zone cannot be signed", "zone", stored.Zone, "error", err)
		z.err = err
		return
	}
	for i := range keys {
		z.addRR(keys[i].DNSKEY)
		if keys[i].Active {
			z.signer = &keys[i]
		}
	}
}

// signatureValidity is how long an online signature is valid; signatures
// are refreshed after half of it.
const signatureValidity = 7 * 24 * time.Hour

// rrsig returns the signature of rrset, signing it on first use.
func (z *zone) rrsig(rrset []dns.RR) dns.RR {
	h := rrset[0].Header()
	key := fmt.Sprintf("%s/%d/%d", h.Name, h.Rrtype, h.Ttl)
	now := time.Now()
	z.sigMu.Lock()
	cached, ok := z.sigs[key]
	z.sigMu.Unlock()
	if ok && now.Before(cached.refresh) {
		return cached.sig
	}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl}, Algorithm: dns.ECDSAP256SHA256,
		KeyTag: z.signer.DNSKEY.KeyTag(), SignerName: z.apex,
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(signatureValidity).Unix())}
	if err := sig.Sign(z.signer.Signer, rrset); err != nil {
		log.Error("dns: signing failed", "zone", z.apex, "name", h.Name, "error", err)
		return nil
	}
	z.sigMu.Lock()
	if len(z.sigs) >= maxCachedSignatures {
		// Random names make distinct denial records; bound the cache.
		z.sigs = map[string]cachedSig{}
	}
	z.sigs[key] = cachedSig{sig: sig, refresh: now.Add(signatureValidity / 2)}
	z.sigMu.Unlock()
	return sig
}

const maxCachedSignatures = 20000

// records returns every record of the zone for a transfer, SOA first.
func (z *zone) records() []dns.RR {
	names := make([]string, 0, len(z.nodes))
	for name := range z.nodes {
		names = append(names, name)
	}
	slices.Sort(names)
	out := []dns.RR{z.soa}
	for _, name := range names {
		types := make([]uint16, 0, len(z.nodes[name]))
		for rtype := range z.nodes[name] {
			if rtype != dns.TypeSOA {
				types = append(types, rtype)
			}
		}
		slices.Sort(types)
		for _, rtype := range types {
			out = append(out, z.nodes[name][rtype]...)
		}
	}
	return out
}
