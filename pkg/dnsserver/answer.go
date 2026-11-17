package dnsserver

import (
	"net"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/miekg/dns"
)

// maxUDPSize is the largest UDP response sent, the DNS flag day 2020 value
// that avoids IP fragmentation.
const maxUDPSize = 1232

// maxCNAMEChain bounds CNAME chasing within a zone.
const maxCNAMEChain = 8

// ServeDNS answers one query.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	_, udp := w.RemoteAddr().(*net.UDPAddr)
	if len(r.Question) == 1 && r.Opcode == dns.OpcodeQuery && (r.Question[0].Qtype == dns.TypeAXFR || r.Question[0].Qtype == dns.TypeIXFR) {
		s.transfer(w, r, udp)
		return
	}
	reply := s.answer(r)
	if udp && s.RateLimit >= 0 {
		switch s.limiter().decide(w.RemoteAddr(), time.Now()) {
		case rrlDrop:
			return
		case rrlSlip:
			// A truncated empty reply sends legitimate clients to TCP,
			// which is never rate limited and cannot be spoofed.
			reply = new(dns.Msg)
			reply.SetReply(r)
			reply.Authoritative, reply.Truncated = true, true
		}
	}
	fit(reply, r, udp)
	if err := w.WriteMsg(reply); err != nil {
		log.Debug("dns: write failed", "error", err)
	}
}

// fit adds the EDNS(0) OPT record when the query had one and truncates the
// reply to the client's UDP payload size (512 bytes without EDNS).
func fit(reply, query *dns.Msg, udp bool) {
	size := dns.MaxMsgSize
	if opt := query.IsEdns0(); opt != nil {
		if reply.IsEdns0() == nil {
			reply.SetEdns0(maxUDPSize, opt.Do())
		}
		if udp {
			size = min(max(int(opt.UDPSize()), dns.MinMsgSize), maxUDPSize)
		}
	} else if udp {
		size = dns.MinMsgSize
	}
	reply.Truncate(size)
}

// answer builds the reply to a query: REFUSED for names outside the hosted
// zones (the server never recurses), authoritative data otherwise.
func (s *Server) answer(r *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.RecursionAvailable = false
	if r.Opcode != dns.OpcodeQuery {
		reply.SetRcode(r, dns.RcodeNotImplemented)
		return reply
	}
	if len(r.Question) != 1 {
		reply.SetRcode(r, dns.RcodeFormatError)
		return reply
	}
	opt := r.IsEdns0()
	if opt != nil && opt.Version() != 0 {
		reply.SetEdns0(maxUDPSize, opt.Do())
		reply.Rcode = dns.RcodeBadVers
		return reply
	}
	q := r.Question[0]
	z := s.current().find(q.Name)
	if q.Qclass != dns.ClassINET || z == nil {
		reply.SetRcode(r, dns.RcodeRefused)
		return reply
	}
	if z.err != nil {
		reply.SetRcode(r, dns.RcodeServerFailure)
		return reply
	}
	reply.Authoritative = true
	z.resolve(reply, q, opt != nil && opt.Do() && z.signer != nil)
	return reply
}

// find returns the zone with the longest apex containing name.
func (snap *snapshot) find(name string) *zone {
	name = strings.ToLower(dns.Fqdn(name))
	for {
		if z, ok := snap.zones[name]; ok {
			return z
		}
		next, end := dns.NextLabel(name, 0)
		if end {
			return nil
		}
		name = name[next:]
	}
}

// resolve fills reply for q. dnssec adds signatures and compact denial.
func (z *zone) resolve(reply *dns.Msg, q dns.Question, dnssec bool) {
	name := strings.ToLower(q.Name)
	for hop := 0; ; hop++ {
		node, exists := z.nodes[name]
		if !exists {
			z.deny(reply, name, nil, dnssec)
			return
		}
		if q.Qtype == dns.TypeANY {
			// RFC 8482: answer ANY with one small synthesized RRset.
			if len(node) == 0 {
				z.deny(reply, name, node, dnssec)
				return
			}
			z.add(&reply.Answer, []dns.RR{&dns.HINFO{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: apexTTL}, Cpu: "RFC8482"}}, dnssec)
			return
		}
		if rrset := node[q.Qtype]; len(rrset) > 0 {
			z.add(&reply.Answer, rrset, dnssec)
			if q.Qtype == dns.TypeNS {
				z.glue(reply, rrset, dnssec)
			}
			return
		}
		if cname := node[dns.TypeCNAME]; len(cname) > 0 {
			z.add(&reply.Answer, cname, dnssec)
			target := strings.ToLower(cname[0].(*dns.CNAME).Target)
			if hop+1 >= maxCNAMEChain || !dns.IsSubDomain(z.apex, target) {
				return
			}
			name = target
			continue
		}
		z.deny(reply, name, node, dnssec)
		return
	}
}

// add appends rrset to section with its signature when signing.
func (z *zone) add(section *[]dns.RR, rrset []dns.RR, dnssec bool) {
	*section = append(*section, rrset...)
	if dnssec {
		if sig := z.rrsig(rrset); sig != nil {
			*section = append(*section, sig)
		}
	}
}

// glue adds the in-zone addresses of nameservers.
func (z *zone) glue(reply *dns.Msg, servers []dns.RR, dnssec bool) {
	for _, rr := range servers {
		target := strings.ToLower(rr.(*dns.NS).Ns)
		for _, rtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if rrset := z.nodes[target][rtype]; len(rrset) > 0 {
				z.add(&reply.Extra, rrset, dnssec)
			}
		}
	}
}

// deny answers a name that does not exist (node is nil) or has no data of
// the queried type with the SOA in the authority section (RFC 2308).
// Signed answers use compact denial of existence (RFC 9824): a NOERROR reply
// with one online-signed NSEC record at the name whose next name is its
// immediate successor, listing the types present, or NXNAME for a
// nonexistent name.
func (z *zone) deny(reply *dns.Msg, name string, node map[uint16][]dns.RR, dnssec bool) {
	soa := *z.soa
	soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
	z.add(&reply.Ns, []dns.RR{&soa}, dnssec)
	if !dnssec {
		if node == nil {
			reply.Rcode = dns.RcodeNameError
		}
		return
	}
	types := []uint16{dns.TypeRRSIG, dns.TypeNSEC}
	if node == nil {
		types = append(types, typeNXNAME)
	}
	for rtype := range node {
		types = append(types, rtype)
	}
	slices.Sort(types)
	next := "\\000." + name
	if len(name)+2 > 255 {
		next = name
	}
	z.add(&reply.Ns, []dns.RR{&dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: soa.Hdr.Ttl}, NextDomain: next, TypeBitMap: types}}, dnssec)
}

// transfer answers AXFR and IXFR (always as a full transfer) over TCP for
// clients presenting the configured TSIG key. Transfers are refused when no
// key is configured, without a valid signature, over UDP, and while DNSSEC
// is enabled, since online signing leaves no NSEC chain to transfer.
func (s *Server) transfer(w dns.ResponseWriter, r *dns.Msg, udp bool) {
	reply := new(dns.Msg)
	refuse := func(rcode int) {
		reply.SetRcode(r, rcode)
		if err := w.WriteMsg(reply); err != nil {
			log.Debug("dns: write failed", "error", err)
		}
	}
	settings := s.settings.Load()
	if udp || settings.AXFR == nil || r.IsTsig() == nil || settings.DNSSEC {
		refuse(dns.RcodeRefused)
		return
	}
	if err := w.TsigStatus(); err != nil {
		log.Warn("dns: zone transfer with an invalid TSIG signature", "client", w.RemoteAddr().String(), "error", err)
		refuse(dns.RcodeNotAuth)
		return
	}
	z := s.current().zones[strings.ToLower(dns.Fqdn(r.Question[0].Name))]
	if z == nil {
		refuse(dns.RcodeNotAuth)
		return
	}
	records := append(z.records(), z.soa)
	envelopes := make(chan *dns.Envelope)
	go func() {
		defer close(envelopes)
		for chunk := range slices.Chunk(records, 100) {
			envelopes <- &dns.Envelope{RR: chunk}
		}
	}()
	if err := new(dns.Transfer).Out(w, r, envelopes); err != nil {
		log.Warn("dns: zone transfer failed", "zone", z.apex, "error", err)
		for range envelopes {
		}
		return
	}
	log.Info("dns: zone transferred", "zone", z.apex, "client", w.RemoteAddr().String())
}
