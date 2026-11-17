package dnsprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/miekg/dns"
)

// KindBuiltin serves a zone from Veksel' own authoritative DNS server
// (pkg/dnsserver); its records live in the system store.
const KindBuiltin = "builtin"

// dnssecPurpose binds sealed DNSSEC private keys to this subsystem.
const dnssecPurpose = "dns-dnssec"

// ErrNotHosted reports that the built-in DNS server does not serve a zone.
var ErrNotHosted = errors.New("the zone is not served by the built-in DNS server")

// builtinTypes are the record types the built-in server stores. The apex
// SOA, NS, and DNSKEY records are synthesized and never stored.
var builtinTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true, "CAA": true}

// Hosted owns the zones the built-in DNS server serves: their records, SOA
// serials, and DNSSEC keys. It keeps every zone in memory; Generation
// changes after each write so the server can rebuild its answers.
type Hosted struct {
	store  *model.DNSHostedZoneStore
	sealer Sealer
	mu     sync.Mutex // serializes writes
	zones  atomic.Pointer[map[string]model.DNSHostedZone]
	gen    atomic.Uint64
}

func newHosted(ctx context.Context, ts *model.TypedStore, sealer Sealer) (*Hosted, error) {
	if err := ts.EnsureNamespace(ctx, model.NSDNSHostedZones); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, fmt.Errorf("initialize hosted DNS zones: %w", err)
	}
	h := &Hosted{store: model.NewDNSHostedZoneStore(ts), sealer: sealer}
	zones, err := h.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("load hosted DNS zones: %w", err)
	}
	loaded := make(map[string]model.DNSHostedZone, len(zones))
	for _, zone := range zones {
		loaded[zone.Zone] = zone
	}
	h.zones.Store(&loaded)
	return h, nil
}

// Generation identifies the current zone contents.
func (h *Hosted) Generation() uint64 { return h.gen.Load() }

// Zones returns every hosted zone. Callers must not modify the result.
func (h *Hosted) Zones() []model.DNSHostedZone {
	zones := *h.zones.Load()
	out := make([]model.DNSHostedZone, 0, len(zones))
	for _, zone := range zones {
		out = append(out, zone)
	}
	slices.SortFunc(out, func(a, b model.DNSHostedZone) int { return strings.Compare(a.Zone, b.Zone) })
	return out
}

// Zone returns one hosted zone. Callers must not modify the result.
func (h *Hosted) Zone(apex string) (model.DNSHostedZone, bool) {
	zone, ok := (*h.zones.Load())[NormalizeName(apex)]
	return zone, ok
}

// write replaces (or, with a nil zone, removes) one zone in the store and
// in memory. h.mu must be held.
func (h *Hosted) write(ctx context.Context, apex string, zone *model.DNSHostedZone) error {
	next := make(map[string]model.DNSHostedZone, len(*h.zones.Load())+1)
	for key, value := range *h.zones.Load() {
		next[key] = value
	}
	if zone == nil {
		if err := h.store.Delete(ctx, apex); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		delete(next, apex)
	} else {
		if err := h.store.Set(ctx, *zone); err != nil {
			return err
		}
		next[apex] = *zone
	}
	h.zones.Store(&next)
	h.gen.Add(1)
	return nil
}

// update applies change to a copy of a hosted zone, bumps its SOA serial,
// and stores it.
func (h *Hosted) update(ctx context.Context, apex string, change func(*model.DNSHostedZone) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	zone, ok := (*h.zones.Load())[apex]
	if !ok {
		return ErrNotHosted
	}
	zone.Records, zone.Keys = slices.Clone(zone.Records), slices.Clone(zone.Keys)
	if err := change(&zone); err != nil {
		return err
	}
	now := time.Now().UTC()
	zone.Serial, zone.UpdatedAt = nextSerial(zone.Serial, now), now
	return h.write(ctx, apex, &zone)
}

// nextSerial increments serial, moving it to the date-based YYYYMMDDnn form
// when that is larger.
func nextSerial(serial uint32, now time.Time) uint32 {
	dated := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)
	return max(serial+1, dated)
}

// ensure starts hosting apex with a fresh DNSSEC key; an existing zone is
// kept unchanged.
func (h *Hosted) ensure(ctx context.Context, apex string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := (*h.zones.Load())[apex]; ok {
		return nil
	}
	key, err := h.generateKey(apex, true)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	zone := model.DNSHostedZone{Zone: apex, Serial: nextSerial(0, now), Keys: []model.DNSSECKey{key}, UpdatedAt: now}
	return h.write(ctx, apex, &zone)
}

// remove stops hosting apex and discards its records and keys.
func (h *Hosted) remove(ctx context.Context, apex string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.write(ctx, apex, nil)
}

func randomID() string {
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

// validateBuiltin checks rec for the built-in server and returns it with
// canonical presentation data and TTL.
func validateBuiltin(zone model.DNSHostedZone, rec Record) (Record, error) {
	rec.Type, rec.Name = strings.ToUpper(strings.TrimSpace(rec.Type)), NormalizeName(rec.Name)
	if !builtinTypes[rec.Type] {
		return rec, fmt.Errorf("unsupported record type %q; use A, AAAA, CNAME, MX, TXT, SRV, or CAA", rec.Type)
	}
	if !InZone(rec.Name, zone.Zone) {
		return rec, fmt.Errorf("record %s is outside zone %s", rec.Name, zone.Zone)
	}
	if _, ok := dns.IsDomainName(rec.Name); !ok {
		return rec, fmt.Errorf("invalid record name %q", rec.Name)
	}
	if strings.TrimSpace(rec.Value) == "" {
		return rec, errors.New("record value is required")
	}
	if rec.TTL < 0 || rec.TTL > 604800 {
		return rec, errors.New("TTL must be between 0 and 604800 seconds")
	}
	rec.TTL = ttlOrDefault(rec.TTL)
	rr, err := RecordRR(rec)
	if err != nil {
		return rec, err
	}
	rec.Value = rrValue(rr)
	if rec.Type == "CNAME" && rec.Name == zone.Zone {
		return rec, errors.New("a CNAME record cannot be placed at the zone apex")
	}
	for _, other := range zone.Records {
		if other.Name != rec.Name || other.ID == rec.ID {
			continue
		}
		if rec.Type == "CNAME" || other.Type == "CNAME" {
			return rec, fmt.Errorf("%s already has a %s record; a CNAME cannot share its name with other records", rec.Name, other.Type)
		}
	}
	return rec, nil
}

func (h *Hosted) list(apex, name, rtype string) []Record {
	zone, _ := h.Zone(apex)
	var out []Record
	for _, rec := range zone.Records {
		if rec.Name == NormalizeName(name) && strings.EqualFold(rec.Type, rtype) {
			out = append(out, Record{ID: rec.ID, Type: rec.Type, Name: rec.Name, Value: rec.Value, TTL: rec.TTL})
		}
	}
	return out
}

// upsert adds rec, or replaces the record rec.ID names, and returns the
// stored record.
func (h *Hosted) upsert(ctx context.Context, apex string, rec Record) (Record, error) {
	var stored Record
	err := h.update(ctx, apex, func(zone *model.DNSHostedZone) error {
		index := slices.IndexFunc(zone.Records, func(r model.DNSHostedRecord) bool { return rec.ID != "" && r.ID == rec.ID })
		if rec.ID != "" && index < 0 {
			return fmt.Errorf("record %s: %w", rec.ID, store.ErrNotFound)
		}
		valid, err := validateBuiltin(*zone, rec)
		if err != nil {
			return err
		}
		if index < 0 {
			valid.ID = randomID()
			zone.Records = append(zone.Records, model.DNSHostedRecord{})
			index = len(zone.Records) - 1
		}
		zone.Records[index] = model.DNSHostedRecord{ID: valid.ID, Type: valid.Type, Name: valid.Name, Value: valid.Value, TTL: valid.TTL}
		stored = valid
		return nil
	})
	return stored, err
}

// delete removes the record rec.ID names, or the one matching rec's type,
// name, and value.
func (h *Hosted) delete(ctx context.Context, apex string, rec Record) error {
	return h.update(ctx, apex, func(zone *model.DNSHostedZone) error {
		index := slices.IndexFunc(zone.Records, func(r model.DNSHostedRecord) bool {
			if rec.ID != "" {
				return r.ID == rec.ID
			}
			return strings.EqualFold(r.Type, rec.Type) && r.Name == NormalizeName(rec.Name) && SameValue(r.Type, r.Value, rec.Value)
		})
		if index < 0 {
			return fmt.Errorf("record: %w", store.ErrNotFound)
		}
		zone.Records = slices.Delete(zone.Records, index, index+1)
		return nil
	})
}

// Builtin is the Provider for a zone the built-in DNS server serves.
type Builtin struct {
	hosted *Hosted
	zone   string
}

// ListRecords returns the stored records of one type at one name.
func (b *Builtin) ListRecords(_ context.Context, name, rtype string) ([]Record, error) {
	if _, ok := b.hosted.Zone(b.zone); !ok {
		return nil, ErrNotHosted
	}
	return b.hosted.list(b.zone, name, rtype), nil
}

// UpsertRecord creates rec or replaces the record rec.ID names.
func (b *Builtin) UpsertRecord(ctx context.Context, rec Record) error {
	_, err := b.hosted.upsert(ctx, b.zone, rec)
	return err
}

// DeleteRecord removes one record.
func (b *Builtin) DeleteRecord(ctx context.Context, rec Record) error {
	return b.hosted.delete(ctx, b.zone, rec)
}

// DNSSEC keys.

// DNSKEYOf returns the DNSKEY record of a stored key: a combined signing
// key (flags 257) using ECDSA P-256 with SHA-256.
func DNSKEYOf(apex string, key model.DNSSECKey) *dns.DNSKEY {
	return &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(NormalizeName(apex)), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: DefaultTTL},
		Flags: dns.ZONE | dns.SEP, Protocol: 3, Algorithm: dns.ECDSAP256SHA256, PublicKey: key.PublicKey}
}

func (h *Hosted) generateKey(apex string, active bool) (model.DNSSECKey, error) {
	dnskey := DNSKEYOf(apex, model.DNSSECKey{})
	private, err := dnskey.Generate(256)
	if err != nil {
		return model.DNSSECKey{}, fmt.Errorf("generate DNSSEC key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return model.DNSSECKey{}, fmt.Errorf("encode DNSSEC key: %w", err)
	}
	id := randomID()
	sealed, err := h.sealer.SealSecret(dnssecPurpose, apex+"/"+id, der)
	if err != nil {
		return model.DNSSECKey{}, fmt.Errorf("protect DNSSEC key: %w", err)
	}
	return model.DNSSECKey{ID: id, PublicKey: dnskey.PublicKey, SealedPrivate: sealed, Active: active, CreatedAt: time.Now().UTC()}, nil
}

// SigningKey is an opened DNSSEC key.
type SigningKey struct {
	DNSKEY *dns.DNSKEY
	Signer crypto.Signer
	Active bool
}

// SigningKeys opens zone's DNSSEC keys.
func (h *Hosted) SigningKeys(zone model.DNSHostedZone) ([]SigningKey, error) {
	keys := make([]SigningKey, 0, len(zone.Keys))
	for _, key := range zone.Keys {
		der, err := h.sealer.OpenSecret(dnssecPurpose, zone.Zone+"/"+key.ID, key.SealedPrivate)
		if err != nil {
			return nil, fmt.Errorf("open DNSSEC key for %s: %w", zone.Zone, err)
		}
		private, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("decode DNSSEC key for %s: %w", zone.Zone, err)
		}
		signer, ok := private.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("DNSSEC key for %s cannot sign", zone.Zone)
		}
		keys = append(keys, SigningKey{DNSKEY: DNSKEYOf(zone.Zone, key), Signer: signer, Active: key.Active})
	}
	return keys, nil
}

// rollKey performs one manual rollover step: without a standby key it
// publishes a new standby key next to the active one ("staged"); with one
// it makes the standby key sign and removes the old key ("activated").
func (h *Hosted) rollKey(ctx context.Context, apex string) (string, error) {
	step := ""
	err := h.update(ctx, apex, func(zone *model.DNSHostedZone) error {
		if standby := slices.IndexFunc(zone.Keys, func(k model.DNSSECKey) bool { return !k.Active }); standby >= 0 {
			promoted := zone.Keys[standby]
			promoted.Active = true
			zone.Keys, step = []model.DNSSECKey{promoted}, "activated"
			return nil
		}
		first := len(zone.Keys) == 0
		key, err := h.generateKey(apex, first)
		if err != nil {
			return err
		}
		zone.Keys, step = append(zone.Keys, key), "staged"
		if first {
			step = "activated"
		}
		return nil
	})
	return step, err
}
