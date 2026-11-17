package model

import (
	"context"
	"time"
)

// DNSHostedZone is a zone the built-in authoritative DNS server serves.
// Records hold every published and administrator-added record; the server
// synthesizes the apex SOA, NS, and DNSKEY records. Serial is the SOA serial,
// bumped on every change. Keys are the zone's DNSSEC signing keys with
// sealed private halves.
type DNSHostedZone struct {
	Zone      string            `json:"zone"`
	Serial    uint32            `json:"serial"`
	Records   []DNSHostedRecord `json:"records,omitempty"`
	Keys      []DNSSECKey       `json:"keys,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// DNSHostedRecord is one resource record in presentation form (see
// dnsprovider.Record). ID is stable across value updates.
type DNSHostedRecord struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// DNSSECKey is an ECDSA P-256 combined signing key. PublicKey is the DNSKEY
// public key field; SealedPrivate is the sealed PKCS#8 private key. The
// active key signs; a standby key is published ahead of a manual rollover.
type DNSSECKey struct {
	ID            string    `json:"id"`
	PublicKey     string    `json:"public_key"`
	SealedPrivate []byte    `json:"sealed_private"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"created_at"`
}

// DNSHostedZoneStore persists built-in DNS zones keyed by zone apex.
type DNSHostedZoneStore struct{ zones collection[DNSHostedZone] }

// NewDNSHostedZoneStore creates a hosted zone store.
func NewDNSHostedZoneStore(ts *TypedStore) *DNSHostedZoneStore {
	return &DNSHostedZoneStore{zones: newCollection[DNSHostedZone](ts, NSDNSHostedZones)}
}

// List returns every hosted zone in apex order.
func (s *DNSHostedZoneStore) List(ctx context.Context) ([]DNSHostedZone, error) {
	return s.zones.list(ctx)
}

// Set creates or replaces a hosted zone.
func (s *DNSHostedZoneStore) Set(ctx context.Context, zone DNSHostedZone) error {
	return s.zones.set(ctx, zone.Zone, zone)
}

// Delete removes a hosted zone.
func (s *DNSHostedZoneStore) Delete(ctx context.Context, apex string) error {
	return s.zones.delete(ctx, apex)
}
