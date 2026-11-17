package model

import (
	"context"
	"time"
)

// DNSZone binds a DNS zone apex to a provider connector. Settings hold only
// non-secret connector parameters; the credential is sealed with the
// installation's stored-credential keys and is never projected. Owned lists
// the records Veksel created, which are the only records it changes or
// removes without an administrator's explicit confirmation.
type DNSZone struct {
	Zone         string            `json:"zone"`
	Provider     string            `json:"provider"`
	Settings     map[string]string `json:"settings,omitempty"`
	SealedSecret []byte            `json:"sealed_secret,omitempty"`
	Owned        []DNSOwnedRecord  `json:"owned,omitempty"`
	UpdatedAt    time.Time         `json:"updated_at"`

	// Outcome of the most recent provider change, for health and the UI.
	LastSuccessAt time.Time `json:"last_success_at,omitzero"`
	LastFailureAt time.Time `json:"last_failure_at,omitzero"`
	LastFailure   string    `json:"last_failure,omitempty"`
}

// DNSOwnedRecord is one record Veksel published. Purpose scopes ownership to
// the hosted domain (or "acme") whose desired set produced it, so publishing
// one domain never removes another domain's records in a shared zone.
type DNSOwnedRecord struct {
	Purpose   string    `json:"purpose"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

// DNSZoneStore persists DNS provider zones keyed by zone apex.
type DNSZoneStore struct{ zones collection[DNSZone] }

// NewDNSZoneStore creates a DNS zone store.
func NewDNSZoneStore(ts *TypedStore) *DNSZoneStore {
	return &DNSZoneStore{zones: newCollection[DNSZone](ts, NSDNSZones)}
}

// Get returns the zone configured for apex.
func (s *DNSZoneStore) Get(ctx context.Context, apex string) (DNSZone, error) {
	return s.zones.get(ctx, apex)
}

// List returns every configured zone in apex order.
func (s *DNSZoneStore) List(ctx context.Context) ([]DNSZone, error) { return s.zones.list(ctx) }

// Set creates or replaces a zone.
func (s *DNSZoneStore) Set(ctx context.Context, zone DNSZone) error {
	return s.zones.set(ctx, zone.Zone, zone)
}

// Delete removes a zone.
func (s *DNSZoneStore) Delete(ctx context.Context, apex string) error {
	return s.zones.delete(ctx, apex)
}
