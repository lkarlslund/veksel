// Package dnsprovider publishes DNS records through provider connectors. A
// Provider is scoped to one zone; Zones stores per-zone connector settings
// with sealed credentials, tracks the records Veksel owns, plans and applies
// changes with audit evidence, and solves ACME DNS-01 challenges.
package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Record is one resource record. Name is the fully qualified owner name
// without the trailing dot; Value is the presentation-format data, with TXT
// data as one unquoted string and MX data as "preference host.". ID is the
// provider's handle for a listed record and is empty for a new one.
type Record struct {
	ID    string `json:"id,omitempty"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// Provider changes records in one zone. ListRecords returns the records of
// one type at one owner name. UpsertRecord creates rec, or replaces the
// listed record rec.ID names. DeleteRecord removes a listed record, or the
// record matching rec's type, name, and value when rec.ID is empty.
type Provider interface {
	ListRecords(ctx context.Context, name, rtype string) ([]Record, error)
	UpsertRecord(ctx context.Context, rec Record) error
	DeleteRecord(ctx context.Context, rec Record) error
}

// DefaultTTL is used for records published without an explicit TTL.
const DefaultTTL = 3600

// Provider kinds accepted by Zones.
const (
	KindRFC2136    = "rfc2136"
	KindCloudflare = "cloudflare"
	KindWebhook    = "webhook"
)

// ErrNoProvider reports that no configured zone covers a name.
var ErrNoProvider = errors.New("no DNS provider is configured for this name")

// NormalizeName lower-cases a DNS name and removes the trailing dot.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// SameValue compares record data ignoring case of the type, insignificant
// whitespace, and a trailing dot on host names.
func SameValue(rtype, left, right string) bool {
	norm := func(value string) string {
		value = strings.Join(strings.Fields(value), " ")
		if !strings.EqualFold(rtype, "TXT") {
			value = strings.ToLower(strings.TrimSuffix(value, "."))
		}
		return value
	}
	return norm(left) == norm(right)
}

// InZone reports whether name is the zone apex or below it.
func InZone(name, zone string) bool {
	name, zone = NormalizeName(name), NormalizeName(zone)
	return zone != "" && (name == zone || strings.HasSuffix(name, "."+zone))
}

// splitMX parses "preference host" MX data.
func splitMX(value string) (int, string, error) {
	var preference int
	var host string
	if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d %s", &preference, &host); err != nil || preference < 0 || preference > 65535 {
		return 0, "", fmt.Errorf("invalid MX data %q", value)
	}
	return preference, NormalizeName(host), nil
}

// validateRecord checks the fields every provider needs.
func validateRecord(zone string, rec Record) error {
	switch strings.ToUpper(rec.Type) {
	case "TXT", "MX", "CNAME", "A", "AAAA", "SRV":
	default:
		return fmt.Errorf("unsupported record type %q", rec.Type)
	}
	if !InZone(rec.Name, zone) {
		return fmt.Errorf("record %s is outside zone %s", rec.Name, zone)
	}
	if strings.TrimSpace(rec.Value) == "" {
		return errors.New("record value is required")
	}
	return nil
}

func ttlOrDefault(ttl int) int {
	if ttl <= 0 {
		return DefaultTTL
	}
	return ttl
}
