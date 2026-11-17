package dnsprovider

import (
	"context"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/miekg/dns"
)

// HostedRecordView is one record of a built-in zone. Owner names the purpose
// (hosted domain or "acme") whose publish created it; administrator-added
// records have none.
type HostedRecordView struct {
	Record
	Owner string `json:"owner,omitempty"`
}

// DNSSECKeyView describes a DNSSEC key and the DS record a registrar needs
// for it.
type DNSSECKeyView struct {
	ID        string    `json:"id"`
	KeyTag    uint16    `json:"key_tag"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	DNSKEY    string    `json:"dnskey"`
	DS        string    `json:"ds"`
}

// HostedZoneView is a built-in zone's records and keys.
type HostedZoneView struct {
	Zone      string             `json:"zone"`
	Serial    uint32             `json:"serial"`
	UpdatedAt time.Time          `json:"updated_at"`
	Records   []HostedRecordView `json:"records"`
	Keys      []DNSSECKeyView    `json:"keys"`
}

// builtinZone returns the zone configuration of a built-in zone.
func (z *Zones) builtinZone(ctx context.Context, apex string) (model.DNSZone, error) {
	zone, err := z.store.Get(ctx, NormalizeName(apex))
	if err != nil {
		return zone, err
	}
	if zone.Provider != KindBuiltin {
		return zone, ErrNotHosted
	}
	return zone, nil
}

// HostedZone returns a built-in zone's records, marking those Veksel
// published, and its DNSSEC keys with their DS records.
func (z *Zones) HostedZone(ctx context.Context, apex string) (HostedZoneView, error) {
	config, err := z.builtinZone(ctx, apex)
	if err != nil {
		return HostedZoneView{}, err
	}
	zone, ok := z.hosted.Zone(config.Zone)
	if !ok {
		return HostedZoneView{}, ErrNotHosted
	}
	view := HostedZoneView{Zone: zone.Zone, Serial: zone.Serial, UpdatedAt: zone.UpdatedAt, Records: []HostedRecordView{}, Keys: []DNSSECKeyView{}}
	for _, rec := range zone.Records {
		record := HostedRecordView{Record: Record{ID: rec.ID, Type: rec.Type, Name: rec.Name, Value: rec.Value, TTL: rec.TTL}}
		for _, owned := range config.Owned {
			if strings.EqualFold(owned.Type, rec.Type) && owned.Name == rec.Name && SameValue(rec.Type, owned.Value, rec.Value) {
				record.Owner = owned.Purpose
			}
		}
		view.Records = append(view.Records, record)
	}
	for _, key := range zone.Keys {
		dnskey := DNSKEYOf(zone.Zone, key)
		view.Keys = append(view.Keys, DNSSECKeyView{ID: key.ID, KeyTag: dnskey.KeyTag(), Active: key.Active, CreatedAt: key.CreatedAt,
			DNSKEY: dnskey.String(), DS: dnskey.ToDS(dns.SHA256).String()})
	}
	return view, nil
}

// AddHostedRecord adds an administrator record to a built-in zone. Veksel
// does not own it, so publishing never changes or removes it unless the
// administrator confirms a replacement.
func (z *Zones) AddHostedRecord(ctx context.Context, actor, apex string, rec Record) (Record, error) {
	config, err := z.builtinZone(ctx, apex)
	if err != nil {
		return Record{}, err
	}
	rec.ID = ""
	stored, err := z.hosted.upsert(ctx, config.Zone, rec)
	if err != nil {
		return Record{}, err
	}
	z.audit.Log(actor, "dns.record.create", stored.Name, map[string]string{"zone": config.Zone, "type": stored.Type, "name": stored.Name, "value": auditValue(stored.Value), "purpose": "custom"})
	return stored, nil
}

// DeleteHostedRecord removes a record from a built-in zone.
func (z *Zones) DeleteHostedRecord(ctx context.Context, actor, apex, id string) error {
	config, err := z.builtinZone(ctx, apex)
	if err != nil {
		return err
	}
	var removed Record
	if zone, ok := z.hosted.Zone(config.Zone); ok {
		for _, rec := range zone.Records {
			if rec.ID == id {
				removed = Record{ID: rec.ID, Type: rec.Type, Name: rec.Name, Value: rec.Value}
			}
		}
	}
	if err := z.hosted.delete(ctx, config.Zone, Record{ID: id}); err != nil {
		return err
	}
	z.audit.Log(actor, "dns.record.delete", removed.Name, map[string]string{"zone": config.Zone, "type": removed.Type, "name": removed.Name, "value": auditValue(removed.Value), "purpose": "custom"})
	return nil
}

// RollDNSSECKey performs one manual key rollover step (see Hosted.rollKey)
// and returns "staged" or "activated".
func (z *Zones) RollDNSSECKey(ctx context.Context, actor, apex string) (string, error) {
	config, err := z.builtinZone(ctx, apex)
	if err != nil {
		return "", err
	}
	step, err := z.hosted.rollKey(ctx, config.Zone)
	if err != nil {
		return "", err
	}
	z.audit.Log(actor, "dns.dnssec.rollover", config.Zone, map[string]string{"step": step})
	return step, nil
}
