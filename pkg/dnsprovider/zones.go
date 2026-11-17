package dnsprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/netguard"
	"github.com/lkarlslund/veksel/pkg/store"
)

// secretPurpose binds sealed provider credentials to this subsystem.
const secretPurpose = "dns-provider"

// PurposeACME owns transient ACME DNS-01 challenge records.
const PurposeACME = "acme"

// Sealer protects provider credentials at rest; migration.Store implements
// it with the installation's rotating stored-credential keys.
type Sealer interface {
	SealSecret(purpose, id string, plaintext []byte) ([]byte, error)
	OpenSecret(purpose, id string, sealed []byte) ([]byte, error)
}

// Auditor records DNS changes; audit.Logger implements it.
type Auditor interface {
	Log(actor, action, target string, details map[string]string)
}

// Factory builds a Provider for a zone and its opened credential.
type Factory func(zone model.DNSZone, secret string) (Provider, error)

// Zones owns DNS provider configuration, record ownership, and every change
// Veksel makes through a provider.
type Zones struct {
	store       *model.DNSZoneStore
	sealer      Sealer
	audit       Auditor
	factory     Factory
	propagation Propagation
	hosted      *Hosted
	// client carries every provider API call; it reaches private networks
	// only while allowPrivate is set.
	client       *http.Client
	allowPrivate atomic.Bool
	mu           sync.Mutex // serializes zone read-modify-write
}

// NewZones opens the zone store.
func NewZones(ctx context.Context, ts *model.TypedStore, sealer Sealer, audit Auditor) (*Zones, error) {
	if err := ts.EnsureNamespace(ctx, model.NSDNSZones); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, fmt.Errorf("initialize DNS zones: %w", err)
	}
	hosted, err := newHosted(ctx, ts, sealer)
	if err != nil {
		return nil, err
	}
	z := &Zones{store: model.NewDNSZoneStore(ts), sealer: sealer, audit: audit, hosted: hosted}
	z.client = (&netguard.Dialer{AllowPrivate: z.allowPrivate.Load}).Client(providerTimeout)
	z.factory = func(zone model.DNSZone, secret string) (Provider, error) { return NewProvider(zone, secret, z.client) }
	return z, nil
}

// SetAllowPrivateNetworks lets provider APIs on loopback, private, and
// link-local addresses be reached (outbound_http_allow_private_networks).
func (z *Zones) SetAllowPrivateNetworks(allow bool) { z.allowPrivate.Store(allow) }

// Hosted returns the zones the built-in DNS server serves.
func (z *Zones) Hosted() *Hosted { return z.hosted }

// SetFactory replaces provider construction, for tests.
func (z *Zones) SetFactory(factory Factory) { z.factory = factory }

// SetPropagation replaces the authoritative propagation check.
func (z *Zones) SetPropagation(propagation Propagation) { z.propagation = propagation }

// providerSettings lists the non-secret settings each provider accepts and
// whether each is required. No accepted setting may carry a credential.
var providerSettings = map[string]map[string]bool{
	KindRFC2136:    {"server": true, "key_name": true, "algorithm": false},
	KindCloudflare: {"zone_id": false},
	KindWebhook:    {"url": true},
	KindBuiltin:    {},
}

// NewProvider builds the connector for a stored zone; HTTP providers send
// their API calls through client.
func NewProvider(zone model.DNSZone, secret string, client *http.Client) (Provider, error) {
	s := zone.Settings
	switch zone.Provider {
	case KindRFC2136:
		algorithm := TSIGAlgorithms[strings.ToLower(strings.TrimSuffix(firstNonEmpty(s["algorithm"], "hmac-sha256"), "."))]
		return &RFC2136{Zone: zone.Zone, Server: withDefaultPort(s["server"]), KeyName: s["key_name"], Algorithm: algorithm, Secret: secret}, nil
	case KindCloudflare:
		return &Cloudflare{Zone: zone.Zone, ZoneID: s["zone_id"], Token: secret, Client: client}, nil
	case KindWebhook:
		return &Webhook{Zone: zone.Zone, URL: s["url"], Token: secret, Client: client}, nil
	}
	return nil, fmt.Errorf("unknown DNS provider %q", zone.Provider)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// ZoneInput configures a zone. A nil Secret keeps the stored credential.
type ZoneInput struct {
	Provider string            `json:"provider"`
	Settings map[string]string `json:"settings"`
	Secret   *string           `json:"secret,omitempty"`
}

// ZoneView is the redacted projection of a zone: the credential is reduced
// to whether one is stored.
type ZoneView struct {
	Zone          string            `json:"zone"`
	Provider      string            `json:"provider"`
	Settings      map[string]string `json:"settings"`
	SecretSet     bool              `json:"secret_set"`
	OwnedRecords  int               `json:"owned_records"`
	UpdatedAt     time.Time         `json:"updated_at"`
	LastSuccessAt time.Time         `json:"last_success_at,omitzero"`
	LastFailureAt time.Time         `json:"last_failure_at,omitzero"`
	LastFailure   string            `json:"last_failure,omitempty"`
}

func viewOf(zone model.DNSZone) ZoneView {
	settings := make(map[string]string, len(zone.Settings))
	for key, value := range zone.Settings {
		settings[key] = value
	}
	return ZoneView{Zone: zone.Zone, Provider: zone.Provider, Settings: settings, SecretSet: len(zone.SealedSecret) > 0,
		OwnedRecords: len(zone.Owned), UpdatedAt: zone.UpdatedAt, LastSuccessAt: zone.LastSuccessAt, LastFailureAt: zone.LastFailureAt, LastFailure: zone.LastFailure}
}

// List returns every zone, redacted.
func (z *Zones) List(ctx context.Context) ([]ZoneView, error) {
	zones, err := z.store.List(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]ZoneView, 0, len(zones))
	for _, zone := range zones {
		views = append(views, viewOf(zone))
	}
	return views, nil
}

// Put validates and stores a zone's connector; ownership and outcome history
// are kept when the zone already exists.
func (z *Zones) Put(ctx context.Context, actor, apex string, input ZoneInput) (ZoneView, error) {
	apex = NormalizeName(apex)
	if apex == "" || strings.ContainsAny(apex, " /*\\") || !strings.Contains(apex, ".") {
		return ZoneView{}, fmt.Errorf("invalid zone %q", apex)
	}
	allowed, ok := providerSettings[input.Provider]
	if !ok {
		return ZoneView{}, fmt.Errorf("provider must be one of %s, %s, %s, or %s", KindRFC2136, KindCloudflare, KindWebhook, KindBuiltin)
	}
	settings := map[string]string{}
	for key, value := range input.Settings {
		if _, known := allowed[key]; !known {
			return ZoneView{}, fmt.Errorf("%s does not accept setting %q", input.Provider, key)
		}
		if value = strings.TrimSpace(value); value != "" {
			settings[key] = value
		}
	}
	for key, required := range allowed {
		if required && settings[key] == "" {
			return ZoneView{}, fmt.Errorf("%s requires setting %q", input.Provider, key)
		}
	}
	if err := validateSettings(input.Provider, settings); err != nil {
		return ZoneView{}, err
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	zone, err := z.store.Get(ctx, apex)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return ZoneView{}, err
	}
	previous := zone.Provider
	if previous != "" && previous != input.Provider && input.Secret == nil && input.Provider != KindBuiltin {
		return ZoneView{}, errors.New("a new credential is required when the provider changes")
	}
	zone.Zone, zone.Provider, zone.Settings, zone.UpdatedAt = apex, input.Provider, settings, time.Now().UTC()
	secretChanged := input.Secret != nil
	if input.Provider == KindBuiltin {
		// The built-in server needs no credential.
		secretChanged, zone.SealedSecret = len(zone.SealedSecret) > 0, nil
	} else if secretChanged {
		zone.SealedSecret = nil
		if secret := strings.TrimSpace(*input.Secret); secret != "" {
			if err := validateSecret(input.Provider, secret); err != nil {
				return ZoneView{}, err
			}
			if zone.SealedSecret, err = z.sealer.SealSecret(secretPurpose, apex, []byte(secret)); err != nil {
				return ZoneView{}, fmt.Errorf("protect DNS provider credential: %w", err)
			}
		}
	}
	if len(zone.SealedSecret) == 0 && input.Provider != KindWebhook && input.Provider != KindBuiltin {
		return ZoneView{}, fmt.Errorf("%s requires a credential", input.Provider)
	}
	if input.Provider == KindBuiltin {
		if err := z.hosted.ensure(ctx, apex); err != nil {
			return ZoneView{}, err
		}
	}
	if err := z.store.Set(ctx, zone); err != nil {
		return ZoneView{}, err
	}
	if previous == KindBuiltin && input.Provider != KindBuiltin {
		if err := z.hosted.remove(ctx, apex); err != nil {
			return ZoneView{}, err
		}
	}
	details := map[string]string{"provider": zone.Provider, "credential_changed": fmt.Sprint(secretChanged)}
	for key, value := range settings {
		details[key] = value
	}
	z.audit.Log(actor, "dns.zone.configure", apex, details)
	return viewOf(zone), nil
}

func validateSettings(provider string, settings map[string]string) error {
	switch provider {
	case KindRFC2136:
		if algorithm := settings["algorithm"]; algorithm != "" && TSIGAlgorithms[strings.ToLower(strings.TrimSuffix(algorithm, "."))] == "" {
			return fmt.Errorf("unsupported TSIG algorithm %q", algorithm)
		}
		if strings.ContainsAny(settings["server"], "/ ") {
			return fmt.Errorf("server must be host or host:port")
		}
	case KindWebhook:
		parsed, err := url.Parse(settings["url"])
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
			return errors.New("url must be an absolute http(s) URL without credentials")
		}
	}
	return nil
}

func validateSecret(provider, secret string) error {
	if provider == KindRFC2136 {
		if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
			return errors.New("TSIG secret must be base64")
		}
	}
	return nil
}

// Delete removes a zone. Records published through an external provider
// stay in DNS; the built-in server stops serving its zone and discards it.
func (z *Zones) Delete(ctx context.Context, actor, apex string) error {
	apex = NormalizeName(apex)
	z.mu.Lock()
	defer z.mu.Unlock()
	zone, err := z.store.Get(ctx, apex)
	if err != nil {
		return err
	}
	if err := z.store.Delete(ctx, apex); err != nil {
		return err
	}
	if zone.Provider == KindBuiltin {
		if err := z.hosted.remove(ctx, apex); err != nil {
			return err
		}
	}
	z.audit.Log(actor, "dns.zone.remove", apex, nil)
	return nil
}

// ForName returns the most specific zone containing name.
func (z *Zones) ForName(ctx context.Context, name string) (model.DNSZone, error) {
	zones, err := z.store.List(ctx)
	if err != nil {
		return model.DNSZone{}, err
	}
	best := -1
	for i, zone := range zones {
		if InZone(name, zone.Zone) && (best < 0 || len(zone.Zone) > len(zones[best].Zone)) {
			best = i
		}
	}
	if best < 0 {
		return model.DNSZone{}, ErrNoProvider
	}
	return zones[best], nil
}

// ViewFor returns the redacted zone covering name.
func (z *Zones) ViewFor(ctx context.Context, name string) (ZoneView, error) {
	zone, err := z.ForName(ctx, name)
	if err != nil {
		return ZoneView{}, err
	}
	return viewOf(zone), nil
}

// Available reports whether a provider covers name.
func (z *Zones) Available(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := z.ForName(ctx, name)
	return err == nil
}

func (z *Zones) provider(zone model.DNSZone) (Provider, error) {
	if zone.Provider == KindBuiltin {
		return &Builtin{hosted: z.hosted, zone: zone.Zone}, nil
	}
	secret := ""
	if len(zone.SealedSecret) > 0 {
		opened, err := z.sealer.OpenSecret(secretPurpose, zone.Zone, zone.SealedSecret)
		if err != nil {
			return nil, fmt.Errorf("open DNS provider credential: %w", err)
		}
		secret = string(opened)
	}
	return z.factory(zone, secret)
}

// PlanResult is a zone-scoped plan, or an applied plan's outcome.
type PlanResult struct {
	Zone     string   `json:"zone"`
	Provider string   `json:"provider"`
	Changes  []Change `json:"changes"`
}

// Scope selects the owned records a plan may delete: those Veksel published
// for purpose that match the predicate (nil matches all of them).
type Scope struct {
	Purpose string
	Match   func(model.DNSOwnedRecord) bool
}

func (s Scope) contains(rec model.DNSOwnedRecord) bool {
	return rec.Purpose == s.Purpose && (s.Match == nil || s.Match(rec))
}

// Plan compares desired records, which must lie in one zone, with the
// provider's live records.
func (z *Zones) Plan(ctx context.Context, name string, desired []Desired, scope Scope) (PlanResult, error) {
	result, _, _, _, err := z.plan(ctx, name, desired, scope)
	return result, err
}

func (z *Zones) plan(ctx context.Context, name string, desired []Desired, scope Scope) (PlanResult, model.DNSZone, Provider, []model.DNSOwnedRecord, error) {
	zone, err := z.ForName(ctx, name)
	if err != nil {
		return PlanResult{}, zone, nil, nil, err
	}
	provider, err := z.provider(zone)
	if err != nil {
		return PlanResult{}, zone, nil, nil, err
	}
	var retired []model.DNSOwnedRecord
	for _, rec := range zone.Owned {
		if !scope.contains(rec) {
			continue
		}
		wanted := false
		for _, want := range desired {
			wanted = wanted || (strings.EqualFold(want.Type, rec.Type) && NormalizeName(want.Name) == rec.Name && SameValue(rec.Type, want.Value, rec.Value))
		}
		if !wanted {
			retired = append(retired, rec)
		}
	}
	live := map[string][]Record{}
	fetch := func(rtype, name string) error {
		key := recordKey(rtype, name)
		if _, done := live[key]; done {
			return nil
		}
		if !InZone(name, zone.Zone) {
			return fmt.Errorf("%s is outside zone %s", name, zone.Zone)
		}
		records, err := provider.ListRecords(ctx, NormalizeName(name), strings.ToUpper(rtype))
		if err != nil {
			return fmt.Errorf("list %s %s: %w", rtype, name, err)
		}
		live[key] = records
		return nil
	}
	for _, want := range desired {
		if err := fetch(want.Type, want.Name); err != nil {
			return PlanResult{}, zone, nil, nil, err
		}
	}
	for _, rec := range retired {
		if err := fetch(rec.Type, rec.Name); err != nil {
			return PlanResult{}, zone, nil, nil, err
		}
	}
	owned := func(rec Record) bool { return ownedIndex(zone.Owned, rec.Type, rec.Name, rec.Value) >= 0 }
	changes, vanished := computePlan(desired, live, owned, retired)
	if changes == nil {
		changes = []Change{}
	}
	return PlanResult{Zone: zone.Zone, Provider: zone.Provider, Changes: changes}, zone, provider, vanished, nil
}

func ownedIndex(owned []model.DNSOwnedRecord, rtype, name, value string) int {
	for i, rec := range owned {
		if strings.EqualFold(rec.Type, rtype) && rec.Name == NormalizeName(name) && SameValue(rtype, rec.Value, value) {
			return i
		}
	}
	return -1
}

// ApplyOptions confirms changes Veksel never makes on its own.
type ApplyOptions struct {
	// OverwriteConflicts replaces records Veksel did not create.
	OverwriteConflicts bool
}

// Apply recomputes the plan and performs it: creates, updates of owned
// records, deletions of retired owned records, and, only when confirmed,
// replacements of foreign records. Every change is audited and the zone's
// outcome feeds runtime health. The returned error summarizes failures.
func (z *Zones) Apply(ctx context.Context, actor, name string, desired []Desired, scope Scope, options ApplyOptions) (PlanResult, error) {
	result, zone, provider, vanished, err := z.plan(ctx, name, desired, scope)
	if err != nil {
		z.recordOutcome(ctx, zone.Zone, err)
		return result, err
	}
	var failures []string
	var forget []model.DNSOwnedRecord
	var adopt []model.DNSOwnedRecord
	for i := range result.Changes {
		change := &result.Changes[i]
		var opErr error
		switch change.Action {
		case ActionCreate:
			opErr = provider.UpsertRecord(ctx, Record{Type: change.Type, Name: change.Name, Value: change.Value})
		case ActionUpdate:
			opErr = provider.UpsertRecord(ctx, Record{ID: change.Replace.ID, Type: change.Type, Name: change.Name, Value: change.Value, TTL: change.Replace.TTL})
		case ActionConflict:
			if !options.OverwriteConflicts {
				continue
			}
			opErr = provider.UpsertRecord(ctx, Record{ID: change.Replace.ID, Type: change.Type, Name: change.Name, Value: change.Value, TTL: change.Replace.TTL})
		case ActionDelete:
			opErr = provider.DeleteRecord(ctx, *change.Replace)
		default:
			continue
		}
		details := map[string]string{"zone": zone.Zone, "type": change.Type, "name": change.Name, "value": auditValue(change.Value), "purpose": scope.Purpose}
		action := map[string]string{ActionCreate: "create", ActionUpdate: "update", ActionConflict: "update", ActionDelete: "delete"}[change.Action]
		if change.Replace != nil && change.Action != ActionDelete {
			details["replaced"] = auditValue(change.Replace.Value)
		}
		if opErr != nil {
			change.Error = opErr.Error()
			failures = append(failures, fmt.Sprintf("%s %s %s: %v", action, change.Type, change.Name, opErr))
			details["error"] = opErr.Error()
			z.audit.Log(actor, "dns.record.failed", change.Name, details)
			continue
		}
		change.Applied = true
		z.audit.Log(actor, "dns.record."+action, change.Name, details)
		if change.Replace != nil {
			forget = append(forget, model.DNSOwnedRecord{Type: change.Type, Name: change.Name, Value: change.Replace.Value})
		}
		if change.Action != ActionDelete {
			adopt = append(adopt, model.DNSOwnedRecord{Purpose: scope.Purpose, Type: change.Type, Name: change.Name, Value: change.Value, CreatedAt: time.Now().UTC()})
		}
	}
	forget = append(forget, vanished...)
	var applyErr error
	if len(failures) > 0 {
		applyErr = fmt.Errorf("DNS publish for %s failed: %s", name, strings.Join(failures, "; "))
	}
	z.updateZone(ctx, zone.Zone, func(stored *model.DNSZone) {
		for _, rec := range forget {
			if i := ownedIndex(stored.Owned, rec.Type, rec.Name, rec.Value); i >= 0 {
				stored.Owned = append(stored.Owned[:i], stored.Owned[i+1:]...)
			}
		}
		for _, rec := range adopt {
			if ownedIndex(stored.Owned, rec.Type, rec.Name, rec.Value) < 0 {
				stored.Owned = append(stored.Owned, rec)
			}
		}
		setOutcome(stored, applyErr)
	})
	return result, applyErr
}

// auditValue bounds long values such as DKIM keys in audit details.
func auditValue(value string) string {
	if len(value) > 120 {
		return value[:117] + "..."
	}
	return value
}

func setOutcome(zone *model.DNSZone, err error) {
	now := time.Now().UTC()
	if err != nil {
		zone.LastFailureAt, zone.LastFailure = now, auditValue(err.Error())
		return
	}
	zone.LastSuccessAt, zone.LastFailure = now, ""
}

func (z *Zones) recordOutcome(ctx context.Context, apex string, err error) {
	if apex != "" {
		z.updateZone(ctx, apex, func(zone *model.DNSZone) { setOutcome(zone, err) })
	}
}

func (z *Zones) updateZone(ctx context.Context, apex string, apply func(*model.DNSZone)) {
	z.mu.Lock()
	defer z.mu.Unlock()
	zone, err := z.store.Get(ctx, apex)
	if err != nil {
		return
	}
	apply(&zone)
	_ = z.store.Set(ctx, zone)
}

// PresentTXT publishes an ACME DNS-01 challenge record, waits until the
// zone's authoritative servers serve it, and returns its cleanup.
func (z *Zones) PresentTXT(ctx context.Context, name, value string, wait time.Duration) (func(context.Context) error, error) {
	name = NormalizeName(name)
	desired := []Desired{{Record: Record{Type: "TXT", Name: name, Value: value}, Prefix: value}}
	scope := Scope{Purpose: PurposeACME, Match: func(model.DNSOwnedRecord) bool { return false }}
	const actor = "system:acme"
	result, err := z.Apply(ctx, actor, name, desired, scope, ApplyOptions{})
	if err != nil {
		return nil, err
	}
	cleanup := func(ctx context.Context) error {
		_, err := z.Apply(ctx, actor, name, nil, Scope{Purpose: PurposeACME, Match: func(rec model.DNSOwnedRecord) bool {
			return rec.Name == name && rec.Value == value
		}}, ApplyOptions{})
		return err
	}
	if err := z.propagation.WaitTXT(ctx, result.Zone, name, value, wait); err != nil {
		z.recordOutcome(ctx, result.Zone, err)
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_ = cleanup(cleanupCtx)
		return nil, err
	}
	return cleanup, nil
}

// Observation reports DNS provider health: degraded while any zone's most
// recent change failed, so failed publishes and DKIM rotation publishes
// raise a health alert until a later change succeeds.
func (z *Zones) Observation(ctx context.Context) health.Observation {
	observation := health.Observation{ID: "dns-providers", Label: "DNS provider publishing", Kind: "dependency", State: health.StateDisabled}
	zones, err := z.store.List(ctx)
	if err != nil {
		observation.Desired, observation.State, observation.Severity, observation.Reason = true, health.StateUnavailable, health.SeverityWarning, "DNS zone configuration is unavailable"
		return observation
	}
	if len(zones) == 0 {
		return observation
	}
	observation.Desired, observation.State, observation.Details = true, health.StateHealthy, map[string]string{"zones": fmt.Sprint(len(zones))}
	var failing []string
	for _, zone := range zones {
		if zone.LastFailure != "" && zone.LastFailureAt.After(zone.LastSuccessAt) {
			failing = append(failing, zone.Zone+": "+zone.LastFailure)
		}
	}
	if len(failing) > 0 {
		sort.Strings(failing)
		observation.State, observation.Severity, observation.Reason = health.StateDegraded, health.SeverityWarning, strings.Join(failing, "; ")
	}
	return observation
}
