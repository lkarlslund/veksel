// Package greylist provides durable, protocol-neutral SMTP greylisting.
package greylist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	currentVersion = 1
	statsKey       = "metadata:stats"
	tripletPrefix  = "triplet:"
	networkPrefix  = "network:"
	allowPrefix    = "allow:"
	maxIdentityLen = 320
)

// Config controls greylisting time windows and remote-network normalization.
type Config struct {
	Enabled         bool          `json:"enabled"`
	MinimumDelay    time.Duration `json:"minimum_delay"`
	RetryWindow     time.Duration `json:"retry_window"`
	PendingLifetime time.Duration `json:"pending_lifetime"`
	PassLifetime    time.Duration `json:"pass_lifetime"`
	IPv4PrefixBits  int           `json:"ipv4_prefix_bits"`
	IPv6PrefixBits  int           `json:"ipv6_prefix_bits"`
	MaxEntries      uint64        `json:"max_entries"`
	// ScoreTriggered greylists only messages whose spam score reaches the
	// greylist threshold, checked after DATA, instead of every unfamiliar
	// triplet at RCPT.
	ScoreTriggered bool `json:"score_triggered"`
	// AutoWhitelistPasses whitelists a client network for every sender and
	// recipient once it has passed greylisting this many times within the
	// pass lifetime; 0 disables auto-whitelisting.
	AutoWhitelistPasses int `json:"auto_whitelist_passes"`
	// AutoWhitelistLifetime is how long a whitelisted network stays
	// whitelisted after its latest message; each message extends it.
	AutoWhitelistLifetime time.Duration `json:"auto_whitelist_lifetime"`
	// SkipSPFPass bypasses greylisting when SPF passes for the envelope
	// sender's domain from the connecting address.
	SkipSPFPass bool `json:"skip_spf_pass"`
	// SPFPoolTriplets keys a triplet on the SPF-authenticated sender domain
	// instead of the client network when SPF passes, so a retry from
	// another address in the same sending pool matches the first attempt.
	SPFPoolTriplets bool `json:"spf_pool_triplets"`
}

// DefaultConfig is deliberately conservative and does not enable greylisting.
func DefaultConfig() Config {
	return Config{
		MinimumDelay: 5 * time.Minute, RetryWindow: 4 * time.Hour,
		PendingLifetime: 24 * time.Hour, PassLifetime: 36 * 24 * time.Hour,
		IPv4PrefixBits: 24, IPv6PrefixBits: 64, MaxEntries: 1_000_000,
		AutoWhitelistPasses: 5, AutoWhitelistLifetime: 36 * 24 * time.Hour, SPFPoolTriplets: true,
	}
}

func (config Config) Validate() error {
	if config.MinimumDelay < time.Second || config.MinimumDelay > 24*time.Hour {
		return errors.New("greylist minimum delay must be between one second and 24 hours")
	}
	if config.RetryWindow <= config.MinimumDelay || config.RetryWindow > 7*24*time.Hour {
		return errors.New("greylist retry window must be greater than the minimum delay and at most seven days")
	}
	if config.PendingLifetime < config.RetryWindow || config.PendingLifetime > 30*24*time.Hour {
		return errors.New("greylist pending lifetime must cover the retry window and be at most 30 days")
	}
	if config.PassLifetime < config.RetryWindow || config.PassLifetime > 365*24*time.Hour {
		return errors.New("greylist pass lifetime must cover the retry window and be at most 365 days")
	}
	if config.IPv4PrefixBits < 0 || config.IPv4PrefixBits > 32 || config.IPv6PrefixBits < 0 || config.IPv6PrefixBits > 128 {
		return errors.New("greylist network prefix bits are invalid")
	}
	if config.MaxEntries < 100 || config.MaxEntries > 10_000_000 {
		return errors.New("greylist maximum entries must be between 100 and 10000000")
	}
	if config.AutoWhitelistPasses < 0 || config.AutoWhitelistPasses > 1000 {
		return errors.New("greylist auto-whitelist passes must be between 0 and 1000")
	}
	if config.AutoWhitelistPasses > 0 && (config.AutoWhitelistLifetime < 24*time.Hour || config.AutoWhitelistLifetime > 365*24*time.Hour) {
		return errors.New("greylist auto-whitelist lifetime must be between one and 365 days")
	}
	return nil
}

// Triplet is the protocol-neutral input. Bypass must be set only after the
// caller has established an authenticated, trusted, or explicit allow rule.
// SPFPassDomain is the envelope sender's domain when SPF passed for it from
// RemoteIP, and empty otherwise.
type Triplet struct {
	RemoteIP      string `json:"remote_ip"`
	EnvelopeFrom  string `json:"envelope_from"`
	Recipient     string `json:"recipient"`
	SPFPassDomain string `json:"spf_pass_domain,omitempty"`
	Bypass        bool   `json:"bypass,omitempty"`
	BypassReason  string `json:"bypass_reason,omitempty"`
}

type AllowKind string

const (
	AllowSourceCIDR AllowKind = "source_cidr"
	AllowSender     AllowKind = "sender"
	AllowRecipient  AllowKind = "recipient"
)

// AllowEntry is an administrator-owned explicit greylist bypass. Sender and
// recipient values accept an exact address or @domain suffix.
type AllowEntry struct {
	ID        string    `json:"id"`
	Kind      AllowKind `json:"kind"`
	Value     string    `json:"value"`
	Comment   string    `json:"comment,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

type Action string

const (
	ActionDefer  Action = "defer"
	ActionPass   Action = "pass"
	ActionBypass Action = "bypass"
)

// Decision contains bounded evidence suitable for SMTP replies and tracing.
type Decision struct {
	Action       Action        `json:"action"`
	Reason       string        `json:"reason"`
	RetryAfter   time.Duration `json:"retry_after,omitempty"`
	FirstSeen    time.Time     `json:"first_seen,omitzero"`
	PassedAt     time.Time     `json:"passed_at,omitzero"`
	Attempts     uint64        `json:"attempts,omitempty"`
	TripletID    string        `json:"triplet_id,omitempty"`
	WindowReset  bool          `json:"window_reset,omitempty"`
	BypassReason string        `json:"bypass_reason,omitempty"`
}

// Stats is durable constant-time operational metadata. StoredEntries and
// StoredNetworks include entries not yet visited by cleanup even when their
// logical expiry passed.
type Stats struct {
	Version       int    `json:"version"`
	Checks        uint64 `json:"checks"`
	Deferred      uint64 `json:"deferred"`
	Passed        uint64 `json:"passed"`
	Bypassed      uint64 `json:"bypassed"`
	WindowResets  uint64 `json:"window_resets"`
	StoredEntries uint64 `json:"stored_entries"`
	Expired       uint64 `json:"expired"`
	CapacityPass  uint64 `json:"capacity_pass"`
	// SPFBypassed counts checks skipped because SPF passed.
	SPFBypassed uint64 `json:"spf_bypassed"`
	// AutoWhitelisted counts checks bypassed by an auto-whitelisted client
	// network; Promotions counts networks that became whitelisted.
	AutoWhitelisted uint64    `json:"auto_whitelisted"`
	Promotions      uint64    `json:"auto_whitelist_promotions"`
	StoredNetworks  uint64    `json:"stored_networks"`
	LastCheckAt     time.Time `json:"last_check_at,omitzero"`
	CleanupCursor   string    `json:"cleanup_cursor,omitempty"`
}

type entry struct {
	Version   int       `json:"version"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	PassedAt  time.Time `json:"passed_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at"`
	Attempts  uint64    `json:"attempts"`
}

// networkEntry counts a client network's greylisting passes toward its
// auto-whitelisting. Passes count from FirstPass for one pass lifetime.
type networkEntry struct {
	Version          int       `json:"version"`
	FirstPass        time.Time `json:"first_pass"`
	Passes           uint64    `json:"passes"`
	WhitelistedUntil time.Time `json:"whitelisted_until,omitzero"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// Service serializes read-modify-write transitions and commits each decision
// with its durable counters through the generic store batch contract.
type Service struct {
	store  store.Store
	config atomic.Pointer[Config]
	now    func() time.Time
	mu     sync.Mutex
	allows atomic.Pointer[allowSnapshot]
}

type compiledAllow struct {
	entry  AllowEntry
	prefix netip.Prefix
}

type allowSnapshot struct{ entries []compiledAllow }

func New(ctx context.Context, backend store.Store, config Config) (*Service, error) {
	if backend == nil {
		return nil, errors.New("greylist store is required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := ensureNamespace(ctx, backend); err != nil {
		return nil, err
	}
	service := &Service{store: backend, now: time.Now}
	service.config.Store(&config)
	if err := service.ensureStats(ctx); err != nil {
		return nil, err
	}
	if err := service.reloadAllows(ctx); err != nil {
		return nil, err
	}
	return service, nil
}

// Config returns the runtime configuration currently in effect.
func (service *Service) Config() Config { return *service.config.Load() }

// Enabled reports whether triplet checks currently defer unknown senders.
func (service *Service) Enabled() bool { return service.config.Load().Enabled }

// ScoreTriggered reports whether greylisting waits for a spam score
// instead of deferring every unfamiliar triplet.
func (service *Service) ScoreTriggered() bool { return service.config.Load().ScoreTriggered }

// SetConfig validates and atomically installs a new configuration, or
// returns an error and keeps the current one. Each check uses one snapshot,
// so a decision never mixes old and new timing. Existing triplets keep their
// stored expiry; a changed network prefix length starts new triplets.
func (service *Service) SetConfig(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	service.config.Store(&config)
	return nil
}

func (service *Service) Check(ctx context.Context, input Triplet) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	now := service.now().UTC()
	config := service.config.Load()
	if !config.Enabled || input.Bypass {
		reason := strings.TrimSpace(input.BypassReason)
		if !config.Enabled {
			reason = "greylisting disabled"
		} else if reason == "" {
			reason = "trusted sender"
		}
		decision := Decision{Action: ActionBypass, Reason: reason, BypassReason: reason}
		service.mu.Lock()
		err := service.updateStats(ctx, now, func(stats *Stats) { stats.Checks++; stats.Bypassed++ })
		service.mu.Unlock()
		return decision, err
	}
	if allowID := service.matchAllow(input, now); allowID != "" {
		reason := "explicit greylist allow entry " + allowID
		decision := Decision{Action: ActionBypass, Reason: reason, BypassReason: reason}
		service.mu.Lock()
		err := service.updateStats(ctx, now, func(stats *Stats) { stats.Checks++; stats.Bypassed++ })
		service.mu.Unlock()
		return decision, err
	}
	if config.SkipSPFPass && input.SPFPassDomain != "" {
		reason := "sender domain passed SPF"
		decision := Decision{Action: ActionBypass, Reason: reason, BypassReason: reason}
		service.mu.Lock()
		err := service.updateStats(ctx, now, func(stats *Stats) { stats.Checks++; stats.Bypassed++; stats.SPFBypassed++ })
		service.mu.Unlock()
		return decision, err
	}

	keys, err := tripletKeysFor(config, input)
	if err != nil {
		return Decision{}, err
	}
	key, id := keys.triplet, keys.id
	service.mu.Lock()
	defer service.mu.Unlock()
	var decision Decision
	err = store.Batch(ctx, service.store, func(batchCtx context.Context) error {
		stats, err := service.loadStats(batchCtx)
		if err != nil {
			return err
		}
		stats.Checks++
		stats.LastCheckAt = now
		network, networkFound, err := service.loadNetwork(batchCtx, keys.network)
		if err != nil {
			return err
		}
		if networkFound && config.AutoWhitelistPasses > 0 && now.Before(network.WhitelistedUntil) {
			network.WhitelistedUntil = now.Add(config.AutoWhitelistLifetime)
			network.ExpiresAt = later(network.ExpiresAt, network.WhitelistedUntil)
			reason := "auto-whitelisted client network"
			decision = Decision{Action: ActionBypass, Reason: reason, BypassReason: reason}
			stats.Bypassed++
			stats.AutoWhitelisted++
			if err := setJSON(batchCtx, service.store, keys.network, network); err != nil {
				return err
			}
			return setJSON(batchCtx, service.store, statsKey, stats)
		}
		current, found, err := service.loadEntry(batchCtx, key)
		if err != nil {
			return err
		}
		stored := found
		if found && !now.Before(current.ExpiresAt) {
			found = false
			stats.Expired++
		}
		if !found && keys.fallback != "" {
			// A sender validated by client network before pool keying keeps
			// its pass under the domain key instead of being delayed again.
			previous, previousFound, err := service.loadEntry(batchCtx, keys.fallback)
			if err != nil {
				return err
			}
			if previousFound && !previous.PassedAt.IsZero() && now.Before(previous.ExpiresAt) {
				current, found = previous, true
				if !stored {
					stats.StoredEntries++
				}
			}
		}
		if !found {
			if !stored && stats.StoredEntries >= config.MaxEntries {
				decision = Decision{Action: ActionBypass, Reason: "greylist capacity reached", BypassReason: "greylist capacity reached"}
				stats.Bypassed++
				stats.CapacityPass++
				return setJSON(batchCtx, service.store, statsKey, stats)
			}
			current = entry{Version: currentVersion, FirstSeen: now, LastSeen: now, ExpiresAt: now.Add(config.PendingLifetime), Attempts: 1}
			decision = Decision{Action: ActionDefer, Reason: "new greylist triplet", RetryAfter: config.MinimumDelay, FirstSeen: now, Attempts: 1, TripletID: id}
			stats.Deferred++
			// An expired value is replaced in place and does not change the
			// number of stored keys.
			if !stored {
				stats.StoredEntries++
			}
		} else {
			current.LastSeen = now
			current.Attempts++
			switch {
			case !current.PassedAt.IsZero():
				current.ExpiresAt = now.Add(config.PassLifetime)
				decision = Decision{Action: ActionPass, Reason: "previously validated greylist triplet", FirstSeen: current.FirstSeen, PassedAt: current.PassedAt, Attempts: current.Attempts, TripletID: id}
				stats.Passed++
			case now.Before(current.FirstSeen.Add(config.MinimumDelay)):
				decision = Decision{Action: ActionDefer, Reason: "greylist minimum delay has not elapsed", RetryAfter: current.FirstSeen.Add(config.MinimumDelay).Sub(now), FirstSeen: current.FirstSeen, Attempts: current.Attempts, TripletID: id}
				stats.Deferred++
			case now.After(current.FirstSeen.Add(config.RetryWindow)):
				current.FirstSeen, current.ExpiresAt = now, now.Add(config.PendingLifetime)
				decision = Decision{Action: ActionDefer, Reason: "greylist retry window expired", RetryAfter: config.MinimumDelay, FirstSeen: now, Attempts: current.Attempts, TripletID: id, WindowReset: true}
				stats.Deferred++
				stats.WindowResets++
			default:
				current.PassedAt, current.ExpiresAt = now, now.Add(config.PassLifetime)
				decision = Decision{Action: ActionPass, Reason: "greylist retry accepted", FirstSeen: current.FirstSeen, PassedAt: now, Attempts: current.Attempts, TripletID: id}
				stats.Passed++
			}
		}
		if err := setJSON(batchCtx, service.store, key, current); err != nil {
			return fmt.Errorf("store greylist triplet: %w", err)
		}
		if decision.Action == ActionPass && config.AutoWhitelistPasses > 0 {
			if err := service.recordNetworkPass(batchCtx, config, &stats, keys.network, network, networkFound, now); err != nil {
				return err
			}
		}
		return setJSON(batchCtx, service.store, statsKey, stats)
	})
	return decision, err
}

// recordNetworkPass counts one pass for a client network and whitelists it
// once it reaches the configured count within one pass lifetime. A new
// network is not tracked while the network table is at capacity.
func (service *Service) recordNetworkPass(ctx context.Context, config *Config, stats *Stats, key string, network networkEntry, found bool, now time.Time) error {
	if !found {
		if stats.StoredNetworks >= config.MaxEntries {
			return nil
		}
		stats.StoredNetworks++
	}
	if !found || !now.Before(network.ExpiresAt) || !now.Before(network.FirstPass.Add(config.PassLifetime)) {
		network = networkEntry{Version: currentVersion, FirstPass: now}
	}
	network.Passes++
	if network.Passes >= uint64(config.AutoWhitelistPasses) {
		network.WhitelistedUntil = now.Add(config.AutoWhitelistLifetime)
		stats.Promotions++
	}
	network.ExpiresAt = later(network.FirstPass.Add(config.PassLifetime), network.WhitelistedUntil)
	return setJSON(ctx, service.store, key, network)
}

func later(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

// CreateAllow validates and persists one immutable explicit bypass. Duplicate
// normalized kind/value pairs return store.ErrExists.
func (service *Service) CreateAllow(ctx context.Context, candidate AllowEntry) (AllowEntry, error) {
	now := service.now().UTC()
	candidate.ID = ""
	candidate.CreatedAt = time.Time{}
	entry, _, err := normalizeAllow(candidate, now)
	if err != nil {
		return AllowEntry{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	data, err := json.Marshal(entry)
	if err != nil {
		return AllowEntry{}, err
	}
	if err := service.store.Put(ctx, model.NSGreylisting, allowPrefix+entry.ID, data); err != nil {
		return AllowEntry{}, err
	}
	if err := service.reloadAllows(ctx); err != nil {
		_ = service.store.Delete(ctx, model.NSGreylisting, allowPrefix+entry.ID)
		return AllowEntry{}, err
	}
	return entry, nil
}

func (service *Service) DeleteAllow(ctx context.Context, id string) error {
	if !strings.HasPrefix(id, "allow_") || len(id) != len("allow_")+32 {
		return errors.New("invalid greylist allow entry ID")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.store.Delete(ctx, model.NSGreylisting, allowPrefix+id); err != nil {
		return err
	}
	return service.reloadAllows(ctx)
}

func (service *Service) ListAllows(ctx context.Context) ([]AllowEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot := service.allows.Load()
	if snapshot == nil {
		return []AllowEntry{}, nil
	}
	now := service.now().UTC()
	result := make([]AllowEntry, 0, len(snapshot.entries))
	for _, compiled := range snapshot.entries {
		if compiled.entry.ExpiresAt.IsZero() || now.Before(compiled.entry.ExpiresAt) {
			result = append(result, compiled.entry)
		}
	}
	slices.SortFunc(result, func(left, right AllowEntry) int {
		if left.Kind != right.Kind {
			return strings.Compare(string(left.Kind), string(right.Kind))
		}
		return strings.Compare(left.Value, right.Value)
	})
	return result, nil
}

func (service *Service) Stats(ctx context.Context) (Stats, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.loadStats(ctx)
}

// Cleanup inspects at most limit triplet and client-network entries, deletes
// the expired ones, and advances a durable cursor so old live keys cannot
// indefinitely starve later expired keys.
func (service *Service) Cleanup(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 10000 {
		return 0, errors.New("greylist cleanup limit must be between 1 and 10000")
	}
	now := service.now().UTC()
	service.mu.Lock()
	defer service.mu.Unlock()
	removed, removedNetworks := 0, uint64(0)
	err := store.Batch(ctx, service.store, func(batchCtx context.Context) error {
		stats, err := service.loadStats(batchCtx)
		if err != nil {
			return err
		}
		cursor := stats.CleanupCursor
		last, inspected, reachedEnd := "", 0, true
		err = service.store.Iterate(batchCtx, model.NSGreylisting, "", func(key string, value []byte) (bool, error) {
			isNetwork := strings.HasPrefix(key, networkPrefix)
			if key <= cursor || !isNetwork && !strings.HasPrefix(key, tripletPrefix) {
				return true, nil
			}
			if inspected >= limit {
				reachedEnd = false
				return false, nil
			}
			inspected++
			last = key
			var current struct {
				ExpiresAt time.Time `json:"expires_at"`
			}
			if err := json.Unmarshal(value, &current); err != nil {
				return false, fmt.Errorf("decode greylist entry %s: %w", key, err)
			}
			if !now.Before(current.ExpiresAt) {
				if err := service.store.Delete(batchCtx, model.NSGreylisting, key); err != nil && !errors.Is(err, store.ErrNotFound) {
					return false, err
				}
				if isNetwork {
					removedNetworks++
				} else {
					removed++
				}
			}
			return true, nil
		})
		if err != nil {
			return err
		}
		if reachedEnd || last == "" {
			stats.CleanupCursor = ""
		} else {
			stats.CleanupCursor = last
		}
		stats.StoredEntries -= min(stats.StoredEntries, uint64(removed))
		stats.StoredNetworks -= min(stats.StoredNetworks, removedNetworks)
		return setJSON(batchCtx, service.store, statsKey, stats)
	})
	return removed + int(removedNetworks), err
}

// tripletKeys are the hashed store keys for one check: the client network,
// the triplet, its short ID, and, for a pool-keyed triplet, the network-keyed
// triplet it supersedes.
type tripletKeys struct {
	network, triplet, id, fallback string
}

func tripletKeysFor(config *Config, input Triplet) (tripletKeys, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(input.RemoteIP))
	if err != nil {
		return tripletKeys{}, errors.New("greylist remote IP is invalid")
	}
	address = address.Unmap()
	bits := config.IPv6PrefixBits
	if address.Is4() {
		bits = config.IPv4PrefixBits
	}
	prefix, err := address.Prefix(bits)
	if err != nil {
		return tripletKeys{}, errors.New("greylist remote network is invalid")
	}
	sender, err := canonicalAddress(input.EnvelopeFrom, true)
	if err != nil {
		return tripletKeys{}, fmt.Errorf("greylist envelope sender: %w", err)
	}
	recipient, err := canonicalAddress(input.Recipient, false)
	if err != nil {
		return tripletKeys{}, fmt.Errorf("greylist recipient: %w", err)
	}
	digest := func(source string) string {
		sum := sha256.Sum256([]byte(source + "\x00" + sender + "\x00" + recipient))
		return hex.EncodeToString(sum[:])
	}
	source := prefix.Masked().String()
	networkSum := sha256.Sum256([]byte("network\x00" + source))
	keys := tripletKeys{network: networkPrefix + hex.EncodeToString(networkSum[:])}
	// Pool keying applies only when SPF authenticated the envelope domain
	// itself, never a HELO identity for the null sender.
	_, senderDomain, _ := strings.Cut(sender, "@")
	if domain := strings.ToLower(strings.TrimSpace(input.SPFPassDomain)); config.SPFPoolTriplets && domain != "" && domain == senderDomain {
		keys.fallback = tripletPrefix + digest(source)
		source = "spf:" + domain
	}
	id := digest(source)
	keys.triplet, keys.id = tripletPrefix+id, id[:16]
	return keys, nil
}

func canonicalAddress(value string, allowNull bool) (string, error) {
	value = strings.TrimSpace(value)
	if allowNull && (value == "" || value == "<>") {
		return "<>", nil
	}
	if len(value) > maxIdentityLen {
		return "", errors.New("address exceeds 320 bytes")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address == "" || strings.ContainsAny(parsed.Address, "\r\n\x00") {
		return "", errors.New("address is invalid")
	}
	return strings.ToLower(parsed.Address), nil
}

func normalizeAllow(candidate AllowEntry, now time.Time) (AllowEntry, compiledAllow, error) {
	if len(candidate.Comment) > 512 || len(candidate.CreatedBy) > 128 {
		return AllowEntry{}, compiledAllow{}, errors.New("greylist allow entry metadata exceeds bounds")
	}
	if !candidate.ExpiresAt.IsZero() && !candidate.ExpiresAt.After(now) {
		return AllowEntry{}, compiledAllow{}, errors.New("greylist allow entry expiry must be in the future")
	}
	entry := candidate
	entry.Comment = strings.TrimSpace(entry.Comment)
	entry.CreatedBy = strings.TrimSpace(entry.CreatedBy)
	entry.ExpiresAt = entry.ExpiresAt.UTC()
	compiled := compiledAllow{}
	switch entry.Kind {
	case AllowSourceCIDR:
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry.Value))
		if err != nil {
			return AllowEntry{}, compiledAllow{}, errors.New("greylist source allow value must be a CIDR prefix")
		}
		prefix = prefix.Masked()
		entry.Value, compiled.prefix = prefix.String(), prefix
	case AllowSender, AllowRecipient:
		value := strings.ToLower(strings.TrimSpace(entry.Value))
		if strings.HasPrefix(value, "@") {
			if len(value) < 4 || len(value) > maxIdentityLen || strings.ContainsAny(value, "\r\n\x00 ") || !strings.Contains(value[1:], ".") {
				return AllowEntry{}, compiledAllow{}, errors.New("greylist domain allow value is invalid")
			}
			entry.Value = value
		} else {
			address, err := canonicalAddress(value, entry.Kind == AllowSender)
			if err != nil {
				return AllowEntry{}, compiledAllow{}, err
			}
			entry.Value = address
		}
	default:
		return AllowEntry{}, compiledAllow{}, errors.New("unsupported greylist allow entry kind")
	}
	digest := sha256.Sum256([]byte(string(entry.Kind) + "\x00" + entry.Value))
	entry.ID = "allow_" + hex.EncodeToString(digest[:16])
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	} else {
		entry.CreatedAt = entry.CreatedAt.UTC()
	}
	compiled.entry = entry
	return entry, compiled, nil
}

func (service *Service) reloadAllows(ctx context.Context) error {
	entries := make([]compiledAllow, 0)
	err := service.store.Iterate(ctx, model.NSGreylisting, allowPrefix, func(key string, value []byte) (bool, error) {
		var candidate AllowEntry
		if err := json.Unmarshal(value, &candidate); err != nil {
			return false, fmt.Errorf("decode greylist allow entry %s: %w", key, err)
		}
		entry, compiled, err := normalizeAllow(candidate, time.Time{})
		if err != nil {
			return false, fmt.Errorf("validate greylist allow entry %s: %w", key, err)
		}
		if key != allowPrefix+entry.ID || candidate.ID != entry.ID {
			return false, fmt.Errorf("greylist allow entry %s has inconsistent identity", key)
		}
		entries = append(entries, compiled)
		return true, nil
	})
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(left, right compiledAllow) int { return strings.Compare(left.entry.ID, right.entry.ID) })
	service.allows.Store(&allowSnapshot{entries: entries})
	return nil
}

func (service *Service) matchAllow(input Triplet, now time.Time) string {
	snapshot := service.allows.Load()
	if snapshot == nil {
		return ""
	}
	remote, _ := netip.ParseAddr(strings.TrimSpace(input.RemoteIP))
	remote = remote.Unmap()
	sender, _ := canonicalAddress(input.EnvelopeFrom, true)
	recipient, _ := canonicalAddress(input.Recipient, false)
	for _, compiled := range snapshot.entries {
		entry := compiled.entry
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		matched := false
		switch entry.Kind {
		case AllowSourceCIDR:
			matched = remote.IsValid() && compiled.prefix.Contains(remote)
		case AllowSender:
			matched = addressAllowMatches(sender, entry.Value)
		case AllowRecipient:
			matched = addressAllowMatches(recipient, entry.Value)
		}
		if matched {
			return entry.ID
		}
	}
	return ""
}

func addressAllowMatches(address, value string) bool {
	if strings.HasPrefix(value, "@") {
		return strings.HasSuffix(address, value)
	}
	return address == value
}

func (service *Service) loadEntry(ctx context.Context, key string) (entry, bool, error) {
	data, err := service.store.Get(ctx, model.NSGreylisting, key)
	if errors.Is(err, store.ErrNotFound) {
		return entry{}, false, nil
	}
	if err != nil {
		return entry{}, false, err
	}
	var current entry
	if err := json.Unmarshal(data, &current); err != nil {
		return entry{}, false, fmt.Errorf("decode greylist triplet: %w", err)
	}
	if current.Version != currentVersion {
		return entry{}, false, fmt.Errorf("unsupported greylist triplet version %d", current.Version)
	}
	return current, true, nil
}

func (service *Service) loadNetwork(ctx context.Context, key string) (networkEntry, bool, error) {
	data, err := service.store.Get(ctx, model.NSGreylisting, key)
	if errors.Is(err, store.ErrNotFound) {
		return networkEntry{}, false, nil
	}
	if err != nil {
		return networkEntry{}, false, err
	}
	var current networkEntry
	if err := json.Unmarshal(data, &current); err != nil {
		return networkEntry{}, false, fmt.Errorf("decode greylist client network: %w", err)
	}
	if current.Version != currentVersion {
		return networkEntry{}, false, fmt.Errorf("unsupported greylist client network version %d", current.Version)
	}
	return current, true, nil
}

func (service *Service) loadStats(ctx context.Context) (Stats, error) {
	data, err := service.store.Get(ctx, model.NSGreylisting, statsKey)
	if err != nil {
		return Stats{}, err
	}
	var stats Stats
	if err := json.Unmarshal(data, &stats); err != nil {
		return Stats{}, fmt.Errorf("decode greylist statistics: %w", err)
	}
	if stats.Version != currentVersion {
		return Stats{}, fmt.Errorf("unsupported greylist statistics version %d", stats.Version)
	}
	return stats, nil
}

func (service *Service) ensureStats(ctx context.Context) error {
	initial, _ := json.Marshal(Stats{Version: currentVersion})
	if err := service.store.Put(ctx, model.NSGreylisting, statsKey, initial); err != nil && !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("initialize greylist statistics: %w", err)
	}
	_, err := service.loadStats(ctx)
	return err
}

func (service *Service) updateStats(ctx context.Context, now time.Time, update func(*Stats)) error {
	return store.Batch(ctx, service.store, func(batchCtx context.Context) error {
		stats, err := service.loadStats(batchCtx)
		if err != nil {
			return err
		}
		update(&stats)
		stats.LastCheckAt = now
		return setJSON(batchCtx, service.store, statsKey, stats)
	})
}

func setJSON(ctx context.Context, backend store.Store, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return backend.Set(ctx, model.NSGreylisting, key, data)
}

func ensureNamespace(ctx context.Context, backend store.Store) error {
	exists, err := backend.NamespaceExists(ctx, model.NSGreylisting)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := backend.CreateNamespace(ctx, model.NSGreylisting); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return nil
}
