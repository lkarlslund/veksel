// Package ban is the built-in abuse auto-ban engine. Abuse signals (failed
// logins, second-factor failures, unknown-recipient harvesting, SMTP protocol
// errors) are counted as strikes per client network; a network reaching a
// trigger's threshold within its window is banned for an escalating duration.
// Banned clients are refused at mail connection accept and HTTP request
// entry, always by their effective client IP (after PROXY protocol and
// trusted-proxy resolution).
//
// Bans are durable in the system store and survive restarts. Lookup is an
// in-memory map probed once per distinct banned prefix length, so admission
// cost does not grow with the size of the ban table.
package ban

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleRateLimit)

// Trigger names the abuse signal behind a strike or ban.
type Trigger string

const (
	TriggerAuth         Trigger = "auth_failure"
	TriggerSecondFactor Trigger = "second_factor_failure"
	TriggerRecipient    Trigger = "rcpt_unknown"
	TriggerProtocol     Trigger = "protocol_error"
	// TriggerSpamtrap counts unauthenticated mail to an admin-defined
	// spamtrap address, which no legitimate sender knows.
	TriggerSpamtrap Trigger = "spamtrap"
	TriggerManual   Trigger = "manual"
)

// Ban sources.
const (
	SourceAutomatic = "automatic"
	SourceManual    = "manual"
)

const (
	// MaxActive bounds the ban table; automatic bans beyond it are skipped.
	MaxActive = 100_000
	// AbnormalActive is the active ban count at which health reports a
	// warning; ordinary internet background noise stays far below it.
	AbnormalActive = 10_000
	// offenseMemory is how long an expired ban still counts toward the
	// escalation of the next one.
	offenseMemory = 30 * 24 * time.Hour
	// maxTracked bounds the in-memory strike and success windows.
	maxTracked = 200_000
	// maxManualDuration bounds a manual ban.
	maxManualDuration = 3650 * 24 * time.Hour
)

var (
	// ErrExempt reports a manual ban that would cover an exempt network.
	ErrExempt = errors.New("the network is exempt from bans")
	// ErrNotFound reports an unban of a network that is not banned.
	ErrNotFound = errors.New("ban not found")
)

// Reporter receives abuse strikes against a client IP. Protocol servers hold
// one so they need not know about bans; *Service implements it.
type Reporter interface {
	Strike(ip string, trigger Trigger)
}

// Rule is a trigger threshold: Count strikes within Window ban the client
// network. A zero Count disables the trigger.
type Rule struct {
	Count  int
	Window time.Duration
}

// Policy is the live configuration of the engine.
type Policy struct {
	// Enabled turns automatic banning and enforcement on. While disabled no
	// strikes are counted and no ban is enforced; the table is kept.
	Enabled bool
	Rules   map[Trigger]Rule
	// Durations are the ban lengths of a network's first, second, and later
	// offenses; the last one repeats.
	Durations []time.Duration
	// IPv6Prefix groups IPv6 clients into one banned network; IPv4 clients
	// are always banned as single addresses.
	IPv6Prefix int
	// Exempt networks are never struck, banned, or refused.
	Exempt []netip.Prefix
}

// DefaultPolicy returns the built-in defaults, matching the default
// configuration.
func DefaultPolicy() Policy {
	return Policy{
		Enabled: true,
		Rules: map[Trigger]Rule{
			TriggerAuth: {20, 10 * time.Minute}, TriggerSecondFactor: {10, 10 * time.Minute},
			TriggerRecipient: {20, 10 * time.Minute}, TriggerProtocol: {30, 10 * time.Minute},
			TriggerSpamtrap: {1, 24 * time.Hour},
		},
		Durations:  []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour},
		IPv6Prefix: 64,
	}
}

// network returns the banned network of addr under p.
func (p *Policy) network(addr netip.Addr) netip.Prefix {
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	prefix, _ := addr.Prefix(min(max(p.IPv6Prefix, 0), 128))
	return prefix
}

// duration returns the ban length of a network's offense-th offense.
func (p *Policy) duration(offense int) time.Duration {
	if len(p.Durations) == 0 {
		return 10 * time.Minute
	}
	return p.Durations[min(max(offense, 1), len(p.Durations))-1]
}

// Ban is one banned network as listed and persisted.
type Ban struct {
	Prefix    string    `json:"prefix"`
	Reason    Trigger   `json:"reason"`
	Source    string    `json:"source"`
	Actor     string    `json:"actor,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	Strikes   int       `json:"strikes,omitempty"`
	Offense   int       `json:"offense"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Hits      uint64    `json:"hits"`
	LastHitAt time.Time `json:"last_hit_at,omitzero"`
}

// Active reports whether the ban is in force at now.
func (b Ban) Active(now time.Time) bool { return now.Before(b.ExpiresAt) }

// record is the in-memory form of a Ban; refused connections update the hit
// counters without taking the table lock for writing.
type record struct {
	ban     Ban
	prefix  netip.Prefix
	hits    atomic.Uint64
	lastHit atomic.Int64
	dirty   atomic.Bool
}

func (r *record) snapshot() Ban {
	ban := r.ban
	ban.Hits = r.hits.Load()
	if last := r.lastHit.Load(); last != 0 {
		ban.LastHitAt = time.Unix(0, last).UTC()
	}
	return ban
}

type strikeKey struct {
	network netip.Prefix
	trigger Trigger
}

// Auditor records ban and unban events; *audit.Logger implements it.
type Auditor interface {
	Log(actor, action, target string, details map[string]string)
}

// Metrics receives ban counters and gauges; *metrics.Metrics implements it.
type Metrics interface {
	IncrementCounter(name string, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
}

// Service is the abuse ban engine. A nil *Service bans nothing.
type Service struct {
	store   store.Store
	audit   Auditor
	metrics Metrics
	now     func() time.Time
	policy  atomic.Pointer[Policy]
	exempt  atomic.Pointer[func(netip.Addr) bool]

	mu      sync.RWMutex
	records map[netip.Prefix]*record
	// lengths lists the distinct prefix lengths of active bans for IPv4
	// (index 0) and IPv6 (index 1).
	lengths [2][]int
	active  int
	strikes map[strikeKey][]time.Time
	// trusted records each network's latest successful login; strikes are
	// ignored for the trigger window after it.
	trusted map[netip.Prefix]time.Time
	// persist serializes store writes so they land in decision order.
	persist sync.Mutex
}

// New loads the durable ban table from backend. audit and metrics may be nil.
func New(ctx context.Context, backend store.Store, audit Auditor, metrics Metrics, policy Policy) (*Service, error) {
	s := &Service{
		store: backend, audit: audit, metrics: metrics, now: time.Now,
		records: make(map[netip.Prefix]*record), strikes: make(map[strikeKey][]time.Time), trusted: make(map[netip.Prefix]time.Time),
	}
	s.Configure(policy)
	if err := backend.CreateNamespace(ctx, model.NSBans); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, fmt.Errorf("create ban namespace: %w", err)
	}
	err := backend.Iterate(ctx, model.NSBans, "", func(key string, value []byte) (bool, error) {
		var ban Ban
		if err := json.Unmarshal(value, &ban); err != nil {
			log.Warn("ban: skipping unreadable ban record", "key", key, "error", err)
			return true, nil
		}
		prefix, err := netip.ParsePrefix(ban.Prefix)
		if err != nil {
			log.Warn("ban: skipping ban record with invalid prefix", "key", key, "prefix", ban.Prefix)
			return true, nil
		}
		s.records[prefix] = newRecord(ban, prefix)
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("load bans: %w", err)
	}
	s.mu.Lock()
	s.reindexLocked()
	s.mu.Unlock()
	return s, nil
}

func newRecord(ban Ban, prefix netip.Prefix) *record {
	r := &record{ban: ban, prefix: prefix}
	r.hits.Store(ban.Hits)
	if !ban.LastHitAt.IsZero() {
		r.lastHit.Store(ban.LastHitAt.UnixNano())
	}
	return r
}

// SetClock replaces the time source for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Configure replaces the live policy. Thresholds and exemptions apply to the
// next strike and check; durations and the IPv6 prefix apply to new bans.
func (s *Service) Configure(policy Policy) {
	policy.Rules = maps.Clone(policy.Rules)
	policy.Durations = slices.Clone(policy.Durations)
	policy.Exempt = slices.Clone(policy.Exempt)
	s.policy.Store(&policy)
}

// Policy returns the live policy.
func (s *Service) Policy() Policy { return *s.policy.Load() }

// SetExemptCheck adds a live exemption test consulted with the policy's
// exempt networks, such as the HTTP trusted-proxy resolver.
func (s *Service) SetExemptCheck(check func(netip.Addr) bool) {
	if s == nil {
		return
	}
	if check == nil {
		s.exempt.Store(nil)
		return
	}
	s.exempt.Store(&check)
}

// parseIP returns the unmapped address of ip, a bare address or host:port.
func parseIP(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		addrPort, portErr := netip.ParseAddrPort(ip)
		if portErr != nil {
			return netip.Addr{}, false
		}
		addr = addrPort.Addr()
	}
	addr = addr.WithZone("").Unmap()
	return addr, addr.IsValid() && !addr.IsUnspecified()
}

// exemptAddr reports whether addr may never be struck, banned, or refused.
func (s *Service) exemptAddr(policy *Policy, addr netip.Addr) bool {
	if addr.IsLoopback() || slices.ContainsFunc(policy.Exempt, func(prefix netip.Prefix) bool { return prefix.Contains(addr) }) {
		return true
	}
	check := s.exempt.Load()
	return check != nil && (*check)(addr)
}

// Banned reports whether ip is refused, counting the refusal as a hit on its
// ban and in the ban_refused_total metric for surface. Exempt and unknown
// addresses are never refused.
func (s *Service) Banned(ip, surface string) bool {
	if s == nil {
		return false
	}
	policy := s.policy.Load()
	if !policy.Enabled {
		return false
	}
	addr, ok := parseIP(ip)
	if !ok {
		return false
	}
	now := s.now()
	family := 0
	if addr.Is6() {
		family = 1
	}
	s.mu.RLock()
	var hit *record
	for _, bits := range s.lengths[family] {
		prefix, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if r, ok := s.records[prefix]; ok && r.ban.Active(now) {
			hit = r
			break
		}
	}
	s.mu.RUnlock()
	if hit == nil || s.exemptAddr(policy, addr) {
		return false
	}
	hit.hits.Add(1)
	hit.lastHit.Store(now.UnixNano())
	hit.dirty.Store(true)
	if s.metrics != nil {
		s.metrics.IncrementCounter("ban_refused_total", map[string]string{"surface": surface})
	}
	return true
}

// Strike counts one abuse signal from ip. A network reaching the trigger's
// threshold within its window is banned. Strikes from exempt addresses,
// already banned networks, and networks with a recent successful login are
// ignored.
func (s *Service) Strike(ip string, trigger Trigger) {
	if s == nil {
		return
	}
	policy := s.policy.Load()
	rule := policy.Rules[trigger]
	if !policy.Enabled || rule.Count <= 0 {
		return
	}
	addr, ok := parseIP(ip)
	if !ok || s.exemptAddr(policy, addr) {
		return
	}
	network := policy.network(addr)
	now := s.now()
	s.mu.Lock()
	if last, ok := s.trusted[network]; ok && now.Before(last.Add(rule.Window)) {
		s.mu.Unlock()
		return
	}
	if r, ok := s.records[network]; ok && r.ban.Active(now) {
		s.mu.Unlock()
		return
	}
	key := strikeKey{network, trigger}
	times, tracked := s.strikes[key]
	if !tracked && len(s.strikes) >= maxTracked {
		s.mu.Unlock()
		log.Warn("ban: strike table full; ignoring strike", "network", network.String(), "trigger", string(trigger))
		return
	}
	cutoff := now.Add(-rule.Window)
	times = slices.DeleteFunc(times, func(at time.Time) bool { return !at.After(cutoff) })
	times = append(times, now)
	if len(times) < rule.Count {
		s.strikes[key] = times
		s.mu.Unlock()
		return
	}
	delete(s.strikes, key)
	ban, created := s.banLocked(policy, network, now, Ban{Reason: trigger, Source: SourceAutomatic, Strikes: len(times)}, 0)
	s.mu.Unlock()
	if !created {
		return
	}
	log.Warn("ban: client network banned", "network", ban.Prefix, "reason", string(trigger), "strikes", ban.Strikes, "offense", ban.Offense, "expires", ban.ExpiresAt)
	s.save(context.Background(), ban)
	s.recordBan(ban, "system")
}

// Success records a successful login from ip: its network's strikes are
// cleared and further strikes are ignored for each trigger's window.
func (s *Service) Success(ip string) {
	if s == nil {
		return
	}
	addr, ok := parseIP(ip)
	if !ok {
		return
	}
	policy := s.policy.Load()
	network := policy.network(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	for trigger := range policy.Rules {
		delete(s.strikes, strikeKey{network, trigger})
	}
	if _, tracked := s.trusted[network]; tracked || len(s.trusted) < maxTracked {
		s.trusted[network] = s.now()
	}
}

// banLocked bans network from now, escalating from its previous offense. A
// zero duration uses the escalation schedule. It returns false when the ban
// table is full.
func (s *Service) banLocked(policy *Policy, network netip.Prefix, now time.Time, ban Ban, duration time.Duration) (Ban, bool) {
	previous, exists := s.records[network]
	if !exists && s.active >= MaxActive {
		log.Warn("ban: ban table full; not banning", "network", network.String(), "limit", MaxActive)
		return Ban{}, false
	}
	ban.Offense = 1
	if exists && now.Before(previous.ban.ExpiresAt.Add(offenseMemory)) {
		ban.Offense = previous.ban.Offense + 1
	}
	if duration <= 0 {
		duration = policy.duration(ban.Offense)
	}
	ban.Prefix, ban.CreatedAt, ban.ExpiresAt = network.String(), now.UTC(), now.Add(duration).UTC()
	s.records[network] = newRecord(ban, network)
	s.reindexLocked()
	return ban, true
}

// reindexLocked recomputes the active prefix lengths and count.
func (s *Service) reindexLocked() {
	now := s.now()
	seen := [2]map[int]bool{{}, {}}
	active := 0
	for prefix, r := range s.records {
		if !r.ban.Active(now) {
			continue
		}
		active++
		family := 0
		if prefix.Addr().Is6() {
			family = 1
		}
		seen[family][prefix.Bits()] = true
	}
	for family := range seen {
		lengths := make([]int, 0, len(seen[family]))
		for bits := range seen[family] {
			lengths = append(lengths, bits)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(lengths)))
		s.lengths[family] = lengths
	}
	s.active = active
	if s.metrics != nil {
		s.metrics.SetGauge("ban_active", float64(active), nil)
	}
}

// save persists ban; a failure leaves the in-memory ban in force.
func (s *Service) save(ctx context.Context, ban Ban) {
	data, err := json.Marshal(ban)
	if err != nil {
		return
	}
	s.persist.Lock()
	defer s.persist.Unlock()
	if err := s.store.Set(ctx, model.NSBans, ban.Prefix, data); err != nil {
		log.Error("ban: persist ban", "network", ban.Prefix, "error", err)
	}
}

func (s *Service) recordBan(ban Ban, actor string) {
	if s.metrics != nil {
		s.metrics.IncrementCounter("ban_created_total", map[string]string{"reason": string(ban.Reason)})
	}
	if s.audit != nil {
		details := map[string]string{
			"reason": string(ban.Reason), "source": ban.Source, "offense": strconv.Itoa(ban.Offense),
			"expires_at": ban.ExpiresAt.Format(time.RFC3339),
		}
		if ban.Strikes > 0 {
			details["strikes"] = strconv.Itoa(ban.Strikes)
		}
		if ban.Comment != "" {
			details["comment"] = ban.Comment
		}
		s.audit.Log(actor, "security.ban.add", ban.Prefix, details)
	}
}

// ParseNetwork parses an IP address (a single-host network) or CIDR prefix
// for a manual ban or unban.
func ParseNetwork(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		addr, ok := parseIP(value)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("invalid IP address %q", value)
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid network %q", value)
	}
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// Ban manually bans network for duration (zero follows the escalation
// schedule). Networks overlapping loopback or an exempt network are refused
// with ErrExempt.
func (s *Service) Ban(ctx context.Context, network netip.Prefix, duration time.Duration, actor, comment string) (Ban, error) {
	if duration < 0 || duration > maxManualDuration {
		return Ban{}, fmt.Errorf("ban duration must be at most %d days", int(maxManualDuration/(24*time.Hour)))
	}
	if !network.IsValid() || network.Addr().IsUnspecified() && network.Bits() == 0 {
		return Ban{}, errors.New("a specific network is required")
	}
	network = network.Masked()
	policy := s.policy.Load()
	if slices.ContainsFunc(append(slices.Clone(loopback), policy.Exempt...), network.Overlaps) || s.exemptAddr(policy, network.Addr()) {
		return Ban{}, ErrExempt
	}
	s.mu.Lock()
	ban, created := s.banLocked(policy, network, s.now(), Ban{Reason: TriggerManual, Source: SourceManual, Actor: actor, Comment: strings.TrimSpace(comment)}, duration)
	s.mu.Unlock()
	if !created {
		return Ban{}, fmt.Errorf("the ban table is full (%d bans)", MaxActive)
	}
	s.save(ctx, ban)
	s.recordBan(ban, actor)
	return ban, nil
}

// Unban lifts the ban on network and forgets its offense history.
func (s *Service) Unban(ctx context.Context, network netip.Prefix, actor string) error {
	network = network.Masked()
	s.mu.Lock()
	r, ok := s.records[network]
	if !ok || !r.ban.Active(s.now()) {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.records, network)
	s.reindexLocked()
	s.mu.Unlock()
	s.persist.Lock()
	err := s.store.Delete(ctx, model.NSBans, network.String())
	s.persist.Unlock()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("delete ban: %w", err)
	}
	if s.audit != nil {
		s.audit.Log(actor, "security.ban.remove", network.String(), map[string]string{"reason": string(r.ban.Reason), "hits": strconv.FormatUint(r.hits.Load(), 10)})
	}
	return nil
}

// List returns the active bans whose network, reason, source, actor, or
// comment contains query (case-insensitive), newest first.
func (s *Service) List(query string) []Ban {
	if s == nil {
		return nil
	}
	query = strings.ToLower(strings.TrimSpace(query))
	now := s.now()
	s.mu.RLock()
	bans := make([]Ban, 0, s.active)
	for _, r := range s.records {
		if !r.ban.Active(now) {
			continue
		}
		ban := r.snapshot()
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{ban.Prefix, string(ban.Reason), ban.Source, ban.Actor, ban.Comment}, " ")), query) {
			continue
		}
		bans = append(bans, ban)
	}
	s.mu.RUnlock()
	sort.Slice(bans, func(i, j int) bool {
		if !bans[i].CreatedAt.Equal(bans[j].CreatedAt) {
			return bans[i].CreatedAt.After(bans[j].CreatedAt)
		}
		return bans[i].Prefix < bans[j].Prefix
	})
	return bans
}

// Active returns the number of bans in force.
func (s *Service) Active() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Maintain expires bans, forgets offense history older than its memory,
// prunes stale strike and success windows, and persists hit counters. Run it
// periodically.
func (s *Service) Maintain(ctx context.Context) {
	if s == nil {
		return
	}
	now := s.now()
	policy := s.policy.Load()
	longest := time.Duration(0)
	for _, rule := range policy.Rules {
		longest = max(longest, rule.Window)
	}
	var forget []string
	var dirty []*record
	s.mu.Lock()
	for prefix, r := range s.records {
		if !now.Before(r.ban.ExpiresAt.Add(offenseMemory)) {
			delete(s.records, prefix)
			forget = append(forget, prefix.String())
			continue
		}
		if r.dirty.Swap(false) {
			dirty = append(dirty, r)
		}
	}
	for key, times := range s.strikes {
		if len(times) == 0 || !now.Before(times[len(times)-1].Add(longest)) {
			delete(s.strikes, key)
		}
	}
	for network, at := range s.trusted {
		if !now.Before(at.Add(longest)) {
			delete(s.trusted, network)
		}
	}
	s.reindexLocked()
	s.mu.Unlock()
	for _, r := range dirty {
		// A network re-banned meanwhile saved its new record itself.
		s.mu.RLock()
		current := s.records[r.prefix] == r
		s.mu.RUnlock()
		if current {
			s.save(ctx, r.snapshot())
		}
	}
	s.persist.Lock()
	defer s.persist.Unlock()
	for _, key := range forget {
		if err := s.store.Delete(ctx, model.NSBans, key); err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Error("ban: forget expired ban", "network", key, "error", err)
		}
	}
}
