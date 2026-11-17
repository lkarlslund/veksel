package spam

import (
	"container/list"
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Reputation defaults. A sender needs the minimum number of decayed samples
// before it scores, and its confidence reaches one at four times that.
const (
	DefaultReputationMinSamples = 20
	DefaultReputationMaxEntries = 50_000
	DefaultReputationHalfLife   = 30 * 24 * time.Hour

	// ReputationHeader carries the reputation keys a delivery was judged
	// under, so a later Junk move or quarantine release can credit them. It
	// holds only the authenticated domain and sending network.
	ReputationHeader = "X-Veksel-Reputation"

	reputationConfidenceSpan = 4
	reputationBadRatio       = 0.6
	reputationGoodRatio      = 0.1
	// reputationUserWeight scales an explicit user action or a release
	// against one automatic outcome.
	reputationUserWeight = 3
)

// ReputationEvent is one outcome observed for a sender.
type ReputationEvent uint8

const (
	// RepAccepted is a message scored below the Junk threshold.
	RepAccepted ReputationEvent = iota
	// RepJunked is a message whose score reached the Junk threshold.
	RepJunked
	// RepRejected is a message rejected at the reject threshold.
	RepRejected
	// RepUserJunk is a user moving a delivered message into Junk.
	RepUserJunk
	// RepUserHam is a user moving a message out of Junk.
	RepUserHam
	// RepReleased is a quarantined message released by its owner.
	RepReleased
)

// ReputationCounts are decayed event counts.
type ReputationCounts struct {
	Accepted float64 `json:"accepted"`
	Junked   float64 `json:"junked"`
	Rejected float64 `json:"rejected"`
	UserJunk float64 `json:"user_junk"`
	UserHam  float64 `json:"user_ham"`
	Released float64 `json:"released"`
}

func (c *ReputationCounts) add(event ReputationEvent) {
	switch event {
	case RepAccepted:
		c.Accepted++
	case RepJunked:
		c.Junked++
	case RepRejected:
		c.Rejected++
	case RepUserJunk:
		c.UserJunk++
	case RepUserHam:
		c.UserHam++
	case RepReleased:
		c.Released++
	}
}

func (c *ReputationCounts) scale(factor float64) {
	c.Accepted *= factor
	c.Junked *= factor
	c.Rejected *= factor
	c.UserJunk *= factor
	c.UserHam *= factor
	c.Released *= factor
}

// weights returns the evidence for and against the sender.
func (c ReputationCounts) weights() (good, bad float64) {
	good = c.Accepted + reputationUserWeight*(c.UserHam+c.Released)
	bad = c.Junked + c.Rejected + reputationUserWeight*c.UserJunk
	return good, bad
}

// ReputationKeys identify the sender of one delivery: its authenticated
// domain and the /24 or /48 network of the connecting address. Either may
// be empty.
type ReputationKeys struct {
	Domain  string `json:"domain,omitempty"`
	Network string `json:"network,omitempty"`
}

// Header renders the keys for ReputationHeader; empty without keys.
func (k ReputationKeys) Header() string {
	var parts []string
	if k.Domain != "" {
		parts = append(parts, "d="+k.Domain)
	}
	if k.Network != "" {
		parts = append(parts, "n="+k.Network)
	}
	return strings.Join(parts, "; ")
}

// ParseReputationKeys reads a ReputationHeader value, ignoring anything
// malformed.
func ParseReputationKeys(value string) ReputationKeys {
	var keys ReputationKeys
	for part := range strings.SplitSeq(value, ";") {
		name, text, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch name {
		case "d":
			keys.Domain = normalizeReputationDomain(text)
		case "n":
			if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Bits() == networkBits(prefix.Addr()) {
				keys.Network = prefix.Masked().String()
			}
		}
	}
	return keys
}

func networkBits(addr netip.Addr) int {
	if addr.Is4() {
		return 24
	}
	return 48
}

// ReputationNetwork returns the /24 (IPv4) or /48 (IPv6) containing ip, or
// empty when ip is not an address.
func ReputationNetwork(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	prefix, err := addr.Prefix(networkBits(addr))
	if err != nil {
		return ""
	}
	return prefix.String()
}

func normalizeReputationDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, " ;=,<>@\r\n\t") {
		return ""
	}
	return domain
}

// Reputation is the server-wide, privacy-bounded sender reputation: decayed
// counts per authenticated sending domain and per sending network, never
// per address, user, or message. Its zero value is enabled with the default
// bounds and clock; it is safe for concurrent use.
type Reputation struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   list.List // front is most recently updated

	disabled   atomic.Bool
	minSamples atomic.Int64

	// MaxEntries, HalfLife, and Now are fixed before first use; zero values
	// use the defaults.
	MaxEntries int
	HalfLife   time.Duration
	Now        func() time.Time
}

type reputationEntry struct {
	key     string
	counts  ReputationCounts
	updated time.Time
}

// SetSettings applies the live switches: whether reputation records and
// scores, and the decayed sample count a sender needs before it scores.
func (r *Reputation) SetSettings(enabled bool, minSamples int) {
	r.disabled.Store(!enabled)
	r.minSamples.Store(int64(minSamples))
}

// Enabled reports whether reputation records and scores.
func (r *Reputation) Enabled() bool { return r != nil && !r.disabled.Load() }

// MinSamples is the decayed sample count a sender needs before it scores.
func (r *Reputation) MinSamples() int {
	if minimum := int(r.minSamples.Load()); minimum > 0 {
		return minimum
	}
	return DefaultReputationMinSamples
}

func (r *Reputation) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reputation) limit() int {
	if r.MaxEntries > 0 {
		return r.MaxEntries
	}
	return DefaultReputationMaxEntries
}

func (r *Reputation) halfLife() time.Duration {
	if r.HalfLife > 0 {
		return r.HalfLife
	}
	return DefaultReputationHalfLife
}

// decayed returns entry's counts as they stand at now.
func (r *Reputation) decayed(entry *reputationEntry, now time.Time) ReputationCounts {
	counts := entry.counts
	if elapsed := now.Sub(entry.updated); elapsed > 0 {
		counts.scale(math.Exp2(-float64(elapsed) / float64(r.halfLife())))
	}
	return counts
}

// Record adds event for the keys of one delivery.
func (r *Reputation) Record(keys ReputationKeys, event ReputationEvent) {
	if !r.Enabled() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if keys.Domain != "" {
		r.recordLocked("d:"+keys.Domain, event)
	}
	if keys.Network != "" {
		r.recordLocked("n:"+keys.Network, event)
	}
}

func (r *Reputation) recordLocked(key string, event ReputationEvent) {
	now := r.now()
	if r.entries == nil {
		r.entries = make(map[string]*list.Element)
	}
	element, found := r.entries[key]
	if !found {
		element = r.order.PushFront(&reputationEntry{key: key, updated: now})
		r.entries[key] = element
	} else {
		r.order.MoveToFront(element)
	}
	entry := element.Value.(*reputationEntry)
	entry.counts = r.decayed(entry, now)
	entry.updated = now
	entry.counts.add(event)
	r.evictLocked()
}

func (r *Reputation) evictLocked() {
	for r.order.Len() > r.limit() {
		oldest := r.order.Back()
		delete(r.entries, oldest.Value.(*reputationEntry).key)
		r.order.Remove(oldest)
	}
}

// Moved credits a user's explicit Junk (junk) or Not-junk move of a
// delivered message to the sender its ReputationHeader names.
func (r *Reputation) Moved(headers map[string]string, junk bool) {
	event := RepUserHam
	if junk {
		event = RepUserJunk
	}
	r.Record(ParseReputationKeys(headerValue(headers, ReputationHeader)), event)
}

// Released credits the owner releasing a quarantined message.
func (r *Reputation) Released(headers map[string]string) {
	r.Record(ParseReputationKeys(headerValue(headers, ReputationHeader)), RepReleased)
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// Signal is a reputation verdict the engine turns into a symbol: the
// symbol's configured score is multiplied by Scale, a confidence and
// severity in (0, 1].
type Signal struct {
	Symbol  string
	Scale   float64
	Options []string
}

// Assess returns the reputation signals for keys. Senders below the minimum
// sample count produce none.
func (r *Reputation) Assess(keys ReputationKeys) []Signal {
	if !r.Enabled() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var signals []Signal
	if signal, ok := r.assessLocked("d:"+keys.Domain, keys.Domain != "", "REP_DOMAIN_BAD", "REP_DOMAIN_GOOD"); ok {
		signals = append(signals, signal)
	}
	if signal, ok := r.assessLocked("n:"+keys.Network, keys.Network != "", "REP_IP_BAD", ""); ok {
		signals = append(signals, signal)
	}
	return signals
}

func (r *Reputation) assessLocked(key string, present bool, badSymbol, goodSymbol string) (Signal, bool) {
	element, found := r.entries[key]
	if !present || !found {
		return Signal{}, false
	}
	good, bad := r.decayed(element.Value.(*reputationEntry), r.now()).weights()
	samples := good + bad
	minimum := float64(r.MinSamples())
	if samples < minimum {
		return Signal{}, false
	}
	confidence := min(1, samples/(reputationConfidenceSpan*minimum))
	ratio := bad / samples
	options := []string{"samples=" + formatScore(samples), "bad=" + formatScore(math.Round(ratio*100)) + "%"}
	switch {
	case ratio >= reputationBadRatio:
		return Signal{Symbol: badSymbol, Scale: confidence * (ratio - 0.5) / 0.5, Options: options}, true
	case ratio <= reputationGoodRatio && goodSymbol != "":
		return Signal{Symbol: goodSymbol, Scale: confidence, Options: options}, true
	}
	return Signal{}, false
}

// ReputationEntry is one sender in an administrator's listing.
type ReputationEntry struct {
	Key string `json:"key"`
	ReputationCounts
	// Samples and BadRatio are the decayed evidence and the share of it
	// against the sender.
	Samples  float64   `json:"samples"`
	BadRatio float64   `json:"bad_ratio"`
	Updated  time.Time `json:"updated"`
}

// ReputationReport lists the senders with the best and worst standing among
// those with enough samples to score.
type ReputationReport struct {
	Enabled      bool              `json:"enabled"`
	MinSamples   int               `json:"min_samples"`
	Tracked      int               `json:"tracked"`
	GoodDomains  []ReputationEntry `json:"good_domains"`
	BadDomains   []ReputationEntry `json:"bad_domains"`
	GoodNetworks []ReputationEntry `json:"good_networks"`
	BadNetworks  []ReputationEntry `json:"bad_networks"`
}

// Report returns at most limit entries per list.
func (r *Reputation) Report(limit int) ReputationReport {
	report := ReputationReport{Enabled: r.Enabled(), MinSamples: r.MinSamples()}
	minimum := float64(report.MinSamples)
	var domains, networks []ReputationEntry
	r.mu.Lock()
	report.Tracked = len(r.entries)
	now := r.now()
	for key, element := range r.entries {
		entry := element.Value.(*reputationEntry)
		counts := r.decayed(entry, now)
		good, bad := counts.weights()
		if samples := good + bad; samples >= minimum {
			item := ReputationEntry{Key: key[2:], ReputationCounts: counts, Samples: samples, BadRatio: bad / samples, Updated: entry.updated}
			if strings.HasPrefix(key, "d:") {
				domains = append(domains, item)
			} else {
				networks = append(networks, item)
			}
		}
	}
	r.mu.Unlock()
	top := func(items []ReputationEntry, worst bool) []ReputationEntry {
		standing := func(e ReputationEntry) float64 {
			if worst {
				return e.BadRatio * e.Samples
			}
			return (1 - e.BadRatio) * e.Samples
		}
		slices.SortFunc(items, func(a, b ReputationEntry) int {
			if sa, sb := standing(a), standing(b); sa != sb {
				if sa > sb {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Key, b.Key)
		})
		result := slices.Clone(items)
		if limit > 0 && len(result) > limit {
			result = result[:limit]
		}
		if result == nil {
			result = []ReputationEntry{}
		}
		return result
	}
	report.GoodDomains, report.BadDomains = top(domains, false), top(domains, true)
	report.GoodNetworks, report.BadNetworks = top(networks, false), top(networks, true)
	return report
}

// Reset forgets every sender.
func (r *Reputation) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = nil
	r.order.Init()
}

type reputationSnapshot struct {
	Key     string           `json:"k"`
	Counts  ReputationCounts `json:"c"`
	Updated time.Time        `json:"u"`
}

// Snapshot serializes the store, least recently updated first so Restore
// rebuilds the same order.
func (r *Reputation) Snapshot() ([]byte, error) {
	r.mu.Lock()
	snapshot := make([]reputationSnapshot, 0, len(r.entries))
	for element := r.order.Back(); element != nil; element = element.Prev() {
		entry := element.Value.(*reputationEntry)
		snapshot = append(snapshot, reputationSnapshot{Key: entry.key, Counts: entry.counts, Updated: entry.updated})
	}
	r.mu.Unlock()
	return json.Marshal(snapshot)
}

// Restore replaces the store with a Snapshot, keeping at most MaxEntries of
// the most recently updated senders.
func (r *Reputation) Restore(data []byte) error {
	var snapshot []reputationSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[string]*list.Element, len(snapshot))
	r.order.Init()
	for _, item := range snapshot {
		valid := strings.HasPrefix(item.Key, "d:") || strings.HasPrefix(item.Key, "n:")
		if _, duplicate := r.entries[item.Key]; !valid || duplicate || len(item.Key) > 260 {
			continue
		}
		r.entries[item.Key] = r.order.PushFront(&reputationEntry{key: item.Key, counts: item.Counts, updated: item.Updated})
	}
	r.evictLocked()
	return nil
}
