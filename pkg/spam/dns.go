package spam

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver looks up the A records of a blocklist query name. *net.Resolver
// implements it.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DNSOptions bound the shared blocklist lookup layer. Zero values select
// the defaults.
type DNSOptions struct {
	// QueryTimeout bounds one lookup (default 2s).
	QueryTimeout time.Duration
	// Concurrency bounds simultaneous lookups for one message (default 16).
	Concurrency int
	// PositiveTTL and NegativeTTL bound how long listed and unlisted answers
	// are reused (defaults 10 and 5 minutes). Failures are never cached.
	PositiveTTL time.Duration
	NegativeTTL time.Duration
	// MaxEntries bounds the cache (default 50000).
	MaxEntries int
	Observer   Observer
	Now        func() time.Time
}

// DNS is the shared, cached blocklist lookup layer. It outlives engine
// reconfiguration so its cache and per-zone health persist; replacing the
// resolver clears the cache, because answers from a refusing public
// resolver must not outlive it.
type DNS struct {
	options  DNSOptions
	resolver atomic.Pointer[resolverBox]

	mu    sync.Mutex
	cache map[string]cacheEntry

	statsMu sync.Mutex
	stats   map[string]*ZoneStats
}

type resolverBox struct {
	resolver Resolver
	address  string
}

type cacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// ZoneStats are the counters and recent outcomes for one zone.
type ZoneStats struct {
	Zone          string    `json:"zone"`
	Kind          ZoneKind  `json:"kind"`
	Lookups       uint64    `json:"lookups"`
	CacheHits     uint64    `json:"cache_hits"`
	Listed        uint64    `json:"listed"`
	Errors        uint64    `json:"errors"`
	Refused       uint64    `json:"refused"`
	LastError     string    `json:"last_error,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitzero"`
	LastRefusedAt time.Time `json:"last_refused_at,omitzero"`
	LastSuccessAt time.Time `json:"last_success_at,omitzero"`
	LastListedAt  time.Time `json:"last_listed_at,omitzero"`
}

// NewDNS creates the lookup layer with resolver, which may be replaced later.
func NewDNS(resolver Resolver, options DNSOptions) *DNS {
	if options.QueryTimeout <= 0 {
		options.QueryTimeout = 2 * time.Second
	}
	if options.Concurrency <= 0 {
		options.Concurrency = 16
	}
	if options.PositiveTTL <= 0 {
		options.PositiveTTL = 10 * time.Minute
	}
	if options.NegativeTTL <= 0 {
		options.NegativeTTL = 5 * time.Minute
	}
	if options.MaxEntries <= 0 {
		options.MaxEntries = 50_000
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	d := &DNS{options: options, cache: make(map[string]cacheEntry), stats: make(map[string]*ZoneStats)}
	d.resolver.Store(&resolverBox{resolver: resolver})
	return d
}

// NewResolver returns the system resolver for an empty address, or a
// resolver that sends every query to address (host or host:port, port 53
// by default). Blocklists refuse queries relayed through large public
// resolvers, so production servers should name a local caching resolver.
func NewResolver(address string) (Resolver, error) {
	address, err := ResolverAddress(address)
	if err != nil || address == "" {
		return net.DefaultResolver, err
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}}, nil
}

// ResolverAddress validates and normalizes a resolver address to
// host:port; empty stays empty and selects the system resolver.
func ResolverAddress(address string) (string, error) {
	if address == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, "53"
	}
	number, portErr := strconv.Atoi(port)
	if _, ipErr := netip.ParseAddr(host); ipErr != nil || portErr != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("resolver %q must be an IP address with an optional port", address)
	}
	return net.JoinHostPort(host, port), nil
}

// SetResolver installs resolver for address and clears the cache when the
// address changes.
func (d *DNS) SetResolver(resolver Resolver, address string) {
	if current := d.resolver.Load(); current != nil && current.address == address && current.resolver != nil {
		return
	}
	d.resolver.Store(&resolverBox{resolver: resolver, address: address})
	d.mu.Lock()
	clear(d.cache)
	d.mu.Unlock()
}

// lookupResult is the raw answer for one query name.
type lookupResult struct {
	addrs  []netip.Addr
	err    error
	cached bool
}

// lookupAll resolves names concurrently within ctx. A name that could not
// be resolved before ctx ended carries ctx's error.
func (d *DNS) lookupAll(ctx context.Context, names []string) map[string]lookupResult {
	results := make(map[string]lookupResult, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, d.options.Concurrency)
	for _, name := range names {
		if addrs, ok := d.cached(name); ok {
			results[name] = lookupResult{addrs: addrs, cached: true}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var result lookupResult
			select {
			case slots <- struct{}{}:
				result = d.lookup(ctx, name)
				<-slots
			case <-ctx.Done():
				result = lookupResult{err: ctx.Err()}
			}
			mu.Lock()
			results[name] = result
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func (d *DNS) lookup(parent context.Context, name string) lookupResult {
	if err := parent.Err(); err != nil {
		return lookupResult{err: err}
	}
	ctx, cancel := context.WithTimeout(parent, d.options.QueryTimeout)
	defer cancel()
	values, err := d.resolver.Load().resolver.LookupHost(ctx, name+".")
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			d.store(name, nil)
			return lookupResult{}
		}
		return lookupResult{err: err}
	}
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		if addr, parseErr := netip.ParseAddr(value); parseErr == nil && addr.Unmap().Is4() {
			addrs = append(addrs, addr.Unmap())
		}
	}
	d.store(name, addrs)
	return lookupResult{addrs: addrs}
}

func (d *DNS) cached(name string) ([]netip.Addr, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.cache[name]
	if !ok {
		return nil, false
	}
	if !d.options.Now().Before(entry.expires) {
		delete(d.cache, name)
		return nil, false
	}
	return entry.addrs, true
}

func (d *DNS) store(name string, addrs []netip.Addr) {
	ttl := d.options.NegativeTTL
	if len(addrs) > 0 {
		ttl = d.options.PositiveTTL
	}
	now := d.options.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.cache) >= d.options.MaxEntries {
		for key, entry := range d.cache {
			if !now.Before(entry.expires) {
				delete(d.cache, key)
			}
		}
		// Still full: drop an arbitrary tenth rather than grow.
		for key := range d.cache {
			if len(d.cache) < d.options.MaxEntries*9/10 {
				break
			}
			delete(d.cache, key)
		}
	}
	d.cache[name] = cacheEntry{addrs: addrs, expires: now.Add(ttl)}
}

// CacheLen returns the number of cached answers.
func (d *DNS) CacheLen() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.cache)
}

// record updates zone statistics with one interpreted lookup.
func (d *DNS) record(zone Zone, result lookupResult, verdict zoneVerdict) {
	now := d.options.Now().UTC()
	outcome := "clean"
	d.statsMu.Lock()
	stats := d.stats[string(zone.Kind)+":"+zone.Name]
	if stats == nil {
		stats = &ZoneStats{Zone: zone.Name, Kind: zone.Kind}
		d.stats[string(zone.Kind)+":"+zone.Name] = stats
	}
	if result.cached {
		stats.CacheHits++
	} else {
		stats.Lookups++
	}
	switch {
	case verdict.err != nil:
		outcome = "error"
		stats.Errors++
		stats.LastError, stats.LastErrorAt = verdict.err.Error(), now
	case verdict.refused:
		outcome = "refused"
		stats.Refused++
		stats.LastRefusedAt = now
		stats.LastError, stats.LastErrorAt = "the list refused the query; use a local recursive resolver, not a public one", now
	case len(verdict.hits) > 0:
		outcome = "listed"
		stats.Listed++
		stats.LastListedAt, stats.LastSuccessAt = now, now
	default:
		stats.LastSuccessAt = now
	}
	d.statsMu.Unlock()
	if d.options.Observer != nil {
		d.options.Observer.ObserveSpamDNS(zone.Kind, zone.Name, outcome)
	}
}

// Stats returns per-zone statistics ordered by kind and zone.
func (d *DNS) Stats() []ZoneStats {
	d.statsMu.Lock()
	result := make([]ZoneStats, 0, len(d.stats))
	for _, stats := range d.stats {
		result = append(result, *stats)
	}
	d.statsMu.Unlock()
	slices.SortFunc(result, func(a, b ZoneStats) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Zone, b.Zone))
	})
	return result
}

// Health summarizes blocklist reachability for zones: degraded while a
// zone refuses this resolver (within the last hour) or fails without a
// later success (within the last 15 minutes). Details name the resolver and
// up to maxHealthDetails problem zones.
func (d *DNS) Health(zones []Zone) (healthy bool, reason string, details map[string]string) {
	const maxHealthDetails = 15
	now := d.options.Now().UTC()
	configured := make(map[string]bool, len(zones))
	for _, zone := range zones {
		configured[string(zone.Kind)+":"+zone.Name] = true
	}
	details = make(map[string]string)
	refused, failing := 0, 0
	for _, stats := range d.Stats() {
		key := string(stats.Kind) + ":" + stats.Zone
		if !configured[key] {
			continue
		}
		problem := ""
		switch {
		case !stats.LastRefusedAt.IsZero() && now.Sub(stats.LastRefusedAt) < time.Hour:
			refused++
			problem = "refused by the list; the resolver is probably a public one"
		case stats.LastErrorAt.After(stats.LastSuccessAt) && now.Sub(stats.LastErrorAt) < 15*time.Minute:
			failing++
			problem = stats.LastError
		}
		if problem != "" && len(details) < maxHealthDetails {
			details[key] = problem
		}
	}
	if address := d.resolver.Load().address; address != "" {
		details["resolver"] = address
	} else {
		details["resolver"] = "system"
	}
	switch {
	case refused > 0:
		return false, fmt.Sprintf("%d blocklist zone(s) refuse queries from the configured resolver; run a local caching resolver and set antispam_dns_resolver", refused), details
	case failing > 0:
		return false, fmt.Sprintf("%d blocklist zone(s) are failing lookups", failing), details
	}
	return true, "", details
}
