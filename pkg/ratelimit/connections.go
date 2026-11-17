package ratelimit

import (
	"net/netip"
	"slices"
	"sync"
)

// DefaultMaxConnectionsPerIP is the default cap on concurrent mail protocol
// connections from one client address. It is sized for an office or carrier
// NAT where dozens of users share one address and every mail client keeps
// several connections open (one per watched folder plus a sync connection);
// failed-authentication throttling, not this cap, protects accounts.
const DefaultMaxConnectionsPerIP = 200

// Connection flood guard: a client address may open connectionBurst
// connections at once and connectionRefill more per second after that, which
// absorbs every client of a shared address reconnecting together after a
// network outage or server restart while still bounding connection floods.
const (
	connectionBurst  = 300
	connectionRefill = 10
)

// ConnectionPolicy is the live, configurable part of connection admission.
type ConnectionPolicy struct {
	// MaxPerIP caps concurrent connections from one client address. Zero
	// disables the cap.
	MaxPerIP int
	// Exempt lists client prefixes that bypass connection admission, such as
	// a webmail or sync gateway that multiplexes many users.
	Exempt []netip.Prefix
}

// exempt reports whether ip falls inside an exempt prefix.
func (p ConnectionPolicy) exempt(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	return slices.ContainsFunc(p.Exempt, func(prefix netip.Prefix) bool { return prefix.Contains(addr) })
}

// ConnectionGate admits inbound protocol connections per client address: it
// bounds the connection rate and the number of concurrent connections.
type ConnectionGate struct {
	rate   *Limiter
	mu     sync.Mutex
	active map[string]int
}

// NewConnectionGate returns a gate with the default connection flood guard.
func NewConnectionGate() *ConnectionGate {
	return &ConnectionGate{rate: NewLimiter(connectionBurst, connectionRefill), active: make(map[string]int)}
}

// Admit decides whether a new connection from remoteAddr (host:port) may
// proceed under policy. When it may, the returned release function must be
// called exactly once when the connection closes.
func (g *ConnectionGate) Admit(remoteAddr string, policy ConnectionPolicy) (release func(), ok bool) {
	ip := AddrIP(remoteAddr)
	if policy.exempt(ip) {
		return func() {}, true
	}
	g.mu.Lock()
	if policy.MaxPerIP > 0 && g.active[ip] >= policy.MaxPerIP {
		g.mu.Unlock()
		log.Warn("ratelimit: concurrent connection limit reached", "ip", ip, "limit", policy.MaxPerIP)
		return nil, false
	}
	if !g.rate.Allow(ip) {
		g.mu.Unlock()
		return nil, false
	}
	g.active[ip]++
	g.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { g.release(ip) }) }, true
}

func (g *ConnectionGate) release(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[ip] <= 1 {
		delete(g.active, ip)
		return
	}
	g.active[ip]--
}
