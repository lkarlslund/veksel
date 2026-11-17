package dnsserver

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Response rate limiting decisions.
const (
	rrlAllow = iota
	rrlSlip
	rrlDrop
)

// limiter is a lightweight response rate limiter (after BIND's RRL): each
// client network (IPv4 /24, IPv6 /56) has a token bucket of rate responses
// per second with a two-second burst. Over the limit every second response
// is slipped (a truncated empty reply that moves real clients to TCP) and
// the rest are dropped, so spoofed queries cannot turn the server into an
// amplifier.
type limiter struct {
	mu        sync.Mutex
	rate      float64
	burst     float64
	buckets   map[netip.Prefix]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	over   uint64
}

// maxBuckets bounds the limiter's memory under address scanning.
const maxBuckets = 100000

func newLimiter(rate int) *limiter {
	return &limiter{rate: float64(rate), burst: float64(2 * rate), buckets: map[netip.Prefix]*bucket{}}
}

func clientNetwork(addr net.Addr) (netip.Prefix, bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.Prefix{}, false
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()
	bits := 56
	if ip.Is4() {
		bits = 24
	}
	prefix, err := ip.Prefix(bits)
	return prefix, err == nil
}

func (l *limiter) decide(addr net.Addr, now time.Time) int {
	network, ok := clientNetwork(addr)
	if !ok {
		return rrlAllow
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) > time.Minute || len(l.buckets) >= maxBuckets {
		for key, b := range l.buckets {
			if now.Sub(b.last) > time.Minute || len(l.buckets) >= maxBuckets {
				delete(l.buckets, key)
			}
		}
		l.lastSweep = now
	}
	b, ok := l.buckets[network]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[network] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return rrlAllow
	}
	b.over++
	if b.over%2 == 1 {
		return rrlSlip
	}
	return rrlDrop
}
