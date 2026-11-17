// Package netguard keeps outbound HTTP requests to configured or
// user-supplied URLs away from private networks. A Dialer resolves the
// target host itself, refuses addresses that are not globally routed, and
// connects to the address it checked, so a later DNS answer cannot move the
// connection. Every connection is vetted, which covers redirects to other
// hosts as well.
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ErrForbiddenAddress means a host resolves only to addresses the dialer
// may not reach.
var ErrForbiddenAddress = errors.New("the address is on a private, loopback, or link-local network")

const defaultDialTimeout = 10 * time.Second

// Resolver looks host names up; net.DefaultResolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens TCP connections only to vetted addresses.
type Dialer struct {
	// AllowPrivate reports whether private, loopback, and other
	// non-public addresses are permitted; nil refuses them.
	AllowPrivate func() bool
	// AllowAddress, when set, permits individual non-public addresses, such
	// as an administrator-approved internal server.
	AllowAddress func(netip.Addr) bool
	// AllowDestination, when set, permits individual non-public
	// address:port destinations.
	AllowDestination func(netip.AddrPort) bool
	// Resolver looks hosts up; nil uses net.DefaultResolver.
	Resolver Resolver
	// Timeout bounds each connection attempt; zero means 10 seconds.
	Timeout time.Duration
}

// Resolve returns the permitted addresses of host, or ErrForbiddenAddress
// when it has none.
func (d *Dialer) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(host, ".")
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolver := d.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	allowPrivate := d.AllowPrivate != nil && d.AllowPrivate()
	permitted := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if allowPrivate || PublicAddress(address) || d.AllowAddress != nil && d.AllowAddress(address) {
			permitted = append(permitted, address)
		}
	}
	if len(permitted) == 0 {
		return nil, ErrForbiddenAddress
	}
	return permitted, nil
}

// DialContext connects to address (host:port) through the first permitted
// address of host that accepts the connection.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := d.Resolve(ctx, host)
	if errors.Is(err, ErrForbiddenAddress) && d.AllowDestination != nil {
		addresses, err = d.allowedDestinations(ctx, host, port)
	}
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, candidate := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// allowedDestinations resolves host and keeps the addresses whose
// address:port AllowDestination permits.
func (d *Dialer) allowedDestinations(ctx context.Context, host, port string) ([]netip.Addr, error) {
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, ErrForbiddenAddress
	}
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(strings.TrimSuffix(host, ".")); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolver := d.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		if addresses, err = resolver.LookupNetIP(ctx, "ip", strings.TrimSuffix(host, ".")); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	permitted := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if PublicAddress(address) || d.AllowDestination(netip.AddrPortFrom(address, uint16(portNumber))) {
			permitted = append(permitted, address)
		}
	}
	if len(permitted) == 0 {
		return nil, ErrForbiddenAddress
	}
	return permitted, nil
}

// Transport returns an HTTP transport that connects only through d and
// never through a proxy, which would bypass the address check.
func (d *Dialer) Transport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
	}
}

// Client returns an HTTP client over Transport with an overall request
// timeout (zero means none). Redirects are followed, and a redirect to
// another host is dialed, and so vetted, again.
func (d *Dialer) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: d.Transport(), Timeout: timeout}
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("fec0::/10"),
}

// PublicAddress reports whether address is a globally routed unicast
// address: not loopback, private, link-local, multicast, unspecified,
// carrier-grade NAT, documentation, or reserved, and not an IPv6 form that
// reaches such an IPv4 address through a gateway.
func PublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsInterfaceLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	if embedded, ok := embeddedIPv4(address); ok {
		return PublicAddress(embedded)
	}
	return true
}

var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	sixToFourPrefix  = netip.MustParsePrefix("2002::/16")
	ipv4CompatPrefix = netip.MustParsePrefix("::/96")
)

// embeddedIPv4 returns the IPv4 address that a NAT64 (64:ff9b::/96), 6to4
// (2002::/16), or IPv4-compatible (::/96) address reaches through its
// gateway.
func embeddedIPv4(address netip.Addr) (netip.Addr, bool) {
	bytes := address.As16()
	switch {
	case !address.Is6():
		return netip.Addr{}, false
	case nat64Prefix.Contains(address), ipv4CompatPrefix.Contains(address):
		return netip.AddrFrom4([4]byte(bytes[12:16])), true
	case sixToFourPrefix.Contains(address):
		return netip.AddrFrom4([4]byte(bytes[2:6])), true
	}
	return netip.Addr{}, false
}
