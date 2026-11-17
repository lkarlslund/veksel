package httpservice

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

// Client is the effective origin of an HTTP request after forwarding headers
// from trusted reverse proxies have been applied.
type Client struct {
	// IP is the client address used for throttling, sessions and audit.
	IP string
	// HTTPS reports whether the client reached Veksel (or its proxy) over TLS.
	HTTPS bool
	// Host is the public host name and optional port the client addressed.
	Host string
}

// Scheme returns "https" or "http".
func (c Client) Scheme() string {
	if c.HTTPS {
		return "https"
	}
	return "http"
}

// TrustedProxies is the single resolver for forwarded request metadata.
// Forwarded, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto and
// X-Forwarded-Host are only
// honoured when the transport peer is inside a configured prefix. The set can
// be replaced at runtime; a nil *TrustedProxies trusts nobody.
type TrustedProxies struct {
	prefixes atomic.Pointer[[]netip.Prefix]
	// rfc7239 selects the Forwarded header family instead of X-Forwarded-*.
	rfc7239 atomic.Bool
}

// NewTrustedProxies returns a resolver trusting the given IPs and CIDRs.
func NewTrustedProxies(values []string) (*TrustedProxies, error) {
	t := &TrustedProxies{}
	if err := t.Set(values); err != nil {
		return nil, err
	}
	return t, nil
}

// Set atomically replaces the trusted set. Invalid entries leave it unchanged.
func (t *TrustedProxies) Set(values []string) error {
	prefixes, err := config.ParseTrustedProxies(values)
	if err != nil {
		return err
	}
	t.prefixes.Store(&prefixes)
	return nil
}

// Trusts reports whether addr is a configured trusted proxy.
// SetHeader selects the forwarding header family trusted proxies set (see
// config.HTTPForwardedHeader); empty selects X-Forwarded-*.
func (t *TrustedProxies) SetHeader(family string) error {
	switch family {
	case "", config.ForwardedHeaderX:
		t.rfc7239.Store(false)
	case config.ForwardedHeaderRFC7239:
		t.rfc7239.Store(true)
	default:
		return fmt.Errorf("unknown forwarding header family %q", family)
	}
	return nil
}

func (t *TrustedProxies) Trusts(addr netip.Addr) bool { return t.trusted(addr) }

func (t *TrustedProxies) trusted(addr netip.Addr) bool {
	if t == nil || !addr.IsValid() {
		return false
	}
	prefixes := t.prefixes.Load()
	if prefixes == nil {
		return false
	}
	for _, prefix := range *prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Resolve returns the effective client of r. Forwarding metadata is honoured
// only when the transport peer is trusted. An RFC 7239 Forwarded header takes
// precedence over the X-Forwarded-* family; either way the hops are walked
// right to left, skipping trusted hops, so the first untrusted address is the
// client and a client cannot spoof its address by prepending entries.
// Malformed, unknown or obfuscated hops stop the walk at the last good address.
func (t *TrustedProxies) Resolve(r *http.Request) Client {
	client := Client{IP: ratelimit.AddrIP(r.RemoteAddr), HTTPS: r.TLS != nil, Host: r.Host}
	peer := parseForwardedAddr(r.RemoteAddr)
	if !t.trusted(peer) {
		return client
	}
	hops := forwardedHops(r.Header, t.rfc7239.Load())
	for i := len(hops) - 1; i >= 0; i-- {
		hop := hops[i]
		if hop.bad {
			break
		}
		// Every visited hop was appended by a trusted proxy, so the scheme
		// and host reported nearest the client are the most accurate.
		if hop.proto != "" {
			client.HTTPS = strings.EqualFold(hop.proto, "https")
		}
		if hop.host != "" {
			client.Host = hop.host
		}
		if !hop.addr.IsValid() {
			break
		}
		client.IP = hop.addr.String()
		if !t.trusted(hop.addr) {
			break
		}
	}
	return client
}

// Handler resolves the client once per request and stores it in the request
// context for RequestClient and for ratelimit.ClientIP.
func (t *TrustedProxies) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := t.Resolve(r)
		ctx := context.WithValue(r.Context(), clientKey{}, client)
		next.ServeHTTP(w, r.WithContext(ratelimit.WithClientIP(ctx, client.IP)))
	})
}

type clientKey struct{}

// RequestClient returns the client resolved by TrustedProxies.Handler. Requests
// that did not pass through the handler are described by their transport
// alone; forwarding headers are never trusted implicitly.
func RequestClient(r *http.Request) Client {
	if client, ok := r.Context().Value(clientKey{}).(Client); ok {
		return client
	}
	return (*TrustedProxies)(nil).Resolve(r)
}

// parseForwardedAddr accepts a bare IP, host:port, or bracketed IPv6 form.
func parseForwardedAddr(value string) netip.Addr {
	value = strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.Unmap()
		}
	}
	return netip.Addr{}
}

// Bounds applied to forwarding headers before they are parsed.
const (
	maxForwardedHeaderBytes = 8192
	maxForwardedHops        = 32
)

// forwardedHop is one proxy hop (a slice holds them oldest first): the node
// the proxy received the request from and, optionally, the scheme and host
// that proxy saw.
type forwardedHop struct {
	addr  netip.Addr // invalid for unknown, obfuscated or unusable nodes
	proto string
	host  string
	bad   bool // malformed: the walk stops without using this hop
}

// forwardedHops collects the hops reported by a trusted peer from the one
// header family the proxy owns: RFC 7239 Forwarded when rfc7239 is set,
// otherwise X-Forwarded-For/-Proto/-Host and X-Real-IP. The other family is
// never read: a proxy that sets one passes a client's copy of the other
// through unchanged.
func forwardedHops(header http.Header, rfc7239 bool) []forwardedHop {
	if rfc7239 {
		lines := header.Values("Forwarded")
		if strings.TrimSpace(strings.Join(lines, "")) == "" {
			return []forwardedHop{{bad: true}}
		}
		return parseForwarded(lines)
	}
	fors, ok := headerValues(header, "X-Forwarded-For")
	if !ok {
		return []forwardedHop{{bad: true}}
	}
	hops := make([]forwardedHop, 0, len(fors)+1)
	for _, value := range fors {
		hops = append(hops, forwardedHop{addr: parseForwardedAddr(value)})
	}
	if len(hops) == 0 {
		if realIP := parseForwardedAddr(header.Get("X-Real-IP")); realIP.IsValid() {
			hops = append(hops, forwardedHop{addr: realIP})
		}
	}
	// X-Forwarded-Proto and -Host are not paired with addresses; their
	// rightmost values were supplied by the trusted peer itself.
	var nearest forwardedHop
	if protos, _ := headerValues(header, "X-Forwarded-Proto"); len(protos) > 0 {
		nearest.proto = protos[len(protos)-1]
	}
	if hosts, _ := headerValues(header, "X-Forwarded-Host"); len(hosts) > 0 && validForwardedHost(hosts[len(hosts)-1]) {
		nearest.host = hosts[len(hosts)-1]
	}
	if nearest.proto != "" || nearest.host != "" {
		if len(hops) == 0 {
			hops = append(hops, forwardedHop{})
		}
		hops[len(hops)-1].proto, hops[len(hops)-1].host = nearest.proto, nearest.host
	}
	return capHops(hops)
}

// capHops keeps the nearest maxForwardedHops hops and stops the walk beyond.
func capHops(hops []forwardedHop) []forwardedHop {
	if len(hops) <= maxForwardedHops {
		return hops
	}
	return append([]forwardedHop{{bad: true}}, hops[len(hops)-maxForwardedHops:]...)
}

// headerValues splits every occurrence of a comma-separated header. It
// reports false when the combined header exceeds maxForwardedHeaderBytes.
func headerValues(header http.Header, name string) ([]string, bool) {
	lines := header.Values(name)
	if headerSize(lines) > maxForwardedHeaderBytes {
		return nil, false
	}
	var values []string
	for _, line := range lines {
		for _, value := range strings.Split(line, ",") {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values, true
}

func headerSize(lines []string) int {
	size := 0
	for _, line := range lines {
		size += len(line)
	}
	return size
}

// parseForwarded parses RFC 7239 Forwarded header lines. Each comma-separated
// forwarded-element across all lines becomes one hop; an element that is not
// well formed becomes a bad hop so the walk stops before it.
func parseForwarded(lines []string) []forwardedHop {
	if headerSize(lines) > maxForwardedHeaderBytes {
		return []forwardedHop{{bad: true}}
	}
	var hops []forwardedHop
	for _, line := range lines {
		p := forwardedParser{s: line}
		for p.i < len(p.s) {
			if hop, ok := p.element(); ok {
				hops = append(hops, hop)
			}
		}
	}
	return capHops(hops)
}

type forwardedParser struct {
	s string
	i int
}

// element parses one forwarded-element and its trailing comma. It reports
// false for an empty list element.
func (p *forwardedParser) element() (forwardedHop, bool) {
	var hop forwardedHop
	var seen []string
	needSeparator := false
	for {
		p.skipSpace()
		if p.i == len(p.s) {
			return hop, len(seen) > 0
		}
		switch p.s[p.i] {
		case ',':
			p.i++
			return hop, len(seen) > 0
		case ';':
			p.i++
			needSeparator = false
			continue
		}
		if needSeparator {
			return p.fail()
		}
		name, ok := p.token()
		if !ok || p.i == len(p.s) || p.s[p.i] != '=' {
			return p.fail()
		}
		p.i++
		value, ok := p.value()
		name = strings.ToLower(name)
		if !ok || slices.Contains(seen, name) {
			return p.fail()
		}
		seen = append(seen, name)
		switch name {
		case "for":
			hop.addr, ok = parseForwardedNode(value)
		case "proto":
			hop.proto, ok = value, validScheme(value)
		case "host":
			hop.host, ok = value, validForwardedHost(value)
		}
		if !ok {
			return p.fail()
		}
		needSeparator = true
	}
}

// fail skips past the next element separator outside a quoted string and
// returns a bad hop.
func (p *forwardedParser) fail() (forwardedHop, bool) {
	quoted := false
	for ; p.i < len(p.s); p.i++ {
		switch c := p.s[p.i]; {
		case quoted && c == '\\':
			p.i++
		case c == '"':
			quoted = !quoted
		case !quoted && c == ',':
			p.i++
			return forwardedHop{bad: true}, true
		}
	}
	return forwardedHop{bad: true}, true
}

func (p *forwardedParser) skipSpace() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *forwardedParser) token() (string, bool) {
	start := p.i
	for p.i < len(p.s) && isTokenChar(p.s[p.i]) {
		p.i++
	}
	return p.s[start:p.i], p.i > start
}

// value parses a token or an RFC 9110 quoted-string.
func (p *forwardedParser) value() (string, bool) {
	if p.i == len(p.s) || p.s[p.i] != '"' {
		return p.token()
	}
	var b strings.Builder
	for p.i++; p.i < len(p.s); p.i++ {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), true
		case c == '\\' && p.i+1 < len(p.s):
			p.i++
			c = p.s[p.i]
		case c == '\\':
			return "", false
		}
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return "", false
		}
		b.WriteByte(c)
	}
	return "", false
}

// parseForwardedNode parses an RFC 7239 node: an IPv4 address, a bracketed
// IPv6 address, "unknown" or an obfuscated "_identifier", each with an
// optional port. Unknown and obfuscated nodes are valid but carry no address.
func parseForwardedNode(value string) (netip.Addr, bool) {
	name, port, hasPort := value, "", false
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return netip.Addr{}, false
		}
		name = value[:end+1]
		if rest := value[end+1:]; rest != "" {
			if rest[0] != ':' {
				return netip.Addr{}, false
			}
			port, hasPort = rest[1:], true
		}
	} else {
		name, port, hasPort = strings.Cut(value, ":")
	}
	if hasPort && !validNodePort(port) {
		return netip.Addr{}, false
	}
	switch {
	case strings.EqualFold(name, "unknown"):
		return netip.Addr{}, true
	case strings.HasPrefix(name, "_"):
		return netip.Addr{}, validObfuscated(name)
	case strings.HasPrefix(name, "["):
		addr, err := netip.ParseAddr(name[1 : len(name)-1])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	}
	addr, err := netip.ParseAddr(name)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

// validNodePort checks 1*5DIGIT or an obfuscated port.
func validNodePort(port string) bool {
	if strings.HasPrefix(port, "_") {
		return validObfuscated(port)
	}
	if port == "" || len(port) > 5 {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	return true
}

// validObfuscated checks "_" 1*( ALPHA / DIGIT / "." / "_" / "-" ).
func validObfuscated(value string) bool {
	if len(value) < 2 || value[0] != '_' {
		return false
	}
	for i := 1; i < len(value); i++ {
		if c := value[i]; !isAlphaNum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// validScheme checks an RFC 3986 URI scheme.
func validScheme(value string) bool {
	if value == "" || !isAlpha(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if c := value[i]; !isAlphaNum(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	return isAlphaNum(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func isAlphaNum(c byte) bool { return isAlpha(c) || c >= '0' && c <= '9' }

func validForwardedHost(host string) bool {
	return host != "" && len(host) <= 255 && !strings.ContainsAny(host, "/\\@?# \t")
}
