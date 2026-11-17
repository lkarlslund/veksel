package httpservice

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"

	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

func forwardedRequest(remote string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://veksel.internal:8472/", nil)
	req.RemoteAddr = remote
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return req
}

func TestResolveIgnoresForwardingHeadersFromUntrustedPeer(t *testing.T) {
	proxies, err := NewTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	spoofed := map[string]string{
		"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.10",
		"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example",
	}
	for _, resolver := range []*TrustedProxies{nil, proxies} {
		got := resolver.Resolve(forwardedRequest("198.51.100.7:4321", spoofed))
		want := Client{IP: "198.51.100.7", HTTPS: false, Host: "veksel.internal:8472"}
		if got != want {
			t.Fatalf("resolved %+v, want %+v", got, want)
		}
	}
}

func TestResolveWalksTrustedProxyChain(t *testing.T) {
	proxies, err := NewTrustedProxies([]string{"10.0.0.0/8", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, xff, realIP, want string
	}{
		{name: "single proxy", xff: "203.0.113.9", want: "203.0.113.9"},
		// The client prepended a forged hop; the rightmost untrusted entry wins.
		{name: "spoof prepended", xff: "1.1.1.1, 203.0.113.9, 192.0.2.1", want: "203.0.113.9"},
		{name: "all trusted", xff: "10.1.1.1, 10.2.2.2", want: "10.1.1.1"},
		{name: "garbage stops walk", xff: "203.0.113.9, bogus", want: "10.0.0.5"},
		{name: "ipv6 with port", xff: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "real ip fallback", realIP: "203.0.113.20", want: "203.0.113.20"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.xff != "" {
				headers["X-Forwarded-For"] = tc.xff
			}
			if tc.realIP != "" {
				headers["X-Real-IP"] = tc.realIP
			}
			if got := proxies.Resolve(forwardedRequest("10.0.0.5:9000", headers)).IP; got != tc.want {
				t.Fatalf("client IP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveSchemeAndHostFromTrustedProxy(t *testing.T) {
	proxies, err := NewTrustedProxies([]string{"::ffff:127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	got := proxies.Resolve(forwardedRequest("127.0.0.1:5555", map[string]string{
		"X-Forwarded-Proto": "http, https", "X-Forwarded-Host": "mail.example.com",
	}))
	if !got.HTTPS || got.Host != "mail.example.com" || got.Scheme() != "https" {
		t.Fatalf("resolved %+v", got)
	}
	tlsRequest := forwardedRequest("127.0.0.1:5555", map[string]string{"X-Forwarded-Host": "bad/host"})
	tlsRequest.TLS = &tls.ConnectionState{}
	if got := proxies.Resolve(tlsRequest); !got.HTTPS || got.Host != "veksel.internal:8472" {
		t.Fatalf("direct TLS or invalid host mishandled: %+v", got)
	}
}

func TestHandlerStoresClientAndAppliesLiveChanges(t *testing.T) {
	proxies, err := NewTrustedProxies(nil)
	if err != nil {
		t.Fatal(err)
	}
	var client Client
	var throttleIP string
	handler := proxies.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		client, throttleIP = RequestClient(r), ratelimit.ClientIP(r.Context())
	}))
	headers := map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"}
	handler.ServeHTTP(httptest.NewRecorder(), forwardedRequest("10.0.0.5:9000", headers))
	if client.IP != "10.0.0.5" || throttleIP != "10.0.0.5" || client.HTTPS {
		t.Fatalf("default trusted a proxy: %+v throttle=%q", client, throttleIP)
	}
	if err := proxies.Set([]string{"not-a-cidr/99"}); err == nil {
		t.Fatal("invalid entry accepted")
	}
	if err := proxies.Set([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), forwardedRequest("10.0.0.5:9000", headers))
	if client.IP != "203.0.113.9" || throttleIP != "203.0.113.9" || !client.HTTPS {
		t.Fatalf("live trusted set not applied: %+v throttle=%q", client, throttleIP)
	}
}

func TestResolveForwardedHeader(t *testing.T) {
	proxies, err := NewTrustedProxies([]string{"10.0.0.0/8", "2001:db8:ffff::/48"})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxies.SetHeader(config.ForwardedHeaderRFC7239); err != nil {
		t.Fatal(err)
	}
	const peer, origin = "10.0.0.5", "veksel.internal:8472"
	cases := []struct {
		name  string
		lines []string
		want  Client
	}{
		{name: "single element", lines: []string{"for=203.0.113.9;proto=https;host=mail.example.com"}, want: Client{IP: "203.0.113.9", HTTPS: true, Host: "mail.example.com"}},
		{name: "case and spaces", lines: []string{`For="203.0.113.9" ; Proto=HTTPS`}, want: Client{IP: "203.0.113.9", HTTPS: true, Host: origin}},
		{name: "quoted ipv4 port", lines: []string{`for="203.0.113.9:47011"`}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "quoted ipv6", lines: []string{`for="[2001:db8::1]"`}, want: Client{IP: "2001:db8::1", Host: origin}},
		{name: "ipv6 port", lines: []string{`for="[2001:db8::1]:443"`}, want: Client{IP: "2001:db8::1", Host: origin}},
		{name: "ipv6 obfuscated port", lines: []string{`for="[2001:db8::1]:_p1"`}, want: Client{IP: "2001:db8::1", Host: origin}},
		{name: "quoted pair", lines: []string{`for="203.0.113.\9";host="mail.example.com"`}, want: Client{IP: "203.0.113.9", Host: "mail.example.com"}},
		{name: "trusted hops skipped", lines: []string{"for=198.51.100.1, for=203.0.113.9, for=10.1.1.1"}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "multiple lines", lines: []string{"for=198.51.100.1, for=203.0.113.9", `for="[2001:db8:ffff::7]"`}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "empty list elements", lines: []string{", for=203.0.113.9,,"}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "all trusted", lines: []string{"for=10.1.1.1, for=10.2.2.2"}, want: Client{IP: "10.1.1.1", Host: origin}},
		// The proxy nearest the client saw HTTPS; the inner hop was plain HTTP.
		{name: "scheme nearest client", lines: []string{"for=203.0.113.9;proto=https;host=mail.example.com, for=10.1.1.1;proto=http;host=inner"}, want: Client{IP: "203.0.113.9", HTTPS: true, Host: "mail.example.com"}},
		{name: "spoofed scheme beyond client ignored", lines: []string{"for=198.51.100.1;proto=https;host=evil.example, for=203.0.113.9;proto=http"}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "obfuscated stops walk", lines: []string{"for=203.0.113.9, for=_hidden;proto=https, for=10.1.1.1"}, want: Client{IP: "10.1.1.1", HTTPS: true, Host: origin}},
		{name: "unknown stops walk", lines: []string{"for=203.0.113.9, for=unknown"}, want: Client{IP: peer, Host: origin}},
		{name: "proto only", lines: []string{"proto=https"}, want: Client{IP: peer, HTTPS: true, Host: origin}},
		{name: "by and extensions ignored", lines: []string{`for=203.0.113.9;by="[2001:db8::2]";ext=x`}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "malformed stops at last good", lines: []string{"for=198.51.100.1, for=203.0.113.9;proto=https;proto=http, for=10.1.1.1"}, want: Client{IP: "10.1.1.1", Host: origin}},
		{name: "malformed nearest", lines: []string{"for=203.0.113.9, for"}, want: Client{IP: peer, Host: origin}},
		{name: "unquoted ipv6", lines: []string{"for=2001:db8::1"}, want: Client{IP: peer, Host: origin}},
		{name: "unquoted bracket", lines: []string{"for=[2001:db8::1]"}, want: Client{IP: peer, Host: origin}},
		{name: "ipv4 in brackets", lines: []string{`for="[203.0.113.9]"`}, want: Client{IP: peer, Host: origin}},
		{name: "bad port", lines: []string{`for="203.0.113.9:123456"`}, want: Client{IP: peer, Host: origin}},
		{name: "bad obfuscated", lines: []string{"for=_"}, want: Client{IP: peer, Host: origin}},
		{name: "unterminated quote", lines: []string{`for=203.0.113.9, for="10.1.1.1`}, want: Client{IP: peer, Host: origin}},
		{name: "invalid host", lines: []string{`for=203.0.113.9;host="evil/x"`}, want: Client{IP: peer, Host: origin}},
		{name: "invalid scheme", lines: []string{`for=203.0.113.9;proto="ht tps"`}, want: Client{IP: peer, Host: origin}},
		{name: "missing separator", lines: []string{`for="203.0.113.9"proto=https`}, want: Client{IP: peer, Host: origin}},
		{name: "quoted comma resync", lines: []string{`for=198.51.100.1;x="a,b";x=1, for=203.0.113.9`}, want: Client{IP: "203.0.113.9", Host: origin}},
		{name: "oversized header", lines: []string{"for=203.0.113.9;ext=" + strings.Repeat("a", maxForwardedHeaderBytes)}, want: Client{IP: peer, Host: origin}},
		{name: "too many hops", lines: []string{"for=203.0.113.9" + strings.Repeat(", for=10.1.1.1", maxForwardedHops)}, want: Client{IP: "10.1.1.1", Host: origin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := forwardedRequest(peer+":9000", nil)
			for _, line := range tc.lines {
				request.Header.Add("Forwarded", line)
			}
			if got := proxies.Resolve(request); got != tc.want {
				t.Fatalf("resolved %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResolveForwardedPrecedenceAndTrust(t *testing.T) {
	proxies, err := NewTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{
		"Forwarded":       "for=203.0.113.9;proto=https;host=mail.example.com",
		"X-Forwarded-For": "198.51.100.1", "X-Real-IP": "198.51.100.2",
		"X-Forwarded-Proto": "http", "X-Forwarded-Host": "legacy.example",
	}
	// By default the proxy owns X-Forwarded-*: a client's own Forwarded
	// header, passed through by a proxy such as HAProxy, is ignored.
	if got, want := proxies.Resolve(forwardedRequest("10.0.0.5:9000", headers)), (Client{IP: "198.51.100.1", Host: "legacy.example"}); got != want {
		t.Fatalf("X-Forwarded family: resolved %+v, want %+v", got, want)
	}
	// A proxy that owns Forwarded makes X-Forwarded-* the client's header.
	if err := proxies.SetHeader(config.ForwardedHeaderRFC7239); err != nil {
		t.Fatal(err)
	}
	if got, want := proxies.Resolve(forwardedRequest("10.0.0.5:9000", headers)), (Client{IP: "203.0.113.9", HTTPS: true, Host: "mail.example.com"}); got != want {
		t.Fatalf("Forwarded family: resolved %+v, want %+v", got, want)
	}
	// A malformed or missing Forwarded header falls back to the peer, never
	// to X-Forwarded-*.
	headers["Forwarded"] = "for="
	if got, want := proxies.Resolve(forwardedRequest("10.0.0.5:9000", headers)), (Client{IP: "10.0.0.5", Host: "veksel.internal:8472"}); got != want {
		t.Fatalf("malformed Forwarded: resolved %+v, want %+v", got, want)
	}
	delete(headers, "Forwarded")
	if got, want := proxies.Resolve(forwardedRequest("10.0.0.5:9000", headers)), (Client{IP: "10.0.0.5", Host: "veksel.internal:8472"}); got != want {
		t.Fatalf("missing Forwarded: resolved %+v, want %+v", got, want)
	}
	headers["Forwarded"] = "for=203.0.113.9;proto=https;host=evil.example"
	if got, want := proxies.Resolve(forwardedRequest("198.51.100.7:4321", headers)), (Client{IP: "198.51.100.7", Host: "veksel.internal:8472"}); got != want {
		t.Fatalf("untrusted Forwarded honoured: resolved %+v, want %+v", got, want)
	}
	if err := proxies.SetHeader("bogus"); err == nil {
		t.Fatal("unknown header family accepted")
	}
}
func TestResolveCapsXForwardedFor(t *testing.T) {
	proxies, err := NewTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	chain := "203.0.113.9" + strings.Repeat(", 10.1.1.1", maxForwardedHops)
	if got := proxies.Resolve(forwardedRequest("10.0.0.5:9000", map[string]string{"X-Forwarded-For": chain})).IP; got != "10.1.1.1" {
		t.Fatalf("over-long chain walked past cap: %q", got)
	}
	huge := strings.Repeat("203.0.113.9, ", maxForwardedHeaderBytes/13+1)
	if got := proxies.Resolve(forwardedRequest("10.0.0.5:9000", map[string]string{"X-Forwarded-For": huge})).IP; got != "10.0.0.5" {
		t.Fatalf("oversized X-Forwarded-For honoured: %q", got)
	}
}
