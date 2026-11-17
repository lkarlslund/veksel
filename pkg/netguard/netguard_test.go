package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicAddressRefusesNonGlobalRanges(t *testing.T) {
	for address, want := range map[string]bool{
		"8.8.8.8": true, "2a00:1450:4001::1": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fd00::1": false, "::ffff:127.0.0.1": false, "224.0.0.1": false,
		// IPv6 forms that embed an IPv4 address reach that address through
		// NAT64 or 6to4 gateways.
		"64:ff9b::a9fe:a9fe": false, "64:ff9b::808:808": true, "2002:7f00:1::1": false, "2002:808:808::1": true, "::7f00:1": false, "fec0::1": false,
	} {
		if got := PublicAddress(netip.MustParseAddr(address)); got != want {
			t.Errorf("PublicAddress(%s) = %v, want %v", address, got, want)
		}
	}
}

type fixedResolver map[string][]netip.Addr

func (r fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestClientVetsEveryConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://internal.test:"+strings.Split(r.Host, ":")[1]+"/ok", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	port := strings.Split(server.URL, ":")[2]
	loopback := netip.MustParseAddr("127.0.0.1")
	var allow atomic.Bool
	dialer := &Dialer{AllowPrivate: allow.Load, Resolver: fixedResolver{"hook.test": {loopback}, "internal.test": {loopback}}}
	client := dialer.Client(5 * time.Second)
	get := func(target string) error {
		response, err := client.Get(target)
		if err == nil {
			_ = response.Body.Close()
		}
		return err
	}
	for _, target := range []string{"http://hook.test:" + port + "/ok", server.URL + "/ok", "http://[::ffff:127.0.0.1]:" + port + "/ok"} {
		if err := get(target); !errors.Is(err, ErrForbiddenAddress) {
			t.Fatalf("GET %s error = %v", target, err)
		}
	}
	allow.Store(true)
	if err := get("http://hook.test:" + port + "/ok"); err != nil {
		t.Fatalf("allowed GET: %v", err)
	}
	// A redirect to another host dials, and is checked, again.
	client.CloseIdleConnections()
	var calls atomic.Int32
	dialer.AllowPrivate = func() bool { return calls.Add(1) == 1 }
	if err := get("http://hook.test:" + port + "/redirect"); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("redirect error = %v", err)
	}
	if _, err := dialer.Resolve(t.Context(), "unknown.test"); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("unresolved host error = %v", err)
	}
}
