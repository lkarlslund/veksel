package calendarfeed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	for input, want := range map[string]string{
		"webcal://example.test/cal.ics":  "https://example.test/cal.ics",
		"webcals://example.test/cal.ics": "https://example.test/cal.ics",
		"http://example.test/a.ics#x":    "http://example.test/a.ics",
	} {
		if got, err := NormalizeURL(input); err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "ftp://example.test/a.ics", "https://user:pass@example.test/a.ics", "/relative.ics"} {
		if _, err := NormalizeURL(input); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeURL(%q) error = %v", input, err)
		}
	}
}

type fixedResolver map[string][]netip.Addr

func (r fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestFetchPinsResolvedAddressAndChecksRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://internal.test:"+strings.Split(r.Host, ":")[1]+"/cal.ics", http.StatusFound)
			return
		}
		if !strings.HasPrefix(r.Host, "feed.test") && !strings.HasPrefix(r.Host, "internal.test") {
			t.Errorf("request Host = %q", r.Host)
		}
		_, _ = w.Write([]byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"))
	}))
	defer server.Close()
	port := strings.Split(server.URL, ":")[2]
	loopback := netip.MustParseAddr("127.0.0.1")
	allow := true
	fetcher := &Fetcher{AllowPrivate: func() bool { return allow }, MaxBytes: 1 << 20, Timeout: 5 * time.Second,
		Resolver: fixedResolver{"feed.test": {loopback}, "internal.test": {loopback}}}
	result, err := fetcher.Fetch(t.Context(), "http://feed.test:"+port+"/cal.ics", "", "")
	if err != nil || !strings.Contains(string(result.Body), "VCALENDAR") {
		t.Fatalf("allowed fetch = %q, %v", result.Body, err)
	}
	allow = false
	if _, err := fetcher.Fetch(t.Context(), "http://feed.test:"+port+"/cal.ics", "", ""); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("private fetch error = %v", err)
	}
	// Redirects are followed, each to an address resolved and checked again.
	allow = true
	result, err = fetcher.Fetch(t.Context(), "http://feed.test:"+port+"/redirect", "", "")
	if err != nil || len(result.Body) == 0 {
		t.Fatalf("redirected fetch = %v", err)
	}
	fetcher.Resolver = fixedResolver{"feed.test": {loopback}}
	if _, err := fetcher.Fetch(t.Context(), "http://feed.test:"+port+"/redirect", "", ""); err == nil {
		t.Fatal("redirect to an unresolvable host succeeded")
	}
	fetcher.MaxBytes = 10
	if _, err := fetcher.Fetch(t.Context(), "http://feed.test:"+port+"/cal.ics", "", ""); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversized fetch error = %v", err)
	}
}
