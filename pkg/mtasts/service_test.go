package mtasts

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

const testPolicy = "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: 172800\n"

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestServiceDiscoversAndPersistsPolicy(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var dnsCalls, httpCalls atomic.Int32
	resolver := resolverFunc(func(_ context.Context, name string) ([]string, error) {
		dnsCalls.Add(1)
		if name != "_mta-sts.example.test" {
			t.Fatalf("TXT name = %q", name)
		}
		return []string{"v=STSv1; id=first"}, nil
	})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		if request.URL.String() != "https://mta-sts.example.test/.well-known/mta-sts.txt" || request.Header.Get("Accept") != "text/plain" {
			t.Fatalf("request = %s, Accept %q", request.URL, request.Header.Get("Accept"))
		}
		return response(http.StatusOK, "text/plain; charset=utf-8", testPolicy), nil
	})}
	service, err := New(t.Context(), backend, Options{Resolver: resolver, HTTPClient: client, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Resolve(t.Context(), "Example.Test.")
	if err != nil || result.Source != SourceLive || result.Policy == nil || result.Policy.PolicyID != "first" || result.Policy.PolicyDomain != "example.test" {
		t.Fatalf("Resolve() = %#v, %v", result, err)
	}

	// Reopening the service proves that the fast path is durable rather than
	// an in-memory cache. A fresh cached policy does no DNS or HTTP work.
	now = now.Add(time.Hour)
	reopened, err := New(t.Context(), backend, Options{Resolver: resolver, HTTPClient: client, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err = reopened.Resolve(t.Context(), "example.test")
	if err != nil || result.Source != SourceCache || result.Policy == nil {
		t.Fatalf("cached Resolve() = %#v, %v", result, err)
	}
	if dnsCalls.Load() != 1 || httpCalls.Load() != 1 {
		t.Fatalf("network calls = DNS %d, HTTP %d", dnsCalls.Load(), httpCalls.Load())
	}
	entries, err := reopened.List(t.Context())
	if err != nil || len(entries) != 1 || entries[0].Domain != "example.test" {
		t.Fatalf("List() = %#v, %v", entries, err)
	}
}

func TestServiceKeepsValidCacheAcrossRefreshFailure(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	resolverErr := false
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		if resolverErr {
			return nil, errors.New("temporary DNS failure")
		}
		return []string{"v=STSv1; id=first"}, nil
	})
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "text/plain", testPolicy), nil
	})}
	service, err := New(t.Context(), backend, Options{Resolver: resolver, HTTPClient: client, Now: func() time.Time { return now }, RefreshInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	resolverErr = true
	now = now.Add(2 * time.Hour)
	result, err := service.Resolve(t.Context(), "example.test")
	if err != nil || result.Source != SourceCache || result.Policy == nil || result.Failure == nil || result.Failure.Type != FailureDNS {
		t.Fatalf("valid-cache failure result = %#v, %v", result, err)
	}

	now = now.Add(172800 * time.Second)
	result, err = service.Resolve(t.Context(), "example.test")
	if err != nil || result.Source != SourceNone || result.Policy != nil || result.Failure == nil {
		t.Fatalf("expired-cache failure result = %#v, %v", result, err)
	}
}

func TestServiceTreatsMissingTXTAsNoPolicyButPreservesCache(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	missing := false
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		if missing {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		return []string{"v=STSv1; id=first"}, nil
	})
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "text/plain", testPolicy), nil
	})}
	service, err := New(t.Context(), backend, Options{Resolver: resolver, HTTPClient: client, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	missing = true
	now = now.Add(time.Hour)
	result, err := service.Refresh(t.Context(), "example.test")
	if err != nil || result.Policy == nil || result.Failure != nil {
		t.Fatalf("refresh with missing TXT = %#v, %v", result, err)
	}
}

func TestServiceRateLimitsFailedPolicyFetch(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	service, err := New(t.Context(), backend, Options{
		Resolver: resolverFunc(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=broken"}, nil }),
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return response(http.StatusServiceUnavailable, "text/plain", ""), nil
		})},
		Now: func() time.Time { return now }, FailureRetry: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		result, resolveErr := service.Resolve(t.Context(), "example.test")
		if resolveErr != nil || result.Policy != nil || result.Failure == nil || result.Failure.Type != FailureHTTPS {
			t.Fatalf("Resolve() = %#v, %v", result, resolveErr)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls.Load())
	}
}

func TestServiceCoalescesConcurrentDiscovery(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	var calls atomic.Int32
	release := make(chan struct{})
	service, err := New(t.Context(), backend, Options{
		Resolver: resolverFunc(func(context.Context, string) ([]string, error) {
			calls.Add(1)
			<-release
			return []string{"v=STSv1; id=one"}, nil
		}),
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, "text/plain", testPolicy), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 20
	var wait sync.WaitGroup
	errorsOut := make(chan error, workers)
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			result, resolveErr := service.Resolve(context.Background(), "example.test")
			if resolveErr == nil && result.Policy == nil {
				resolveErr = errors.New("missing policy")
			}
			errorsOut <- resolveErr
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wait.Wait()
	close(errorsOut)
	for resolveErr := range errorsOut {
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("DNS calls = %d, want 1", calls.Load())
	}
}

func TestServiceRejectsRedirectWrongTypeAndOversizedPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		response *http.Response
		wantType string
	}{
		{name: "redirect", response: response(http.StatusFound, "text/plain", ""), wantType: FailureHTTPS},
		{name: "wrong content type", response: response(http.StatusOK, "text/html", testPolicy), wantType: FailureHTTPS},
		{name: "oversized", response: response(http.StatusOK, "text/plain", strings.Repeat("x", maxPolicyBytes+1)), wantType: FailureHTTPS},
		{name: "invalid policy", response: response(http.StatusOK, "text/plain", "not a policy"), wantType: FailurePolicy},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend, err := jsonstore.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			service, err := New(t.Context(), backend, Options{
				Resolver:   resolverFunc(func(context.Context, string) ([]string, error) { return []string{"v=STSv1; id=x"}, nil }),
				HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return test.response, nil })},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Resolve(t.Context(), "example.test")
			if err != nil || result.Failure == nil || result.Failure.Type != test.wantType {
				t.Fatalf("Resolve() = %#v, %v", result, err)
			}
		})
	}
}
