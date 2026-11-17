package model

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func routeTestStore(t *testing.T) *TypedStore {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := NewTypedStore(backend, store.BackendJSON)
	if err := ts.EnsureNamespace(context.Background(), NSOutboundRoutes); err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestOutboundRouteStoreLifecycleAndNormalization(t *testing.T) {
	routes := routeTestStore(t).OutboundRouteStore()
	route, err := routes.Create(t.Context(), OutboundRoute{Domain: " Routed.Example ", Transport: OutboundTransportMX, RelayHost: "ignored", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if route.Domain != "routed.example" || route.RelayHost != "" || route.RelayPort != 25 || !route.Enabled {
		t.Fatalf("unexpected MX route: %#v", route)
	}
	if _, err := routes.Create(t.Context(), route); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate error = %v", err)
	}

	relay, err := routes.Set(t.Context(), "ROUTED.EXAMPLE", OutboundRoute{Transport: OutboundTransportRelay, RelayHost: " smtp.relay.example ", RelayPort: 2525, RequireTLS: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if relay.RelayHost != "smtp.relay.example" || relay.RelayPort != 2525 || !relay.RequireTLS || relay.CreatedAt.IsZero() || relay.UpdatedAt.Before(relay.CreatedAt) {
		t.Fatalf("unexpected relay route: %#v", relay)
	}
	listed, err := routes.List(t.Context())
	if err != nil || len(listed) != 1 {
		t.Fatalf("list routes: len=%d err=%v", len(listed), err)
	}
	if err := routes.Delete(t.Context(), "routed.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := routes.Get(t.Context(), "routed.example"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get deleted route: %v", err)
	}
}

func TestOutboundRouteValidation(t *testing.T) {
	rs := routeTestStore(t).OutboundRouteStore()
	tests := []OutboundRoute{
		{Domain: "invalid", Transport: OutboundTransportMX},
		{Domain: "bad@example.test", Transport: OutboundTransportMX},
		{Domain: "route.example", Transport: "unknown"},
		{Domain: "route.example", Transport: OutboundTransportRelay},
		{Domain: "route.example", Transport: OutboundTransportRelay, RelayHost: "smtp.example", RelayPort: 70000},
	}
	for _, route := range tests {
		if _, err := rs.Create(t.Context(), route); err == nil {
			t.Fatalf("route should be rejected: %#v", route)
		}
	}
}

func TestOutboundRoutePersistsInPebbleStore(t *testing.T) {
	directory := t.TempDir()
	backend, err := pebblestore.New(directory)
	if err != nil {
		t.Fatal(err)
	}
	ts := NewTypedStore(backend, store.BackendPebble)
	if err := ts.EnsureNamespace(t.Context(), NSOutboundRoutes); err != nil {
		t.Fatal(err)
	}
	want, err := ts.OutboundRouteStore().Create(t.Context(), OutboundRoute{Domain: "mx.example", Transport: OutboundTransportMX, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := pebblestore.New(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := NewTypedStore(reopened, store.BackendPebble).OutboundRouteStore().Get(t.Context(), want.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != want.Domain || got.Transport != want.Transport || got.RelayPort != 25 {
		t.Fatalf("restored route: %#v", got)
	}
}
