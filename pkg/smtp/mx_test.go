package smtp

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestMXLookup_RealDomain(t *testing.T) {
	// Test with a real domain that has MX records
	// gmail.com should have MX records
	host, port, err := mxLookup(context.Background(), "gmail.com")
	if err != nil {
		t.Skipf("skipping MX lookup test: %v", err)
	}
	if host == "" {
		t.Error("expected non-empty host for gmail.com")
	}
	if port != 25 {
		t.Errorf("port = %d, want 25", port)
	}
}

func TestRelayResolveTargetsUsesAllMXRecordsInPreferenceOrder(t *testing.T) {
	client := NewRelayClient(&RelayConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
		return []*net.MX{{Host: "backup.example.test.", Pref: 20}, {Host: "primary.example.test.", Pref: 10}}, nil
	}})
	targets, err := client.resolveTargets(t.Context(), "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{targets[0].Host, targets[1].Host}
	want := []string{"primary.example.test", "backup.example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

func TestRelayResolveTargetsFallsBackToAddressRecord(t *testing.T) {
	client := NewRelayClient(&RelayConfig{
		LookupMX:   func(context.Context, string) ([]*net.MX, error) { return nil, nil },
		LookupHost: func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil },
	})
	targets, err := client.resolveTargets(t.Context(), "alice@example.test")
	if err != nil || len(targets) != 1 || targets[0].Host != "example.test" || targets[0].Port != 25 {
		t.Fatalf("targets = %#v, err = %v", targets, err)
	}
}

func TestMXLookup_NonexistentDomain(t *testing.T) {
	_, _, err := mxLookup(context.Background(), "this-domain-does-not-exist-xyz123.com")
	if err == nil {
		t.Fatal("expected error for nonexistent domain, got nil")
	}
}

func TestMXLookup_ContextCancellation(t *testing.T) {
	// Note: net.LookupMX does not support context cancellation.
	// The context parameter is reserved for future use.
	// This test verifies that a cancelled context does not cause a panic.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should not panic even with cancelled context
	_, _, _ = mxLookup(ctx, "gmail.com")
}
