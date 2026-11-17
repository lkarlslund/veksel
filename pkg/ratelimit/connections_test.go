package ratelimit

import (
	"net/netip"
	"testing"
)

func TestConnectionGateAdmitsSharedAddressUpToConcurrentCap(t *testing.T) {
	gate := NewConnectionGate()
	policy := ConnectionPolicy{MaxPerIP: DefaultMaxConnectionsPerIP}
	var releases []func()
	for i := range DefaultMaxConnectionsPerIP {
		release, ok := gate.Admit("203.0.113.7:40000", policy)
		if !ok {
			t.Fatalf("connection %d from a shared address refused below the cap", i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := gate.Admit("203.0.113.7:40001", policy); ok {
		t.Fatal("connection above the concurrent cap admitted")
	}
	if _, ok := gate.Admit("198.51.100.1:40000", policy); !ok {
		t.Fatal("another address was refused because of the first address's connections")
	}
	releases[0]()
	releases[0]() // release is idempotent
	if _, ok := gate.Admit("203.0.113.7:40002", policy); !ok {
		t.Fatal("connection refused after one closed")
	}
	if _, ok := gate.Admit("203.0.113.7:40003", policy); ok {
		t.Fatal("double release freed two slots")
	}
}

func TestConnectionGateExemptPrefixesBypassLimits(t *testing.T) {
	gate := NewConnectionGate()
	policy := ConnectionPolicy{MaxPerIP: 1, Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for range connectionBurst + 10 {
		if _, ok := gate.Admit("[::ffff:10.1.2.3]:143", policy); !ok {
			t.Fatal("exempt address refused")
		}
	}
	if _, ok := gate.Admit("192.0.2.1:143", policy); !ok {
		t.Fatal("first connection refused")
	}
	if _, ok := gate.Admit("192.0.2.1:143", policy); ok {
		t.Fatal("non-exempt address exceeded its cap")
	}
}

func TestConnectionGateBoundsConnectionFloods(t *testing.T) {
	gate := NewConnectionGate()
	policy := ConnectionPolicy{} // no concurrent cap
	for i := range connectionBurst {
		release, ok := gate.Admit("192.0.2.9:1", policy)
		if !ok {
			t.Fatalf("connection %d inside the burst refused", i+1)
		}
		release()
	}
	if _, ok := gate.Admit("192.0.2.9:1", policy); ok {
		t.Fatal("connection flood beyond the burst admitted")
	}
}
