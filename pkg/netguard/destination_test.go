package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// TestAllowDestinationIsPortSpecific: an allowed internal address:port can
// be dialed, the same address on another port cannot.
func TestAllowDestinationIsPortSpecific(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	allowed := netip.MustParseAddrPort(listener.Addr().String())
	dialer := &Dialer{AllowDestination: func(address netip.AddrPort) bool { return address == allowed }}
	conn, err := dialer.DialContext(context.Background(), "tcp", allowed.String())
	if err != nil {
		t.Fatalf("allowed destination refused: %v", err)
	}
	_ = conn.Close()
	other := netip.AddrPortFrom(allowed.Addr(), allowed.Port()+1)
	if _, err := dialer.DialContext(context.Background(), "tcp", other.String()); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("other port on the same internal address = %v, want ErrForbiddenAddress", err)
	}
	if _, err := (&Dialer{}).DialContext(context.Background(), "tcp", allowed.String()); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("dialer without allowances reached loopback: %v", err)
	}
}
