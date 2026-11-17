package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// startBusySMTPSession connects to an implicit-TLS server without starting
// the handshake, leaving the session busy until the client goes away.
func startBusySMTPSession(t *testing.T) (*Server, net.Conn) {
	t.Helper()
	server := New(&Config{ServerName: "test", TLSConfig: &tls.Config{}, ImplicitTLS: true})
	listener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Accept(t.Context(), listener)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	waitSMTPConnections(t, server.connections, 1)
	return server, client
}

func TestShutdownWaitsForActiveSession(t *testing.T) {
	server, client := startBusySMTPSession(t)
	result := make(chan error, 1)
	go func() { result <- server.Shutdown(t.Context()) }()
	select {
	case err := <-result:
		t.Fatalf("Shutdown returned %v with an active session", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = client.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the session ended")
	}
}

func TestShutdownReturnsAtDeadlineForHungSession(t *testing.T) {
	server, client := startBusySMTPSession(t)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline exceeded", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var netErr net.Error
	if _, err := client.Read(make([]byte, 1)); err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("hung session read = %v, want connection closed by server", err)
	}
}
