package proto

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSessionsShutdownWaitsForBusySessionThenClosesWhenIdle(t *testing.T) {
	var sessions Sessions
	server, client := net.Pipe()
	defer client.Close()
	tracked := sessions.Track(server)

	result := make(chan error, 1)
	go func() { result <- sessions.Shutdown(t.Context()) }()
	select {
	case err := <-result:
		t.Fatalf("Shutdown returned %v while a session was busy", err)
	case <-time.After(20 * time.Millisecond):
	}

	// Finishing the command and waiting for the next one closes the
	// connection; the session then ends.
	tracked.SetIdle(true)
	assertClosed(t, server)
	tracked.Done()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not return after the session ended")
	}
}

func TestSessionsShutdownClosesIdleSessionsImmediately(t *testing.T) {
	var sessions Sessions
	server, client := net.Pipe()
	defer client.Close()
	tracked := sessions.Track(server)
	tracked.SetIdle(true)
	go func() {
		// The session's blocked read fails once shutdown closes it.
		_, _ = server.Read(make([]byte, 1))
		tracked.Done()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := sessions.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
}

func TestSessionsShutdownReturnsAtDeadlineAndClosesHungSession(t *testing.T) {
	var sessions Sessions
	server, client := net.Pipe()
	defer client.Close()
	tracked := sessions.Track(server)
	defer tracked.Done()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := sessions.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline exceeded", err)
	}
	assertClosed(t, server)
}

func TestSessionsRejectConnectionsAfterShutdown(t *testing.T) {
	var sessions Sessions
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sessions.AddListener(listener)
	if err := sessions.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after shutdown = %v, want closed listener", err)
	}
	server, client := net.Pipe()
	defer client.Close()
	if sessions.Track(server) != nil {
		t.Fatal("Track accepted a connection after shutdown")
	}
	assertClosed(t, server)
}

// Protocol shutdown closes listeners to stop accepting before draining, so
// Shutdown must not report the second close as a failure.
func TestSessionsShutdownIgnoresAlreadyClosedListeners(t *testing.T) {
	var sessions Sessions
	for range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sessions.AddListener(listener)
	}
	if err := sessions.CloseListeners(); err != nil {
		t.Fatalf("CloseListeners = %v", err)
	}
	if err := sessions.CloseListeners(); err != nil {
		t.Fatalf("second CloseListeners = %v", err)
	}
	if err := sessions.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
}

func TestSessionsShutdownWithClosedListenerStillReportsHungSession(t *testing.T) {
	var sessions Sessions
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sessions.AddListener(listener)
	_ = listener.Close()
	server, client := net.Pipe()
	defer client.Close()
	tracked := sessions.Track(server)
	defer tracked.Done()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := sessions.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline exceeded", err)
	}
}

func assertClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read = %v, want closed connection", err)
	}
}
