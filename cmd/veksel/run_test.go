package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunReturnsErrorWhenStoreCannotOpen(t *testing.T) {
	dataDir := t.TempDir()
	// A regular file where the store directory belongs makes the open fail.
	if err := os.WriteFile(filepath.Join(dataDir, "pebble"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-data-dir", dataDir}); err == nil {
		t.Fatal("run succeeded with an unopenable store")
	}
}

func TestDrainForceClosesHangingHTTPRequestAtDeadline(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done() // a long poll that only ends when its connection does
		close(finished)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	go func() {
		if response, err := http.Get("http://" + listener.Addr().String()); err == nil {
			_ = response.Body.Close()
		}
	}()
	<-started

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	drain(ctx, []drainTarget{{name: "http", shutdown: shutdownHTTP(server)}})
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("hanging request was not cancelled after the drain deadline")
	}
}

func TestRunRejectsUnknownFlags(t *testing.T) {
	if err := run([]string{"-no-such-flag"}); err == nil {
		t.Fatal("run accepted an unknown flag")
	}
}
