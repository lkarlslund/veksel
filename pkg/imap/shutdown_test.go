package imap

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestShutdownClosesIdleSessionImmediately(t *testing.T) {
	server := New(&Config{ServerName: "test"})
	listener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Accept(t.Context(), listener)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reader := bufio.NewReader(client)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := reader.ReadString('\n'); err != io.EOF {
		t.Fatalf("read after shutdown = %v, want EOF", err)
	}
}
