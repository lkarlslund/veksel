package managesieve

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestShutdownClosesIdleSessionImmediately(t *testing.T) {
	server := &Server{Repository: &service.SieveRepository{}, Authenticate: func(context.Context, string, string) (string, error) {
		return "", store.ErrNotFound
	}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reader := bufio.NewReader(client)
	readUntilStatus(t, reader)
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
