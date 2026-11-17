package smtp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// startLiveServer runs srv's real accept loop on 127.0.0.1 and returns a
// dialer for new sessions.
func startLiveServer(t *testing.T, srv *Server) func() *tc {
	t.Helper()
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Accept(ctx, ln)
	t.Cleanup(func() { cancel(); srv.Close() })
	return func() *tc {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		client := &tc{Conn: conn, r: bufio.NewReader(conn)}
		if code, text, err := client.readReply(); err != nil || code != 220 {
			t.Fatalf("greeting = %d %q, %v", code, text, err)
		}
		return client
	}
}

func TestSetConfigAppliesToNewSessionsOnly(t *testing.T) {
	srv := New(&Config{ServerName: "test.veksel", MaxMessageSize: 1000})
	dial := startLiveServer(t, srv)
	established := dial()
	srv.SetConfig(&Config{ServerName: "test.veksel", MaxMessageSize: 2000})
	if _, text := established.send("EHLO client"); !strings.Contains(text, "SIZE 1000") {
		t.Fatalf("established session lost its configuration: %q", text)
	}
	if _, text := dial().send("EHLO client"); !strings.Contains(text, "SIZE 2000") {
		t.Fatalf("new session did not get the new configuration: %q", text)
	}
}

func TestGreylistToggleAppliesToNextSession(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	config := greylist.DefaultConfig()
	config.Enabled = false
	service, err := greylist.New(t.Context(), backend, config)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(&Config{ServerName: "test.veksel", Greylist: service, Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "folder", "alice", nil },
	}})
	dial := startLiveServer(t, srv)
	rcpt := func() int {
		client := dial()
		client.send("EHLO client")
		client.send("MAIL FROM:<sender@example.net>")
		code, _ := client.send("RCPT TO:<alice@example.com>")
		return code
	}
	if code := rcpt(); code != 250 {
		t.Fatalf("disabled greylisting answered %d", code)
	}
	if stats, err := service.Stats(t.Context()); err != nil || stats.Checks != 0 {
		t.Fatalf("disabled greylisting was consulted: %+v, %v", stats, err)
	}
	config.Enabled = true
	if err := service.SetConfig(config); err != nil {
		t.Fatal(err)
	}
	if code := rcpt(); code != 451 {
		t.Fatalf("enabled greylisting answered %d, want 451", code)
	}
}
