package imap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

// TestProxiedClientAddressDrivesAdmissionAndAuthThrottling serves IMAP behind
// a trusted PROXY protocol listener: connection admission, failed-login
// throttling, and the authentication context see the relayed client, not the
// proxy all clients share.
func TestProxiedClientAddressDrivesAdmissionAndAuthThrottling(t *testing.T) {
	var mu sync.Mutex
	var authIPs []string
	srv := New(&Config{
		ServerName:           "test.veksel",
		RateLimitAuth:        true,
		RateLimitConnections: true,
		ConnectionPolicy:     ratelimit.ConnectionPolicy{MaxPerIP: 1},
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			mu.Lock()
			authIPs = append(authIPs, ratelimit.ClientIP(ctx))
			mu.Unlock()
			if password != "secret" {
				return "", errors.New("bad credentials")
			}
			return username, nil
		},
	})
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := proto.NewProxyListener(inner, &proto.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close(); srv.Close() })
	go srv.Accept(ctx, ln)

	dial := func(client string) (net.Conn, *bufio.Reader, string) {
		t.Helper()
		conn, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "PROXY TCP4 %s 192.0.2.1 40000 143\r\n", client)
		r := bufio.NewReader(conn)
		greeting, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return conn, r, greeting
	}
	login := func(conn net.Conn, r *bufio.Reader, password string) string {
		t.Helper()
		fmt.Fprintf(conn, "a1 LOGIN alice %s\r\n", password)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(line, "a1 ") {
				return line
			}
		}
	}

	// One connection per client address: a second from the same relayed
	// client is refused while another relayed client is admitted.
	held, _, greeting := dial("203.0.113.7")
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting = %q", greeting)
	}
	if _, _, greeting := dial("203.0.113.7"); !strings.Contains(greeting, "Too many connections") {
		t.Fatalf("second connection from the same relayed client = %q", greeting)
	}
	if _, _, greeting := dial("203.0.113.8"); !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("other relayed client refused: %q", greeting)
	}
	_ = held.Close()

	guesser, guesses, _ := dial("203.0.113.9")
	for i := 0; i < ratelimit.DefaultAuthFailuresPerIP; i++ {
		if got := login(guesser, guesses, "wrong"); !strings.Contains(got, "Authentication failed") {
			t.Fatalf("failed login %d: %q", i, got)
		}
	}
	if got := login(guesser, guesses, "wrong"); !strings.Contains(got, "Too many authentication attempts") {
		t.Fatalf("relayed client not throttled: %q", got)
	}
	user, replies, _ := dial("203.0.113.10")
	if got := login(user, replies, "secret"); !strings.HasPrefix(got, "a1 OK") {
		t.Fatalf("throttling one relayed client blocked another: %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if last := authIPs[len(authIPs)-1]; last != "203.0.113.10" {
		t.Fatalf("authentication context client IP = %q, want the relayed client", last)
	}
}
