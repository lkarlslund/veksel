package imap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

// The per-IP authentication limiter slows password guessing, so successful
// logins must not consume it: OfflineIMAP or a mail app opens several
// authenticated connections at once, and many users may share one address.
func TestAuthLimiterCountsOnlyFailedLogins(t *testing.T) {
	t.Parallel()
	srv := New(&Config{
		ServerName:    "test.veksel",
		RateLimitAuth: true,
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if password != "secret" {
				return "", errors.New("bad credentials")
			}
			return username, nil
		},
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); srv.Close() })
	go srv.Accept(ctx, ln)

	login := func(password string) string {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)
		if _, err := r.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
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

	for i := 0; i < 60; i++ {
		if got := login("secret"); !strings.HasPrefix(got, "a1 OK") {
			t.Fatalf("successful login %d refused: %q", i, got)
		}
	}
	for i := 0; i < ratelimit.DefaultAuthFailuresPerIP; i++ {
		if got := login("wrong"); !strings.Contains(got, "Authentication failed") {
			t.Fatalf("failed login %d: %q", i, got)
		}
	}
	if got := login("wrong"); !strings.Contains(got, "Too many authentication attempts") {
		t.Fatalf("repeated failures must still be limited, got %q", got)
	}
}
