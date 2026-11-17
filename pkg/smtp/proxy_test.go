package smtp

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/spam"
)

type recordingSpamChecker struct {
	mu        sync.Mutex
	remoteIPs []string
}

func (c *recordingSpamChecker) Check(_ context.Context, message spam.Message) (spam.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteIPs = append(c.remoteIPs, message.RemoteIP)
	return spam.Result{}, false
}

// TestProxiedClientAddressReachesMailPolicy serves SMTP behind a trusted
// PROXY protocol listener and checks that greylisting and spam scoring (which
// read the client address the same way as SPF, HELO, and DMARC reporting)
// evaluate the relayed client rather than the proxy.
func TestProxiedClientAddressReachesMailPolicy(t *testing.T) {
	var delivered []byte
	greylisting := &testGreylistChecker{decisions: []greylist.Decision{{Action: greylist.ActionPass}}}
	scoring := &recordingSpamChecker{}
	srv := New(&Config{
		ServerName: "mx.example.test",
		Greylist:   greylisting,
		Spam:       scoring,
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "folder", "user", nil },
			AppendMessage: func(_ context.Context, _ string, data []byte, _ map[string]string) (string, error) {
				delivered = append([]byte(nil), data...)
				return "item-1", nil
			},
		},
	})
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := proto.NewProxyListener(inner, &proto.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go srv.Accept(ctx, ln)

	conn, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("PROXY TCP6 2001:db8::25 2001:db8::1 41000 25\r\n")); err != nil {
		t.Fatal(err)
	}
	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	if code, _, _ := c.readReply(); code != 220 {
		t.Fatalf("greeting code = %d", code)
	}
	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@example.com>")
	if code, text := c.send("RCPT TO:<alice@example.com>"); code != 250 {
		t.Fatalf("RCPT = %d %s", code, text)
	}
	c.send("DATA")
	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	if code, text, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA = %d %s", code, text)
	}

	if len(greylisting.inputs) != 1 || greylisting.inputs[0].RemoteIP != "2001:db8::25" {
		t.Fatalf("greylisting saw %+v, want the relayed client", greylisting.inputs)
	}
	scoring.mu.Lock()
	defer scoring.mu.Unlock()
	if len(scoring.remoteIPs) != 1 || scoring.remoteIPs[0] != "2001:db8::25" {
		t.Fatalf("spam scoring saw %v, want the relayed client", scoring.remoteIPs)
	}
	if !strings.Contains(string(delivered), "Received: from client.example.com ([IPv6:2001:db8::25])\r\n\tby mx.example.test (Veksel) with ESMTP id ") {
		t.Fatalf("trace field does not name the relayed client:\n%s", delivered)
	}
}
