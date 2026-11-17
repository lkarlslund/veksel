package smtp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// otherServer is the server a domain is shared with: it hosts only bob.
func otherServer(t *testing.T) CalloutTarget {
	t.Helper()
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "exchange.test", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, recipient string) (string, string, error) {
			if recipient == "bob@example.test" {
				return "bob:inbox", "bob", nil
			}
			return "", "", store.ErrNotFound
		},
		MailQueue: &recordingSystemQueue{},
	}})
	t.Cleanup(cleanup)
	host, port, _ := net.SplitHostPort(addr)
	number, _ := strconv.Atoi(port)
	return CalloutTarget{Host: host, Port: number}
}

func TestRecipientCalloutAsksTheOtherServerAndCaches(t *testing.T) {
	target := otherServer(t)
	now := time.Unix(1_700_000_000, 0)
	callout := &RecipientCallout{Now: func() time.Time { return now }}
	if ok, err := callout.Check(t.Context(), target, "BOB@example.test"); err != nil || !ok {
		t.Fatalf("hosted recipient = %v, %v", ok, err)
	}
	if ok, err := callout.Check(t.Context(), target, "eve@example.test"); err != nil || ok {
		t.Fatalf("unknown recipient = %v, %v", ok, err)
	}
	// Cached answers need no server.
	callout.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") }
	if ok, err := callout.Check(t.Context(), target, "bob@example.test"); err != nil || !ok {
		t.Fatalf("cached answer = %v, %v", ok, err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := callout.Check(t.Context(), target, "bob@example.test"); err == nil {
		t.Fatal("expired answer served without asking")
	}
}

// Split delivery: a recipient the split policy routes is accepted and queued
// for relay; one it refuses is unknown; a failed check defers.
func TestUnknownRecipientsFollowTheSplitDeliveryPolicy(t *testing.T) {
	q := &recordingSystemQueue{}
	var peers []string
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "", "", store.ErrNotFound },
		RouteUnknownRecipient: func(_ context.Context, recipient, peer string) (bool, error) {
			peers = append(peers, peer)
			switch recipient {
			case "bob@example.test":
				return true, nil
			case "slow@example.test":
				return false, errors.New("callout timed out")
			}
			return false, nil
		},
		MailQueue: q,
	}})
	t.Cleanup(cleanup)

	if err := dialClient(t, addr).SendMail("carol@remote.test", []string{"bob@example.test"}, strings.NewReader(
		"From: carol@remote.test\r\nTo: bob@example.test\r\nSubject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("routed recipient refused: %v", err)
	}
	if len(q.messages) != 1 || q.messages[0].Recipient != "bob@example.test" || !q.messages[0].Outbound || q.messages[0].DKIM != nil {
		t.Fatalf("queued = %+v, want one unsigned outbound relay to bob", q.messages)
	}
	if len(peers) == 0 || peers[0] != "127.0.0.1" {
		t.Fatalf("policy saw peers %q, want the client address", peers)
	}
	err := dialClient(t, addr).SendMail("carol@remote.test", []string{"eve@example.test"}, strings.NewReader("Subject: x\r\n\r\nbody\r\n"))
	if err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("unhosted recipient: %v, want 550", err)
	}
	err = dialClient(t, addr).SendMail("carol@remote.test", []string{"slow@example.test"}, strings.NewReader("Subject: x\r\n\r\nbody\r\n"))
	if err == nil || !strings.Contains(err.Error(), "451") {
		t.Fatalf("failed check: %v, want 451", err)
	}
}
