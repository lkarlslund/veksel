package smtp

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// fixedSpamChecker scores every message with result.
type fixedSpamChecker struct{ result spam.Result }

func (c fixedSpamChecker) Check(context.Context, spam.Message) (spam.Result, bool) {
	return c.result, true
}

type recordedSpamtraps struct {
	mu   sync.Mutex
	hits []SpamtrapHit
}

func (r *recordedSpamtraps) record(_ context.Context, hit SpamtrapHit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, hit)
}

func (r *recordedSpamtraps) snapshot() []SpamtrapHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.hits)
}

func spamtrapDelivery(queue *recordingSystemQueue, traps *recordedSpamtraps) *Delivery {
	delivery := spamTestDelivery(queue, nil)
	resolve := delivery.ResolveRecipient
	delivery.ResolveRecipient = func(ctx context.Context, address string) (string, string, error) {
		if strings.HasPrefix(address, "trap@") {
			return "", "", errors.New("not found")
		}
		return resolve(ctx, address)
	}
	delivery.IsSpamtrap = func(_ context.Context, address string) (bool, error) { return address == "trap@example.test", nil }
	delivery.RecordSpamtrap = traps.record
	return delivery
}

func sendSpamtrapTransaction(t *testing.T, c *tc, recipients ...string) {
	t.Helper()
	c.send("EHLO client.example.test")
	c.send("MAIL FROM:<spammer@remote.test> RET=FULL")
	for _, recipient := range recipients {
		if code, text := c.send("RCPT TO:<" + recipient + "> NOTIFY=SUCCESS,FAILURE"); code != 250 {
			t.Fatalf("RCPT %s = %d %q, want 250", recipient, code, text)
		}
	}
	c.send("DATA")
	c.writeData(spamTestMessage + ".\r\n")
	if code, text, err := c.readReply(); err != nil || code != 250 {
		t.Fatalf("DATA completion = %d %q %v, want 250", code, text, err)
	}
	c.send("QUIT")
}

func TestSpamtrapIsAcceptedButNeverDelivered(t *testing.T) {
	queue, traps, reporter := &recordingSystemQueue{}, &recordedSpamtraps{}, &recordingReporter{}
	// The engine would reject the message; a trap-only transaction is
	// accepted anyway so the sender learns nothing.
	rejecting := fixedSpamChecker{spam.Result{Score: 50, Action: spam.ActionReject, Thresholds: spam.DefaultThresholds()}}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Spam: rejecting, Abuse: reporter, Delivery: spamtrapDelivery(queue, traps)})
	sendSpamtrapTransaction(t, c, "trap@example.test")

	if len(queue.messages) != 0 {
		t.Fatalf("trap mail was queued (delivery or DSN): %#v", queue.messages)
	}
	hits := traps.snapshot()
	if len(hits) != 1 || !slices.Equal(hits[0].Traps, []string{"trap@example.test"}) || hits[0].Mixed ||
		hits[0].EnvelopeSender != "spammer@remote.test" || hits[0].RemoteIP != "127.0.0.1" || !strings.Contains(string(hits[0].Message), "\r\n\r\nbody\r\n") || hits[0].CorrelationID == "" {
		t.Fatalf("hits = %#v", hits)
	}
	if got := reporter.recorded(); !slices.Equal(got, []ban.Trigger{ban.TriggerSpamtrap}) {
		t.Fatalf("strikes = %v, want one spamtrap strike", got)
	}
}

func TestSpamtrapMarksRealRecipientsCopies(t *testing.T) {
	queue, traps, reporter := &recordingSystemQueue{}, &recordedSpamtraps{}, &recordingReporter{}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Abuse: reporter, Delivery: spamtrapDelivery(queue, traps)})
	sendSpamtrapTransaction(t, c, "alice@example.test", "trap@example.test")

	if len(queue.messages) != 1 {
		t.Fatalf("queued = %#v, want only alice's copy", queue.messages)
	}
	copy := queue.messages[0]
	if copy.Recipient != "alice@example.test" || copy.TargetFolderID != "alice@example.test:Junk" ||
		!strings.Contains(copy.Headers["X-Spam-Symbols"], spam.SymbolSpamtrapHit+"(10)") || copy.Headers["X-Spam-Flag"] != "YES" {
		t.Fatalf("alice's copy = %#v", copy)
	}
	if hits := traps.snapshot(); len(hits) != 1 || !hits[0].Mixed {
		t.Fatalf("hits = %#v", hits)
	}
	if got := reporter.recorded(); !slices.Equal(got, []ban.Trigger{ban.TriggerSpamtrap}) {
		t.Fatalf("strikes = %v", got)
	}
}

func TestSpamtrapDoesNotApplyToAuthenticatedOrFailingLookups(t *testing.T) {
	traps := &recordedSpamtraps{}
	delivery := spamtrapDelivery(&recordingSystemQueue{}, traps)
	session := &Session{cfg: &Config{Delivery: delivery}, ctx: context.Background(), authenticated: true}
	if trap, err := session.isSpamtrap("trap@example.test"); trap || err != nil {
		t.Fatalf("authenticated session treated trap as trap: %v %v", trap, err)
	}

	delivery.IsSpamtrap = func(context.Context, string) (bool, error) { return false, errors.New("directory down") }
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Delivery: delivery})
	c.send("EHLO client.example.test")
	c.send("MAIL FROM:<spammer@remote.test>")
	if code, _ := c.send("RCPT TO:<trap@example.test>"); code != 451 {
		t.Fatalf("RCPT with failing trap lookup = %d, want 451", code)
	}
}
