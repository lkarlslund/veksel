package smtp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- Mail Forwarding Tests ---

func TestForwarding_sendsCopy(t *testing.T) {
	var forwardedTo string
	var forwardedMsg []byte
	var forwarded = false

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			GetForwardTo: func(ctx context.Context, userID string) string {
				if userID == "alice" {
					return "alice+forward@gmail.com"
				}
				return ""
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				forwarded = true
				forwardedTo = toAddr
				forwardedMsg = fullMsg
				return nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if !forwarded {
		t.Fatal("expected message to be forwarded")
	}
	if forwardedTo != "alice+forward@gmail.com" {
		t.Errorf("forwardedTo = %q, want %q", forwardedTo, "alice+forward@gmail.com")
	}
	if !strings.Contains(string(forwardedMsg), "Hello") {
		t.Error("forwarded message should contain original body")
	}
}

func TestForwarding_disabled(t *testing.T) {
	var forwarded bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			GetForwardTo: func(ctx context.Context, userID string) string {
				return "" // forwarding disabled
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				forwarded = true
				return nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if forwarded {
		t.Error("should not forward when forwarding is disabled")
	}
}

func TestForwardingAddsTraceAndLoopMetadata(t *testing.T) {
	var derived DerivedMessage
	session := &Session{cfg: &Config{Delivery: &Delivery{
		GetForwardTo: func(context.Context, string) string { return "target@example.net" },
		SendDerived: func(_ context.Context, message DerivedMessage) error {
			derived = message
			return nil
		},
	}}}
	headers := map[string]string{"From": "sender@example.test", "Subject": "Forward me"}
	message := buildMessage(headers, []byte("body"))
	session.handleForwarding("alice", "sender@example.test", message, headers, "parent-queue", "transaction-1", nil)
	if derived.Kind != "forward" || derived.ParentID != "parent-queue" || derived.CorrelationID != "transaction-1" || derived.EnvelopeSender != "sender@example.test" {
		t.Fatalf("derived metadata = %+v", derived)
	}
	forwardHeaders, _ := model.ParseMessageHeaders(derived.FullMessage)
	if forwardHeaders["X-Veksel-Forwarded-By"] != "alice" || forwardHeaders["X-Veksel-Forward-Hop"] != "1" {
		t.Fatalf("forward loop headers = %+v", forwardHeaders)
	}
}

func TestForwardingSuppressesVisitedUserAndHopLimit(t *testing.T) {
	calls := 0
	session := &Session{cfg: &Config{Delivery: &Delivery{
		GetForwardTo: func(context.Context, string) string { return "target@example.net" },
		SendDerived:  func(context.Context, DerivedMessage) error { calls++; return nil },
	}}}
	for _, headers := range []map[string]string{
		{"X-Veksel-Forwarded-By": "bob, Alice"},
		{"X-Veksel-Forward-Hop": "10"},
	} {
		session.handleForwarding("alice", "sender@example.test", buildMessage(headers, []byte("body")), headers, "parent", "correlation", nil)
	}
	if calls != 0 {
		t.Fatalf("looping forwards sent = %d", calls)
	}
}

func TestVacationFailedDerivedEnqueueCancelsReservation(t *testing.T) {
	cancelled := ""
	session := &Session{cfg: &Config{ServerName: "mail.example.test", Delivery: &Delivery{
		VacationActive: func(context.Context, string) bool { return true },
		VacationReply:  func(context.Context, string) (string, string) { return "Away", "Later" },
		ReserveVacationReply: func(context.Context, string, string) (string, bool, error) {
			return "lease-token", true, nil
		},
		CancelVacationReply: func(_ context.Context, _, _, token string) error { cancelled = token; return nil },
		SendDerived:         func(context.Context, DerivedMessage) error { return errors.New("queue unavailable") },
	}}}
	session.handleVacationReply("alice", "alice@example.test", "sender@example.net", map[string]string{"To": "alice@example.test"}, "parent", "correlation")
	if cancelled != "lease-token" {
		t.Fatalf("cancelled reservation = %q", cancelled)
	}
}

// --- Vacation Auto-Reply Tests ---

func TestVacationSuppressesAutomaticBulkListNullAndSelfMessages(t *testing.T) {
	tests := []struct {
		name      string
		sender    string
		recipient string
		headers   map[string]string
	}{
		{name: "null sender", sender: "<>", recipient: "alice@example.test"},
		{name: "self", sender: "alice@example.test", recipient: "alice@example.test"},
		{name: "automatic", sender: "bot@example.net", recipient: "alice@example.test", headers: map[string]string{"Auto-Submitted": "auto-generated"}},
		{name: "bulk", sender: "bulk@example.net", recipient: "alice@example.test", headers: map[string]string{"Precedence": "bulk"}},
		{name: "list id", sender: "list@example.net", recipient: "alice@example.test", headers: map[string]string{"List-Id": "example.list"}},
		{name: "unsubscribe", sender: "list@example.net", recipient: "alice@example.test", headers: map[string]string{"List-Unsubscribe": "<mailto:leave@example.net>"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !suppressAutomaticReply(test.sender, test.recipient, test.headers) {
				t.Fatal("message should suppress automatic reply")
			}
		})
	}
	if suppressAutomaticReply("person@example.net", "alice@example.test", map[string]string{"Auto-Submitted": "no"}) {
		t.Fatal("ordinary person-to-person message was suppressed")
	}
}

func TestVacation_replySent(t *testing.T) {
	var replyTo string
	var replyMsg []byte
	var replySent bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			VacationActive: func(ctx context.Context, userID string) bool {
				return userID == "alice"
			},
			VacationReply: func(ctx context.Context, userID string) (string, string) {
				return "Out of Office", "I am currently on vacation."
			},
			ShouldVacationReply: func(ctx context.Context, userID, sender string) bool {
				return true
			},
			RecordVacationReply: func(ctx context.Context, userID, sender string) error {
				return nil
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				replySent = true
				replyTo = toAddr
				replyMsg = fullMsg
				return nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\nMessage-ID: <123@test>\r\n\r\nHi Alice\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if !replySent {
		t.Fatal("expected vacation reply to be sent")
	}
	if replyTo != "bob@example.com" {
		t.Errorf("replyTo = %q, want %q", replyTo, "bob@example.com")
	}
	if !strings.Contains(string(replyMsg), "Out of Office") {
		t.Error("reply should contain vacation subject")
	}
	if !strings.Contains(string(replyMsg), "I am currently on vacation") {
		t.Error("reply should contain vacation message body")
	}
	if !strings.Contains(string(replyMsg), "Auto-Submitted: auto-replied") {
		t.Error("reply should contain Auto-Submitted header")
	}
	if !strings.Contains(string(replyMsg), "In-Reply-To: <123@test>") {
		t.Error("reply should contain In-Reply-To header")
	}
}

func TestVacation_notActive(t *testing.T) {
	var replySent bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			VacationActive: func(ctx context.Context, userID string) bool {
				return false // vacation not active
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				replySent = true
				return nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\n\r\nHi\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if replySent {
		t.Error("should not send vacation reply when not active")
	}
}

func TestVacation_rateLimited(t *testing.T) {
	var replyCount int
	var mu sync.Mutex

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			VacationActive: func(ctx context.Context, userID string) bool {
				return true
			},
			VacationReply: func(ctx context.Context, userID string) (string, string) {
				return "OOO", "Away"
			},
			ShouldVacationReply: func(ctx context.Context, userID, sender string) bool {
				mu.Lock()
				defer mu.Unlock()
				if replyCount >= 1 {
					return false // rate limited after first reply
				}
				return true
			},
			RecordVacationReply: func(ctx context.Context, userID, sender string) error {
				mu.Lock()
				defer mu.Unlock()
				replyCount++
				return nil
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				return nil
			},
		},
	})

	// First message from bob — should trigger a reply
	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Msg1\r\n\r\nHi\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// Second message from bob — should be rate limited
	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Msg2\r\n\r\nHi again\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	mu.Lock()
	count := replyCount
	mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 vacation reply, got %d", count)
	}
}

func TestVacation_differentSenders(t *testing.T) {
	// Track replies per sender
	replies := make(map[string]int)
	var mu sync.Mutex

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			VacationActive: func(ctx context.Context, userID string) bool {
				return true
			},
			VacationReply: func(ctx context.Context, userID string) (string, string) {
				return "OOO", "Away"
			},
			ShouldVacationReply: func(ctx context.Context, userID, sender string) bool {
				mu.Lock()
				defer mu.Unlock()
				return replies[sender] == 0
			},
			RecordVacationReply: func(ctx context.Context, userID, sender string) error {
				mu.Lock()
				defer mu.Unlock()
				replies[sender]++
				return nil
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				return nil
			},
		},
	})

	// Message from bob
	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Hi\r\n\r\nHello\r\n.\r\n")
	c.readReply()

	// Message from carol — different sender, should also get a reply
	c.send("EHLO client")
	c.send("MAIL FROM:<carol@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: carol@example.com\r\nTo: alice@example.com\r\nSubject: Hi\r\n\r\nHello\r\n.\r\n")
	c.readReply()

	mu.Lock()
	bobReplies := replies["bob@example.com"]
	carolReplies := replies["carol@example.com"]
	mu.Unlock()

	if bobReplies != 1 {
		t.Errorf("bob replies = %d, want 1", bobReplies)
	}
	if carolReplies != 1 {
		t.Errorf("carol replies = %d, want 1", carolReplies)
	}
}

// --- Model-level VacationActive tests ---

func TestVacationActive_dates(t *testing.T) {
	now := time.Now().UTC()

	// Active with no dates
	u1 := model.User{VacationEnabled: true, VacationMessage: "Hi"}
	if !u1.VacationActive() {
		t.Error("should be active with no dates")
	}

	// Disabled
	u2 := model.User{VacationEnabled: false, VacationMessage: "Hi"}
	if u2.VacationActive() {
		t.Error("should not be active when disabled")
	}

	// Before start date
	u3 := model.User{
		VacationEnabled: true,
		VacationStart:   now.Add(24 * time.Hour),
		VacationMessage: "Hi",
	}
	if u3.VacationActive() {
		t.Error("should not be active before start date")
	}

	// After end date
	u4 := model.User{
		VacationEnabled: true,
		VacationEnd:     now.Add(-24 * time.Hour),
		VacationMessage: "Hi",
	}
	if u4.VacationActive() {
		t.Error("should not be active after end date")
	}

	// Within date range
	u5 := model.User{
		VacationEnabled: true,
		VacationStart:   now.Add(-24 * time.Hour),
		VacationEnd:     now.Add(24 * time.Hour),
		VacationMessage: "Hi",
	}
	if !u5.VacationActive() {
		t.Error("should be active within date range")
	}

	// Empty message
	u6 := model.User{VacationEnabled: true, VacationMessage: ""}
	if u6.VacationActive() {
		t.Error("should not be active with empty message")
	}
}

// --- Forwarding + Vacation combined ---

func TestForwardingAndVacation_combined(t *testing.T) {
	var forwarded, replied bool

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
			GetForwardTo: func(ctx context.Context, userID string) string {
				return "alice@gmail.com"
			},
			SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
				// First call is forwarding, second is vacation reply
				if strings.Contains(string(fullMsg), "Auto-Submitted") {
					replied = true
				} else {
					forwarded = true
				}
				return nil
			},
			VacationActive: func(ctx context.Context, userID string) bool {
				return true
			},
			VacationReply: func(ctx context.Context, userID string) (string, string) {
				return "OOO", "Away"
			},
			ShouldVacationReply: func(ctx context.Context, userID, sender string) bool {
				return true
			},
			RecordVacationReply: func(ctx context.Context, userID, sender string) error {
				return nil
			},
		},
	})

	c.send("EHLO client")
	c.send("MAIL FROM:<bob@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if !forwarded {
		t.Error("expected message to be forwarded")
	}
	if !replied {
		t.Error("expected vacation reply to be sent")
	}
}
