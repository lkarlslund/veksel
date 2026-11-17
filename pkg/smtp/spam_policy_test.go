package smtp

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// tableResolver answers blocklist queries from a table; anything else is
// NXDOMAIN. Tests never reach real DNS.
type tableResolver map[string][]string

func (r tableResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	name := strings.TrimSuffix(host, ".")
	if answers, ok := r[name]; ok {
		return answers, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// publicSourceChecker scores as if the loopback test client connected from
// a public address, so blocklist lookups are not skipped as private.
type publicSourceChecker struct{ engine *spam.Engine }

const testSpamSource = "203.0.113.7"

func (c publicSourceChecker) Check(ctx context.Context, message spam.Message) (spam.Result, bool) {
	message.RemoteIP = testSpamSource
	return c.engine.Check(ctx, message)
}

func listedSourceChecker(t *testing.T, answers ...string) publicSourceChecker {
	t.Helper()
	config, err := spam.ParseSettings(spam.Settings{Thresholds: spam.DefaultThresholds(), DNSBL: []string{"zen.spamhaus.org"}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := spam.NewEngine(config, spam.NewDNS(tableResolver{"7.113.0.203.zen.spamhaus.org": answers}, spam.DNSOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return publicSourceChecker{engine: engine}
}

func spamTestDelivery(queue *recordingSystemQueue, allow []string) *Delivery {
	return &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			return address + ":INBOX", address, nil
		},
		GetSpamConfig:    func(context.Context, string) (bool, float64, error) { return true, 0, nil },
		GetSpamWhitelist: func(context.Context, string) ([]string, error) { return allow, nil },
		GetJunkFolderID:  func(_ context.Context, userID string) (string, error) { return userID + ":Junk", nil },
		MailQueue:        queue,
	}
}

// spamTestMessage carries a current Date so date anomaly scoring stays quiet.
var spamTestMessage = "From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: hello\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nX-Spam-Flag: NO\r\n\r\nbody\r\n"

func TestListedSourceIsRejectedAtTheRejectThreshold(t *testing.T) {
	queue := &recordingSystemQueue{}
	// SBL 4 + XBL 5 + DROP 7 reaches the default reject threshold of 15.
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: listedSourceChecker(t, "127.0.0.2", "127.0.0.4", "127.0.0.9"), Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(spamTestMessage))
	if err == nil || !strings.Contains(err.Error(), "550") || !strings.Contains(err.Error(), "spam") {
		t.Fatalf("listed source error = %v, want 550 spam rejection", err)
	}
	if len(queue.messages) != 0 {
		t.Fatalf("rejected message was queued: %#v", queue.messages)
	}
}

func TestMidScoreMessageIsFiledInJunkWithEvidence(t *testing.T) {
	queue := &recordingSystemQueue{}
	// XBL 5 + PBL 1.5 + DKIM_MISSING 0.5 + MISSING_MESSAGE_ID 0.5 = 7.5 passes the junk
	// threshold of 6 without reaching rejection; the generated Message-ID is not credited.
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: listedSourceChecker(t, "127.0.0.4", "127.0.0.10"), Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	if err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(spamTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("queued = %#v", queue.messages)
	}
	message := queue.messages[0]
	if message.TargetFolderID != "alice@example.test:Junk" || message.Headers["X-Spam-Flag"] != "YES" {
		t.Fatalf("folder %q headers %#v", message.TargetFolderID, message.Headers)
	}
	if symbols := message.Headers["X-Spam-Symbols"]; !strings.Contains(symbols, "RBL_SPAMHAUS_XBL(5)") || !strings.Contains(symbols, "RBL_SPAMHAUS_PBL(1.5)") {
		t.Fatalf("X-Spam-Symbols = %q", symbols)
	}
	if !strings.Contains(string(message.Content), "X-Spam-Status: Yes, score=7.5 required=6") {
		t.Fatalf("durable content lacks the verdict (peer X-Spam-Flag must be replaced): %s", message.Content)
	}
	if strings.Contains(string(message.Content), "X-Spam-Flag: NO") {
		t.Fatal("peer-supplied X-Spam-Flag survived")
	}
	if transcript := message.Attributes["scan_transcript"]; !strings.Contains(transcript, `"engine":"antispam"`) || !strings.Contains(transcript, "RBL_SPAMHAUS_XBL") || !strings.Contains(transcript, testSpamSource) {
		t.Fatalf("scan transcript = %s", transcript)
	}
	if message.Attributes["scan_summary"] != "antispam=spam" {
		t.Fatalf("scan summary = %q", message.Attributes["scan_summary"])
	}
}

func TestAllowListedSenderIsNeverRejected(t *testing.T) {
	queue := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: listedSourceChecker(t, "127.0.0.2", "127.0.0.4", "127.0.0.9"), Delivery: spamTestDelivery(queue, []string{"remote.test"})})
	t.Cleanup(cleanup)
	if err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(spamTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 || queue.messages[0].TargetFolderID != "alice@example.test:INBOX" {
		t.Fatalf("allow-listed delivery = %#v", queue.messages)
	}
	headers := queue.messages[0].Headers
	if headers["X-Spam-Flag"] != "" || !strings.Contains(headers["X-Spam-Symbols"], "USER_ALLOWLIST(0)") || !strings.Contains(headers["X-Spam-Symbols"], "RBL_SPAMHAUS_DROP") {
		t.Fatalf("allow-listed headers must keep the evidence without flagging: %#v", headers)
	}
}

type scoreGreylist struct {
	testGreylistChecker
	scoreTriggered bool
}

func (g *scoreGreylist) Enabled() bool        { return true }
func (g *scoreGreylist) ScoreTriggered() bool { return g.scoreTriggered }

func TestScoreTriggeredGreylistingDefersOnlyScoredMessages(t *testing.T) {
	checker := &scoreGreylist{scoreTriggered: true, testGreylistChecker: testGreylistChecker{decisions: []greylist.Decision{
		{Action: greylist.ActionDefer, RetryAfter: 5 * time.Minute}, {Action: greylist.ActionDefer, RetryAfter: 5 * time.Minute},
	}}}
	queue := &recordingSystemQueue{}
	// SBL 4 + DKIM_MISSING 0.5 reaches the greylist threshold of 4.
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Greylist: checker, Spam: listedSourceChecker(t, "127.0.0.2"), Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test", "bob@example.test"}, strings.NewReader(spamTestMessage))
	if err == nil || !strings.Contains(err.Error(), "451") || !strings.Contains(err.Error(), "Greylisting") {
		t.Fatalf("scored message error = %v, want 451 greylisting", err)
	}
	if len(checker.inputs) != 2 || checker.inputs[0].RemoteIP != "127.0.0.1" || checker.inputs[1].Recipient != "bob@example.test" || len(queue.messages) != 0 {
		t.Fatalf("triplets = %#v queued = %d; every recipient must be recorded after DATA, not at RCPT", checker.inputs, len(queue.messages))
	}

	// A clean message is never greylisted in score mode.
	clean := &scoreGreylist{scoreTriggered: true}
	addr, cleanup = startSMTPServer(t, &Config{ServerName: "test.veksel", Greylist: clean, Spam: listedSourceChecker(t), Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	if err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(spamTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(clean.inputs) != 0 || len(queue.messages) != 1 {
		t.Fatalf("clean message consulted greylisting %d times, queued %d", len(clean.inputs), len(queue.messages))
	}
}

// verdictClassifier returns a fixed classifier symbol per user; "" is the
// shared model.
type verdictClassifier struct {
	verdicts map[string]spam.Symbol
	mu       sync.Mutex
	learned  []string
}

// learnedOffers waits for want auto-learning offers: they run after the
// session has already replied 250, so the client can finish first.
func (c *verdictClassifier) learnedOffers(want int) []string {
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		c.mu.Lock()
		learned := slices.Clone(c.learned)
		c.mu.Unlock()
		if len(learned) >= want || !time.Now().Before(deadline) {
			return learned
		}
	}
}

func (c *verdictClassifier) Classify(_ context.Context, userID string, tokens []string) (spam.Symbol, bool) {
	symbol, ok := c.verdicts[userID]
	return symbol, ok && len(tokens) > 0
}

func (c *verdictClassifier) Autolearn(_ context.Context, userID string, sample spam.Sample, result spam.Result, trusted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.learned = append(c.learned, fmt.Sprintf("%s:%v:%t:%t", userID, result.Score, trusted, sample.Key != ""))
}

func TestClassifierScoresEachRecipientWithoutChangingTransactionActions(t *testing.T) {
	queue := &recordingSystemQueue{}
	classifier := &verdictClassifier{verdicts: map[string]spam.Symbol{
		"alice@example.test": {Name: "BAYES_SPAM", Score: 5}, "bob@example.test": {Name: "BAYES_HAM", Score: -3},
	}}
	// SBL 4 + XBL 5 + PBL 1.5 + DKIM_MISSING 0.5 + MISSING_MESSAGE_ID 0.5 = 11.5
	// stays below the reject threshold; alice's own model taking her copy to
	// 16.5 must not reject the transaction for bob.
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: listedSourceChecker(t, "127.0.0.2", "127.0.0.4", "127.0.0.10"), Classifier: classifier, Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	if err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test", "bob@example.test"}, strings.NewReader(spamTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 2 {
		t.Fatalf("queued = %#v", queue.messages)
	}
	for _, message := range queue.messages {
		symbols, status := message.Headers["X-Spam-Symbols"], message.Headers["X-Spam-Status"]
		switch message.Recipient {
		case "alice@example.test":
			if message.TargetFolderID != "alice@example.test:Junk" || !strings.Contains(symbols, "BAYES_SPAM(5)") || !strings.Contains(status, "score=16.5") {
				t.Fatalf("alice = %q %#v", message.TargetFolderID, message.Headers)
			}
			if !strings.Contains(message.Attributes["scan_transcript"], "BAYES_SPAM") {
				t.Fatalf("alice's evidence lacks her classifier symbol: %s", message.Attributes["scan_transcript"])
			}
		case "bob@example.test":
			if !strings.Contains(symbols, "BAYES_HAM(-3)") || strings.Contains(symbols, "BAYES_SPAM") || !strings.Contains(status, "score=8.5") {
				t.Fatalf("bob = %q %#v", message.TargetFolderID, message.Headers)
			}
			if strings.Contains(message.Attributes["scan_transcript"], "BAYES_SPAM") {
				t.Fatalf("bob's evidence carries alice's symbol: %s", message.Attributes["scan_transcript"])
			}
		default:
			t.Fatalf("unexpected recipient %q", message.Recipient)
		}
	}
	if learned := classifier.learnedOffers(2); strings.Join(learned, ",") != "alice@example.test:16.5:false:true,bob@example.test:8.5:false:true" {
		t.Fatalf("auto-learning offers = %q", learned)
	}
}

func TestSharedClassifierModelCanRejectTheTransaction(t *testing.T) {
	queue := &recordingSystemQueue{}
	classifier := &verdictClassifier{verdicts: map[string]spam.Symbol{"": {Name: "BAYES_SPAM", Score: 5}}}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: listedSourceChecker(t, "127.0.0.2", "127.0.0.4", "127.0.0.10"), Classifier: classifier, Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(spamTestMessage))
	if err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("shared model verdict error = %v, want 550", err)
	}
	if learned := classifier.learnedOffers(0); len(queue.messages) != 0 || len(learned) != 0 {
		t.Fatalf("rejected message was delivered or learned: %#v %q", queue.messages, learned)
	}
}
