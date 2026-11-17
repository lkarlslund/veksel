package smtp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/spam"
)

type recordingSystemQueue struct {
	messages []*MailMessage
	batchErr error
}

func TestTypedContentScannerSpamRoutesJunkAndPersistsEvidence(t *testing.T) {
	queue := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient:    func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil },
		GetSpamConfig:       func(context.Context, string) (bool, float64, error) { return false, 5, nil },
		GetJunkFolderID:     func(context.Context, string) (string, error) { return "alice:Junk", nil },
		MailQueue:           queue,
		GetVirusScanEnabled: func() bool { return true },
		ContentScan: func(context.Context, contentscan.Message) contentscan.Report {
			return contentscan.Report{Results: []contentscan.Result{{
				Engine: "rspamd", Verdict: contentscan.VerdictSpam, Score: 8.5, RequiredScore: 6,
				Symbols: []contentscan.Symbol{{Name: "BAYES_SPAM", Score: 4.5}},
			}}}
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: scanner evidence\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("queued messages = %#v", queue.messages)
	}
	message := queue.messages[0]
	if message.TargetFolderID != "alice:Junk" || message.Headers["X-Spam-Flag"] != "YES" || message.Headers["X-Veksel-Content-Scan"] != "rspamd=spam" || message.Attributes["scan_transcript"] == "" {
		t.Fatalf("scanned message = %#v", message)
	}
	if !strings.Contains(string(message.Content), "X-Veksel-Content-Scan: rspamd=spam") || !strings.Contains(string(message.Content), "X-Spam-Flag: YES") {
		t.Fatalf("durable content lacks scanner headers: %s", message.Content)
	}
}

func TestTypedContentScannerOutagePoliciesAreTransactional(t *testing.T) {
	t.Run("defer", func(t *testing.T) {
		queue := &recordingSystemQueue{}
		addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "alice", nil }, MailQueue: queue,
			GetVirusScanEnabled: func() bool { return true },
			ContentScan: func(context.Context, contentscan.Message) contentscan.Report {
				return contentscan.Report{Decision: contentscan.DecisionDefer, Results: []contentscan.Result{{Engine: "rspamd", ErrorCode: "timeout", Error: "deadline"}}}
			},
		}})
		t.Cleanup(cleanup)
		client := dialClient(t, addr)
		err := client.SendMail("sender@remote.test", []string{"one@example.test", "two@example.test"}, strings.NewReader("From: sender@remote.test\r\n\r\nbody"))
		if err == nil || len(queue.messages) != 0 {
			t.Fatalf("deferred error=%v queued=%#v", err, queue.messages)
		}
	})
	t.Run("quarantine", func(t *testing.T) {
		queue := &recordingSystemQueue{}
		addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil }, MailQueue: queue,
			GetVirusScanEnabled: func() bool { return true },
			ContentScan: func(context.Context, contentscan.Message) contentscan.Report {
				return contentscan.Report{Decision: contentscan.DecisionQuarantine, Results: []contentscan.Result{{Engine: "clamav", ErrorCode: "scanner_error", Error: "unavailable"}}}
			},
		}})
		t.Cleanup(cleanup)
		client := dialClient(t, addr)
		if err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader("From: sender@remote.test\r\nSubject: held\r\n\r\nbody")); err != nil {
			t.Fatal(err)
		}
		if len(queue.messages) != 1 || queue.messages[0].Kind != MailTaskQuarantine || queue.messages[0].TargetOwnerID != "alice" || queue.messages[0].Attributes["scan_transcript"] == "" || queue.messages[0].Attributes["reason_type"] != "content_scan" {
			t.Fatalf("quarantine messages = %#v", queue.messages)
		}
	})
}

func TestTypedContentScannerRejectsInboundMalware(t *testing.T) {
	queue := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil }, MailQueue: queue,
		GetVirusScanEnabled: func() bool { return true },
		ContentScan: func(context.Context, contentscan.Message) contentscan.Report {
			return contentscan.Report{Decision: contentscan.DecisionQuarantine, Results: []contentscan.Result{{Engine: "clamav", Verdict: contentscan.VerdictMalware, MalwareNames: []string{"Eicar-Signature"}}}}
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader("From: sender@remote.test\r\n\r\nmalware"))
	if err == nil || len(queue.messages) != 0 {
		t.Fatalf("malware error=%v queued=%#v", err, queue.messages)
	}
}

func TestDSNPreferencesPersistPerQueuedRecipient(t *testing.T) {
	q := &recordingSystemQueue{}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			return address + ":INBOX", address, nil
		},
		MailQueue: q,
	}})
	if code, text := c.send("EHLO client"); code != 250 || !strings.Contains(text, "DSN") {
		t.Fatalf("EHLO code=%d text=%s", code, text)
	}
	if code, text := c.send("MAIL FROM:<sender@example.test> RET=HDRS ENVID=job+2Bid"); code != 250 {
		t.Fatalf("MAIL code=%d text=%s", code, text)
	}
	if code, text := c.send("RCPT TO:<first@example.test> NOTIFY=NEVER ORCPT=rfc822;first+40old.test"); code != 250 {
		t.Fatalf("first RCPT code=%d text=%s", code, text)
	}
	if code, text := c.send("RCPT TO:<second@example.test> NOTIFY=FAILURE,DELAY"); code != 250 {
		t.Fatalf("second RCPT code=%d text=%s", code, text)
	}
	if code, text := c.send("DATA"); code != 354 {
		t.Fatalf("DATA code=%d text=%s", code, text)
	}
	c.writeData("From: sender@example.test\r\nTo: first@example.test, second@example.test\r\nSubject: preferences\r\n\r\nbody\r\n.\r\n")
	if code, text, err := c.readReply(); err != nil || code != 250 {
		t.Fatalf("DATA completion code=%d text=%s error=%v", code, text, err)
	}
	if len(q.messages) != 2 {
		t.Fatalf("queued messages=%#v", q.messages)
	}
	byRecipient := map[string]*MailMessage{q.messages[0].Recipient: q.messages[0], q.messages[1].Recipient: q.messages[1]}
	first, second := byRecipient["first@example.test"], byRecipient["second@example.test"]
	if first == nil || first.Attributes["dsn_notify"] != "never" || first.Attributes["dsn_original_recipient"] != "rfc822;first+40old.test" {
		t.Fatalf("first recipient attributes=%#v", first)
	}
	if second == nil || second.Attributes["dsn_notify"] != "failure,delay" {
		t.Fatalf("second recipient attributes=%#v", second)
	}
	for _, message := range q.messages {
		if message.Attributes["dsn_return"] != "hdrs" || message.Attributes["dsn_envelope_id"] != "job+2Bid" {
			t.Fatalf("shared DSN attributes=%#v", message.Attributes)
		}
	}
}

func (q *recordingSystemQueue) Enqueue(msg *MailMessage) error {
	q.messages = append(q.messages, msg)
	return nil
}

func (q *recordingSystemQueue) EnqueueBatch(messages []*MailMessage) error {
	if q.batchErr != nil {
		return q.batchErr
	}
	q.messages = append(q.messages, messages...)
	return nil
}

func TestPolicyAdmissionRejectionPreservesEnhancedSMTPStatus(t *testing.T) {
	q := &recordingSystemQueue{batchErr: &mailpolicy.RejectionError{Reason: "blocked by administrator", EnhancedStatusCode: "5.7.7"}}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			return address + ":INBOX", address, nil
		},
		MailQueue: q,
	}})
	for _, command := range []string{"EHLO client", "MAIL FROM:<sender@example.test>", "RCPT TO:<user@example.test>", "DATA"} {
		code, text := c.send(command)
		if command == "DATA" && code != 354 {
			t.Fatalf("DATA code=%d text=%s", code, text)
		}
	}
	c.writeData("From: sender@example.test\r\nTo: user@example.test\r\n\r\nbody\r\n.\r\n")
	code, text, err := c.readReply()
	if err != nil || code != 550 || !strings.Contains(text, "5.7.7 blocked by administrator") {
		t.Fatalf("policy rejection code=%d text=%q err=%v", code, text, err)
	}
	if len(q.messages) != 0 {
		t.Fatalf("rejected messages were queued: %+v", q.messages)
	}
}

type testTemporaryRejection struct{}

func (testTemporaryRejection) Error() string { return "sending limit reached" }
func (testTemporaryRejection) TemporaryRejection() (string, string) {
	return "4.7.0", "sending limit reached: at most 3 recipients per hour; try again in 20 min"
}

func TestQueueTemporaryRejectionAnswers451WithReason(t *testing.T) {
	q := &recordingSystemQueue{batchErr: fmt.Errorf("queue admission: %w", testTemporaryRejection{})}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			return address + ":INBOX", address, nil
		},
		MailQueue: q,
	}})
	for _, command := range []string{"EHLO client", "MAIL FROM:<sender@example.test>", "RCPT TO:<user@example.test>", "DATA"} {
		c.send(command)
	}
	c.writeData("From: sender@example.test\r\nTo: user@example.test\r\n\r\nbody\r\n.\r\n")
	code, text, err := c.readReply()
	if err != nil || code != 451 || !strings.Contains(text, "4.7.0 sending limit reached: at most 3 recipients per hour") {
		t.Fatalf("temporary rejection code=%d text=%q err=%v", code, text, err)
	}
	if len(q.messages) != 0 {
		t.Fatalf("rejected messages were queued: %+v", q.messages)
	}
}

func TestFilterLookupFailureRejectsWholeRecipientBatch(t *testing.T) {
	q := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			return address + ":INBOX", address, nil
		},
		AppendMessage:       func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:           q,
		GetVirusScanEnabled: func() bool { return true },
		GetVirusScanEnabledForDomain: func(_ context.Context, domain string) (bool, error) {
			if domain == "broken.test" {
				return false, errors.New("policy store unavailable")
			}
			return true, nil
		},
		VirusScan: func([]byte) (string, bool, error) { return "", false, nil },
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	err := client.SendMail("sender@remote.test", []string{"first@healthy.test", "second@broken.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: first@healthy.test, second@broken.test\r\nSubject: atomic filters\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("DATA succeeded despite unavailable recipient filter policy")
	}
	if len(q.messages) != 0 {
		t.Fatalf("partially accepted filtered batch: %#v", q.messages)
	}
}

func TestSpamPolicyFailureRejectsWholeRecipientBatch(t *testing.T) {
	q := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        q,
		GetSpamConfig: func(_ context.Context, userID string) (bool, float64, error) {
			if strings.HasPrefix(userID, "second@") {
				return false, 0, errors.New("account policy unavailable")
			}
			return false, 5, nil
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	err := client.SendMail("sender@remote.test", []string{"first@example.test", "second@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: first@example.test, second@example.test\r\nSubject: atomic spam policy\r\n\r\nbody\r\n"))
	if err == nil || len(q.messages) != 0 {
		t.Fatalf("spam policy failure error=%v queued=%#v", err, q.messages)
	}
}

func TestRecipientFilterHeadersAreIsolated(t *testing.T) {
	q := &recordingSystemQueue{}
	scorer, err := spam.NewEngine(spam.Config{Thresholds: spam.DefaultThresholds()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: scorer, Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        q,
		GetSpamConfig: func(_ context.Context, userID string) (bool, float64, error) {
			return strings.HasPrefix(userID, "junk@"), -1, nil
		},
		GetJunkFolderID: func(_ context.Context, userID string) (string, error) { return userID + ":Junk", nil },
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.SendMail("sender@remote.test", []string{"junk@example.test", "clean@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: junk@example.test, clean@example.test\r\nSubject: isolated headers\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	// The junk account's own threshold flags the message; the account with
	// filtering off sees the same score judged against the server threshold.
	if len(q.messages) != 2 || q.messages[0].Headers["X-Spam-Flag"] != "YES" || q.messages[0].TargetFolderID != "junk@example.test:Junk" ||
		q.messages[1].Headers["X-Spam-Flag"] != "" || !strings.HasPrefix(q.messages[1].Headers["X-Spam-Status"], "No,") {
		t.Fatalf("recipient headers leaked: %#v %#v", q.messages[0].Headers, q.messages[1].Headers)
	}
}

func TestSieveLookupFailureCannotEnterRetryQueueUnfiltered(t *testing.T) {
	q := &recordingSystemQueue{}
	s := &Session{stagingDelivery: true, cfg: &Config{Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "alice", nil },
		GetSieveScript: func(context.Context, string) (string, bool, error) {
			return "", false, errors.New("policy store unavailable")
		},
		MailQueue: q,
	}}}
	err := s.deliverMessage("alice@example.test", map[string]string{"From": "sender@example.net"}, []byte("body"))
	var filterErr *FilterTemporaryError
	if !errors.As(err, &filterErr) || filterErr.Stage != "Sieve policy" {
		t.Fatalf("delivery error = %v, want Sieve policy temporary error", err)
	}
	if len(q.messages) != 0 || len(s.stagedDeliveries) != 0 {
		t.Fatal("unfiltered Sieve delivery was staged or queued")
	}
}

func TestAuthenticatedInfectedSubmissionStopsAfterQuarantine(t *testing.T) {
	q := &recordingSystemQueue{}
	quarantined := false
	s := &Session{authenticated: true, stagingDelivery: true, envelopeSender: "alice@example.test", cfg: &Config{AuthRequired: true, Delivery: &Delivery{
		ResolveRecipient:    func(context.Context, string) (string, string, error) { return "inbox", "bob", nil },
		GetVirusScanEnabled: func() bool { return true },
		VirusScan:           func([]byte) (string, bool, error) { return "EICAR", true, nil },
		QuarantineMessage: func(context.Context, string, string, string, map[string]string, []byte, string) (string, error) {
			quarantined = true
			return "quarantine-1", nil
		},
		MailQueue: q,
	}}}
	if err := s.deliverMessage("bob@example.test", map[string]string{"From": "alice@example.test"}, []byte("infected")); err != nil {
		t.Fatalf("quarantine delivery: %v", err)
	}
	if quarantined || len(q.messages) != 0 || len(s.stagedDeliveries) != 1 || s.stagedDeliveries[0].Kind != MailTaskQuarantine || s.stagedDeliveries[0].Attributes["virus_name"] != "EICAR" {
		t.Fatalf("quarantined=%v queued=%d staged=%d", quarantined, len(q.messages), len(s.stagedDeliveries))
	}
}

func TestAuthenticatedExternalSubmissionIsScannedBeforeRelayQueue(t *testing.T) {
	q := &recordingSystemQueue{}
	quarantined := false
	s := &Session{authenticated: true, stagingDelivery: true, envelopeSender: "alice@example.test", cfg: &Config{AuthRequired: true, Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "", "", errors.New("external") },
		MailQueue:        q, AllowAuthenticatedRelay: true,
		GetVirusScanEnabled: func() bool { return true },
		VirusScan:           func([]byte) (string, bool, error) { return "EICAR", true, nil },
		QuarantineMessage: func(_ context.Context, _, recipient, _ string, _ map[string]string, _ []byte, _ string) (string, error) {
			quarantined = recipient == "outside@example.net"
			return "quarantine-outbound", nil
		},
	}}}
	if err := s.deliverMessage("outside@example.net", map[string]string{"From": "alice@example.test"}, []byte("infected")); err != nil {
		t.Fatal(err)
	}
	if quarantined || len(s.stagedDeliveries) != 1 || s.stagedDeliveries[0].Kind != MailTaskQuarantine || s.stagedDeliveries[0].Recipient != "outside@example.net" || len(q.messages) != 0 {
		t.Fatalf("outbound quarantine=%v staged=%d queued=%d", quarantined, len(s.stagedDeliveries), len(q.messages))
	}
}

func TestNormalAndQuarantineRecipientsShareAtomicBatch(t *testing.T) {
	q := &recordingSystemQueue{}
	legacyQuarantineCalled := false
	s := &Session{authenticated: true, stagingDelivery: true, envelopeSender: "sender@example.test", deliveryCorrelationID: "mixed-transaction", cfg: &Config{AuthRequired: true, Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			return address + ":inbox", address, nil
		},
		AppendMessage:       func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:           q,
		GetVirusScanEnabled: func() bool { return true },
		GetVirusScanEnabledForDomain: func(_ context.Context, domain string) (bool, error) {
			return domain == "infected.test", nil
		},
		VirusScan: func([]byte) (string, bool, error) { return "EICAR", true, nil },
		QuarantineMessage: func(context.Context, string, string, string, map[string]string, []byte, string) (string, error) {
			legacyQuarantineCalled = true
			return "legacy", nil
		},
	}}}
	headers := map[string]string{"From": "sender@example.test", "Subject": "mixed"}
	if err := s.deliverMessage("clean@clean.test", headers, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverMessage("blocked@infected.test", headers, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if len(s.stagedDeliveries) != 2 || s.stagedDeliveries[0].Kind != "" || s.stagedDeliveries[1].Kind != MailTaskQuarantine {
		t.Fatalf("mixed staged deliveries = %#v", s.stagedDeliveries)
	}
	if err := q.EnqueueBatch(s.stagedDeliveries); err != nil {
		t.Fatal(err)
	}
	if legacyQuarantineCalled || len(q.messages) != 2 || q.messages[0].CorrelationID != "mixed-transaction" || q.messages[1].CorrelationID != "mixed-transaction" {
		t.Fatalf("legacy=%t queue=%#v", legacyQuarantineCalled, q.messages)
	}
}

func TestFailedMixedBatchCreatesNoQuarantineSideEffect(t *testing.T) {
	q := &recordingSystemQueue{batchErr: errors.New("disk unavailable")}
	s := &Session{authenticated: true, stagingDelivery: true, envelopeSender: "sender@example.test", cfg: &Config{AuthRequired: true, Delivery: &Delivery{
		ResolveRecipient:    func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:       func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:           q,
		GetVirusScanEnabled: func() bool { return true },
		VirusScan:           func([]byte) (string, bool, error) { return "EICAR", true, nil },
	}}}
	if err := s.deliverMessage("blocked@example.test", map[string]string{"Subject": "infected"}, []byte("body")); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueBatch(s.stagedDeliveries); err == nil || len(q.messages) != 0 {
		t.Fatalf("failed batch error=%v messages=%#v", err, q.messages)
	}
}

func newSieveQueueSession(q *recordingSystemQueue) *Session {
	return &Session{stagingDelivery: true, envelopeSender: "sender@example.test", deliveryCorrelationID: "sieve-transaction", recipients: []string{"alice@example.test"}, cfg: &Config{Delivery: &Delivery{
		MailQueue:     q,
		AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
	}}}
}

func TestSieveRedirectOnlyAndCopyStageAtomicDeliveries(t *testing.T) {
	headers, body := map[string]string{"From": "sender@example.test", "Subject": "redirect"}, []byte("body")
	full := buildMessage(headers, body)

	redirectOnly := newSieveQueueSession(&recordingSystemQueue{})
	result, err := redirectOnly.runSieve(`redirect "archive@example.net";`, full, "alice", "alice:inbox", cloneSMTPHeaders(headers), body)
	if err != nil || result.Kept || len(redirectOnly.stagedDeliveries) != 1 {
		t.Fatalf("redirect-only result=%+v staged=%#v err=%v", result, redirectOnly.stagedDeliveries, err)
	}
	redirect := redirectOnly.stagedDeliveries[0]
	if !redirect.Outbound || redirect.Recipient != "archive@example.net" || redirect.CorrelationID != "sieve-transaction" || redirect.Headers["X-Veksel-Forwarded-By"] != "alice" || redirect.Headers["X-Veksel-Forward-Hop"] != "1" {
		t.Fatalf("redirect delivery = %+v", redirect)
	}

	copySession := newSieveQueueSession(&recordingSystemQueue{})
	result, err = copySession.runSieve(`require "copy"; redirect :copy "archive@example.net";`, full, "alice", "alice:inbox", cloneSMTPHeaders(headers), body)
	if err != nil || !result.Kept || len(copySession.stagedDeliveries) != 2 || !copySession.stagedDeliveries[0].Outbound || copySession.stagedDeliveries[1].TargetFolderID != "alice:inbox" {
		t.Fatalf("redirect-copy result=%+v staged=%#v err=%v", result, copySession.stagedDeliveries, err)
	}
}

func TestSieveRedirectValidationLoopAndBatchFailure(t *testing.T) {
	headers, body := map[string]string{"From": "sender@example.test"}, []byte("body")
	full := buildMessage(headers, body)
	invalid := newSieveQueueSession(&recordingSystemQueue{})
	if _, err := invalid.runSieve(`require "variables"; set "to" "not-an-address"; redirect "${to}";`, full, "alice", "inbox", cloneSMTPHeaders(headers), body); err == nil || len(invalid.stagedDeliveries) != 0 {
		t.Fatalf("invalid redirect error=%v staged=%#v", err, invalid.stagedDeliveries)
	}

	loopHeaders := map[string]string{"From": "sender@example.test", "X-Veksel-Forwarded-By": "alice"}
	loop := newSieveQueueSession(&recordingSystemQueue{})
	result, err := loop.runSieve(`redirect "archive@example.net";`, buildMessage(loopHeaders, body), "alice", "inbox", loopHeaders, body)
	if err != nil || !result.Kept || len(loop.stagedDeliveries) != 1 || loop.stagedDeliveries[0].Outbound {
		t.Fatalf("loop redirect result=%+v staged=%#v err=%v", result, loop.stagedDeliveries, err)
	}

	failedQueue := &recordingSystemQueue{batchErr: errors.New("disk unavailable")}
	copySession := newSieveQueueSession(failedQueue)
	if _, err := copySession.runSieve(`require "copy"; redirect :copy "archive@example.net";`, full, "alice", "inbox", cloneSMTPHeaders(headers), body); err != nil {
		t.Fatal(err)
	}
	if err := failedQueue.EnqueueBatch(copySession.stagedDeliveries); err == nil || len(failedQueue.messages) != 0 {
		t.Fatalf("failed redirect batch error=%v messages=%#v", err, failedQueue.messages)
	}
}

func TestSieveFileIntoStagesUnresolvedPathWithoutCreatingFolders(t *testing.T) {
	q := &recordingSystemQueue{}
	createCalls := 0
	s := &Session{stagingDelivery: true, envelopeSender: "sender@example.test", deliveryCorrelationID: "fileinto-transaction", cfg: &Config{Delivery: &Delivery{
		MailQueue: q,
		GetFolderIDByPath: func(context.Context, string, string) (string, error) {
			return "", errors.New("not found")
		},
		CreateFolder: func(context.Context, string, string, string, string) error {
			createCalls++
			return nil
		},
	}}}
	headers, body := map[string]string{"From": "sender@example.test", "Subject": "deferred folder"}, []byte("body")
	result, err := s.runSieve(`require "fileinto"; fileinto "Projects/2026";`, buildMessage(headers, body), "alice", "alice:inbox", cloneSMTPHeaders(headers), body)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.FileIntoFolders) != 1 || result.FileIntoFolders[0] != "Projects/2026" || createCalls != 0 || len(q.messages) != 0 || len(s.stagedDeliveries) != 1 {
		t.Fatalf("result=%+v createCalls=%d queued=%d staged=%#v", result, createCalls, len(q.messages), s.stagedDeliveries)
	}
	staged := s.stagedDeliveries[0]
	if staged.TargetFolderPath != "Projects/2026" || staged.TargetFolderID != "" || staged.TargetOwnerID != "alice" || staged.CorrelationID != "fileinto-transaction" || string(staged.Content) == "" {
		t.Fatalf("staged fileinto = %+v", staged)
	}
}

func TestSieveFileIntoFailedAdmissionHasNoFolderSideEffect(t *testing.T) {
	q := &recordingSystemQueue{batchErr: errors.New("disk unavailable")}
	createCalls := 0
	s := &Session{stagingDelivery: true, envelopeSender: "sender@example.test", cfg: &Config{Delivery: &Delivery{
		MailQueue: q,
		GetFolderIDByPath: func(context.Context, string, string) (string, error) {
			return "", errors.New("not found")
		},
		CreateFolder: func(context.Context, string, string, string, string) error {
			createCalls++
			return nil
		},
	}}}
	headers, body := map[string]string{"From": "sender@example.test"}, []byte("body")
	if _, err := s.runSieve(`require "fileinto"; fileinto "Projects/2026";`, buildMessage(headers, body), "alice", "alice:inbox", headers, body); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueBatch(s.stagedDeliveries); err == nil || len(q.messages) != 0 || createCalls != 0 {
		t.Fatalf("batch error=%v queued=%d createCalls=%d", err, len(q.messages), createCalls)
	}
}

func TestSieveFileIntoCreateMakesNestedFolderAndFiles(t *testing.T) {
	folders := map[string]string{"INBOX": "alice:inbox"}
	appended := map[string]int{}
	var created []string
	s := &Session{envelopeSender: "sender@example.test", cfg: &Config{Delivery: &Delivery{
		GetFolderIDByPath: func(_ context.Context, _ string, path string) (string, error) {
			if id, ok := folders[path]; ok {
				return id, nil
			}
			return "", errors.New("not found")
		},
		CreateFolder: func(_ context.Context, _ string, path, _, _ string) error {
			created = append(created, path)
			folders[path] = "alice:" + path
			return nil
		},
		AppendFolderItem: func(_ context.Context, _ string, folderID string, _ []byte, _ map[string]string) (string, error) {
			appended[folderID]++
			return "item", nil
		},
	}}}
	headers, body := map[string]string{"From": "sender@example.test", "Subject": "roundcube"}, []byte("body")
	script := `require ["fileinto", "mailbox"];
if mailboxexists "Projects/2026" { fileinto "Wrong"; stop; }
fileinto :create "Projects/2026";
if mailboxexists "INBOX" { keep; }`
	result, err := s.runSieve(script, buildMessage(headers, body), "alice", "alice:inbox", cloneSMTPHeaders(headers), body)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(created, []string{"Projects/2026"}) || appended["alice:Projects/2026"] != 1 || appended["alice:inbox"] != 1 || len(appended) != 2 || !slices.Equal(result.CreateFolders, []string{"Projects/2026"}) {
		t.Fatalf("created=%v appended=%v result=%+v", created, appended, result)
	}
}

func atomicDerivedPreparer(message DerivedMessage) (*MailMessage, error) {
	headers, body := model.ParseMessageHeaders(message.FullMessage)
	return &MailMessage{ID: "derived-" + message.Kind + "-" + strings.ReplaceAll(message.Recipient, "@", "-"), ParentID: message.ParentID,
		CorrelationID: message.CorrelationID, EnvelopeSender: message.EnvelopeSender, Recipient: message.Recipient, Headers: headers, Body: body, Outbound: true}, nil
}

func TestForwardJoinsOriginalAtomicQueueBatch(t *testing.T) {
	q := &recordingSystemQueue{}
	legacySendCalled := false
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
		MailQueue:        q,
		GetForwardTo:     func(context.Context, string) string { return "archive@example.net" },
		PrepareDerived: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
			return atomicDerivedPreparer(message)
		},
		SendDerived: func(context.Context, DerivedMessage) error { legacySendCalled = true; return nil },
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: atomic forward\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if legacySendCalled || len(q.messages) != 2 {
		t.Fatalf("legacy=%t queued=%#v", legacySendCalled, q.messages)
	}
	local, forward := q.messages[0], q.messages[1]
	if local.TargetFolderID != "alice:inbox" || !forward.Outbound || forward.Recipient != "archive@example.net" || forward.ParentID != local.ID || forward.CorrelationID == "" || forward.CorrelationID != local.CorrelationID {
		t.Fatalf("local=%+v forward=%+v", local, forward)
	}
}

func TestForwardPreparationOrBatchFailureAcceptsNothing(t *testing.T) {
	tests := []struct {
		name      string
		prepare   func(context.Context, DerivedMessage) (*MailMessage, error)
		batchErr  error
		lookupErr error
	}{
		{name: "prepare", prepare: func(context.Context, DerivedMessage) (*MailMessage, error) {
			return nil, errors.New("routing unavailable")
		}},
		{name: "commit", prepare: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
			return atomicDerivedPreparer(message)
		}, batchErr: errors.New("disk unavailable")},
		{name: "policy lookup", prepare: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
			return atomicDerivedPreparer(message)
		}, lookupErr: errors.New("account store unavailable")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			q := &recordingSystemQueue{batchErr: test.batchErr}
			addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
				ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
				MailQueue:        q, ResolveForwardTo: func(context.Context, string) (string, error) {
					return "archive@example.net", test.lookupErr
				}, PrepareDerived: test.prepare,
			}})
			t.Cleanup(cleanup)
			client := dialClient(t, addr)
			err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
				"From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: rejected forward\r\n\r\nbody\r\n"))
			if err == nil || len(q.messages) != 0 {
				t.Fatalf("error=%v queued=%#v", err, q.messages)
			}
		})
	}
}

func TestSieveNotifyJoinsBatchAndInvalidTargetFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, target string
		wantQueued   int
		wantError    bool
	}{
		{name: "valid", target: "alerts@example.net", wantQueued: 2},
		// An invalid target is a Sieve runtime error: RFC 5228 section
		// 2.10.6 falls back to the implicit keep without a notification.
		{name: "invalid", target: "not-an-address", wantQueued: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := &recordingSystemQueue{}
			addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
				ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
				MailQueue:        q,
				GetSieveScript: func(context.Context, string) (string, bool, error) {
					return `require ["enotify", "variables"]; set "target" "` + test.target + `"; notify :message "new mail" "mailto:${target}";`, true, nil
				},
				PrepareDerived: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
					return atomicDerivedPreparer(message)
				},
			}})
			t.Cleanup(cleanup)
			client := dialClient(t, addr)
			err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
				"From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: notify\r\n\r\nbody\r\n"))
			if (err != nil) != test.wantError || len(q.messages) != test.wantQueued {
				t.Fatalf("error=%v queued=%#v", err, q.messages)
			}
			if test.wantQueued == 1 && q.messages[0].TargetFolderID != "alice:inbox" {
				t.Fatalf("fallback delivery = %+v", q.messages[0])
			}
			if test.wantQueued == 2 {
				notify, local := q.messages[0], q.messages[1]
				if notify.Headers["Auto-Submitted"] != "auto-notified" || string(notify.Body) != "new mail" {
					t.Fatalf("notification = %v %q", notify.Headers, notify.Body)
				}
				if notify.Recipient != test.target || !notify.Outbound || notify.CorrelationID == "" || notify.CorrelationID != local.CorrelationID || local.TargetFolderID != "alice:inbox" {
					t.Fatalf("notify=%+v local=%+v", notify, local)
				}
			}
		})
	}
}

func TestVacationIntentJoinsOriginalBatchWithoutPreAcceptanceReservation(t *testing.T) {
	q := &recordingSystemQueue{}
	reservations := 0
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
		MailQueue:        q, PrepareDerived: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
			return atomicDerivedPreparer(message)
		},
		VacationActive: func(context.Context, string) bool { return true }, VacationReply: func(context.Context, string) (string, string) { return "Away", "Back later" },
		ReserveVacationReply: func(context.Context, string, string) (string, bool, error) { reservations++; return "token", true, nil },
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: alice@example.test\r\nMessage-ID: <original@example.test>\r\nSubject: vacation\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if reservations != 0 || len(q.messages) != 2 {
		t.Fatalf("reservations=%d queued=%#v", reservations, q.messages)
	}
	local, intent := q.messages[0], q.messages[1]
	if intent.Kind != MailTaskVacation || intent.Attributes["user_id"] != "alice" || intent.Attributes["sender"] != "sender@remote.test" || intent.Attributes["derived_kind"] != "vacation" || intent.ParentID != local.ID || intent.CorrelationID != local.CorrelationID || len(intent.Content) == 0 {
		t.Fatalf("local=%+v intent=%+v", local, intent)
	}
}

func TestVacationIntentFailedAdmissionAndAutomaticSuppression(t *testing.T) {
	for _, test := range []struct {
		name, extra string
		batchErr    error
		wantQueued  int
		wantError   bool
	}{
		{name: "batch failure", batchErr: errors.New("disk unavailable"), wantError: true},
		{name: "automatic message", extra: "Auto-Submitted: auto-generated\r\n", wantQueued: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := &recordingSystemQueue{batchErr: test.batchErr}
			addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
				ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
				MailQueue:        q, PrepareDerived: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
					return atomicDerivedPreparer(message)
				},
				VacationActive: func(context.Context, string) bool { return true }, VacationReply: func(context.Context, string) (string, string) { return "Away", "Later" },
			}})
			t.Cleanup(cleanup)
			client := dialClient(t, addr)
			err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
				"From: sender@remote.test\r\nTo: alice@example.test\r\n"+test.extra+"Subject: vacation\r\n\r\nbody\r\n"))
			if (err != nil) != test.wantError || len(q.messages) != test.wantQueued {
				t.Fatalf("error=%v queued=%#v", err, q.messages)
			}
		})
	}
}

func TestVacationPolicyFailureRejectsAtomicAdmission(t *testing.T) {
	q := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
		MailQueue:        q, PrepareDerived: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
			return atomicDerivedPreparer(message)
		},
		ResolveVacation: func(context.Context, string) (bool, string, string, error) {
			return false, "", "", errors.New("account store unavailable")
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: vacation\r\n\r\nbody\r\n"))
	if err == nil || len(q.messages) != 0 {
		t.Fatalf("error=%v queued=%#v", err, q.messages)
	}
}

func TestSieveVacationStagesDurableIntent(t *testing.T) {
	q := &recordingSystemQueue{}
	s := &Session{stagingDelivery: true, envelopeSender: "sender@example.net", deliveryRecipient: "alice@example.test", deliveryCorrelationID: "sieve-vacation-transaction", recipients: []string{"alice@example.test"}, cfg: &Config{ServerName: "test.veksel", Delivery: &Delivery{
		MailQueue: q, PrepareDerived: func(_ context.Context, message DerivedMessage) (*MailMessage, error) {
			return atomicDerivedPreparer(message)
		},
	}}}
	headers, body := map[string]string{"From": "sender@example.net", "To": "alice@example.test", "Message-ID": "<original@example.net>"}, []byte("body")
	if _, err := s.runSieve(`require "vacation"; vacation :subject "Away" :days 3 "Back later";`, buildMessage(headers, body), "alice", "alice:inbox", headers, body); err != nil {
		t.Fatal(err)
	}
	if len(s.stagedDeliveries) != 2 || s.stagedDeliveries[0].Kind != MailTaskVacation || s.stagedDeliveries[0].Attributes["derived_kind"] != "sieve-vacation" || s.stagedDeliveries[1].TargetFolderID != "alice:inbox" {
		t.Fatalf("staged=%#v", s.stagedDeliveries)
	}
	intent := s.stagedDeliveries[0]
	reply := string(intent.Content)
	if intent.Recipient != "sender@example.net" || intent.Attributes[AttributeVacationPeriod] != "259200" || !strings.HasPrefix(intent.Attributes[AttributeVacationKey], "sieve:") ||
		!strings.Contains(reply, "Subject: Away\r\n") || !strings.Contains(reply, "In-Reply-To: <original@example.net>\r\n") || !strings.Contains(reply, "Auto-Submitted: auto-replied\r\n") {
		t.Fatalf("vacation intent = %+v\n%s", intent.Attributes, reply)
	}
}

func TestQueueBatchCommitFailureAcceptsNoRecipient(t *testing.T) {
	q := &recordingSystemQueue{batchErr: errors.New("disk unavailable")}
	forwarded := false
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        q,
		GetForwardTo:     func(context.Context, string) string { return "forward@example.net" },
		SendForward:      func(context.Context, string, []byte) error { forwarded = true; return nil },
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	err := client.SendMail("sender@remote.test", []string{"one@example.test", "two@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: one@example.test, two@example.test\r\nSubject: atomic queue\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("DATA succeeded despite failed atomic queue commit")
	}
	if len(q.messages) != 0 || forwarded {
		t.Fatalf("queue retained recipients after failed batch: %#v", q.messages)
	}
}

func TestPostDeliverySideEffectsRunAfterBatchCommit(t *testing.T) {
	q := &recordingSystemQueue{}
	forwardedAfterCommit := make(chan bool, 1)
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        q,
		GetForwardTo:     func(context.Context, string) string { return "forward@example.net" },
		SendForward: func(context.Context, string, []byte) error {
			forwardedAfterCommit <- len(q.messages) == 1
			return nil
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.SendMail("sender@remote.test", []string{"one@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: one@example.test\r\nSubject: commit ordering\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case committed := <-forwardedAfterCommit:
		if !committed {
			t.Fatal("forwarding ran before the recipient batch committed")
		}
	case <-time.After(time.Second):
		t.Fatal("forwarding hook did not run")
	}
}

func TestPostCommitHookCannotDelayAcceptanceResponse(t *testing.T) {
	q := &recordingSystemQueue{}
	hookStarted, releaseHook := make(chan struct{}), make(chan struct{})
	defer close(releaseHook)
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        q,
		GetForwardTo:     func(context.Context, string) string { return "forward@example.net" },
		SendForward: func(context.Context, string, []byte) error {
			close(hookStarted)
			<-releaseHook
			return nil
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	result := make(chan error, 1)
	go func() {
		result <- client.SendMail("sender@remote.test", []string{"one@example.test"}, strings.NewReader(
			"From: sender@remote.test\r\nTo: one@example.test\r\nSubject: prompt acceptance\r\n\r\nbody\r\n"))
	}()
	select {
	case <-hookStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("post-commit hook did not start")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("accepted DATA returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP acceptance response was delayed by post-commit hook")
	}
}

func TestPostCommitHookPanicDoesNotSuppressLaterHooksOrSession(t *testing.T) {
	q := &recordingSystemQueue{}
	vacationSent := make(chan struct{}, 1)
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) { return address, address, nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		MailQueue:        q,
		GetForwardTo:     func(context.Context, string) string { return "forward@example.net" },
		VacationActive:   func(context.Context, string) bool { return true },
		VacationReply:    func(context.Context, string) (string, string) { return "Away", "Back later" },
		SendForward: func(_ context.Context, recipient string, _ []byte) error {
			if recipient == "forward@example.net" {
				panic("broken forwarding integration")
			}
			vacationSent <- struct{}{}
			return nil
		},
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.SendMail("sender@remote.test", []string{"one@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: one@example.test\r\nSubject: isolated hooks\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-vacationSent:
	case <-time.After(time.Second):
		t.Fatal("later vacation hook was suppressed by forwarding panic")
	}
	if err := client.Noop(); err != nil {
		t.Fatalf("SMTP session did not survive post-commit panic: %v", err)
	}
}

func TestSieveRejectRejectsDATAWithoutQueueOrDSN(t *testing.T) {
	q := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "alice", nil },
		AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
		GetSieveScript: func(context.Context, string) (string, bool, error) {
			return "require \"reject\";\nreject text:\nPolicy rejection\r\n250 injected\n.\n;", true, nil
		},
		MailQueue: q,
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	err := client.SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: rejected by Sieve\r\n\r\nbody\r\n"))
	if err == nil || len(q.messages) != 0 || !strings.Contains(err.Error(), "550: Policy rejection 250 injected") {
		t.Fatalf("Sieve rejection error=%v queued=%#v", err, q.messages)
	}
	// The multi-line reason was folded into the one reply line.
	if err := client.Noop(); err != nil {
		t.Fatalf("session desynchronized after reject: %v", err)
	}
}

func TestAuthenticatedSubmissionAuthorizationRunsBeforeQueueCommit(t *testing.T) {
	q := &recordingSystemQueue{}
	called := false
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel", AuthRequired: true, AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "recipient", nil },
			AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "unused", nil },
			MailQueue:        q,
			AuthorizeSubmission: func(_ context.Context, actor, envelope, from, sender string) error {
				called = true
				if actor != "alice" || envelope != "forged@example.test" || from != "forged@example.test" {
					t.Errorf("authorization input actor=%q envelope=%q from=%q sender=%q", actor, envelope, from, sender)
				}
				return errors.New("not delegated")
			},
		},
	})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.Auth(sasl.NewPlainClient("", "alice", "password")); err != nil {
		t.Fatal(err)
	}
	err := client.SendMail("forged@example.test", []string{"recipient@example.test"}, strings.NewReader(
		"From: forged@example.test\r\nTo: recipient@example.test\r\nSubject: rejected\r\n\r\nbody\r\n"))
	if err == nil || !called {
		t.Fatalf("submission error=%v authorization called=%v", err, called)
	}
	if len(q.messages) != 0 {
		t.Fatal("unauthorized submission entered queue")
	}
}

func TestAuthenticatedSubmissionRecordsRecipientsAfterQueueCommit(t *testing.T) {
	q := &recordingSystemQueue{}
	recorded := make(chan struct {
		user       string
		recipients []string
	}, 1)
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel", AuthRequired: true, AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "recipient", nil },
			MailQueue:        q,
			RecordRecentRecipients: func(_ context.Context, userID string, recipients []string) error {
				recorded <- struct {
					user       string
					recipients []string
				}{user: userID, recipients: append([]string(nil), recipients...)}
				return nil
			},
		},
	})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.Auth(sasl.NewPlainClient("", "alice", "password")); err != nil {
		t.Fatal(err)
	}
	if err := client.SendMail("alice@example.test", []string{"one@example.test", "two@example.test"}, strings.NewReader(
		"From: alice@example.test\r\nTo: one@example.test\r\nSubject: accepted\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-recorded:
		if got.user != "alice" || strings.Join(got.recipients, ",") != "one@example.test,two@example.test" {
			t.Fatalf("recorded user=%q recipients=%v", got.user, got.recipients)
		}
	case <-time.After(time.Second):
		t.Fatal("recipient history callback was not run")
	}
}

func TestAuthenticatedExternalDeliveryUsesSystemQueue(t *testing.T) {
	q := &recordingSystemQueue{}
	s := &Session{
		authenticated:  true,
		envelopeSender: "alice@example.test",
		cfg: &Config{Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) {
				return "", "", errors.New("not local")
			},
			MailQueue: q, AllowAuthenticatedRelay: true,
		}},
	}
	headers := map[string]string{"Subject": "Queued outbound"}
	if err := s.deliverMessage("outside@example.net", headers, []byte("payload")); err != nil {
		t.Fatalf("deliver message: %v", err)
	}
	if len(q.messages) != 1 {
		t.Fatalf("queued messages = %d, want 1", len(q.messages))
	}
	got := q.messages[0]
	if !got.Outbound || got.EnvelopeSender != "alice@example.test" || got.Recipient != "outside@example.net" {
		t.Fatalf("incorrect outbound queue job: %#v", got)
	}
}

func TestUnauthenticatedExternalDeliveryIsNotRelayed(t *testing.T) {
	q := &recordingSystemQueue{}
	s := &Session{cfg: &Config{Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) {
			return "", "", errors.New("not local")
		},
		MailQueue: q, AllowAuthenticatedRelay: true,
	}}}
	if err := s.deliverMessage("outside@example.net", nil, nil); err == nil {
		t.Fatal("unauthenticated external delivery unexpectedly succeeded")
	}
	if len(q.messages) != 0 {
		t.Fatal("unauthenticated external delivery reached queue")
	}
}

func TestAuthenticatedRelayHonorsDestinationPolicy(t *testing.T) {
	q := &recordingSystemQueue{}
	s := &Session{
		authenticated: true,
		cfg: &Config{Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) {
				return "", "", errors.New("not local")
			},
			MailQueue:               q,
			AllowAuthenticatedRelay: true,
			CanRelayRecipient: func(_ context.Context, recipient string) bool {
				return recipient == "allowed@routed.test"
			},
		}},
	}
	if err := s.deliverMessage("blocked@other.test", nil, nil); err == nil {
		t.Fatal("destination policy was bypassed by the legacy relay flag")
	}
	if err := s.deliverMessage("allowed@routed.test", nil, []byte("payload")); err != nil {
		t.Fatalf("allowed route was rejected: %v", err)
	}
	if len(q.messages) != 1 || q.messages[0].Recipient != "allowed@routed.test" {
		t.Fatalf("queued messages: %#v", q.messages)
	}
}

func TestConfiguredAuthenticationMechanismsAreAuthoritative(t *testing.T) {
	s := &Session{cfg: &Config{AuthMechanisms: []string{" plain ", "PLAIN"}}}
	if !s.authMechanismAllowed("PLAIN") {
		t.Fatal("configured PLAIN mechanism was rejected")
	}
	if s.authMechanismAllowed("LOGIN") {
		t.Fatal("unconfigured LOGIN mechanism was accepted")
	}
	if got := s.allowedAuthMechanisms(); len(got) != 1 || got[0] != "PLAIN" {
		t.Fatalf("advertised mechanisms: %v", got)
	}

	s.cfg.AuthMechanisms = []string{"XOAUTH2", "NTLM"}
	if got := s.allowedAuthMechanisms(); len(got) != 0 {
		t.Fatalf("mechanisms without validators were advertised: %v", got)
	}
	s.cfg.NtlmEnabled = true
	if !s.authMechanismAllowed("NTLM") {
		t.Fatal("enabled configured NTLM mechanism was rejected")
	}
}
