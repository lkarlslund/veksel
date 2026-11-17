package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dkim/dkimtest"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestMailPolicySubjectRewriteIsCoveredByDKIMSignature(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	policies, err := mailpolicy.NewService(ctx, mailpolicy.NewRepository(s.ts.Store()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Replace(ctx, policies.Document().Revision, mailpolicy.Document{Rules: []mailpolicy.Rule{{
		ID: "tag-external", Name: "Tag external mail", Enabled: true,
		Conditions: []mailpolicy.Condition{{Field: mailpolicy.FieldDirection, Operator: mailpolicy.OperatorEquals, Value: "submission"}},
		Actions:    []mailpolicy.Action{{Type: mailpolicy.ActionAddHeader, Header: "Subject", Value: "[external] Hello"}},
	}}}); err != nil {
		t.Fatal(err)
	}
	mailQueue := queue.New(&queue.Config{Admission: mailPolicyAdmission(policies), Signer: dkim.NewSigner(s.ts.DomainStore())})
	t.Cleanup(mailQueue.Close)
	if err := s.ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	webmail := service.NewMail(s.ts, authz.New(s.ts), mailQueue)
	if _, err := webmail.Submit(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, service.Submission{
		From: "alice@example.test", To: []string{"carol@remote.test"}, Subject: "Hello", Body: "Hi Carol.",
	}); err != nil {
		t.Fatal(err)
	}
	queued := mailQueue.List("")
	if len(queued) != 1 {
		t.Fatalf("queued = %d messages, want 1", len(queued))
	}
	message := queued[0]
	if message.Headers["Subject"] != "[external] Hello" {
		t.Fatalf("policy did not rewrite Subject: %v", message.Headers)
	}
	if result := verifier.Verify(t.Context(), queue.BuildMessage(message.Headers, message.Body)); !result.Pass || result.Domain != "example.test" {
		t.Fatalf("verification over the rewritten message = %+v", result)
	}
}

// TestSMTPSubmissionTraceFieldsSurviveSigning sends an authenticated SMTP
// submission that already carries a Received field through queue admission
// signing: the relayed bytes keep both trace fields in order, Veksel' own on
// top, and the signature added above them verifies.
func TestSMTPSubmissionTraceFieldsSurviveSigning(t *testing.T) {
	s := liveAddressingServer(t)
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	mailQueue := queue.New(&queue.Config{Signer: dkim.NewSigner(s.ts.DomainStore())})
	t.Cleanup(mailQueue.Close)
	server := smtp.New(&smtp.Config{
		ServerName: "mx.example.test", AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		Delivery: &smtp.Delivery{
			ResolveRecipient:        func(context.Context, string) (string, string, error) { return "", "", store.ErrNotFound },
			MailQueue:               queue.NewSMTPAdapter(mailQueue),
			AllowAuthenticatedRelay: true,
		},
	})
	listener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() { cancel(); _ = server.Close() })
	go server.Accept(ctx, listener)
	client, err := gosmtp.Dial(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Auth(sasl.NewPlainClient("", "alice", "secret")); err != nil {
		t.Fatal(err)
	}
	clientTrace := "Received: from desktop by laptop.example.test; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
	if err := client.SendMail("alice@example.test", []string{"carol@remote.test"}, strings.NewReader(clientTrace+
		"From: alice@example.test\r\nTo: carol@remote.test\r\nSubject: traced\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nHello Carol.\r\n")); err != nil {
		t.Fatal(err)
	}
	queued := mailQueue.List("")
	if len(queued) != 1 {
		t.Fatalf("queued = %d messages, want 1", len(queued))
	}
	data := string(queued[0].RawMessage())
	ours := strings.Index(data, "Received: from localhost ([127.0.0.1])\r\n\tby mx.example.test (Veksel) with ESMTPA id ")
	if !strings.HasPrefix(data, "DKIM-Signature: ") || ours < 0 || ours > strings.Index(data, clientTrace) {
		t.Fatalf("relayed message lost trace order:\n%s", data)
	}
	if result := verifier.Verify(t.Context(), []byte(data)); !result.Pass || result.Domain != "example.test" {
		t.Fatalf("verification = %+v", result)
	}
}

func TestDeliveryStatusNotificationIsDKIMSigned(t *testing.T) {
	s := liveAddressingServer(t)
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	mailQueue := queue.New(&queue.Config{
		ProcessPeriod: time.Millisecond, RetryInitial: time.Hour, Signer: dkim.NewSigner(s.ts.DomainStore()),
		FailureMessage: s.deliveryStatusNotification,
		Delivery: func(_ context.Context, msg *queue.Message) error {
			if strings.HasPrefix(msg.ID, "dsn-") {
				return &queue.DeliveryError{Class: queue.DeliveryTemporary, Response: "hold notification"}
			}
			return &queue.DeliveryError{Class: queue.DeliveryPermanent, EnhancedCode: "5.1.1", Response: "unknown user"}
		},
	})
	t.Cleanup(mailQueue.Close)
	if err := mailQueue.Enqueue(&queue.Message{ID: "original", EnvelopeSender: "carol@remote.test", Recipient: "missing@elsewhere.test",
		Headers: map[string]string{"From": "carol@remote.test", "Subject": "Hi"}, Body: []byte("hello\r\n")}); err != nil {
		t.Fatal(err)
	}
	var dsn *queue.Message
	for deadline := time.Now().Add(5 * time.Second); dsn == nil && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		dsn = mailQueue.Get("dsn-original")
	}
	if dsn == nil {
		t.Fatal("no delivery status notification was queued")
	}
	if dsn.Recipient != "carol@remote.test" || dsn.EnvelopeSender != "" || dsn.Headers["From"] != "Mail Delivery System <MAILER-DAEMON@example.test>" {
		t.Fatalf("notification envelope and From = %q %q %v", dsn.EnvelopeSender, dsn.Recipient, dsn.Headers)
	}
	data := queue.BuildMessage(dsn.Headers, dsn.Body)
	if !strings.Contains(string(data), "missing@elsewhere.test") {
		t.Fatalf("notification body lost the report:\n%s", data)
	}
	if result := verifier.Verify(t.Context(), data); !result.Pass || result.Domain != "example.test" {
		t.Fatalf("notification verification = %+v", result)
	}
}

func TestGeneratedDerivedMailIsSignedAndForwardsAreNot(t *testing.T) {
	s := liveAddressingServer(t)
	s.mailQueue = queue.New(&queue.Config{Signer: dkim.NewSigner(s.ts.DomainStore())})
	t.Cleanup(s.mailQueue.Close)
	s.smtpQueueAdapter = queue.NewSMTPAdapter(s.mailQueue)
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	notification := []byte("From: alice@example.test\r\nTo: alerts@remote.test\r\nSubject: new mail\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nYou have mail.\r\n")
	if err := s.enqueueDerived(s.ctx, smtp.DerivedMessage{Kind: "sieve-notify", Recipient: "alerts@remote.test", EnvelopeSender: "alice@example.test",
		FullMessage: notification, CorrelationID: "transaction-1", DKIM: &dkim.Request{}}); err != nil {
		t.Fatal(err)
	}
	// A forward of hosted-domain mail keeps the bytes it arrived with.
	received := []byte("From: bob@example.test\r\nTo: alice@example.test\r\nSubject: forwarded\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nFor Alice.\r\n")
	if err := s.enqueueDerived(s.ctx, smtp.DerivedMessage{Kind: "forward", Recipient: "alice@elsewhere.test", EnvelopeSender: "bob@example.test",
		FullMessage: received, CorrelationID: "transaction-2"}); err != nil {
		t.Fatal(err)
	}
	for _, message := range s.mailQueue.List("") {
		data := message.RawMessage()
		switch message.Recipient {
		case "alerts@remote.test":
			if result := verifier.Verify(t.Context(), data); !result.Pass || result.Domain != "example.test" {
				t.Fatalf("Sieve notification verification = %+v", result)
			}
		case "alice@elsewhere.test":
			if message.Headers["DKIM-Signature"] != "" || string(data) != string(received) {
				t.Fatalf("forward was altered:\n%s", data)
			}
		default:
			t.Fatalf("unexpected recipient %q", message.Recipient)
		}
	}
}
