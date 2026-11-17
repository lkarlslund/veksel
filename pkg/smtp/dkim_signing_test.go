package smtp

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func dkimSignatures(headers map[string]string) []string {
	var signatures []string
	for name, value := range headers {
		if strings.EqualFold(name, "DKIM-Signature") {
			signatures = append(signatures, value)
		}
	}
	return signatures
}

// aliceMaySendAs authorizes only alice's own identity, as the submission
// service does.
func aliceMaySendAs(_ context.Context, actorID, _, from, _ string) error {
	address, err := mail.ParseAddress(from)
	if err != nil || actorID != "alice" || address.Address != "alice@example.test" {
		return errors.New("not authorized")
	}
	return nil
}

func TestAuthenticatedSubmissionRequestsSigningAtQueueAdmission(t *testing.T) {
	q := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel", AuthRequired: true, AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		Delivery: &Delivery{
			ResolveRecipient:        func(context.Context, string) (string, string, error) { return "", "", store.ErrNotFound },
			MailQueue:               q,
			AllowAuthenticatedRelay: true,
		},
	})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	if err := client.Auth(sasl.NewPlainClient("", "alice", "password")); err != nil {
		t.Fatal(err)
	}
	if err := client.SendMail("bounces@other.test", []string{"carol@remote.test"}, strings.NewReader(
		"From: Alice <alice@example.test>\r\nTo: carol@remote.test\r\nSubject: signed\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(q.messages) != 1 {
		t.Fatalf("queued = %#v", q.messages)
	}
	// The queue signs after mail policy has rewritten headers; the session
	// only marks the submission.
	message := q.messages[0]
	if message.DKIM == nil || len(dkimSignatures(message.Headers)) != 0 {
		t.Fatalf("submission DKIM request = %+v, signatures = %q", message.DKIM, dkimSignatures(message.Headers))
	}
}

func TestRelayedAndForwardedMailIsNotSigned(t *testing.T) {
	mailQueue := &recordingSystemQueue{}
	delivery := srsDelivery(t, testSRSCodec(t), mailQueue)
	delivery.ResolveForwardTo = func(context.Context, string) (string, error) { return "alice@elsewhere.example", nil }
	address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: delivery})
	t.Cleanup(cleanup)
	const original = "v=1; a=rsa-sha256; d=remote.example; s=mx; h=from:subject; bh=abc; b=def"
	// An external message keeps its own signature; an unauthenticated message
	// claiming a hosted From domain is never vouched for with its key.
	for _, sender := range []string{"bob@remote.example", "carol@example.test"} {
		mailQueue.messages = nil
		if err := dialClient(t, address).SendMail(sender, []string{"alice@example.test"}, strings.NewReader(
			"DKIM-Signature: "+original+"\r\nFrom: "+sender+"\r\nTo: alice@example.test\r\nSubject: forward\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
		if len(mailQueue.messages) != 2 {
			t.Fatalf("%s: queued = %#v", sender, mailQueue.messages)
		}
		for _, message := range mailQueue.messages {
			headers := message.Headers
			if len(message.Content) > 0 {
				headers, _ = model.ParseMessageHeaders(message.Content)
			}
			if signatures := dkimSignatures(headers); message.DKIM != nil || len(signatures) != 1 || signatures[0] != original {
				t.Fatalf("%s: %s DKIM request = %+v, signatures = %q, want only the original", sender, message.Recipient, message.DKIM, signatures)
			}
		}
	}
}

func TestGeneratedMailRequestsSigningOnlyForAuthorizedIdentity(t *testing.T) {
	// deliver sends one message to alice, whose identity is
	// alice@example.test, and returns what the transaction queued.
	deliver := func(t *testing.T, to string, configure func(*Delivery)) []*MailMessage {
		t.Helper()
		q := &recordingSystemQueue{}
		delivery := &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
			MailQueue:        q,
			PrepareDerived: func(ctx context.Context, derived DerivedMessage) (*MailMessage, error) {
				return PrepareDerivedMessage(ctx, derived, nil)
			},
			AuthorizeSubmission: aliceMaySendAs,
		}
		configure(delivery)
		addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Delivery: delivery})
		t.Cleanup(cleanup)
		if err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(
			"From: sender@remote.test\r\nTo: "+to+"\r\nSubject: hello\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
		return q.messages
	}
	for _, test := range []struct {
		name, from string
		signed     bool
	}{
		{name: "own identity", from: "Alice <alice@example.test>", signed: true},
		{name: "another hosted identity", from: "ceo@example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			queued := deliver(t, "alice@example.test", func(delivery *Delivery) {
				delivery.GetSieveScript = func(context.Context, string) (string, bool, error) {
					return `require "enotify"; notify :from "` + test.from + `" :message "new mail" "mailto:alerts@remote.test";`, true, nil
				}
			})
			if len(queued) != 2 || queued[0].Recipient != "alerts@remote.test" || (queued[0].DKIM != nil) != test.signed {
				t.Fatalf("Sieve notify = %+v, want one notification with signed=%v", queued, test.signed)
			}
			// The vacation reply is sent from the incoming To header, which
			// any sender can set.
			queued = deliver(t, test.from, func(delivery *Delivery) {
				delivery.VacationActive = func(context.Context, string) bool { return true }
				delivery.VacationReply = func(context.Context, string) (string, string) { return "Away", "Back later" }
			})
			if len(queued) != 2 || queued[1].Kind != MailTaskVacation || (queued[1].Attributes[AttributeDKIMSign] == "true") != test.signed {
				t.Fatalf("vacation = %+v, want one intent with signed=%v", queued, test.signed)
			}
		})
	}
}
