package smtp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/srs"
	"github.com/lkarlslund/veksel/pkg/store"
)

// srsDelivery wires a recording queue, alice@example.test, and SRS hooks for
// the fwd.example forwarding domain.
func srsDelivery(t *testing.T, codec *srs.Codec, mailQueue *recordingSystemQueue) *Delivery {
	t.Helper()
	return &Delivery{
		ResolveRecipient: func(_ context.Context, address string) (string, string, error) {
			if address == "alice@example.test" || strings.HasPrefix(address, "alice+") {
				return "alice:INBOX", "alice", nil
			}
			return "", "", store.ErrNotFound
		},
		MailQueue: mailQueue,
		PrepareDerived: func(ctx context.Context, derived DerivedMessage) (*MailMessage, error) {
			return PrepareDerivedMessage(ctx, derived, nil)
		},
		RewriteForwardSender: func(_ context.Context, sender string) string {
			if sender == "" || strings.HasSuffix(sender, "@example.test") {
				return sender
			}
			rewritten, err := codec.Forward(sender, "fwd.example")
			if err != nil {
				t.Errorf("rewrite %q: %v", sender, err)
			}
			return rewritten
		},
		ReverseSRS: func(_ context.Context, address string) (string, bool, error) {
			if !strings.HasSuffix(address, "@fwd.example") {
				return "", false, nil
			}
			original, err := codec.Reverse(address)
			if errors.Is(err, srs.ErrNotSRS) {
				return "", false, nil
			}
			return original, true, err
		},
		RecipientDelimiters: func() string { return "+" },
	}
}

func testSRSCodec(t *testing.T) *srs.Codec {
	t.Helper()
	codec, err := srs.New([][]byte{[]byte("smtp-srs-test-secret-0123456789")})
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func outboundTo(messages []*MailMessage, recipient string) *MailMessage {
	for _, message := range messages {
		if message.Outbound && message.Recipient == recipient {
			return message
		}
	}
	return nil
}

func TestForwardAndRedirectUseSRSEnvelopeSender(t *testing.T) {
	codec := testSRSCodec(t)
	for _, test := range []struct {
		name      string
		configure func(*Delivery)
	}{
		{"account forward", func(delivery *Delivery) {
			delivery.ResolveForwardTo = func(context.Context, string) (string, error) { return "alice@elsewhere.example", nil }
		}},
		{"sieve redirect", func(delivery *Delivery) {
			delivery.GetSieveScript = func(context.Context, string) (string, bool, error) {
				return `redirect "alice@elsewhere.example";`, true, nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mailQueue := &recordingSystemQueue{}
			delivery := srsDelivery(t, codec, mailQueue)
			test.configure(delivery)
			address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: delivery})
			t.Cleanup(cleanup)
			for _, sender := range []string{"bob@remote.example", "carol@example.test"} {
				mailQueue.messages = nil
				if err := dialClient(t, address).SendMail(sender, []string{"alice@example.test"}, strings.NewReader(
					"From: "+sender+"\r\nTo: alice@example.test\r\nSubject: forward\r\n\r\nbody\r\n")); err != nil {
					t.Fatal(err)
				}
				forwarded := outboundTo(mailQueue.messages, "alice@elsewhere.example")
				if forwarded == nil {
					t.Fatalf("no forwarded message in %#v", mailQueue.messages)
				}
				if sender == "carol@example.test" {
					if forwarded.EnvelopeSender != sender {
						t.Fatalf("local sender rewritten to %q", forwarded.EnvelopeSender)
					}
					continue
				}
				if !strings.HasPrefix(forwarded.EnvelopeSender, "SRS0=") || !strings.HasSuffix(forwarded.EnvelopeSender, "@fwd.example") {
					t.Fatalf("forward envelope sender = %q", forwarded.EnvelopeSender)
				}
				if original, err := codec.Reverse(forwarded.EnvelopeSender); err != nil || original != sender {
					t.Fatalf("forward envelope reverses to %q, %v", original, err)
				}
			}
		})
	}
}

func TestForwardedBounceKeepsNullSender(t *testing.T) {
	message, err := PrepareDerivedMessage(context.Background(), DerivedMessage{Kind: "forward", Recipient: "target@example.net",
		FullMessage: buildMessage(map[string]string{"From": "MAILER-DAEMON@remote.example", "Return-Path": "<>"}, []byte("bounce"))}, nil)
	if err != nil || message.EnvelopeSender != "" {
		t.Fatalf("forwarded bounce sender = %q, %v", message.EnvelopeSender, err)
	}
}

func TestBounceToSRSAddressReturnsToOriginalSender(t *testing.T) {
	codec := testSRSCodec(t)
	mailQueue := &recordingSystemQueue{}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: srsDelivery(t, codec, mailQueue)})
	t.Cleanup(cleanup)
	srsAddress, err := codec.Forward("bob@remote.example", "fwd.example")
	if err != nil {
		t.Fatal(err)
	}
	// Remote MTAs may fold the case of the local part.
	if err := dialClient(t, address).SendMail("", []string{strings.ToLower(srsAddress)}, strings.NewReader(
		"From: MAILER-DAEMON@elsewhere.example\r\nSubject: Undelivered\r\n\r\nbounce\r\n")); err != nil {
		t.Fatal(err)
	}
	returned := outboundTo(mailQueue.messages, "bob@remote.example")
	if returned == nil || returned.EnvelopeSender != "" || len(mailQueue.messages) != 1 {
		t.Fatalf("returned bounce = %#v", mailQueue.messages)
	}

	forged := strings.Replace(srsAddress, "=bob@", "=mallory@", 1)
	for _, recipient := range []string{forged, "SRS0=abcd=AA=remote.example=bob@fwd.example"} {
		if err := dialClient(t, address).SendMail("", []string{recipient}, strings.NewReader("Subject: x\r\n\r\nbody\r\n")); err == nil || !strings.Contains(err.Error(), "550") {
			t.Fatalf("forged SRS recipient %q accepted: %v", recipient, err)
		}
	}
}

func TestSieveSubaddressSeesEnvelopeDetail(t *testing.T) {
	mailQueue := &recordingSystemQueue{}
	delivery := srsDelivery(t, testSRSCodec(t), mailQueue)
	delivery.GetSieveScript = func(context.Context, string) (string, bool, error) {
		return `require ["envelope", "subaddress", "fileinto"]; if envelope :detail :is "to" "news" { fileinto "News"; }`, true, nil
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: delivery})
	t.Cleanup(cleanup)
	for recipient, folder := range map[string]string{"alice+news@example.test": "News", "alice@example.test": "alice:INBOX"} {
		mailQueue.messages = nil
		if err := dialClient(t, address).SendMail("bob@remote.example", []string{recipient}, strings.NewReader("Subject: x\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
		if len(mailQueue.messages) != 1 || mailQueue.messages[0].TargetFolderID != folder || mailQueue.messages[0].Recipient != recipient {
			t.Fatalf("%s delivered as %#v", recipient, mailQueue.messages)
		}
	}
}
