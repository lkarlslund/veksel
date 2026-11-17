package smtp

import (
	"context"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"

	"github.com/lkarlslund/veksel/pkg/store"
)

// A second From or Sender field, in any spelling, must not let a submission
// authorize one identity while the recipient's client shows another.
func TestSubmissionRejectsRepeatedIdentityFields(t *testing.T) {
	for name, message := range map[string]string{
		"two From fields":      "From: ceo@example.test\r\nFrom: Alice <alice@example.test>\r\n",
		"From spelled twice":   "from: ceo@example.test\r\nFrom: Alice <alice@example.test>\r\n",
		"two Sender fields":    "From: Alice <alice@example.test>\r\nSender: alice@example.test\r\nSENDER: ceo@example.test\r\n",
		"lowercase From alone": "from: ceo@example.test\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			q := &recordingSystemQueue{}
			addr, cleanup := startSMTPServer(t, &Config{
				ServerName: "test.veksel", AuthRequired: true, AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true,
				AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
				Delivery: &Delivery{
					ResolveRecipient:        func(context.Context, string) (string, string, error) { return "", "", store.ErrNotFound },
					MailQueue:               q,
					AllowAuthenticatedRelay: true,
					AuthorizeSubmission:     aliceMaySendAs,
				},
			})
			t.Cleanup(cleanup)
			client := dialClient(t, addr)
			if err := client.Auth(sasl.NewPlainClient("", "alice", "password")); err != nil {
				t.Fatal(err)
			}
			err := client.SendMail("alice@example.test", []string{"carol@remote.test"}, strings.NewReader(
				message+"To: carol@remote.test\r\nSubject: x\r\n\r\nbody\r\n"))
			if name == "lowercase From alone" {
				// One field in any spelling is the identity that is checked.
				if err == nil || len(q.messages) != 0 {
					t.Fatalf("unauthorized lowercase From accepted: err=%v queued=%d", err, len(q.messages))
				}
				return
			}
			if err == nil || len(q.messages) != 0 {
				t.Fatalf("repeated identity field accepted: err=%v queued=%d", err, len(q.messages))
			}
		})
	}
}

// The inbound listener refuses a second From field before the local-domain
// spoof check could read only one of them.
func TestInboundRejectsRepeatedFrom(t *testing.T) {
	q := &recordingSystemQueue{}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:inbox", "alice", nil },
		MailQueue:        q,
	}})
	t.Cleanup(cleanup)
	err := dialClient(t, addr).SendMail("x@remote.test", []string{"alice@example.test"}, strings.NewReader(
		"From: ceo@example.test\r\nFrom: x@remote.test\r\nTo: alice@example.test\r\nSubject: x\r\n\r\nbody\r\n"))
	if err == nil || !strings.Contains(err.Error(), "more than one from") {
		t.Fatalf("err = %v, want a repeated From rejection", err)
	}
}
