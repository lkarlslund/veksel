package smtp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/batv"
)

func TestBouncesRequireValidBATVTagWhichIsRemoved(t *testing.T) {
	codec, err := batv.New([][]byte{[]byte("smtp-batv-test-secret-0123456789")})
	if err != nil {
		t.Fatal(err)
	}
	srsCodec := testSRSCodec(t)
	mailQueue := &recordingSystemQueue{}
	delivery := srsDelivery(t, srsCodec, mailQueue)
	policy := &batv.Policy{Codec: codec, Enabled: true}
	delivery.CheckReturnPath = func(_ context.Context, address string, bounce bool) (string, error) {
		if !strings.HasSuffix(address, "@example.test") {
			return address, nil
		}
		recipient, err := policy.Recipient(address, bounce, time.Now())
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrBackscatter, err)
		}
		return recipient, nil
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: delivery})
	t.Cleanup(cleanup)
	send := func(sender, recipient string) error {
		mailQueue.messages = nil
		return dialClient(t, address).SendMail(sender, []string{recipient}, strings.NewReader("From: MAILER-DAEMON@remote.example\r\nSubject: Undelivered\r\n\r\nbounce\r\n"))
	}

	signed, err := codec.Sign("alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := send("", signed); err != nil {
		t.Fatalf("tagged bounce: %v", err)
	}
	if len(mailQueue.messages) != 1 || mailQueue.messages[0].Recipient != "alice@example.test" || mailQueue.messages[0].TargetFolderID != "alice:INBOX" {
		t.Fatalf("tagged bounce delivered as %#v", mailQueue.messages)
	}
	for _, recipient := range []string{"alice@example.test", strings.Replace(signed, "=alice@", "=alice+x@", 1)} {
		if err := send("", recipient); err == nil || !strings.Contains(err.Error(), "550") || !strings.Contains(err.Error(), "backscatter") {
			t.Fatalf("bounce to %q = %v, want backscatter rejection", recipient, err)
		}
	}
	// Ordinary mail needs no tag, and a valid tag still routes.
	if err := send("bob@remote.example", "alice@example.test"); err != nil {
		t.Fatalf("ordinary mail: %v", err)
	}
	if err := send("bob@remote.example", signed); err != nil || mailQueue.messages[0].Recipient != "alice@example.test" {
		t.Fatalf("ordinary mail to tag = %v, %#v", err, mailQueue.messages)
	}
	// SRS returns are validated by SRS alone.
	srsAddress, _ := srsCodec.Forward("bob@remote.example", "fwd.example")
	if err := send("", srsAddress); err != nil || outboundTo(mailQueue.messages, "bob@remote.example") == nil {
		t.Fatalf("SRS bounce = %v, %#v", err, mailQueue.messages)
	}
}

func TestGreylistTripletNamesSPFAuthenticatedDomain(t *testing.T) {
	session := &Session{envelopeSender: "a@example.net", spfResult: &SpfResult{Result: "pass", SenderDomain: "example.net"}}
	if triplet := session.greylistTriplet("192.0.2.1", "b@example.com"); triplet.SPFPassDomain != "example.net" || triplet.EnvelopeFrom != "a@example.net" {
		t.Fatalf("SPF pass triplet = %+v", triplet)
	}
	for _, result := range []string{"softfail", "none", "skip"} {
		session.spfResult.Result = result
		if triplet := session.greylistTriplet("192.0.2.1", "b@example.com"); triplet.SPFPassDomain != "" {
			t.Fatalf("SPF %s triplet = %+v", result, triplet)
		}
	}
	session = &Session{spfResult: &SpfResult{Result: "pass", SenderDomain: "helo.example.net"}}
	if triplet := session.greylistTriplet("192.0.2.1", "b@example.com"); triplet.SPFPassDomain != "" {
		t.Fatalf("null sender triplet = %+v", triplet)
	}
}
