package smtp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestRecipientRewritingAtRCPT(t *testing.T) {
	mailQueue := &recordingSystemQueue{}
	delivery := srsDelivery(t, testSRSCodec(t), mailQueue)
	delivery.RewriteRecipient = func(_ context.Context, address string) (string, error) {
		switch address {
		case "alice@legacy.test":
			return "alice@example.test", nil
		case "broken@legacy.test":
			return "", errors.New("rules unavailable")
		}
		return address, nil
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", Delivery: delivery})
	t.Cleanup(cleanup)
	send := func(recipient string) error {
		mailQueue.messages = nil
		return dialClient(t, address).SendMail("bob@remote.example", []string{recipient}, strings.NewReader("Subject: hi\r\n\r\nbody\r\n"))
	}
	if err := send("alice@legacy.test"); err != nil {
		t.Fatal(err)
	}
	if len(mailQueue.messages) != 1 || mailQueue.messages[0].Recipient != "alice@example.test" || mailQueue.messages[0].TargetFolderID != "alice:INBOX" {
		t.Fatalf("rewritten recipient delivered as %#v", mailQueue.messages)
	}
	if err := send("broken@legacy.test"); err == nil || !strings.Contains(err.Error(), "451") {
		t.Fatalf("rewrite failure = %v, want 451", err)
	}
}

func TestJournalMessageListsEveryEnvelopeRecipient(t *testing.T) {
	original := []byte("From: alice@example.test\r\nTo: Carol <carol@remote.test>\r\nCc: dave@remote.test\r\nSubject: Quarterly\r\nMessage-ID: <q@example.test>\r\n\r\nNumbers.\r\n")
	request := JournalRequest{From: "Journal <postmaster@example.test>", To: "journal@example.test", ServerName: "mx.example.test", ID: "msg-1",
		Direction: "outbound", Sender: "alice@example.test", Recipients: []string{"carol@remote.test", "dave@remote.test", "erin@remote.test"}, Original: original}

	request.Format = model.JournalEnvelope
	report := string(BuildJournalMessage(request, time.Now()))
	for _, want := range []string{"To: journal@example.test\r\n", "X-Veksel-Journal: msg-1\r\n", "Subject: Journal report: Quarterly\r\n",
		"Sender: alice@example.test\r\n", "Message-Id: <q@example.test>\r\n", "To: carol@remote.test\r\n", "Cc: dave@remote.test\r\n",
		"Bcc: erin@remote.test\r\n", "Content-Type: message/rfc822", string(original)} {
		if !strings.Contains(report, want) {
			t.Fatalf("envelope report lacks %q:\n%s", want, report)
		}
	}
	headers, _ := model.ParseMessageHeaders([]byte(report))
	if !strings.HasPrefix(headers["Content-Type"], "multipart/mixed; boundary=") {
		t.Fatalf("report content type = %q", headers["Content-Type"])
	}

	request.Format = model.JournalRaw
	raw := string(BuildJournalMessage(request, time.Now()))
	if !strings.HasSuffix(raw, string(original)) || !strings.Contains(raw, "X-Veksel-Journal-Recipient: erin@remote.test; type=bcc\r\n") ||
		!strings.Contains(raw, "X-Veksel-Journal-Direction: outbound\r\n") || !strings.HasPrefix(raw, "X-Veksel-Journal: msg-1\r\n") {
		t.Fatalf("raw journal copy:\n%s", raw)
	}
}
