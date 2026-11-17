package smtp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

var attachmentTestMessage = "From: sender@remote.test\r\nTo: alice@example.test\r\nSubject: invoice\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMessage-ID: <1@remote.test>\r\n" +
	"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
	"--XX\r\nContent-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVo=\r\n--XX--\r\n"

func attachmentSwitch(t *testing.T, mode string, submissions bool) *attachment.Switch {
	t.Helper()
	policy, err := attachment.NewPolicy(attachment.Settings{Mode: mode, BlockedExtensions: attachment.DefaultBlockedExtensions(), CheckSubmissions: submissions})
	if err != nil {
		t.Fatal(err)
	}
	var live attachment.Switch
	live.Set(policy)
	return &live
}

func attachmentServer(t *testing.T, live *attachment.Switch, queue *recordingSystemQueue) string {
	t.Helper()
	engine, err := spam.NewEngine(spam.Config{Thresholds: spam.DefaultThresholds()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Attachments: live, Spam: publicSourceChecker{engine: engine}, Delivery: spamTestDelivery(queue, nil)})
	t.Cleanup(cleanup)
	return address
}

func TestAttachmentPolicyRejectsDangerousExecutables(t *testing.T) {
	queue := &recordingSystemQueue{}
	address := attachmentServer(t, attachmentSwitch(t, "reject", false), queue)
	err := dialClient(t, address).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(attachmentTestMessage))
	if err == nil || !strings.Contains(err.Error(), "550") || !strings.Contains(err.Error(), "ATTACH_DANGEROUS_EXT") {
		t.Fatalf("error = %v, want 550 naming the symbol", err)
	}
	if len(queue.messages) != 0 {
		t.Fatalf("rejected message was queued: %#v", queue.messages)
	}
}

func TestAttachmentPolicyQuarantinesWithEvidence(t *testing.T) {
	queue := &recordingSystemQueue{}
	address := attachmentServer(t, attachmentSwitch(t, "quarantine", false), queue)
	if err := dialClient(t, address).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(attachmentTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 || queue.messages[0].Kind != MailTaskQuarantine {
		t.Fatalf("queued = %#v", queue.messages)
	}
	message := queue.messages[0]
	if reason := message.Attributes["reason"]; !strings.Contains(reason, "ATTACH_DANGEROUS_EXT (invoice.pdf.exe)") {
		t.Fatalf("reason = %q", reason)
	}
	transcript := message.Attributes["scan_transcript"]
	for _, want := range []string{`"engine":"attachments"`, "ATTACH_DOUBLE_EXT", `"engine":"antispam"`} {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript lacks %s: %s", want, transcript)
		}
	}
}

func TestAttachmentPolicyScoreOnlyDeliversWithSymbols(t *testing.T) {
	queue := &recordingSystemQueue{}
	address := attachmentServer(t, attachmentSwitch(t, "score", false), queue)
	if err := dialClient(t, address).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(attachmentTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 || queue.messages[0].Kind == MailTaskQuarantine {
		t.Fatalf("score mode must not quarantine: %#v", queue.messages)
	}
	// 6 (dangerous) + 4 (double extension) crosses the junk threshold.
	headers := queue.messages[0].Headers
	if !strings.Contains(headers["X-Spam-Symbols"], "ATTACH_DANGEROUS_EXT(6)") || headers["X-Spam-Flag"] != "YES" || queue.messages[0].TargetFolderID != "alice@example.test:Junk" {
		t.Fatalf("headers = %#v folder %q", headers, queue.messages[0].TargetFolderID)
	}
}

func TestAttachmentPolicyOffAndLiveSwitch(t *testing.T) {
	queue := &recordingSystemQueue{}
	live := attachmentSwitch(t, "off", false)
	address := attachmentServer(t, live, queue)
	if err := dialClient(t, address).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(attachmentTestMessage)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 || strings.Contains(queue.messages[0].Headers["X-Spam-Symbols"], "ATTACH_") {
		t.Fatalf("off must not inspect: %#v", queue.messages[0].Headers)
	}
	live.Set(attachmentSwitch(t, "reject", false).Load())
	if err := dialClient(t, address).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(attachmentTestMessage)); err == nil {
		t.Fatal("a live switch to reject must apply to the next message")
	}
}

func submissionAttachmentServer(t *testing.T, live *attachment.Switch, queue *recordingSystemQueue) string {
	t.Helper()
	address, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel", AuthRequired: true, AuthMechanisms: []string{"PLAIN"}, SaslIrEnabled: true, Attachments: live,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "", "", store.ErrNotFound },
			MailQueue:        queue, AllowAuthenticatedRelay: true,
		},
	})
	t.Cleanup(cleanup)
	return address
}

func sendSubmission(t *testing.T, address string) error {
	t.Helper()
	client := dialClient(t, address)
	if err := client.Auth(sasl.NewPlainClient("", "alice", "password")); err != nil {
		t.Fatal(err)
	}
	message := strings.Replace(attachmentTestMessage, "sender@remote.test", "alice@example.test", 1)
	return client.SendMail("alice@example.test", []string{"carol@remote.test"}, strings.NewReader(message))
}

func TestAuthenticatedSubmissionsAreInspectedOnlyWhenOptedIn(t *testing.T) {
	queue := &recordingSystemQueue{}
	if err := sendSubmission(t, submissionAttachmentServer(t, attachmentSwitch(t, "reject", false), queue)); err != nil {
		t.Fatalf("default must not block users' sends: %v", err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("queued = %#v", queue.messages)
	}
	// Quarantine has no recipient to hold a submission, so it rejects.
	for _, mode := range []string{"reject", "quarantine"} {
		queue := &recordingSystemQueue{}
		err := sendSubmission(t, submissionAttachmentServer(t, attachmentSwitch(t, mode, true), queue))
		if err == nil || !strings.Contains(err.Error(), "550") || len(queue.messages) != 0 {
			t.Fatalf("%s with submissions opted in: err=%v queued=%#v", mode, err, queue.messages)
		}
	}
}
