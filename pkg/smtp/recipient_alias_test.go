package smtp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
)

func TestSMTPRecipientAliasExpandsAndDeduplicatesTerminalTargets(t *testing.T) {
	mailQueue := &recordingSystemQueue{}
	resolve := func(_ context.Context, address string) (string, string, error) {
		switch address {
		case "alice@example.test":
			return "alice:INBOX", "alice", nil
		case "bob@example.test":
			return "bob:INBOX", "bob", nil
		default:
			return "", "", store.ErrNotFound
		}
	}
	expand := func(_ context.Context, address string) ([]string, bool, error) {
		if address == "team@example.test" {
			return []string{"alice@example.test", "bob@example.test"}, true, nil
		}
		return nil, false, nil
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", MaxRecipients: 2, Delivery: &Delivery{
		ResolveRecipient: resolve, ExpandRecipient: expand, MailQueue: mailQueue,
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, address)
	if err := client.SendMail("sender@remote.test", []string{"team@example.test", "alice@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nTo: team@example.test\r\nSubject: alias\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(mailQueue.messages) != 2 {
		t.Fatalf("queued messages = %#v", mailQueue.messages)
	}
	got := []string{mailQueue.messages[0].Recipient, mailQueue.messages[1].Recipient}
	if strings.Join(got, ",") != "alice@example.test,bob@example.test" {
		t.Fatalf("terminal recipients = %v", got)
	}
	if !strings.Contains(string(mailQueue.messages[0].Content), "Subject: alias") || mailQueue.messages[0].TargetFolderID != "alice:INBOX" || mailQueue.messages[1].TargetFolderID != "bob:INBOX" {
		t.Fatalf("queued alias deliveries = %#v", mailQueue.messages)
	}
}

func TestSMTPRecipientAliasEnforcesExpandedLimitAndFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		expand func(context.Context, string) ([]string, bool, error)
	}{
		{"limit", func(context.Context, string) ([]string, bool, error) {
			return []string{"one@example.test", "two@example.test", "three@example.test"}, true, nil
		}},
		{"backend error", func(context.Context, string) ([]string, bool, error) {
			return nil, true, errors.New("store unavailable")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mailQueue := &recordingSystemQueue{}
			address, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", MaxRecipients: 2, Delivery: &Delivery{
				ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "owner", nil },
				ExpandRecipient:  test.expand,
				MailQueue:        mailQueue,
			}})
			t.Cleanup(cleanup)
			client := dialClient(t, address)
			if err := client.SendMail("sender@remote.test", []string{"team@example.test"}, strings.NewReader("From: sender@remote.test\r\n\r\nbody")); err == nil {
				t.Fatal("unsafe alias was accepted")
			}
			if len(mailQueue.messages) != 0 {
				t.Fatalf("rejected alias queued messages: %#v", mailQueue.messages)
			}
		})
	}
}

func TestSMTPDiscardingRecipientIsAcceptedAndDropped(t *testing.T) {
	mailQueue := &recordingSystemQueue{}
	resolve := func(_ context.Context, address string) (string, string, error) {
		switch address {
		case "alice@example.test":
			return "alice:INBOX", "alice", nil
		case "gone@example.test":
			return "", "", ErrRecipientDiscarded
		case "expired@example.test":
			return "", "", errors.New("address disabled")
		default:
			return "", "", store.ErrNotFound
		}
	}
	address, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", MaxRecipients: 5, Delivery: &Delivery{
		ResolveRecipient: resolve, MailQueue: mailQueue,
	}})
	t.Cleanup(cleanup)
	client := dialClient(t, address)
	if err := client.SendMail("sender@remote.test", []string{"alice@example.test", "gone@example.test"}, strings.NewReader(
		"From: sender@remote.test\r\nSubject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("discarded recipient was refused: %v", err)
	}
	if len(mailQueue.messages) != 1 || mailQueue.messages[0].Recipient != "alice@example.test" {
		t.Fatalf("queued = %#v", mailQueue.messages)
	}
	rejecting := dialClient(t, address)
	if err := rejecting.SendMail("sender@remote.test", []string{"expired@example.test"}, strings.NewReader("From: sender@remote.test\r\n\r\nbody")); err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("expired alias error = %v, want 550", err)
	}
}
