package main

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dkim/dkimtest"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestCalendarIMIPSettingAppliesLive(t *testing.T) {
	s := liveAddressingServer(t)
	base := service.NewFolderSpace(s.ts, authz.New(s.ts))
	engine, err := rules.NewEngine(s.ctx, s.store, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	space, err := rules.NewFolderSpace(base, engine)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.buildCalendarScheduling(space); err != nil {
		t.Fatal(err)
	}
	if !s.imip.Enabled() {
		t.Fatal("calendar_imip_enabled default is not applied")
	}
	patchAndApply(t, s, map[string]any{"calendar_imip_enabled": false})
	if s.imip.Enabled() {
		t.Fatal("disabling calendar_imip_enabled did not apply live")
	}
	patchAndApply(t, s, map[string]any{"calendar_imip_enabled": true})
	if !s.imip.Enabled() {
		t.Fatal("re-enabling calendar_imip_enabled did not apply live")
	}
	// Until the queue starts, generated invitations are refused rather
	// than dropped silently.
	if err := s.sendIMIP(s.ctx, imip.Outgoing{From: "alice@example.test", To: []string{"carol@remote.test"}, Raw: []byte("Subject: x\r\n\r\nx")}); err == nil {
		t.Fatal("sendIMIP accepted a message before the queue started")
	}
}

func TestCalendarIMIPIsDKIMSignedForRemoteRecipientsOnly(t *testing.T) {
	s := liveAddressingServer(t)
	s.mailQueue = queue.New(&queue.Config{Signer: dkim.NewSigner(s.ts.DomainStore())})
	t.Cleanup(s.mailQueue.Close)
	s.smtpQueueAdapter = queue.NewSMTPAdapter(s.mailQueue)
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	invitation := imip.Outgoing{From: "alice@example.test", To: []string{"carol@remote.test", "bob@example.test"}, UID: "uid-1",
		Raw: []byte("From: alice@example.test\r\nTo: carol@remote.test, bob@example.test\r\nSubject: Invitation\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nBEGIN:VCALENDAR\r\n")}
	// A replay must not queue a second, differently signed copy.
	for range 2 {
		if err := s.sendIMIP(s.ctx, invitation); err != nil {
			t.Fatal(err)
		}
	}
	queued := s.mailQueue.List("")
	if len(queued) != 2 {
		t.Fatalf("queued = %d messages, want 2", len(queued))
	}
	for _, message := range queued {
		switch message.Recipient {
		case "carol@remote.test":
			if result := verifier.Verify(t.Context(), message.RawMessage()); !result.Pass || result.Domain != "example.test" {
				t.Fatalf("remote invitation verification = %+v", result)
			}
		case "bob@example.test":
			if strings.Contains(string(message.Content), "DKIM-Signature") {
				t.Fatal("local invitation was signed")
			}
		default:
			t.Fatalf("unexpected recipient %q", message.Recipient)
		}
	}
}
