package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestSpamtrapsApplyLiveAndNeverShadowIdentities(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	isTrap := func(address string) bool {
		t.Helper()
		trap, err := s.isSpamtrap(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		return trap
	}
	if isTrap("trap@example.test") {
		t.Fatal("trap matched before any was configured")
	}
	patchAndApply(t, s, map[string]any{"antispam_spamtraps": []string{"trap", "Honey@Example.test"}})
	if status := applyState(t, s, "antispam_spamtraps"); status.State != config.ApplyEffective || status.RestartRequired {
		t.Fatalf("apply state = %+v", status)
	}
	for address, want := range map[string]bool{"trap@example.test": true, "TRAP@example.test": true, "honey@example.test": true,
		"trap@unhosted.test": false, "alice@example.test": false, "honey@other.test": false} {
		if got := isTrap(address); got != want {
			t.Errorf("isSpamtrap(%s) = %t, want %t", address, got, want)
		}
	}

	// Lists that would swallow real mail are refused; the previous list stays.
	for _, traps := range [][]string{{"alice"}, {"bob@example.test"}, {"trap@unhosted.test"}} {
		patchAndApply(t, s, map[string]any{"antispam_spamtraps": traps})
		if status := applyState(t, s, "antispam_spamtraps"); status.State != config.ApplyFailed {
			t.Fatalf("%v: apply state = %+v, want failed", traps, status)
		}
		if !isTrap("trap@example.test") {
			t.Fatalf("%v: previous list was replaced", traps)
		}
	}

	// An identity created after the trap was configured wins.
	if err := s.ts.UserStore().AddEmailAddress(ctx, "trap@example.test", "bob", "example.test", false); err != nil {
		t.Fatal(err)
	}
	if isTrap("trap@example.test") {
		t.Fatal("trap shadows a real address")
	}
}

func TestSpamtrapHitTrainsReputationFuzzyAndTrace(t *testing.T) {
	s := liveAddressingServer(t)
	var err error
	if s.messageTrace, err = messagetrace.New(s.ctx, s.ts.Store()); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("cheap watches and limited offers for every reader today only ", 4)
	message := "Message-ID: <trap-1@spammer.test>\r\nSubject: Offer\r\nFrom: spammer@spammer.test\r\n\r\n" + body + "\r\n"
	s.recordSpamtrap(s.ctx, smtp.SpamtrapHit{CorrelationID: "smtp-transaction-1", RemoteIP: "203.0.113.7", EnvelopeSender: "spammer@spammer.test",
		Traps: []string{"trap@example.test"}, Headers: map[string]string{spam.ReputationHeader: "d=spammer.test; n=203.0.113.0/24"}, Message: []byte(message)})

	if report := s.delivery.reputation.Report(10); report.Tracked != 2 {
		t.Fatalf("reputation tracked %d senders, want the domain and network", report.Tracked)
	}
	if report := s.delivery.fuzzy.Report(); report.Signatures != 1 {
		t.Fatalf("fuzzy signatures = %d, want 1", report.Signatures)
	}
	record, err := s.messageTrace.Get(s.ctx, "smtp-transaction-1-spamtrap-1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Kind != "spamtrap" || record.Recipient != "trap@example.test" || record.Status != "discarded" || record.MessageID != "<trap-1@spammer.test>" ||
		len(record.Events) != 1 || record.Events[0].Stage != "spamtrap" {
		t.Fatalf("trace = %+v", record)
	}
}

func TestSpamtrapBanAndARCPoliciesFollowConfiguration(t *testing.T) {
	cfg := config.DefaultAt(t.TempDir())
	if rule := banPolicy(cfg).Rules[ban.TriggerSpamtrap]; rule != (ban.Rule{Count: 1, Window: 24 * time.Hour}) {
		t.Fatalf("spamtrap ban rule = %+v", rule)
	}
	s := liveAddressingServer(t)
	policy := arcPolicy(cfg, s.ts)
	if !policy.Verify || policy.Sealer == nil || len(policy.TrustedSealers) != 0 {
		t.Fatalf("default ARC policy = %+v", policy)
	}
	cfg.ArcVerify, cfg.ArcSealForwards, cfg.ArcTrustedSealers = false, false, []string{"Google.com."}
	policy = arcPolicy(cfg, s.ts)
	if policy.Verify || policy.Sealer != nil || len(policy.TrustedSealers) != 1 || policy.TrustedSealers[0] != "google.com" {
		t.Fatalf("configured ARC policy = %+v", policy)
	}
}
