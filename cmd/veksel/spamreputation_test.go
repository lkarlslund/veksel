package main

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestSpamReputationSettingsApplyLiveAndStatePersists(t *testing.T) {
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
	if err := s.buildSpamClassifier(space); err != nil {
		t.Fatal(err)
	}
	reputation := &s.delivery.reputation
	if !reputation.Enabled() || reputation.MinSamples() != spam.DefaultReputationMinSamples || !s.delivery.autoAllowlist.Load() {
		t.Fatalf("defaults: reputation %v/%d, auto-allowlist %v", reputation.Enabled(), reputation.MinSamples(), s.delivery.autoAllowlist.Load())
	}
	patchAndApply(t, s, map[string]any{"antispam_auto_allowlist": false, "antispam_reputation": false, "antispam_reputation_min_samples": 7})
	if reputation.Enabled() || reputation.MinSamples() != 7 || s.delivery.autoAllowlist.Load() {
		t.Fatalf("applied: reputation %v/%d, auto-allowlist %v", reputation.Enabled(), reputation.MinSamples(), s.delivery.autoAllowlist.Load())
	}
	for _, key := range spamReputationKeys {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, map[string]any{"antispam_reputation_min_samples": 0}); err == nil {
		t.Fatal("a zero minimum sample count was accepted")
	}

	// The auto-allowlist consults nothing while it is off.
	if _, known, err := s.knownCorrespondent(s.ctx, "alice", "pal@example.test"); err != nil || known {
		t.Fatalf("disabled auto-allowlist = %v, %v", known, err)
	}

	// State survives a restart through the store.
	patchAndApply(t, s, map[string]any{"antispam_reputation": true})
	reputation.Record(spam.ReputationKeys{Domain: "kept.example"}, spam.RepJunked)
	s.saveSpamReputation(s.ctx)
	var restored spam.Reputation
	data, err := s.store.Get(s.ctx, spamReputationNamespace, spamReputationKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}
	if got := restored.Report(5); got.Tracked != 1 {
		t.Fatalf("restored report = %+v", got)
	}
}
