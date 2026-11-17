package main

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestSpamFuzzySettingsApplyLiveAndStatePersists(t *testing.T) {
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
	fuzzy := &s.delivery.fuzzy
	if report := fuzzy.Report(); !report.Enabled || report.Threshold != spam.DefaultFuzzyThreshold || report.BulkThreshold != spam.DefaultBulkThreshold {
		t.Fatalf("defaults = %+v", report)
	}
	patchAndApply(t, s, map[string]any{"antispam_fuzzy": false, "antispam_fuzzy_threshold": 90, "antispam_bulk_threshold": 9})
	if report := fuzzy.Report(); report.Enabled || report.Threshold != 90 || report.BulkThreshold != 9 {
		t.Fatalf("applied = %+v", report)
	}
	for _, key := range spamFuzzyKeys {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	for _, patch := range []map[string]any{{"antispam_fuzzy_threshold": 10}, {"antispam_bulk_threshold": 1}} {
		if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, patch); err == nil {
			t.Fatalf("%v was accepted", patch)
		}
	}

	// Learned signatures survive a restart through the store.
	patchAndApply(t, s, map[string]any{"antispam_fuzzy": true})
	fuzzy.Moved([]byte("Subject: x\r\n\r\n"+strings.Repeat("alpha beta gamma delta epsilon ", 12)), true)
	s.saveSpamState(s.ctx, spamFuzzyNamespace, fuzzy.Snapshot)
	data, err := s.store.Get(s.ctx, spamFuzzyNamespace, spamReputationKey)
	if err != nil {
		t.Fatal(err)
	}
	var restored spam.Fuzzy
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}
	if got := restored.Report(); got.Signatures != 1 {
		t.Fatalf("restored = %+v", got)
	}
}
