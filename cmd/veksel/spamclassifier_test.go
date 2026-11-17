package main

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/bayes"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestSpamClassifierSettingsApplyLive(t *testing.T) {
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
	want := bayes.Settings{Enabled: true, MinLearns: 200, MaxTokens: bayes.DefaultMaxTokens, MaxRecords: bayes.DefaultMaxRecords}
	if got := s.spamClassifier.Settings(); got != want {
		t.Fatalf("default settings = %+v", got)
	}
	patchAndApply(t, s, map[string]any{"antispam_bayes_enabled": false, "antispam_bayes_min_learns": 50, "antispam_bayes_autolearn": true, "antispam_bayes_global": true})
	want = bayes.Settings{MinLearns: 50, Autolearn: true, Global: true, MaxTokens: bayes.DefaultMaxTokens, MaxRecords: bayes.DefaultMaxRecords}
	if got := s.spamClassifier.Settings(); got != want {
		t.Fatalf("applied settings = %+v", got)
	}
	for _, key := range spamClassifierKeys {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, map[string]any{"antispam_bayes_min_learns": 0}); err == nil {
		t.Fatal("a zero minimum training count was accepted")
	}
}
