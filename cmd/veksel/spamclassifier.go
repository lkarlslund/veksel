package main

import (
	"context"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/bayes"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

// spamClassifierKeys are the statistical classifier settings applied
// together.
var spamClassifierKeys = []string{"antispam_bayes_enabled", "antispam_bayes_min_learns", "antispam_bayes_autolearn", "antispam_bayes_global"}

func spamClassifierSettings(cfg *config.Config) bayes.Settings {
	return bayes.Settings{
		Enabled: cfg.AntispamBayesEnabled, MinLearns: cfg.AntispamBayesMinLearns,
		Autolearn: cfg.AntispamBayesAutolearn, Global: cfg.AntispamBayesGlobal,
	}
}

// accountIndexes opens an account's index store for its classifier model.
type accountIndexes struct{ accounts *account.Manager }

func (a accountIndexes) WithIndex(ctx context.Context, userID string, fn func(context.Context, store.Store) error) error {
	generation, release, err := a.accounts.Acquire(userID)
	if err != nil {
		return err
	}
	defer release()
	return fn(ctx, generation.Index)
}

// buildSpamClassifier attaches the statistical classifier to the automated
// folder space, so Junk moves from every protocol train it, and registers
// its live settings. Its symbols use the live spam engine's overrides.
func (s *server) buildSpamClassifier(space *rules.FolderSpace) error {
	if err := s.buildSpamFuzzy(); err != nil {
		return err
	}
	if err := s.buildSpamReputation(); err != nil {
		return err
	}
	classifier, err := bayes.New(bayes.Config{
		Space: space, Accounts: accountIndexes{accounts: s.accountManager}, Global: s.store, Symbols: &s.delivery.spam,
		Feedback: spam.MoveFeedback{Reputation: &s.delivery.reputation, Fuzzy: &s.delivery.fuzzy},
	}, spamClassifierSettings(s.cfg))
	if err != nil {
		return startupError("initialize spam classifier", err)
	}
	s.cleanup.push(classifier.Close)
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		classifier.SetSettings(spamClassifierSettings(cfg))
		return nil
	}, spamClassifierKeys...); err != nil {
		return err
	}
	space.AddItemObserver(classifier)
	s.spamClassifier = classifier
	return nil
}
