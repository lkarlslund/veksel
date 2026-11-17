package main

import (
	"errors"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/store"
)

// spamFuzzyKeys are the fuzzy and bulk detection settings applied together.
var spamFuzzyKeys = []string{"antispam_fuzzy", "antispam_fuzzy_threshold", "antispam_bulk_threshold"}

const spamFuzzyNamespace = "veksel:spam-fuzzy"

// buildSpamFuzzy restores the learned spam signatures, keeps them persisted,
// and registers the live settings. Users' Junk moves feed the signatures
// through the classifier's move observer and the spam engine scores from and
// learns into them.
func (s *server) buildSpamFuzzy() error {
	fuzzy := &s.delivery.fuzzy
	if data, err := s.store.Get(s.ctx, spamFuzzyNamespace, spamReputationKey); err == nil {
		if err := fuzzy.Restore(data); err != nil {
			log.Warn("spam fuzzy: discarding unreadable state", "error", err)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return startupError("restore spam fuzzy signatures", err)
	}
	apply := func(cfg *config.Config) error {
		fuzzy.SetSettings(cfg.AntispamFuzzy, cfg.AntispamFuzzyThreshold, cfg.AntispamBulkThreshold)
		return nil
	}
	_ = apply(s.cfg)
	if err := s.cfgService.RegisterApplier(apply, spamFuzzyKeys...); err != nil {
		return err
	}
	s.persistSpamState(spamFuzzyNamespace, fuzzy.Snapshot)
	return nil
}
