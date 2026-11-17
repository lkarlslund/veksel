package main

import (
	"context"
	"errors"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

// spamReputationKeys are the reputation and auto-allowlist settings applied
// together.
var spamReputationKeys = []string{"antispam_auto_allowlist", "antispam_reputation", "antispam_reputation_min_samples"}

const (
	spamReputationNamespace = "veksel:spam-reputation"
	spamReputationKey       = "state"
	spamReputationFlush     = 5 * time.Minute
)

// buildSpamReputation restores the sender reputation, keeps it persisted,
// and registers its live settings. The classifier feeds it users' Junk
// moves and the spam engine scores from and records into it.
func (s *server) buildSpamReputation() error {
	reputation := &s.delivery.reputation
	if data, err := s.store.Get(s.ctx, spamReputationNamespace, spamReputationKey); err == nil {
		if err := reputation.Restore(data); err != nil {
			log.Warn("spam reputation: discarding unreadable state", "error", err)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return startupError("restore spam reputation", err)
	}
	apply := func(cfg *config.Config) error {
		reputation.SetSettings(cfg.AntispamReputation, cfg.AntispamReputationMinSamples)
		s.delivery.autoAllowlist.Store(cfg.AntispamAutoAllowlist)
		return nil
	}
	_ = apply(s.cfg)
	if err := s.cfgService.RegisterApplier(apply, spamReputationKeys...); err != nil {
		return err
	}
	s.persistSpamState(spamReputationNamespace, reputation.Snapshot)
	return nil
}

func (s *server) saveSpamReputation(ctx context.Context) {
	s.saveSpamState(ctx, spamReputationNamespace, s.delivery.reputation.Snapshot)
}

// saveSpamState writes one learned spam state, such as sender reputation,
// under its namespace.
func (s *server) saveSpamState(ctx context.Context, namespace string, snapshot func() ([]byte, error)) {
	data, err := snapshot()
	if err == nil {
		err = s.store.Set(ctx, namespace, spamReputationKey, data)
	}
	if err != nil {
		log.Warn("spam state: save failed", "namespace", namespace, "error", err)
	}
}

// persistSpamState saves a learned spam state every spamReputationFlush and
// once more when the background group stops, before the store closes.
func (s *server) persistSpamState(namespace string, snapshot func() ([]byte, error)) {
	s.background.Go(func(ctx context.Context) {
		ticker := time.NewTicker(spamReputationFlush)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.saveSpamState(context.Background(), namespace, snapshot)
			case <-ctx.Done():
				s.saveSpamState(context.Background(), namespace, snapshot)
				return
			}
		}
	})
}

// knownCorrespondent is the SMTP auto-allowlist: the KNOWN_CORRESPONDENT
// symbol when userID has written to sender. The caller has already
// established that the sender authenticated as its own From address.
func (s *server) knownCorrespondent(ctx context.Context, userID, sender string) (spam.Symbol, bool, error) {
	if !s.delivery.autoAllowlist.Load() {
		return spam.Symbol{}, false, nil
	}
	symbol, ok := s.delivery.spam.BuiltinSymbol(spam.SymbolKnownCorrespondent)
	if !ok {
		return spam.Symbol{}, false, nil
	}
	known, err := s.recipientHistory.Knows(ctx, userID, sender)
	return symbol, known, err
}
