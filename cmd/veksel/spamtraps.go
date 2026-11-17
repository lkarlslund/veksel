package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

// spamtrapKeys are the spamtrap settings.
var spamtrapKeys = []string{"antispam_spamtraps"}

// applySpamtraps replaces the live spamtrap list. A configuration whose
// traps collide with real identities is refused and the previous list
// stays.
func (s *server) applySpamtraps(cfg *config.Config) error {
	traps, err := config.ParseSpamtraps(cfg.AntispamSpamtraps)
	if err != nil {
		return err
	}
	if err := s.checkSpamtraps(traps); err != nil {
		return err
	}
	s.delivery.spamtraps.Store(&traps)
	return nil
}

// loadSpamtraps installs the configured spamtraps at startup. A collision
// with an identity created since the traps were configured is reported but
// not fatal: the identity wins at RCPT (see isSpamtrap).
func (s *server) loadSpamtraps() {
	traps, err := config.ParseSpamtraps(s.cfg.AntispamSpamtraps)
	if err == nil {
		err = s.checkSpamtraps(traps)
	}
	if err != nil {
		log.Warn("spamtraps: configured list needs attention", "error", err)
	}
	s.delivery.spamtraps.Store(&traps)
}

// checkSpamtraps verifies that traps never shadow real mail: an exact trap
// must be on a hosted domain, and neither it nor a trap local part on any
// hosted domain may resolve to a mailbox, alias, or catch-all.
func (s *server) checkSpamtraps(traps config.Spamtraps) error {
	candidates := slices.Clone(traps.Addresses)
	if len(traps.LocalParts) > 0 {
		domains, err := s.ts.DomainStore().List(s.ctx)
		if err != nil {
			return fmt.Errorf("list hosted domains: %w", err)
		}
		for _, local := range traps.LocalParts {
			for _, domain := range domains {
				candidates = append(candidates, local+"@"+domain.ID)
			}
		}
	}
	for _, address := range traps.Addresses {
		_, domain, _ := strings.Cut(address, "@")
		hosted, err := s.isHostedDomain(s.ctx, domain)
		if err != nil {
			return fmt.Errorf("check spamtrap domain: %w", err)
		}
		if !hosted {
			return fmt.Errorf("antispam_spamtraps entry %q is not on a hosted domain", address)
		}
	}
	for _, address := range candidates {
		identity, err := s.realIdentity(s.ctx, address)
		if err != nil {
			return fmt.Errorf("check spamtrap %q: %w", address, err)
		}
		if identity {
			return fmt.Errorf("antispam_spamtraps entry %q is a real address or alias", address)
		}
	}
	return nil
}

// realIdentity reports whether address resolves to a mailbox, alias, or
// catch-all route.
func (s *server) realIdentity(ctx context.Context, address string) (bool, error) {
	_, err := s.resolveRecipient(ctx, address)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// isSpamtrap reports whether addr is a configured spamtrap: an exact trap
// address, or a trap local part on a hosted domain. A real identity created
// after the trap was configured wins, so a trap never swallows real mail.
func (s *server) isSpamtrap(ctx context.Context, addr string) (bool, error) {
	traps := s.delivery.spamtraps.Load()
	if traps == nil {
		return false, nil
	}
	addr = strings.ToLower(addr)
	local, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return false, nil
	}
	if !slices.Contains(traps.Addresses, addr) {
		if !slices.Contains(traps.LocalParts, local) {
			return false, nil
		}
		if hosted, err := s.isHostedDomain(ctx, domain); err != nil || !hosted {
			return false, err
		}
	}
	identity, err := s.realIdentity(ctx, addr)
	return err == nil && !identity, err
}

// recordSpamtrap learns from mail sent to spamtraps as if a user had moved
// it to Junk: the sender's reputation and the fuzzy body signatures learn
// it as spam. Each trap recipient gets a message trace record, since trap
// mail never enters the queue that traces ordinary deliveries.
func (s *server) recordSpamtrap(ctx context.Context, hit smtp.SpamtrapHit) {
	spam.MoveFeedback{Reputation: &s.delivery.reputation, Fuzzy: &s.delivery.fuzzy}.Moved(hit.Message, hit.Headers, true)
	if s.messageTrace == nil {
		return
	}
	headers := model.ParseItemHeaders(hit.Message)
	now := time.Now().UTC()
	for index, trap := range hit.Traps {
		record := messagetrace.Record{QueueID: hit.CorrelationID + "-spamtrap-" + strconv.Itoa(index+1), CorrelationID: hit.CorrelationID,
			Kind: "spamtrap", Direction: "inbound", EnvelopeSender: hit.EnvelopeSender, Recipient: trap,
			MessageID: headers["Message-Id"], Subject: headers["Subject"]}
		event := messagetrace.Event{Time: now, Stage: "spamtrap", Status: "discarded", Destination: hit.RemoteIP,
			Response: "accepted for a spamtrap and discarded; sender reputation, fuzzy signatures, and a ban strike recorded"}
		if err := s.messageTrace.Record(ctx, record, event); err != nil {
			log.Error("record spamtrap trace", "recipient", trap, "error", err)
		}
	}
}

// arcPolicy builds the SMTP ARC policy for cfg: verification, the trusted
// sealers, and sealing of forwards with the hosted domains' active DKIM
// keys. The sealer list was validated when the configuration was accepted.
func arcPolicy(cfg *config.Config, ts *model.TypedStore) *smtp.ARCPolicy {
	sealers, _ := config.ParseARCTrustedSealers(cfg.ArcTrustedSealers)
	policy := &smtp.ARCPolicy{Verify: cfg.ArcVerify, TrustedSealers: sealers}
	if cfg.ArcSealForwards && ts != nil {
		policy.Sealer = dkim.NewSigner(ts.DomainStore())
	}
	return policy
}
