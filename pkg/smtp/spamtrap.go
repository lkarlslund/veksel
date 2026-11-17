package smtp

import (
	"context"
	"slices"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// SpamtrapHit is an accepted transaction that addressed spamtraps. The
// message is never delivered to the traps; it is evidence against its
// sender.
type SpamtrapHit struct {
	CorrelationID  string
	RemoteIP       string
	EnvelopeSender string
	// Traps are the spamtrap recipients.
	Traps []string
	// Mixed reports that real recipients received copies marked
	// SPAMTRAP_HIT.
	Mixed bool
	// Headers are the transaction headers after scoring, including the
	// sender's reputation keys.
	Headers map[string]string
	// Message is the message as accepted.
	Message []byte
}

// isSpamtrap reports whether an unauthenticated transaction's recipient is
// a spamtrap.
func (s *Session) isSpamtrap(addr string) (bool, error) {
	if s.authenticated || s.cfg.Delivery == nil || s.cfg.Delivery.IsSpamtrap == nil {
		return false, nil
	}
	return s.cfg.Delivery.IsSpamtrap(s.ctx, addr)
}

// spamtrapRecipient reports whether the accepted recipient addr is a trap.
func (s *Session) spamtrapRecipient(addr string) bool {
	_, trap := s.spamtraps[addr]
	return trap
}

// onlySpamtraps reports whether every recipient of the transaction is a
// spamtrap. Such a transaction is accepted whatever its score, so the
// sender learns nothing and the trap collects the whole message.
func (s *Session) onlySpamtraps() bool {
	return len(s.spamtraps) > 0 && !slices.ContainsFunc(s.recipients, func(addr string) bool { return !s.spamtrapRecipient(addr) })
}

// markSpamtrapHit adds SPAMTRAP_HIT to the transaction score when the
// transaction addressed spamtraps besides real recipients, so their copies
// are judged with that evidence. It runs after the transaction-level spam
// actions: the symbol files copies as Junk rather than rejecting a
// transaction a trap must see accepted.
func (s *Session) markSpamtrapHit() {
	if len(s.spamtraps) == 0 || s.onlySpamtraps() {
		return
	}
	symbol, ok := spam.Symbol{}, false
	if engine, isEngine := s.cfg.Spam.(interface {
		BuiltinSymbol(string, ...string) (spam.Symbol, bool)
	}); isEngine {
		symbol, ok = engine.BuiltinSymbol(spam.SymbolSpamtrapHit)
	}
	if !ok {
		symbol, _ = spam.DefaultSymbol(spam.SymbolSpamtrapHit)
	}
	result := spam.Result{Thresholds: spam.DefaultThresholds()}
	if s.spamResult != nil {
		result = *s.spamResult
	}
	result = result.WithSymbol(symbol)
	s.spamResult = &result
}

// spamtrapAction returns the post-commit action that reports the
// transaction's spamtrap hit: the sender's IP gets a ban strike and the
// message trains reputation and fuzzy signatures. ok is false when the
// transaction addressed no trap.
func (s *Session) spamtrapAction(headers map[string]string, body []byte) (action func(), ok bool) {
	if len(s.spamtraps) == 0 {
		return nil, false
	}
	hit := SpamtrapHit{CorrelationID: s.deliveryCorrelationID, RemoteIP: extractRemoteIP(s.conn), EnvelopeSender: s.envelopeSender,
		Mixed: !s.onlySpamtraps(), Headers: cloneSMTPHeaders(headers), Message: s.composeMessage(headers, body)}
	for _, addr := range s.recipients {
		if s.spamtrapRecipient(addr) {
			hit.Traps = append(hit.Traps, addr)
		}
	}
	record := s.cfg.Delivery.RecordSpamtrap
	logger.Info("smtp: spamtrap hit", "session", s.id, "ip", hit.RemoteIP, "sender", hit.EnvelopeSender, "traps", len(hit.Traps), "mixed", hit.Mixed)
	return func() {
		s.reportAbuse(ban.TriggerSpamtrap)
		if record != nil {
			record(context.Background(), hit)
		}
	}, true
}
