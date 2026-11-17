package main

import (
	"context"

	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// outboundProtectionKeys are the live settings of the outbound send guard.
var outboundProtectionKeys = []string{"outbound_rate_limits", "outbound_compromise_threshold", "outbound_hold_enabled"}

// buildSendGuard creates the outbound send guard that screens every
// locally originated queue batch. Successful protocol and browser logins,
// outbound content scores, and queue delivery outcomes feed its compromise
// heuristics; a hold notifies the account owner by mail.
func (s *server) buildSendGuard() error {
	guardConfig, err := s.cfg.OutboundProtection()
	if err != nil {
		return startupError("configure outbound protection", err)
	}
	s.sendGuard, err = sendguard.New(s.ctx, s.ts, guardConfig)
	if err != nil {
		return startupError("initialize outbound protection", err)
	}
	// Graceful shutdown waits for asynchronous holds before the queue closes.
	s.cleanup.pushAbort(s.sendGuard.Wait)
	s.sendGuard.SetContentScorer(s.scoreOutboundContent)
	s.sendGuard.SetHoldNotifier(func(ctx context.Context, account string, hold model.OutboundHold) {
		recipient, err := s.digestRecipient(ctx, account)
		if err == nil {
			err = s.sendNotificationMail(ctx, "outbound-hold", recipient, alertnotify.OutboundHoldMessage(account, hold))
		}
		if err != nil {
			log.Warn("notify account of outbound hold", "account", account, "error", err)
		}
	})
	if s.protocolAuth != nil {
		s.protocolAuth.SetLoginObserver(s.sendGuard.RecordLogin)
	}
	if s.appHandler != nil {
		s.appHandler.ConfigureSendGuard(s.sendGuard)
	}
	return nil
}

// scoreOutboundContent scores a submitted message with the spam engine's
// content rules; authentication and blocklist rules do not apply to mail
// this server originates.
func (s *server) scoreOutboundContent(ctx context.Context, message *queue.Message) (float64, bool) {
	thresholds, enabled := s.delivery.spam.Thresholds()
	if !enabled || thresholds.Junk <= 0 {
		return 0, false
	}
	result, ok := s.delivery.spam.CheckOutbound(ctx, spam.Message{
		Content: message.RawMessage(), Headers: message.Headers, EnvelopeFrom: message.EnvelopeSender, Authenticated: true,
	})
	return result.Score, ok && result.Score >= thresholds.Junk
}

// applyOutboundProtection applies the outbound protection settings live.
func (s *server) applyOutboundProtection(cfg *config.Config) error {
	guardConfig, err := cfg.OutboundProtection()
	if err != nil {
		return err
	}
	return s.sendGuard.SetConfig(guardConfig)
}
