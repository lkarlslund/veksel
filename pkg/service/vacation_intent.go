package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// VacationIntentProcessor turns a durably admitted vacation intent into one
// idempotent derived delivery while maintaining the sender rate limit. A
// Sieve vacation intent carries its response-tracking key and period
// (RFC 5230 :handle and :days, RFC 6131 :seconds); others track the sender
// for 24 hours.
type VacationIntentProcessor struct {
	Prepare   func(context.Context, smtp.DerivedMessage) (*smtp.MailMessage, error)
	GetQueue  func(string) *queue.Message
	Completed func(string) bool
	Enqueue   func(*smtp.MailMessage) error
	Release   func(string) bool
	Reserve   func(context.Context, string, string, time.Duration) (string, bool, error)
	Complete  func(context.Context, string, string, string) error
	Cancel    func(context.Context, string, string, string) error
	Record    func(context.Context, string, string) error
}

func (p VacationIntentProcessor) Process(ctx context.Context, msg *queue.Message) error {
	userID, sender, derivedKind := msg.Attributes["user_id"], msg.Attributes["sender"], msg.Attributes["derived_kind"]
	if userID == "" || sender == "" || derivedKind == "" || len(msg.Content) == 0 {
		return fmt.Errorf("5.3.0 invalid vacation intent")
	}
	if p.Prepare == nil || p.GetQueue == nil || p.Completed == nil || p.Enqueue == nil || p.Release == nil || p.Reserve == nil || p.Complete == nil || p.Cancel == nil || p.Record == nil {
		return &queue.DeliveryError{Class: queue.DeliveryDeferred, EnhancedCode: "4.3.2", Response: "vacation processor starting", RetryAfter: time.Second}
	}
	trackingKey, period := sender, 24*time.Hour
	if key := msg.Attributes[smtp.AttributeVacationKey]; key != "" {
		trackingKey = key
	}
	if value, err := strconv.ParseInt(msg.Attributes[smtp.AttributeVacationPeriod], 10, 64); err == nil && value >= 0 {
		period = time.Duration(value) * time.Second
	}
	derived := smtp.DerivedMessage{Kind: derivedKind, Recipient: sender, FullMessage: msg.Content, ParentID: msg.ParentID, CorrelationID: msg.CorrelationID}
	if msg.Attributes[smtp.AttributeDKIMSign] == "true" {
		derived.DKIM = &dkim.Request{}
	}
	prepared, err := p.Prepare(ctx, derived)
	if err != nil {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation recipient unavailable", Err: err}
	}
	if prepared.Attributes == nil {
		prepared.Attributes = make(map[string]string)
	}
	for _, attribute := range []string{smtp.AttributeRequireTLS, smtp.AttributeTLSOptional} {
		if value := msg.Attributes[attribute]; value != "" {
			prepared.Attributes[attribute] = value
		}
	}
	if p.Completed(prepared.ID) {
		if err := p.Record(ctx, userID, trackingKey); err != nil {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation rate limit repair failed", Err: err}
		}
		return nil
	}
	if p.GetQueue(prepared.ID) != nil {
		if err := p.Record(ctx, userID, trackingKey); err != nil {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation rate limit repair failed", Err: err}
		}
		if !p.Release(prepared.ID) {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation release failed"}
		}
		return nil
	}
	token, allowed, err := p.Reserve(ctx, userID, trackingKey, period)
	if err != nil {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation rate limit unavailable", Err: err}
	}
	if !allowed {
		return nil
	}
	prepared.Held = true
	if err := p.Enqueue(prepared); err != nil && !errors.Is(err, queue.ErrDuplicate) {
		_ = p.Cancel(ctx, userID, trackingKey, token)
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation queue unavailable", Err: err}
	}
	if err := p.Complete(ctx, userID, trackingKey, token); err != nil {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation rate limit completion failed", Err: err}
	}
	if !p.Release(prepared.ID) {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "vacation release failed"}
	}
	return nil
}
