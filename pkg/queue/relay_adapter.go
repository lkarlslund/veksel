package queue

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
)

// RelayAdapter bridges the queue DeliveryFunc to an SMTP RelayClient.
// It delivers queued messages to external domains via SMTP relay.
type RelayAdapter struct {
	relay *smtp.RelayClient
}

// NewRelayAdapter creates a queue adapter that delivers via SMTP relay.
func NewRelayAdapter(relay *smtp.RelayClient) *RelayAdapter {
	return &RelayAdapter{relay: relay}
}

// Deliver implements queue.DeliveryFunc.
// It sends the queued message via the SMTP relay client.
func (a *RelayAdapter) Deliver(ctx context.Context, msg *Message) error {
	if a.relay == nil {
		return fmt.Errorf("relay client not configured")
	}

	logger.Info("relay: delivering message",
		"id", msg.ID,
		"sender", msg.EnvelopeSender,
		"recipient", msg.Recipient,
		"attempt", msg.RetryCount)

	ctx = tlsrpt.WithAttemptID(ctx, msg.AttemptID)
	if msg.Attributes["tlsrpt_suppress"] == "true" {
		ctx = tlsrpt.Suppress(ctx)
	}
	err := a.relay.DeliverMessage(ctx, msg.EnvelopeSender, msg.Recipient, msg.RawMessage(), smtp.DSNEnvelopeOptions{
		Return:            msg.Attributes["dsn_return"],
		EnvelopeID:        msg.Attributes["dsn_envelope_id"],
		Notify:            msg.Attributes["dsn_notify"],
		OriginalRecipient: msg.Attributes["dsn_original_recipient"],
		RequireTLS:        msg.Attributes[smtp.AttributeRequireTLS] == "true",
		TLSOptional:       msg.Attributes[smtp.AttributeTLSOptional] == "true",
	})
	if err != nil {
		class, code := DeliveryTemporary, "4.4.2"
		text := err.Error()
		if smtp.IsDeliveryUncertain(err) {
			class = DeliveryUncertain
		}
		if smtpCode := responseClass(text); smtpCode != "" {
			code = smtpCode
			if strings.HasPrefix(smtpCode, "5") {
				class = DeliveryPermanent
			} else {
				class = DeliveryTemporary
			}
		}
		// Reply codes from the next hops decide over the first code-like
		// word in the text: any 4xx (one MX greylisting while another
		// refused) is retried.
		if temporary, permanent := smtpReplyClasses(err); temporary {
			class = DeliveryTemporary
			if !strings.HasPrefix(code, "4") {
				code = "4.0.0"
			}
		} else if permanent && class != DeliveryUncertain {
			class = DeliveryPermanent
		}
		delivery := &DeliveryError{Class: class, EnhancedCode: code, Response: text, Err: fmt.Errorf("relay deliver: %w", err)}
		if class == DeliveryTemporary {
			delivery.RetryAfter = greylistRetryAfter(text)
		}
		return delivery
	}

	logger.Info("relay: message delivered",
		"id", msg.ID,
		"recipient", msg.Recipient)
	return nil
}

func responseClass(message string) string {
	for _, field := range strings.Fields(message) {
		field = strings.Trim(field, "[]():,;")
		if len(field) >= 5 && (field[0] == '4' || field[0] == '5') && field[1] == '.' && field[3] == '.' {
			return field[:5]
		}
		if len(field) >= 3 && (field[0] == '4' || field[0] == '5') && field[1] >= '0' && field[1] <= '9' && field[2] >= '0' && field[2] <= '9' {
			return string(field[0]) + ".0.0"
		}
	}
	return ""
}

var (
	greylistPattern = regexp.MustCompile(`(?i)grey ?list|gray ?list|try again later|please retry later`)
	waitPattern     = regexp.MustCompile(`(?i)(\d{1,5})\s*(seconds?|secs?|s\b|minutes?|mins?|m\b|hours?|h\b)`)
)

// greylistRetryAfter schedules the retry after a greylisting deferral for
// when the receiver will accept it: the period it states ("Greylisted for
// 5 minutes", "try again in 300 seconds") plus a minute, or six minutes
// when it states none. Retrying earlier only repeats the deferral, and
// some greylisters restart their timer on early retries. Zero means the
// response is not greylisting and the queue's backoff applies.
func greylistRetryAfter(response string) time.Duration {
	if !greylistPattern.MatchString(response) {
		return 0
	}
	wait := 5 * time.Minute
	if match := waitPattern.FindStringSubmatch(response); match != nil {
		amount, _ := strconv.Atoi(match[1])
		switch unit := strings.ToLower(match[2]); {
		case strings.HasPrefix(unit, "h"):
			wait = time.Duration(amount) * time.Hour
		case strings.HasPrefix(unit, "m"):
			wait = time.Duration(amount) * time.Minute
		default:
			wait = time.Duration(amount) * time.Second
		}
	}
	wait += time.Minute
	return min(max(wait, 2*time.Minute), 2*time.Hour)
}
