package queue

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/smtp"
)

func TestGreylistRetryAfter(t *testing.T) {
	for response, want := range map[string]time.Duration{
		"RCPT TO: 451 4.7.1 Recipient address rejected: Greylisted for 5 minutes": 6 * time.Minute,
		"RCPT TO: 450 Greylisting in action, try again in 300 seconds":            6 * time.Minute,
		"RCPT TO: 451 4.7.1 greylisted, please retry later":                       6 * time.Minute,
		"RCPT TO: 450 4.2.0 graylisted for 30s":                                   2 * time.Minute,
		"RCPT TO: 421 4.4.2 too many connections":                                 0,
	} {
		if got := greylistRetryAfter(response); got != want {
			t.Errorf("greylistRetryAfter(%q) = %v, want %v", response, got, want)
		}
	}
}

// TestReplyCodesDecideRetry: a plain "450 …" without an enhanced code, or a
// 4xx from any of several MX targets, is retried; only 5xx everywhere bounces.
func TestReplyCodesDecideRetry(t *testing.T) {
	greylisted := &smtp.ReplyError{Command: "RCPT TO", Code: 450, Text: "450 Greylisted, come back later"}
	refused := &smtp.ReplyError{Command: "RCPT TO", Code: 550, Text: "550 5.1.1 no such user"}
	for name, test := range map[string]struct {
		err  error
		want DeliveryClass
	}{
		"plain 450":      {fmt.Errorf("deliver: %w", greylisted), DeliveryTemporary},
		"5xx then 4xx":   {fmt.Errorf("all delivery targets failed: %w", errors.Join(refused, greylisted)), DeliveryTemporary},
		"5xx everywhere": {fmt.Errorf("all delivery targets failed: %w", errors.Join(refused, refused)), DeliveryPermanent},
	} {
		if got := classifyDeliveryError(test.err).Class; got != test.want {
			t.Errorf("%s: class %v, want %v", name, got, test.want)
		}
	}
}
