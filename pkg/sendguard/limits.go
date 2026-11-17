package sendguard

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Limit names used in settings, overrides, and rejection reasons.
const (
	LimitMessagesPerHour   = "messages_per_hour"
	LimitRecipientsPerHour = "recipients_per_hour"
	LimitRecipientsPerDay  = "recipients_per_day"
)

// MaxLimit bounds one configured limit value.
const MaxLimit = 10_000_000

// Limits are outbound sending limits for one account. Zero means unlimited.
type Limits struct {
	MessagesPerHour   int `json:"messages_per_hour"`
	RecipientsPerHour int `json:"recipients_per_hour"`
	RecipientsPerDay  int `json:"recipients_per_day"`
}

// DefaultLimits are generous enough for interactive users and small
// newsletters while stopping a hijacked account from sending bulk spam.
func DefaultLimits() Limits {
	return Limits{MessagesPerHour: 500, RecipientsPerHour: 2000, RecipientsPerDay: 10000}
}

// ParseLimits reads outbound_rate_limits entries in name=value form. A limit
// that is not listed, or is zero, is unlimited.
func ParseLimits(entries []string) (Limits, error) {
	var limits Limits
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name, value, found := strings.Cut(strings.TrimSpace(entry), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !found || name == "" {
			return Limits{}, fmt.Errorf("outbound rate limit %q must use name=value form", entry)
		}
		if seen[name] {
			return Limits{}, fmt.Errorf("outbound rate limit %s is listed twice", name)
		}
		seen[name] = true
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || number < 0 || number > MaxLimit {
			return Limits{}, fmt.Errorf("outbound rate limit %s must be an integer between 0 and %d", name, MaxLimit)
		}
		switch name {
		case LimitMessagesPerHour:
			limits.MessagesPerHour = number
		case LimitRecipientsPerHour:
			limits.RecipientsPerHour = number
		case LimitRecipientsPerDay:
			limits.RecipientsPerDay = number
		default:
			return Limits{}, fmt.Errorf("unknown outbound rate limit %q; use %s, %s, or %s", name, LimitMessagesPerHour, LimitRecipientsPerHour, LimitRecipientsPerDay)
		}
	}
	return limits, nil
}

// Entries renders limits in the outbound_rate_limits setting form.
func (l Limits) Entries() []string {
	return []string{
		LimitMessagesPerHour + "=" + strconv.Itoa(l.MessagesPerHour),
		LimitRecipientsPerHour + "=" + strconv.Itoa(l.RecipientsPerHour),
		LimitRecipientsPerDay + "=" + strconv.Itoa(l.RecipientsPerDay),
	}
}

// Override applies an account's overrides to l; nil fields keep l's value.
func (l Limits) Override(override *model.SendLimits) Limits {
	if override == nil {
		return l
	}
	if override.MessagesPerHour != nil {
		l.MessagesPerHour = *override.MessagesPerHour
	}
	if override.RecipientsPerHour != nil {
		l.RecipientsPerHour = *override.RecipientsPerHour
	}
	if override.RecipientsPerDay != nil {
		l.RecipientsPerDay = *override.RecipientsPerDay
	}
	return l
}

// ValidateOverride rejects negative or oversized per-account overrides.
func ValidateOverride(override *model.SendLimits) error {
	if override == nil {
		return nil
	}
	for _, value := range []*int{override.MessagesPerHour, override.RecipientsPerHour, override.RecipientsPerDay} {
		if value != nil && (*value < 0 || *value > MaxLimit) {
			return fmt.Errorf("sending limits must be between 0 and %d", MaxLimit)
		}
	}
	return nil
}

// QuotaError rejects a submission that would exceed a sending limit. It is
// temporary: SMTP answers 451 4.7.0 and HTTP APIs answer 429.
type QuotaError struct {
	Limit      string
	Max        int
	RetryAfter time.Duration
}

func (e *QuotaError) Error() string {
	what := map[string]string{
		LimitMessagesPerHour:   "messages per hour",
		LimitRecipientsPerHour: "recipients per hour",
		LimitRecipientsPerDay:  "recipients per day",
	}[e.Limit]
	wait := max(e.RetryAfter.Round(time.Minute), time.Minute)
	return fmt.Sprintf("sending limit reached: at most %d %s; try again in %s", e.Max, what, formatWait(wait))
}

// TemporaryRejection implements smtp.TemporaryRejection.
func (e *QuotaError) TemporaryRejection() (string, string) { return "4.7.0", e.Error() }

// IsQuota reports whether err is a sending limit rejection.
func IsQuota(err error) bool {
	var quota *QuotaError
	return errors.As(err, &quota)
}

func formatWait(wait time.Duration) string {
	if wait >= time.Hour {
		hours := int(wait / time.Hour)
		minutes := int(wait % time.Hour / time.Minute)
		if minutes == 0 {
			return fmt.Sprintf("%d h", hours)
		}
		return fmt.Sprintf("%d h %d min", hours, minutes)
	}
	return fmt.Sprintf("%d min", int(wait/time.Minute))
}
