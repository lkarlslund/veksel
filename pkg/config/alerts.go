package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
)

// Alert digest modes.
const (
	AlertDigestOff   = "off"
	AlertDigestDaily = "daily"
)

const (
	maxAlertEmailRecipients = 20
	maxAlertNotifyTokenLen  = 1024
	maxAlertMinInterval     = 24 * 60
)

// ParseAlertEmailRecipients validates the administrator addresses that
// receive alert notification mail and returns them as bare addresses.
func ParseAlertEmailRecipients(values []string) ([]string, error) {
	if len(values) > maxAlertEmailRecipients {
		return nil, fmt.Errorf("alert_email_recipients accepts at most %d addresses", maxAlertEmailRecipients)
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		parsed, err := mail.ParseAddress(strings.TrimSpace(value))
		if err != nil || parsed.Name != "" || !strings.Contains(parsed.Address, "@") {
			return nil, fmt.Errorf("alert_email_recipients entry %q is not a plain email address", value)
		}
		address := strings.ToLower(parsed.Address)
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result, nil
}

// validateAlertDelivery checks the alert notification channel settings.
func validateAlertDelivery(cfg *Config) error {
	if _, err := ParseAlertEmailRecipients(cfg.AlertEmailRecipients); err != nil {
		return err
	}
	if raw := strings.TrimSpace(cfg.AlertNotifyURL); raw != "" {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("alert_notify_url must be an absolute http:// or https:// URL")
		}
	}
	if len(cfg.AlertNotifyToken) > maxAlertNotifyTokenLen || strings.ContainsAny(cfg.AlertNotifyToken, "\r\n\t ") {
		return fmt.Errorf("alert_notify_token must be at most %d characters without whitespace", maxAlertNotifyTokenLen)
	}
	if cfg.AlertMinIntervalMinutes < 0 || cfg.AlertMinIntervalMinutes > maxAlertMinInterval {
		return fmt.Errorf("alert_min_interval_minutes must be between 0 and %d", maxAlertMinInterval)
	}
	if cfg.AlertDigest != AlertDigestOff && cfg.AlertDigest != AlertDigestDaily {
		return errors.New("alert_digest must be off or daily")
	}
	return nil
}
