package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Ban threshold and duration bounds.
const (
	maxBanThresholdCount = 10000
	minBanWindow         = 10 * time.Second
	maxBanWindow         = 24 * time.Hour
	minBanDuration       = time.Minute
	maxBanDuration       = 3650 * 24 * time.Hour
	maxBanDurationSteps  = 10
)

// BanThreshold is a parsed "count/window" abuse trigger such as "20/10m": a
// client address reaching Count strikes within Window is banned. A zero Count
// disables the trigger.
type BanThreshold struct {
	Count  int
	Window time.Duration
}

// ParseBanThreshold parses the "count/window" value of the setting key. The
// window accepts Go durations plus whole days ("1d") and weeks ("1w"); "0"
// alone disables the trigger.
func ParseBanThreshold(key, value string) (BanThreshold, error) {
	value = strings.TrimSpace(value)
	if value == "0" || value == "off" {
		return BanThreshold{}, nil
	}
	countText, windowText, ok := strings.Cut(value, "/")
	if !ok {
		return BanThreshold{}, fmt.Errorf("%s must be count/window, for example 20/10m", key)
	}
	count, err := strconv.Atoi(strings.TrimSpace(countText))
	if err != nil || count < 0 || count > maxBanThresholdCount {
		return BanThreshold{}, fmt.Errorf("%s count must be 0-%d", key, maxBanThresholdCount)
	}
	window, err := ParseBanDuration(windowText)
	if err != nil || window < minBanWindow || window > maxBanWindow {
		return BanThreshold{}, fmt.Errorf("%s window must be a duration from 10s to 24h", key)
	}
	if count == 0 {
		return BanThreshold{}, nil
	}
	return BanThreshold{Count: count, Window: window}, nil
}

// ParseBanDuration parses a Go duration or a whole number of days ("7d") or
// weeks ("1w").
func ParseBanDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if number, ok := strings.CutSuffix(value, suffix); ok {
			n, err := strconv.Atoi(number)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("invalid duration %q", value)
			}
			return time.Duration(n) * unit, nil
		}
	}
	return time.ParseDuration(value)
}

// ParseBanDurations parses ban_durations: the escalating ban lengths for a
// client's first, second, and later offenses. Lengths must not decrease.
func ParseBanDurations(values []string) ([]time.Duration, error) {
	if len(values) == 0 || len(values) > maxBanDurationSteps {
		return nil, fmt.Errorf("ban_durations must list 1-%d durations", maxBanDurationSteps)
	}
	durations := make([]time.Duration, 0, len(values))
	for _, value := range values {
		duration, err := ParseBanDuration(value)
		if err != nil || duration < minBanDuration || duration > maxBanDuration {
			return nil, fmt.Errorf("ban_durations: %q must be a duration from 1m to 3650d", value)
		}
		if len(durations) > 0 && duration < durations[len(durations)-1] {
			return nil, errors.New("ban_durations must not decrease")
		}
		durations = append(durations, duration)
	}
	return durations, nil
}

// validateBans checks the abuse ban settings.
func validateBans(cfg *Config) error {
	for key, value := range map[string]string{
		"ban_auth_failures": cfg.BanAuthFailures, "ban_second_factor_failures": cfg.BanSecondFactorFailures,
		"ban_rcpt_unknown": cfg.BanRcptUnknown, "ban_protocol_errors": cfg.BanProtocolErrors,
		"ban_spamtrap_hits": cfg.BanSpamtrapHits,
	} {
		if _, err := ParseBanThreshold(key, value); err != nil {
			return err
		}
	}
	if _, err := ParseBanDurations(cfg.BanDurations); err != nil {
		return err
	}
	if cfg.BanIPv6Prefix < 32 || cfg.BanIPv6Prefix > 128 {
		return errors.New("ban_ipv6_prefix must be between 32 and 128")
	}
	return nil
}
