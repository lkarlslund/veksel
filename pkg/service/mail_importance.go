package service

import (
	"errors"
	"strconv"
	"strings"
)

// MailImportance is the user-visible urgency hint carried by conventional
// Internet message headers and mail protocols. It does not affect queue order.
type MailImportance string

const (
	MailImportanceLow    MailImportance = "low"
	MailImportanceNormal MailImportance = "normal"
	MailImportanceHigh   MailImportance = "high"
)

// NormalizeMailImportance validates a submission value. An omitted value is
// normal so older API clients retain their existing behavior.
func NormalizeMailImportance(value MailImportance) (MailImportance, error) {
	switch MailImportance(strings.ToLower(strings.TrimSpace(string(value)))) {
	case "", MailImportanceNormal:
		return MailImportanceNormal, nil
	case MailImportanceLow:
		return MailImportanceLow, nil
	case MailImportanceHigh:
		return MailImportanceHigh, nil
	default:
		return "", errors.New("importance must be low, normal, or high")
	}
}

// MessageImportance projects the de-facto Importance, X-Priority, and Priority
// headers into one value. Earlier, more explicit headers win; malformed values
// are ignored so an imported message remains readable.
func MessageImportance(headers map[string]string) MailImportance {
	if value, found := headerValue(headers, "Importance"); found {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "high":
			return MailImportanceHigh
		case "normal":
			return MailImportanceNormal
		case "low":
			return MailImportanceLow
		}
	}
	if value, found := headerValue(headers, "X-Priority"); found {
		fields := strings.Fields(value)
		if len(fields) > 0 {
			if priority, err := strconv.Atoi(strings.TrimRight(fields[0], ";")); err == nil {
				switch priority {
				case 1, 2:
					return MailImportanceHigh
				case 3:
					return MailImportanceNormal
				case 4, 5:
					return MailImportanceLow
				}
			}
		}
	}
	if value, found := headerValue(headers, "Priority"); found {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "urgent":
			return MailImportanceHigh
		case "normal":
			return MailImportanceNormal
		case "non-urgent":
			return MailImportanceLow
		}
	}
	return MailImportanceNormal
}

// SetMailImportanceHeaders replaces all supported importance headers. Normal
// is represented by their absence, which avoids adding noise to ordinary mail.
func SetMailImportanceHeaders(headers map[string]string, value MailImportance) {
	for key := range headers {
		if strings.EqualFold(key, "Importance") || strings.EqualFold(key, "X-Priority") || strings.EqualFold(key, "Priority") {
			delete(headers, key)
		}
	}
	switch value {
	case MailImportanceHigh:
		headers["Importance"] = "high"
		headers["X-Priority"] = "1"
		headers["Priority"] = "urgent"
	case MailImportanceLow:
		headers["Importance"] = "low"
		headers["X-Priority"] = "5"
		headers["Priority"] = "non-urgent"
	}
}

func headerValue(headers map[string]string, wanted string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, wanted) {
			return value, true
		}
	}
	return "", false
}
