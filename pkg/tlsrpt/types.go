// Package tlsrpt aggregates and delivers SMTP TLS reports defined by RFC 8460.
package tlsrpt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/mtasts"
)

const (
	PolicyTypeSTS           = "sts"
	PolicyTypeTLSA          = "tlsa"
	PolicyTypeNoPolicyFound = "no-policy-found"

	ResultSTARTTLSNotSupported    = "starttls-not-supported"
	ResultCertificateHostMismatch = "certificate-host-mismatch"
	ResultCertificateExpired      = "certificate-expired"
	ResultCertificateNotTrusted   = "certificate-not-trusted"
	ResultValidationFailure       = "validation-failure"
	ResultSTSPolicyFetchError     = "sts-policy-fetch-error"
	ResultSTSPolicyInvalid        = "sts-policy-invalid"
	ResultSTSWebPKIInvalid        = "sts-webpki-invalid"
	ResultTLSAInvalid             = "tlsa-invalid"
	ResultDNSSECInvalid           = "dnssec-invalid"
	ResultDANERequired            = "dane-required"
)

const (
	maxPolicyStrings = 32
	maxStringLength  = 512
	maxReasonLength  = 256
)

// AppliedPolicy is the privacy-safe policy material included in an aggregate
// report. It never contains an envelope address or message identifier.
type AppliedPolicy struct {
	Type    string   `json:"policy-type"`
	Strings []string `json:"policy-string,omitempty"`
	Domain  string   `json:"policy-domain"`
	MX      []string `json:"mx-host,omitempty"`
}

// Event describes one TLS policy outcome. AttemptID is used only to build a
// one-way durable deduplication key and is never included in reports.
type Event struct {
	AttemptID         string
	Time              time.Time
	Policy            AppliedPolicy
	ReceivingMX       string
	ReceivingMXHELO   string
	SendingMTAIP      string
	ReceivingIP       string
	Success           bool
	ResultType        string
	FailureReasonCode string
}

// FailureDetail is one bounded aggregate failure bucket.
type FailureDetail struct {
	ResultType          string `json:"result-type"`
	SendingMTAIP        string `json:"sending-mta-ip,omitempty"`
	ReceivingMXHostname string `json:"receiving-mx-hostname,omitempty"`
	ReceivingMXHELO     string `json:"receiving-mx-helo,omitempty"`
	ReceivingIP         string `json:"receiving-ip,omitempty"`
	FailedSessionCount  int64  `json:"failed-session-count"`
	FailureReasonCode   string `json:"failure-reason-code,omitempty"`
}

// Aggregate is the durable daily projection for one applied policy.
type Aggregate struct {
	ID                  string          `json:"id"`
	Day                 string          `json:"day"`
	Policy              AppliedPolicy   `json:"policy"`
	SuccessfulSessions  int64           `json:"successful_sessions"`
	FailedSessions      int64           `json:"failed_sessions"`
	Failures            []FailureDetail `json:"failures,omitempty"`
	FailureKindsDropped int64           `json:"failure_kinds_dropped,omitempty"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

type suppressKey struct{}
type attemptKey struct{}

// Suppress marks internally generated TLS reports so their own delivery does
// not recursively contribute to the next report.
func Suppress(ctx context.Context) context.Context {
	return context.WithValue(ctx, suppressKey{}, true)
}

// IsSuppressed reports whether TLS outcome recording is disabled for ctx.
func IsSuppressed(ctx context.Context) bool {
	suppressed, _ := ctx.Value(suppressKey{}).(bool)
	return suppressed
}

// WithAttemptID attaches a durable queue-attempt identity for deduplication.
// The identity is hashed before persistence and never appears in a report.
func WithAttemptID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, attemptKey{}, id)
}

// AttemptID returns the delivery attempt identity attached to ctx.
func AttemptID(ctx context.Context) string {
	id, _ := ctx.Value(attemptKey{}).(string)
	return id
}

func normalizeEvent(event Event, now time.Time) (Event, error) {
	if event.Time.IsZero() {
		event.Time = now.UTC()
	} else {
		event.Time = event.Time.UTC()
	}
	domain, err := mtasts.CanonicalDomain(event.Policy.Domain)
	if err != nil {
		return Event{}, errors.New("TLS report policy domain is invalid")
	}
	event.Policy.Domain = domain
	if event.Policy.Type == "" {
		event.Policy.Type = PolicyTypeNoPolicyFound
	}
	if event.Policy.Type != PolicyTypeSTS && event.Policy.Type != PolicyTypeTLSA && event.Policy.Type != PolicyTypeNoPolicyFound {
		return Event{}, errors.New("TLS report policy type is unsupported")
	}
	event.Policy.Strings = boundedStrings(event.Policy.Strings, maxPolicyStrings, maxStringLength)
	event.Policy.MX = boundedStrings(event.Policy.MX, maxPolicyStrings, maxStringLength)
	event.ReceivingMX = boundedDomain(event.ReceivingMX)
	event.ReceivingMXHELO = boundedDomain(event.ReceivingMXHELO)
	event.SendingMTAIP = canonicalIP(event.SendingMTAIP)
	event.ReceivingIP = canonicalIP(event.ReceivingIP)
	event.FailureReasonCode = bound(strings.TrimSpace(event.FailureReasonCode), maxReasonLength)
	if event.Success {
		event.ResultType = ""
	} else if !validResultType(event.ResultType) {
		event.ResultType = ResultValidationFailure
	}
	event.AttemptID = bound(strings.TrimSpace(event.AttemptID), maxStringLength)
	return event, nil
}

func policyID(policy AppliedPolicy) string {
	digest := sha256.New()
	digest.Write([]byte(policy.Type))
	digest.Write([]byte{0})
	digest.Write([]byte(policy.Domain))
	for _, value := range policy.Strings {
		digest.Write([]byte{0})
		digest.Write([]byte(value))
	}
	for _, value := range policy.MX {
		digest.Write([]byte{0})
		digest.Write([]byte(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func validResultType(value string) bool {
	switch value {
	case ResultSTARTTLSNotSupported, ResultCertificateHostMismatch, ResultCertificateExpired,
		ResultCertificateNotTrusted, ResultValidationFailure, ResultSTSPolicyFetchError,
		ResultSTSPolicyInvalid, ResultSTSWebPKIInvalid, ResultTLSAInvalid, ResultDNSSECInvalid, ResultDANERequired:
		return true
	default:
		return false
	}
}

func boundedStrings(values []string, maximum, length int) []string {
	if len(values) > maximum {
		values = values[:maximum]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = bound(strings.TrimSpace(value), length)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func boundedDomain(value string) string {
	if value == "" {
		return ""
	}
	canonical, err := mtasts.CanonicalDomain(value)
	if err != nil {
		return ""
	}
	return canonical
}

func canonicalIP(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func bound(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) > maximum {
		runes = runes[:maximum]
	}
	return string(runes)
}
