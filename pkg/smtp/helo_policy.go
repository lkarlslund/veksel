package smtp

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// HeloPolicyMode controls how HELO/EHLO violations are handled.
type HeloPolicyMode string

const (
	HeloPolicyOff    HeloPolicyMode = "off"
	HeloPolicyWarn   HeloPolicyMode = "warn"
	HeloPolicyReject HeloPolicyMode = "reject"
)

// HeloPolicy holds configurable rules for HELO/EHLO validation.
type HeloPolicy struct {
	// Mode controls the enforcement level: off, warn, or reject.
	Mode HeloPolicyMode

	// RequireHelo rejects connections that never send HELO/EHLO.
	RequireHelo bool

	// CheckRdns performs reverse DNS lookups on the client IP and
	// verifies that the HELO hostname matches the PTR record.
	CheckRdns bool

	// MinDomainParts is the minimum number of dot-separated parts
	// required in the HELO hostname. A value of 2 rejects single-part
	// hostnames like "client" and requires at least "client.example.com".
	MinDomainParts int
}

// HeloResult captures the outcome of HELO policy evaluation.
type HeloResult struct {
	// Pass indicates whether the HELO hostname passes all checks.
	Pass bool

	// Warnings lists non-fatal issues found during validation.
	Warnings []string

	// RejectionCode is the SMTP response code when the policy rejects.
	RejectionCode int

	// RejectionText is the human-readable rejection reason.
	RejectionText string

	// HeaderValue is the value for the X-HELO-Status header.
	HeaderValue string

	// ReverseDNS is the client's PTR name found by the rDNS check, empty when
	// the check did not run or found none. The Received field reuses it, so
	// tracing never costs another lookup.
	ReverseDNS string
}

// Evaluate runs the HELO policy checks against the provided hostname and client IP.
// Returns a HeloResult describing the outcome.
func (p *HeloPolicy) Evaluate(heloHostname, clientIP string) *HeloResult {
	result := &HeloResult{Pass: true}
	var warnings []string

	if p.Mode == HeloPolicyOff {
		result.HeaderValue = "skipped"
		return result
	}

	// --- HELO hostname validation ---
	if validationErr := validateHeloHostname(heloHostname, p.MinDomainParts); validationErr != nil {
		warnings = append(warnings, validationErr.Error())
	}

	// --- Reverse DNS check ---
	if p.CheckRdns && heloHostname != "" && clientIP != "" {
		ptr, rdnsErr := checkReverseDNS(heloHostname, clientIP)
		result.ReverseDNS = ptr
		if rdnsErr != nil {
			warnings = append(warnings, rdnsErr.Error())
		}
	}

	result.Warnings = warnings

	if len(warnings) > 0 {
		result.Pass = false
		result.RejectionCode = 504
		result.RejectionText = strings.Join(warnings, "; ")

		if p.Mode == HeloPolicyWarn {
			result.HeaderValue = "warning:" + strings.Join(warnings, "; ")
		} else {
			result.HeaderValue = "rejected"
		}
	} else {
		result.HeaderValue = "pass"
	}

	return result
}

// validateHeloHostname checks the HELO hostname against RFC 5321 rules and
// additional anti-spam heuristics.
//
// Rejects:
//   - Empty hostname
//   - IP addresses (both IPv4 and IPv6)
//   - "localhost" or "localhost.domain"
//   - Single-part hostnames (when minDomainParts >= 2)
func validateHeloHostname(hostname string, minDomainParts int) error {
	hostname = strings.TrimSpace(hostname)

	// Empty hostname is not allowed (RFC 5321 §4.1.4)
	if hostname == "" {
		return fmt.Errorf("empty HELO hostname")
	}

	lower := strings.ToLower(hostname)

	// IP addresses are not allowed as HELO hostname (RFC 5321 §4.1.4)
	if isIPAddress(hostname) {
		return fmt.Errorf("HELO hostname must not be an IP address")
	}

	// Reject localhost variants
	if lower == "localhost" ||
		strings.HasPrefix(lower, "localhost.") ||
		strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("HELO hostname must not be localhost")
	}

	// Check minimum domain parts (e.g., require "example.com" not just "example")
	if minDomainParts > 0 {
		parts := strings.Split(hostname, ".")
		if len(parts) < minDomainParts {
			return fmt.Errorf("HELO hostname must have at least %d domain parts, got %d", minDomainParts, len(parts))
		}
	}

	return nil
}

// isIPAddress returns true if s looks like an IP address (IPv4 or IPv6).
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// checkReverseDNS performs a reverse DNS lookup on the client IP and verifies
// that the PTR record matches the HELO hostname. It returns the PTR name
// whenever one was found, even when it does not match.
//
// The check is case-insensitive and allows the HELO hostname to match the
// PTR record exactly or be a subdomain of the PTR record.
func checkReverseDNS(heloHostname, clientIP string) (string, error) {
	// Perform reverse DNS (PTR) lookup
	names, err := net.DefaultResolver.LookupAddr(context.Background(), clientIP)
	if err != nil {
		return "", fmt.Errorf("rDNS lookup failed for %s: %w", clientIP, err)
	}

	if len(names) == 0 {
		return "", fmt.Errorf("no PTR record for %s", clientIP)
	}

	// PTR records come with a trailing dot; strip it for comparison
	ptrName := strings.TrimSuffix(strings.ToLower(names[0]), ".")
	heloLower := strings.ToLower(heloHostname)

	// Exact match or the HELO hostname is a subdomain of the PTR record
	if heloLower == ptrName || strings.HasSuffix(heloLower, "."+ptrName) {
		return ptrName, nil
	}

	return ptrName, fmt.Errorf("HELO hostname %q does not match rDNS %q", heloHostname, ptrName)
}

// heloStatusHeader returns the X-HELO-Status header value for a given result.
func heloStatusHeader(result *HeloResult) string {
	return result.HeaderValue
}

// DefaultHeloPolicy returns the default HELO policy configuration.
func DefaultHeloPolicy() *HeloPolicy {
	return &HeloPolicy{
		Mode:           HeloPolicyWarn,
		RequireHelo:    true,
		CheckRdns:      true,
		MinDomainParts: 2,
	}
}
