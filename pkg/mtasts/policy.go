// Package mtasts discovers, caches, and evaluates SMTP MTA Strict Transport
// Security policies as defined by RFC 8461.
package mtasts

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const (
	ModeEnforce = "enforce"
	ModeTesting = "testing"
	ModeNone    = "none"

	maxPolicyAgeSeconds = 31_557_600
	maxPolicyBytes      = 64 * 1024
)

// Policy is one validated MTA-STS policy document. Discovery metadata is
// attached by Service before a policy is persisted or returned.
type Policy struct {
	Version      string   `json:"version"`
	Mode         string   `json:"mode"`
	MX           []string `json:"mx,omitempty"`
	MaxAge       int64    `json:"max_age"`
	PolicyDomain string   `json:"policy_domain,omitempty"`
	PolicyID     string   `json:"policy_id,omitempty"`
}

// ParsePolicy parses and validates an RFC 8461 policy body. Unknown fields
// are accepted and ignored, and the first value wins for fields other than mx.
func ParsePolicy(body []byte) (Policy, error) {
	if len(body) > maxPolicyBytes {
		return Policy{}, fmt.Errorf("policy exceeds %d bytes", maxPolicyBytes)
	}
	if !utf8.Valid(body) {
		return Policy{}, errors.New("policy is not valid UTF-8")
	}
	text := string(body)
	if strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\r") {
		return Policy{}, errors.New("policy contains a bare carriage return")
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	var policy Policy
	seen := make(map[string]bool)
	for lineNumber, line := range lines {
		if line == "" && lineNumber == len(lines)-1 {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return Policy{}, fmt.Errorf("policy line %d is not a field", lineNumber+1)
		}
		name := line[:colon]
		value := strings.TrimLeft(line[colon+1:], " \t")
		if !validFieldName(name) || value == "" || value != strings.TrimRight(value, " \t") || !validFieldValue(value) {
			return Policy{}, fmt.Errorf("policy line %d is invalid", lineNumber+1)
		}
		name = strings.ToLower(name)
		if name != "mx" && seen[name] {
			continue
		}
		seen[name] = true
		switch name {
		case "version":
			if !strings.EqualFold(value, "STSv1") {
				return Policy{}, fmt.Errorf("unsupported policy version %q", value)
			}
			policy.Version = "STSv1"
		case "mode":
			mode := strings.ToLower(value)
			if mode != ModeEnforce && mode != ModeTesting && mode != ModeNone {
				return Policy{}, fmt.Errorf("unsupported policy mode %q", value)
			}
			policy.Mode = mode
		case "mx":
			pattern, err := canonicalMXPattern(value)
			if err != nil {
				return Policy{}, fmt.Errorf("invalid mx pattern %q: %w", value, err)
			}
			policy.MX = append(policy.MX, pattern)
		case "max_age":
			if len(value) > 10 || !asciiDigits(value) {
				return Policy{}, fmt.Errorf("invalid max_age %q", value)
			}
			maxAge, err := strconv.ParseInt(value, 10, 64)
			if err != nil || maxAge > maxPolicyAgeSeconds {
				return Policy{}, fmt.Errorf("invalid max_age %q", value)
			}
			policy.MaxAge = maxAge
		}
	}
	if policy.Version == "" || policy.Mode == "" || !seen["max_age"] {
		return Policy{}, errors.New("policy requires version, mode, and max_age")
	}
	if policy.Mode != ModeNone && len(policy.MX) == 0 {
		return Policy{}, errors.New("enforce and testing policies require at least one mx field")
	}
	return policy, nil
}

// PolicyID selects the single usable MTA-STS TXT record and returns its id.
// A syntactically invalid or ambiguous record set is treated as unavailable.
func PolicyID(records []string) (string, bool, error) {
	usable := make([]string, 0, 1)
	for _, record := range records {
		if len(record) >= len("v=STSv1;") && strings.EqualFold(record[:len("v=STSv1;")], "v=STSv1;") {
			usable = append(usable, record)
		}
	}
	if len(usable) == 0 {
		return "", false, nil
	}
	if len(usable) != 1 {
		return "", false, errors.New("multiple usable MTA-STS TXT records")
	}
	id, err := parsePolicyID(usable[0])
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}

func parsePolicyID(record string) (string, error) {
	fields := strings.Split(record, ";")
	if len(fields) < 2 || !strings.EqualFold(fields[0], "v=STSv1") {
		return "", errors.New("invalid MTA-STS version field")
	}
	seen := map[string]bool{"v": true}
	id := ""
	for index, raw := range fields[1:] {
		field := strings.Trim(raw, " \t")
		if field == "" && index == len(fields[1:])-1 {
			continue
		}
		equals := strings.IndexByte(field, '=')
		if equals <= 0 || equals == len(field)-1 {
			return "", errors.New("invalid MTA-STS TXT field")
		}
		name, value := field[:equals], field[equals+1:]
		if !validExtensionName(name) || !validTXTValue(value) {
			return "", errors.New("invalid MTA-STS TXT field")
		}
		name = strings.ToLower(name)
		if seen[name] {
			continue
		}
		seen[name] = true
		if name == "id" {
			if len(value) > 32 || !asciiAlphaNumeric(value) {
				return "", errors.New("invalid MTA-STS policy id")
			}
			id = value
		}
	}
	if id == "" {
		return "", errors.New("MTA-STS TXT record has no policy id")
	}
	return id, nil
}

// MatchesMX reports whether host matches one of the policy's exact or
// complete-leftmost-label wildcard MX patterns.
func (p Policy) MatchesMX(host string) bool {
	host, err := CanonicalDomain(host)
	if err != nil {
		return false
	}
	for _, pattern := range p.MX {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[2:]
			if strings.HasSuffix(host, "."+suffix) && strings.Count(host, ".") == strings.Count(suffix, ".")+1 {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

// CanonicalDomain returns a lower-case DNS A-label without a trailing dot.
func CanonicalDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" || net.ParseIP(domain) != nil {
		return "", errors.New("domain name required")
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("convert domain to A-label: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", errors.New("domain is too long")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, char := range label {
			if !isASCIIAlphaNumeric(char) && char != '-' {
				return "", errors.New("invalid domain label")
			}
		}
	}
	return ascii, nil
}

func canonicalMXPattern(pattern string) (string, error) {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	wildcard := strings.HasPrefix(pattern, "*.")
	domain := pattern
	if wildcard {
		domain = pattern[2:]
	}
	canonical, err := CanonicalDomain(domain)
	if err != nil {
		return "", err
	}
	// RFC 8461 requires policy documents to contain A-labels rather than
	// Unicode U-labels, even though host inputs may be canonicalized here.
	if !strings.EqualFold(canonical, domain) {
		return "", errors.New("mx pattern must use a lower-case DNS A-label")
	}
	if wildcard {
		return "*." + canonical, nil
	}
	return canonical, nil
}

func validFieldName(value string) bool {
	return validExtensionName(value)
}

func validExtensionName(value string) bool {
	if len(value) == 0 || len(value) > 32 || !isASCIIAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, char := range value[1:] {
		if !isASCIIAlphaNumeric(char) && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func validFieldValue(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func validTXTValue(value string) bool {
	for _, char := range value {
		if char <= 0x20 || char == ';' || char == '=' || char == 0x7f || char > 0x7e {
			return false
		}
	}
	return true
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !isASCIIAlphaNumeric(char) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}
