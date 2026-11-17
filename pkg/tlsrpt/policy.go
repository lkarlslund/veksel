package tlsrpt

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
)

const (
	maxReportingRecordBytes = 4096
	maxReportingURIs        = 10
	maxReportingURIBytes    = 2048
)

// ReportingPolicy is the validated _smtp._tls policy for one domain.
type ReportingPolicy struct {
	Domain string   `json:"domain"`
	URIs   []string `json:"uris"`
}

// ParseReportingPolicy selects and parses the single usable RFC 8460 TXT
// record. Unsupported records are ignored; an ambiguous set is unavailable.
func ParseReportingPolicy(domain string, records []string) (ReportingPolicy, bool, error) {
	policy := ReportingPolicy{Domain: domain}
	usable := make([]string, 0, 1)
	const prefix = "v=TLSRPTv1;"
	for _, record := range records {
		if len(record) >= len(prefix) && strings.EqualFold(record[:len(prefix)], prefix) {
			usable = append(usable, record)
		}
	}
	if len(usable) == 0 {
		return policy, false, nil
	}
	if len(usable) != 1 {
		return policy, false, errors.New("multiple usable SMTP TLS reporting records")
	}
	if len(usable[0]) > maxReportingRecordBytes {
		return policy, false, errors.New("SMTP TLS reporting record is too large")
	}
	fields := strings.Split(usable[0], ";")
	if len(fields) < 2 || !strings.EqualFold(fields[0], "v=TLSRPTv1") {
		return policy, false, errors.New("invalid SMTP TLS reporting version")
	}
	seen := map[string]bool{"v": true}
	for index, raw := range fields[1:] {
		field := strings.Trim(raw, " \t")
		if field == "" && index == len(fields[1:])-1 {
			continue
		}
		equals := strings.IndexByte(field, '=')
		if equals <= 0 || equals == len(field)-1 {
			return policy, false, errors.New("invalid SMTP TLS reporting field")
		}
		name, value := strings.ToLower(field[:equals]), field[equals+1:]
		if !validPolicyFieldName(name) || name != "rua" && !validPolicyFieldValue(value) {
			return policy, false, errors.New("invalid SMTP TLS reporting field")
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if name != "rua" {
			continue
		}
		for _, rawURI := range strings.Split(value, ",") {
			if len(policy.URIs) == maxReportingURIs {
				break
			}
			rawURI = strings.Trim(rawURI, " \t")
			if len(rawURI) == 0 || len(rawURI) > maxReportingURIBytes || !validPolicyFieldValue(rawURI) {
				return policy, false, errors.New("invalid SMTP TLS reporting URI")
			}
			canonical, err := validateReportingURI(rawURI)
			if err != nil {
				return policy, false, err
			}
			policy.URIs = append(policy.URIs, canonical)
		}
	}
	if len(policy.URIs) == 0 {
		return policy, false, errors.New("SMTP TLS reporting record has no rua endpoint")
	}
	return policy, true, nil
}

func validateReportingURI(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid SMTP TLS reporting URI")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		if parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return "", errors.New("invalid HTTPS SMTP TLS reporting URI")
		}
		return parsed.String(), nil
	case "mailto":
		if parsed.Opaque == "" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", errors.New("invalid mailto SMTP TLS reporting URI")
		}
		address, err := url.PathUnescape(parsed.Opaque)
		if err != nil {
			return "", errors.New("invalid mailto SMTP TLS reporting URI")
		}
		parsedAddress, err := mail.ParseAddress(address)
		if err != nil || parsedAddress.Address != address || strings.ContainsAny(address, "\r\n") {
			return "", errors.New("invalid mailto SMTP TLS reporting address")
		}
		return "mailto:" + parsed.Opaque, nil
	default:
		return "", fmt.Errorf("unsupported SMTP TLS reporting URI scheme %q", parsed.Scheme)
	}
}

func validPolicyFieldName(value string) bool {
	if len(value) == 0 || len(value) > 32 || !asciiAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, char := range value[1:] {
		if !asciiAlphaNumeric(char) && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func validPolicyFieldValue(value string) bool {
	for _, char := range value {
		if char <= 0x20 || char == ';' || char == '=' || char == 0x7f || char > 0x7e {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}
