package smtp

import (
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authresults"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func (s *Session) authenticationResultsHeader(headers map[string]string) (string, error) {
	results := make([]authresults.Result, 0, 4)
	if result := s.spfResult; result != nil && result.Result != "skip" {
		results = append(results, spfAuthenticationResult(result, s.envelopeSender))
	}
	if result := s.dkimResult; result != nil && result.Result != "skip" {
		results = append(results, dkimAuthenticationResults(result)...)
	}
	if result := s.arcResult; result != nil {
		// The reason and sealer quote peer-supplied tags.
		arc := authresults.Result{Method: "arc", Result: result.Status}
		if result.Status == "fail" {
			arc.Reason = printableValue(result.Reason, 120)
		}
		if sealer := printableValue(result.Sealer, 253); sealer != "" {
			arc.Properties = []authresults.Property{{Name: "header.d", Value: sealer}}
		}
		results = append(results, arc)
	}
	if result := s.dmarcResult; result != nil && result.Result != "skip" {
		properties := make([]authresults.Property, 0, 4)
		// header.from names the From domain DMARC evaluated, which with
		// several From domains is the one that decided the result.
		if domain := printableValue(result.Domain, 253); domain != "" {
			properties = append(properties, authresults.Property{Name: "header.from", Value: domain})
		}
		if result.Disposition != "" {
			properties = append(properties, authresults.Property{Name: "policy.dmarc", Value: result.Disposition})
		}
		if result.PolicyDomain != "" {
			properties = append(properties, authresults.Property{Name: "policy.domain", Value: result.PolicyDomain})
		}
		if result.Percentage > 0 {
			properties = append(properties, authresults.Property{Name: "policy.pct", Value: strconv.Itoa(result.Percentage)})
		}
		results = append(results, authresults.Result{Method: "dmarc", Result: authenticationOutcome(result.Result), Reason: result.OverrideReason, Properties: properties})
	}
	if result := s.spoofResult; result != nil {
		properties := make([]authresults.Property, 0, 2)
		if result.EnvelopeDomain != "" {
			properties = append(properties, authresults.Property{Name: "smtp.mailfrom", Value: result.EnvelopeDomain})
		}
		if result.HeaderDomain != "" {
			properties = append(properties, authresults.Property{Name: "header.from", Value: result.HeaderDomain})
		}
		results = append(results, authresults.Result{Method: "policy", Result: result.Result, Reason: result.Reason, Properties: properties})
	}
	if len(results) == 0 {
		return "", nil
	}
	authservID := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.cfg.ServerName)), ".")
	return authresults.Build(authservID, results)
}

// dkimAuthenticationResults returns one RFC 8601 dkim entry per verified
// signature, identified by header.d, header.s, and a header.b prefix (RFC
// 6008), or a single entry when no signature was verified. Every value is
// peer-supplied, so each is reduced to bounded printable ASCII.
func dkimAuthenticationResults(result *DkimResult) []authresults.Result {
	if len(result.Signatures) == 0 {
		entry := authresults.Result{Method: "dkim", Result: authenticationOutcome(result.Result)}
		if domain := printableValue(result.Domain, 253); domain != "" {
			entry.Properties = append(entry.Properties, authresults.Property{Name: "header.d", Value: domain})
		}
		if selector := printableValue(result.Selector, 63); selector != "" {
			entry.Properties = append(entry.Properties, authresults.Property{Name: "header.s", Value: selector})
		}
		return []authresults.Result{entry}
	}
	entries := make([]authresults.Result, 0, len(result.Signatures))
	for _, signature := range result.Signatures {
		entry := authresults.Result{Method: "dkim", Result: authenticationOutcome(signature.Status)}
		if signature.Status != dkim.StatusPass {
			reason := signature.Reason
			if signature.Testing {
				reason += " (testing key)"
			}
			entry.Reason = printableValue(reason, 120)
		}
		for _, property := range []authresults.Property{
			{Name: "header.d", Value: printableValue(signature.Domain, 253)},
			{Name: "header.s", Value: printableValue(signature.Selector, 63)},
			{Name: "header.b", Value: printableValue(signature.Signature, 12)},
		} {
			if property.Value != "" {
				entry.Properties = append(entry.Properties, property)
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// spfAuthenticationResult is the RFC 8601 spf method entry: smtp.mailfrom
// names the checked sender, or smtp.helo when a null sender was checked
// through the HELO identity (RFC 7208 section 9.1, RFC 8601 section 2.7.2).
func spfAuthenticationResult(result *SpfResult, envelopeSender string) authresults.Result {
	entry := authresults.Result{Method: "spf", Result: authenticationOutcome(result.Result)}
	sender := printableValue(strings.Trim(strings.TrimSpace(envelopeSender), "<>"), 320)
	switch {
	case sender != "":
		entry.Properties = []authresults.Property{{Name: "smtp.mailfrom", Value: sender}}
	case result.Identity == spam.SPFIdentityHelo && printableValue(result.SenderDomain, 253) != "":
		entry.Properties = []authresults.Property{{Name: "smtp.helo", Value: printableValue(result.SenderDomain, 253)}}
	default:
		entry.Properties = []authresults.Property{{Name: "smtp.mailfrom", Value: "<>"}}
	}
	if result.Result == "temperror" || result.Result == "permerror" {
		entry.Reason = printableValue(result.Problem, 120)
	}
	return entry
}

// printableValue keeps the printable ASCII of value, cut to limit bytes, so
// peer-supplied text can never invalidate the field.
func printableValue(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, value)
	return strings.TrimSpace(value[:min(len(value), limit)])
}

func authenticationOutcome(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		return "none"
	}
}

func replaceSMTPHeader(headers map[string]string, name, value string) {
	for existing := range headers {
		if strings.EqualFold(existing, name) {
			delete(headers, existing)
		}
	}
	if value != "" {
		headers[name] = value
	}
}
