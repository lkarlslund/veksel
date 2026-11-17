// Package dmarc provides DMARC policy evaluation per RFC 7489.
//
// This file implements:
//   - DMARC DNS TXT record parsing (v=DMARC1, p=, sp=, pct, rua, ruf)
//   - SPF alignment check (strict: exact domain match; relaxed: org domain match)
//   - DKIM alignment check (strict: exact domain match; relaxed: org domain match)
//   - DMARC policy evaluation (none/quarantine/reject) based on alignment
//   - structured evidence for the caller's Authentication-Results field
package dmarc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// DmarcPolicyMode controls how DMARC failures are handled.
type DmarcPolicyMode string

const (
	DmarcPolicyOff    DmarcPolicyMode = "off"
	DmarcPolicyWarn   DmarcPolicyMode = "warn"
	DmarcPolicyReject DmarcPolicyMode = "reject"
)

// DmarcPolicy holds configurable rules for DMARC checking.
type DmarcPolicy struct {
	// Mode controls the enforcement level: off, warn, or reject.
	Mode DmarcPolicyMode
}

// DmarcResult captures the outcome of DMARC evaluation.
type DmarcResult struct {
	// Result is the DMARC verification result: pass, fail, none, temperror, permerror.
	Result string

	// Domain is the organizational domain being checked.
	Domain string

	// SpfPass indicates whether SPF alignment passed.
	SpfPass bool

	// DkimPass indicates whether DKIM alignment passed.
	DkimPass bool

	// Pass indicates whether the DMARC check passes (at least one aligned).
	Pass bool

	// ShouldReject indicates whether the message should be rejected based on policy.
	ShouldReject bool

	// RejectionCode is the SMTP response code when the policy rejects.
	RejectionCode int

	// RejectionText is the human-readable rejection reason.
	RejectionText string

	// HeaderValue is a legacy diagnostic projection. New protocol adapters use
	// the structured fields to build Authentication-Results.
	HeaderValue string

	// PolicyDomain is the domain that published the effective record. It can
	// differ from Domain when organizational-domain fallback is used.
	PolicyDomain string

	// Disposition is the sampled policy result: none, quarantine, or reject.
	Disposition string

	PolicyApplied bool
	Percentage    int

	// Reporting is the normalized policy publication needed for aggregate
	// reporting. It is nil when no valid DMARC record was discovered.
	Reporting *ReportingPolicy
}

// ReportingPolicy is the immutable, privacy-safe portion of a discovered
// DMARC policy needed to group and generate aggregate reports.
type ReportingPolicy struct {
	Domain          string
	Policy          string
	SubdomainPolicy string
	ADKIM           string
	ASPF            string
	FailureOptions  string
	Percentage      int
	RUA             []string
	DiscoveryMethod string
}

// DmarcRecord represents a parsed DMARC DNS TXT record per RFC 7489.
type DmarcRecord struct {
	// Version is the record version (must be "DMARC1").
	Version string

	// Policy is the domain owner's requested handling for non-compliant mail: none, quarantine, or reject.
	Policy string

	// SpPolicy is the sub-domain policy; defaults to Policy if not set.
	SpPolicy string

	// Pct is the percentage of messages to which the policy is applied (1-100).
	Pct int

	// Ruaglobal aggregate reporting URIs.
	RUA []string

	// Rufor forensic reporting URIs.
	RUF []string

	// Adkim specifies DKIM alignment mode: 's' (strict) or 'r' (relaxed).
	Adkim string

	// Aspf specifies SPF alignment mode: 's' (strict) or 'r' (relaxed).
	Aspf string

	// Fo specifies the failure reporting option.
	Fo string
}

// dmarcDNSTimeout is the timeout for DMARC DNS lookups.
const dmarcDNSTimeout = 5 * time.Second

// TXTResolver is the bounded DNS dependency used by DMARC evaluation.
type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

// Evaluator owns DNS lookup, timeout, and percentage selection policy.
type Evaluator struct {
	Resolver TXTResolver
	Timeout  time.Duration
	Sample   func(int) bool
}

func DefaultEvaluator() Evaluator {
	return Evaluator{Resolver: net.DefaultResolver, Timeout: dmarcDNSTimeout, Sample: applyPercentage}
}

// EvaluateDMARC runs DMARC evaluation for the given header From domain,
// SPF result, and DKIM result. Returns a DmarcResult describing the outcome.
//
// The headerFromDomain is extracted from the From: header of the message.
// The spfDomain is the domain from SPF checking (envelope sender domain).
// The spfPass indicates whether SPF passed.
// The dkimDomains is the list of signing domains from DKIM signatures.
// The dkimPass indicates whether any DKIM signature passed.
func EvaluateDMARC(ctx context.Context, policy *DmarcPolicy, headerFromDomain string,
	spfDomain string, spfPass bool, dkimDomains []string, dkimPass bool) *DmarcResult {
	return DefaultEvaluator().Evaluate(ctx, policy, headerFromDomain, spfDomain, spfPass, dkimDomains, dkimPass)
}

// Evaluate performs one DMARC evaluation with bounded, injectable DNS.
func (e Evaluator) Evaluate(ctx context.Context, policy *DmarcPolicy, headerFromDomain string,
	spfDomain string, spfPass bool, dkimDomains []string, dkimPass bool) *DmarcResult {

	if policy == nil || policy.Mode == DmarcPolicyOff {
		return &DmarcResult{Result: "skip", Pass: true}
	}

	if headerFromDomain == "" {
		return &DmarcResult{Result: "none", Pass: true, HeaderValue: "none; reason=no-from-domain"}
	}

	domain := strings.TrimSuffix(strings.ToLower(headerFromDomain), ".")
	resolver := e.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = dmarcDNSTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dmarcRecord, policyDomain, inherited, err := lookupPolicyRecord(lookupCtx, resolver, domain)
	if err != nil {
		if errors.Is(err, errNoRecord) {
			return &DmarcResult{Result: "none", Domain: domain, Pass: true, Disposition: "none", HeaderValue: fmt.Sprintf("none; domain=%s; reason=no-record", domain)}
		}
		result := "temperror"
		if errors.Is(err, errInvalidRecord) {
			result = "permerror"
		}
		log.Warn("dmarc: policy lookup failed", "domain", domain, "result", result, "error", err)
		return &DmarcResult{Result: result, Domain: domain, Pass: true, Disposition: "none", HeaderValue: fmt.Sprintf("%s; domain=%s; reason=policy-lookup", result, domain)}
	}

	// Determine alignment modes from the record
	adkimStrict := dmarcRecord.Adkim == "s"
	aspfStrict := dmarcRecord.Aspf == "s"

	// Check SPF alignment
	spfAligned := checkSpfAlignment(spfDomain, domain, spfPass, aspfStrict)

	// Check DKIM alignment
	dkimAligned := checkDkimAlignment(dkimDomains, domain, dkimPass, adkimStrict)

	// DMARC passes if either SPF or DKIM is aligned
	passed := spfAligned || dkimAligned

	result := &DmarcResult{Domain: domain, PolicyDomain: policyDomain, SpfPass: spfAligned,
		DkimPass: dkimAligned, Pass: passed, Disposition: "none", PolicyApplied: true, Percentage: dmarcRecord.Pct}
	result.Reporting = &ReportingPolicy{Domain: policyDomain, Policy: dmarcRecord.Policy,
		SubdomainPolicy: dmarcRecord.SpPolicy, ADKIM: dmarcRecord.Adkim, ASPF: dmarcRecord.Aspf,
		FailureOptions: dmarcRecord.Fo, Percentage: dmarcRecord.Pct,
		RUA: append([]string(nil), dmarcRecord.RUA...), DiscoveryMethod: "psl"}

	if passed {
		result.Result = "pass"
		result.HeaderValue = fmt.Sprintf("pass; domain=%s; header.from=%s", domain, headerFromDomain)
		log.Debug("dmarc: check passed",
			"domain", domain, "spf", spfAligned, "dkim", dkimAligned)
		return result
	}

	// DMARC failed — apply policy
	result.Result = "fail"

	// Check percentage — policy only applies to Pct% of messages
	sample := e.Sample
	if sample == nil {
		sample = applyPercentage
	}
	// Determine the effective policy
	effectivePolicy := dmarcRecord.Policy
	if inherited {
		effectivePolicy = dmarcRecord.SpPolicy
	}
	if effectivePolicy != "none" && !sample(dmarcRecord.Pct) {
		// RFC 7489 section 6.6.4: mail outside the sampled percentage of a
		// reject policy is treated as quarantine; outside a quarantine
		// policy it gets local classification only.
		log.Debug("dmarc: excluded by percentage", "domain", domain, "pct", dmarcRecord.Pct, "policy", effectivePolicy)
		if effectivePolicy != "reject" {
			result.PolicyApplied = false
			result.HeaderValue = fmt.Sprintf("fail; domain=%s; policy=none; pct=%d; reason=percentage-excluded", domain, dmarcRecord.Pct)
			return result
		}
		effectivePolicy = "quarantine"
	}
	result.Disposition = effectivePolicy

	// Apply based on policy mode and DMARC record policy
	switch effectivePolicy {
	case "reject":
		if policy.Mode == DmarcPolicyReject {
			result.ShouldReject = true
			result.RejectionCode = 550
			result.RejectionText = "5.7.1 DMARC policy requires rejection"
		}
	case "quarantine":
		// Quarantine is a distinct disposition. The SMTP adapter routes it to
		// durable quarantine instead of translating it into rejection.
	case "none":
		// No action required — just log
		log.Warn("dmarc: policy is none, no action taken",
			"domain", domain, "record_policy", effectivePolicy)
	default:
		// Unknown policy — treat as none
		log.Warn("dmarc: unknown policy", "domain", domain, "policy", effectivePolicy)
	}

	result.HeaderValue = fmt.Sprintf("fail; domain=%s; header.from=%s; policy=%s",
		domain, headerFromDomain, effectivePolicy)

	log.Warn("dmarc: check failed",
		"domain", domain, "policy", effectivePolicy, "mode", policy.Mode,
		"spf", spfAligned, "dkim", dkimAligned)

	return result
}

// checkSpfAlignment checks whether the SPF result is aligned with the From domain.
// strict requires exact domain match; relaxed allows organizational domain match.
func checkSpfAlignment(spfDomain, fromDomain string, spfPass bool, strict bool) bool {
	if !spfPass || spfDomain == "" {
		return false
	}

	spfDomain = strings.ToLower(spfDomain)

	if strict {
		// Strict: exact domain match
		return spfDomain == fromDomain
	}

	// Relaxed: organizational domain match
	return domainsAlignRelaxed(spfDomain, fromDomain)
}

// checkDkimAlignment checks whether any DKIM signature is aligned with the From domain.
// strict requires exact domain match; relaxed allows organizational domain match.
func checkDkimAlignment(dkimDomains []string, fromDomain string, dkimPass bool, strict bool) bool {
	if !dkimPass || len(dkimDomains) == 0 {
		return false
	}

	for _, dkimDomain := range dkimDomains {
		dkimDomain = strings.ToLower(dkimDomain)
		if strict {
			// Strict: exact domain match between signing domain and From domain
			if dkimDomain == fromDomain {
				return true
			}
		} else {
			// Relaxed: organizational domain match
			if domainsAlignRelaxed(dkimDomain, fromDomain) {
				return true
			}
		}
	}

	return false
}

// domainsAlignRelaxed checks whether two domains share the same organizational domain.
// Per RFC 7489 Section 4.4, relaxed alignment compares the organizational domain,
// which is the registered domain (e.g., "example.com" for "mail.example.com").
// The public suffix list determines the organizational boundary; simply
// removing one label is incorrect for both deep subdomains and suffixes such
// as co.uk.
func domainsAlignRelaxed(domainA, domainB string) bool {
	if domainA == domainB {
		return true
	}

	// Get organizational domains
	orgA := organizationalDomain(domainA)
	orgB := organizationalDomain(domainB)

	return orgA == orgB
}

// organizationalDomain extracts the organizational domain from a domain name.
// For "mail.example.com" it returns "example.com".
// For "example.com" it returns "example.com".
// For "sub.mail.example.com" it returns "example.com". The public suffix
// list is required for domains such as example.co.uk.
func organizationalDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	value, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return value
}

// applyPercentage determines whether the message falls within the percentage
// of messages to which the DMARC policy applies.
// pct defaults to 100 if not specified.
func applyPercentage(pct int) bool {
	if pct <= 0 {
		return false
	}
	if pct > 100 {
		return true
	}
	if pct == 100 {
		return true
	}
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		// Sampling failure must not silently weaken a published policy.
		return true
	}
	return binary.BigEndian.Uint64(value[:])%100 < uint64(pct)
}

var (
	errNoRecord      = errors.New("no DMARC record")
	errInvalidRecord = errors.New("invalid DMARC record")
)

func lookupPolicyRecord(ctx context.Context, resolver TXTResolver, domain string) (*DmarcRecord, string, bool, error) {
	record, err := lookupDmarcRecordWithResolver(ctx, resolver, domain)
	if err == nil {
		return record, domain, false, nil
	}
	if !errors.Is(err, errNoRecord) {
		return nil, "", false, err
	}
	organization := organizationalDomain(domain)
	if organization == domain {
		return nil, "", false, errNoRecord
	}
	record, err = lookupDmarcRecordWithResolver(ctx, resolver, organization)
	if err != nil {
		return nil, "", false, err
	}
	return record, organization, true, nil
}

func lookupDmarcRecordWithResolver(ctx context.Context, resolver TXTResolver, domain string) (*DmarcRecord, error) {
	queryName := fmt.Sprintf("_dmarc.%s.", domain)
	txtRecords, err := resolver.LookupTXT(ctx, queryName)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, errNoRecord
		}
		return nil, fmt.Errorf("DMARC DNS TXT lookup for %s: %w", queryName, err)
	}
	candidates := make([]string, 0, 1)
	for _, record := range txtRecords {
		if isDMARCRecord(record) {
			candidates = append(candidates, record)
		}
	}
	if len(candidates) == 0 {
		return nil, errNoRecord
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("%w: multiple records for %s", errInvalidRecord, domain)
	}
	record, err := parseDmarcRecord(candidates[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidRecord, err)
	}
	return record, nil
}

func isDMARCRecord(record string) bool {
	first, _, _ := strings.Cut(strings.TrimSpace(record), ";")
	key, value, found := strings.Cut(first, "=")
	// RFC 7489 section 6.3: v= comes first and its value matches DMARC1
	// precisely; anything else is not a DMARC record.
	return found && strings.TrimSpace(key) == "v" && strings.TrimSpace(value) == "DMARC1"
}

// parseDmarcRecord parses a DMARC DNS TXT record string into a DmarcRecord.
// The record format is: v=DMARC1; p=none; sp=none; pct=100; rua=mailto:...; ruf=mailto:...
func parseDmarcRecord(record string) (*DmarcRecord, error) {
	dmarcRecord := &DmarcRecord{Pct: 100}
	seen := make(map[string]struct{})

	// Split by ; and parse key=value pairs
	fields := splitDmarcFields(record)

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		eqIdx := strings.Index(field, "=")
		if eqIdx < 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(field[:eqIdx]))
		value := strings.TrimSpace(field[eqIdx+1:])
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate DMARC tag: %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "v":
			dmarcRecord.Version = value
		case "p":
			dmarcRecord.Policy = strings.ToLower(value)
		case "sp":
			dmarcRecord.SpPolicy = strings.ToLower(value)
		case "pct":
			// RFC 7489 section 6.3: a syntax error outside v= and p= falls
			// back to the default rather than voiding the published policy.
			if pct, err := strconv.Atoi(value); err == nil && pct >= 0 && pct <= 100 {
				dmarcRecord.Pct = pct
			}
		case "rua":
			dmarcRecord.RUA = parseMailtoURIs(value)
		case "ruf":
			dmarcRecord.RUF = parseMailtoURIs(value)
		case "adkim":
			dmarcRecord.Adkim = strings.ToLower(value)
		case "aspf":
			dmarcRecord.Aspf = strings.ToLower(value)
		case "fo":
			dmarcRecord.Fo = value
		}
	}

	// Validate version tag
	if dmarcRecord.Version != "DMARC1" {
		return nil, fmt.Errorf("invalid DMARC record version: %q (expected DMARC1)", dmarcRecord.Version)
	}

	// RFC 7489 section 6.6.3: a missing or invalid p=, or an invalid sp=,
	// leaves a record that still requests aggregate reports acting as
	// p=none; without a usable rua= the record is invalid.
	validPolicy := func(policy string) bool { return policy == "none" || policy == "quarantine" || policy == "reject" }
	if !validPolicy(dmarcRecord.Policy) || dmarcRecord.SpPolicy != "" && !validPolicy(dmarcRecord.SpPolicy) {
		if !hasValidReportURI(dmarcRecord.RUA) {
			return nil, fmt.Errorf("invalid DMARC policy: p=%q sp=%q", dmarcRecord.Policy, dmarcRecord.SpPolicy)
		}
		dmarcRecord.Policy, dmarcRecord.SpPolicy = "none", "none"
	}

	// Default sub-domain policy to domain policy
	if dmarcRecord.SpPolicy == "" {
		dmarcRecord.SpPolicy = dmarcRecord.Policy
	}

	// Alignment modes default to relaxed, as does an invalid value.
	if dmarcRecord.Adkim != "s" {
		dmarcRecord.Adkim = "r"
	}
	if dmarcRecord.Aspf != "s" {
		dmarcRecord.Aspf = "r"
	}

	return dmarcRecord, nil
}

// hasValidReportURI reports whether uris holds a usable mailto: rua URI.
func hasValidReportURI(uris []string) bool {
	for _, uri := range uris {
		if _, _, err := parseAggregateDestination(uri); err == nil {
			return true
		}
	}
	return false
}

// splitDmarcFields splits a DMARC record by semicolons, respecting quoted strings.
func splitDmarcFields(record string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, ch := range record {
		switch ch {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(ch)
		case ';':
			if !inQuotes {
				fields = append(fields, current.String())
				current.Reset()
				continue
			}
			current.WriteRune(ch)
		default:
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		fields = append(fields, current.String())
	}

	return fields
}

// parseMailtoURIs parses a comma-separated list of mailto URIs.
func parseMailtoURIs(value string) []string {
	var uris []string
	for _, uri := range strings.Split(value, ",") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

// DefaultDmarcPolicy returns the default DMARC policy configuration.
func DefaultDmarcPolicy() *DmarcPolicy {
	return &DmarcPolicy{
		Mode: DmarcPolicyWarn,
	}
}
