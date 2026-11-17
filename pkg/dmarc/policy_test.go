package dmarc

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

func fixedResolver(records map[string][]string) resolverFunc {
	return func(_ context.Context, name string) ([]string, error) {
		values, ok := records[name]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return values, nil
	}
}

// --- EvaluateDMARC tests ---

func TestEvaluateDMARC_off_mode(t *testing.T) {
	policy := &DmarcPolicy{Mode: DmarcPolicyOff}
	result := EvaluateDMARC(context.Background(), policy, "example.com",
		"example.com", true, []string{"example.com"}, true)

	if result.Result != "skip" {
		t.Errorf("expected 'skip' in off mode, got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected pass in off mode")
	}
}

func TestEvaluateDMARC_nil_policy(t *testing.T) {
	result := EvaluateDMARC(context.Background(), nil, "example.com",
		"example.com", true, []string{"example.com"}, true)

	if result.Result != "skip" {
		t.Errorf("expected 'skip' for nil policy, got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected pass for nil policy")
	}
}

func TestEvaluateDMARC_no_from_domain(t *testing.T) {
	policy := &DmarcPolicy{Mode: DmarcPolicyWarn}
	result := EvaluateDMARC(context.Background(), policy, "",
		"example.com", true, []string{"example.com"}, true)

	if result.Result != "none" {
		t.Errorf("expected 'none' for empty from domain, got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected pass for empty from domain")
	}
}

func TestEvaluateDMARC_no_record(t *testing.T) {
	// For a domain with no DMARC record, the result should be "none" and pass
	policy := &DmarcPolicy{Mode: DmarcPolicyReject}
	result := EvaluateDMARC(context.Background(), policy, "nonexistent-domain-dmarc-test-12345.com",
		"nonexistent-domain-dmarc-test-12345.com", true, []string{"nonexistent-domain-dmarc-test-12345.com"}, true)

	if result.Result != "none" {
		t.Errorf("expected 'none' for no DMARC record, got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected pass when no DMARC record exists")
	}
}

func TestEvaluatorAppliesQuarantineWithoutConvertingItToReject(t *testing.T) {
	evaluator := Evaluator{Resolver: fixedResolver(map[string][]string{
		"_dmarc.example.test.": {"v=DMARC1; p=quarantine"},
	}), Sample: func(int) bool { return true }}
	result := evaluator.Evaluate(t.Context(), &DmarcPolicy{Mode: DmarcPolicyReject}, "example.test", "outside.test", false, nil, false)
	if result.Result != "fail" || result.Disposition != "quarantine" || !result.PolicyApplied || result.ShouldReject {
		t.Fatalf("quarantine result = %+v", result)
	}
}

func TestEvaluatorUsesOrganizationalDomainAndSubdomainPolicy(t *testing.T) {
	evaluator := Evaluator{Resolver: fixedResolver(map[string][]string{
		"_dmarc.example.co.uk.": {"v=DMARC1; p=reject; sp=quarantine"},
	}), Sample: func(int) bool { return true }}
	result := evaluator.Evaluate(t.Context(), &DmarcPolicy{Mode: DmarcPolicyReject}, "mail.example.co.uk", "outside.test", false, nil, false)
	if result.PolicyDomain != "example.co.uk" || result.Domain != "mail.example.co.uk" || result.Disposition != "quarantine" || result.ShouldReject {
		t.Fatalf("inherited result = %+v", result)
	}
}

func TestEvaluatorRetainsPublishedAggregateReportingPolicy(t *testing.T) {
	evaluator := Evaluator{Resolver: fixedResolver(map[string][]string{
		"_dmarc.example.test.": {"v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=75; fo=1; rua=mailto:first@reports.test,mailto:second@reports.test"},
	})}
	result := evaluator.Evaluate(t.Context(), &DmarcPolicy{Mode: DmarcPolicyWarn}, "example.test", "example.test", true, nil, false)
	if result.Reporting == nil {
		t.Fatal("reporting policy was discarded")
	}
	want := result.Reporting
	if want.Domain != "example.test" || want.Policy != "reject" || want.SubdomainPolicy != "quarantine" ||
		want.ADKIM != "s" || want.ASPF != "r" || want.Percentage != 75 || want.FailureOptions != "1" ||
		want.DiscoveryMethod != "psl" || len(want.RUA) != 2 {
		t.Fatalf("reporting policy = %+v", want)
	}
}

// TestEvaluatorPercentageExclusionLowersPolicy follows RFC 7489 section
// 6.6.4: failing mail outside the sampled percentage of p=reject is
// quarantined, and outside p=quarantine gets no DMARC disposition.
func TestEvaluatorPercentageExclusionLowersPolicy(t *testing.T) {
	for _, test := range []struct {
		record, disposition string
		applied             bool
	}{
		{"v=DMARC1; p=reject; pct=25", "quarantine", true},
		{"v=DMARC1; p=reject; pct=0", "quarantine", true},
		{"v=DMARC1; p=quarantine; pct=25", "none", false},
		{"v=DMARC1; p=none; sp=reject; pct=0", "none", true},
	} {
		evaluator := Evaluator{Resolver: fixedResolver(map[string][]string{"_dmarc.example.test.": {test.record}}), Sample: func(int) bool { return false }}
		result := evaluator.Evaluate(t.Context(), &DmarcPolicy{Mode: DmarcPolicyReject}, "example.test", "outside.test", false, nil, false)
		if result.Result != "fail" || result.Pass || result.ShouldReject || result.Disposition != test.disposition || result.PolicyApplied != test.applied {
			t.Errorf("%s: result = %+v", test.record, result)
		}
	}
}

func TestEvaluatorClassifiesLookupFailures(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		evaluator := Evaluator{Resolver: resolverFunc(func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}), Timeout: time.Millisecond}
		result := evaluator.Evaluate(t.Context(), &DmarcPolicy{Mode: DmarcPolicyReject}, "example.test", "", false, nil, false)
		if result.Result != "temperror" {
			t.Fatalf("timeout result = %+v", result)
		}
	})
	t.Run("multiple records", func(t *testing.T) {
		evaluator := Evaluator{Resolver: fixedResolver(map[string][]string{
			"_dmarc.example.test.": {"v=DMARC1; p=none", "v=DMARC1; p=reject"},
		})}
		result := evaluator.Evaluate(t.Context(), &DmarcPolicy{Mode: DmarcPolicyReject}, "example.test", "", false, nil, false)
		if result.Result != "permerror" {
			t.Fatalf("multiple-record result = %+v", result)
		}
	})
}

// --- SPF alignment tests ---

func TestCheckSpfAlignment_strict_pass(t *testing.T) {
	aligned := checkSpfAlignment("example.com", "example.com", true, true)
	if !aligned {
		t.Error("expected strict SPF alignment for exact match")
	}
}

func TestCheckSpfAlignment_strict_fail(t *testing.T) {
	aligned := checkSpfAlignment("mail.example.com", "example.com", true, true)
	if aligned {
		t.Error("expected strict SPF alignment to fail for subdomain")
	}
}

func TestCheckSpfAlignment_relaxed_pass(t *testing.T) {
	aligned := checkSpfAlignment("mail.example.com", "example.com", true, false)
	if !aligned {
		t.Error("expected relaxed SPF alignment to pass for subdomain")
	}
}

func TestCheckSpfAlignment_relaxed_exact(t *testing.T) {
	aligned := checkSpfAlignment("example.com", "example.com", true, false)
	if !aligned {
		t.Error("expected relaxed SPF alignment to pass for exact match")
	}
}

func TestCheckSpfAlignment_spf_not_pass(t *testing.T) {
	aligned := checkSpfAlignment("example.com", "example.com", false, false)
	if aligned {
		t.Error("expected SPF alignment to fail when SPF did not pass")
	}
}

func TestCheckSpfAlignment_empty_spf_domain(t *testing.T) {
	aligned := checkSpfAlignment("", "example.com", true, false)
	if aligned {
		t.Error("expected SPF alignment to fail for empty SPF domain")
	}
}

// --- DKIM alignment tests ---

func TestCheckDkimAlignment_strict_pass(t *testing.T) {
	aligned := checkDkimAlignment([]string{"example.com"}, "example.com", true, true)
	if !aligned {
		t.Error("expected strict DKIM alignment for exact match")
	}
}

func TestCheckDkimAlignment_strict_fail(t *testing.T) {
	aligned := checkDkimAlignment([]string{"mail.example.com"}, "example.com", true, true)
	if aligned {
		t.Error("expected strict DKIM alignment to fail for subdomain")
	}
}

func TestCheckDkimAlignment_relaxed_pass(t *testing.T) {
	aligned := checkDkimAlignment([]string{"mail.example.com"}, "example.com", true, false)
	if !aligned {
		t.Error("expected relaxed DKIM alignment to pass for subdomain")
	}
}

func TestCheckDkimAlignment_relaxed_exact(t *testing.T) {
	aligned := checkDkimAlignment([]string{"example.com"}, "example.com", true, false)
	if !aligned {
		t.Error("expected relaxed DKIM alignment to pass for exact match")
	}
}

func TestCheckDkimAlignment_multiple_signatures(t *testing.T) {
	// One of multiple DKIM signatures should align
	aligned := checkDkimAlignment([]string{"other.com", "mail.example.com"}, "example.com", true, false)
	if !aligned {
		t.Error("expected relaxed DKIM alignment to pass when one of multiple signatures aligns")
	}
}

func TestCheckDkimAlignment_dkim_not_pass(t *testing.T) {
	aligned := checkDkimAlignment([]string{"example.com"}, "example.com", false, false)
	if aligned {
		t.Error("expected DKIM alignment to fail when DKIM did not pass")
	}
}

func TestCheckDkimAlignment_empty_domains(t *testing.T) {
	aligned := checkDkimAlignment([]string{}, "example.com", true, false)
	if aligned {
		t.Error("expected DKIM alignment to fail for empty domain list")
	}
}

// --- Organizational domain tests ---

func TestOrganizationalDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"mail.example.com", "example.com"},
		{"sub.mail.example.com", "example.com"},
		{"a.b.c.d.example.com", "example.com"},
		{"mail.example.co.uk", "example.co.uk"},
		{"com", "com"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := organizationalDomain(tt.domain)
			if got != tt.want {
				t.Errorf("organizationalDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestDomainsAlignRelaxed(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"example.com", "example.com", true},
		{"mail.example.com", "example.com", true},
		{"sub.mail.example.com", "mail.example.com", true},
		{"mail.example.co.uk", "example.co.uk", true},
		{"example.com", "other.com", false},
		{"mail.example.com", "mail.other.com", false},
		{"a.example.com", "b.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.a+"-vs-"+tt.b, func(t *testing.T) {
			got := domainsAlignRelaxed(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("domainsAlignRelaxed(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --- DMARC record parsing tests ---

func TestParseDmarcRecord_basic(t *testing.T) {
	record, err := parseDmarcRecord("v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:dmarc@example.com")
	if err != nil {
		t.Fatalf("parseDmarcRecord() error: %v", err)
	}

	if record.Version != "DMARC1" {
		t.Errorf("Version = %q, want %q", record.Version, "DMARC1")
	}
	if record.Policy != "reject" {
		t.Errorf("Policy = %q, want %q", record.Policy, "reject")
	}
	if record.SpPolicy != "quarantine" {
		t.Errorf("SpPolicy = %q, want %q", record.SpPolicy, "quarantine")
	}
	if record.Pct != 50 {
		t.Errorf("Pct = %d, want %d", record.Pct, 50)
	}
	if len(record.RUA) != 1 || record.RUA[0] != "mailto:dmarc@example.com" {
		t.Errorf("RUA = %v, want [mailto:dmarc@example.com]", record.RUA)
	}
	// Defaults
	if record.Adkim != "r" {
		t.Errorf("Adkim should default to 'r', got %q", record.Adkim)
	}
	if record.Aspf != "r" {
		t.Errorf("Aspf should default to 'r', got %q", record.Aspf)
	}
}

func TestParseDmarcRecord_defaults(t *testing.T) {
	record, err := parseDmarcRecord("v=DMARC1; p=none")
	if err != nil {
		t.Fatalf("parseDmarcRecord() error: %v", err)
	}

	if record.SpPolicy != "none" {
		t.Errorf("SpPolicy should default to Policy, got %q", record.SpPolicy)
	}
	if record.Pct != 100 {
		t.Errorf("Pct should default to 100, got %d", record.Pct)
	}
}

func TestParseDmarcRecord_strict_alignment(t *testing.T) {
	record, err := parseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s")
	if err != nil {
		t.Fatalf("parseDmarcRecord() error: %v", err)
	}

	if record.Adkim != "s" {
		t.Errorf("Adkim = %q, want %q", record.Adkim, "s")
	}
	if record.Aspf != "s" {
		t.Errorf("Aspf = %q, want %q", record.Aspf, "s")
	}
}

func TestParseDmarcRecord_multiple_rua(t *testing.T) {
	record, err := parseDmarcRecord("v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com")
	if err != nil {
		t.Fatalf("parseDmarcRecord() error: %v", err)
	}

	if len(record.RUA) != 2 {
		t.Fatalf("RUA length = %d, want 2", len(record.RUA))
	}
	if record.RUA[0] != "mailto:a@example.com" {
		t.Errorf("RUA[0] = %q, want %q", record.RUA[0], "mailto:a@example.com")
	}
	if record.RUA[1] != "mailto:b@example.com" {
		t.Errorf("RUA[1] = %q, want %q", record.RUA[1], "mailto:b@example.com")
	}
}

func TestParseDmarcRecord_invalid_version(t *testing.T) {
	_, err := parseDmarcRecord("v=INVALID; p=none")
	if err == nil {
		t.Error("expected error for invalid version, got nil")
	}
}

func TestParseDmarcRecord_invalid_policy(t *testing.T) {
	_, err := parseDmarcRecord("v=DMARC1; p=invalid")
	if err == nil {
		t.Error("expected error for invalid policy, got nil")
	}
}

func TestParseDmarcRecord_rejectsDuplicateAndInvalidPolicyTags(t *testing.T) {
	for name, value := range map[string]string{
		"duplicate":     "v=DMARC1; p=none; p=reject",
		"sp":            "v=DMARC1; p=none; sp=invalid",
		"missing p":     "v=DMARC1; adkim=s",
		"lower version": "v=dmarc1; p=reject",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDmarcRecord(value); err == nil {
				t.Fatalf("invalid record %q was accepted", value)
			}
		})
	}
}

// TestParseDmarcRecord_syntaxErrorsFallBackToDefaults follows RFC 7489
// section 6.3: an invalid optional tag takes its default instead of
// voiding the record, which left p=reject unenforced (permerror) for a
// typo such as adkim=x.
func TestParseDmarcRecord_syntaxErrorsFallBackToDefaults(t *testing.T) {
	record, err := parseDmarcRecord("v=DMARC1; p=reject; adkim=x; aspf=strict; pct=150; future=1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Policy != "reject" || record.SpPolicy != "reject" || record.Adkim != "r" || record.Aspf != "r" || record.Pct != 100 {
		t.Fatalf("record = %+v", record)
	}
	if record, err = parseDmarcRecord("v=DMARC1; p=none; pct=0"); err != nil || record.Pct != 0 {
		t.Fatalf("pct=0: %+v, %v", record, err)
	}
	// RFC 7489 section 6.6.3: an invalid p= or sp= with a usable rua= acts
	// as p=none so reports still flow.
	for _, value := range []string{"v=DMARC1; p=bogus; rua=mailto:dmarc@example.com", "v=DMARC1; rua=mailto:dmarc@example.com", "v=DMARC1; p=reject; sp=x; rua=mailto:dmarc@example.com"} {
		record, err := parseDmarcRecord(value)
		if err != nil || record.Policy != "none" || record.SpPolicy != "none" {
			t.Errorf("%s: %+v, %v", value, record, err)
		}
	}
	if _, err := parseDmarcRecord("v=DMARC1; p=bogus; rua=https://example.com/"); err == nil {
		t.Error("invalid p= with an unusable rua= was accepted")
	}
}

func TestParseDmarcRecord_ruf(t *testing.T) {
	record, err := parseDmarcRecord("v=DMARC1; p=reject; ruf=mailto:forensic@example.com")
	if err != nil {
		t.Fatalf("parseDmarcRecord() error: %v", err)
	}

	if len(record.RUF) != 1 || record.RUF[0] != "mailto:forensic@example.com" {
		t.Errorf("RUF = %v, want [mailto:forensic@example.com]", record.RUF)
	}
}

// --- Apply percentage tests ---

func TestApplyPercentage_100(t *testing.T) {
	for i := 0; i < 100; i++ {
		if !applyPercentage(100) {
			t.Error("expected pct=100 to always apply")
			break
		}
	}
}

func TestApplyPercentage_0(t *testing.T) {
	// pct=0 intentionally applies the requested disposition to no messages.
	for i := 0; i < 100; i++ {
		if applyPercentage(0) {
			t.Error("expected pct=0 to never apply")
			break
		}
	}
}

// --- Header value tests ---

func TestDmarcResult_header_value_pass(t *testing.T) {
	result := &DmarcResult{
		Result: "pass",
		Domain: "example.com",
		Pass:   true,
	}
	result.HeaderValue = "pass; domain=example.com; header.from=example.com"

	if !strings.Contains(result.HeaderValue, "pass") {
		t.Error("header value should contain 'pass'")
	}
	if !strings.Contains(result.HeaderValue, "domain=example.com") {
		t.Error("header value should contain domain")
	}
}

func TestDmarcResult_header_value_fail(t *testing.T) {
	result := &DmarcResult{
		Result:      "fail",
		Domain:      "example.com",
		Pass:        false,
		HeaderValue: "fail; domain=example.com; header.from=example.com; policy=reject",
	}

	if !strings.Contains(result.HeaderValue, "fail") {
		t.Error("header value should contain 'fail'")
	}
	if !strings.Contains(result.HeaderValue, "policy=reject") {
		t.Error("header value should contain policy")
	}
}

// --- DefaultDmarcPolicy tests ---

func TestDefaultDmarcPolicy(t *testing.T) {
	p := DefaultDmarcPolicy()
	if p.Mode != DmarcPolicyWarn {
		t.Errorf("expected default mode warn, got %q", p.Mode)
	}
}

// --- Split DMARC fields tests ---

func TestSplitDmarcFields(t *testing.T) {
	fields := splitDmarcFields("v=DMARC1; p=reject; rua=mailto:\"test@example.com\"")

	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}

	if strings.TrimSpace(fields[0]) != "v=DMARC1" {
		t.Errorf("field[0] = %q, want %q", fields[0], "v=DMARC1")
	}
	if strings.TrimSpace(fields[1]) != "p=reject" {
		t.Errorf("field[1] = %q, want %q", fields[1], "p=reject")
	}
}

// --- Parse mailto URIs tests ---

func TestParseMailtoURIs(t *testing.T) {
	uris := parseMailtoURIs("mailto:a@example.com, mailto:b@example.com")

	if len(uris) != 2 {
		t.Fatalf("expected 2 URIs, got %d", len(uris))
	}
	if uris[0] != "mailto:a@example.com" {
		t.Errorf("URI[0] = %q, want %q", uris[0], "mailto:a@example.com")
	}
	if uris[1] != "mailto:b@example.com" {
		t.Errorf("URI[1] = %q, want %q", uris[1], "mailto:b@example.com")
	}
}

func TestParseMailtoURIs_empty(t *testing.T) {
	uris := parseMailtoURIs("")
	if len(uris) != 0 {
		t.Errorf("expected 0 URIs for empty input, got %d", len(uris))
	}
}
