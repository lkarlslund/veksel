package smtp

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dmarc"
)

type recordingDMARCAggregates struct {
	mu           sync.Mutex
	observations []dmarc.AggregateObservation
}

func (r *recordingDMARCAggregates) Record(_ context.Context, observation dmarc.AggregateObservation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observations = append(r.observations, observation)
	return nil
}

func (r *recordingDMARCAggregates) snapshot() []dmarc.AggregateObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]dmarc.AggregateObservation(nil), r.observations...)
}

type smtpTXTResolverFunc func(context.Context, string) ([]string, error)

func (f smtpTXTResolverFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

// --- EvaluateDMARC tests ---

func TestEvaluateDMARC_off_mode(t *testing.T) {
	policy := &DmarcPolicy{Mode: DmarcPolicyOff}
	result := EvaluateDMARC(policy, "example.com",
		"example.com", true, []string{"example.com"}, true)

	if result.Result != "skip" {
		t.Errorf("expected 'skip' in off mode, got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected pass in off mode")
	}
}

func TestEvaluateDMARC_nil_policy(t *testing.T) {
	result := EvaluateDMARC(nil, "example.com",
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
	result := EvaluateDMARC(policy, "",
		"example.com", true, []string{"example.com"}, true)

	// Empty from domain returns "none" (no DMARC check possible)
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
	result := EvaluateDMARC(policy, "nonexistent-domain-dmarc-test-99999.com",
		"nonexistent-domain-dmarc-test-99999.com", true, []string{"nonexistent-domain-dmarc-test-99999.com"}, true)

	if result.Result != "none" {
		t.Errorf("expected 'none' for no DMARC record, got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected pass when no DMARC record exists")
	}
	if result.ShouldReject {
		t.Error("should not reject when no DMARC record exists")
	}
}

// --- extractDomainFromAddress tests ---

func TestExtractDomainFromAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr string
		want string
	}{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"John Doe <john@example.com>", "example.com"},
		{"USER@EXAMPLE.COM", "example.com"},
		{"", ""},
		{"no-at-sign", ""},
		{"<>", ""},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := extractDomainFromAddress(tt.addr)
			if got != tt.want {
				t.Errorf("extractDomainFromAddress(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// --- DefaultDmarcPolicy tests ---

func TestDefaultDmarcPolicy(t *testing.T) {
	t.Parallel()
	p := DefaultDmarcPolicy()
	if p.Mode != DmarcPolicyWarn {
		t.Errorf("expected default mode warn, got %q", p.Mode)
	}
}

// --- Integration: DMARC in SMTP flow ---

func TestDMARC_off_mode_allows(t *testing.T) {
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyOff,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// In off mode, no DMARC header should be added
	if receivedHeaders["DMARC-Verification-Result"] != "" {
		t.Errorf("expected no DMARC header in off mode, got: %s", receivedHeaders["DMARC-Verification-Result"])
	}
}

func TestDMARC_no_policy_allows(t *testing.T) {
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		// No DmarcPolicy set
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// No DMARC header when policy is nil
	if receivedHeaders["DMARC-Verification-Result"] != "" {
		t.Errorf("expected no DMARC header when policy is nil, got: %s", receivedHeaders["DMARC-Verification-Result"])
	}
}

func TestDMARC_warn_mode_no_record(t *testing.T) {
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyWarn,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				receivedHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@nonexistent-domain-dmarc-88888.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@nonexistent-domain-dmarc-88888.com\r\nTo: alice@example.com\r\nSubject: DMARC Test\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// A single standards-shaped Authentication-Results field carries DMARC.
	authenticationResults := receivedHeaders["Authentication-Results"]
	if !strings.Contains(authenticationResults, "dmarc=none") {
		t.Fatalf("Authentication-Results = %q, want DMARC none", authenticationResults)
	}
	if receivedHeaders["DMARC-Verification-Result"] != "" {
		t.Fatal("legacy DMARC result header was retained")
	}
}

func TestDMARC_reject_mode_no_record_allows(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyReject,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@nonexistent-domain-dmarc-77777.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@nonexistent-domain-dmarc-77777.com\r\nTo: alice@example.com\r\nSubject: DMARC Reject Test\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250 (no DMARC record means allow)", code)
	}
}

func TestDMARCQuarantineIsDurablyQueuedWithCombinedResults(t *testing.T) {
	queue := &recordingSystemQueue{}
	evaluator := &dmarc.Evaluator{
		Resolver: smtpTXTResolverFunc(func(_ context.Context, _ string) ([]string, error) {
			return []string{"v=DMARC1; p=quarantine"}, nil
		}),
		Sample: func(int) bool { return true },
	}
	c := makeTestServer(t, &Config{
		ServerName:  "test.veksel",
		DmarcPolicy: &DmarcPolicy{Mode: DmarcPolicyReject, Evaluator: evaluator},
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) {
				return "alice:INBOX", "alice", nil
			},
			MailQueue: queue,
		},
	})

	c.send("EHLO client.example.test")
	c.send("MAIL FROM:<sender@outside.test>")
	c.send("RCPT TO:<alice@example.test>")
	c.send("DATA")
	c.writeData("Authentication-Results: attacker.test; dmarc=pass\r\nFrom: sender@example.test\r\nTo: alice@example.test\r\nSubject: quarantine me\r\n\r\nBody\r\n.\r\n")
	code, text, err := c.readReply()
	if err != nil || code != 250 {
		t.Fatalf("DATA completion code=%d text=%q error=%v", code, text, err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("queued messages = %#v", queue.messages)
	}
	message := queue.messages[0]
	if message.Kind != MailTaskQuarantine || message.TargetOwnerID != "alice" || message.TargetFolderID != "" {
		t.Fatalf("quarantine target = %#v", message)
	}
	authenticationResults := message.Headers["Authentication-Results"]
	if !strings.HasPrefix(authenticationResults, "test.veksel;") || !strings.Contains(authenticationResults, "dmarc=fail") || !strings.Contains(authenticationResults, "policy.dmarc=quarantine") || strings.Contains(authenticationResults, "attacker.test") {
		t.Fatalf("Authentication-Results = %q", authenticationResults)
	}
	for _, legacy := range []string{"Received-SPF", "DKIM-Verification-Result", "DMARC-Verification-Result"} {
		if message.Headers[legacy] != "" {
			t.Fatalf("legacy header %s was retained", legacy)
		}
	}
	if message.Attributes["reason_type"] != "dmarc" || message.Attributes["authentication_results"] != authenticationResults {
		t.Fatalf("quarantine evidence = %#v", message.Attributes)
	}
}

func TestDMARCAggregateRecordedBeforePolicyReject(t *testing.T) {
	recorder := &recordingDMARCAggregates{}
	evaluator := &dmarc.Evaluator{Resolver: smtpTXTResolverFunc(func(_ context.Context, _ string) ([]string, error) {
		return []string{"v=DMARC1; p=reject; rua=mailto:dmarc@reports.example"}, nil
	}), Sample: func(int) bool { return true }}
	c := makeTestServer(t, &Config{ServerName: "test.veksel", DmarcPolicy: &DmarcPolicy{Mode: DmarcPolicyReject, Evaluator: evaluator},
		DMARCAggregates: recorder, Delivery: &Delivery{ResolveRecipient: func(context.Context, string) (string, string, error) {
			return "alice:INBOX", "alice", nil
		}}})

	c.send("EHLO client.example.test")
	c.send("MAIL FROM:<sender@outside.test>")
	c.send("RCPT TO:<alice@example.test>")
	c.send("DATA")
	c.writeData("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: reject me\r\n\r\nBody\r\n.\r\n")
	code, _, err := c.readReply()
	if err != nil || code != 550 {
		t.Fatalf("DATA completion code=%d error=%v", code, err)
	}
	observations := recorder.snapshot()
	if len(observations) != 1 || observations[0].Policy.Domain != "example.test" ||
		observations[0].Disposition != "reject" || observations[0].HeaderFrom != "example.test" {
		t.Fatalf("observations = %#v", observations)
	}
}

func TestDMARC_rset_clears_result(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyWarn,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@example.com>")

	// RSET should clear DMARC result
	code, _ := c.send("RSET")
	if code != 250 {
		t.Fatalf("RSET: code=%d, want 250", code)
	}

	// New MAIL FROM should work
	code, _ = c.send("MAIL FROM:<other@example.com>")
	if code != 250 {
		t.Fatalf("MAIL FROM after RSET: code=%d, want 250", code)
	}

	code, _ = c.send("RCPT TO:<alice@example.com>")
	if code != 250 {
		t.Fatalf("RCPT TO: code=%d, want 250", code)
	}
}

func TestDMARC_full_smtp_transaction(t *testing.T) {
	var deliveredHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyWarn,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				deliveredHeaders = headers
				return "item-1", nil
			},
		},
	})

	// Full SMTP transaction
	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<test@nonexistent-domain-dmarc-66666.com>")
	c.send("RCPT TO:<recipient@example.com>")
	c.send("DATA")

	c.writeData("From: test@nonexistent-domain-dmarc-66666.com\r\nTo: recipient@example.com\r\nSubject: DMARC Full Test\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// Verify message was delivered
	if deliveredHeaders == nil {
		t.Fatal("expected headers to be set")
	}
	if deliveredHeaders["Message-ID"] == "" {
		t.Error("expected auto-generated Message-ID")
	}
	if deliveredHeaders["Subject"] != "DMARC Full Test" {
		t.Errorf("Subject = %q, want %q", deliveredHeaders["Subject"], "DMARC Full Test")
	}
	if !strings.Contains(deliveredHeaders["Authentication-Results"], "dmarc=none") {
		t.Fatalf("Authentication-Results = %q, want DMARC none", deliveredHeaders["Authentication-Results"])
	}
}

func TestDMARC_with_named_from_header(t *testing.T) {
	var deliveredHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyWarn,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				deliveredHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@nonexistent-domain-dmarc-55555.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	// From header with display name
	c.writeData("From: John Doe <john@nonexistent-domain-dmarc-55555.com>\r\nTo: alice@example.com\r\nSubject: Named From\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if !strings.Contains(deliveredHeaders["Authentication-Results"], "dmarc=none") {
		t.Fatalf("Authentication-Results = %q, want DMARC none", deliveredHeaders["Authentication-Results"])
	}
}

func TestDMARC_no_from_header(t *testing.T) {
	var deliveredHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		DmarcPolicy: &DmarcPolicy{
			Mode: DmarcPolicyWarn,
		},
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
				deliveredHeaders = headers
				return "item-1", nil
			},
		},
	})

	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	// No From header
	c.writeData("To: alice@example.com\r\nSubject: No From\r\n\r\nBody\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	// Should still deliver — DMARC result is "none" when no From header
	if deliveredHeaders["Subject"] != "No From" {
		t.Errorf("Subject = %q, want %q", deliveredHeaders["Subject"], "No From")
	}
}

// --- DmarcResult header value tests ---

func TestDmarcResult_header_value_format(t *testing.T) {
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

func TestDmarcResult_rejection_fields(t *testing.T) {
	result := &DmarcResult{
		Result:        "fail",
		Domain:        "example.com",
		Pass:          false,
		ShouldReject:  true,
		RejectionCode: 550,
		RejectionText: "5.7.1 DMARC policy requires rejection",
	}

	if !result.ShouldReject {
		t.Error("expected ShouldReject to be true")
	}
	if result.RejectionCode != 550 {
		t.Errorf("expected rejection code 550, got %d", result.RejectionCode)
	}
	if !strings.Contains(result.RejectionText, "DMARC") {
		t.Error("rejection text should mention DMARC")
	}
}
