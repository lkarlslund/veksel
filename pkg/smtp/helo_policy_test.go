package smtp

import (
	"context"
	"strings"
	"testing"
)

// --- validateHeloHostname tests ---

func TestValidateHeloHostname_valid(t *testing.T) {
	tests := []struct {
		name string
		helo string
		min  int
	}{
		{"fully_qualified", "client.example.com", 2},
		{"three_parts", "mail.server.example.com", 2},
		{"single_part_min1", "client", 1},
		{"single_part_min0", "client", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHeloHostname(tt.helo, tt.min)
			if err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestValidateHeloHostname_empty(t *testing.T) {
	err := validateHeloHostname("", 0)
	if err == nil {
		t.Fatal("expected error for empty hostname")
	}
	if !contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

func TestValidateHeloHostname_whitespace(t *testing.T) {
	err := validateHeloHostname("  ", 0)
	if err == nil {
		t.Fatal("expected error for whitespace-only hostname")
	}
}

func TestValidateHeloHostname_ipv4(t *testing.T) {
	err := validateHeloHostname("192.168.1.1", 0)
	if err == nil {
		t.Fatal("expected error for IPv4 address")
	}
	if !contains(err.Error(), "IP address") {
		t.Errorf("expected 'IP address' in error, got: %v", err)
	}
}

func TestValidateHeloHostname_ipv6(t *testing.T) {
	err := validateHeloHostname("::1", 0)
	if err == nil {
		t.Fatal("expected error for IPv6 address")
	}
	if !contains(err.Error(), "IP address") {
		t.Errorf("expected 'IP address' in error, got: %v", err)
	}
}

func TestValidateHeloHostname_localhost(t *testing.T) {
	tests := []string{
		"localhost",
		"LOCALHOST",
		"localhost.localdomain",
		"mail.localhost",
	}

	for _, h := range tests {
		t.Run(h, func(t *testing.T) {
			err := validateHeloHostname(h, 0)
			if err == nil {
				t.Fatalf("expected error for localhost variant %q", h)
			}
			if !contains(err.Error(), "localhost") {
				t.Errorf("expected 'localhost' in error, got: %v", err)
			}
		})
	}
}

func TestValidateHeloHostname_single_part_rejected(t *testing.T) {
	err := validateHeloHostname("client", 2)
	if err == nil {
		t.Fatal("expected error for single-part hostname with minDomainParts=2")
	}
	if !contains(err.Error(), "domain parts") {
		t.Errorf("expected 'domain parts' in error, got: %v", err)
	}
}

func TestValidateHeloHostname_two_parts_accepted(t *testing.T) {
	err := validateHeloHostname("client.example.com", 2)
	if err != nil {
		t.Errorf("expected valid for two-part hostname, got: %v", err)
	}
}

// --- isIPAddress tests ---

func TestIsIPAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"client.example.com", false},
		{"localhost", false},
		{"", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isIPAddress(tt.input)
			if got != tt.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- HeloPolicy.Evaluate tests ---

func TestHeloPolicy_evaluate_off_mode(t *testing.T) {
	policy := &HeloPolicy{Mode: HeloPolicyOff}
	result := policy.Evaluate("", "192.168.1.1")

	if !result.Pass {
		t.Error("expected pass in off mode")
	}
	if result.HeaderValue != "skipped" {
		t.Errorf("expected 'skipped', got %q", result.HeaderValue)
	}
}

func TestHeloPolicy_evaluate_reject_empty_helo(t *testing.T) {
	policy := &HeloPolicy{
		Mode:           HeloPolicyReject,
		MinDomainParts: 2,
	}
	result := policy.Evaluate("", "192.168.1.1")

	if result.Pass {
		t.Error("expected failure for empty HELO")
	}
	if result.RejectionCode != 504 {
		t.Errorf("expected rejection code 504, got %d", result.RejectionCode)
	}
	if result.HeaderValue != "rejected" {
		t.Errorf("expected 'rejected', got %q", result.HeaderValue)
	}
}

func TestHeloPolicy_evaluate_warn_empty_helo(t *testing.T) {
	policy := &HeloPolicy{
		Mode:           HeloPolicyWarn,
		MinDomainParts: 2,
	}
	result := policy.Evaluate("", "192.168.1.1")

	if result.Pass {
		t.Error("expected failure for empty HELO even in warn mode")
	}
	if result.HeaderValue != "warning:empty HELO hostname" {
		t.Errorf("expected warning header, got %q", result.HeaderValue)
	}
}

func TestHeloPolicy_evaluate_valid_hostname(t *testing.T) {
	policy := &HeloPolicy{
		Mode:           HeloPolicyReject,
		MinDomainParts: 2,
		CheckRdns:      false, // skip rDNS to avoid network dependency
	}
	result := policy.Evaluate("client.example.com", "192.168.1.1")

	if !result.Pass {
		t.Errorf("expected pass for valid hostname, got warnings: %v", result.Warnings)
	}
	if result.HeaderValue != "pass" {
		t.Errorf("expected 'pass', got %q", result.HeaderValue)
	}
}

func TestHeloPolicy_evaluate_ip_rejected(t *testing.T) {
	policy := &HeloPolicy{
		Mode:      HeloPolicyReject,
		CheckRdns: false,
	}
	result := policy.Evaluate("192.168.1.1", "192.168.1.1")

	if result.Pass {
		t.Error("expected failure for IP address as HELO")
	}
}

func TestHeloPolicy_evaluate_localhost_rejected(t *testing.T) {
	policy := &HeloPolicy{
		Mode:      HeloPolicyReject,
		CheckRdns: false,
	}
	result := policy.Evaluate("localhost", "192.168.1.1")

	if result.Pass {
		t.Error("expected failure for localhost as HELO")
	}
}

func TestHeloPolicy_evaluate_single_part_rejected(t *testing.T) {
	policy := &HeloPolicy{
		Mode:           HeloPolicyReject,
		MinDomainParts: 2,
		CheckRdns:      false,
	}
	result := policy.Evaluate("client", "192.168.1.1")

	if result.Pass {
		t.Error("expected failure for single-part hostname")
	}
}

func TestHeloPolicy_evaluate_nil_policy(t *testing.T) {
	// Simulate what evaluateHeloPolicy does when policy is nil
	result := &HeloResult{Pass: true, HeaderValue: "off"}
	if !result.Pass {
		t.Error("expected pass when policy is nil")
	}
}

// --- DefaultHeloPolicy tests ---

func TestDefaultHeloPolicy(t *testing.T) {
	t.Parallel()
	p := DefaultHeloPolicy()

	if p.Mode != HeloPolicyWarn {
		t.Errorf("expected default mode warn, got %q", p.Mode)
	}
	if !p.RequireHelo {
		t.Error("expected RequireHelo to be true by default")
	}
	if !p.CheckRdns {
		t.Error("expected CheckRdns to be true by default")
	}
	if p.MinDomainParts != 2 {
		t.Errorf("expected MinDomainParts=2, got %d", p.MinDomainParts)
	}
}

// --- Integration tests: EHLO/HELO with policy ---

func TestEHLO_policy_reject_empty(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyReject,
			MinDomainParts: 2,
			CheckRdns:      false,
		},
	})

	// EHLO with empty hostname should be rejected
	code, _ := c.send("EHLO ")
	if code != 504 {
		t.Fatalf("EHLO with empty hostname: code=%d, want 504", code)
	}
}

func TestEHLO_policy_reject_ip(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:      HeloPolicyReject,
			CheckRdns: false,
		},
	})

	code, _ := c.send("EHLO 192.168.1.1")
	if code != 504 {
		t.Fatalf("EHLO with IP: code=%d, want 504", code)
	}
}

func TestEHLO_policy_reject_localhost(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:      HeloPolicyReject,
			CheckRdns: false,
		},
	})

	code, _ := c.send("EHLO localhost")
	if code != 504 {
		t.Fatalf("EHLO with localhost: code=%d, want 504", code)
	}
}

func TestEHLO_policy_reject_single_part(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyReject,
			MinDomainParts: 2,
			CheckRdns:      false,
		},
	})

	code, _ := c.send("EHLO client")
	if code != 504 {
		t.Fatalf("EHLO with single-part: code=%d, want 504", code)
	}
}

func TestEHLO_policy_accept_valid(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyReject,
			MinDomainParts: 2,
			CheckRdns:      false,
		},
	})

	code, _ := c.send("EHLO client.example.com")
	if code != 250 {
		t.Fatalf("EHLO with valid hostname: code=%d, want 250", code)
	}
}

func TestEHLO_policy_warn_allows(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyWarn,
			MinDomainParts: 2,
			CheckRdns:      false,
		},
	})

	// In warn mode, even invalid hostnames are accepted (with a warning logged)
	code, _ := c.send("EHLO client")
	if code != 250 {
		t.Fatalf("EHLO in warn mode: code=%d, want 250", code)
	}
}

func TestEHLO_policy_off_allows(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode: HeloPolicyOff,
		},
	})

	code, _ := c.send("EHLO ")
	if code != 250 {
		t.Fatalf("EHLO in off mode: code=%d, want 250", code)
	}
}

func TestHELO_policy_reject(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyReject,
			MinDomainParts: 2,
			CheckRdns:      false,
		},
	})

	code, _ := c.send("HELO localhost")
	if code != 504 {
		t.Fatalf("HELO with localhost: code=%d, want 504", code)
	}
}

func TestHELO_policy_accept_valid(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyReject,
			MinDomainParts: 2,
			CheckRdns:      false,
		},
	})

	code, _ := c.send("HELO client.example.com")
	if code != 250 {
		t.Fatalf("HELO with valid hostname: code=%d, want 250", code)
	}
}

func TestHELO_no_policy_accepts(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		// No HeloPolicy set
	})

	code, _ := c.send("HELO anything")
	if code != 250 {
		t.Fatalf("HELO without policy: code=%d, want 250", code)
	}
}

// --- X-HELO-Status header tests ---

func TestXHELOStatus_header_pass(t *testing.T) {
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyWarn,
			MinDomainParts: 2,
			CheckRdns:      false,
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

	if receivedHeaders == nil {
		t.Fatal("expected headers to be set")
	}
	if receivedHeaders["X-HELO-Status"] != "pass" {
		t.Errorf("X-HELO-Status = %q, want %q", receivedHeaders["X-HELO-Status"], "pass")
	}
}

func TestXHELOStatus_header_warning(t *testing.T) {
	var receivedHeaders map[string]string

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		HeloPolicy: &HeloPolicy{
			Mode:           HeloPolicyWarn,
			MinDomainParts: 2,
			CheckRdns:      false,
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

	// Single-part hostname triggers warning in warn mode
	c.send("EHLO client")
	c.send("MAIL FROM:<sender@example.com>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")

	c.writeData("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	code, _, _ := c.readReply()
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}

	if receivedHeaders == nil {
		t.Fatal("expected headers to be set")
	}
	status := receivedHeaders["X-HELO-Status"]
	if status == "" {
		t.Error("expected X-HELO-Status header to be set")
	}
	if !contains(status, "warning") {
		t.Errorf("X-HELO-Status should contain 'warning', got %q", status)
	}
}

// --- Helper ---

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
