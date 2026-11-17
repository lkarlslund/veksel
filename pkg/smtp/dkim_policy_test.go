package smtp

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dkim"
)

func TestEvaluateDKIM_NilPolicy(t *testing.T) {
	message := []byte("From: alice@example.com\r\n\r\nBody")
	result := EvaluateDKIM(nil, message)

	if result.Result != "skip" {
		t.Errorf("expected result 'skip', got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected Pass=true for nil policy")
	}
}

func TestEvaluateDKIM_OffPolicy(t *testing.T) {
	policy := &DkimPolicy{Mode: DkimPolicyOff}
	message := []byte("From: alice@example.com\r\n\r\nBody")
	result := EvaluateDKIM(policy, message)

	if result.Result != "skip" {
		t.Errorf("expected result 'skip', got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected Pass=true for off policy")
	}
}

func TestEvaluateDKIM_NoSignature(t *testing.T) {
	policy := &DkimPolicy{Mode: DkimPolicyWarn}
	message := []byte("From: alice@example.com\r\n\r\nBody")
	result := EvaluateDKIM(policy, message)

	if result.Result != "none" {
		t.Errorf("expected result 'none', got %q", result.Result)
	}
	if !result.Pass {
		t.Error("expected Pass=true for no signature (not rejected)")
	}
}

// signedPolicyMessage returns a signed message and a Verifier that serves
// lookup for its key without DNS.
func signedPolicyMessage(t *testing.T, body string) ([]byte, dkim.Verifier) {
	t.Helper()
	private, public, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	message := []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Test\r\n" +
		"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <policy-test@example.com>\r\n" +
		"\r\n" + body)
	signed, err := dkim.Sign(message, "example.com", "default", private)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	record := dkim.DKIMDNSRecord(public)
	return signed, dkim.Verifier{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if name != "default._domainkey.example.com" {
			return nil, errors.New("unexpected lookup " + name)
		}
		return []string{record}, nil
	}}
}

func TestEvaluateDKIM_ValidSignature(t *testing.T) {
	signed, verifier := signedPolicyMessage(t, "Test body.")
	result := EvaluateDKIM(&DkimPolicy{Mode: DkimPolicyReject, Verifier: verifier}, signed)

	if result.Result != "pass" || !result.Pass || result.ShouldReject {
		t.Fatalf("result = %+v, want unrejected pass", result)
	}
	if result.Domain != "example.com" || result.Selector != "default" {
		t.Fatalf("domain/selector = %q/%q", result.Domain, result.Selector)
	}
}

func TestEvaluateDKIM_BodyTampered(t *testing.T) {
	signed, verifier := signedPolicyMessage(t, "Original body.")
	tampered := strings.Replace(string(signed), "Original body.", "Tampered body.", 1)
	result := EvaluateDKIM(&DkimPolicy{Mode: DkimPolicyReject, Verifier: verifier}, []byte(tampered))

	if result.Result != "fail" || result.Pass {
		t.Errorf("result = %+v, want fail", result)
	}
	if !result.ShouldReject {
		t.Error("expected ShouldReject=true for fail in reject mode")
	}
}

func TestEvaluateDKIM_WarnMode(t *testing.T) {
	signed, verifier := signedPolicyMessage(t, "Original body.")
	tampered := strings.Replace(string(signed), "Original body.", "Tampered body.", 1)
	result := EvaluateDKIM(&DkimPolicy{Mode: DkimPolicyWarn, Verifier: verifier}, []byte(tampered))

	if result.Result != "fail" {
		t.Errorf("expected result 'fail', got %q", result.Result)
	}
	if result.ShouldReject {
		t.Error("expected ShouldReject=false in warn mode")
	}
}

func TestEvaluateDKIM_TemporaryDNSFailureIsNotRejected(t *testing.T) {
	signed, _ := signedPolicyMessage(t, "Test body.")
	verifier := dkim.Verifier{LookupTXT: func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "timeout", IsTimeout: true, IsTemporary: true}
	}}
	result := EvaluateDKIM(&DkimPolicy{Mode: DkimPolicyReject, Verifier: verifier}, signed)

	if result.Result != "temperror" || result.ShouldReject {
		t.Fatalf("result = %+v, want unrejected temperror", result)
	}
}

func TestDkimVerificationHeader(t *testing.T) {
	t.Parallel()
	result := &DkimResult{
		HeaderValue: "pass; header.i=@example.com; header.s=default; header.d=example.com",
	}
	header := dkimVerificationHeader(result)
	if header != "pass; header.i=@example.com; header.s=default; header.d=example.com" {
		t.Errorf("unexpected header value: %q", header)
	}

	// Nil result
	header = dkimVerificationHeader(nil)
	if header != "skip" {
		t.Errorf("expected 'skip' for nil result, got %q", header)
	}
}

func TestDefaultDkimPolicy(t *testing.T) {
	t.Parallel()
	policy := DefaultDkimPolicy()
	if policy.Mode != DkimPolicyWarn {
		t.Errorf("expected default mode 'warn', got %q", policy.Mode)
	}
}
