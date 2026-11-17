package dkim

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

const testMessage = "From: alice@example.com\r\n" +
	"To: bob@example.net\r\n" +
	"Subject: Hello   there\r\n" +
	"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n" +
	"Message-ID: <test@example.com>\r\n" +
	"\r\n" +
	"Hello world.  \r\n" +
	"Second line.\r\n\r\n"

// keys returns a Verifier whose key lookups are served from records keyed by
// DNS query name.
func keys(records map[string]string) Verifier {
	return Verifier{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if record, ok := records[name]; ok {
			return []string{record}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}}
}

func signedTestMessage(t *testing.T, domain, selector string) ([]byte, string) {
	t.Helper()
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign([]byte(testMessage), domain, selector, private)
	if err != nil {
		t.Fatal(err)
	}
	return signed, DKIMDNSRecord(public)
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signed, record := signedTestMessage(t, "example.com", "s1")
	verifier := keys(map[string]string{"s1._domainkey.example.com": record})

	result := verifier.Verify(context.Background(), signed)
	if !result.Pass || result.Status != "pass" {
		t.Fatalf("result = %+v, want pass", result)
	}
	if result.Domain != "example.com" || result.Selector != "s1" {
		t.Fatalf("domain/selector = %q/%q", result.Domain, result.Selector)
	}
}

func TestSignatureSurvivesRelaxedTransportChanges(t *testing.T) {
	signed, record := signedTestMessage(t, "example.com", "s1")
	verifier := keys(map[string]string{"s1._domainkey.example.com": record})

	// Relaxed canonicalization tolerates whitespace changes and header-name case.
	mangled := bytes.Replace(signed, []byte("Subject: Hello   there"), []byte("subject:  Hello there"), 1)
	mangled = bytes.Replace(mangled, []byte("Hello world.  \r\n"), []byte("Hello  world.\r\n"), 1)
	if result := verifier.Verify(context.Background(), mangled); !result.Pass {
		t.Fatalf("result = %+v, want pass", result)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	signed, record := signedTestMessage(t, "example.com", "s1")
	verifier := keys(map[string]string{"s1._domainkey.example.com": record})

	for name, tampered := range map[string][]byte{
		"body":   bytes.Replace(signed, []byte("Second line."), []byte("Second lie."), 1),
		"header": bytes.Replace(signed, []byte("Subject: Hello"), []byte("Subject: Goodbye"), 1),
	} {
		result := verifier.Verify(context.Background(), tampered)
		if result.Pass || result.Status != "fail" {
			t.Errorf("%s: result = %+v, want fail", name, result)
		}
	}
}

func TestVerifyWithoutSignature(t *testing.T) {
	result := VerifyMessage(context.Background(), []byte(testMessage))
	if result.Status != "none" || result.Pass {
		t.Fatalf("result = %+v, want none", result)
	}
}

func TestVerifyKeyLookupFailures(t *testing.T) {
	signed, _ := signedTestMessage(t, "example.com", "s1")

	verifier := keys(nil)
	if result := verifier.Verify(context.Background(), signed); result.Status != "permerror" || result.Pass {
		t.Fatalf("missing key: result = %+v, want permerror", result)
	}

	verifier = Verifier{LookupTXT: func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "timeout", IsTimeout: true, IsTemporary: true}
	}}
	if result := verifier.Verify(context.Background(), signed); result.Status != "temperror" || result.Pass {
		t.Fatalf("DNS timeout: result = %+v, want temperror", result)
	}
}

func TestVerifyReportsSelectorOfPassingSignature(t *testing.T) {
	inner, record := signedTestMessage(t, "inner.example", "a")
	private, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// The outer signature's key is not published, so only the inner passes.
	signed, err := Sign(inner, "outer.example", "b", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier := keys(map[string]string{"a._domainkey.inner.example": record})

	result := verifier.Verify(context.Background(), signed)
	if !result.Pass || result.Domain != "inner.example" || result.Selector != "a" {
		t.Fatalf("result = %+v, want pass for inner.example/a", result)
	}
}

func TestDKIMDNSRecordPublishesSubjectPublicKeyInfo(t *testing.T) {
	_, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	record := DKIMDNSRecord(public)
	encoded, ok := strings.CutPrefix(record, "v=DKIM1; k=rsa; p=")
	if !ok {
		t.Fatalf("record = %q", record)
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("p= is not SubjectPublicKeyInfo: %v", err)
	}
	if DKIMDNSRecord([]byte("not pem")) != "" {
		t.Fatal("invalid key produced a record")
	}
}

func TestSignRejectsInvalidKey(t *testing.T) {
	if _, err := Sign([]byte(testMessage), "example.com", "s1", []byte("not pem")); err == nil {
		t.Fatal("Sign accepted an invalid key")
	}
}

func TestSPFDNSRecord(t *testing.T) {
	if got := SPFDNSRecord(true); got != "v=spf1 mx -all" {
		t.Errorf("SPFDNSRecord(true) = %q", got)
	}
	if got := SPFDNSRecord(false); got != "v=spf1 a -all" {
		t.Errorf("SPFDNSRecord(false) = %q", got)
	}
}

func TestDMARCDNSRecord(t *testing.T) {
	for pct, policy := range map[int]string{0: "none", 50: "quarantine", 100: "reject"} {
		got := DMARCDNSRecord(pct, "dmarc@example.com")
		if !strings.Contains(got, "p="+policy+";") || !strings.HasSuffix(got, "rua=mailto:dmarc@example.com") {
			t.Errorf("DMARCDNSRecord(%d) = %q", pct, got)
		}
		if strings.Contains(got, "pct=") != (pct == 50) {
			t.Errorf("DMARCDNSRecord(%d) = %q: pct belongs only to a partial quarantine or reject", pct, got)
		}
	}
}
