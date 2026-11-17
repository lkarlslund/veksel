package dkim

import (
	"bytes"
	"context"
	"testing"
)

// FuzzDKIM feeds arbitrary input through the public signing and verification
// entry points; neither may panic.
func FuzzDKIM(f *testing.F) {
	for _, seed := range []string{
		testMessage,
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default; c=relaxed/simple; h=from; bh=abc=; b=xyz=\r\n" + testMessage,
		"DKIM-Signature: v=1; d=d1.com; s=s1\r\nDKIM-Signature: d=d2.com\r\nFrom: a@b.c\r\n\r\nbody",
		"",
		"\r\n\r\n",
		"\x00\xff\xfe",
		"-----BEGIN RSA PRIVATE KEY-----\nnot-valid-base64\n-----END RSA PRIVATE KEY-----",
	} {
		f.Add(seed)
	}
	private, _, err := GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input string) {
		verifier := Verifier{LookupTXT: func(context.Context, string) ([]string, error) { return []string{input}, nil }}
		_ = verifier.Verify(context.Background(), []byte(input))
		_, _ = Sign([]byte(input), "example.com", "s1", private)
		_, _ = ParsePrivateKey([]byte(input))
		_ = DKIMDNSRecord([]byte(input))
	})
}

// FuzzCanonicalization checks RFC 6376 section 3.4 invariants on arbitrary
// input: canonicalization is idempotent, a relaxed field is one line, and
// verifying a message never yields more results than signatures.
func FuzzCanonicalization(f *testing.F) {
	for _, seed := range []string{
		"A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n",
		"Subject: a\n b\r\n\r\nline\n\n",
		"\r\n \t\r\n\r",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, message string) {
		fields, body := splitMessage([]byte(message))
		for _, relaxed := range []bool{true, false} {
			once := canonicalBody(body, relaxed)
			if twice := canonicalBody(once, relaxed); !bytes.Equal(once, twice) {
				t.Fatalf("body canonicalization (relaxed=%v) is not idempotent: %q -> %q", relaxed, once, twice)
			}
		}
		for _, field := range fields {
			canonical := canonicalHeader(field.raw, true)
			if bytes.Count([]byte(canonical), []byte("\r\n")) != 1 || canonicalHeader(canonical, true) != canonical {
				t.Fatalf("relaxed header %q -> %q", field.raw, canonical)
			}
		}
		result := Verifier{LookupTXT: func(context.Context, string) ([]string, error) { return nil, nil }}.Verify(context.Background(), []byte(message))
		if len(result.Signatures) > maxVerifications {
			t.Fatalf("%d results", len(result.Signatures))
		}
	})
}
