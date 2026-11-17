package dkim

import (
	"context"
	"testing"
)

// FuzzARC feeds arbitrary messages through ARC chain validation and sealing,
// and arbitrary DNS answers through the key-record and tag-list parsers.
func FuzzARC(f *testing.F) {
	for _, seed := range []struct{ message, record string }{
		{"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=s1; b=abc=\r\n" +
			"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1; h=from; bh=abc=; b=abc=\r\n" +
			"ARC-Authentication-Results: i=1; mx.example.com; spf=pass smtp.mailfrom=a@example.com; dkim=pass header.d=example.com\r\n" +
			"From: a@example.com\r\n\r\nbody\r\n", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"},
		{"ARC-Seal: i=0\r\nARC-Seal: i=51\r\nARC-Seal: i=x\r\n\r\n", "k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
		{testMessage, "v=DKIM1; p="},
		{"", ""},
		{"\r\n\r\n", "p=\x00\xff"},
	} {
		f.Add(seed.message, seed.record)
	}
	pemKey, _, err := GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	private, err := ParsePrivateKey(pemKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, message, record string) {
		verifier := Verifier{LookupTXT: func(context.Context, string) ([]string, error) { return []string{record}, nil }}
		result := verifier.VerifyARC(context.Background(), []byte(message))
		_, _ = SealARC([]byte(message), ARCSealOptions{
			Domain: "example.com", Selector: "s1", Key: private,
			AuthResults: "mx.example.com; spf=pass", ChainValidation: result.Status,
		})
		_, _ = parseKeyRecord(record)
		_ = tagList(record)
		_, _ = parseTags(record)
		_ = parseAuthResults(record)
		fields, body := splitMessage([]byte(message))
		for _, field := range fields {
			_ = canonicalHeader(field.raw, true)
			_ = canonicalHeader(field.raw, false)
			_ = stripSignature(field.raw)
		}
		_ = canonicalBody(body, true)
		_ = canonicalBody(body, false)
	})
}
