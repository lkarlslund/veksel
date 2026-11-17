package dkim

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	msgauth "github.com/emersion/go-msgauth/dkim"
)

// crlf converts a test literal written with LF line ends to CRLF.
func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

// rfc8463Message is the signed example of RFC 8463 Appendix A.3: one
// Ed25519 and one RSA signature by football.example.com, with oversigned
// From, Subject, and Date fields.
const rfc8463Message = `DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.
`

// rfc8463Keys are the key records of RFC 8463 Appendix A.2.
var rfc8463Keys = map[string]string{
	"brisbane._domainkey.football.example.com": "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
	"test._domainkey.football.example.com": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/" +
		"J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
}

func TestVerifyRFC8463Vectors(t *testing.T) {
	result := keys(rfc8463Keys).Verify(context.Background(), crlf(rfc8463Message))
	if len(result.Signatures) != 2 {
		t.Fatalf("signatures = %+v, want 2", result.Signatures)
	}
	for _, signature := range result.Signatures {
		if signature.Status != StatusPass {
			t.Errorf("%s/%s: %s (%s), want pass", signature.Selector, signature.Algorithm, signature.Status, signature.Reason)
		}
	}
	if result.Signatures[0].Algorithm != "ed25519-sha256" || result.Signatures[1].Algorithm != "rsa-sha256" {
		t.Errorf("algorithms = %q, %q", result.Signatures[0].Algorithm, result.Signatures[1].Algorithm)
	}
	// Oversigning: a second From field added below the signed one is
	// selected by the second h=from and breaks both signatures.
	forged := strings.Replace(rfc8463Message, "\nTo: Suzie", "\nFrom: mallory@evil.example\nTo: Suzie", 1)
	forgedResult := keys(rfc8463Keys).Verify(context.Background(), crlf(forged))
	if forgedResult.Pass {
		t.Fatalf("message with an added From field passed: %+v", forgedResult.Signatures)
	}
	// Relaxed body canonicalization tolerates trailing white space and
	// extra empty lines.
	padded := strings.Replace(rfc8463Message, "Joe.\n", "Joe.  \n\n\n", 1)
	if result := keys(rfc8463Keys).Verify(context.Background(), crlf(padded)); !result.Pass || len(result.PassingDomains()) != 1 {
		t.Fatalf("relaxed padding: %+v", result.Signatures)
	}
}

// TestVerifyRFC6376AppendixA verifies the simple/simple example of RFC
// 6376 Appendix A, including a non-default i= in a subdomain of d=.
func TestVerifyRFC6376AppendixA(t *testing.T) {
	message := `DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
      4bmp/YzhwvcubU4=;
Received: from client1.football.example.com  [192.0.2.1]
      by submitserver.example.com with SUBMISSION;
      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.
`
	record := "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
		"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
		"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"
	verifier := keys(map[string]string{"brisbane._domainkey.example.com": record})
	result := verifier.Verify(context.Background(), crlf(message))
	if !result.Pass || result.Signatures[0].Identifier != "joe@football.example.com" {
		t.Fatalf("result = %+v", result.Signatures)
	}
	// Simple canonicalization is sensitive to white space in the body.
	changed := strings.Replace(message, "Are you hungry", "Are  you hungry", 1)
	if result := verifier.Verify(context.Background(), crlf(changed)); result.Status != StatusFail {
		t.Fatalf("simple body change: %+v", result.Signatures)
	}
	// A key published with t=s forbids the i= subdomain.
	strict := keys(map[string]string{"brisbane._domainkey.example.com": record + "; t=s"})
	if result := strict.Verify(context.Background(), crlf(message)); result.Status != StatusPermError || !strings.Contains(result.Reason, "t=s") {
		t.Fatalf("t=s with i= subdomain: %+v", result.Signatures)
	}
}

// TestCanonicalizationRFC6376Example checks the worked example of RFC 6376
// section 3.4.6.
func TestCanonicalizationRFC6376Example(t *testing.T) {
	message := []byte("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n")
	fields, body := splitMessage(message)
	var relaxed, simple strings.Builder
	for _, field := range fields {
		relaxed.WriteString(canonicalHeader(field.raw, true))
		simple.WriteString(canonicalHeader(field.raw, false))
	}
	if got, want := relaxed.String(), "a:X\r\nb:Y Z\r\n"; got != want {
		t.Errorf("relaxed header = %q, want %q", got, want)
	}
	if got, want := simple.String(), "A: X\r\nB : Y\t\r\n\tZ  \r\n"; got != want {
		t.Errorf("simple header = %q, want %q", got, want)
	}
	if got, want := string(canonicalBody(body, true)), " C\r\nD E\r\n"; got != want {
		t.Errorf("relaxed body = %q, want %q", got, want)
	}
	if got, want := string(canonicalBody(body, false)), " C \r\nD \t E\r\n"; got != want {
		t.Errorf("simple body = %q, want %q", got, want)
	}
	// Empty bodies: simple is one CRLF, relaxed is empty (RFC 6376 section
	// 3.4.3 and 3.4.4, erratum 3192).
	if got := string(canonicalBody(nil, false)); got != "\r\n" {
		t.Errorf("simple empty body = %q", got)
	}
	if got := canonicalBody([]byte("\r\n\r\n"), true); len(got) != 0 {
		t.Errorf("relaxed empty body = %q", got)
	}
	// A body without a final line break gains one.
	if got := string(canonicalBody([]byte("abc"), false)); got != "abc\r\n" {
		t.Errorf("simple unterminated body = %q", got)
	}
}

// rawSigner builds DKIM-Signature fields with arbitrary tags, so tests can
// exercise tags a conforming signer never writes.
type rawSigner struct {
	domain, selector string
	key              crypto.Signer
	algorithm        string
}

func newRawSigner(t *testing.T, domain, selector string) (rawSigner, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return rawSigner{domain: domain, selector: selector, key: key, algorithm: "rsa-sha256"}, "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// sign prepends a relaxed/relaxed signature over the From and Subject
// fields; extra is inserted verbatim before bh=.
func (s rawSigner) sign(t *testing.T, message, extra string) []byte {
	t.Helper()
	fields, body := splitMessage([]byte(message))
	bodyHash := sha256.Sum256(canonicalBody(body, true))
	unsigned := "DKIM-Signature: v=1; a=" + s.algorithm + "; c=relaxed/relaxed; d=" + s.domain + "; s=" + s.selector +
		"; h=from:subject; " + extra + "bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]) + "; b="
	var data strings.Builder
	for _, field := range selectHeaders(fields, []string{"from", "subject"}) {
		data.WriteString(canonicalHeader(field.raw, true))
	}
	data.WriteString(canonicalHeader(unsigned, true))
	digest := sha256.Sum256([]byte(strings.TrimSuffix(data.String(), "\r\n")))
	var signature []byte
	var err error
	if _, ok := s.key.(ed25519.PrivateKey); ok {
		signature, err = s.key.Sign(rand.Reader, digest[:], crypto.Hash(0))
	} else {
		signature, err = s.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	return []byte(unsigned + base64.StdEncoding.EncodeToString(signature) + "\r\n" + message)
}

const rawMessage = "From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"

func TestVerifySignatureTagRules(t *testing.T) {
	signer, record := newRawSigner(t, "example.com", "s1")
	verifier := keys(map[string]string{"s1._domainkey.example.com": record})
	verifier.Now = func() time.Time { return time.Unix(2_000_000_000, 0) }
	for _, test := range []struct {
		name, extra, status, reason string
	}{
		{"plain", "", StatusPass, ""},
		{"uppercase AUID domain", "i=alice@Mail.EXAMPLE.com; ", StatusPass, ""},
		{"AUID outside SDID", "i=alice@example.net; ", StatusPermError, "not within d="},
		{"AUID suffix trick", "i=alice@badexample.com; ", StatusPermError, "not within d="},
		{"unexpired", "t=1999999000; x=2000000100; ", StatusPass, ""},
		{"expired", "t=1999999000; x=1999999999; ", StatusPermError, "expired"},
		{"negative expiry", "x=-1; ", StatusPermError, "malformed x="},
		{"duplicate tag", "s=s1; ", StatusPermError, "duplicate"},
		{"unknown tag", "zb=keep; ", StatusPass, ""},
		{"unknown query method", "q=http/well-known; ", StatusPermError, "query method"},
		{"full body length", "l=6; ", StatusPass, ""},
		{"body longer than l=", "l=4; ", StatusFail, "body hash"},
		{"body shorter than l=", "l=60; ", StatusFail, "shorter than l="},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := verifier.Verify(context.Background(), signer.sign(t, rawMessage, test.extra))
			got := result.Signatures[0]
			if got.Status != test.status || !strings.Contains(got.Reason, test.reason) {
				t.Fatalf("status = %s (%s), want %s (%s)", got.Status, got.Reason, test.status, test.reason)
			}
		})
	}
}

func TestVerifyBodyLengthLeavesAppendedContentUnsigned(t *testing.T) {
	signer, record := newRawSigner(t, "example.com", "s1")
	verifier := keys(map[string]string{"s1._domainkey.example.com": record})
	signed := signer.sign(t, rawMessage, "l=6; ")
	appended := append(append([]byte(nil), signed...), "Click http://phish.example/\r\n"...)
	result := verifier.Verify(context.Background(), appended)
	if result.Pass || result.Status != StatusPolicy || len(result.PassingDomains()) != 0 {
		t.Fatalf("appended content after l=: %+v", result.Signatures)
	}
}

func TestVerifyKeyRecordRules(t *testing.T) {
	signer, record := newRawSigner(t, "example.com", "s1")
	edPublic, edPrivate, _ := ed25519.GenerateKey(rand.Reader)
	edRecord := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edPublic)
	// Go refuses to generate RSA keys under 1024 bits; a 512-bit modulus
	// is enough for the record parser to reject.
	modulus := new(big.Int).Lsh(big.NewInt(1), 511)
	shortDER, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus.Add(modulus, big.NewInt(1)), E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		records []string
		status  string
		reason  string
		testing bool
	}{
		{"revoked", []string{"v=DKIM1; p="}, StatusPermError, "revoked", false},
		{"hash restricted", []string{record + "; h=sha1"}, StatusPermError, "hash", false},
		{"hash allowed", []string{record + "; h=sha1:sha256"}, StatusPass, "", false},
		{"other service", []string{record + "; s=tlsrpt"}, StatusPermError, "e-mail", false},
		{"any service", []string{record + "; s=*"}, StatusPass, "", false},
		{"key type mismatch", []string{edRecord}, StatusPermError, "key type", false},
		{"testing", []string{record + "; t=y"}, StatusPass, "", true},
		{"short RSA key", []string{"v=DKIM1; p=" + base64.StdEncoding.EncodeToString(shortDER)}, StatusPermError, "too short", false},
		{"wrong version", []string{"v=DKIM2; " + strings.TrimPrefix(record, "v=DKIM1; ")}, StatusPermError, "version", false},
		{"garbage then valid", []string{"not a key", record}, StatusPass, "", false},
		{"no record", nil, StatusPermError, "no key", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := Verifier{LookupTXT: func(context.Context, string) ([]string, error) { return test.records, nil }}
			got := verifier.Verify(context.Background(), signer.sign(t, rawMessage, "")).Signatures[0]
			if got.Status != test.status || !strings.Contains(got.Reason, test.reason) || got.Testing != test.testing {
				t.Fatalf("got %+v, want %s (%s) testing=%v", got, test.status, test.reason, test.testing)
			}
		})
	}
	ed := rawSigner{domain: "example.com", selector: "ed", key: edPrivate, algorithm: "ed25519-sha256"}
	verifier := keys(map[string]string{"ed._domainkey.example.com": edRecord})
	if result := verifier.Verify(context.Background(), ed.sign(t, rawMessage, "")); !result.Pass {
		t.Fatalf("ed25519: %+v", result.Signatures)
	}
}

func TestVerifyRejectsRSASHA1(t *testing.T) {
	signer, record := newRawSigner(t, "example.com", "s1")
	signer.algorithm = "rsa-sha1"
	got := keys(map[string]string{"s1._domainkey.example.com": record}).Verify(context.Background(), signer.sign(t, rawMessage, "")).Signatures[0]
	if got.Status != StatusPermError || !strings.Contains(got.Reason, "8301") {
		t.Fatalf("rsa-sha1: %+v", got)
	}
}

// TestVerifyReportsEverySignature covers a mailing-list style message: an
// unaligned third-party signature that passes, followed by the author's
// aligned one. DMARC must see both passing domains, not only the first.
func TestVerifyReportsEverySignature(t *testing.T) {
	author, authorRecord := newRawSigner(t, "example.com", "a")
	provider, providerRecord := newRawSigner(t, "esp.example", "p")
	broken, _ := newRawSigner(t, "broken.example", "b")
	message := author.sign(t, rawMessage, "")
	message = provider.sign(t, string(message), "")
	message = broken.sign(t, string(message), "")
	verifier := keys(map[string]string{"a._domainkey.example.com": authorRecord, "p._domainkey.esp.example": providerRecord})
	result := verifier.Verify(context.Background(), message)
	statuses := make([]string, 0, len(result.Signatures))
	for _, signature := range result.Signatures {
		statuses = append(statuses, signature.Domain+"="+signature.Status)
	}
	if want := []string{"broken.example=permerror", "esp.example=pass", "example.com=pass"}; !slices.Equal(statuses, want) {
		t.Fatalf("signatures = %v, want %v", statuses, want)
	}
	if got := result.PassingDomains(); !slices.Equal(got, []string{"esp.example", "example.com"}) {
		t.Fatalf("passing domains = %v", got)
	}
	if !result.Pass || result.Domain != "esp.example" || result.Selector != "p" {
		t.Fatalf("summary = %+v", result)
	}
}

func TestVerifyBoundsSignatureCount(t *testing.T) {
	signer, record := newRawSigner(t, "example.com", "s1")
	message := []byte(rawMessage)
	for range maxVerifications + 3 {
		message = signer.sign(t, string(message), "")
	}
	lookups := 0
	verifier := Verifier{LookupTXT: func(context.Context, string) ([]string, error) { lookups++; return []string{record}, nil }}
	result := verifier.Verify(context.Background(), message)
	if len(result.Signatures) != maxVerifications || lookups != 1 || !result.Pass {
		t.Fatalf("signatures = %d, lookups = %d, pass = %v", len(result.Signatures), lookups, result.Pass)
	}
}

func TestStripSignatureOnlyEmptiesTheBTag(t *testing.T) {
	raw := "DKIM-Signature: v=1; zb=keep; bh=abcb= ; b = sig\r\n\tnature ;\r\n"
	if got, want := stripSignature(raw), "DKIM-Signature: v=1; zb=keep; bh=abcb= ; b =;\r\n"; got != want {
		t.Fatalf("stripSignature = %q, want %q", got, want)
	}
}

// TestVerifyMatchesGoMsgauthSigner keeps the verifier interoperable with
// the signer used for outbound mail across both canonicalizations and
// oversigned header lists.
func TestVerifyMatchesGoMsgauthSigner(t *testing.T) {
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ParsePrivateKey(private)
	message := "From: alice@example.com\r\nTo:   bob@example.net\r\nSubject: Folded\r\n\tsubject  line \r\nSubject: Second\r\n\r\nBody  with   spaces \r\n\r\n\r\n"
	verifier := keys(map[string]string{"s1._domainkey.example.com": DKIMDNSRecord(public)})
	for _, canon := range []msgauth.Canonicalization{msgauth.CanonicalizationSimple, msgauth.CanonicalizationRelaxed} {
		signer, err := msgauth.NewSigner(&msgauth.SignOptions{Domain: "example.com", Selector: "s1", Signer: key, Identifier: "alice@example.com",
			HeaderCanonicalization: canon, BodyCanonicalization: canon, HeaderKeys: []string{"from", "to", "subject", "subject", "subject"}})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = signer.Write([]byte(message))
		if err := signer.Close(); err != nil {
			t.Fatal(err)
		}
		if result := verifier.Verify(context.Background(), []byte(signer.Signature()+message)); !result.Pass {
			t.Fatalf("%s: %+v", canon, result.Signatures)
		}
	}
}
