package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	msgauth "github.com/emersion/go-msgauth/dkim"
)

// arcSealer is one forwarding hop's key and its published DNS record.
type arcSealer struct {
	domain, selector string
	key              *rsa.PrivateKey
	record           string
}

func newARCSealer(t *testing.T, domain string) arcSealer {
	t.Helper()
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return arcSealer{domain: domain, selector: "arc", key: key, record: DKIMDNSRecord(public)}
}

func arcVerifier(sealers ...arcSealer) Verifier {
	records := make(map[string]string)
	for _, sealer := range sealers {
		records[sealer.selector+"._domainkey."+sealer.domain] = sealer.record
	}
	return keys(records)
}

func (s arcSealer) seal(t *testing.T, message []byte, chain string) []byte {
	t.Helper()
	sealed, err := SealARC(message, ARCSealOptions{Domain: s.domain, Selector: s.selector, Key: s.key,
		AuthResults:     "mx." + s.domain + "; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
		ChainValidation: chain})
	if err != nil {
		t.Fatalf("seal by %s: %v", s.domain, err)
	}
	return sealed
}

func TestARCCanonicalizationMatchesDKIM(t *testing.T) {
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ParsePrivateKey(private)
	message := "From: alice@example.com\r\nTo:   bob@example.net\r\nSubject: Folded\r\n\tsubject  line \r\nSubject: Second\r\n\r\nBody  with   spaces \r\n\r\n\r\n"
	for _, canon := range []msgauth.Canonicalization{msgauth.CanonicalizationSimple, msgauth.CanonicalizationRelaxed} {
		signer, err := msgauth.NewSigner(&msgauth.SignOptions{Domain: "example.com", Selector: "s1", Signer: key,
			HeaderCanonicalization: canon, BodyCanonicalization: canon, HeaderKeys: []string{"from", "to", "subject", "subject", "subject"}})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = signer.Write([]byte(message))
		if err := signer.Close(); err != nil {
			t.Fatal(err)
		}
		fields, body := splitMessage([]byte(signer.Signature() + message))
		cache := keyCache{verifier: keys(map[string]string{"s1._domainkey.example.com": DKIMDNSRecord(public)})}
		if err := cache.verifyMessageSignature(context.Background(), fields, body, fields[0]); err != nil {
			t.Fatalf("%s: go-msgauth signature does not verify with ARC canonicalization: %v", canon, err)
		}
	}
}

func TestARCSingleSealVerifies(t *testing.T) {
	forwarder := newARCSealer(t, "forwarder.test")
	sealed := forwarder.seal(t, []byte(testMessage), ARCNone)
	if !bytes.HasPrefix(sealed, []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=forwarder.test; s=arc;")) {
		t.Fatalf("seal does not lead the message:\n%s", sealed)
	}
	result := arcVerifier(forwarder).VerifyARC(context.Background(), sealed)
	if result.Status != ARCPass || result.Instances != 1 || result.Sealer != "forwarder.test" {
		t.Fatalf("result = %+v, want pass by forwarder.test", result)
	}
	if result.SealerResults["dmarc"] != "pass" || result.SealerResults["spf"] != "pass" {
		t.Fatalf("sealer results = %v", result.SealerResults)
	}
	// Relaxed canonicalization tolerates transport refolding.
	refolded := bytes.Replace(sealed, []byte("Subject: Hello   there"), []byte("Subject: Hello\r\n there"), 1)
	if result := arcVerifier(forwarder).VerifyARC(context.Background(), refolded); result.Status != ARCPass {
		t.Fatalf("refolded result = %+v", result)
	}
	again := forwarder.seal(t, []byte(testMessage), ARCNone)
	if !bytes.Equal(again, sealed) {
		t.Fatal("sealing the same message twice differs")
	}
}

func TestARCTwoHopChainVerifies(t *testing.T) {
	first, second := newARCSealer(t, "first.test"), newARCSealer(t, "second.test")
	verifier := arcVerifier(first, second)
	hop1 := first.seal(t, []byte(testMessage), ARCNone)
	// The second hop changes the message (a list footer) before sealing; only
	// the newest ARC-Message-Signature has to match the message.
	changed := append(append([]byte(nil), hop1...), []byte("-- \r\nList footer\r\n")...)
	if result := verifier.VerifyARC(context.Background(), changed); result.Status != ARCFail {
		t.Fatalf("modified single-hop chain = %+v, want fail", result)
	}
	hop2 := second.seal(t, changed, ARCPass)
	result := verifier.VerifyARC(context.Background(), hop2)
	if result.Status != ARCPass || result.Instances != 2 || result.Sealer != "second.test" {
		t.Fatalf("result = %+v, want pass sealed by second.test", result)
	}
	if !strings.Contains(string(hop2), "ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=second.test") {
		t.Fatalf("second seal missing cv=pass:\n%s", hop2)
	}
}

func TestARCChainFailures(t *testing.T) {
	first, second := newARCSealer(t, "first.test"), newARCSealer(t, "second.test")
	verifier := arcVerifier(first, second)
	hop1 := first.seal(t, []byte(testMessage), ARCNone)
	hop2 := second.seal(t, hop1, ARCPass)
	ctx := context.Background()
	for _, tc := range []struct {
		name, reason string
		message      []byte
	}{
		{"body changed after seal", "body hash mismatch", append(append([]byte(nil), hop2...), "tampered\r\n"...)},
		{"signed header changed", "did not verify", bytes.Replace(hop2, []byte("Subject: Hello   there"), []byte("Subject: Hello there!"), 1)},
		{"older seal signature broken", "ARC-Seal i=2: signature did not verify", breakSeal(t, hop2, 1)},
		{"only seal signature broken", "ARC-Seal i=1: signature did not verify", breakSeal(t, hop1, 1)},
		{"wrong cv on instance 2", "cv=none, want pass", bytes.Replace(hop2, []byte("i=2; a=rsa-sha256; cv=pass"), []byte("i=2; a=rsa-sha256; cv=none"), 1)},
		{"older seal cv changed", "ARC-Seal i=2: signature did not verify", bytes.Replace(hop2, []byte("i=1; a=rsa-sha256; cv=none"), []byte("i=1; a=rsa-sha256; cv=pass"), 1)},
		{"signed cv=pass on instance 1", "cv=pass, want none", first.resealTop(t, hop1, ARCPass)},
		{"newest seal reports fail", "cv=fail", bytes.Replace(hop2, []byte("i=2; a=rsa-sha256; cv=pass"), []byte("i=2; a=rsa-sha256; cv=fail"), 1)},
		{"instance gap", "i=2 is missing", renumber(hop2, 2, 3)},
		{"duplicate instance", "duplicate", renumber(hop2, 2, 1)},
		{"instance out of range", "invalid instance", renumber(hop2, 2, 51)},
		{"unknown sealer key", "key lookup", hop2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verifier
			if tc.name == "unknown sealer key" {
				v = arcVerifier(first)
			}
			result := v.VerifyARC(ctx, tc.message)
			if result.Status != ARCFail || !strings.Contains(result.Reason, tc.reason) {
				t.Fatalf("result = %+v, want fail containing %q", result, tc.reason)
			}
		})
	}
	if result := verifier.VerifyARC(ctx, []byte(testMessage)); result.Status != ARCNone {
		t.Fatalf("unsealed message = %+v, want none", result)
	}
}

// resealTop replaces the newest ARC-Seal with a valid one claiming cv.
func (s arcSealer) resealTop(t *testing.T, message []byte, cv string) []byte {
	t.Helper()
	fields, _ := splitMessage(message)
	sets, count, err := collectARCSets(fields)
	if err != nil || count == 0 {
		t.Fatalf("no chain to reseal: %v", err)
	}
	top := sets[count].seal.raw
	pending := fmt.Sprintf("ARC-Seal: i=%d; a=rsa-sha256; cv=%s; d=%s; s=%s;\r\n\tb=", count, cv, s.domain, s.selector)
	digest := sha256.Sum256([]byte(sealInput(sets, count, pending)))
	signature, err := rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(message), top, pending+base64.StdEncoding.EncodeToString(signature)+"\r\n", 1))
}

// breakSeal flips one character of the signature of the ARC-Seal at
// instance.
func breakSeal(t *testing.T, message []byte, instance int) []byte {
	t.Helper()
	text := string(message)
	start := strings.Index(text, fmt.Sprintf("ARC-Seal: i=%d;", instance))
	b := strings.Index(text[start:], "b=") + start + 2
	if start < 0 || b < start+2 {
		t.Fatal("seal not found")
	}
	replacement := byte('A')
	if text[b] == 'A' {
		replacement = 'B'
	}
	return []byte(text[:b] + string(replacement) + text[b+1:])
}

// renumber rewrites the i= tag of every ARC field at instance from to to.
func renumber(message []byte, from, to int) []byte {
	text := string(message)
	for _, name := range []string{ARCSealField, ARCMessageSignField, ARCAuthResultsField} {
		text = strings.Replace(text, fmt.Sprintf("%s: i=%d;", name, from), fmt.Sprintf("%s: i=%d;", name, to), 1)
	}
	return []byte(text)
}

func TestARCBoundsKeyLookups(t *testing.T) {
	sealer := newARCSealer(t, "many.test")
	lookups := 0
	verifier := Verifier{LookupTXT: func(context.Context, string) ([]string, error) {
		lookups++
		return []string{sealer.record}, nil
	}}
	message := []byte(testMessage)
	for i := 1; i <= maxKeyLookups+2; i++ {
		hop := sealer
		hop.selector = fmt.Sprintf("s%d", i)
		chain := ARCNone
		if i > 1 {
			chain = ARCPass
		}
		message = hop.seal(t, message, chain)
	}
	result := verifier.VerifyARC(context.Background(), message)
	if result.Status != ARCFail || !strings.Contains(result.Reason, "too many distinct key lookups") || lookups != maxKeyLookups {
		t.Fatalf("result = %+v after %d lookups", result, lookups)
	}
}

func TestSealARCRefusesUnextendableChains(t *testing.T) {
	forwarder := newARCSealer(t, "forwarder.test")
	hop1 := forwarder.seal(t, []byte(testMessage), ARCNone)
	options := ARCSealOptions{Domain: "next.test", Selector: "arc", Key: forwarder.key, AuthResults: "mx.next.test; arc=fail"}
	for _, chain := range []string{ARCFail, ARCNone, ""} {
		options.ChainValidation = chain
		if _, err := SealARC(hop1, options); !errors.Is(err, ErrARCNotSealable) {
			t.Fatalf("chain %q: err = %v, want ErrARCNotSealable", chain, err)
		}
	}
	var full strings.Builder
	for i := 1; i <= MaxARCInstances; i++ {
		fmt.Fprintf(&full, "ARC-Seal: i=%d; cv=pass; d=x.test; s=a; b=AA==\r\nARC-Message-Signature: i=%d; d=x.test; s=a; b=AA==\r\nARC-Authentication-Results: i=%d; x.test; none\r\n", i, i, i)
	}
	options.ChainValidation = ARCPass
	if _, err := SealARC([]byte(full.String()+testMessage), options); !errors.Is(err, ErrARCNotSealable) {
		t.Fatalf("full chain: err = %v, want ErrARCNotSealable", err)
	}
	options.AuthResults = "mx.next.test;\r\n spf=pass"
	if _, err := SealARC([]byte(testMessage), options); err == nil {
		t.Fatal("multi-line authentication results were accepted")
	}
}

func TestStripSignatureKeepsBodyHash(t *testing.T) {
	raw := "ARC-Seal: i=1; bh=abcb=; d=x.test;\r\n\tb=ZZZ\r\n\t YYY\r\n"
	if got := stripSignature(raw); got != "ARC-Seal: i=1; bh=abcb=; d=x.test;\r\n\tb=\r\n" {
		t.Fatalf("stripSignature = %q", got)
	}
}

// TestARCMessageSignatureBodyLength refuses an ARC-Message-Signature whose
// l= leaves part of the body unsigned: a trusted sealer's vouching must
// not extend to content appended after it.
func TestARCMessageSignatureBodyLength(t *testing.T) {
	sealer := newARCSealer(t, "forwarder.test")
	sign := func(message string) headerField {
		fields, body := splitMessage([]byte(message))
		bodyHash := sha256.Sum256(canonicalBody(body, true)[:6])
		unsigned := "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=forwarder.test; s=arc; h=from:subject; l=6; bh=" +
			base64.StdEncoding.EncodeToString(bodyHash[:]) + "; b="
		var data strings.Builder
		for _, field := range selectHeaders(fields, []string{"from", "subject"}) {
			data.WriteString(canonicalHeader(field.raw, true))
		}
		data.WriteString(strings.TrimSuffix(canonicalHeader(unsigned, true), "\r\n"))
		digest := sha256.Sum256([]byte(data.String()))
		signature, err := rsa.SignPKCS1v15(nil, sealer.key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		raw := unsigned + base64.StdEncoding.EncodeToString(signature) + "\r\n"
		return headerField{key: arcMessageSignatureKey, raw: raw}
	}
	cache := keyCache{verifier: arcVerifier(sealer)}
	ams := sign(rawMessage)
	fields, body := splitMessage([]byte(rawMessage))
	if err := cache.verifyMessageSignature(context.Background(), fields, body, ams); err != nil {
		t.Fatalf("l= covering the body: %v", err)
	}
	fields, body = splitMessage([]byte(rawMessage + "appended\r\n"))
	if err := cache.verifyMessageSignature(context.Background(), fields, body, ams); err == nil || !strings.Contains(err.Error(), "body length") {
		t.Fatalf("l= leaving appended content unsigned: err = %v", err)
	}
}

func TestARCSealWithHeaderListFails(t *testing.T) {
	forwarder := newARCSealer(t, "forwarder.test")
	sealed := forwarder.seal(t, []byte(testMessage), ARCNone)
	fields, _ := splitMessage(sealed)
	sets, _, _ := collectARCSets(fields)
	pending := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=forwarder.test; s=arc; h=from;\r\n\tb="
	digest := sha256.Sum256([]byte(sealInput(sets, 1, pending)))
	signature, err := rsa.SignPKCS1v15(nil, forwarder.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(sealed), sets[1].seal.raw, pending+base64.StdEncoding.EncodeToString(signature)+"\r\n", 1)
	result := arcVerifier(forwarder).VerifyARC(context.Background(), []byte(forged))
	if result.Status != ARCFail || !strings.Contains(result.Reason, "h= tag") {
		t.Fatalf("result = %+v, want fail for h= on the seal", result)
	}
}
