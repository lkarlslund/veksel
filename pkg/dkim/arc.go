package dkim

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ARC (RFC 8617) header fields and limits.
const (
	ARCSealField           = "ARC-Seal"
	ARCMessageSignField    = "ARC-Message-Signature"
	ARCAuthResultsField    = "ARC-Authentication-Results"
	arcSealKey             = "arc-seal"
	arcMessageSignatureKey = "arc-message-signature"
	arcAuthResultsKey      = "arc-authentication-results"
	// MaxARCInstances is the highest ARC instance RFC 8617 section 4.2.1
	// allows; a longer chain fails and is never extended.
	MaxARCInstances = 50
	// minRSABits rejects keys too weak to trust (RFC 8301).
	minRSABits = 1024
)

// ARC chain validation states, the cv= values and arc= results.
const (
	ARCNone = "none"
	ARCPass = "pass"
	ARCFail = "fail"
)

// ErrARCNotSealable reports a message whose ARC chain must not be extended:
// a failed or unvalidated chain, or one already at MaxARCInstances.
var ErrARCNotSealable = errors.New("ARC chain cannot be extended")

// ARCResult is the outcome of validating a message's ARC chain.
type ARCResult struct {
	// Status is none (no ARC sets), pass, or fail.
	Status string
	// Reason explains a failure.
	Reason string
	// Instances is the number of ARC sets in the chain.
	Instances int
	// Sealer is the d= domain of the most recent ARC-Seal: the last hop
	// that vouched for the message, whose results a receiver may trust.
	Sealer string
	// SealerResults maps each method in the most recent
	// ARC-Authentication-Results to its result, such as dmarc=pass.
	SealerResults map[string]string
}

// arcSet is one instance's three header fields.
type arcSet struct {
	aar, ams, seal *headerField
}

// VerifyARC validates the ARC chain of a complete raw message per RFC 8617
// section 5.2: every instance from 1 to the highest present exactly once
// with all three fields, the most recent ARC-Message-Signature valid for
// the message as received, and every ARC-Seal valid with cv=none at
// instance 1 and cv=pass above it.
func (v Verifier) VerifyARC(ctx context.Context, message []byte) *ARCResult {
	fields, body := splitMessage(message)
	sets, count, err := collectARCSets(fields)
	if err != nil {
		return &ARCResult{Status: ARCFail, Reason: err.Error(), Instances: count}
	}
	if count == 0 {
		return &ARCResult{Status: ARCNone}
	}
	result := &ARCResult{Status: ARCFail, Instances: count}
	latest := tagList(sets[count].seal.value())
	if latest["cv"] == ARCFail {
		result.Reason = "most recent ARC-Seal reports cv=fail"
		return result
	}
	keys := keyCache{verifier: v}
	if err := keys.verifyMessageSignature(ctx, fields, body, *sets[count].ams); err != nil {
		result.Reason = fmt.Sprintf("ARC-Message-Signature i=%d: %v", count, err)
		return result
	}
	for instance := count; instance >= 1; instance-- {
		tags, err := parseTags(sets[instance].seal.value())
		if err != nil {
			result.Reason = fmt.Sprintf("ARC-Seal i=%d: %v", instance, err)
			return result
		}
		if _, ok := tags["h"]; ok {
			// RFC 8617 section 4.1.3: an ARC-Seal never carries h=.
			result.Reason = fmt.Sprintf("ARC-Seal i=%d has an h= tag", instance)
			return result
		}
		want := ARCPass
		if instance == 1 {
			want = ARCNone
		}
		if tags["cv"] != want {
			result.Reason = fmt.Sprintf("ARC-Seal i=%d has cv=%s, want %s", instance, tags["cv"], want)
			return result
		}
		if err := keys.verify(ctx, tags, sealInput(sets, instance, "")); err != nil {
			result.Reason = fmt.Sprintf("ARC-Seal i=%d: %v", instance, err)
			return result
		}
	}
	result.Status, result.Sealer = ARCPass, strings.ToLower(latest["d"])
	result.SealerResults = parseAuthResults(sets[count].aar.value())
	return result
}

// collectARCSets groups the ARC fields by instance. It returns the highest
// instance and an error for a malformed, duplicated, out-of-range, or
// incomplete set.
func collectARCSets(fields []headerField) (map[int]*arcSet, int, error) {
	sets := make(map[int]*arcSet)
	highest := 0
	for i := range fields {
		field := &fields[i]
		if field.key != arcSealKey && field.key != arcMessageSignatureKey && field.key != arcAuthResultsKey {
			continue
		}
		instance, err := arcInstance(field)
		if err != nil {
			return nil, highest, err
		}
		set := sets[instance]
		if set == nil {
			set = &arcSet{}
			sets[instance] = set
		}
		slot := map[string]**headerField{arcSealKey: &set.seal, arcMessageSignatureKey: &set.ams, arcAuthResultsKey: &set.aar}[field.key]
		if *slot != nil {
			return nil, highest, fmt.Errorf("duplicate %s for i=%d", field.key, instance)
		}
		*slot = field
		highest = max(highest, instance)
	}
	for instance := 1; instance <= highest; instance++ {
		set := sets[instance]
		if set == nil || set.aar == nil || set.ams == nil || set.seal == nil {
			return nil, highest, fmt.Errorf("ARC set i=%d is missing or incomplete", instance)
		}
	}
	return sets, highest, nil
}

// arcInstance parses the i= tag that opens every ARC field.
func arcInstance(field *headerField) (int, error) {
	value := field.value()
	if field.key == arcAuthResultsKey {
		value, _, _ = strings.Cut(value, ";")
	}
	text := tagList(value)["i"]
	instance, err := strconv.Atoi(text)
	if err != nil || instance < 1 || instance > MaxARCInstances {
		return 0, fmt.Errorf("%s has invalid instance %q", field.key, text)
	}
	return instance, nil
}

// sealInput is the RFC 8617 section 5.1.1 data an ARC-Seal at instance
// signs: every set from 1 up to it, AAR, AMS, then AS, relaxed, with the
// sealing field's own signature removed and no final CRLF. A non-empty
// pending field stands in for that instance's seal.
func sealInput(sets map[int]*arcSet, instance int, pending string) string {
	var data strings.Builder
	for i := 1; i <= instance; i++ {
		data.WriteString(canonicalHeader(sets[i].aar.raw, true))
		data.WriteString(canonicalHeader(sets[i].ams.raw, true))
		if i < instance {
			data.WriteString(canonicalHeader(sets[i].seal.raw, true))
		}
	}
	seal := pending
	if seal == "" {
		seal = sets[instance].seal.raw
	}
	data.WriteString(strings.TrimSuffix(canonicalHeader(stripSignature(seal), true), "\r\n"))
	return data.String()
}

// parseAuthResults maps each method of an Authentication-Results style
// value (after an optional i= instance and the authserv-id) to its result.
func parseAuthResults(value string) map[string]string {
	results := make(map[string]string)
	parts := strings.Split(value, ";")
	if len(parts) > 0 && strings.HasPrefix(strings.TrimSpace(parts[0]), "i=") {
		parts = parts[1:]
	}
	if len(parts) > 0 {
		parts = parts[1:] // authserv-id
	}
	for _, part := range parts {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		method, outcome, ok := strings.Cut(fields[0], "=")
		if !ok {
			continue
		}
		method = strings.ToLower(method)
		if _, seen := results[method]; !seen {
			results[method] = strings.ToLower(outcome)
		}
	}
	return results
}

// verifyMessageSignature checks an ARC-Message-Signature against the
// message as received. It follows DKIM (RFC 8617 section 4.1.2), except
// that a body length limit must cover the whole body: a seal vouching for
// a prefix would let anyone append content to a trusted forward.
func (k *keyCache) verifyMessageSignature(ctx context.Context, fields []headerField, body []byte, signature headerField) error {
	tags, err := parseTags(signature.value())
	if err != nil {
		return err
	}
	for _, required := range []string{"a", "b", "bh", "d", "h", "s"} {
		if tags[required] == "" {
			return fmt.Errorf("missing %s= tag", required)
		}
	}
	headerCanon, bodyCanon, err := parseCanonicalization(tags["c"])
	if err != nil {
		return err
	}
	names := colonList(tags["h"])
	if slices.Contains(names, arcSealKey) {
		return errors.New("signature covers ARC-Seal")
	}
	canonical := canonicalBody(body, bodyCanon == "relaxed")
	if length, ok := tags["l"]; ok {
		limit, err := strconv.Atoi(length)
		if err != nil || limit != len(canonical) {
			return errors.New("body length limit does not cover the body")
		}
	}
	bodyHash := sha256.Sum256(canonical)
	if base64.StdEncoding.EncodeToString(bodyHash[:]) != tags["bh"] {
		return errors.New("body hash mismatch")
	}
	relaxed := headerCanon == "relaxed"
	var data strings.Builder
	for _, field := range selectHeaders(fields, names) {
		data.WriteString(canonicalHeader(field.raw, relaxed))
	}
	data.WriteString(strings.TrimSuffix(canonicalHeader(stripSignature(signature.raw), relaxed), "\r\n"))
	return k.verify(ctx, tags, data.String())
}

// ARCSealOptions describe the ARC set a sealer adds.
type ARCSealOptions struct {
	// Domain and Selector name the sealing key in DNS.
	Domain, Selector string
	// Key is the sealing domain's private key.
	Key *rsa.PrivateKey
	// AuthResults is this hop's Authentication-Results value, starting with
	// its authserv-id, recorded in the ARC-Authentication-Results field.
	AuthResults string
	// ChainValidation is this hop's validation of the incoming chain (an
	// ARCResult status). A message that already carries ARC sets is sealed
	// only when it is pass; the first set is always cv=none.
	ChainValidation string
	// Headers are the fields the ARC-Message-Signature covers; empty uses
	// DefaultHeaders plus DKIM-Signature.
	Headers []string
}

// SealARC returns message with a new ARC set (RFC 8617 section 5.1)
// prepended: ARC-Authentication-Results carrying this hop's results, an
// ARC-Message-Signature over the message as forwarded, and an ARC-Seal over
// the whole chain. It returns ErrARCNotSealable for a chain that failed or
// was not validated and for one already at MaxARCInstances. The fields carry
// no timestamp, so sealing the same message twice yields the same bytes.
func SealARC(message []byte, options ARCSealOptions) ([]byte, error) {
	if options.Key == nil || options.Domain == "" || options.Selector == "" {
		return nil, errors.New("ARC sealing requires a domain, selector, and key")
	}
	authResults := strings.TrimSpace(options.AuthResults)
	if authResults == "" || strings.ContainsAny(authResults, "\r\n") {
		return nil, errors.New("ARC sealing requires single-line authentication results")
	}
	fields, body := splitMessage(message)
	sets, count, err := collectARCSets(fields)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrARCNotSealable, err)
	case count >= MaxARCInstances:
		return nil, fmt.Errorf("%w: chain already has %d sets", ErrARCNotSealable, count)
	case count > 0 && options.ChainValidation != ARCPass:
		return nil, fmt.Errorf("%w: incoming chain is %q", ErrARCNotSealable, options.ChainValidation)
	}
	cv := ARCNone
	if count > 0 {
		cv = ARCPass
	}
	instance := count + 1
	sign := func(data string) (string, error) {
		digest := sha256.Sum256([]byte(data))
		signature, err := rsa.SignPKCS1v15(rand.Reader, options.Key, crypto.SHA256, digest[:])
		if err != nil {
			return "", err
		}
		return foldBase64(base64.StdEncoding.EncodeToString(signature)), nil
	}

	aar := headerField{key: arcAuthResultsKey, raw: fmt.Sprintf("%s: i=%d; %s\r\n", ARCAuthResultsField, instance, authResults)}

	names := options.Headers
	if len(names) == 0 {
		names = append(slices.Clone(DefaultHeaders), "dkim-signature")
	}
	var signed []string
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == arcSealKey || name == arcMessageSignatureKey || name == arcAuthResultsKey || slices.Contains(signed, name) {
			continue
		}
		for _, field := range fields {
			if field.key == name {
				signed = append(signed, name)
			}
		}
	}
	bodyHash := sha256.Sum256(canonicalBody(body, true))
	amsUnsigned := fmt.Sprintf("%s: i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s;\r\n\th=%s;\r\n\tbh=%s;\r\n\tb=", ARCMessageSignField, instance,
		options.Domain, options.Selector, strings.Join(signed, ":"), base64.StdEncoding.EncodeToString(bodyHash[:]))
	var data strings.Builder
	for _, field := range selectHeaders(fields, signed) {
		data.WriteString(canonicalHeader(field.raw, true))
	}
	data.WriteString(canonicalHeader(amsUnsigned, true))
	amsSignature, err := sign(strings.TrimSuffix(data.String(), "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("sign ARC-Message-Signature: %w", err)
	}
	ams := headerField{key: arcMessageSignatureKey, raw: amsUnsigned + amsSignature + "\r\n"}

	sealUnsigned := fmt.Sprintf("%s: i=%d; a=rsa-sha256; cv=%s; d=%s; s=%s;\r\n\tb=", ARCSealField, instance, cv, options.Domain, options.Selector)
	sets[instance] = &arcSet{aar: &aar, ams: &ams}
	sealSignature, err := sign(sealInput(sets, instance, sealUnsigned))
	if err != nil {
		return nil, fmt.Errorf("sign ARC-Seal: %w", err)
	}
	header := sealUnsigned + sealSignature + "\r\n" + ams.raw + aar.raw
	return append([]byte(header), message...), nil
}
