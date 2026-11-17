package dkim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// maxVerifications bounds the DKIM-Signature fields verified for one
	// message; later fields are ignored, as RFC 6376 section 6.1 allows.
	maxVerifications = 5
	// maxKeyLookups bounds the distinct key lookups of one message, so a
	// crafted 50-set ARC chain cannot cost 50 DNS queries.
	maxKeyLookups = 8
)

// DKIM results (RFC 8601 section 2.7.1).
const (
	StatusPass      = "pass"
	StatusFail      = "fail"
	StatusNone      = "none"
	StatusPolicy    = "policy"
	StatusTempError = "temperror"
	StatusPermError = "permerror"
)

// SignatureResult is the verification outcome of one DKIM-Signature field.
type SignatureResult struct {
	// Domain is the lower-case signing domain (SDID) from d=.
	Domain string
	// Selector is the s= tag.
	Selector string
	// Identifier is the AUID from i=, "@" plus Domain when absent.
	Identifier string
	// Algorithm is the a= tag.
	Algorithm string
	// Signature is the b= value without white space; Authentication-Results
	// identifies the signature by a prefix of it (RFC 6008).
	Signature string
	// Status is pass, fail, policy, temperror, or permerror.
	Status string
	// Reason explains any status but pass.
	Reason string
	// Testing reports a key published with t=y. RFC 6376 section 3.6.1
	// requires a failure under a testing key to be treated as unsigned mail.
	Testing bool
}

// VerifyResult captures the outcome of DKIM verification.
type VerifyResult struct {
	// Domain is the signing domain of the summary signature: the first that
	// passed, or the first verified when none passed.
	Domain string

	// Selector is the summary signature's s= tag.
	Selector string

	// Pass indicates whether any signature verified.
	Pass bool

	// Status is the summary signature's result, or none when the message
	// carries no DKIM-Signature field.
	Status string

	// Reason is a human-readable explanation when verification failed.
	Reason string

	// Testing reports that the summary signature's key is in testing mode.
	Testing bool

	// HeaderValue is the value for the DKIM-Verification-Result header.
	HeaderValue string

	// Signatures holds every verified signature in header order. DMARC
	// considers each passing signature's domain, and Authentication-Results
	// reports each one.
	Signatures []SignatureResult
}

// PassingDomains returns the distinct signing domains of the passing
// signatures, the DKIM identifiers DMARC may align with.
func (r *VerifyResult) PassingDomains() []string {
	if r == nil {
		return nil
	}
	var domains []string
	for _, signature := range r.Signatures {
		if signature.Status == StatusPass && !slices.Contains(domains, signature.Domain) {
			domains = append(domains, signature.Domain)
		}
	}
	return domains
}

// Verifier verifies DKIM signatures. The zero value uses the system resolver.
type Verifier struct {
	// LookupTXT resolves DKIM key records such as "s1._domainkey.example.com".
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// Now returns the verification time; nil uses time.Now.
	Now func() time.Time
}

// VerifyMessage verifies a message with the zero Verifier.
func VerifyMessage(ctx context.Context, message []byte) *VerifyResult {
	return Verifier{}.Verify(ctx, message)
}

// Verify performs RFC 6376 section 6 verification of every DKIM-Signature
// field of a complete raw message, up to maxVerifications of them.
func (v Verifier) Verify(ctx context.Context, message []byte) *VerifyResult {
	fields, body := splitMessage(message)
	var signatures []headerField
	for _, field := range fields {
		if field.key == "dkim-signature" {
			signatures = append(signatures, field)
		}
	}
	if len(signatures) == 0 {
		return &VerifyResult{Status: StatusNone, Reason: "no DKIM-Signature header found", HeaderValue: "none; reason=no-signature"}
	}
	if len(signatures) > maxVerifications {
		log.Debug("dkim: ignoring excess signatures", "count", len(signatures), "limit", maxVerifications)
		signatures = signatures[:maxVerifications]
	}
	verification := messageVerification{verifier: v, fields: fields, body: body, keys: keyCache{verifier: v}}
	result := &VerifyResult{}
	for _, field := range signatures {
		result.Signatures = append(result.Signatures, verification.verify(ctx, field))
	}
	summary := result.Signatures[0]
	for _, signature := range result.Signatures {
		if signature.Status == StatusPass {
			summary = signature
			break
		}
	}
	result.Domain, result.Selector, result.Status = summary.Domain, summary.Selector, summary.Status
	result.Pass, result.Reason, result.Testing = summary.Status == StatusPass, summary.Reason, summary.Testing
	if result.Pass {
		result.HeaderValue = fmt.Sprintf("pass; domain=%s; selector=%s", result.Domain, result.Selector)
	} else {
		result.HeaderValue = fmt.Sprintf("%s; domain=%s; selector=%s; reason=%q", result.Status, result.Domain, result.Selector, result.Reason)
	}
	return result
}

// messageVerification holds the state shared by the signatures of one
// message: its fields, canonical bodies, and resolved keys.
type messageVerification struct {
	verifier Verifier
	fields   []headerField
	body     []byte
	bodies   [2][]byte
	done     [2]bool
	keys     keyCache
}

// canonicalBody returns the message body canonicalized once per algorithm.
func (m *messageVerification) canonicalBody(relaxed bool) []byte {
	index := 0
	if relaxed {
		index = 1
	}
	if !m.done[index] {
		m.bodies[index], m.done[index] = canonicalBody(m.body, relaxed), true
	}
	return m.bodies[index]
}

// verify checks one DKIM-Signature field per RFC 6376 sections 6.1.1-6.1.3.
func (m *messageVerification) verify(ctx context.Context, field headerField) SignatureResult {
	result := SignatureResult{}
	finish := func(status, reason string) SignatureResult {
		result.Status, result.Reason = status, reason
		return result
	}
	tags, err := parseTags(field.value())
	if err != nil {
		return finish(StatusPermError, "malformed signature: "+err.Error())
	}
	result.Domain = strings.ToLower(strings.TrimSuffix(tags["d"], "."))
	result.Selector, result.Algorithm, result.Signature = tags["s"], tags["a"], tags["b"]
	if tags["v"] != "1" {
		return finish(StatusPermError, "incompatible signature version")
	}
	for _, required := range []string{"a", "b", "bh", "d", "h", "s"} {
		if _, ok := tags[required]; !ok {
			return finish(StatusPermError, "signature missing required tag "+required+"=")
		}
	}
	if result.Domain == "" || result.Selector == "" {
		return finish(StatusPermError, "empty d= or s= tag")
	}
	// The AUID's domain must be the SDID or a subdomain of it.
	result.Identifier = "@" + result.Domain
	auidDomain := result.Domain
	if identifier, ok := tags["i"]; ok {
		at := strings.LastIndex(identifier, "@")
		if at < 0 {
			return finish(StatusPermError, "malformed i= tag")
		}
		result.Identifier = identifier
		auidDomain = strings.ToLower(strings.TrimSuffix(identifier[at+1:], "."))
		if auidDomain != result.Domain && !strings.HasSuffix(auidDomain, "."+result.Domain) {
			return finish(StatusPermError, "i= domain is not within d=")
		}
	}
	signed := colonList(tags["h"])
	if !slices.Contains(signed, "from") {
		return finish(StatusPermError, "From field not signed")
	}
	if timestamp, ok := tags["t"]; ok {
		if _, err := parseTimestamp(timestamp); err != nil {
			return finish(StatusPermError, "malformed t= tag")
		}
	}
	if expiry, ok := tags["x"]; ok {
		expires, err := parseTimestamp(expiry)
		if err != nil {
			return finish(StatusPermError, "malformed x= tag")
		}
		now := time.Now
		if m.verifier.Now != nil {
			now = m.verifier.Now
		}
		if now().Unix() > expires {
			return finish(StatusPermError, "signature expired")
		}
	}
	if methods, ok := tags["q"]; ok && !slices.Contains(colonList(methods), "dns/txt") {
		return finish(StatusPermError, "unsupported query method")
	}
	switch result.Algorithm {
	case "rsa-sha256", "ed25519-sha256":
	case "rsa-sha1":
		// RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for verifying.
		return finish(StatusPermError, "rsa-sha1 is not accepted (RFC 8301)")
	default:
		return finish(StatusPermError, "unsupported algorithm "+strconv.Quote(result.Algorithm))
	}
	headerCanon, bodyCanon, err := parseCanonicalization(tags["c"])
	if err != nil {
		return finish(StatusPermError, err.Error())
	}
	signature, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil || len(signature) == 0 {
		return finish(StatusPermError, "malformed b= tag")
	}
	bodyHash, err := base64.StdEncoding.DecodeString(tags["bh"])
	if err != nil || len(bodyHash) != sha256.Size {
		return finish(StatusPermError, "malformed bh= tag")
	}

	var limit int64 = -1
	if length, ok := tags["l"]; ok {
		limit, err = strconv.ParseInt(length, 10, 64)
		if err != nil || limit < 0 || len(length) > 76 {
			return finish(StatusPermError, "malformed l= tag")
		}
	}

	// The key comes first (RFC 6376 section 6.1.2): its t=y flag decides
	// how even a body hash failure is treated.
	records, err := m.keys.records(ctx, result.Domain, result.Selector)
	if err != nil {
		status := StatusPermError
		if lookupErr, ok := err.(*keyLookupError); ok {
			status = lookupErr.status
		}
		return finish(status, err.Error())
	}
	var keys []keyRecord
	reason := ""
	for _, key := range records {
		switch {
		case key.usableFor(result.Algorithm) != "":
			reason = key.usableFor(result.Algorithm)
		case key.strict && auidDomain != result.Domain:
			reason = "key flag t=s forbids an i= subdomain"
		default:
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return finish(StatusPermError, reason)
	}
	result.Testing = keys[0].testing

	body := m.canonicalBody(bodyCanon == "relaxed")
	unsigned := 0
	if limit >= 0 {
		if limit > int64(len(body)) {
			return finish(StatusFail, "body is shorter than l=")
		}
		unsigned = len(body) - int(limit)
		body = body[:limit]
	}
	computed := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(computed[:], bodyHash) != 1 {
		return finish(StatusFail, "body hash did not verify")
	}

	relaxed := headerCanon == "relaxed"
	var data strings.Builder
	for _, header := range selectHeaders(m.fields, signed) {
		data.WriteString(canonicalHeader(header.raw, relaxed))
	}
	data.WriteString(strings.TrimSuffix(canonicalHeader(stripSignature(field.raw), relaxed), "\r\n"))
	for _, key := range keys {
		if !key.verifyDigest(data.String(), signature) {
			continue
		}
		result.Testing = key.testing
		if unsigned > 0 {
			// RFC 6376 section 8.2: content past l= is unsigned and could
			// be anything; the signature vouches for less than the message.
			return finish(StatusPolicy, fmt.Sprintf("l= leaves %d body octets unsigned", unsigned))
		}
		return finish(StatusPass, "")
	}
	return finish(StatusFail, "signature did not verify")
}

// parseCanonicalization parses a c= tag; each half defaults to simple.
func parseCanonicalization(value string) (header, body string, err error) {
	header, body, _ = strings.Cut(strings.ToLower(value), "/")
	if header == "" {
		header = "simple"
	}
	if body == "" {
		body = "simple"
	}
	for _, canon := range []string{header, body} {
		if canon != "simple" && canon != "relaxed" {
			return "", "", fmt.Errorf("unsupported canonicalization %q", value)
		}
	}
	return header, body, nil
}

// parseTimestamp parses a t= or x= value: at most 12 decimal digits.
func parseTimestamp(value string) (int64, error) {
	if value == "" || len(value) > 12 {
		return 0, fmt.Errorf("invalid timestamp %q", value)
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	return int64(parsed), err
}

// tagList parses an RFC 6376 section 3.2 tag=value list leniently: a
// malformed or repeated tag is skipped rather than failing the list.
func tagList(value string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(value, ";") {
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.TrimSpace(name)] = strings.Join(strings.Fields(val), "")
	}
	return tags
}
