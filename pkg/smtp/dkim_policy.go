package smtp

import (
	"context"
	"time"

	"github.com/lkarlslund/veksel/pkg/dkim"
)

// DkimPolicyMode controls how DKIM verification failures are handled.
type DkimPolicyMode string

const (
	DkimPolicyOff    DkimPolicyMode = "off"
	DkimPolicyWarn   DkimPolicyMode = "warn"
	DkimPolicyReject DkimPolicyMode = "reject"
)

// DkimPolicy holds configurable rules for DKIM verification.
type DkimPolicy struct {
	// Mode controls the enforcement level: off, warn, or reject.
	Mode DkimPolicyMode
	// Verifier performs verification; the zero value uses system DNS.
	Verifier dkim.Verifier
}

// DkimResult captures the outcome of DKIM verification.
type DkimResult struct {
	// Result is the DKIM verification result: pass, fail, none, temperror, permerror.
	Result string

	// Domain is the signing domain.
	Domain string

	// Selector is the DKIM selector.
	Selector string

	// Pass indicates whether the DKIM check passes.
	Pass bool

	// ShouldReject indicates whether the message should be rejected based on policy.
	ShouldReject bool

	// RejectionCode is the SMTP response code when the policy rejects.
	RejectionCode int

	// RejectionText is the human-readable rejection reason.
	RejectionText string

	// HeaderValue is the value for the DKIM-Verification-Result header.
	HeaderValue string

	// Testing reports that the summary signature's key is published in
	// testing mode (t=y); its failure is treated as unsigned mail.
	Testing bool

	// Signatures holds every verified signature in header order.
	Signatures []dkim.SignatureResult
}

// PassingDomains returns the distinct signing domains of the passing
// signatures, the identifiers DMARC may align with.
func (r *DkimResult) PassingDomains() []string {
	if r == nil {
		return nil
	}
	if r.Signatures == nil && r.Result == "pass" && r.Domain != "" {
		return []string{r.Domain}
	}
	return (&dkim.VerifyResult{Signatures: r.Signatures}).PassingDomains()
}

// EvaluateDKIM runs DKIM verification for the given message.
// Returns a DkimResult describing the outcome.
func EvaluateDKIM(policy *DkimPolicy, message []byte) *DkimResult {
	if policy == nil || policy.Mode == DkimPolicyOff {
		return &DkimResult{Result: "skip", Pass: true}
	}

	ctx, cancel := context.WithTimeout(context.Background(), dkimDNSTimeout)
	defer cancel()

	verifyResult := policy.Verifier.Verify(ctx, message)

	dkimResult := &DkimResult{
		Result:      verifyResult.Status,
		Domain:      verifyResult.Domain,
		Selector:    verifyResult.Selector,
		Pass:        verifyResult.Pass,
		HeaderValue: verifyResult.HeaderValue,
		Testing:     verifyResult.Testing,
		Signatures:  verifyResult.Signatures,
	}

	// Determine action based on result and policy. RFC 6376 section 3.6.1:
	// a failure under a testing key is treated like unsigned mail.
	status := verifyResult.Status
	if verifyResult.Testing && status != "pass" {
		status = "none"
	}
	switch status {
	case "pass":
		dkimResult.Pass = true
	case "fail":
		dkimResult.Pass = false
		if policy.Mode == DkimPolicyReject {
			dkimResult.ShouldReject = true
			dkimResult.RejectionCode = 550
			dkimResult.RejectionText = "5.7.25 DKIM verification failed; rejected"
		}
	case "temperror":
		// DNS errors — don't reject on temporary failures
		dkimResult.Pass = true
		logger.Warn("smtp: DKIM temporary error",
			"domain", verifyResult.Domain, "reason", verifyResult.Reason)
	case "permerror":
		// Permanent errors (invalid signature format) — treat as failure
		dkimResult.Pass = false
		if policy.Mode == DkimPolicyReject {
			dkimResult.ShouldReject = true
			dkimResult.RejectionCode = 550
			dkimResult.RejectionText = "5.7.25 DKIM permanent error; rejected"
		}
	case "none":
		// No DKIM signature — don't reject (many legitimate senders don't sign)
		dkimResult.Pass = true
	default:
		dkimResult.Pass = true
	}

	// Log DKIM verification results
	if !dkimResult.Pass {
		logger.Warn("smtp: DKIM verification failed",
			"domain", verifyResult.Domain, "selector", verifyResult.Selector,
			"result", verifyResult.Status, "policy", policy.Mode)
	} else {
		logger.Debug("smtp: DKIM verification",
			"domain", verifyResult.Domain, "selector", verifyResult.Selector,
			"result", verifyResult.Status)
	}

	return dkimResult
}

// dkimDNSTimeout is the timeout for DKIM DNS lookups.
const dkimDNSTimeout = 5 * time.Second

// DefaultDkimPolicy returns the default DKIM policy configuration.
func DefaultDkimPolicy() *DkimPolicy {
	return &DkimPolicy{
		Mode: DkimPolicyWarn,
	}
}

// dkimVerificationHeader returns the DKIM-Verification-Result header value.
func dkimVerificationHeader(result *DkimResult) string {
	if result == nil {
		return "skip"
	}
	return result.HeaderValue
}
