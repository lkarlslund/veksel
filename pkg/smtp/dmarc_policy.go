package smtp

import (
	"context"

	"github.com/lkarlslund/veksel/pkg/dmarc"
)

// DmarcPolicyMode controls how DMARC failures are handled.
type DmarcPolicyMode string

const (
	DmarcPolicyOff    DmarcPolicyMode = "off"
	DmarcPolicyWarn   DmarcPolicyMode = "warn"
	DmarcPolicyReject DmarcPolicyMode = "reject"
)

// DmarcPolicy holds configurable rules for DMARC checking.
type DmarcPolicy struct {
	// Mode controls the enforcement level: off, warn, or reject.
	Mode DmarcPolicyMode

	// Evaluator optionally injects bounded DNS and sampling behavior.
	Evaluator *dmarc.Evaluator
}

// DmarcResult captures the outcome of DMARC evaluation.
type DmarcResult struct {
	// Result is the DMARC verification result: pass, fail, none, temperror, permerror.
	Result string

	// Domain is the organizational domain being checked.
	Domain string

	// SpfPass indicates whether SPF alignment passed.
	SpfPass bool

	// DkimPass indicates whether DKIM alignment passed.
	DkimPass bool

	// Pass indicates whether the DMARC check passes (at least one aligned).
	Pass bool

	// ShouldReject indicates whether the message should be rejected based on policy.
	ShouldReject bool

	// RejectionCode is the SMTP response code when the policy rejects.
	RejectionCode int

	// RejectionText is the human-readable rejection reason.
	RejectionText string

	// HeaderValue is retained as internal diagnostic data; SMTP emits the
	// combined Authentication-Results field instead.
	HeaderValue string

	PolicyDomain  string
	Disposition   string
	PolicyApplied bool
	Percentage    int
	Reporting     *dmarc.ReportingPolicy
	// OverrideReason explains a local policy override of a failure, such
	// as a valid ARC chain from a trusted sealer; the policy then did not
	// apply.
	OverrideReason string
}

// EvaluateDMARC runs DMARC evaluation for the given header From domain,
// SPF result, and DKIM result. Returns a DmarcResult describing the outcome.
func EvaluateDMARC(policy *DmarcPolicy, headerFromDomain string,
	spfDomain string, spfPass bool, dkimDomains []string, dkimPass bool) *DmarcResult {

	if policy == nil || policy.Mode == DmarcPolicyOff {
		return &DmarcResult{Result: "skip", Pass: true}
	}

	// Build the internal DMARC policy for the dmarc package
	internalPolicy := &dmarc.DmarcPolicy{
		Mode: dmarc.DmarcPolicyMode(policy.Mode),
	}

	ctx := context.Background()
	evaluator := dmarc.DefaultEvaluator()
	if policy.Evaluator != nil {
		evaluator = *policy.Evaluator
	}
	internalResult := evaluator.Evaluate(ctx, internalPolicy, headerFromDomain, spfDomain, spfPass, dkimDomains, dkimPass)

	// Map the internal result to our SMTP result
	result := &DmarcResult{
		Result:        internalResult.Result,
		Domain:        internalResult.Domain,
		SpfPass:       internalResult.SpfPass,
		DkimPass:      internalResult.DkimPass,
		Pass:          internalResult.Pass,
		ShouldReject:  internalResult.ShouldReject,
		RejectionCode: internalResult.RejectionCode,
		RejectionText: internalResult.RejectionText,
		HeaderValue:   internalResult.HeaderValue,
		PolicyDomain:  internalResult.PolicyDomain,
		Disposition:   internalResult.Disposition,
		PolicyApplied: internalResult.PolicyApplied,
		Percentage:    internalResult.Percentage,
		Reporting:     internalResult.Reporting,
	}

	// Log DMARC evaluation results
	if !result.Pass {
		logger.Warn("smtp: DMARC check failed",
			"domain", result.Domain, "result", result.Result, "policy", policy.Mode)
	} else {
		logger.Debug("smtp: DMARC check",
			"domain", result.Domain, "result", result.Result)
	}

	return result
}

// DefaultDmarcPolicy returns the default DMARC policy configuration.
func DefaultDmarcPolicy() *DmarcPolicy {
	return &DmarcPolicy{
		Mode: DmarcPolicyWarn,
	}
}
