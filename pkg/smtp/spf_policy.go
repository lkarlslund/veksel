package smtp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/spam"
)

// SpfPolicyMode controls how SPF violations are handled.
type SpfPolicyMode string

const (
	SpfPolicyOff    SpfPolicyMode = "off"
	SpfPolicyWarn   SpfPolicyMode = "warn"
	SpfPolicyReject SpfPolicyMode = "reject"
)

// SpfPolicy holds configurable rules for SPF checking.
type SpfPolicy struct {
	// Mode controls the enforcement level: off, warn, or reject.
	Mode SpfPolicyMode

	// Resolver performs the SPF DNS lookups; nil uses net.DefaultResolver.
	Resolver spam.SPFResolver

	// Timeout bounds one evaluation; zero selects spam.DefaultSPFTimeout.
	Timeout time.Duration
}

// SpfResult captures the outcome of SPF evaluation.
type SpfResult struct {
	// Result is the SPF verification result: pass, fail, softfail, neutral,
	// none, temperror, permerror, or skip when no check ran.
	Result string

	// SenderDomain is the domain that was checked: the MAIL FROM domain, or
	// the HELO domain for a null sender.
	SenderDomain string

	// SenderIP is the IP address of the sending server.
	SenderIP string

	// Identity is "mailfrom", or "helo" when a null sender was checked as
	// postmaster@<HELO domain> (RFC 7208 section 2.4).
	Identity string

	// Helo is the HELO/EHLO name the client announced.
	Helo string

	// Mechanism is the policy term that decided the result.
	Mechanism string

	// Problem explains a temperror or permerror result.
	Problem string

	// Explanation is the domain's exp= text for a fail result.
	Explanation string

	// Pass is false only for fail and softfail results.
	Pass bool

	// ShouldReject indicates whether the message should be rejected based on policy.
	ShouldReject bool

	// RejectionCode is the SMTP response code when the policy rejects.
	RejectionCode int

	// RejectionText is the human-readable rejection reason.
	RejectionText string

	// HeaderValue is the RFC 7208 section 9.1 Received-SPF value, kept as
	// diagnostic data; SMTP emits the combined Authentication-Results field.
	HeaderValue string
}

// EvaluateSPF runs SPF checking for the given envelope sender, HELO name
// and client IP. A null sender is checked as postmaster@helo.
func EvaluateSPF(ctx context.Context, policy *SpfPolicy, envelopeSender, helo, clientIP string) *SpfResult {
	if policy == nil || policy.Mode == SpfPolicyOff {
		return &SpfResult{Result: "skip", Pass: true}
	}

	sender := strings.TrimSpace(strings.Trim(strings.TrimSpace(envelopeSender), "<>"))
	identity := spam.SPFIdentityMailFrom
	domain := ""
	if sender == "" {
		identity = spam.SPFIdentityHelo
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(helo)), ".")
	} else {
		atIdx := strings.LastIndex(sender, "@")
		if atIdx < 0 {
			result := &SpfResult{Result: "permerror", SenderIP: clientIP, Identity: identity, Helo: helo, Pass: true, Problem: "envelope sender has no domain"}
			result.HeaderValue = buildReceivedSPFHeader(result, sender, "")
			return result
		}
		domain = strings.TrimSuffix(strings.ToLower(sender[atIdx+1:]), ".")
	}

	// Skip SPF check for local IPs (loopback, private ranges)
	if isLocalIP(clientIP) {
		return &SpfResult{Result: "skip", SenderDomain: domain, SenderIP: clientIP, Identity: identity, Helo: helo, Pass: true}
	}

	ip, err := netip.ParseAddr(clientIP)
	if err != nil {
		result := &SpfResult{Result: "permerror", SenderDomain: domain, SenderIP: clientIP, Identity: identity, Helo: helo, Pass: true, Problem: "invalid client IP"}
		result.HeaderValue = buildReceivedSPFHeader(result, sender, "")
		return result
	}
	outcome := spam.CheckSPF(ctx, policy.Resolver, spam.SPFRequest{IP: ip, Sender: sender, Helo: helo, Timeout: policy.Timeout})
	result := string(outcome.Result)
	spfResult := &SpfResult{
		Result:       result,
		SenderDomain: domain,
		SenderIP:     clientIP,
		Identity:     outcome.Identity,
		Helo:         helo,
		Mechanism:    outcome.Mechanism,
		Problem:      outcome.Problem,
		Explanation:  outcome.Explanation,
		// Only fail and softfail are negative; DNS and policy errors are
		// never held against the sender.
		Pass: outcome.Result != spam.SPFFail && outcome.Result != spam.SPFSoftfail,
	}
	// RFC 7208 section 8.4: a fail may be rejected. A softfail (section
	// 8.5) is recorded and scored but not rejected.
	if outcome.Result == spam.SPFFail && policy.Mode == SpfPolicyReject {
		spfResult.ShouldReject = true
		spfResult.RejectionCode = 550
		spfResult.RejectionText = "5.7.23 SPF validation failed"
		if text := printableValue(outcome.Explanation, 200); text != "" {
			spfResult.RejectionText += ": " + text
		}
	}

	spfResult.HeaderValue = buildReceivedSPFHeader(spfResult, sender, "")

	if !spfResult.Pass || outcome.Problem != "" {
		logger.Warn("smtp: SPF check failed",
			"domain", domain, "identity", outcome.Identity, "ip", clientIP, "result", result, "problem", outcome.Problem, "policy", policy.Mode)
	} else {
		logger.Debug("smtp: SPF check",
			"domain", domain, "identity", outcome.Identity, "ip", clientIP, "result", result, "mechanism", outcome.Mechanism)
	}

	return spfResult
}

// buildReceivedSPFHeader constructs an RFC 7208 section 9.1 Received-SPF
// value: the result, a comment, and the key-value pairs. sender is the
// MAIL FROM address (empty for a null sender).
func buildReceivedSPFHeader(r *SpfResult, sender, receiver string) string {
	var b strings.Builder
	b.WriteString(r.Result)
	subject := "domain of " + printableValue(strings.NewReplacer("(", "", ")", "").Replace(sender), 256)
	if r.Identity == spam.SPFIdentityHelo {
		subject = "domain of postmaster@" + printableValue(strings.NewReplacer("(", "", ")", "").Replace(r.Helo), 253)
	}
	switch r.Result {
	case "pass":
		b.WriteString(" (" + subject + " designates " + r.SenderIP + " as permitted sender)")
	case "fail", "softfail":
		b.WriteString(" (" + subject + " does not designate " + r.SenderIP + " as permitted sender)")
	case "neutral", "none":
		b.WriteString(" (" + subject + " neither permits nor denies " + r.SenderIP + ")")
	}
	quoted := func(value string, limit int) string {
		return "\"" + printableValue(strings.NewReplacer("\"", "", "\\", "").Replace(value), limit) + "\""
	}
	pairs := []string{"client-ip=" + r.SenderIP, "envelope-from=" + quoted(sender, 256)}
	if r.Helo != "" {
		pairs = append(pairs, "helo="+quoted(r.Helo, 253))
	}
	if r.Identity != "" {
		pairs = append(pairs, "identity="+r.Identity)
	}
	if receiver != "" {
		pairs = append(pairs, "receiver="+receiver)
	}
	if r.Mechanism != "" {
		pairs = append(pairs, "mechanism="+quoted(r.Mechanism, 200))
	}
	if r.Problem != "" {
		pairs = append(pairs, "problem="+quoted(r.Problem, 200))
	}
	b.WriteString(" " + strings.Join(pairs, "; ") + ";")
	return b.String()
}

// isLocalIP returns true if the IP is a loopback, private, or link-local address.
func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// DefaultSpfPolicy returns the default SPF policy configuration.
func DefaultSpfPolicy() *SpfPolicy {
	return &SpfPolicy{
		Mode: SpfPolicyWarn,
	}
}
