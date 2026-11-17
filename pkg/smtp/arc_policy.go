package smtp

import (
	"context"
	"errors"
	"strings"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/model"
)

// ARCPolicy configures ARC (RFC 8617) for inbound and forwarded mail.
type ARCPolicy struct {
	// Verify validates inbound ARC chains and reports arc= in
	// Authentication-Results.
	Verify bool
	// Verifier resolves sealer keys; the zero value uses system DNS.
	Verifier dkim.Verifier
	// TrustedSealers are forwarding domains, matching their subdomains too,
	// whose valid seal recording dmarc=pass overrides a DMARC failure.
	TrustedSealers []string
	// Sealer, when set, adds an ARC set to forwarded and redirected mail.
	Sealer ARCSealer
}

// ARCSealer seals a forwarded message for the forwarding domain;
// *dkim.Signer implements it.
type ARCSealer interface {
	Seal(ctx context.Context, domain string, message []byte, authResults, chainValidation string) ([]byte, bool, error)
}

// runARCVerification validates the ARC chain of the exact bytes the peer
// sent, before this hop adds any header field.
func (s *Session) runARCVerification(message []byte) *dkim.ARCResult {
	policy := s.cfg.ARC
	if policy == nil || !policy.Verify {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dkimDNSTimeout)
	defer cancel()
	result := policy.Verifier.VerifyARC(ctx, message)
	if result.Status == dkim.ARCFail {
		logger.Info("smtp: ARC chain failed", "session", s.id, "instances", result.Instances, "reason", result.Reason)
	}
	return result
}

// applyARCOverride lets a valid ARC chain from a trusted sealer override a
// DMARC failure, as RFC 7489 section 10.5 local policy allows for
// forwarded mail: the newest sealer must be trusted and must have recorded
// dmarc=pass before it forwarded the message. Only the newest seal is
// trusted because only its message signature has to match the message as
// received; older sets can be replayed from other mail.
func (s *Session) applyARCOverride() {
	result, arc := s.dmarcResult, s.arcResult
	if result == nil || result.Result != "fail" || arc == nil || arc.Status != dkim.ARCPass || arc.SealerResults["dmarc"] != "pass" || !s.trustedSealer(arc.Sealer) {
		return
	}
	result.OverrideReason = "arc trusted sealer " + arc.Sealer
	result.ShouldReject, result.RejectionCode, result.RejectionText = false, 0, ""
	result.PolicyApplied, result.Disposition = false, "none"
	logger.Info("smtp: DMARC failure overridden by trusted ARC sealer", "session", s.id, "sealer", arc.Sealer, "domain", result.Domain)
}

func (s *Session) trustedSealer(sealer string) bool {
	if s.cfg.ARC == nil || sealer == "" {
		return false
	}
	for _, trusted := range s.cfg.ARC.TrustedSealers {
		if sealer == trusted || strings.HasSuffix(sealer, "."+trusted) {
			return true
		}
	}
	return false
}

// forwardSealer returns the function that ARC-seals a forward or redirect
// of the message accepted for recipient, signed for recipient's domain and
// recording this hop's Authentication-Results. It captures the session's
// state, so it stays valid after the transaction resets. Without sealing it
// returns messages unchanged.
func (s *Session) forwardSealer(recipient string) func([]byte) []byte {
	policy := s.cfg.ARC
	if policy == nil || policy.Sealer == nil {
		return func(message []byte) []byte { return message }
	}
	sealer, domain, sessionID := policy.Sealer, extractDomainFromAddress(recipient), s.id
	chain := ""
	if s.arcResult != nil {
		chain = s.arcResult.Status
	}
	authservID := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.cfg.ServerName)), ".")
	return func(message []byte) []byte {
		headers, _ := model.ParseMessageHeaders(message)
		authResults := smtpHeaderValue(headers, "Authentication-Results")
		if authResults == "" {
			authResults = authservID + "; none"
		}
		sealed, ok, err := sealer.Seal(context.Background(), domain, message, authResults, chain)
		switch {
		case errors.Is(err, dkim.ErrARCNotSealable):
			logger.Debug("smtp: forward not ARC-sealed", "session", sessionID, "domain", domain, "reason", err)
		case err != nil:
			logger.Warn("smtp: ARC sealing failed", "session", sessionID, "domain", domain, "error", err)
		case ok:
			return sealed
		}
		return message
	}
}
