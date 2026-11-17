package smtp

import "github.com/lkarlslund/veksel/pkg/spam"

// senderAuth is the transaction's authentication evidence for its From
// address.
func (s *Session) senderAuth(headers map[string]string) spam.SenderAuth {
	auth := spam.SenderAuth{From: s.spamPolicySender(headers)}
	if s.dmarcResult != nil {
		auth.DMARCPass = s.dmarcResult.Result == "pass"
	}
	if s.dkimResult != nil {
		auth.DKIMPass, auth.DKIMDomain = s.dkimResult.Result == "pass", s.dkimResult.Domain
		auth.DKIMDomains = s.dkimResult.PassingDomains()
	}
	if s.spfResult != nil {
		auth.SPFPass, auth.SPFDomain = s.spfResult.Result == "pass", s.spfResult.SenderDomain
	}
	return auth
}

// knownCorrespondent returns the KNOWN_CORRESPONDENT symbol when the sender
// authenticated as its own From address (a forged From never benefits) and
// userID has written to it.
func (s *Session) knownCorrespondent(userID string, headers map[string]string) (spam.Symbol, bool, error) {
	delivery := s.cfg.Delivery
	if delivery == nil || delivery.KnownCorrespondent == nil {
		return spam.Symbol{}, false, nil
	}
	address, _, aligned := s.senderAuth(headers).Sender()
	if !aligned {
		return spam.Symbol{}, false, nil
	}
	return delivery.KnownCorrespondent(s.ctx, userID, address)
}
