package smtp

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
)

// SpoofPolicyMode controls unauthenticated use of locally hosted identities.
type SpoofPolicyMode string

const (
	SpoofPolicyOff    SpoofPolicyMode = "off"
	SpoofPolicyWarn   SpoofPolicyMode = "warn"
	SpoofPolicyReject SpoofPolicyMode = "reject"
)

// SpoofResult is bounded evidence for the trusted Authentication-Results
// policy method. It never contains a complete address or message content.
type SpoofResult struct {
	Result         string
	Reason         string
	EnvelopeDomain string
	HeaderDomain   string
	Reject         bool
}

func (s *Session) evaluateLocalIdentity(ctx context.Context, headers map[string]string) (*SpoofResult, error) {
	if s.authenticated || s.cfg.LocalDomainSpoofPolicy == SpoofPolicyOff || s.cfg.Delivery == nil || s.cfg.Delivery.IsLocalDomain == nil {
		return nil, nil
	}
	envelopeDomain := extractDomainFromAddress(s.envelopeSender)
	headerDomains := headerIdentityDomains(smtpHeaderValue(headers, "From"))
	envelopeLocal, err := localDomain(ctx, s.cfg.Delivery.IsLocalDomain, envelopeDomain)
	if err != nil {
		return nil, err
	}
	headerDomain, headerLocal := "", false
	for _, domain := range headerDomains {
		local, lookupErr := localDomain(ctx, s.cfg.Delivery.IsLocalDomain, domain)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if local {
			headerDomain, headerLocal = domain, true
			break
		}
	}
	if !envelopeLocal && !headerLocal {
		return nil, nil
	}
	// The server a domain is shared with sends that domain's mail during a
	// migration; it is trusted for the domains it serves, and only those.
	if s.cfg.Delivery.TrustedDomainRelay != nil {
		trusted := true
		peer := extractRemoteIP(s.conn)
		for _, domain := range []string{envelopeDomain, headerDomain} {
			if domain == "" || domain == envelopeDomain && !envelopeLocal || domain == headerDomain && !headerLocal {
				continue
			}
			ok, err := s.cfg.Delivery.TrustedDomainRelay(ctx, domain, peer)
			if err != nil {
				return nil, err
			}
			trusted = trusted && ok
		}
		if trusted {
			return &SpoofResult{Result: "pass", Reason: "split-delivery server for the domain", EnvelopeDomain: envelopeDomain, HeaderDomain: headerDomain}, nil
		}
	}
	reasons := make([]string, 0, 2)
	if envelopeLocal && (s.spfResult == nil || s.spfResult.Result != "pass") {
		reasons = append(reasons, "local envelope identity without SPF pass")
	}
	if headerLocal && (s.dmarcResult == nil || s.dmarcResult.Result != "pass") {
		reasons = append(reasons, "local header identity without DMARC pass")
	}
	result := &SpoofResult{Result: "pass", EnvelopeDomain: envelopeDomain, HeaderDomain: headerDomain}
	if len(reasons) == 0 {
		result.Reason = "local identity authenticated"
		return result, nil
	}
	result.Result = "fail"
	result.Reason = strings.Join(reasons, "; ")
	result.Reject = s.cfg.LocalDomainSpoofPolicy == SpoofPolicyReject
	return result, nil
}

func headerIdentityDomains(value string) []string {
	addresses, err := mail.ParseAddressList(strings.TrimSpace(value))
	if err != nil || len(addresses) == 0 {
		if domain := extractDomainFromAddress(value); domain != "" {
			return []string{domain}
		}
		return nil
	}
	if len(addresses) > 16 {
		addresses = addresses[:16]
	}
	domains := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		domain := strings.ToLower(extractDomainFromAddress(address.Address))
		if domain == "" {
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains
}

func localDomain(ctx context.Context, lookup func(context.Context, string) (bool, error), domain string) (bool, error) {
	if domain == "" {
		return false, nil
	}
	local, err := lookup(ctx, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	if err != nil {
		return false, fmt.Errorf("look up local domain %q: %w", domain, err)
	}
	return local, nil
}
