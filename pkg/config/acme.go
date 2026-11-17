package config

import (
	"errors"
	"fmt"
	"strings"
)

// ACME challenge modes for acme_challenge.
const (
	ACMEChallengeAuto = "auto"
	ACMEChallengeHTTP = "http-01"
	ACMEChallengeDNS  = "dns-01"
)

// ACMEChallenges is the parsed acme_challenge setting: a default mode and
// per-certificate overrides keyed by lower-case host name.
type ACMEChallenges struct {
	Default   string
	Overrides map[string]string
}

// ParseACMEChallenge parses "mode[, host=mode...]". The bare mode is the
// default for every certificate (auto when omitted); auto uses DNS-01 when a
// DNS provider covers the host and HTTP-01 otherwise.
func ParseACMEChallenge(value string) (ACMEChallenges, error) {
	parsed := ACMEChallenges{Default: ACMEChallengeAuto, Overrides: map[string]string{}}
	sawDefault := false
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, mode, override := strings.Cut(part, "=")
		mode = strings.ToLower(strings.TrimSpace(mode))
		if !override {
			mode = strings.ToLower(host)
		}
		if mode != ACMEChallengeAuto && mode != ACMEChallengeHTTP && mode != ACMEChallengeDNS {
			return ACMEChallenges{}, fmt.Errorf("acme_challenge: %q is not auto, http-01, or dns-01", mode)
		}
		if !override {
			if sawDefault {
				return ACMEChallenges{}, errors.New("acme_challenge: only one default mode is allowed")
			}
			parsed.Default, sawDefault = mode, true
			continue
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return ACMEChallenges{}, fmt.Errorf("acme_challenge: %q has no host", part)
		}
		parsed.Overrides[host] = mode
	}
	return parsed, nil
}

// For returns the configured mode for host. Wildcard names can only be
// validated with DNS-01, so auto resolves to dns-01 for them.
func (c ACMEChallenges) For(host string) string {
	mode, ok := c.Overrides[strings.ToLower(host)]
	if !ok {
		mode = c.Default
	}
	if mode == ACMEChallengeAuto && strings.HasPrefix(host, "*.") {
		return ACMEChallengeDNS
	}
	return mode
}

// validateACME checks the challenge selection, the propagation timeout,
// and wildcard host names in acme_domains.
func validateACME(cfg *Config) error {
	challenges, err := ParseACMEChallenge(cfg.AcmeChallenge)
	if err != nil {
		return err
	}
	if cfg.AcmeDNSPropagationSeconds < 10 || cfg.AcmeDNSPropagationSeconds > 3600 {
		return errors.New("acme_dns_propagation_seconds must be between 10 and 3600")
	}
	for _, host := range strings.Split(cfg.AcmeDomains, ",") {
		host = strings.ToLower(strings.TrimSpace(host))
		if !strings.Contains(host, "*") {
			continue
		}
		if !strings.HasPrefix(host, "*.") || strings.Contains(host[2:], "*") {
			return fmt.Errorf("acme_domains: %q may only use a leading *. wildcard label", host)
		}
		if challenges.For(host) == ACMEChallengeHTTP {
			return fmt.Errorf("acme_domains: wildcard %q requires the dns-01 challenge", host)
		}
	}
	return nil
}
