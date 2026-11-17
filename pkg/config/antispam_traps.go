package config

import (
	"fmt"
	"slices"
	"strings"
)

// Bounds of the spamtrap and ARC sealer lists.
const (
	maxSpamtraps         = 1000
	maxARCTrustedSealers = 100
)

// Spamtraps is the parsed antispam_spamtraps setting, lower case and
// without duplicates. Whether an address belongs to a hosted domain and
// collides with a real identity is checked by the owner, which knows the
// directory.
type Spamtraps struct {
	// Addresses are exact trap addresses.
	Addresses []string
	// LocalParts are trap local parts that apply on every hosted domain.
	LocalParts []string
}

// ParseSpamtraps parses antispam_spamtraps: each entry is an address
// (trap@example.com) or a bare local part (trap) for every hosted domain.
func ParseSpamtraps(entries []string) (Spamtraps, error) {
	var traps Spamtraps
	if len(entries) > maxSpamtraps {
		return traps, fmt.Errorf("antispam_spamtraps must list at most %d addresses", maxSpamtraps)
	}
	for _, entry := range entries {
		value := strings.ToLower(strings.TrimSpace(entry))
		local, domain, isAddress := strings.Cut(value, "@")
		if !validLocalPart(local) || isAddress && !validDomainName(domain) {
			return Spamtraps{}, fmt.Errorf("antispam_spamtraps entry %q is not an address or local part", entry)
		}
		list := &traps.LocalParts
		if isAddress {
			list = &traps.Addresses
		}
		if slices.Contains(*list, value) {
			return Spamtraps{}, fmt.Errorf("antispam_spamtraps lists %q twice", entry)
		}
		*list = append(*list, value)
	}
	return traps, nil
}

// validLocalPart accepts a dot-atom local part of up to 64 characters.
func validLocalPart(local string) bool {
	if local == "" || len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	for _, r := range local {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune(".!#$%&'*+/=?^_`{|}~-", r)) {
			return false
		}
	}
	return true
}

// ParseARCTrustedSealers parses arc_trusted_sealers into lower-case domain
// names. A sealer matches its domain and the domain's subdomains.
func ParseARCTrustedSealers(entries []string) ([]string, error) {
	if len(entries) > maxARCTrustedSealers {
		return nil, fmt.Errorf("arc_trusted_sealers must list at most %d domains", maxARCTrustedSealers)
	}
	domains := make([]string, 0, len(entries))
	for _, entry := range entries {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if !validDomainName(domain) || !strings.Contains(domain, ".") {
			return nil, fmt.Errorf("arc_trusted_sealers entry %q is not a domain name", entry)
		}
		domains = append(domains, domain)
	}
	return domains, nil
}
