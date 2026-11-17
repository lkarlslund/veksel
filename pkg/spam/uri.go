package spam

import (
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var (
	// urlPattern finds scheme and www links in text, including the common
	// hxxp defanging that still renders as a clickable link in many clients.
	urlPattern = regexp.MustCompile(`(?i)\b(?:(?:https?|hxxps?|ftp)://|www\.)[^\s<>"'(){}\[\]\\^` + "`" + `]+`)
	// emailPattern finds address domains.
	emailPattern = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])`)
	// bareDomainPattern finds unlinked host names such as "example.com".
	bareDomainPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\b`)
	// dotObfuscation matches "[.]", "(.)", "[dot]", and "(dot)".
	dotObfuscation = regexp.MustCompile(`(?i)\s?(?:\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\})\s?`)
)

// reservedSuffixes are never real registrations and are never queried.
var reservedSuffixes = []string{"test", "example", "invalid", "localhost", "local", "arpa", "internal", "home.arpa", "lan", "corp"}

// reservedDomains are RFC 2606 documentation domains.
var reservedDomains = map[string]bool{"example.com": true, "example.net": true, "example.org": true}

// extractURIDomains returns up to max distinct registrable domains linked
// or named in the message, in order of first appearance. Link attributes
// come first because they are what a reader clicks.
func extractURIDomains(body content, max int) []string {
	memo := body.uris
	if memo != nil && memo.max > 0 && (max <= memo.max || len(memo.domains) < memo.max) {
		// The extraction is a deterministic walk that stops at max, so a
		// shorter bound is a prefix of a longer one, and a list that ended
		// before its bound is complete.
		return slices.Clone(memo.domains[:min(max, len(memo.domains))])
	}
	domains := scanURIDomains(body, max)
	if memo != nil {
		memo.max, memo.domains = max, domains
	}
	return slices.Clone(domains)
}

func scanURIDomains(body content, max int) []string {
	seen := make(map[string]bool)
	var domains []string
	add := func(host string) bool {
		domain, ok := registrableDomain(host)
		if ok && !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
		return len(domains) < max
	}
	for _, link := range body.links {
		if !add(hostFromLink(link)) {
			return domains
		}
	}
	for _, text := range append(append([]string(nil), body.text...), body.htmlText...) {
		text = deobfuscate(text)
		for _, link := range urlPattern.FindAllString(text, -1) {
			if !add(hostFromLink(link)) {
				return domains
			}
		}
		for _, match := range emailPattern.FindAllStringSubmatch(text, -1) {
			if !add(match[1]) {
				return domains
			}
		}
		for _, host := range bareDomainPattern.FindAllString(text, -1) {
			if !add(host) {
				return domains
			}
		}
	}
	return domains
}

// deobfuscate undoes defanged dots so "evil[.]com" is checked as evil.com.
func deobfuscate(text string) string {
	if !strings.ContainsAny(text, "[({") {
		return text
	}
	return dotObfuscation.ReplaceAllString(text, ".")
}

// hostFromLink returns the host a link points at: the authority of an
// absolute or scheme-relative URL (ignoring user information), the domain
// of a mailto: address, or empty for relative links.
func hostFromLink(link string) string {
	link = strings.TrimSpace(link)
	lower := strings.ToLower(link)
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		address, _, _ := strings.Cut(link[len("mailto:"):], "?")
		if at := strings.LastIndex(address, "@"); at >= 0 {
			return address[at+1:]
		}
		return ""
	case strings.HasPrefix(lower, "hxxp"):
		link = "http" + link[4:]
	case strings.HasPrefix(lower, "www."):
		link = "http://" + link
	}
	// Browsers treat backslashes in the authority as slashes.
	link = strings.ReplaceAll(link, "\\", "/")
	parsed, err := url.Parse(link)
	if err != nil {
		if scheme, rest, found := strings.Cut(link, "://"); found && scheme != "" {
			host, _, _ := strings.Cut(rest, "/")
			if at := strings.LastIndex(host, "@"); at >= 0 {
				host = host[at+1:]
			}
			host, _, _ = strings.Cut(host, ":")
			if unescaped, err := url.PathUnescape(host); err == nil {
				host = unescaped
			}
			return host
		}
		return ""
	}
	host := parsed.Hostname()
	if unescaped, err := url.PathUnescape(host); err == nil {
		host = unescaped
	}
	return host
}

// registrableDomain normalizes host to its registrable domain (eTLD+1)
// under an ICANN public suffix. Address literals, single labels, reserved
// names, and private suffixes are rejected.
func registrableDomain(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.Trim(host, "[]")
	if host == "" || len(host) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || !strings.Contains(ascii, ".") {
		return "", false
	}
	for _, suffix := range reservedSuffixes {
		if ascii == suffix || strings.HasSuffix(ascii, "."+suffix) {
			return "", false
		}
	}
	if suffix, icann := publicsuffix.PublicSuffix(ascii); !icann || suffix == ascii {
		return "", false
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || reservedDomains[domain] {
		return "", false
	}
	return domain, true
}
