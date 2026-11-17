// Package mailidentity validates the public SMTP identity: that a host name is
// a fully qualified domain name, and that the public egress address and the
// name agree in DNS (forward-confirmed reverse DNS). It never probes the
// network by itself; callers inject the resolver.
package mailidentity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

// MessageIDDomain picks the right-hand side of a generated Message-ID: the
// domain of the sending address when it is a fully qualified host name, else
// the configured server name, else the machine host name. It never returns a
// placeholder domain such as "veksel.local", which receivers read as a sign of
// misconfiguration.
func MessageIDDomain(address, serverName string) string {
	address = strings.Trim(strings.TrimSpace(address), "<>")
	if at := strings.LastIndexByte(address, '@'); at >= 0 {
		if domain := Normalize(strings.Trim(address[at+1:], "<> ")); ValidateFQDN(domain) == nil {
			return domain
		}
	}
	if name := Normalize(serverName); ValidateFQDN(name) == nil {
		return name
	}
	if host, err := os.Hostname(); err == nil {
		if name := Normalize(host); name != "" && hostCharacters(name) {
			return name
		}
	}
	return "localhost"
}

// hostCharacters reports whether name, possibly unqualified, holds only host
// name characters and no empty labels.
func hostCharacters(name string) bool {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return !strings.HasPrefix(name, ".") && !strings.Contains(name, "..")
}

// Normalize lower-cases a host name and removes surrounding space and a
// trailing dot.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// ValidateFQDN reports why name cannot be a public mail host name.
func ValidateFQDN(name string) error {
	name = Normalize(name)
	if name == "" {
		return errors.New("host name is empty")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%q is an IP address, not a host name", name)
	}
	if !strings.Contains(name, ".") {
		return fmt.Errorf("%q is not a fully qualified domain name", name)
	}
	if len(name) > 253 {
		return errors.New("host name is longer than 253 characters")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", name)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return fmt.Errorf("%q contains invalid character %q", name, r)
			}
		}
	}
	return nil
}

// Resolver is the subset of *net.Resolver used for identity checks.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// FCrDNS checks that addr reverse-resolves to name and that name resolves
// forward to addr. It returns human-readable problems; none means confirmed.
func FCrDNS(ctx context.Context, r Resolver, name, addr string) []string {
	name = Normalize(name)
	parsed, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return []string{fmt.Sprintf("smtp_public_address %q is not a valid IP address", addr)}
	}
	addr = parsed.String()
	var problems []string
	ptrs, err := r.LookupAddr(ctx, addr)
	switch {
	case len(ptrs) == 0 && err != nil:
		problems = append(problems, fmt.Sprintf("reverse DNS for smtp_public_address %s failed: %v", addr, err))
	case len(ptrs) == 0:
		problems = append(problems, fmt.Sprintf("smtp_public_address %s has no reverse DNS (PTR) record; expected %s", addr, name))
	default:
		matched := false
		for _, p := range ptrs {
			matched = matched || Normalize(p) == name
		}
		if !matched {
			problems = append(problems, fmt.Sprintf("reverse DNS for smtp_public_address %s is %s, expected %s", addr, strings.Join(ptrs, ", "), name))
		}
	}
	hosts, err := r.LookupHost(ctx, name)
	forward := false
	for _, h := range hosts {
		if ip, perr := netip.ParseAddr(h); perr == nil && ip.Unmap() == parsed.Unmap() {
			forward = true
		}
	}
	if !forward {
		if err != nil && len(hosts) == 0 {
			problems = append(problems, fmt.Sprintf("%s does not resolve forward: %v", name, err))
		} else {
			problems = append(problems, fmt.Sprintf("%s does not resolve forward to smtp_public_address %s (this server's resolver answers %s; a split-DNS or NAT setup can answer an internal address here)", name, addr, strings.Join(hosts, ", ")))
		}
	}
	return problems
}

// Problems lists why name is unlikely to be accepted as an EHLO identity. It
// checks FQDN shape and forward resolution and, when publicAddr is set, the
// full FCrDNS relationship. Without publicAddr reverse DNS is not checked
// because the egress address is unknown locally.
func Problems(ctx context.Context, r Resolver, name, publicAddr string) []string {
	if err := ValidateFQDN(name); err != nil {
		return []string{fmt.Sprintf("smtp_server_name: %v; receiving servers may reject or penalize mail", err)}
	}
	name = Normalize(name)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if strings.TrimSpace(publicAddr) != "" {
		return FCrDNS(ctx, r, name, publicAddr)
	}
	if _, err := r.LookupHost(ctx, name); err != nil {
		return []string{fmt.Sprintf("smtp_server_name %q does not resolve: %v", name, err)}
	}
	return nil
}
