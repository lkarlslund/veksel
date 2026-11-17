package smtp

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// mxResult holds the result of an MX lookup for a domain.
type mxResult struct {
	Host       string // target mail server hostname
	Port       int    // SMTP port (always 25 for MX)
	Preference int    // MX preference value (lower = higher priority)
}

// mxLookup performs a DNS MX lookup for the given domain and returns
// the best mail server (lowest preference value) and port 25.
//
// If no MX records exist, it falls back to an A/AAAA record for the
// domain itself (RFC 974 section 1.1.3).
func mxLookup(ctx context.Context, domain string) (string, int, error) {
	targets, err := mxLookupAll(ctx, domain, nil, nil)
	if err != nil {
		return "", 0, err
	}
	return targets[0].Host, targets[0].Port, nil
}

func mxLookupAll(ctx context.Context, domain string, lookupMX func(context.Context, string) ([]*net.MX, error), lookupHost func(context.Context, string) ([]string, error)) ([]mxResult, error) {
	if lookupMX == nil {
		lookupMX = net.DefaultResolver.LookupMX
	}
	if lookupHost == nil {
		lookupHost = net.DefaultResolver.LookupHost
	}
	results, err := lookupMX(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS MX lookup for %s: %w", domain, err)
	}

	if len(results) == 0 {
		// No MX records — fall back to A/AAAA lookup (RFC 974)
		addrs, err := lookupHost(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("no MX or A record for %s: %w", domain, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no MX or A record for %s", domain)
		}
		// Use the domain name itself as the host
		return []mxResult{{Host: domain, Port: 25}}, nil
	}

	// Sort by preference (lower = higher priority)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Pref < results[j].Pref
	})

	// Strip trailing dot from hostname
	targets := make([]mxResult, 0, len(results))
	for _, result := range results {
		host := strings.TrimSuffix(result.Host, ".")
		if host == "" {
			continue
		}
		targets = append(targets, mxResult{Host: host, Port: 25, Preference: int(result.Pref)})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("domain %s publishes a null MX", domain)
	}
	return targets, nil
}
