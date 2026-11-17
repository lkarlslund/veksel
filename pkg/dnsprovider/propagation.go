package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Propagation waits until a zone's authoritative nameservers all serve a
// record, bypassing recursive resolver caches.
type Propagation struct {
	// Nameservers returns host:port addresses of the zone's authoritative
	// servers; nil looks up the zone's NS records.
	Nameservers func(ctx context.Context, zone string) ([]string, error)
	// Interval between polls; zero uses five seconds.
	Interval time.Duration
}

// WaitTXT polls until every authoritative server answers name with a TXT
// record whose data equals value, or timeout elapses.
func (p Propagation) WaitTXT(ctx context.Context, zone, name, value string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	interval := p.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	lookup := p.Nameservers
	if lookup == nil {
		lookup = authoritativeNameservers
	}
	var lastErr error
	for {
		servers, err := lookup(ctx, zone)
		if err == nil && len(servers) == 0 {
			err = fmt.Errorf("zone %s has no nameservers", zone)
		}
		if err == nil {
			err = allServeTXT(ctx, servers, name, value)
			if err == nil {
				return nil
			}
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not propagate to the authoritative nameservers within %s: %w", name, timeout, lastErr)
		case <-time.After(interval):
		}
	}
}

func authoritativeNameservers(ctx context.Context, zone string) ([]string, error) {
	records, err := net.DefaultResolver.LookupNS(ctx, NormalizeName(zone))
	if err != nil {
		return nil, err
	}
	servers := make([]string, 0, len(records))
	for _, ns := range records {
		servers = append(servers, net.JoinHostPort(NormalizeName(ns.Host), "53"))
	}
	return servers, nil
}

func allServeTXT(ctx context.Context, servers []string, name, value string) error {
	for _, server := range servers {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(NormalizeName(name)), dns.TypeTXT)
		msg.RecursionDesired = false
		reply, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(ctx, msg, server)
		if err == nil && reply.Truncated {
			reply, _, err = (&dns.Client{Net: "tcp", Timeout: 5 * time.Second}).ExchangeContext(ctx, msg, server)
		}
		if err != nil {
			return fmt.Errorf("query %s: %w", server, err)
		}
		found := false
		for _, rr := range reply.Answer {
			if txt, ok := rr.(*dns.TXT); ok && strings.Join(txt.Txt, "") == value {
				found = true
			}
		}
		if !found {
			return errors.New(server + " does not serve the record yet")
		}
	}
	return nil
}
