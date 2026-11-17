package spam

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
)

// blocklistQuery is one zone lookup and the subject it asks about.
type blocklistQuery struct {
	zone    Zone
	name    string
	subject string
}

// scoreBlocklists queries every configured zone within the message budget
// and adds a symbol for each listing. Failed lookups add the zero-score
// DNS_LOOKUP_ERROR evidence instead of guessing.
func (e *Engine) scoreBlocklists(ctx context.Context, symbols *symbolSet, m Message, headers map[string]string, body content) {
	ctx, cancel := context.WithTimeout(ctx, e.config.Budget)
	defer cancel()
	var queries []blocklistQuery
	if addr, err := netip.ParseAddr(m.RemoteIP); err == nil {
		addr = addr.Unmap().WithZone("")
		for _, zone := range e.config.DNSBL {
			queries = append(queries, blocklistQuery{zone: zone, name: ReverseIP(addr) + "." + zone.Name, subject: addr.String()})
		}
	}
	if len(e.config.RHSBL) > 0 {
		for _, domain := range e.senderDomains(ctx, m, headers) {
			for _, zone := range e.config.RHSBL {
				queries = append(queries, blocklistQuery{zone: zone, name: domain + "." + zone.Name, subject: domain})
			}
		}
	}
	if len(e.config.URIBL) > 0 {
		checked := 0
		for _, domain := range extractURIDomains(body, e.config.MaxURIDomains*2) {
			if checked >= e.config.MaxURIDomains {
				break
			}
			if !e.queryableDomain(ctx, domain) {
				continue
			}
			checked++
			for _, zone := range e.config.URIBL {
				queries = append(queries, blocklistQuery{zone: zone, name: domain + "." + zone.Name, subject: domain})
			}
		}
	}
	names := make([]string, 0, len(queries))
	seen := make(map[string]bool, len(queries))
	for _, query := range queries {
		if !seen[query.name] {
			seen[query.name] = true
			names = append(names, query.name)
		}
	}
	answers := e.dns.lookupAll(ctx, names)
	for _, query := range queries {
		answer := answers[query.name]
		verdict := zoneVerdict{err: answer.err}
		if answer.err == nil {
			verdict = query.zone.evaluate(answer.addrs)
		}
		e.dns.record(query.zone, answer, verdict)
		if verdict.err != nil || verdict.refused {
			symbols.builtin("DNS_LOOKUP_ERROR", query.zone.Name)
			continue
		}
		for _, rule := range verdict.hits {
			symbols.add(rule.Symbol, rule.Score, rule.Description, query.subject)
		}
	}
}

// senderDomains returns the distinct registrable envelope, From, and HELO
// domains that may be queried.
func (e *Engine) senderDomains(ctx context.Context, m Message, headers map[string]string) []string {
	var domains []string
	for _, candidate := range []string{extractDomain(m.EnvelopeFrom), extractDomain(headers["from"]), strings.TrimSuffix(strings.ToLower(m.Helo), ".")} {
		domain, ok := registrableDomain(candidate)
		if ok && !slices.Contains(domains, domain) && e.queryableDomain(ctx, domain) {
			domains = append(domains, domain)
		}
	}
	return domains
}

// queryableDomain excludes hosted domains, whose reputation is local.
func (e *Engine) queryableDomain(ctx context.Context, domain string) bool {
	return e.config.IsLocalDomain == nil || !e.config.IsLocalDomain(ctx, domain)
}

// Listing is one DNSBL zone's verdict for an address.
type Listing struct {
	Zone    string   `json:"zone"`
	Listed  bool     `json:"listed"`
	Refused bool     `json:"refused,omitempty"`
	Error   string   `json:"error,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

// CheckAddress asks every DNSBL zone whether addr is listed, through the
// same cache, answer interpretation, and zone statistics as message scoring.
// Operators use it to check the server's own egress addresses.
func (d *DNS) CheckAddress(ctx context.Context, addr netip.Addr, zones []Zone) []Listing {
	addr = addr.Unmap().WithZone("")
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		names = append(names, ReverseIP(addr)+"."+zone.Name)
	}
	answers := d.lookupAll(ctx, names)
	listings := make([]Listing, 0, len(zones))
	for index, zone := range zones {
		answer := answers[names[index]]
		verdict := zoneVerdict{err: answer.err}
		if answer.err == nil {
			verdict = zone.evaluate(answer.addrs)
		}
		d.record(zone, answer, verdict)
		listing := Listing{Zone: zone.Name, Refused: verdict.refused, Listed: len(verdict.hits) > 0}
		if verdict.err != nil {
			listing.Error = verdict.err.Error()
		}
		for _, rule := range verdict.hits {
			listing.Reasons = append(listing.Reasons, cmp.Or(rule.Description, rule.Symbol, rule.Code))
		}
		listings = append(listings, listing)
	}
	return listings
}
