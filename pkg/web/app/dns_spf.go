package app

import (
	"context"
	"net/netip"
	"strings"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/spam"
)

const spfNote = "Ok when the record authorizes the SMTP server's addresses (mx, a, ip4/ip6, include, redirect)."

// checkSPF reports whether the domain's live SPF policy authorizes the SMTP
// server's addresses, instead of requiring the exact recommended string. With
// smtp_public_address set, that is the only address mail leaves from (the
// server name may resolve to an internal address behind NAT or split DNS),
// so only it is checked.
func checkSPF(ctx context.Context, resolver DNSResolver, domain, server, publicAddr string) dnsGuidanceRecord {
	rec := checkTXT(ctx, resolver, "SPF", domain, dkim.SPFDNSRecord(true), "v=spf1", spfNote)
	rec.Live = spfRecords(rec.Live)
	if len(rec.Live) == 0 {
		if rec.Status == dnsMismatch {
			rec.Status = dnsMissing
		}
		return rec
	}
	if len(rec.Live) > 1 {
		rec.Status, rec.Note = dnsMismatch, "Multiple v=spf1 records are an SPF permerror (RFC 7208); publish exactly one."
		return rec
	}
	var hosts []string
	var err error
	if public, perr := netip.ParseAddr(strings.TrimSpace(publicAddr)); perr == nil {
		hosts = []string{public.Unmap().String()}
	} else {
		hosts, err = resolver.LookupHost(ctx, server)
	}
	addrs := parseAddrs(hosts)
	if len(addrs) == 0 {
		rec.Status, rec.Error = dnsError, "SMTP server name has no addresses to check"
		if err != nil {
			rec.Error = err.Error()
		}
		return rec
	}
	rec.Status = dnsOK
	permissive := false
	for _, addr := range addrs {
		verdict := evaluateSPF(ctx, resolver, domain, server, addr)
		switch {
		case verdict.problem != "":
			rec.Status, rec.Error = dnsError, verdict.problem
			return rec
		case !verdict.authorized:
			rec.Status, rec.Note = dnsMismatch, "SPF record does not authorize "+strings.Join(hosts, ", ")
			return rec
		}
		permissive = permissive || verdict.permissive
	}
	if permissive {
		rec.Note = "Authorized, but the record ends in +all or ?all, which lets any sender pass or stay neutral."
	}
	return rec
}

// spfVerdict is the administrative reading of one RFC 7208 evaluation.
type spfVerdict struct {
	outcome spam.SPFOutcome
	// authorized is a pass, or a neutral decided by the domain's own ?all,
	// which is accepted with a warning like +all.
	authorized bool
	// permissive marks authorization through +all or ?all.
	permissive bool
	// problem describes a temperror or permerror.
	problem string
}

// evaluateSPF runs the same RFC 7208 check_host() as inbound SMTP for mail
// from postmaster@domain sent by addr.
func evaluateSPF(ctx context.Context, resolver DNSResolver, domain, server string, addr netip.Addr) spfVerdict {
	outcome := spam.CheckSPF(ctx, resolver, spam.SPFRequest{IP: addr, Sender: "postmaster@" + domain, Helo: server, Timeout: dnsGuidanceTimeout})
	verdict := spfVerdict{outcome: outcome}
	allTerm := strings.EqualFold(strings.TrimLeft(outcome.Mechanism, "+?"), "all")
	switch outcome.Result {
	case spam.SPFPass:
		verdict.authorized, verdict.permissive = true, allTerm
	case spam.SPFNeutral:
		verdict.authorized = allTerm && strings.HasPrefix(outcome.Mechanism, "?")
		verdict.permissive = verdict.authorized
	case spam.SPFTemperror, spam.SPFPermerror:
		verdict.problem = "SPF " + string(outcome.Result) + ": " + outcome.Problem
	}
	return verdict
}

func parseAddrs(hosts []string) []netip.Addr {
	var out []netip.Addr
	for _, host := range hosts {
		if addr, err := netip.ParseAddr(host); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// spfRecords keeps values whose first term is exactly the v=spf1 version tag.
func spfRecords(values []string) []string {
	var out []string
	for _, value := range values {
		if fields := strings.Fields(value); len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1") {
			out = append(out, value)
		}
	}
	return out
}
