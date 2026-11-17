package dane

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Exchanger sends one DNS query to a validating resolver. Tests substitute
// canned responses; production uses Client.
type Exchanger interface {
	Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
}

// Client queries resolver addresses (host:port) in order over UDP, retrying
// truncated answers over TCP. A resolver's SERVFAIL is final: it is the
// validating resolver's verdict, not a transport failure.
type Client struct {
	Servers []string
	Timeout time.Duration
}

// Exchange implements Exchanger.
func (c *Client) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	lastErr := errors.New("no DANE resolvers are configured")
	for _, server := range c.Servers {
		response, _, err := (&dns.Client{Net: "udp", Timeout: timeout}).ExchangeContext(ctx, query, server)
		if err == nil && response.Truncated {
			response, _, err = (&dns.Client{Net: "tcp", Timeout: timeout}).ExchangeContext(ctx, query, server)
		}
		if err == nil {
			return response, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// Security is the DNSSEC status of one lookup as reported by a trusted
// validating resolver.
type Security string

const (
	// Insecure answers carry no AD bit: the zone is unsigned (or the
	// resolver does not validate), so they cannot authenticate DANE.
	Insecure Security = "insecure"
	// Secure answers carry the AD bit from a trusted validating resolver.
	Secure Security = "secure"
	// Bogus covers SERVFAIL (validation failure on a signed zone) and
	// resolver errors. RFC 7672 treats these as temporary failures.
	Bogus Security = "bogus"
)

// Resolver performs the DNSSEC-aware lookups RFC 7672 needs.
type Resolver struct {
	exchanger Exchanger
}

// NewResolver returns a resolver that trusts the AD bit in answers from
// exchanger. The caller is responsible for exchanger reaching only a
// validating resolver over a trusted path.
func NewResolver(exchanger Exchanger) *Resolver {
	return &Resolver{exchanger: exchanger}
}

func (r *Resolver) lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, Security, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	query.RecursionDesired = true
	query.AuthenticatedData = true
	query.SetEdns0(1232, true)
	label := strings.TrimSuffix(dns.Fqdn(name), ".") + " " + dns.TypeToString[qtype]
	response, err := r.exchanger.Exchange(ctx, query)
	if err != nil {
		return nil, Bogus, fmt.Errorf("%s lookup failed: %w", label, err)
	}
	switch response.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	case dns.RcodeServerFailure:
		return nil, Bogus, fmt.Errorf("%s lookup returned SERVFAIL (DNSSEC validation failure or unreachable zone)", label)
	default:
		return nil, Bogus, fmt.Errorf("%s lookup returned %s", label, dns.RcodeToString[response.Rcode])
	}
	if !response.AuthenticatedData {
		return response.Answer, Insecure, nil
	}
	return response.Answer, Secure, nil
}

// MX is one mail exchanger from a DNSSEC-aware lookup.
type MX struct {
	Host       string
	Preference int
}

// MXResult is the outcome of an MX lookup. A Secure result with no hosts
// means the domain has no MX RRset and its own name is the implicit MX.
type MXResult struct {
	Security Security
	Hosts    []MX
	Err      error
}

// MX looks up domain's MX RRset and its DNSSEC status.
func (r *Resolver) MX(ctx context.Context, domain string) MXResult {
	answer, security, err := r.lookup(ctx, domain, dns.TypeMX)
	result := MXResult{Security: security, Err: err}
	for _, rr := range answer {
		if mx, ok := rr.(*dns.MX); ok {
			result.Hosts = append(result.Hosts, MX{Host: canonicalName(mx.Mx), Preference: int(mx.Preference)})
		}
	}
	sort.SliceStable(result.Hosts, func(i, j int) bool { return result.Hosts[i].Preference < result.Hosts[j].Preference })
	return result
}

// State is the DANE disposition of one MX host.
type State string

const (
	// StateNone: no DNSSEC-authenticated TLSA records; DANE does not apply.
	StateNone State = "none"
	// StateUsable: the server must present a certificate matching a record.
	StateUsable State = "usable"
	// StateUnusable: secure TLSA records exist but none are usable for SMTP;
	// TLS is still mandatory but not authenticated (RFC 7672 section 2.2).
	StateUnusable State = "unusable"
	// StateFailed: a DNSSEC lookup failed; delivery via this host must be
	// deferred (RFC 7672 section 2.2).
	StateFailed State = "failed"
)

// HostPolicy is the DANE policy for one MX host.
type HostPolicy struct {
	Host     string
	State    State
	TLSAName string   // owner name of the secure TLSA RRset
	Records  []Record // the secure TLSA RRset, usable or not
	Names    []string // reference identifiers for DANE-TA name checks
	Reason   string
}

// Usable returns the records SMTP may authenticate with.
func (p HostPolicy) Usable() []Record {
	var usable []Record
	for _, record := range p.Records {
		if record.Usable() {
			usable = append(usable, record)
		}
	}
	return usable
}

// HostPolicy determines the DANE policy for host on port. The caller must
// only ask for hosts obtained from a secure MX lookup (or the domain itself
// as a secure implicit MX). Per RFC 7672 section 2.2.2 the address records
// must be secure; when they are a secure CNAME expansion, TLSA records are
// sought at the expanded name first and then at the original name.
func (r *Resolver) HostPolicy(ctx context.Context, host string, port int) HostPolicy {
	host = canonicalName(host)
	policy := HostPolicy{Host: host, State: StateNone}
	answer, security, err := r.lookup(ctx, host, dns.TypeA)
	if err == nil && security == Secure && !hasAddress(answer) {
		answer, security, err = r.lookup(ctx, host, dns.TypeAAAA)
	}
	switch security {
	case Bogus:
		policy.State, policy.Reason = StateFailed, err.Error()
		return policy
	case Insecure:
		policy.Reason = "address records of " + host + " are not DNSSEC-signed"
		return policy
	}
	bases := []string{host}
	if target := cnameTarget(host, answer); target != host {
		bases = []string{target, host}
	}
	for _, base := range bases {
		name := fmt.Sprintf("_%d._tcp.%s", port, base)
		tlsaAnswer, tlsaSecurity, tlsaErr := r.lookup(ctx, name, dns.TypeTLSA)
		switch tlsaSecurity {
		case Bogus:
			policy.State, policy.Reason = StateFailed, tlsaErr.Error()
			return policy
		case Insecure:
			continue
		}
		records := tlsaRecords(tlsaAnswer)
		if len(records) == 0 {
			continue
		}
		policy.TLSAName, policy.Records = name, records
		policy.Names = uniqueNames(base, host)
		if len(policy.Usable()) > 0 {
			policy.State = StateUsable
		} else {
			policy.State, policy.Reason = StateUnusable, "TLSA records at "+name+" are all unusable for SMTP"
		}
		return policy
	}
	policy.Reason = "no DNSSEC-authenticated TLSA records for " + host
	return policy
}

func hasAddress(answer []dns.RR) bool {
	for _, rr := range answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			return true
		}
	}
	return false
}

// cnameTarget follows the CNAME chain for name within answer.
func cnameTarget(name string, answer []dns.RR) string {
	for range len(answer) {
		next := ""
		for _, rr := range answer {
			if cname, ok := rr.(*dns.CNAME); ok && canonicalName(cname.Hdr.Name) == name {
				next = canonicalName(cname.Target)
				break
			}
		}
		if next == "" || next == name {
			break
		}
		name = next
	}
	return name
}

func tlsaRecords(answer []dns.RR) []Record {
	var records []Record
	for _, rr := range answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		data, err := hex.DecodeString(tlsa.Certificate)
		if err != nil {
			continue
		}
		records = append(records, Record{Usage: tlsa.Usage, Selector: tlsa.Selector, MatchingType: tlsa.MatchingType, Data: data})
	}
	return records
}

func uniqueNames(names ...string) []string {
	var result []string
	for _, name := range names {
		if name != "" && !slices.Contains(result, name) {
			result = append(result, name)
		}
	}
	return result
}

func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
