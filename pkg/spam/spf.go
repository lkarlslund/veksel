// SPF (Sender Policy Framework) evaluation per RFC 7208.
//
// CheckSPF implements check_host() (RFC 7208 section 4): the record is
// fetched from DNS, parsed completely (any syntax error is a permerror),
// and its mechanisms are evaluated in order under the processing limits of
// section 4.6.4, with macro expansion (section 7), include and redirect
// recursion, and the exp= explanation for fail results.

package spam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SPFResult is an RFC 7208 section 2.6 result.
type SPFResult string

const (
	SPFNone      SPFResult = "none"
	SPFNeutral   SPFResult = "neutral"
	SPFPass      SPFResult = "pass"
	SPFFail      SPFResult = "fail"
	SPFSoftfail  SPFResult = "softfail"
	SPFTemperror SPFResult = "temperror"
	SPFPermerror SPFResult = "permerror"
)

// SPF identities (RFC 7208 section 2.3 and 2.4).
const (
	SPFIdentityMailFrom = "mailfrom"
	SPFIdentityHelo     = "helo"
)

// RFC 7208 section 4.6.4 processing limits.
const (
	spfLookupLimit = 10 // DNS-querying terms per evaluation
	spfVoidLimit   = 2  // terms whose lookup returned no answer
	spfMXLimit     = 10 // MX names per mx mechanism
	spfPTRLimit    = 10 // PTR names considered by ptr and %{p}
	// DefaultSPFTimeout bounds one whole evaluation (RFC 7208 section 4.6.4
	// asks for at least 20 seconds).
	DefaultSPFTimeout = 20 * time.Second
	spfMaxDomainLen   = 253
)

// SPFResolver is the DNS boundary of SPF evaluation. *net.Resolver
// implements it. When the resolver also implements
// LookupNetIP(ctx, network, host), A and AAAA queries are made separately;
// otherwise LookupHost answers are filtered by address family.
type SPFResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

type spfNetIPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SPFRequest names the identities of one SPF check.
type SPFRequest struct {
	// IP is the SMTP client address. IPv4-mapped IPv6 is evaluated as IPv4.
	IP netip.Addr
	// Sender is the MAIL FROM address without angle brackets. When empty,
	// the check uses postmaster@Helo (RFC 7208 section 2.4).
	Sender string
	// Helo is the HELO/EHLO domain (%{h}).
	Helo string
	// Receiver is the checking host's domain (%{r} in explanations).
	Receiver string
	// Timeout bounds the whole evaluation; zero selects DefaultSPFTimeout.
	Timeout time.Duration
	// Now supplies %{t}; nil uses time.Now.
	Now func() time.Time
}

// SPFOutcome is the result of CheckSPF.
type SPFOutcome struct {
	Result SPFResult
	// Identity is SPFIdentityMailFrom or SPFIdentityHelo.
	Identity string
	// Sender is the evaluated sender (postmaster@helo for a null sender).
	Sender string
	// Domain is the domain whose policy was evaluated.
	Domain string
	// Mechanism is the term of the checked domain's policy (or its
	// redirect target) that decided the result, empty for the default.
	Mechanism string
	// Explanation is the expanded exp= text of a fail result.
	Explanation string
	// Problem describes why the result is temperror or permerror.
	Problem string
	// Lookups counts the DNS-querying terms evaluated.
	Lookups int
}

// CheckSPF evaluates the SPF policy of the request's sender (or HELO
// domain for a null sender) for the client IP.
func CheckSPF(ctx context.Context, resolver SPFResolver, req SPFRequest) SPFOutcome {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultSPFTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	helo := normalizeSPFDomain(req.Helo)
	outcome := SPFOutcome{Identity: SPFIdentityMailFrom}
	sender := strings.TrimSpace(strings.Trim(strings.TrimSpace(req.Sender), "<>"))
	local, domain := "", ""
	if sender == "" {
		outcome.Identity = SPFIdentityHelo
		local, domain = "postmaster", helo
	} else {
		at := strings.LastIndexByte(sender, '@')
		if at < 0 {
			local, domain = "postmaster", sender
		} else {
			local, domain = sender[:at], sender[at+1:]
		}
		if local == "" {
			local = "postmaster"
		}
		domain = normalizeSPFDomain(domain)
	}
	outcome.Sender = local + "@" + domain
	outcome.Domain = domain
	if !req.IP.IsValid() {
		outcome.Result, outcome.Problem = SPFPermerror, "invalid client IP"
		return outcome
	}
	e := &spfEval{
		ctx: ctx, resolver: resolver, ip: req.IP.Unmap().WithZone(""),
		sender: outcome.Sender, local: local, senderDomain: domain,
		helo: helo, receiver: req.Receiver, now: req.Now,
	}
	result, err := e.checkHost(domain, true)
	outcome.Result, outcome.Lookups = result, e.lookups
	outcome.Mechanism, outcome.Explanation = e.mechanism, e.explanation
	if err != nil {
		outcome.Problem = err.Error()
	}
	return outcome
}

// normalizeSPFDomain lower-cases a domain and drops one trailing dot.
func normalizeSPFDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// spfError carries a temperror or permerror out of nested evaluation.
type spfError struct {
	result SPFResult
	msg    string
}

func (e *spfError) Error() string { return e.msg }

func permerror(format string, args ...any) error {
	return &spfError{result: SPFPermerror, msg: fmt.Sprintf(format, args...)}
}

func temperror(format string, args ...any) error {
	return &spfError{result: SPFTemperror, msg: fmt.Sprintf(format, args...)}
}

func errorResult(err error) SPFResult {
	var spfErr *spfError
	if errors.As(err, &spfErr) {
		return spfErr.result
	}
	return SPFTemperror
}

type spfEval struct {
	ctx          context.Context
	resolver     SPFResolver
	ip           netip.Addr
	sender       string
	local        string
	senderDomain string
	helo         string
	receiver     string
	now          func() time.Time

	lookups     int
	voids       int
	ptrNames    []string
	ptrDone     bool
	mechanism   string
	explanation string
}

// checkHost is RFC 7208 check_host(). top marks the checked domain's own
// policy and its redirect targets, whose deciding term and exp= are kept.
func (e *spfEval) checkHost(domain string, top bool) (SPFResult, error) {
	if !validSPFDomain(domain) {
		return SPFNone, nil
	}
	if err := e.ctx.Err(); err != nil {
		return SPFTemperror, temperror("SPF evaluation timed out")
	}
	txt, err := e.resolver.LookupTXT(e.ctx, domain)
	if err != nil {
		if isNotFound(err) {
			return SPFNone, nil
		}
		return SPFTemperror, temperror("TXT lookup for %s: %v", domain, err)
	}
	var records []string
	for _, value := range txt {
		if isSPFRecord(value) {
			records = append(records, value)
		}
	}
	switch len(records) {
	case 0:
		return SPFNone, nil
	case 1:
	default:
		return SPFPermerror, permerror("multiple SPF records at %s", domain)
	}
	record, err := parseSPFRecord(records[0])
	if err != nil {
		return SPFPermerror, permerror("%s: %v", domain, err)
	}
	for _, term := range record.directives {
		matched, err := e.matches(domain, term)
		if err != nil {
			return errorResult(err), err
		}
		if !matched {
			continue
		}
		result := term.qualifier.result()
		if top {
			e.mechanism = term.raw
			if result == SPFFail && record.exp != "" {
				e.explanation = e.explain(domain, record.exp)
			}
		}
		return result, nil
	}
	if record.redirect == "" {
		if top {
			e.mechanism = ""
		}
		return SPFNeutral, nil
	}
	if err := e.countLookup(); err != nil {
		return SPFPermerror, err
	}
	target, err := e.expandDomain(record.redirect, domain)
	if err != nil {
		return errorResult(err), err
	}
	result, err := e.checkHost(target, top)
	if result == SPFNone {
		return SPFPermerror, permerror("redirect target %s has no SPF record", target)
	}
	return result, err
}

func isSPFRecord(value string) bool {
	return len(value) >= 6 && strings.EqualFold(value[:6], "v=spf1") && (len(value) == 6 || value[6] == ' ')
}

func (e *spfEval) countLookup() error {
	e.lookups++
	if e.lookups > spfLookupLimit {
		return permerror("SPF evaluation exceeded the %d DNS lookup limit", spfLookupLimit)
	}
	return nil
}

func (e *spfEval) countVoid() error {
	e.voids++
	if e.voids > spfVoidLimit {
		return permerror("SPF evaluation exceeded the %d void lookup limit", spfVoidLimit)
	}
	return nil
}

// matches evaluates one directive against the client IP.
func (e *spfEval) matches(domain string, term spfDirective) (bool, error) {
	switch term.mechanism {
	case "all":
		return true, nil
	case "ip4", "ip6":
		return term.prefix.Contains(e.ip), nil
	case "include":
		if err := e.countLookup(); err != nil {
			return false, err
		}
		target, err := e.expandDomain(term.domain, domain)
		if err != nil {
			return false, err
		}
		result, err := e.checkHost(target, false)
		switch result {
		case SPFPass:
			return true, nil
		case SPFFail, SPFSoftfail, SPFNeutral:
			return false, nil
		case SPFNone:
			return false, permerror("included domain %s has no SPF record", target)
		}
		return false, err
	}
	if err := e.countLookup(); err != nil {
		return false, err
	}
	target := domain
	if term.domain != "" {
		var err error
		if target, err = e.expandDomain(term.domain, domain); err != nil {
			return false, err
		}
	}
	switch term.mechanism {
	case "a":
		addrs, err := e.lookupIP(target, e.ip.Is4())
		if err != nil {
			return false, err
		}
		if len(addrs) == 0 {
			return false, e.countVoid()
		}
		return term.covers(addrs, e.ip), nil
	case "mx":
		return e.matchMX(target, term)
	case "ptr":
		names, err := e.validatedNames()
		if err != nil {
			return false, err
		}
		return slices.ContainsFunc(names, func(name string) bool {
			return name == target || strings.HasSuffix(name, "."+target)
		}), nil
	case "exists":
		addrs, err := e.lookupIP(target, true)
		if err != nil {
			return false, err
		}
		if len(addrs) == 0 {
			return false, e.countVoid()
		}
		return true, nil
	}
	return false, permerror("unknown mechanism %s", term.mechanism)
}

func (e *spfEval) matchMX(target string, term spfDirective) (bool, error) {
	if !validLookupName(target) {
		return false, e.countVoid()
	}
	records, err := e.resolver.LookupMX(e.ctx, target)
	if err != nil && !isNotFound(err) {
		return false, temperror("MX lookup for %s: %v", target, err)
	}
	var hosts []string
	for _, mx := range records {
		// A null MX (".") names no host.
		if host := normalizeSPFDomain(mx.Host); strings.Trim(host, ".") != "" {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return false, e.countVoid()
	}
	if len(hosts) > spfMXLimit {
		return false, permerror("mx:%s returned more than %d names", target, spfMXLimit)
	}
	for _, host := range hosts {
		addrs, err := e.lookupIP(host, e.ip.Is4())
		if err != nil {
			return false, err
		}
		if term.covers(addrs, e.ip) {
			return true, nil
		}
	}
	return false, nil
}

// lookupIP returns the A (v4) or AAAA addresses of name; a name that does
// not exist or has no such records yields no addresses.
func (e *spfEval) lookupIP(name string, v4 bool) ([]netip.Addr, error) {
	if !validLookupName(name) {
		return nil, nil
	}
	if err := e.ctx.Err(); err != nil {
		return nil, temperror("SPF evaluation timed out")
	}
	var addrs []netip.Addr
	if r, ok := e.resolver.(spfNetIPResolver); ok {
		network := "ip6"
		if v4 {
			network = "ip4"
		}
		found, err := r.LookupNetIP(e.ctx, network, name)
		if err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, temperror("address lookup for %s: %v", name, err)
		}
		addrs = found
	} else {
		hosts, err := e.resolver.LookupHost(e.ctx, name)
		if err != nil {
			if isNotFound(err) {
				return nil, nil
			}
			return nil, temperror("address lookup for %s: %v", name, err)
		}
		for _, host := range hosts {
			if addr, err := netip.ParseAddr(host); err == nil {
				addrs = append(addrs, addr)
			}
		}
	}
	out := addrs[:0]
	for _, addr := range addrs {
		addr = addr.Unmap().WithZone("")
		if addr.Is4() == v4 {
			out = append(out, addr)
		}
	}
	return out, nil
}

// validatedNames returns the client's PTR names that resolve back to it
// (RFC 7208 section 5.5), at most spfPTRLimit of them considered.
func (e *spfEval) validatedNames() ([]string, error) {
	names, err := e.resolver.LookupAddr(e.ctx, e.ip.String())
	if err != nil || len(names) == 0 {
		// A PTR lookup error makes ptr fail to match.
		if err == nil || isNotFound(err) {
			return nil, e.countVoid()
		}
		return nil, nil
	}
	if len(names) > spfPTRLimit {
		names = names[:spfPTRLimit]
	}
	var validated []string
	for _, name := range names {
		name = normalizeSPFDomain(name)
		addrs, err := e.lookupIP(name, e.ip.Is4())
		if err != nil {
			continue
		}
		if slices.Contains(addrs, e.ip) {
			validated = append(validated, name)
		}
	}
	return validated, nil
}

// explain expands the exp= explanation of a fail result. Any problem
// leaves the explanation empty (RFC 7208 section 6.2).
func (e *spfEval) explain(domain, spec string) string {
	target, err := e.expandDomain(spec, domain)
	if err != nil || !validLookupName(target) {
		return ""
	}
	txt, err := e.resolver.LookupTXT(e.ctx, target)
	if err != nil || len(txt) != 1 {
		return ""
	}
	text, err := e.expand(txt[0], domain, true)
	if err != nil {
		return ""
	}
	return printableASCII(text, 512)
}

func printableASCII(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, value)
	return strings.TrimSpace(value[:min(len(value), limit)])
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// validSPFDomain reports whether domain is a well-formed multi-label name
// (RFC 7208 section 4.3); malformed domains evaluate to none.
func validSPFDomain(domain string) bool {
	if !validLookupName(domain) || !strings.Contains(domain, ".") {
		return false
	}
	for i := 0; i < len(domain); i++ {
		if c := domain[i]; !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// validLookupName reports whether name can be queried: at most 253 octets,
// non-empty labels of at most 63 octets, and not an IP literal.
func validLookupName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > spfMaxDomainLen {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

// --- Record parsing (RFC 7208 section 4.6 and 12) ---

type spfQualifier byte

func (q spfQualifier) result() SPFResult {
	switch q {
	case '-':
		return SPFFail
	case '~':
		return SPFSoftfail
	case '?':
		return SPFNeutral
	}
	return SPFPass
}

type spfDirective struct {
	raw       string
	qualifier spfQualifier
	mechanism string
	// domain is the unexpanded domain-spec of include, a, mx, ptr, exists.
	domain string
	// prefix is the network of ip4 and ip6.
	prefix netip.Prefix
	// v4Bits and v6Bits are the dual-cidr lengths of a and mx.
	v4Bits, v6Bits int
}

// covers reports whether ip lies within one of addrs under the term's
// CIDR lengths.
func (d spfDirective) covers(addrs []netip.Addr, ip netip.Addr) bool {
	for _, addr := range addrs {
		bits := d.v6Bits
		if addr.Is4() {
			bits = d.v4Bits
		}
		if prefix, err := addr.Prefix(bits); err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

type spfRecord struct {
	directives []spfDirective
	redirect   string
	exp        string
}

// ParseSPFRecord reports whether record is a syntactically valid SPF
// record; the error names the first problem.
func ParseSPFRecord(record string) error {
	_, err := parseSPFRecord(record)
	return err
}

func parseSPFRecord(record string) (spfRecord, error) {
	var out spfRecord
	if !isSPFRecord(record) {
		return out, errors.New("missing v=spf1 version tag")
	}
	seenRedirect, seenExp := false, false
	for term := range strings.SplitSeq(record[6:], " ") {
		if term == "" {
			continue
		}
		if name, value, ok := strings.Cut(term, "="); ok && validModifierName(name) {
			switch strings.ToLower(name) {
			case "redirect":
				if seenRedirect {
					return out, errors.New("duplicate redirect modifier")
				}
				if err := checkDomainSpec(value); err != nil {
					return out, fmt.Errorf("redirect=%s: %w", value, err)
				}
				seenRedirect, out.redirect = true, value
			case "exp":
				if seenExp {
					return out, errors.New("duplicate exp modifier")
				}
				if err := checkDomainSpec(value); err != nil {
					return out, fmt.Errorf("exp=%s: %w", value, err)
				}
				seenExp, out.exp = true, value
			default:
				// Unknown modifiers are ignored but must be well formed.
				if err := checkMacroString(value, false); err != nil {
					return out, fmt.Errorf("%s: %w", term, err)
				}
			}
			continue
		}
		directive, err := parseSPFDirective(term)
		if err != nil {
			return out, fmt.Errorf("%s: %w", term, err)
		}
		out.directives = append(out.directives, directive)
	}
	return out, nil
}

func validModifierName(name string) bool {
	if name == "" || !isAlpha(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func parseSPFDirective(term string) (spfDirective, error) {
	d := spfDirective{raw: term, qualifier: '+', v4Bits: 32, v6Bits: 128}
	rest := term
	if strings.IndexByte("+-~?", rest[0]) >= 0 {
		d.qualifier, rest = spfQualifier(rest[0]), rest[1:]
	}
	// The mechanism name ends at the first ':' or '/'.
	end := strings.IndexAny(rest, ":/")
	if end < 0 {
		end = len(rest)
	}
	d.mechanism, rest = strings.ToLower(rest[:end]), rest[end:]
	switch d.mechanism {
	case "all":
		if rest != "" {
			return d, errors.New("all takes no argument")
		}
	case "include", "exists":
		spec, ok := strings.CutPrefix(rest, ":")
		if !ok || spec == "" {
			return d, errors.New("missing domain")
		}
		if err := checkDomainSpec(spec); err != nil {
			return d, err
		}
		d.domain = spec
	case "ptr":
		if rest != "" {
			spec, ok := strings.CutPrefix(rest, ":")
			if !ok || spec == "" {
				return d, errors.New("malformed ptr")
			}
			if err := checkDomainSpec(spec); err != nil {
				return d, err
			}
			d.domain = spec
		}
	case "a", "mx":
		spec, cidr := rest, ""
		if after, ok := strings.CutPrefix(rest, ":"); ok {
			spec, cidr = splitCIDR(after)
			if spec == "" {
				return d, errors.New("missing domain")
			}
			if err := checkDomainSpec(spec); err != nil {
				return d, err
			}
		} else {
			spec, cidr = "", rest
		}
		d.domain = spec
		var err error
		if d.v4Bits, d.v6Bits, err = parseDualCIDR(cidr); err != nil {
			return d, err
		}
	case "ip4", "ip6":
		value, ok := strings.CutPrefix(rest, ":")
		if !ok || value == "" {
			return d, errors.New("missing network")
		}
		network, bitsText, hasBits := strings.Cut(value, "/")
		addr, err := netip.ParseAddr(network)
		if err != nil || addr.Zone() != "" || addr.Is4() != (d.mechanism == "ip4") {
			return d, fmt.Errorf("invalid %s network", d.mechanism)
		}
		bits := addr.BitLen()
		if hasBits {
			if bits, err = parseCIDRLength(bitsText, addr.BitLen()); err != nil {
				return d, err
			}
		}
		// Mapped ip6 networks match their IPv4 clients.
		if addr.Is4In6() && bits >= 96 {
			addr, bits = addr.Unmap(), bits-96
		}
		d.prefix, err = addr.Prefix(bits)
		if err != nil {
			return d, err
		}
	default:
		return d, errors.New("unknown mechanism")
	}
	return d, nil
}

// splitCIDR splits "domain/cidr" at the first '/' outside a macro.
func splitCIDR(value string) (spec, cidr string) {
	depth := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '{':
			if i > 0 && value[i-1] == '%' {
				depth++
			}
		case '}':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				return value[:i], value[i:]
			}
		}
	}
	return value, ""
}

// parseDualCIDR parses "", "/v4", "//v6" or "/v4//v6".
func parseDualCIDR(cidr string) (v4, v6 int, err error) {
	v4, v6 = 32, 128
	if cidr == "" {
		return v4, v6, nil
	}
	if after, ok := strings.CutPrefix(cidr, "//"); ok {
		v6, err = parseCIDRLength(after, 128)
		return v4, v6, err
	}
	first, second, dual := strings.Cut(strings.TrimPrefix(cidr, "/"), "//")
	if !strings.HasPrefix(cidr, "/") {
		return v4, v6, errors.New("malformed CIDR length")
	}
	if v4, err = parseCIDRLength(first, 32); err != nil {
		return v4, v6, err
	}
	if dual {
		v6, err = parseCIDRLength(second, 128)
	}
	return v4, v6, err
}

func parseCIDRLength(text string, max int) (int, error) {
	if text == "" || len(text) > 3 || (len(text) > 1 && text[0] == '0') {
		return 0, errors.New("malformed CIDR length")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 0 || n > max {
		return 0, errors.New("malformed CIDR length")
	}
	return n, nil
}

// checkDomainSpec validates a domain-spec: a macro-string ending in a
// macro-expand or a "." toplabel.
func checkDomainSpec(spec string) error {
	if err := checkMacroString(spec, false); err != nil {
		return err
	}
	tail, endsInMacro := literalTail(spec)
	tail = strings.TrimSuffix(tail, ".")
	if tail == "" {
		if endsInMacro {
			return nil
		}
		return errors.New("empty domain")
	}
	dot := strings.LastIndexByte(tail, '.')
	if dot < 0 {
		if endsInMacro {
			// "%{d}com" is not a domain-end, but "%{d}" + ".com" is.
			return errors.New("domain must end in a top-level label")
		}
		return errors.New("domain must have more than one label")
	}
	if !validTopLabel(tail[dot+1:]) {
		return errors.New("invalid top-level label")
	}
	return nil
}

// literalTail returns the literal text after the last macro-expand of a
// syntactically valid macro-string, and whether the string contained one.
func literalTail(spec string) (string, bool) {
	var tail strings.Builder
	sawMacro := false
	for i := 0; i < len(spec); i++ {
		if spec[i] != '%' {
			tail.WriteByte(spec[i])
			continue
		}
		i++
		switch spec[i] {
		case '{':
			end := strings.IndexByte(spec[i:], '}')
			i += end
			tail.Reset()
			sawMacro = true
		case '%':
			tail.WriteByte('%')
		case '_':
			tail.WriteByte(' ')
		case '-':
			tail.WriteString("%20")
		}
	}
	return tail.String(), sawMacro
}

// validTopLabel implements RFC 7208 toplabel: alphanumerics with at least
// one letter, or an inner-hyphenated alphanumeric label.
func validTopLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	hasAlpha := false
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case isAlpha(c):
			hasAlpha = true
		case isDigit(c):
		case c == '-':
			if i == 0 || i == len(label)-1 {
				return false
			}
			hasAlpha = true // the hyphenated form needs no letter
		default:
			return false
		}
	}
	return hasAlpha
}

// checkMacroString validates RFC 7208 macro-string syntax. The c, r and t
// macro letters are only valid in explanation text.
func checkMacroString(value string, exp bool) error {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '%' {
			if c < 0x21 || c > 0x7e {
				if exp && c == ' ' {
					continue
				}
				return errors.New("invalid character")
			}
			continue
		}
		if i+1 >= len(value) {
			return errors.New("dangling %")
		}
		i++
		switch value[i] {
		case '%', '_', '-':
			continue
		case '{':
		default:
			return errors.New("invalid macro escape")
		}
		end := strings.IndexByte(value[i:], '}')
		if end < 0 {
			return errors.New("unterminated macro")
		}
		if _, err := parseMacro(value[i+1:i+end], exp); err != nil {
			return err
		}
		i += end
	}
	return nil
}

type spfMacro struct {
	letter     byte // lower case
	escape     bool // upper-case letter: URL-escape the value
	digits     int  // 0 keeps every part
	reverse    bool
	delimiters string
}

func parseMacro(body string, exp bool) (spfMacro, error) {
	var m spfMacro
	if body == "" {
		return m, errors.New("empty macro")
	}
	letter := body[0]
	if letter >= 'A' && letter <= 'Z' {
		m.escape, letter = true, letter+'a'-'A'
	}
	switch letter {
	case 's', 'l', 'o', 'd', 'i', 'p', 'h', 'v':
	case 'c', 'r', 't':
		if !exp {
			return m, fmt.Errorf("macro %%{%c} is only valid in explanations", body[0])
		}
	default:
		return m, fmt.Errorf("invalid macro letter %q", body[0])
	}
	m.letter = letter
	rest := body[1:]
	n := 0
	for n < len(rest) && isDigit(rest[n]) {
		n++
	}
	if n > 0 {
		digits, err := strconv.Atoi(rest[:n])
		if err != nil || digits == 0 || n > 3 {
			return m, errors.New("invalid macro digit transformer")
		}
		m.digits = digits
	}
	rest = rest[n:]
	if rest != "" && (rest[0] == 'r' || rest[0] == 'R') {
		m.reverse, rest = true, rest[1:]
	}
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte(".-+,/_=", rest[i]) < 0 {
			return m, fmt.Errorf("invalid macro delimiter %q", rest[i])
		}
	}
	m.delimiters = rest
	return m, nil
}

// --- Macro expansion (RFC 7208 section 7) ---

// expandDomain expands a domain-spec for a DNS query, truncating labels
// from the left to fit 253 octets (RFC 7208 section 7.3).
func (e *spfEval) expandDomain(spec, domain string) (string, error) {
	expanded, err := e.expand(spec, domain, false)
	if err != nil {
		return "", err
	}
	expanded = normalizeSPFDomain(expanded)
	for len(expanded) > spfMaxDomainLen {
		dot := strings.IndexByte(expanded, '.')
		if dot < 0 {
			return "", nil
		}
		expanded = expanded[dot+1:]
	}
	return expanded, nil
}

func (e *spfEval) expand(value, domain string, exp bool) (string, error) {
	if !strings.Contains(value, "%") {
		return value, nil
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '%' {
			out.WriteByte(c)
			continue
		}
		if i+1 >= len(value) {
			return "", permerror("dangling %% in %q", value)
		}
		i++
		switch value[i] {
		case '%':
			out.WriteByte('%')
			continue
		case '_':
			out.WriteByte(' ')
			continue
		case '-':
			out.WriteString("%20")
			continue
		case '{':
		default:
			return "", permerror("invalid macro escape in %q", value)
		}
		end := strings.IndexByte(value[i:], '}')
		if end < 0 {
			return "", permerror("unterminated macro in %q", value)
		}
		m, err := parseMacro(value[i+1:i+end], exp)
		if err != nil {
			return "", permerror("%v", err)
		}
		i += end
		raw, err := e.macroValue(m.letter, domain)
		if err != nil {
			return "", err
		}
		out.WriteString(m.transform(raw))
	}
	return out.String(), nil
}

func (e *spfEval) macroValue(letter byte, domain string) (string, error) {
	switch letter {
	case 's':
		return e.sender, nil
	case 'l':
		return e.local, nil
	case 'o':
		return e.senderDomain, nil
	case 'd':
		return domain, nil
	case 'i':
		return dottedIP(e.ip), nil
	case 'p':
		return e.validatedName(domain), nil
	case 'h':
		return e.helo, nil
	case 'v':
		if e.ip.Is4() {
			return "in-addr", nil
		}
		return "ip6", nil
	case 'c':
		return e.ip.String(), nil
	case 'r':
		if e.receiver == "" {
			return "unknown", nil
		}
		return e.receiver, nil
	case 't':
		now := time.Now
		if e.now != nil {
			now = e.now
		}
		return strconv.FormatInt(now().Unix(), 10), nil
	}
	return "", permerror("invalid macro letter %q", letter)
}

// validatedName is %{p}: a validated PTR name, preferring the domain
// itself, then a subdomain of it (RFC 7208 section 7.3).
func (e *spfEval) validatedName(domain string) string {
	if !e.ptrDone {
		// The PTR names are resolved once; the preference depends on domain.
		e.ptrDone = true
		voids := e.voids
		e.ptrNames, _ = e.validatedNames()
		e.voids = voids
	}
	best, bestRank := "unknown", 3
	for _, name := range e.ptrNames {
		rank := 2
		switch {
		case name == domain:
			rank = 0
		case strings.HasSuffix(name, "."+domain):
			rank = 1
		}
		if rank < bestRank {
			best, bestRank = name, rank
		}
	}
	return best
}

func (m spfMacro) transform(value string) string {
	delimiters := m.delimiters
	if delimiters == "" {
		delimiters = "."
	}
	parts := splitAny(value, delimiters)
	if m.reverse {
		slices.Reverse(parts)
	}
	if m.digits > 0 && m.digits < len(parts) {
		parts = parts[len(parts)-m.digits:]
	}
	result := strings.Join(parts, ".")
	if m.escape {
		result = urlEscape(result)
	}
	return result
}

func splitAny(value, delimiters string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(value); i++ {
		if strings.IndexByte(delimiters, value[i]) >= 0 {
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	return append(parts, value[start:])
}

// urlEscape percent-encodes everything outside the RFC 3986 unreserved set.
func urlEscape(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~' {
			out.WriteByte(c)
			continue
		}
		fmt.Fprintf(&out, "%%%02X", c)
	}
	return out.String()
}

// dottedIP is %{i}: dotted-quad IPv4 or dot-separated IPv6 nibbles.
func dottedIP(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String()
	}
	const hex = "0123456789abcdef"
	raw := ip.As16()
	parts := make([]byte, 0, 63)
	for i, b := range raw {
		if i > 0 {
			parts = append(parts, '.')
		}
		parts = append(parts, hex[b>>4], '.', hex[b&0x0f])
	}
	return string(parts)
}
