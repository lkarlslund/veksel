package smtp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// PregreetAction is what the inbound listener does with a client that sends
// data before the greeting has finished.
type PregreetAction string

const (
	// PregreetOff disables the greeting delay and the early-talker test.
	PregreetOff PregreetAction = "off"
	// PregreetScore records SMTP_PREGREET and a ban strike, then serves the
	// session normally.
	PregreetScore PregreetAction = "score"
	// PregreetReject also answers 554 and closes the connection.
	PregreetReject PregreetAction = "reject"
)

// Connection screening bounds.
const (
	// maxLineLength caps every line the session reads before DATA: the
	// RFC 4954 limit for an AUTH command with its initial response. Longer
	// lines are discarded unread.
	maxLineLength = 12288
	// maxCommandLength is the longest non-AUTH command accepted: the RFC
	// 5321 512-octet base with room for MAIL and RCPT extension parameters.
	maxCommandLength = 2048
	// junkCommandLimit is the number of RSET, NOOP, VRFY, and EXPN commands
	// a client may send per accepted message before each further one counts
	// as a protocol violation.
	junkCommandLimit = 100
	// maxTarpitDelay bounds the delay before one RCPT reply.
	maxTarpitDelay = 10 * time.Second
	// rdnsTimeout bounds the reverse and forward lookups of one FCrDNS check.
	rdnsTimeout = 3 * time.Second
	// maxConnectionFindings bounds the facts one session collects.
	maxConnectionFindings = 32

	passedTTL       = 24 * time.Hour
	maxPassedCached = 50000
	rdnsTTL         = time.Hour
	maxRDNSCached   = 10000
)

// errLineTooLong reports a line longer than maxLineLength; its remainder has
// been discarded.
var errLineTooLong = errors.New("line too long")

// Screening is the postscreen-style connection-stage protection of the
// inbound (port 25) listener. The zero value screens nothing. Authenticated
// sessions, listeners that require authentication, and clients in Exempt
// are never screened.
type Screening struct {
	// GreetDelay holds the greeting back, after a first "220-" line, to
	// catch clients that talk before it finishes. Zero disables the test.
	GreetDelay time.Duration
	// Pregreet is the action for an early talker; empty or off disables
	// the test.
	Pregreet PregreetAction
	// ViolationLimit closes the session with 421 and a ban strike once this
	// many protocol violations were counted. Zero never closes.
	ViolationLimit int
	// TarpitAfterUnknownRcpts delays every further RCPT reply, increasingly
	// and boundedly, once a session probed this many unknown recipients.
	// Zero disables tarpitting.
	TarpitAfterUnknownRcpts int
	// FCrDNS checks that the client's reverse DNS name resolves back to its
	// address and scores the outcome.
	FCrDNS bool
	// Exempt lists client prefixes that are never screened.
	Exempt []netip.Prefix
	// Cache remembers clients that passed the greeting test and reverse
	// DNS outcomes; it should outlive configuration changes. Nil remembers
	// nothing.
	Cache *ScreenCache
	// Resolver performs the FCrDNS lookups; nil uses net.DefaultResolver.
	Resolver Resolver

	// sleep replaces time.Sleep for tarpit delays in tests.
	sleep func(time.Duration)
}

// Resolver is the DNS boundary of the FCrDNS check. *net.Resolver
// implements it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// greetingTest reports whether the early-talker test is enabled.
func (sc *Screening) greetingTest() bool {
	return sc.GreetDelay > 0 && sc.Pregreet != "" && sc.Pregreet != PregreetOff
}

func (sc *Screening) exempt(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	return slices.ContainsFunc(sc.Exempt, func(prefix netip.Prefix) bool { return prefix.Contains(addr) })
}

func (sc *Screening) resolver() Resolver {
	if sc.Resolver != nil {
		return sc.Resolver
	}
	return net.DefaultResolver
}

func (sc *Screening) pause(delay time.Duration) {
	if sc.sleep != nil {
		sc.sleep(delay)
		return
	}
	time.Sleep(delay)
}

// ScreenCache is the bounded cross-session memory of connection screening.
// The zero value is ready to use and safe for concurrent use.
type ScreenCache struct {
	mu     sync.Mutex
	passed ttlMap[struct{}]
	rdns   ttlMap[[]spam.ConnectionFinding]
}

// Passed reports whether ip passed the greeting test within the last day.
func (c *ScreenCache) Passed(ip string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.passed.get(ip, time.Now())
	return ok
}

func (c *ScreenCache) pass(ip string) {
	if c != nil {
		c.mu.Lock()
		c.passed.put(ip, struct{}{}, time.Now().Add(passedTTL), maxPassedCached)
		c.mu.Unlock()
	}
}

// forget drops a client that misbehaved from the passed set.
func (c *ScreenCache) forget(ip string) {
	if c != nil {
		c.mu.Lock()
		c.passed.delete(ip)
		c.mu.Unlock()
	}
}

func (c *ScreenCache) reverseDNS(ip string) ([]spam.ConnectionFinding, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rdns.get(ip, time.Now())
}

func (c *ScreenCache) storeReverseDNS(ip string, findings []spam.ConnectionFinding) {
	if c != nil {
		c.mu.Lock()
		c.rdns.put(ip, findings, time.Now().Add(rdnsTTL), maxRDNSCached)
		c.mu.Unlock()
	}
}

// ttlMap is a size-bounded map whose entries expire. Callers serialize it.
type ttlMap[V any] struct {
	entries map[string]ttlEntry[V]
}

type ttlEntry[V any] struct {
	value   V
	expires time.Time
}

func (m *ttlMap[V]) get(key string, now time.Time) (V, bool) {
	entry, ok := m.entries[key]
	if !ok || now.After(entry.expires) {
		var zero V
		return zero, false
	}
	return entry.value, true
}

// put stores value until expires. A full map first drops expired entries,
// then arbitrary ones down to nine tenths of limit.
func (m *ttlMap[V]) put(key string, value V, expires time.Time, limit int) {
	if m.entries == nil {
		m.entries = make(map[string]ttlEntry[V])
	}
	if _, exists := m.entries[key]; !exists && len(m.entries) >= limit {
		now := time.Now()
		for name, entry := range m.entries {
			if now.After(entry.expires) {
				delete(m.entries, name)
			}
		}
		for name := range m.entries {
			if len(m.entries) < limit*9/10 {
				break
			}
			delete(m.entries, name)
		}
	}
	m.entries[key] = ttlEntry[V]{value: value, expires: expires}
}

func (m *ttlMap[V]) delete(key string) { delete(m.entries, key) }

// screened reports whether connection screening applies to this session:
// an unauthenticated client of a listener that does not require
// authentication, outside the exempt networks.
func (s *Session) screened() bool {
	return !s.screenExempt && !s.authenticated && !s.cfg.AuthRequired
}

// greet sends the greeting. When the early-talker test applies, it sends a
// first "220-" line, waits GreetDelay for the client to talk, and only then
// finishes the greeting; clients that passed recently skip the wait. It
// returns false when the session must end.
func (s *Session) greet() bool {
	banner := fmt.Sprintf("%s ESMTP Veksel", s.cfg.ServerName)
	sc := &s.cfg.Screening
	ip := extractRemoteIP(s.conn)
	if !sc.greetingTest() || s.tlsDone || !s.screened() || sc.Cache.Passed(ip) {
		s.send(220, banner)
		return true
	}
	s.rw.WriteString("220-" + banner + "\r\n")
	if err := s.rw.Flush(); err != nil {
		return false
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(sc.GreetDelay))
	_, err := s.rw.Reader.Peek(1)
	_ = s.conn.SetReadDeadline(time.Time{})
	var timeout net.Error
	switch {
	case err == nil:
		logger.Info("smtp: client talked before the greeting", "session", s.id, "remote", ip, "action", sc.Pregreet)
		if s.violation(spam.SymbolPregreet, "data before greeting", true) {
			return false
		}
		if sc.Pregreet == PregreetReject {
			s.sendImmediate(554, "5.7.1 Protocol error: data sent before the greeting")
			return false
		}
	case errors.As(err, &timeout) && timeout.Timeout():
		sc.Cache.pass(ip)
	default:
		return false // the client left
	}
	s.send(220, banner)
	return true
}

// observe records a connection-stage fact for the transaction's spam
// evaluation.
func (s *Session) observe(symbol, detail string) {
	finding := spam.ConnectionFinding{Symbol: symbol, Detail: detail}
	if len(s.findings) < maxConnectionFindings && !slices.Contains(s.findings, finding) {
		s.findings = append(s.findings, finding)
	}
}

// violation records a protocol violation as symbol with detail and counts
// it. strike also reports it to the abuse ban engine at once. Reaching the
// violation limit strikes, answers 421, and ends the session; violation
// then returns true and the caller must stop processing. Unscreened
// sessions record nothing.
func (s *Session) violation(symbol, detail string, strike bool) bool {
	if !s.screened() {
		return false
	}
	s.observe(symbol, detail)
	s.cfg.Screening.Cache.forget(extractRemoteIP(s.conn))
	if strike {
		s.reportAbuse(ban.TriggerProtocol)
	}
	s.violations++
	if limit := s.cfg.Screening.ViolationLimit; limit <= 0 || s.violations < limit {
		return false
	}
	logger.Warn("smtp: protocol violation limit reached", "session", s.id, "remote", extractRemoteIP(s.conn), "violations", s.violations, "last", detail)
	if !strike {
		s.reportAbuse(ban.TriggerProtocol)
	}
	if len(s.cmdResponses) > 0 {
		s.sendQueuedResponses()
		s.cmdResponses = s.cmdResponses[:0]
	}
	s.cmdQueue = nil
	s.sendImmediate(421, "4.7.0 Too many protocol violations, closing connection")
	s.curState = stateQuit
	return true
}

// inspectLine counts the syntax violations of one raw command line: a bare
// LF terminator (counted once per session) and NUL bytes. It returns true
// when the session ended.
func (s *Session) inspectLine(raw string) bool {
	if !strings.HasSuffix(raw, "\r\n") && !s.bareLFSeen {
		s.bareLFSeen = true
		if s.violation(spam.SymbolProtocolViolation, "bare LF", false) {
			return true
		}
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return s.violation(spam.SymbolProtocolViolation, "NUL byte", false)
	}
	return false
}

// queueCommand queues line read from the client and reports whether more
// pipelined commands may be read after it. A command that must end its
// group (any command while PIPELINING is not negotiated) with more client
// data already waiting is a pipelining violation.
func (s *Session) queueCommand(line string) bool {
	s.cmdQueue = append(s.cmdQueue, line)
	command, _, _ := strings.Cut(line, " ")
	command = strings.ToUpper(command)
	if line != overlongLine && command != "BDAT" && command != "QUIT" && s.rw.Reader.Buffered() > 0 && (!s.pipelining || endsPipelineGroup(command)) {
		logger.Info("smtp: client pipelined without permission", "session", s.id, "command", command)
		if s.violation(spam.SymbolPipelining, command, true) {
			return false
		}
	}
	return !commandStartsMessageData(line)
}

// endsPipelineGroup reports commands that may only end a pipelined group
// (RFC 2920 section 3.1, RFC 3207, RFC 4954).
func endsPipelineGroup(command string) bool {
	switch command {
	case "EHLO", "HELO", "DATA", "VRFY", "EXPN", "TURN", "NOOP", "STARTTLS", "AUTH":
		return true
	}
	return false
}

// junkCommand counts RSET, NOOP, VRFY, and EXPN; past junkCommandLimit per
// accepted message each one is a violation. It returns true when the
// session ended.
func (s *Session) junkCommand(command string) bool {
	s.junkCommands++
	return s.junkCommands > junkCommandLimit && s.violation(spam.SymbolProtocolViolation, "too many "+command+" commands", false)
}

// tarpit delays an RCPT reply once the session probed
// TarpitAfterUnknownRcpts unknown recipients: one second more for every
// further unknown recipient, up to maxTarpitDelay.
func (s *Session) tarpit() {
	after := s.cfg.Screening.TarpitAfterUnknownRcpts
	if after <= 0 || s.unknownRcpts < after || !s.screened() {
		return
	}
	s.cfg.Screening.pause(min(time.Duration(s.unknownRcpts-after+1)*time.Second, maxTarpitDelay))
}

// unknownRecipient counts a recipient rejected as unknown; once the tarpit
// starts the probing is also scored.
func (s *Session) unknownRecipient() {
	s.unknownRcpts++
	if after := s.cfg.Screening.TarpitAfterUnknownRcpts; after > 0 && s.unknownRcpts >= after && s.screened() {
		s.observe(spam.SymbolUnknownRecipients, "")
	}
}

// connectionFindings returns the connection-stage facts for the
// transaction's spam evaluation: what the session observed plus HELO and
// reverse DNS checks.
func (s *Session) connectionFindings() []spam.ConnectionFinding {
	if !s.screened() {
		return nil
	}
	findings := slices.Clone(s.findings)
	findings = append(findings, s.heloFindings()...)
	return append(findings, s.reverseDNSFindings()...)
}

// heloFindings scores the HELO name a public client announced: a bare IP
// address (address literals in brackets are legitimate), a name without a
// dot, and this server's own name or a hosted domain. Internal clients
// often announce short names and are not scored.
func (s *Session) heloFindings() []spam.ConnectionFinding {
	helo := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.heloHostname)), ".")
	addr, public := publicAddress(extractRemoteIP(s.conn))
	if helo == "" || strings.HasPrefix(helo, "[") || !public {
		return nil
	}
	if net.ParseIP(helo) != nil {
		return []spam.ConnectionFinding{{Symbol: spam.SymbolHeloBareIP, Detail: helo}}
	}
	var findings []spam.ConnectionFinding
	if !strings.Contains(helo, ".") {
		findings = append(findings, spam.ConnectionFinding{Symbol: spam.SymbolHeloNotFQDN, Detail: helo})
	}
	if s.heloClaimsLocal(helo) {
		findings = append(findings, spam.ConnectionFinding{Symbol: spam.SymbolHeloForgedLocal, Detail: helo + " from " + addr.String()})
	}
	return findings
}

// heloClaimsLocal reports whether helo is this server's name or exactly a
// hosted domain. Host names below a hosted domain are not claimed: hosted
// organizations legitimately send from their own servers.
func (s *Session) heloClaimsLocal(helo string) bool {
	if helo == strings.TrimSuffix(strings.ToLower(s.cfg.ServerName), ".") {
		return true
	}
	if s.cfg.Delivery == nil || s.cfg.Delivery.IsLocalDomain == nil {
		return false
	}
	local, err := s.cfg.Delivery.IsLocalDomain(s.ctx, helo)
	return err == nil && local
}

// reverseDNSFindings runs the FCrDNS check once per client address and
// cache lifetime. It reuses the PTR name the HELO policy found.
func (s *Session) reverseDNSFindings() []spam.ConnectionFinding {
	sc := &s.cfg.Screening
	if !sc.FCrDNS {
		return nil
	}
	if s.rdnsChecked {
		return s.rdnsFindings
	}
	s.rdnsChecked = true
	addr, ok := publicAddress(extractRemoteIP(s.conn))
	if !ok {
		return nil
	}
	if findings, ok := sc.Cache.reverseDNS(addr.String()); ok {
		s.rdnsFindings = findings
		return findings
	}
	known := ""
	if s.heloResult != nil {
		known = s.heloResult.ReverseDNS
	}
	ctx, cancel := context.WithTimeout(s.ctx, rdnsTimeout)
	defer cancel()
	findings, definite := checkFCrDNS(ctx, sc.resolver(), addr, known)
	if definite {
		sc.Cache.storeReverseDNS(addr.String(), findings)
	}
	s.rdnsFindings = findings
	return findings
}

// maxPTRNames bounds the reverse DNS names checked for one address.
const maxPTRNames = 5

// checkFCrDNS checks addr's forward-confirmed reverse DNS: RDNS_NONE when it
// has no PTR name, RDNS_NOT_FCRDNS when no PTR name resolves back to it, and
// RDNS_DYNAMIC when its name looks dynamic. known is a PTR name already
// looked up, or empty. definite is false when a temporary DNS failure left
// the outcome open; such failures are never scored.
func checkFCrDNS(ctx context.Context, resolver Resolver, addr netip.Addr, known string) (findings []spam.ConnectionFinding, definite bool) {
	names := []string{known}
	if known == "" {
		var err error
		names, err = resolver.LookupAddr(ctx, addr.String())
		if err != nil && !dnsNotFound(err) {
			return nil, false
		}
	}
	var normalized []string
	for _, name := range names {
		if name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."); name != "" && len(normalized) < maxPTRNames {
			normalized = append(normalized, name)
		}
	}
	if len(normalized) == 0 {
		return []spam.ConnectionFinding{{Symbol: spam.SymbolRDNSNone, Detail: addr.String()}}, true
	}
	confirmed, answered := false, false
	for _, name := range normalized {
		ips, err := resolver.LookupIPAddr(ctx, name)
		if err != nil && !dnsNotFound(err) {
			continue
		}
		answered = true
		for _, ip := range ips {
			if candidate, ok := netip.AddrFromSlice(ip.IP); ok && candidate.Unmap() == addr {
				confirmed = true
			}
		}
		if confirmed {
			break
		}
	}
	if !confirmed && !answered {
		return nil, false
	}
	if !confirmed {
		findings = append(findings, spam.ConnectionFinding{Symbol: spam.SymbolRDNSNotFCrDNS, Detail: normalized[0]})
	}
	if dynamicHostname(normalized[0], addr) {
		findings = append(findings, spam.ConnectionFinding{Symbol: spam.SymbolRDNSDynamic, Detail: normalized[0]})
	}
	return findings, true
}

func dnsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// dynamicWords are host name words that mark end-user access networks.
var dynamicWords = map[string]bool{
	"dsl": true, "adsl": true, "vdsl": true, "xdsl": true, "sdsl": true, "dyn": true, "dynamic": true, "dynip": true,
	"pool": true, "dial": true, "dialup": true, "dialin": true, "ppp": true, "pppoe": true, "dhcp": true,
	"cable": true, "broadband": true, "cpe": true, "cust": true, "customer": true, "client": true, "clients": true,
	"catv": true, "res": true, "residential": true, "subscriber": true, "nat": true, "unassigned": true,
}

// dynamicHostname reports whether name looks like a generic name of a
// dynamic or residential address: it contains a dynamicWords word in a
// label left of the registered domain, or embeds the IPv4 address.
func dynamicHostname(name string, addr netip.Addr) bool {
	labels := strings.Split(name, ".")
	if len(labels) > 2 {
		labels = labels[:len(labels)-2]
	}
	for _, label := range labels {
		words := strings.FieldsFunc(label, func(r rune) bool { return r < 'a' || r > 'z' })
		if slices.ContainsFunc(words, func(word string) bool { return dynamicWords[word] }) {
			return true
		}
	}
	if !addr.Is4() {
		return false
	}
	o := addr.As4()
	for _, embedded := range []string{
		fmt.Sprintf("%d-%d-%d-%d", o[0], o[1], o[2], o[3]), fmt.Sprintf("%d-%d-%d-%d", o[3], o[2], o[1], o[0]),
		fmt.Sprintf("%d.%d.%d.%d", o[0], o[1], o[2], o[3]), fmt.Sprintf("%d.%d.%d.%d", o[3], o[2], o[1], o[0]),
		fmt.Sprintf("%d_%d_%d_%d", o[0], o[1], o[2], o[3]), fmt.Sprintf("%03d%03d%03d%03d", o[0], o[1], o[2], o[3]),
		fmt.Sprintf("%02x%02x%02x%02x", o[0], o[1], o[2], o[3]),
	} {
		if strings.Contains(name, embedded) {
			return true
		}
	}
	return false
}

// publicAddress parses ip and reports whether it is a public unicast
// address; private, loopback, and link-local clients are internal.
func publicAddress(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap().WithZone("")
	return addr, addr.IsGlobalUnicast() && !addr.IsPrivate()
}
