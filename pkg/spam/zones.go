package spam

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ZoneKind is what a blocklist zone is queried for.
type ZoneKind string

const (
	// ZoneDNSBL lists connecting IP addresses.
	ZoneDNSBL ZoneKind = "dnsbl"
	// ZoneRHSBL lists sender domains (envelope, From, and HELO).
	ZoneRHSBL ZoneKind = "rhsbl"
	// ZoneURIBL lists domains linked in message bodies.
	ZoneURIBL ZoneKind = "uribl"
)

const (
	maxZonesPerKind = 16
	maxRulesPerZone = 32
	genericZoneRule = 2.0
)

// Zone is one blocklist and the return codes it maps to symbols.
type Zone struct {
	Name  string     `json:"name"`
	Kind  ZoneKind   `json:"kind"`
	Rules []ZoneRule `json:"rules"`
}

// ZoneRule maps matching answers to a symbol, or marks them as the list's
// refusal sentinel (the list declined to answer this resolver).
type ZoneRule struct {
	match       answerMatch
	Code        string  `json:"code"`
	Symbol      string  `json:"symbol,omitempty"`
	Score       float64 `json:"score,omitempty"`
	Description string  `json:"description,omitempty"`
	Refused     bool    `json:"refused,omitempty"`
}

// answerMatch selects 127.0.0.0/8 answers: an inclusive range, or any
// answer whose last octet shares a bit with mask (SURBL/URIBL bitmasks).
type answerMatch struct {
	first, last netip.Addr
	mask        byte
}

func (m answerMatch) matches(addr netip.Addr) bool {
	if m.mask != 0 {
		return addr.As4()[3]&m.mask != 0
	}
	return addr.Compare(m.first) >= 0 && addr.Compare(m.last) <= 0
}

// knownZone is a list whose return codes Veksel maps without configuration.
type knownZone struct {
	kind  ZoneKind
	names []string // the public zone and its Spamhaus DQS form, matched as suffixes
	rules string
	about string
}

var knownZones = []knownZone{
	{ZoneDNSBL, []string{"zen.spamhaus.org", "zen.dq.spamhaus.net"},
		"127.0.0.2=RBL_SPAMHAUS_SBL:4 127.0.0.3=RBL_SPAMHAUS_CSS:3 127.0.0.4-127.0.0.7=RBL_SPAMHAUS_XBL:5 127.0.0.9=RBL_SPAMHAUS_DROP:7 127.0.0.10-127.0.0.11=RBL_SPAMHAUS_PBL:1.5",
		"Spamhaus ZEN"},
	{ZoneDNSBL, []string{"b.barracudacentral.org"}, "127.0.0.2=RBL_BARRACUDA:3", "Barracuda reputation"},
	{ZoneDNSBL, []string{"bl.spamcop.net"}, "127.0.0.2=RBL_SPAMCOP:3", "SpamCop"},
	{ZoneDNSBL, []string{"psbl.surriel.com"}, "127.0.0.2=RBL_PSBL:2.5", "Passive Spam Block List"},
	{ZoneRHSBL, []string{"dbl.spamhaus.org", "dbl.dq.spamhaus.net"},
		"127.0.1.2=RHSBL_DBL_SPAM:4 127.0.1.4=RHSBL_DBL_PHISH:6 127.0.1.5=RHSBL_DBL_MALWARE:6 127.0.1.6=RHSBL_DBL_BOTNET:6 127.0.1.102=RHSBL_DBL_ABUSED_SPAM:2 127.0.1.103=RHSBL_DBL_ABUSED_REDIRECTOR:1 127.0.1.104=RHSBL_DBL_ABUSED_PHISH:4 127.0.1.105=RHSBL_DBL_ABUSED_MALWARE:4 127.0.1.106=RHSBL_DBL_ABUSED_BOTNET:4 127.0.1.255=!",
		"Spamhaus DBL"},
	{ZoneURIBL, []string{"dbl.spamhaus.org", "dbl.dq.spamhaus.net"},
		"127.0.1.2=URIBL_DBL_SPAM:5 127.0.1.4=URIBL_DBL_PHISH:7 127.0.1.5=URIBL_DBL_MALWARE:7 127.0.1.6=URIBL_DBL_BOTNET:7 127.0.1.102=URIBL_DBL_ABUSED_SPAM:2.5 127.0.1.103=URIBL_DBL_ABUSED_REDIRECTOR:1.5 127.0.1.104=URIBL_DBL_ABUSED_PHISH:5 127.0.1.105=URIBL_DBL_ABUSED_MALWARE:5 127.0.1.106=URIBL_DBL_ABUSED_BOTNET:5 127.0.1.255=!",
		"Spamhaus DBL"},
	{ZoneURIBL, []string{"multi.surbl.org"},
		"127.0.0.1=! &8=URIBL_SURBL_PHISH:5 &16=URIBL_SURBL_MALWARE:6 &64=URIBL_SURBL_ABUSE:5 &128=URIBL_SURBL_CRACKED:4",
		"SURBL"},
	{ZoneURIBL, []string{"multi.uribl.com"},
		"127.0.0.1=! &2=URIBL_BLACK:5 &4=URIBL_GREY:1.5 &8=URIBL_RED:3",
		"URIBL"},
}

// DefaultZones returns the zones enabled by default for kind.
func DefaultZones(kind ZoneKind) []string {
	switch kind {
	case ZoneDNSBL:
		return []string{"zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net", "psbl.surriel.com"}
	case ZoneRHSBL:
		return []string{"dbl.spamhaus.org"}
	case ZoneURIBL:
		return []string{"dbl.spamhaus.org", "multi.surbl.org", "multi.uribl.com"}
	}
	return nil
}

// ParseZones parses zone specifications for kind. Each entry is a zone
// name optionally followed by space-separated rules:
//
//	CODE=SYMBOL:SCORE   CODE is 127.0.0.2, 127.0.0.4-127.0.0.7, &8 (a bit of
//	                    the last octet), or * (any answer)
//	CODE=!              the list's "query refused" sentinel answer
//
// A zone without rules uses Veksel' return-code map when the list is known,
// and otherwise scores any answer as RBL_/RHSBL_/URIBL_<ZONE>.
func ParseZones(kind ZoneKind, specs []string) ([]Zone, error) {
	if len(specs) > maxZonesPerKind {
		return nil, fmt.Errorf("at most %d %s zones are allowed", maxZonesPerKind, kind)
	}
	zones := make([]Zone, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for _, spec := range specs {
		zone, err := parseZone(kind, spec)
		if err != nil {
			return nil, fmt.Errorf("%s zone %q: %w", kind, spec, err)
		}
		if seen[zone.Name] {
			return nil, fmt.Errorf("%s zone %s is listed more than once", kind, zone.Name)
		}
		seen[zone.Name] = true
		zones = append(zones, zone)
	}
	return zones, nil
}

func parseZone(kind ZoneKind, spec string) (Zone, error) {
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return Zone{}, errors.New("zone name is required")
	}
	name := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
	if !validZoneName(name) {
		return Zone{}, errors.New("zone name must be a DNS name with at least two labels")
	}
	zone := Zone{Name: name, Kind: kind}
	rules := fields[1:]
	about := name
	if len(rules) == 0 {
		if known, ok := lookupKnownZone(kind, name); ok {
			rules, about = strings.Fields(known.rules), known.about
		} else {
			rules = []string{"*=" + genericSymbol(kind, name) + ":" + strconv.FormatFloat(genericZoneRule, 'f', -1, 64)}
		}
	}
	if len(rules) > maxRulesPerZone {
		return Zone{}, fmt.Errorf("at most %d rules are allowed", maxRulesPerZone)
	}
	for _, text := range rules {
		rule, err := parseZoneRule(text, about)
		if err != nil {
			return Zone{}, err
		}
		zone.Rules = append(zone.Rules, rule)
	}
	return zone, nil
}

func parseZoneRule(text, about string) (ZoneRule, error) {
	code, target, found := strings.Cut(text, "=")
	if !found {
		return ZoneRule{}, fmt.Errorf("rule %q must have the form CODE=SYMBOL:SCORE or CODE=!", text)
	}
	rule := ZoneRule{Code: code}
	switch {
	case code == "*":
		rule.match = answerMatch{first: netip.AddrFrom4([4]byte{127, 0, 0, 0}), last: netip.AddrFrom4([4]byte{127, 255, 255, 255})}
	case strings.HasPrefix(code, "&"):
		mask, err := strconv.ParseUint(code[1:], 10, 8)
		if err != nil || mask == 0 {
			return ZoneRule{}, fmt.Errorf("rule %q has an invalid bitmask", text)
		}
		rule.match = answerMatch{mask: byte(mask)}
	default:
		firstText, lastText, isRange := strings.Cut(code, "-")
		if !isRange {
			lastText = firstText
		}
		first, firstErr := netip.ParseAddr(firstText)
		last, lastErr := netip.ParseAddr(lastText)
		if firstErr != nil || lastErr != nil || !loopbackAnswer(first) || !loopbackAnswer(last) || last.Less(first) {
			return ZoneRule{}, fmt.Errorf("rule %q must use 127.0.0.0/8 answer codes", text)
		}
		rule.match = answerMatch{first: first, last: last}
	}
	if target == "!" {
		rule.Refused = true
		return rule, nil
	}
	symbol, scoreText, found := strings.Cut(target, ":")
	if !found || !validSymbolName(symbol) {
		return ZoneRule{}, fmt.Errorf("rule %q must name an upper-case SYMBOL:SCORE", text)
	}
	score, err := strconv.ParseFloat(scoreText, 64)
	if err != nil || !validSymbolScore(score) {
		return ZoneRule{}, fmt.Errorf("rule %q needs a score between -100 and 100", text)
	}
	rule.Symbol, rule.Score = symbol, score
	rule.Description = "Listed by " + about + " (" + code + ")"
	return rule, nil
}

func lookupKnownZone(kind ZoneKind, name string) (knownZone, bool) {
	for _, known := range knownZones {
		if known.kind != kind {
			continue
		}
		for _, candidate := range known.names {
			if name == candidate || strings.HasSuffix(name, "."+candidate) {
				return known, true
			}
		}
	}
	return knownZone{}, false
}

// knownZoneSymbols returns every symbol the known zones define.
func knownZoneSymbols() map[string]bool {
	symbols := make(map[string]bool)
	for _, known := range knownZones {
		for _, text := range strings.Fields(known.rules) {
			if _, target, _ := strings.Cut(text, "="); target != "!" {
				symbol, _, _ := strings.Cut(target, ":")
				symbols[symbol] = true
			}
		}
	}
	return symbols
}

func genericSymbol(kind ZoneKind, name string) string {
	prefix := map[ZoneKind]string{ZoneDNSBL: "RBL_", ZoneRHSBL: "RHSBL_", ZoneURIBL: "URIBL_"}[kind]
	symbol := []byte(prefix + strings.ToUpper(name))
	for index, character := range symbol {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			symbol[index] = '_'
		}
	}
	if len(symbol) > 64 {
		symbol = symbol[:64]
	}
	return string(symbol)
}

func validZoneName(name string) bool {
	if len(name) > 200 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func loopbackAnswer(addr netip.Addr) bool {
	return addr.Is4() && addr.As4()[0] == 127
}

// refusedAnswer reports Spamhaus' error range: 127.255.255.252 (typing
// error), .254 (query through a public resolver), and .255 (excessive
// queries). No list uses 127.255.255.0/24 for listings.
func refusedAnswer(addr netip.Addr) bool {
	a := addr.As4()
	return a[0] == 127 && a[1] == 255 && a[2] == 255
}

// zoneVerdict is the interpretation of one zone answer.
type zoneVerdict struct {
	hits    []ZoneRule
	refused bool
	err     error
}

// evaluate interprets the A records a zone returned. An empty answer is a
// miss. Answers outside 127.0.0.0/8 (a resolver rewriting NXDOMAIN) are an
// error, and refusal sentinels are reported as refusals, never as hits.
func (z Zone) evaluate(addrs []netip.Addr) zoneVerdict {
	var verdict zoneVerdict
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !loopbackAnswer(addr) {
			verdict.err = fmt.Errorf("unexpected answer %s; the resolver may rewrite blocklist responses", addr)
			return verdict
		}
		if refusedAnswer(addr) {
			verdict.refused = true
			return verdict
		}
		for _, rule := range z.Rules {
			if rule.Refused && rule.match.matches(addr) {
				verdict.refused = true
				return verdict
			}
		}
	}
	for _, addr := range addrs {
		addr = addr.Unmap()
		for _, rule := range z.Rules {
			if !rule.Refused && rule.match.matches(addr) {
				verdict.hits = append(verdict.hits, rule)
			}
		}
	}
	return verdict
}

// ReverseIP returns the DNSBL query label for addr: reversed octets for
// IPv4 and reversed nibbles for IPv6.
func ReverseIP(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		a := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d", a[3], a[2], a[1], a[0])
	}
	a := addr.As16()
	digits := hex.EncodeToString(a[:])
	labels := make([]byte, 0, 63)
	for index := len(digits) - 1; index >= 0; index-- {
		labels = append(labels, digits[index])
		if index > 0 {
			labels = append(labels, '.')
		}
	}
	return string(labels)
}
