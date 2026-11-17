package spam

import (
	"maps"
	"math"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// SymbolKnownCorrespondent is applied per recipient to authenticated mail
// from an address the recipient has written to.
const SymbolKnownCorrespondent = "KNOWN_CORRESPONDENT"

func init() {
	maps.Copy(builtinSymbols, map[string]symbolInfo{
		"REP_DOMAIN_GOOD":        {-2.0, "Authenticated sending domain has a good delivery reputation"},
		"REP_DOMAIN_BAD":         {3.0, "Authenticated sending domain has a poor delivery reputation"},
		"REP_IP_BAD":             {2.0, "Sending network has a poor delivery reputation"},
		SymbolKnownCorrespondent: {-3.0, "Authenticated sender is someone the recipient has written to"},
	})
}

const reputationSymbolPrefix = "REP_"

// scoreReputation records the message's outcome for its authenticated
// domain and sending network, then adds the symbols their earlier history
// earned. The outcome is judged without reputation symbols so reputation
// never feeds on itself; mail from private and trusted networks is not
// tracked.
func (e *Engine) scoreReputation(result *Result, symbols *symbolSet, m Message) {
	reputation := e.config.Reputation
	if !reputation.Enabled() || e.addressSkip(m.RemoteIP) != "" {
		return
	}
	keys := ReputationKeys{Domain: normalizeReputationDomain(m.AuthDomain), Network: ReputationNetwork(m.RemoteIP)}
	if keys == (ReputationKeys{}) {
		return
	}
	result.Reputation = keys
	for _, signal := range reputation.Assess(keys) {
		base := builtinSymbols[signal.Symbol]
		score := base.score
		if override, ok := e.config.SymbolScores[signal.Symbol]; ok {
			score = override
		}
		symbols.add(signal.Symbol, math.Round(score*signal.Scale*100)/100, base.description, signal.Options...)
	}
	var score float64
	for _, symbol := range symbols.symbols {
		if !strings.HasPrefix(symbol.Name, reputationSymbolPrefix) {
			score += symbol.Score
		}
	}
	event := RepAccepted
	switch e.config.Thresholds.Action(score) {
	case ActionReject:
		event = RepRejected
	case ActionJunk:
		event = RepJunked
	}
	reputation.Record(keys, event)
}

// SenderAuth is the authentication evidence for one message's From address,
// as the SMTP boundary evaluated it.
type SenderAuth struct {
	// From is the From header value.
	From       string
	DMARCPass  bool
	DKIMPass   bool
	DKIMDomain string
	// DKIMDomains are the domains of every passing DKIM signature; when
	// set, an aligned one among them aligns the message, and DKIMDomain
	// names the unaligned fallback.
	DKIMDomains []string
	SPFPass     bool
	SPFDomain   string
}

// Sender returns the organizational domain the message authenticated as and
// whether that domain is the From address's own (aligned): DMARC pass, or an
// aligned DKIM or SPF pass. A DKIM pass for another domain still names that
// domain, unaligned, which reputation may track but allow-listing must not
// trust. The address is the From address, lower-cased; both are empty when
// the message did not authenticate.
func (a SenderAuth) Sender() (address, domain string, aligned bool) {
	address = strings.ToLower(senderAddress(a.From))
	from := organizationalDomain(extractDomain(address))
	switch {
	case from == "" || !strings.Contains(address, "@"):
		return "", "", false
	case a.DMARCPass,
		a.DKIMPass && organizationalDomain(a.DKIMDomain) == from,
		slices.ContainsFunc(a.DKIMDomains, func(domain string) bool { return organizationalDomain(domain) == from }),
		a.SPFPass && organizationalDomain(a.SPFDomain) == from:
		return address, from, true
	case a.DKIMPass && a.DKIMDomain != "":
		return address, organizationalDomain(a.DKIMDomain), false
	}
	return address, "", false
}

// organizationalDomain is domain's registered domain under the public
// suffix list, as DMARC relaxed alignment compares; reserved names such as
// example.com count, unlike the link checks' registrableDomain.
func organizationalDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if registered, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return registered
	}
	return domain
}

// StampReputation records result's reputation keys in headers, replacing
// any claim a peer made.
func StampReputation(headers map[string]string, result Result) {
	for name := range headers {
		if strings.EqualFold(name, ReputationHeader) {
			delete(headers, name)
		}
	}
	if value := result.Reputation.Header(); value != "" {
		headers[ReputationHeader] = value
	}
}

// BuiltinSymbol returns a built-in symbol at its configured score, or false
// while scoring is disabled or name is unknown.
func (e *Engine) BuiltinSymbol(name string, options ...string) (Symbol, bool) {
	symbol, ok := DefaultSymbol(name, options...)
	if e == nil || !ok {
		return Symbol{}, false
	}
	if override, ok := e.config.SymbolScores[name]; ok {
		symbol.Score = override
	}
	return symbol, true
}

// BuiltinSymbol returns the current engine's built-in symbol.
func (s *Switch) BuiltinSymbol(name string, options ...string) (Symbol, bool) {
	return s.engine.Load().BuiltinSymbol(name, options...)
}

// WithSymbol returns r with symbol added, replacing a symbol of the same
// name, and the score and action recomputed.
func (r Result) WithSymbol(symbol Symbol) Result {
	symbols := slices.DeleteFunc(slices.Clone(r.Symbols), func(existing Symbol) bool { return existing.Name == symbol.Name })
	r.Symbols = sortSymbols(append(symbols, symbol))
	r.Score = 0
	for _, existing := range r.Symbols {
		r.Score += existing.Score
	}
	r.Score = math.Round(r.Score*100) / 100
	r.Action = r.Thresholds.Action(r.Score)
	return r
}
