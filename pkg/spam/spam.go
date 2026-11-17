// Package spam scores inbound mail with a weighted, explainable rule engine.
//
// Every check contributes a named symbol with a score, a description, and
// bounded options naming what matched. The total is compared to configurable
// action thresholds (greylist, junk, reject). Header and content heuristics,
// the SMTP boundary's SPF/DKIM/DMARC results, and DNS blocklists for the
// connecting IP (DNSBL), sender domains (RHSBL), and body links (URIBL) all
// report through the same symbols, so the evidence that decided a message is
// exactly the evidence shown to administrators, users, and Sieve.
package spam

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/contentscan"
)

//go:generate go tool enumer -type=Action -linecomment -json -text -output=enums_generated.go

// EngineName identifies built-in scoring results in content-scan evidence.
const EngineName = "antispam"

const (
	maxResultSymbols = 64
	maxSymbolOptions = 8
	maxHeaderBytes   = 900
	// DefaultMaxURIDomains caps the distinct registrable link domains
	// checked against URI blocklists for one message.
	DefaultMaxURIDomains = 20
	// DefaultBudget bounds all blocklist lookups made for one message.
	DefaultBudget = 5 * time.Second
)

// Action is the strongest admission action a score reached.
type Action uint8

const (
	ActionNone     Action = iota // no action
	ActionGreylist               // greylist
	ActionJunk                   // add header
	ActionReject                 // reject
)

// Symbol is one named, scored piece of evidence.
type Symbol struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// Thresholds are the scores at which each action applies. A zero greylist
// or reject threshold disables that action.
type Thresholds struct {
	Junk     float64 `json:"junk"`
	Greylist float64 `json:"greylist"`
	Reject   float64 `json:"reject"`
}

// DefaultThresholds returns the built-in action thresholds.
func DefaultThresholds() Thresholds { return Thresholds{Junk: 6, Greylist: 4, Reject: 15} }

// Validate rejects thresholds whose actions cannot be ordered.
func (t Thresholds) Validate() error {
	for _, value := range []float64{t.Junk, t.Greylist, t.Reject} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1000 {
			return errors.New("spam thresholds must be between 0 and 1000")
		}
	}
	if t.Junk <= 0 {
		return errors.New("the junk threshold must be positive")
	}
	if t.Greylist != 0 && t.Greylist > t.Junk {
		return errors.New("the greylist threshold must not exceed the junk threshold")
	}
	if t.Reject != 0 && t.Reject <= t.Junk {
		return errors.New("the reject threshold must exceed the junk threshold")
	}
	return nil
}

// Action returns the strongest action score reaches.
func (t Thresholds) Action(score float64) Action {
	switch {
	case t.Reject > 0 && score >= t.Reject:
		return ActionReject
	case score >= t.Junk:
		return ActionJunk
	case t.Greylist > 0 && score >= t.Greylist:
		return ActionGreylist
	default:
		return ActionNone
	}
}

// Message is the input to one check. Authentication results come from the
// SMTP boundary that already evaluated them, so scoring adds no lookups of
// its own for SPF, DKIM, or DMARC.
type Message struct {
	// Content is the complete RFC 5322 message.
	Content []byte
	// Headers are the parsed top-level headers; names match case-insensitively.
	Headers       map[string]string
	RemoteIP      string
	Helo          string
	EnvelopeFrom  string
	Authenticated bool
	// SPF, DKIM, and DMARC are results such as pass, fail, softfail, or
	// permerror; empty when the boundary did not evaluate them.
	SPF   string
	DKIM  string
	DMARC string
	// AuthDomain is the sending domain the message authenticated as: the
	// aligned DMARC, DKIM, or SPF domain, else a passing DKIM d= domain.
	// Reputation tracks it; empty when nothing authenticated.
	AuthDomain string
	// Attachments are the findings of attachment inspection, which the
	// caller runs once and shares with its hard attachment policy.
	Attachments []attachment.Finding
	// Connection are the connection-stage facts the SMTP session observed:
	// early talking, pipelining and protocol violations, reverse DNS, and
	// HELO checks.
	Connection []ConnectionFinding
}

// Result is the explainable outcome of one check.
type Result struct {
	Score      float64    `json:"score"`
	Action     Action     `json:"action"`
	Thresholds Thresholds `json:"thresholds"`
	Symbols    []Symbol   `json:"symbols"`
	Skipped    string     `json:"skipped,omitempty"`
	// Reputation names the sender keys the message was judged under.
	Reputation ReputationKeys `json:"reputation,omitzero"`
	Duration   time.Duration  `json:"duration"`
}

// Greylist reports whether the score reached an enabled greylist threshold
// without reaching rejection.
func (r Result) Greylist() bool {
	return r.Thresholds.Greylist > 0 && r.Score >= r.Thresholds.Greylist && r.Action != ActionReject
}

// Observer receives bounded operational projections: per-zone lookup
// outcomes and final results. Implementations must return quickly.
type Observer interface {
	ObserveSpamDNS(kind ZoneKind, zone, outcome string)
	ObserveSpamResult(Result)
}

// Config is one immutable engine configuration.
type Config struct {
	Thresholds      Thresholds
	SymbolScores    map[string]float64
	DNSBL           []Zone
	RHSBL           []Zone
	URIBL           []Zone
	TrustedNetworks []netip.Prefix
	// MaxURIDomains defaults to DefaultMaxURIDomains.
	MaxURIDomains int
	// Budget defaults to DefaultBudget.
	Budget time.Duration
	// IsLocalDomain reports hosted domains, which are never queried.
	IsLocalDomain func(context.Context, string) bool
	Observer      Observer
	// ProtectedBrands are names or domains impersonation checks protect
	// besides the hosted domains; URLShorteners are link hosts that hide
	// their destination. Identities supplies hosted domains and local
	// display names; nil protects only ProtectedBrands.
	ProtectedBrands []string
	URLShorteners   []string
	Identities      *IdentityCache
	// Reputation scores and learns sender reputation; nil disables it.
	Reputation *Reputation
	// Fuzzy scores local fuzzy and bulk body matches; nil disables it.
	Fuzzy *Fuzzy
}

// Engine scores messages with one configuration. It is safe for concurrent
// use; replace it rather than mutating it.
type Engine struct {
	config Config
	dns    *DNS
	phish  phishConfig
	// now is the receipt clock; tests replace it.
	now func() time.Time
}

// NewEngine validates config. dns performs blocklist lookups and may be nil
// only when no zone is configured.
func NewEngine(config Config, dns *DNS) (*Engine, error) {
	if err := config.Thresholds.Validate(); err != nil {
		return nil, err
	}
	if dns == nil && len(config.DNSBL)+len(config.RHSBL)+len(config.URIBL) > 0 {
		return nil, errors.New("blocklist zones require a DNS resolver")
	}
	if config.MaxURIDomains <= 0 {
		config.MaxURIDomains = DefaultMaxURIDomains
	}
	if config.Budget <= 0 {
		config.Budget = DefaultBudget
	}
	return &Engine{config: config, dns: dns, phish: newPhishConfig(config), now: time.Now}, nil
}

// Check scores m. It returns false on a nil engine, which scores nothing.
// Authenticated submissions are never scored.
func (e *Engine) Check(ctx context.Context, m Message) (Result, bool) {
	if e == nil {
		return Result{}, false
	}
	started := time.Now()
	result := Result{Thresholds: e.config.Thresholds}
	if m.Authenticated {
		result.Skipped = "authenticated submission"
		result.Duration = time.Since(started)
		return result, true
	}
	symbols := newSymbolSet(e)
	headers := lowerHeaders(m.Headers)
	body := parseContent(m.Content)
	scoreHeuristics(symbols, headers, body, m)
	scoreAuthentication(symbols, headers, m)
	scoreAttachments(symbols, m.Attachments)
	scoreConnection(symbols, m.Connection)
	e.scorePhishing(ctx, symbols, headers, body, m)
	e.scoreAnomalies(ctx, symbols, headers, body, m)
	if skip := e.networkSkip(m.RemoteIP); skip != "" {
		result.Skipped = skip
	} else {
		e.scoreBlocklists(ctx, symbols, m, headers, body)
	}
	e.scoreReputation(&result, symbols, m)
	e.scoreFuzzy(symbols, headers, body, m)
	e.total(&result, symbols, started)
	if e.config.Observer != nil {
		e.config.Observer.ObserveSpamResult(result)
	}
	return result, true
}

// total sums the matched symbols into result and applies the thresholds.
func (e *Engine) total(result *Result, symbols *symbolSet, started time.Time) {
	result.Symbols = symbols.list()
	for _, symbol := range result.Symbols {
		result.Score += symbol.Score
	}
	result.Score = math.Round(result.Score*100) / 100
	result.Action = e.config.Thresholds.Action(result.Score)
	result.Duration = time.Since(started)
}

// CheckOutbound scores a locally submitted message with content rules only:
// header and body heuristics, phishing, and MIME anomalies. Authentication
// and blocklist rules describe the sending host, which for submissions is
// this server, so they are skipped. It returns false on a nil engine.
func (e *Engine) CheckOutbound(ctx context.Context, m Message) (Result, bool) {
	if e == nil {
		return Result{}, false
	}
	started := time.Now()
	result := Result{Thresholds: e.config.Thresholds}
	symbols := newSymbolSet(e)
	headers := lowerHeaders(m.Headers)
	body := parseContent(m.Content)
	scoreHeuristics(symbols, headers, body, m)
	scoreAttachments(symbols, m.Attachments)
	e.scorePhishing(ctx, symbols, headers, body, m)
	e.scoreAnomalies(ctx, symbols, headers, body, m)
	e.total(&result, symbols, started)
	return result, true
}

// networkSkip names why no blocklist may be queried for remoteIP, or
// returns empty when lookups are allowed.
func (e *Engine) networkSkip(remoteIP string) string {
	if e.dns == nil || len(e.config.DNSBL)+len(e.config.RHSBL)+len(e.config.URIBL) == 0 {
		return "no blocklists configured"
	}
	return e.addressSkip(remoteIP)
}

// addressSkip names why remoteIP is not a public, untrusted client (no
// address, loopback, private, or a trusted network), or returns empty.
func (e *Engine) addressSkip(remoteIP string) string {
	addr, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return "no client address"
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() {
		return "loopback or private client address"
	}
	if e.trusted(addr) {
		return "trusted network"
	}
	return ""
}

// trusted reports whether addr lies in a configured trusted network.
func (e *Engine) trusted(addr netip.Addr) bool {
	return slices.ContainsFunc(e.config.TrustedNetworks, func(prefix netip.Prefix) bool { return prefix.Contains(addr) })
}

// symbolSet collects symbols once per name, merging options.
type symbolSet struct {
	engine  *Engine
	symbols []Symbol
	index   map[string]int
}

func newSymbolSet(engine *Engine) *symbolSet {
	return &symbolSet{engine: engine, index: make(map[string]int)}
}

// add records name with its configured score: an administrator override,
// else score. Repeated names keep the highest score and merge options.
func (set *symbolSet) add(name string, score float64, description string, options ...string) {
	if override, ok := set.engine.config.SymbolScores[name]; ok {
		score = override
	}
	position, exists := set.index[name]
	if !exists {
		set.index[name] = len(set.symbols)
		set.symbols = append(set.symbols, Symbol{Name: name, Score: score, Description: description})
		position = len(set.symbols) - 1
	} else if score > set.symbols[position].Score {
		set.symbols[position].Score = score
	}
	symbol := &set.symbols[position]
	for _, option := range options {
		if option != "" && len(symbol.Options) < maxSymbolOptions && !slices.Contains(symbol.Options, option) {
			symbol.Options = append(symbol.Options, option)
		}
	}
}

// builtin records a registered built-in symbol.
func (set *symbolSet) builtin(name string, options ...string) {
	info := builtinSymbols[name]
	set.add(name, info.score, info.description, options...)
}

func (set *symbolSet) list() []Symbol {
	return sortSymbols(slices.Clone(set.symbols))
}

// sortSymbols orders symbols by descending absolute score, then name, and
// keeps at most maxResultSymbols.
func sortSymbols(result []Symbol) []Symbol {
	slices.SortStableFunc(result, func(a, b Symbol) int {
		if order := cmp.Compare(math.Abs(b.Score), math.Abs(a.Score)); order != 0 {
			return order
		}
		return strings.Compare(a.Name, b.Name)
	})
	if len(result) > maxResultSymbols {
		result = result[:maxResultSymbols]
	}
	return result
}

func lowerHeaders(headers map[string]string) map[string]string {
	lowered := make(map[string]string, len(headers))
	for name, value := range headers {
		lowered[strings.ToLower(name)] = value
	}
	return lowered
}

// ListMatches reports whether sender matches an allow- or block-list entry:
// a full address, or a domain matching every address at it. Display names
// and angle brackets around sender are ignored.
func ListMatches(entries []string, sender string) bool {
	address := strings.ToLower(senderAddress(sender))
	if address == "" {
		return false
	}
	for _, entry := range entries {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry != "" && (address == entry || strings.HasSuffix(address, "@"+entry)) {
			return true
		}
	}
	return false
}

// AddHeaders writes the X-Spam-* headers for result: X-Spam-Score,
// X-Spam-Status, X-Spam-Symbols, and X-Spam-Flag when isSpam. required is
// the junk threshold the verdict was judged against.
func AddHeaders(headers map[string]string, result Result, required float64, isSpam bool) {
	names := make([]string, 0, len(result.Symbols))
	scored := make([]string, 0, len(result.Symbols))
	for _, symbol := range result.Symbols {
		names = append(names, symbol.Name)
		scored = append(scored, symbol.Name+"("+formatScore(symbol.Score)+")")
	}
	tests := boundedJoin(names, ",")
	if tests == "" {
		tests = "NONE"
	}
	status := "No"
	if isSpam {
		status = "Yes"
	}
	headers["X-Spam-Score"] = formatScore(result.Score)
	headers["X-Spam-Status"] = status + ", score=" + formatScore(result.Score) + " required=" + formatScore(required) + " tests=[" + tests + "]"
	if symbols := boundedJoin(scored, ", "); symbols != "" {
		headers["X-Spam-Symbols"] = symbols
	} else {
		delete(headers, "X-Spam-Symbols")
	}
	if isSpam {
		headers["X-Spam-Flag"] = "YES"
	} else {
		delete(headers, "X-Spam-Flag")
	}
}

// PeerHeaders lists the X-Spam-* fields Veksel owns; inbound copies supplied
// by a peer must be removed before scoring so they cannot impersonate it.
var PeerHeaders = []string{"X-Spam-Score", "X-Spam-Status", "X-Spam-Symbols", "X-Spam-Flag", ReputationHeader}

// boundedJoin joins values, dropping trailing values that would exceed the
// header budget so a field never approaches the 998-octet line limit.
func boundedJoin(values []string, separator string) string {
	var builder strings.Builder
	for _, value := range values {
		if builder.Len()+len(separator)+len(value) > maxHeaderBytes {
			break
		}
		if builder.Len() > 0 {
			builder.WriteString(separator)
		}
		builder.WriteString(value)
	}
	return builder.String()
}

// formatScore formats a score to at most one decimal place.
func formatScore(score float64) string {
	s := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", score), "0"), ".")
	if s == "" || s == "-0" {
		s = "0"
	}
	return s
}

// ScanResult projects r onto the content-scan evidence contract, so the
// built-in engine appears beside Rspamd and malware engines in message
// trace and quarantine transcripts. Symbol options are folded into the
// bounded description.
func (r Result) ScanResult() contentscan.Result {
	verdict := contentscan.VerdictClean
	if r.Score >= r.Thresholds.Junk {
		verdict = contentscan.VerdictSpam
	}
	symbols := make([]contentscan.Symbol, 0, len(r.Symbols))
	for _, symbol := range r.Symbols {
		description := symbol.Description
		if len(symbol.Options) > 0 {
			description = strings.TrimSpace(description + " [" + strings.Join(symbol.Options, ", ") + "]")
		}
		symbols = append(symbols, contentscan.Symbol{Name: symbol.Name, Score: symbol.Score, Description: description})
	}
	return contentscan.Result{
		Engine: EngineName, Verdict: verdict, Score: r.Score, RequiredScore: r.Thresholds.Junk,
		Symbols: symbols, Duration: r.Duration,
	}
}

// Switch is a stable checking boundary whose engine is replaced live. Each
// check runs to completion on the engine installed when it started. The
// zero value has no engine and scores nothing.
type Switch struct {
	engine atomic.Pointer[Engine]
}

// Set installs engine for subsequent checks; nil disables scoring.
func (s *Switch) Set(engine *Engine) { s.engine.Store(engine) }

// Check scores m with the current engine.
func (s *Switch) Check(ctx context.Context, m Message) (Result, bool) {
	return s.engine.Load().Check(ctx, m)
}

// CheckOutbound scores a submitted message's content with the current engine.
func (s *Switch) CheckOutbound(ctx context.Context, m Message) (Result, bool) {
	return s.engine.Load().CheckOutbound(ctx, m)
}

// Enabled reports whether an engine is installed.
func (s *Switch) Enabled() bool { return s.engine.Load() != nil }

// Thresholds returns the current engine's thresholds.
func (s *Switch) Thresholds() (Thresholds, bool) {
	engine := s.engine.Load()
	if engine == nil {
		return Thresholds{}, false
	}
	return engine.config.Thresholds, true
}
