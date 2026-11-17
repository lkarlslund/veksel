package model

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// Mail flow rules are administrative objects read live by queue admission,
// SMTP recipient handling, and outbound delivery: sender-dependent relay
// routes, address rewriting (canonical maps), journaling, and always-BCC.
//
// Address patterns are lowercased and take two forms: "user@example.com"
// matches that address exactly, and "@example.com" (or "example.com")
// matches every address at that domain. An exact pattern is more specific
// than a domain pattern.

// MailFlowRule holds the fields every mail flow rule shares.
type MailFlowRule struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (rule *MailFlowRule) meta() *MailFlowRule { return rule }

// SenderRouteSecretPurpose binds sealed sender route relay passwords to
// their route ID.
const SenderRouteSecretPurpose = "sender-route"

// SenderRoute selects a relay or direct MX for outbound mail by its sender.
// Sender matches the envelope sender and Account the authenticated account
// (an account ID, or "@domain" for every account ID at that domain); when
// both are set both must match. With Destination set the route only applies
// to recipients at that domain and takes precedence over routes without one.
type SenderRoute struct {
	MailFlowRule
	Sender      string            `json:"sender,omitempty"`
	Account     string            `json:"account,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Transport   OutboundTransport `json:"transport"`
	RelayHost   string            `json:"relay_host,omitempty"`
	RelayPort   int               `json:"relay_port"`
	Username    string            `json:"username,omitempty"`
	// SealedPassword is the relay password sealed with the installation's
	// stored-credential keys; it never leaves the server.
	SealedPassword []byte `json:"sealed_password,omitempty"`
	RequireTLS     bool   `json:"require_tls"`
	TLSSkipVerify  bool   `json:"tls_skip_verify"`
}

// RewriteDirection selects which addresses an AddressRewrite changes.
type RewriteDirection string

const (
	// RewriteOutbound rewrites the envelope sender and/or From header of
	// locally originated mail at queue admission.
	RewriteOutbound RewriteDirection = "outbound"
	// RewriteInbound rewrites envelope recipients at RCPT and recipient
	// resolution (masquerading).
	RewriteInbound RewriteDirection = "inbound"
)

// AddressRewrite is one canonical-map entry. Unlike an alias, which keeps
// the envelope address and adds delivery targets, a rewrite replaces the
// address itself. A domain Replacement keeps the local part. Rewriting is
// one pass: a rule's output may never match another rule's pattern.
type AddressRewrite struct {
	MailFlowRule
	Direction      RewriteDirection `json:"direction"`
	Pattern        string           `json:"pattern"`
	Replacement    string           `json:"replacement"`
	EnvelopeSender bool             `json:"envelope_sender"`
	HeaderFrom     bool             `json:"header_from"`
}

// JournalFormat is how a journal copy carries the original message.
type JournalFormat string

const (
	// JournalEnvelope wraps the original as message/rfc822 after a plain
	// text part listing the envelope (an Exchange-style journal report).
	JournalEnvelope JournalFormat = "envelope"
	// JournalRaw sends the original with X-Veksel-Journal-* header fields.
	JournalRaw JournalFormat = "raw"
)

// JournalRule copies inbound and/or outbound mail of one hosted domain, or
// of every domain when Domain is empty, to a journal address.
type JournalRule struct {
	MailFlowRule
	Domain   string        `json:"domain,omitempty"`
	Inbound  bool          `json:"inbound"`
	Outbound bool          `json:"outbound"`
	Address  string        `json:"address"`
	Format   JournalFormat `json:"format"`
}

// BCCMatch selects whether a BCCRule matches the sender or a recipient.
type BCCMatch string

const (
	BCCSender    BCCMatch = "sender"
	BCCRecipient BCCMatch = "recipient"
)

// BCCRule adds Address as a blind copy recipient of mail whose envelope
// sender or recipient matches Pattern (Postfix sender_bcc_maps and
// recipient_bcc_maps).
type BCCRule struct {
	MailFlowRule
	Match   BCCMatch `json:"match"`
	Pattern string   `json:"pattern"`
	Address string   `json:"address"`
}

// mailFlowRecord is implemented by pointers to the mail flow rule types.
type mailFlowRecord[T any] interface {
	*T
	meta() *MailFlowRule
	normalize() error
}

// MailFlowStore is the durable CRUD store of one mail flow rule type.
type MailFlowStore[T any, P mailFlowRecord[T]] struct {
	rules collection[T]
	mu    sync.Mutex // serializes writes and their cross-rule checks
	// check validates a candidate against the other stored rules.
	check func(others []T, candidate T) error
}

type (
	SenderRouteStore    = MailFlowStore[SenderRoute, *SenderRoute]
	AddressRewriteStore = MailFlowStore[AddressRewrite, *AddressRewrite]
	JournalRuleStore    = MailFlowStore[JournalRule, *JournalRule]
	BCCRuleStore        = MailFlowStore[BCCRule, *BCCRule]
)

func newMailFlowStore[T any, P mailFlowRecord[T]](ts *TypedStore, ns string, check func([]T, T) error) *MailFlowStore[T, P] {
	return &MailFlowStore[T, P]{rules: newCollection[T](ts, ns), check: check}
}

// List returns every rule in ID order.
func (s *MailFlowStore[T, P]) List(ctx context.Context) ([]T, error) {
	rules, err := s.rules.list(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return []T{}, nil
	}
	return rules, err
}

func (s *MailFlowStore[T, P]) Get(ctx context.Context, id string) (T, error) {
	return s.rules.get(ctx, strings.TrimSpace(id))
}

// Create stores a new rule under a generated ID.
func (s *MailFlowStore[T, P]) Create(ctx context.Context, rule T) (T, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return rule, err
	}
	now := time.Now().UTC()
	meta := P(&rule).meta()
	meta.ID, meta.CreatedAt, meta.UpdatedAt = hex.EncodeToString(id), now, now
	return rule, s.write(ctx, &rule, true)
}

// Set replaces the rule with id, keeping its creation time.
func (s *MailFlowStore[T, P]) Set(ctx context.Context, id string, rule T) (T, error) {
	existing, err := s.Get(ctx, id)
	if err != nil {
		return rule, err
	}
	meta := P(&rule).meta()
	meta.ID, meta.CreatedAt, meta.UpdatedAt = P(&existing).meta().ID, P(&existing).meta().CreatedAt, time.Now().UTC()
	return rule, s.write(ctx, &rule, false)
}

func (s *MailFlowStore[T, P]) write(ctx context.Context, rule *T, create bool) error {
	if err := P(rule).normalize(); err != nil {
		return err
	}
	id := P(rule).meta().ID
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check != nil {
		all, err := s.List(ctx)
		if err != nil {
			return err
		}
		others := slices.DeleteFunc(all, func(other T) bool { return P(&other).meta().ID == id })
		if err := s.check(others, *rule); err != nil {
			return err
		}
	}
	if create {
		return s.rules.put(ctx, id, *rule)
	}
	return s.rules.set(ctx, id, *rule)
}

func (s *MailFlowStore[T, P]) Delete(ctx context.Context, id string) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	return s.rules.delete(ctx, strings.TrimSpace(id))
}

// validDomain reports whether domain is a plausible DNS mail domain.
func validDomain(domain string) bool {
	return domain != "" && !strings.ContainsAny(domain, "@:/\\ ") && net.ParseIP(domain) == nil && strings.Contains(domain, ".")
}

// NormalizeAddressPattern returns pattern as "user@domain" or "@domain".
func NormalizeAddressPattern(pattern string) (string, error) {
	pattern = normalizeID(pattern)
	local, domain, found := strings.Cut(pattern, "@")
	if !found {
		local, domain = "", pattern
	}
	if strings.Contains(domain, "@") || strings.ContainsAny(local, " <>,") || !validDomain(domain) {
		return "", fmt.Errorf("%q is not an address or domain", pattern)
	}
	return local + "@" + domain, nil
}

// normalizeAddress returns a valid lowercased single address.
func normalizeAddress(address, field string) (string, error) {
	normalized, err := NormalizeAddressPattern(address)
	if err != nil || strings.HasPrefix(normalized, "@") {
		return "", fmt.Errorf("%s must be an email address", field)
	}
	return normalized, nil
}

// MatchAddress reports how specifically pattern matches address: 2 for the
// exact address, 1 for its domain, and 0 for no match.
func MatchAddress(pattern, address string) int {
	address = normalizeID(address)
	at := strings.LastIndex(address, "@")
	switch {
	case pattern == "" || at <= 0:
		return 0
	case pattern == address:
		return 2
	case strings.HasPrefix(pattern, "@") && pattern == address[at:]:
		return 1
	}
	return 0
}

// matchAccount is MatchAddress for an authenticated account ID, which may
// not be an address.
func matchAccount(pattern, account string) int {
	account = normalizeID(account)
	switch {
	case pattern == "" || account == "":
		return 0
	case pattern == account:
		return 2
	case strings.HasPrefix(pattern, "@") && strings.HasSuffix(account, pattern):
		return 1
	}
	return 0
}

func (route *SenderRoute) normalize() error {
	var err error
	if route.Sender != "" {
		if route.Sender, err = NormalizeAddressPattern(route.Sender); err != nil {
			return fmt.Errorf("sender: %w", err)
		}
	}
	if route.Account = normalizeID(route.Account); route.Account == "@" || strings.ContainsAny(route.Account, " <>,") {
		return fmt.Errorf("account must be an account ID or @domain")
	}
	if route.Sender == "" && route.Account == "" {
		return fmt.Errorf("a sender or account match is required")
	}
	if route.Destination = strings.TrimPrefix(normalizeID(route.Destination), "@"); route.Destination != "" && !validDomain(route.Destination) {
		return fmt.Errorf("destination must be a domain")
	}
	route.Username = strings.TrimSpace(route.Username)
	// The transport rules are those of a destination route.
	normalized, err := normalizeRoute(OutboundRoute{Domain: "sender.route", Transport: route.Transport, RelayHost: route.RelayHost, RelayPort: route.RelayPort})
	if err != nil {
		return err
	}
	route.RelayHost, route.RelayPort = normalized.RelayHost, normalized.RelayPort
	if route.Transport == OutboundTransportMX {
		route.Username, route.SealedPassword = "", nil
	}
	return nil
}

// SelectSenderRoute returns the enabled sender route for a message from
// sender, submitted by account (empty when not authenticated), to a
// recipient at destination. A route with a matching destination wins over
// one without, then the more specific sender and account matches, then the
// lower ID.
func SelectSenderRoute(routes []SenderRoute, sender, account, destination string) (SenderRoute, bool) {
	destination = normalizeID(destination)
	best, bestScore := SenderRoute{}, 0
	for _, route := range routes {
		if !route.Enabled || route.Destination != "" && route.Destination != destination {
			continue
		}
		senderScore, accountScore := MatchAddress(route.Sender, sender), matchAccount(route.Account, account)
		if route.Sender != "" && senderScore == 0 || route.Account != "" && accountScore == 0 {
			continue
		}
		score := senderScore + accountScore
		if route.Destination != "" {
			score += 10
		}
		if score > bestScore || score == bestScore && route.ID < best.ID {
			best, bestScore = route, score
		}
	}
	return best, bestScore > 0
}

func (rule *AddressRewrite) normalize() error {
	var err error
	if rule.Pattern, err = NormalizeAddressPattern(rule.Pattern); err != nil {
		return fmt.Errorf("pattern: %w", err)
	}
	if rule.Replacement, err = NormalizeAddressPattern(rule.Replacement); err != nil {
		return fmt.Errorf("replacement: %w", err)
	}
	if strings.HasPrefix(rule.Replacement, "@") && !strings.HasPrefix(rule.Pattern, "@") {
		return fmt.Errorf("an address pattern needs an address replacement")
	}
	switch rule.Direction {
	case RewriteOutbound:
		if !rule.EnvelopeSender && !rule.HeaderFrom {
			return fmt.Errorf("an outbound rewrite must change the envelope sender, the From header, or both")
		}
	case RewriteInbound:
		rule.EnvelopeSender, rule.HeaderFrom = false, false
	default:
		return fmt.Errorf("direction must be outbound or inbound")
	}
	return nil
}

// produces reports whether rewriting with replacement can yield an address
// that pattern matches.
func produces(replacement, pattern string) bool {
	repLocal, repDomain, _ := strings.Cut(replacement, "@")
	patLocal, patDomain, _ := strings.Cut(pattern, "@")
	return repDomain == patDomain && (patLocal == "" || repLocal == "" || repLocal == patLocal)
}

// checkRewriteChains refuses a rewrite whose output another rule of its
// direction would rewrite again, or that would rewrite another rule's
// output, so rewriting is idempotent and can never loop.
func checkRewriteChains(others []AddressRewrite, candidate AddressRewrite) error {
	rules := append(slices.Clone(others), candidate)
	for _, from := range rules {
		for _, to := range rules {
			if from.Direction == candidate.Direction && to.Direction == candidate.Direction && (from.ID == candidate.ID || to.ID == candidate.ID) && produces(from.Replacement, to.Pattern) {
				if from.ID == to.ID {
					return fmt.Errorf("the replacement %s matches the rule's own pattern", from.Replacement)
				}
				return fmt.Errorf("chained rewrite: %s → %s would be rewritten again by the rule for %s", from.Pattern, from.Replacement, to.Pattern)
			}
		}
	}
	return nil
}

// RewriteAddress applies the most specific enabled rule of direction whose
// pattern matches address and that accepts it (nil accepts every rule). A
// domain replacement keeps the local part as given.
func RewriteAddress(rules []AddressRewrite, direction RewriteDirection, address string, accept func(AddressRewrite) bool) (string, bool) {
	best, bestScore := AddressRewrite{}, 0
	for _, rule := range rules {
		if !rule.Enabled || rule.Direction != direction || accept != nil && !accept(rule) {
			continue
		}
		if score := MatchAddress(rule.Pattern, address); score > bestScore || score > 0 && score == bestScore && rule.ID < best.ID {
			best, bestScore = rule, score
		}
	}
	if bestScore == 0 {
		return address, false
	}
	if strings.HasPrefix(best.Replacement, "@") {
		return address[:strings.LastIndex(address, "@")] + best.Replacement, true
	}
	return best.Replacement, true
}

func (rule *JournalRule) normalize() error {
	var err error
	if rule.Domain = strings.TrimPrefix(normalizeID(rule.Domain), "@"); rule.Domain != "" && !validDomain(rule.Domain) {
		return fmt.Errorf("domain must be a domain or empty for all domains")
	}
	if rule.Address, err = normalizeAddress(rule.Address, "journal address"); err != nil {
		return err
	}
	if !rule.Inbound && !rule.Outbound {
		return fmt.Errorf("journal inbound mail, outbound mail, or both")
	}
	switch rule.Format {
	case "":
		rule.Format = JournalEnvelope
	case JournalEnvelope, JournalRaw:
	default:
		return fmt.Errorf("format must be envelope or raw")
	}
	return nil
}

// Matches reports whether rule journals a message. submitted marks mail a
// local account submitted, which is outbound; inbound mail has a recipient
// at a hosted domain, listed in localDomains.
func (rule JournalRule) Matches(submitted bool, senderDomain string, localDomains []string) bool {
	if !rule.Enabled {
		return false
	}
	if rule.Outbound && submitted && (rule.Domain == "" || rule.Domain == normalizeID(senderDomain)) {
		return true
	}
	return rule.Inbound && slices.ContainsFunc(localDomains, func(domain string) bool { return rule.Domain == "" || rule.Domain == domain })
}

func (rule *BCCRule) normalize() error {
	var err error
	if rule.Match != BCCSender && rule.Match != BCCRecipient {
		return fmt.Errorf("match must be sender or recipient")
	}
	if rule.Pattern, err = NormalizeAddressPattern(rule.Pattern); err != nil {
		return fmt.Errorf("pattern: %w", err)
	}
	if rule.Address, err = normalizeAddress(rule.Address, "BCC address"); err != nil {
		return err
	}
	return nil
}

// BCCAddresses returns the BCC addresses of the enabled rules of match for
// address. As Postfix looks up the full address before the domain, exact
// rules hide domain rules.
func BCCAddresses(rules []BCCRule, match BCCMatch, address string) []string {
	var exact, domain []string
	for _, rule := range rules {
		if !rule.Enabled || rule.Match != match {
			continue
		}
		switch MatchAddress(rule.Pattern, address) {
		case 2:
			exact = append(exact, rule.Address)
		case 1:
			domain = append(domain, rule.Address)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return domain
}
