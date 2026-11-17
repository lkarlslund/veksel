package model

import (
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func mailFlowTestStore(t *testing.T) *TypedStore {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := NewTypedStore(backend, store.BackendJSON)
	if listed, err := ts.BCCRuleStore().List(t.Context()); err != nil || len(listed) != 0 {
		t.Fatalf("list before the namespace exists = %v, %v", listed, err)
	}
	for _, namespace := range []string{NSSenderRoutes, NSAddressRewrites, NSJournalRules, NSBCCRules} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	return ts
}

func TestMailFlowStoreLifecycle(t *testing.T) {
	ts := mailFlowTestStore(t)
	routes := ts.SenderRouteStore()
	created, err := routes.Create(t.Context(), SenderRoute{Sender: " Example.COM ", Transport: OutboundTransportRelay, RelayHost: " smtp.provider.test ", Username: "u", SealedPassword: []byte("sealed"), MailFlowRule: MailFlowRule{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Sender != "@example.com" || created.RelayHost != "smtp.provider.test" || created.RelayPort != 25 || created.CreatedAt.IsZero() {
		t.Fatalf("created = %+v", created)
	}
	updated, err := routes.Set(t.Context(), created.ID, SenderRoute{Account: "alice", Destination: "@Remote.Test", Transport: OutboundTransportMX, Username: "dropped", SealedPassword: []byte("dropped")})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || !updated.CreatedAt.Equal(created.CreatedAt) || updated.Destination != "remote.test" || updated.Username != "" || updated.SealedPassword != nil || updated.RelayPort != 25 {
		t.Fatalf("updated = %+v", updated)
	}
	for _, invalid := range []SenderRoute{
		{Transport: OutboundTransportMX},
		{Sender: "not an address", Transport: OutboundTransportMX},
		{Sender: "example.com", Transport: OutboundTransportRelay},
		{Sender: "example.com", Destination: "nodot", Transport: OutboundTransportMX},
	} {
		if _, err := routes.Create(t.Context(), invalid); err == nil {
			t.Fatalf("invalid route accepted: %+v", invalid)
		}
	}
	if err := routes.Delete(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := routes.Get(t.Context(), created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
	if err := routes.Delete(t.Context(), created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestSelectSenderRoutePrecedence(t *testing.T) {
	route := func(id, sender, account, destination string) SenderRoute {
		return SenderRoute{MailFlowRule: MailFlowRule{ID: id, Enabled: true}, Sender: sender, Account: account, Destination: destination, Transport: OutboundTransportMX}
	}
	routes := []SenderRoute{
		route("a-domain", "@example.com", "", ""),
		route("b-address", "alice@example.com", "", ""),
		route("c-destination", "@example.com", "", "partner.test"),
		route("d-account", "", "@corp.test", ""),
		route("e-both", "@other.test", "bob", ""),
		{MailFlowRule: MailFlowRule{ID: "0-disabled"}, Sender: "alice@example.com", Destination: "partner.test", Transport: OutboundTransportMX},
	}
	for _, test := range []struct {
		sender, account, destination, want string
	}{
		{"carol@example.com", "", "remote.test", "a-domain"},
		{"Alice@Example.com", "", "remote.test", "b-address"},      // the exact sender beats its domain
		{"alice@example.com", "", "PARTNER.test", "c-destination"}, // sender+destination beats sender alone
		{"x@unrelated.test", "dave@corp.test", "remote.test", "d-account"},
		{"x@other.test", "bob", "remote.test", "e-both"},
		{"x@other.test", "carol", "remote.test", ""}, // both matches are required
		{"x@unrelated.test", "", "partner.test", ""},
	} {
		got, ok := SelectSenderRoute(routes, test.sender, test.account, test.destination)
		if ok != (test.want != "") || got.ID != test.want {
			t.Fatalf("SelectSenderRoute(%q, %q, %q) = %q, %v; want %q", test.sender, test.account, test.destination, got.ID, ok, test.want)
		}
	}
}

func TestAddressRewritesApplyOnceAndRefuseChains(t *testing.T) {
	rewrites := mailFlowTestStore(t).AddressRewriteStore()
	domain, err := rewrites.Create(t.Context(), AddressRewrite{Direction: RewriteOutbound, Pattern: "internal.example", Replacement: "@example.com", EnvelopeSender: true, HeaderFrom: true, MailFlowRule: MailFlowRule{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rewrites.Create(t.Context(), AddressRewrite{Direction: RewriteOutbound, Pattern: "ceo@internal.example", Replacement: "boss@example.com", HeaderFrom: true, MailFlowRule: MailFlowRule{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	for _, chained := range []AddressRewrite{
		{Direction: RewriteOutbound, Pattern: "@example.com", Replacement: "@public.example", EnvelopeSender: true},       // would rewrite the output again
		{Direction: RewriteOutbound, Pattern: "@legacy.example", Replacement: "x@internal.example", EnvelopeSender: true}, // output would be rewritten
		{Direction: RewriteInbound, Pattern: "@a.example", Replacement: "user@a.example"},                                 // its own output
		{Direction: RewriteInbound, Pattern: "user@a.example", Replacement: "@b.example"},                                 // address pattern, domain replacement
		{Direction: RewriteOutbound, Pattern: "@legacy.example", Replacement: "@example.org"},                             // changes nothing
	} {
		if _, err := rewrites.Create(t.Context(), chained); err == nil {
			t.Fatalf("rewrite accepted: %+v", chained)
		}
	}
	// The inbound direction is independent of the outbound rules.
	if _, err := rewrites.Create(t.Context(), AddressRewrite{Direction: RewriteInbound, Pattern: "@example.com", Replacement: "@internal.example", MailFlowRule: MailFlowRule{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	rules, err := rewrites.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	envelope := func(rule AddressRewrite) bool { return rule.EnvelopeSender }
	for _, test := range []struct {
		direction     RewriteDirection
		address, want string
		accept        func(AddressRewrite) bool
		wantRewritten bool
	}{
		{RewriteOutbound, "Joe@internal.example", "Joe@example.com", nil, true},
		{RewriteOutbound, "ceo@internal.example", "boss@example.com", nil, true},
		{RewriteOutbound, "ceo@internal.example", "ceo@example.com", envelope, true}, // the exact rule only rewrites From
		{RewriteOutbound, "joe@example.com", "joe@example.com", nil, false},
		{RewriteInbound, "joe@example.com", "joe@internal.example", nil, true},
	} {
		got, rewritten := RewriteAddress(rules, test.direction, test.address, test.accept)
		if got != test.want || rewritten != test.wantRewritten {
			t.Fatalf("RewriteAddress(%s, %q) = %q, %v", test.direction, test.address, got, rewritten)
		}
	}
	// Disabling keeps the rule in the chain check but stops rewriting.
	domain.Enabled = false
	if _, err := rewrites.Set(t.Context(), domain.ID, domain); err != nil {
		t.Fatal(err)
	}
	rules, _ = rewrites.List(t.Context())
	if got, _ := RewriteAddress(rules, RewriteOutbound, "joe@internal.example", nil); got != "joe@internal.example" {
		t.Fatalf("disabled rule rewrote to %q", got)
	}
}

func TestBCCAndJournalRuleMatching(t *testing.T) {
	ts := mailFlowTestStore(t)
	for _, rule := range []BCCRule{
		{Match: BCCSender, Pattern: "example.com", Address: "archive@example.com"},
		{Match: BCCSender, Pattern: "ceo@example.com", Address: "Assistant@Example.com"},
		{Match: BCCRecipient, Pattern: "@example.com", Address: "inbound@example.com"},
	} {
		rule.Enabled = true
		if _, err := ts.BCCRuleStore().Create(t.Context(), rule); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ts.BCCRuleStore().Create(t.Context(), BCCRule{Match: "both", Pattern: "example.com", Address: "x@example.com"}); err == nil {
		t.Fatal("invalid match accepted")
	}
	rules, err := ts.BCCRuleStore().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := BCCAddresses(rules, BCCSender, "joe@example.com"); strings.Join(got, ",") != "archive@example.com" {
		t.Fatalf("domain sender BCC = %v", got)
	}
	if got := BCCAddresses(rules, BCCSender, "ceo@example.com"); strings.Join(got, ",") != "assistant@example.com" {
		t.Fatalf("exact sender BCC = %v", got)
	}
	if got := BCCAddresses(rules, BCCRecipient, "joe@remote.test"); len(got) != 0 {
		t.Fatalf("unmatched recipient BCC = %v", got)
	}

	if _, err := ts.JournalRuleStore().Create(t.Context(), JournalRule{Address: "journal@example.com"}); err == nil {
		t.Fatal("journal rule without a direction accepted")
	}
	rule, err := ts.JournalRuleStore().Create(t.Context(), JournalRule{Domain: "Example.com", Inbound: true, Address: "Journal@Example.com", MailFlowRule: MailFlowRule{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if rule.Format != JournalEnvelope || rule.Address != "journal@example.com" || rule.Domain != "example.com" {
		t.Fatalf("journal rule = %+v", rule)
	}
	if !rule.Matches(false, "remote.test", []string{"example.com"}) || rule.Matches(true, "example.com", nil) || rule.Matches(false, "remote.test", []string{"other.test"}) {
		t.Fatal("inbound journal rule matched wrongly")
	}
	global := JournalRule{MailFlowRule: MailFlowRule{Enabled: true}, Outbound: true}
	if !global.Matches(true, "any.test", nil) || global.Matches(false, "any.test", []string{"example.com"}) {
		t.Fatal("global outbound journal rule matched wrongly")
	}
}

func TestQuotaExemptWritesCountButAreNotRefused(t *testing.T) {
	ts := mailFlowTestStore(t)
	if err := ts.EnsureNamespace(t.Context(), NSUsers); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().CreateUser(t.Context(), User{ID: "journal"}); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().UpdateQuota(t.Context(), "journal", 10, 0); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().CheckAndIncrementUsage(t.Context(), "journal", 20); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over-quota write = %v", err)
	}
	if err := ts.UserStore().CheckAndIncrementUsage(WithQuotaExempt(t.Context()), "journal", 20); err != nil {
		t.Fatalf("exempt write = %v", err)
	}
	if quota, err := ts.UserStore().GetQuota(t.Context(), "journal"); err != nil || quota.CurrentStorageBytes != 20 {
		t.Fatalf("usage after exempt write = %+v, %v", quota, err)
	}
}
