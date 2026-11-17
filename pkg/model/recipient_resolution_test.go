package model

import (
	"errors"
	"slices"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
)

func TestSplitSubaddress(t *testing.T) {
	for _, test := range []struct {
		local, delimiters, user, detail string
		ok                              bool
	}{
		{"alice+news", "+", "alice", "news", true},
		{"alice-news+x", "+-", "alice", "news+x", true},
		{"alice+", "+", "alice", "", true},
		{"+news", "+", "+news", "", false},
		{"alice+news", "", "alice+news", "", false},
		{"alice", "+", "alice", "", false},
	} {
		user, detail, ok := SplitSubaddress(test.local, test.delimiters)
		if user != test.user || detail != test.detail || ok != test.ok {
			t.Errorf("SplitSubaddress(%q, %q) = %q, %q, %t", test.local, test.delimiters, user, detail, ok)
		}
	}
}

func TestResolveRecipientPrecedence(t *testing.T) {
	ts := newTestSetup(t)
	ctx := t.Context()
	for _, domain := range []string{"example.test", "other.test"} {
		if err := ts.DomainStore().Create(ctx, domain); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"alice", "bob", "carol"} {
		if err := ts.UserStore().Create(ctx, id, id, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := ts.UserStore().AddEmailAddress(ctx, id+"@example.test", id, "example.test", true); err != nil {
			t.Fatal(err)
		}
	}
	// An exact identity that looks subaddressed belongs to carol.
	if err := ts.UserStore().AddEmailAddress(ctx, "alice+exact@example.test", "carol", "example.test", false); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.RecipientAliasStore().Create(ctx, "team@example.test", []string{"alice@example.test", "bob@example.test"}, true); err != nil {
		t.Fatal(err)
	}

	resolve := func(address, delimiters string) RecipientRoute {
		t.Helper()
		route, err := ts.ResolveRecipient(ctx, address, delimiters)
		if err != nil {
			t.Fatalf("resolve %s: %v", address, err)
		}
		return route
	}
	if route := resolve("alice+exact@example.test", "+"); route.Identity.UserID != "carol" || route.Detail != "" {
		t.Fatalf("exact identity lost to subaddress: %+v", route)
	}
	if route := resolve("Alice+News@Example.test", "+"); route.Identity.UserID != "alice" || route.Detail != "news" {
		t.Fatalf("subaddress = %+v", route)
	}
	if route := resolve("alice-news@example.test", "+-"); route.Identity.UserID != "alice" || route.Detail != "news" {
		t.Fatalf("second delimiter = %+v", route)
	}
	if route := resolve("team+ops@example.test", "+"); !slices.Equal(route.Targets, []string{"alice@example.test", "bob@example.test"}) || route.Detail != "ops" {
		t.Fatalf("subaddressed alias = %+v", route)
	}
	if _, err := ts.ResolveRecipient(ctx, "alice+news@example.test", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled delimiter resolved: %v", err)
	}

	// Catch-all applies only after every specific match fails.
	if err := ts.DomainStore().SetCatchAll(ctx, "example.test", "nobody@example.test"); !errors.Is(err, ErrCatchAllInvalid) {
		t.Fatalf("unknown catch-all target accepted: %v", err)
	}
	if err := ts.DomainStore().SetCatchAll(ctx, "example.test", "Carol@Example.test"); err != nil {
		t.Fatal(err)
	}
	if route := resolve("unknown@example.test", "+"); route.Identity.UserID != "carol" || !route.CatchAll {
		t.Fatalf("catch-all = %+v", route)
	}
	if route := resolve("alice+news@example.test", "+"); route.Identity.UserID != "alice" || route.CatchAll {
		t.Fatalf("catch-all took a subaddress: %+v", route)
	}
	if route := resolve("team@example.test", "+"); len(route.Targets) != 2 || route.CatchAll {
		t.Fatalf("catch-all took an alias: %+v", route)
	}
	for _, address := range []string{"SRS0=abcd=AA=origin.test=x@example.test", "srs1=abcd=host==x@example.test", "unknown@other.test", "unknown@absent.test"} {
		if _, err := ts.ResolveRecipient(ctx, address, "+"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s resolved: %v", address, err)
		}
	}
	if err := ts.UserStore().DeleteEmailAddress(ctx, "carol@example.test"); !errors.Is(err, ErrCatchAllInvalid) {
		t.Fatalf("catch-all target deletion = %v", err)
	}

	// A disabled exact identity is a match; it never falls through.
	if err := ts.UserStore().AddEmailAddress(ctx, "off@example.test", "alice", "example.test", false); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().UpdateEmailAddress(ctx, "off@example.test", false, false); err != nil {
		t.Fatal(err)
	}
	if route := resolve("off@example.test", "+"); !route.Disabled || route.CatchAll {
		t.Fatalf("disabled identity = %+v", route)
	}
	if err := ts.DomainStore().SetCatchAll(ctx, "example.test", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ResolveRecipient(ctx, "unknown@example.test", "+"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cleared catch-all still resolves: %v", err)
	}
}
