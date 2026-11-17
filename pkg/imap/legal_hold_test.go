package imap

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// TestExpungeUnderLegalHoldPreservesMessage proves IMAP EXPUNGE reaches the
// FolderSpace hold check: the message leaves the mailbox for the client but
// remains available to compliance access.
func TestExpungeUnderLegalHoldPreservesMessage(t *testing.T) {
	ts := setupTestStore(t)
	compliance, err := service.NewCompliance(t.Context(), ts)
	if err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	space.SetLegalHolds(compliance)
	alice := service.UserAccess("alice", "imap")
	item, err := space.CreateItem(t.Context(), alice, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: held\r\n\r\nbody\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compliance.PlaceHold(t.Context(), service.LegalHold{Scope: service.HoldScopeAccount, Target: "alice", Reason: "case"}); err != nil {
		t.Fatal(err)
	}
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    ts,
		FolderSpace:   space,
	})
	c.send("A001", "LOGIN alice secret")
	if _, code, text := c.send("A002", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: %s %s", code, text)
	}
	if _, code, text := c.send("A003", `STORE 1 +FLAGS (\Deleted)`); code != "OK" {
		t.Fatalf("STORE: %s %s", code, text)
	}
	if _, code, text := c.send("A004", "EXPUNGE"); code != "OK" {
		t.Fatalf("EXPUNGE: %s %s", code, text)
	}
	if items, err := space.ListItems(t.Context(), alice, model.InboxFolderID("alice"), service.ItemQuery{}); err != nil || len(items) != 0 {
		t.Fatalf("inbox after expunge = %d err=%v", len(items), err)
	}
	if _, err := space.GetItem(t.Context(), alice, item.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user reads expunged held message: %v", err)
	}
	preserved, err := space.GetItem(t.Context(), service.ComplianceAccess("alice"), item.ID)
	if err != nil || preserved.HeldDeletedAt.IsZero() {
		t.Fatalf("compliance read = %+v err=%v", preserved, err)
	}
}
