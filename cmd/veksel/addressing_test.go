package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/batv"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/srs"
)

func liveAddressingServer(t *testing.T) *server {
	t.Helper()
	s := &server{}
	t.Cleanup(func() {
		s.cleanup.run(true)
	})
	if err := s.openRuntime(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := s.openAddressing(); err != nil {
		t.Fatal(err)
	}
	if err := s.registerDeliverySettings(); err != nil {
		t.Fatal(err)
	}
	ctx := s.ctx
	if err := s.ts.DomainStore().Create(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob"} {
		if err := s.ts.UserStore().Create(ctx, id, id, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := s.ts.UserStore().AddEmailAddress(ctx, id+"@example.test", id, "example.test", true); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestForwardSenderRewritingAppliesLive(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	patchAndApply(t, s, map[string]any{"srs_domain": "fwd.example.test"})
	rewritten := s.rewriteForwardSender(ctx, "carol@remote.example")
	if !strings.HasPrefix(rewritten, "SRS0=") || !strings.HasSuffix(rewritten, "=remote.example=carol@fwd.example.test") {
		t.Fatalf("rewritten sender = %q", rewritten)
	}
	for _, sender := range []string{"", "alice@example.test", "x@fwd.example.test"} {
		if got := s.rewriteForwardSender(ctx, sender); got != sender {
			t.Fatalf("sender %q rewritten to %q", sender, got)
		}
	}

	original, isSRS, err := s.reverseSRS(ctx, strings.ToLower(rewritten))
	if !isSRS || err != nil || original != "carol@remote.example" {
		t.Fatalf("reverse = %q, %t, %v", original, isSRS, err)
	}
	if _, isSRS, _ := s.reverseSRS(ctx, strings.Replace(rewritten, "@fwd.example.test", "@example.test", 1)); isSRS {
		t.Fatal("SRS address at another domain was treated as ours")
	}
	if _, isSRS, err := s.reverseSRS(ctx, strings.Replace(rewritten, "=carol@", "=mallory@", 1)); !isSRS || err == nil {
		t.Fatalf("forged SRS address = %t, %v", isSRS, err)
	}

	// Disabling rewriting keeps earlier addresses returnable.
	patchAndApply(t, s, map[string]any{"srs_enabled": false})
	if got := s.rewriteForwardSender(ctx, "carol@remote.example"); got != "carol@remote.example" {
		t.Fatalf("disabled SRS rewrote to %q", got)
	}
	if _, isSRS, err := s.reverseSRS(ctx, rewritten); !isSRS || err != nil {
		t.Fatalf("return after disabling = %t, %v", isSRS, err)
	}
	for _, key := range []string{"srs_enabled", "srs_domain"} {
		if state := applyState(t, s, key); state.RestartRequired {
			t.Fatalf("%s requires restart", key)
		}
	}
}

func TestSRSSecretsPersistAcrossRestarts(t *testing.T) {
	s := liveAddressingServer(t)
	first, err := loadSigningSecrets(s.ctx, s.ts, srsSecretsKey)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadSigningSecrets(s.ctx, s.ts, srsSecretsKey)
	if err != nil || len(first) != 1 || len(again) != 1 || string(first[0]) != string(again[0]) {
		t.Fatalf("secrets changed between loads: %d/%d, %v", len(first), len(again), err)
	}
	// A second, older secret still verifies addresses it signed.
	older := []byte("previous-installation-secret-012345")
	oldCodec, _ := srs.New([][]byte{older})
	address, _ := oldCodec.Forward("carol@remote.example", s.srsDomain())
	rotated, _ := srs.New(append(first, older))
	s.delivery.srs = rotated
	if original, isSRS, err := s.reverseSRS(s.ctx, address); !isSRS || err != nil || original != "carol@remote.example" {
		t.Fatalf("rotated secret reverse = %q, %t, %v", original, isSRS, err)
	}
}

func TestSignedReturnPathsApplyLive(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	if got := s.signReturnPath(ctx, "alice@example.test"); got != "alice@example.test" {
		t.Fatalf("disabled BATV signed %q", got)
	}
	if got, err := s.checkReturnPath(ctx, "alice@example.test", true); err != nil || got != "alice@example.test" {
		t.Fatalf("disabled BATV bounce = %q, %v", got, err)
	}

	patchAndApply(t, s, map[string]any{"batv_enabled": true, "batv_grace_period_hours": int64(0)})
	signed := s.signReturnPath(ctx, "alice@example.test")
	if !batv.IsTagged(strings.Split(signed, "@")[0]) || !strings.HasSuffix(signed, "=alice@example.test") {
		t.Fatalf("signed sender = %q", signed)
	}
	srsSender, _ := s.delivery.srs.Forward("carol@remote.example", "example.test")
	for _, sender := range []string{"", "carol@remote.example", srsSender, signed} {
		if got := s.signReturnPath(ctx, sender); got != sender {
			t.Fatalf("sender %q signed as %q", sender, got)
		}
	}
	if got, err := s.checkReturnPath(ctx, strings.ToLower(signed), true); err != nil || got != "alice@example.test" {
		t.Fatalf("tagged bounce = %q, %v", got, err)
	}
	if _, err := s.checkReturnPath(ctx, "alice@example.test", true); !errors.Is(err, smtp.ErrBackscatter) {
		t.Fatalf("untagged bounce = %v", err)
	}
	for _, recipient := range []string{"postmaster@example.test", "abuse@example.test", "dave@remote.example"} {
		if got, err := s.checkReturnPath(ctx, recipient, true); err != nil || got != recipient {
			t.Fatalf("exempt bounce to %s = %q, %v", recipient, got, err)
		}
	}
	if got, err := s.checkReturnPath(ctx, "alice@example.test", false); err != nil || got != "alice@example.test" {
		t.Fatalf("ordinary mail = %q, %v", got, err)
	}

	// Remote deliveries carry the signed sender; the queued message keeps
	// the original.
	relay := startFakeRelay(t)
	message := &queue.Message{ID: "m", EnvelopeSender: "alice@example.test", Recipient: "b@remote.test", Headers: map[string]string{"Subject": "batv"}, Body: []byte("body")}
	if err := s.relay(ctx, s.outboundClient(smtp.RelayConfig{Host: "127.0.0.1", Port: relay.port}), message); err != nil {
		t.Fatal(err)
	}
	if sent := relay.sender.Load(); sent == nil || !strings.HasPrefix(*sent, "prvs=") || message.EnvelopeSender != "alice@example.test" {
		t.Fatalf("relayed sender = %v, queued sender %q", sent, message.EnvelopeSender)
	}

	// The grace period counts from enabling, which persists.
	patchAndApply(t, s, map[string]any{"batv_grace_period_hours": int64(24)})
	if _, err := s.checkReturnPath(ctx, "alice@example.test", true); err != nil {
		t.Fatalf("untagged bounce in grace = %v", err)
	}
	patchAndApply(t, s, map[string]any{"batv_enabled": false})
	if got := s.signReturnPath(ctx, "alice@example.test"); got != "alice@example.test" {
		t.Fatalf("disabled BATV signed %q", got)
	}
	if got, err := s.checkReturnPath(ctx, signed, true); err != nil || got != "alice@example.test" {
		t.Fatalf("tag after disabling = %q, %v", got, err)
	}
	for _, key := range []string{"batv_enabled", "batv_grace_period_hours"} {
		if state := applyState(t, s, key); state.RestartRequired {
			t.Fatalf("%s requires restart", key)
		}
	}
}

func TestRecipientResolutionUsesLiveDelimiterAndCatchAll(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	if _, owner, err := s.resolveLocalAddress(ctx, "alice+news@example.test"); err != nil || owner != "alice" {
		t.Fatalf("plus address = %q, %v", owner, err)
	}
	patchAndApply(t, s, map[string]any{"recipient_delimiter": "-"})
	if _, _, err := s.resolveLocalAddress(ctx, "alice+news@example.test"); err == nil {
		t.Fatal("old delimiter still resolves")
	}
	if _, owner, err := s.resolveLocalAddress(ctx, "alice-news@example.test"); err != nil || owner != "alice" {
		t.Fatalf("new delimiter = %q, %v", owner, err)
	}
	patchAndApply(t, s, map[string]any{"recipient_delimiter": ""})
	if _, _, err := s.resolveLocalAddress(ctx, "alice-news@example.test"); err == nil {
		t.Fatal("disabled delimiter still resolves")
	}

	if err := s.ts.DomainStore().SetCatchAll(ctx, "example.test", "bob@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, owner, err := s.resolveLocalAddress(ctx, "anything@example.test"); err != nil || owner != "bob" {
		t.Fatalf("catch-all = %q, %v", owner, err)
	}
	if _, owner, err := s.resolveLocalAddress(ctx, "alice@example.test"); err != nil || owner != "alice" {
		t.Fatalf("exact address lost to catch-all: %q, %v", owner, err)
	}
	identity, err := s.recipientMailbox(ctx, "anything@example.test")
	if err != nil || identity.UserID != "bob" || !identity.Enabled {
		t.Fatalf("queue routing view = %+v, %v", identity, err)
	}
	if _, _, err := s.resolveLocalAddress(ctx, "anything@unknown.test"); err == nil {
		t.Fatal("unknown domain resolved")
	}
	if state := applyState(t, s, "recipient_delimiter"); state.RestartRequired {
		t.Fatal("recipient_delimiter requires restart")
	}
}

func TestTemporaryAliasDeliveryFolderDiscardAndCleanup(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	aliases := s.ts.UserAliasStore()
	if err := s.ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	filed, err := aliases.Create(ctx, model.UserAliasRequest{UserID: "alice", DomainID: "example.test", FolderPath: "Archive"})
	if err != nil {
		t.Fatal(err)
	}
	folderID, owner, err := s.resolveLocalAddress(ctx, filed.Address)
	if err != nil || owner != "alice" || folderID == model.InboxFolderID("alice") {
		t.Fatalf("filed alias = %q, %q, %v", folderID, owner, err)
	}
	plain, err := aliases.Create(ctx, model.UserAliasRequest{UserID: "alice", DomainID: "example.test", Expiry: time.Hour, OnInactive: model.UserAliasDiscardInactive})
	if err != nil {
		t.Fatal(err)
	}
	if folderID, _, err = s.resolveLocalAddress(ctx, plain.Address); err != nil || folderID != model.InboxFolderID("alice") {
		t.Fatalf("plain alias = %q, %v", folderID, err)
	}
	off := false
	if _, err := aliases.Update(ctx, plain.Address, "alice", model.UserAliasUpdate{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.resolveLocalAddress(ctx, plain.Address); !errors.Is(err, smtp.ErrRecipientDiscarded) {
		t.Fatalf("inactive discard alias = %v", err)
	}
	if err := s.ts.DomainStore().SetCatchAll(ctx, "example.test", "bob@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := aliases.Delete(ctx, filed.Address, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, owner, err := s.resolveLocalAddress(ctx, filed.Address); err == nil || owner == "bob" {
		t.Fatalf("deleted alias fell through to the catch-all: %q, %v", owner, err)
	}
}
