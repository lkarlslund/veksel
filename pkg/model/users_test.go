package model

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestUserStoreCRUD(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	// Create
	if err := us.Create(ctx, "alice", "Alice Smith", "hashed-pass"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Get
	u, err := us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.ID != "alice" {
		t.Errorf("id = %q, want %q", u.ID, "alice")
	}
	if u.DisplayName != "Alice Smith" {
		t.Errorf("display_name = %q, want %q", u.DisplayName, "Alice Smith")
	}
	if !u.Enabled {
		t.Error("expected user to be enabled")
	}

	// Idempotent create should fail
	if err := us.Create(ctx, "alice", "Alice", "pass"); err != store.ErrExists {
		t.Errorf("expected ErrExists, got %v", err)
	}

	// Update
	if err := us.Update(ctx, "alice", func(u *User) { u.DisplayName = "Alice Jones" }); err != nil {
		t.Fatalf("update: %v", err)
	}
	u, err = us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if u.DisplayName != "Alice Jones" {
		t.Errorf("display_name = %q, want %q", u.DisplayName, "Alice Jones")
	}

	// List
	if err := us.Create(ctx, "bob", "Bob Jones", "pass"); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	users, err := us.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := len(users); got != 2 {
		t.Errorf("list returned %d users, want 2", got)
	}

	// Delete
	if err := us.Delete(ctx, "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = us.Get(ctx, "alice")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestUserStoreNormalizeID(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	if err := us.Create(ctx, "  Alice  ", "Alice", "pass"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get with normalized id: %v", err)
	}
}

func TestEmailIdentityPrimaryLifecycle(t *testing.T) {
	ts := newTestSetup(t)
	users := NewUserStore(ts)
	if err := users.Create(t.Context(), "alice", "Alice", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := users.AddEmailAddress(t.Context(), "z@example.test", "alice", "example.test", false); err != nil {
		t.Fatal(err)
	}
	if identity, err := users.GetEmailAddress(t.Context(), "z@example.test"); err != nil || !identity.Primary {
		t.Fatalf("first identity = %+v, %v; want primary", identity, err)
	}
	if err := users.AddEmailAddress(t.Context(), "a@example.test", "alice", "example.test", false); err != nil {
		t.Fatal(err)
	}
	if err := users.UpdateEmailAddress(t.Context(), "a@example.test", true, true); err != nil {
		t.Fatal(err)
	}
	assertPrimaryIdentity(t, users, "alice", "a@example.test")
	if err := users.UpdateEmailAddress(t.Context(), "a@example.test", false, false); err != nil {
		t.Fatal(err)
	}
	assertPrimaryIdentity(t, users, "alice", "z@example.test")
	if err := users.UpdateEmailAddress(t.Context(), "z@example.test", false, true); err == nil {
		t.Fatal("disabled primary update succeeded")
	}
	if err := users.DeleteEmailAddress(t.Context(), "z@example.test"); err != nil {
		t.Fatal(err)
	}
	identities, err := users.ListEmailAddressesForUser(t.Context(), "alice")
	if err != nil || len(identities) != 1 || identities[0].Primary || identities[0].Enabled {
		t.Fatalf("remaining identities = %+v, %v", identities, err)
	}
}

func TestConcurrentPrimaryIdentityUpdatesLeaveOnePrimary(t *testing.T) {
	ts := newTestSetup(t)
	users := NewUserStore(ts)
	if err := users.Create(t.Context(), "alice", "Alice", "pass"); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"a@example.test", "b@example.test"} {
		if err := users.AddEmailAddress(t.Context(), address, "alice", "example.test", false); err != nil {
			t.Fatal(err)
		}
	}
	var wait sync.WaitGroup
	errors := make(chan error, 2)
	for _, address := range []string{"a@example.test", "b@example.test"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- users.UpdateEmailAddress(t.Context(), address, true, true)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	identities, err := users.ListEmailAddressesForUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	primary := 0
	for _, identity := range identities {
		if identity.Primary {
			primary++
		}
	}
	if primary != 1 {
		t.Fatalf("primary identity count = %d, identities=%+v", primary, identities)
	}
}

func assertPrimaryIdentity(t *testing.T, users *UserStore, userID, want string) {
	t.Helper()
	identities, err := users.ListEmailAddressesForUser(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range identities {
		if identity.Primary != (identity.ID == want) {
			t.Fatalf("identities = %+v, want only %s primary", identities, want)
		}
	}
}

func TestUserStoreGetNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	_, err := us.Get(ctx, "nobody")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserStoreDeleteNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	err := us.Delete(ctx, "nobody")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserStoreDeleteForgetsRolesAndGroups(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := t.Context()
	for _, namespace := range []string{NSPolicyBindings, NSPolicyIndexes, NSGroups} {
		if err := ts.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := us.Create(ctx, "carol", "Carol", "hash"); err != nil {
		t.Fatal(err)
	}
	policies, groups := NewPolicyStore(ts), NewGroupStore(ts)
	if _, err := policies.Create(ctx, PolicyBinding{Principal: PrincipalRef{Kind: PrincipalUser, ID: "carol"}, Resource: ResourceRef{Kind: ResourceSystem, ID: "system"}, Effect: EffectAllow, RoleID: "system.admin", Inheritance: InheritanceSubtree, GrantedBy: "owner"}); err != nil {
		t.Fatal(err)
	}
	if err := groups.Set(ctx, Group{ID: "admins", Name: "Admins", Members: []string{"carol", "dave"}}); err != nil {
		t.Fatal(err)
	}
	if err := us.Delete(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	// An account later created with the same ID starts with nothing.
	if bindings, err := policies.ListForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: "carol"}); err != nil || len(bindings) != 0 {
		t.Fatalf("bindings after delete = %+v, %v", bindings, err)
	}
	if group, err := groups.Get(ctx, "admins"); err != nil || len(group.Members) != 1 || group.Members[0] != "dave" {
		t.Fatalf("group after delete = %+v, %v", group, err)
	}
}

func TestUserStoreUpdateNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	err := us.Update(ctx, "nobody", func(u *User) {})
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserMailSignatureRequiresOwnedIdentityAndIsRemovedWithIt(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	users := NewUserStore(ts)
	if err := users.Create(t.Context(), "alice", "Alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := users.Create(t.Context(), "bob", "Bob", "password"); err != nil {
		t.Fatal(err)
	}
	if err := users.AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	signature := MailSignature{Text: "Kind regards,\nAlice", NewMessages: true, RepliesForwards: true}
	if err := users.UpdateMailSignature(t.Context(), "alice", "ALICE@example.test", signature); err != nil {
		t.Fatal(err)
	}
	if err := users.UpdateMailSignature(t.Context(), "bob", "alice@example.test", signature); err != store.ErrNotFound {
		t.Fatalf("cross-owner signature error = %v", err)
	}
	user, err := users.Get(t.Context(), "alice")
	if err != nil || user.MailSignatures["alice@example.test"] != signature {
		t.Fatalf("stored signatures = %#v, %v", user.MailSignatures, err)
	}
	if err := users.DeleteEmailAddress(t.Context(), "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	user, err = users.Get(t.Context(), "alice")
	if err != nil || len(user.MailSignatures) != 0 {
		t.Fatalf("signature survived identity removal: %#v, %v", user.MailSignatures, err)
	}
}

func TestUserStoreListEmpty(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	users, err := us.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected empty list, got %d users", len(users))
	}
}

// --- Email address tests ---

func TestUserStoreAddAndGetEmailAddress(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	// Create user and domain first
	if err := us.Create(ctx, "alice", "Alice", "pass"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ds := NewDomainStore(ts)
	if err := ds.Create(ctx, "example.com"); err != nil {
		t.Fatalf("create domain: %v", err)
	}

	// Add email address
	if err := us.AddEmailAddress(ctx, "alice@example.com", "alice", "example.com", true); err != nil {
		t.Fatalf("add email: %v", err)
	}

	// Get
	ea, err := us.GetEmailAddress(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("get email: %v", err)
	}
	if ea.ID != "alice@example.com" {
		t.Errorf("id = %q, want %q", ea.ID, "alice@example.com")
	}
	if ea.UserID != "alice" {
		t.Errorf("user_id = %q, want %q", ea.UserID, "alice")
	}
	if ea.DomainID != "example.com" {
		t.Errorf("domain_id = %q, want %q", ea.DomainID, "example.com")
	}
	if ea.LocalPart != "alice" {
		t.Errorf("local_part = %q, want %q", ea.LocalPart, "alice")
	}
	if !ea.Primary {
		t.Error("expected primary to be true")
	}
}

func TestUserStoreAddEmailAddressDuplicate(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	ds := NewDomainStore(ts)
	ds.Create(ctx, "example.com")

	us.AddEmailAddress(ctx, "alice@example.com", "alice", "example.com", true)
	err := us.AddEmailAddress(ctx, "alice@example.com", "alice", "example.com", false)
	if err != store.ErrExists {
		t.Errorf("expected ErrExists, got %v", err)
	}
}

func TestUserStoreListEmailAddressesForUser(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	ds := NewDomainStore(ts)
	ds.Create(ctx, "example.com")

	us.AddEmailAddress(ctx, "alice@example.com", "alice", "example.com", true)
	us.AddEmailAddress(ctx, "a@example.com", "alice", "example.com", false)

	addrs, err := us.ListEmailAddressesForUser(ctx, "alice")
	if err != nil {
		t.Fatalf("list for user: %v", err)
	}
	if got := len(addrs); got != 2 {
		t.Fatalf("expected 2 addresses, got %d", got)
	}
}

func TestUserStoreListEmailAddressesForDomain(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.Create(ctx, "bob", "Bob", "pass")
	ds := NewDomainStore(ts)
	ds.Create(ctx, "example.com")

	us.AddEmailAddress(ctx, "alice@example.com", "alice", "example.com", true)
	us.AddEmailAddress(ctx, "bob@example.com", "bob", "example.com", true)

	addrs, err := us.ListEmailAddressesForDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("list for domain: %v", err)
	}
	if got := len(addrs); got != 2 {
		t.Fatalf("expected 2 addresses, got %d", got)
	}
}

func TestUserStoreDeleteEmailAddress(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	ds := NewDomainStore(ts)
	ds.Create(ctx, "example.com")
	us.AddEmailAddress(ctx, "alice@example.com", "alice", "example.com", true)

	if err := us.DeleteEmailAddress(ctx, "alice@example.com"); err != nil {
		t.Fatalf("delete email: %v", err)
	}

	_, err := us.GetEmailAddress(ctx, "alice@example.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}

	// Verify user index is cleaned up
	addrs, _ := us.ListEmailAddressesForUser(ctx, "alice")
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses after delete, got %d", len(addrs))
	}

	// Verify domain index is cleaned up
	dAddrs, _ := us.ListEmailAddressesForDomain(ctx, "example.com")
	if len(dAddrs) != 0 {
		t.Errorf("expected 0 addresses on domain after delete, got %d", len(dAddrs))
	}
}

func TestUserStoreDeleteEmailAddressNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	err := us.DeleteEmailAddress(ctx, "nobody@nowhere.com")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserStoreEmailAddressNormalize(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	ds := NewDomainStore(ts)
	ds.Create(ctx, "example.com")

	// Add with uppercase
	if err := us.AddEmailAddress(ctx, "  ALICE@EXAMPLE.COM  ", "alice", "example.com", true); err != nil {
		t.Fatalf("add email: %v", err)
	}

	// Get with lowercase
	_, err := us.GetEmailAddress(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("get with lowercase: %v", err)
	}
}

// --- Forwarding tests ---

func TestUserStoreUpdateForwarding(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")

	if err := us.UpdateForwarding(ctx, "alice", "alice@gmail.com"); err != nil {
		t.Fatalf("update forwarding: %v", err)
	}

	u, err := us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.ForwardTo != "alice@gmail.com" {
		t.Errorf("forward_to = %q, want %q", u.ForwardTo, "alice@gmail.com")
	}

	// Disable forwarding
	if err := us.UpdateForwarding(ctx, "alice", ""); err != nil {
		t.Fatalf("disable forwarding: %v", err)
	}

	u, err = us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.ForwardTo != "" {
		t.Errorf("forward_to = %q, want empty", u.ForwardTo)
	}
}

// --- Vacation tests ---

func TestUserStoreUpdateVacation(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")

	now := timeNow()
	if err := us.UpdateVacation(ctx, "alice", true, now, now.Add(7*24*time.Hour), "Out of Office", "I'm away"); err != nil {
		t.Fatalf("update vacation: %v", err)
	}

	u, err := us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !u.VacationEnabled {
		t.Error("expected vacation to be enabled")
	}
	if u.VacationSubject != "Out of Office" {
		t.Errorf("subject = %q, want %q", u.VacationSubject, "Out of Office")
	}
	if u.VacationMessage != "I'm away" {
		t.Errorf("message = %q, want %q", u.VacationMessage, "I'm away")
	}
}

func TestVacationActiveMethod(t *testing.T) {
	t.Parallel()
	now := timeNow()

	// Enabled with message, no dates
	u1 := User{VacationEnabled: true, VacationMessage: "Hi"}
	if !u1.VacationActive() {
		t.Error("should be active")
	}

	// Disabled
	u2 := User{VacationEnabled: false, VacationMessage: "Hi"}
	if u2.VacationActive() {
		t.Error("should not be active when disabled")
	}

	// Empty message
	u3 := User{VacationEnabled: true, VacationMessage: ""}
	if u3.VacationActive() {
		t.Error("should not be active with empty message")
	}

	// Before start
	u4 := User{VacationEnabled: true, VacationStart: now.Add(24 * time.Hour), VacationMessage: "Hi"}
	if u4.VacationActive() {
		t.Error("should not be active before start date")
	}

	// After end
	u5 := User{VacationEnabled: true, VacationEnd: now.Add(-24 * time.Hour), VacationMessage: "Hi"}
	if u5.VacationActive() {
		t.Error("should not be active after end date")
	}

	// Within range
	u6 := User{VacationEnabled: true, VacationStart: now.Add(-24 * time.Hour), VacationEnd: now.Add(24 * time.Hour), VacationMessage: "Hi"}
	if !u6.VacationActive() {
		t.Error("should be active within date range")
	}
}

func TestVacationReplyTracking(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")

	// First time — should reply
	if !us.ShouldVacationReply(ctx, "alice", "bob@example.com") {
		t.Error("should reply on first message")
	}

	// Record the reply
	if err := us.RecordVacationReply(ctx, "alice", "bob@example.com"); err != nil {
		t.Fatalf("record reply: %v", err)
	}

	// Immediately after — should not reply (within 24h)
	if us.ShouldVacationReply(ctx, "alice", "bob@example.com") {
		t.Error("should not reply within 24h")
	}

	// Different sender — should reply
	if !us.ShouldVacationReply(ctx, "alice", "carol@example.com") {
		t.Error("should reply to different sender")
	}

	// LastVacationReply
	lastReply, err := us.LastVacationReply(ctx, "alice", "bob@example.com")
	if err != nil {
		t.Fatalf("last reply: %v", err)
	}
	if lastReply.IsZero() {
		t.Error("expected non-zero time")
	}
}

func TestVacationReplyReservationIsAtomicAndCancelable(t *testing.T) {
	ts := newTestSetup(t)
	users := NewUserStore(ts)
	const contenders = 32
	var wait sync.WaitGroup
	start := make(chan struct{})
	tokens := make(chan string, contenders)
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			token, reserved, err := users.ReserveVacationReply(t.Context(), "alice", "Sender@Example.Test")
			if err != nil {
				t.Errorf("reserve: %v", err)
				return
			}
			if reserved {
				tokens <- token
			}
		}()
	}
	close(start)
	wait.Wait()
	close(tokens)
	var winners []string
	for token := range tokens {
		winners = append(winners, token)
	}
	if len(winners) != 1 {
		t.Fatalf("reservation winners = %d, want 1", len(winners))
	}
	if err := users.CancelVacationReply(t.Context(), "alice", "sender@example.test", winners[0]); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	token, reserved, err := users.ReserveVacationReply(t.Context(), "alice", "sender@example.test")
	if err != nil || !reserved {
		t.Fatalf("reserve after cancel: token=%q reserved=%t err=%v", token, reserved, err)
	}
	if err := users.CompleteVacationReply(t.Context(), "alice", "sender@example.test", token); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if _, reserved, err := users.ReserveVacationReply(t.Context(), "alice", "sender@example.test"); err != nil || reserved {
		t.Fatalf("reservation ignored completed rate limit: reserved=%t err=%v", reserved, err)
	}
	if err := ts.Set(t.Context(), NSVacationReplies, vacationReplyKey("alice", "stale@example.test"), vacationReplyState{ReservedAt: time.Now().UTC().Add(-vacationReservationLease - time.Minute), Token: "abandoned"}); err != nil {
		t.Fatal(err)
	}
	if _, reserved, err := users.ReserveVacationReply(t.Context(), "alice", "stale@example.test"); err != nil || !reserved {
		t.Fatalf("stale reservation did not recover: reserved=%t err=%v", reserved, err)
	}
	// A Sieve vacation chooses its period: :seconds 0 always replies, while
	// a longer period suppresses the same tracking key.
	const sieveKey = "sieve:handle:sender@example.test"
	for _, period := range []time.Duration{0, 0} {
		token, reserved, err := users.ReserveVacationReplyWithin(t.Context(), "alice", sieveKey, period)
		if err != nil || !reserved {
			t.Fatalf("zero-period reservation: reserved=%t err=%v", reserved, err)
		}
		if err := users.CompleteVacationReply(t.Context(), "alice", sieveKey, token); err != nil {
			t.Fatal(err)
		}
	}
	if _, reserved, err := users.ReserveVacationReplyWithin(t.Context(), "alice", sieveKey, time.Hour); err != nil || reserved {
		t.Fatalf("one-hour period ignored the last reply: reserved=%t err=%v", reserved, err)
	}
}

// timeNow returns time.Now().UTC() for use in tests.
// We use a variable so we can override it if needed.
var timeNow = func() time.Time {
	return time.Now().UTC()
}

// --- Password Reset tests ---

func TestGeneratePasswordResetToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	if err := us.Create(ctx, "alice", "Alice", "oldpass"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := us.GeneratePasswordResetToken(ctx, "alice")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64 (32-byte hex)", len(token))
	}

	// Token should be valid
	userID, err := us.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if userID != "alice" {
		t.Errorf("user_id = %q, want %q", userID, "alice")
	}
}

func TestGeneratePasswordResetTokenUserNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	_, err := us.GeneratePasswordResetToken(ctx, "nobody")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestValidatePasswordResetTokenExpired(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "oldpass")
	token, err := us.GeneratePasswordResetToken(ctx, "alice")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Manually expire the token by finding and modifying it
	keys, _ := us.ts.List(ctx, NSPasswordResets)
	for _, k := range keys {
		var prt PasswordResetToken
		if err := us.ts.Get(ctx, NSPasswordResets, k, &prt); err != nil {
			continue
		}
		if prt.Token == token {
			prt.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
			us.ts.Set(ctx, NSPasswordResets, k, prt)
			break
		}
	}

	_, err = us.ValidatePasswordResetToken(ctx, token)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for expired token, got %v", err)
	}
}

func TestValidatePasswordResetTokenUsed(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "oldpass")
	token, err := us.GeneratePasswordResetToken(ctx, "alice")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Mark as used
	keys, _ := us.ts.List(ctx, NSPasswordResets)
	for _, k := range keys {
		var prt PasswordResetToken
		if err := us.ts.Get(ctx, NSPasswordResets, k, &prt); err != nil {
			continue
		}
		if prt.Token == token {
			prt.Used = true
			prt.UsedAt = time.Now().UTC()
			us.ts.Set(ctx, NSPasswordResets, k, prt)
			break
		}
	}

	_, err = us.ValidatePasswordResetToken(ctx, token)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for used token, got %v", err)
	}
}

func TestValidatePasswordResetTokenInvalid(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	_, err := us.ValidatePasswordResetToken(ctx, "invalidtoken")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for invalid token, got %v", err)
	}
}

func TestCompletePasswordReset(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "oldpass")
	token, err := us.GeneratePasswordResetToken(ctx, "alice")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if err := us.CompletePasswordReset(ctx, token, "newpass123"); err != nil {
		t.Fatalf("complete reset: %v", err)
	}

	// Verify password was updated
	u, err := us.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.PasswordHash == "" {
		t.Error("password hash should not be empty after reset")
	}

	// Verify new password works
	if !auth.ComparePassword("newpass123", u.PasswordHash) {
		t.Error("new password should match")
	}

	// Token should be consumed
	_, err = us.ValidatePasswordResetToken(ctx, token)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after completing reset, got %v", err)
	}
}

func TestCompletePasswordResetInvalidToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	err := us.CompletePasswordReset(ctx, "invalidtoken", "newpass")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCleanupExpiredResetTokens(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.Create(ctx, "bob", "Bob", "pass")

	// Generate tokens
	token1, _ := us.GeneratePasswordResetToken(ctx, "alice")
	token2, _ := us.GeneratePasswordResetToken(ctx, "bob")

	// Expire token1
	keys, _ := us.ts.List(ctx, NSPasswordResets)
	for _, k := range keys {
		var prt PasswordResetToken
		if err := us.ts.Get(ctx, NSPasswordResets, k, &prt); err != nil {
			continue
		}
		if prt.Token == token1 {
			prt.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
			us.ts.Set(ctx, NSPasswordResets, k, prt)
		}
		if prt.Token == token2 {
			prt.Used = true
			prt.UsedAt = time.Now().UTC().Add(-25 * time.Hour)
			us.ts.Set(ctx, NSPasswordResets, k, prt)
		}
	}

	removed := us.CleanupExpiredResetTokens(ctx)
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
}

func TestListPasswordResetTokens(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	us.GeneratePasswordResetToken(ctx, "alice")

	tokens, err := us.ListPasswordResetTokens(ctx)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].UserID != "alice" {
		t.Errorf("user_id = %q, want %q", tokens[0].UserID, "alice")
	}
}

func TestRevokePasswordResetToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	us.Create(ctx, "alice", "Alice", "pass")
	token, err := us.GeneratePasswordResetToken(ctx, "alice")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if err := us.RevokePasswordResetToken(ctx, token); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// Token should no longer validate
	_, err = us.ValidatePasswordResetToken(ctx, token)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after revoke, got %v", err)
	}
}

func TestRevokePasswordResetTokenNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	us := NewUserStore(ts)
	ctx := context.Background()

	err := us.RevokePasswordResetToken(ctx, "nonexistent")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSpamListEntriesRemainBackwardCompatibleAndExpire(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.EnsureNamespace(t.Context(), NSMetadata); err != nil {
		t.Fatal(err)
	}
	users := ts.UserStore()
	if err := ts.SetStringList(t.Context(), NSMetadata, SpamWhitelistKey("alice"), []string{"legacy.example"}); err != nil {
		t.Fatal(err)
	}
	legacy, err := users.ReadSpamListEntries(t.Context(), "alice", SpamListAllow)
	if err != nil || len(legacy) != 1 || legacy[0].Value != "legacy.example" || !legacy[0].ExpiresAt.IsZero() {
		t.Fatalf("legacy entries = %+v, %v", legacy, err)
	}

	expiresAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	if err := users.AddSpamListEntry(t.Context(), "alice", SpamListAllow, "temporary.example", expiresAt); err != nil {
		t.Fatal(err)
	}
	entries, err := users.ReadSpamListEntries(t.Context(), "alice", SpamListAllow)
	if err != nil || len(entries) != 2 || !entries[1].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("active entries = %+v, %v", entries, err)
	}
	if got := users.GetSpamWhitelist(t.Context(), "alice"); len(got) != 2 || got[1] != "temporary.example" {
		t.Fatalf("legacy projection = %v", got)
	}

	if err := users.AddSpamListEntry(t.Context(), "alice", SpamListBlock, "temporary.example", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := users.GetSpamWhitelist(t.Context(), "alice"); len(got) != 1 || got[0] != "legacy.example" {
		t.Fatalf("opposite allow list = %v", got)
	}
	if got := users.GetSpamBlacklist(t.Context(), "alice"); len(got) != 1 || got[0] != "temporary.example" {
		t.Fatalf("block list = %v", got)
	}

	if err := users.AddSpamListEntry(t.Context(), "alice", SpamListAllow, "expired.example", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := ts.Set(t.Context(), NSMetadata, SpamListExpirationsKey("alice", SpamListAllow), map[string]time.Time{"expired.example": time.Now().UTC().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	active, err := users.ReadSpamListEntries(t.Context(), "alice", SpamListAllow)
	if err != nil || len(active) != 1 || active[0].Value != "legacy.example" {
		t.Fatalf("entries after expiry = %+v, %v", active, err)
	}
	persisted, err := ts.StringList(t.Context(), NSMetadata, SpamWhitelistKey("alice"))
	if err != nil || len(persisted) != 1 || persisted[0] != "legacy.example" {
		t.Fatalf("pruned values = %v, %v", persisted, err)
	}
	var expirations map[string]time.Time
	if err := ts.Get(t.Context(), NSMetadata, SpamListExpirationsKey("alice", SpamListAllow), &expirations); err != nil || len(expirations) != 0 {
		t.Fatalf("pruned expirations = %v, %v", expirations, err)
	}
	if err := users.AddSpamListEntry(t.Context(), "alice", SpamListAllow, "past.example", time.Now().UTC().Add(-time.Second)); err == nil {
		t.Fatal("past expiry succeeded")
	}
}

func TestSpamListOppositeMutationIsAtomic(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	faults := faultstore.New(backend)
	ts := NewTypedStore(faults, store.BackendJSON)
	testSetup(t, ts)
	if err := ts.EnsureNamespace(t.Context(), NSMetadata); err != nil {
		t.Fatal(err)
	}
	users := ts.UserStore()
	if err := users.AddSpamListEntry(t.Context(), "alice", SpamListAllow, "sender.example", time.Time{}); err != nil {
		t.Fatal(err)
	}
	faults.Fail("set", 3)
	if err := users.AddSpamListEntry(t.Context(), "alice", SpamListBlock, "sender.example", time.Time{}); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("mutation error = %v, want injected failure", err)
	}
	if got := users.GetSpamWhitelist(t.Context(), "alice"); len(got) != 1 || got[0] != "sender.example" {
		t.Fatalf("allow list changed after rollback: %v", got)
	}
	if got := users.GetSpamBlacklist(t.Context(), "alice"); len(got) != 0 {
		t.Fatalf("block list visible after rollback: %v", got)
	}
}
