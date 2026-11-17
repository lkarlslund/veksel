package jmap

import (
	"slices"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// mailChanges calls Email/changes or Mailbox/changes as user for accountID.
func (f *fixture) mailChanges(t *testing.T, user, accountID, method, since string) map[string]any {
	t.Helper()
	responses := f.call(t, user, []any{method, map[string]any{"accountId": accountID, "sinceState": since}, "c"})
	return result(t, responses, "c", method)
}

func (f *fixture) mailState(t *testing.T, user, accountID, method string) string {
	t.Helper()
	responses := f.call(t, user, []any{method, map[string]any{"accountId": accountID, "ids": []string{}}, "s"})
	return result(t, responses, "s", method)["state"].(string)
}

func stringsOf(t *testing.T, value any) []string {
	t.Helper()
	var out []string
	for _, v := range value.([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestSharedMailChangesFollowOwnerJournal(t *testing.T) {
	// Per-account journals are required for the owner and the viewer to have
	// distinct states, so run on the real account-sharded folder space.
	f := buildFixture(t, func(ts *model.TypedStore, _ store.Store, _ service.FolderSpace) service.FolderSpace {
		manager, err := account.NewManager(t.TempDir(), store.BackendPebble)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		for _, login := range []string{"alice", "bob"} {
			user, err := ts.UserStore().Get(t.Context(), login)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Ensure(t.Context(), user, "", nil); err != nil {
				t.Fatal(err)
			}
		}
		space, err := service.NewAccountFolderSpace(t.Context(), ts, manager, authz.New(ts))
		if err != nil {
			t.Fatal(err)
		}
		return space
	})
	ctx := t.Context()
	alice := service.UserAccess("alice", "test")
	inbox := folderByPath(t, f, "alice", "INBOX")
	archive, err := f.space.CreateFolder(ctx, alice, "Team", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	private, err := f.space.CreateFolder(ctx, alice, "Secret", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	share(t, f, inbox, "bob", authz.RoleFolderViewer)
	share(t, f, archive, "bob", authz.RoleFolderViewer)

	emailState := f.mailState(t, "bob", "alice", "Email/get")
	mailboxState := f.mailState(t, "bob", "alice", "Mailbox/get")
	bobState := f.mailState(t, "bob", "bob", "Email/get")

	// New mail.
	item, err := f.space.CreateItem(ctx, alice, inbox.ID, service.ItemInput{Data: []byte("Subject: shared\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	changes := f.mailChanges(t, "bob", "alice", "Email/changes", emailState)
	if !slices.Equal(stringsOf(t, changes["created"]), []string{item.ID}) || changes["oldState"] != emailState || changes["newState"] == emailState {
		t.Fatalf("new mail changes = %#v", changes)
	}
	emailState = changes["newState"].(string)
	if got := f.mailState(t, "bob", "alice", "Email/get"); got != emailState {
		t.Fatalf("Email/get state %q != newState %q", got, emailState)
	}
	if got := f.mailState(t, "bob", "bob", "Email/get"); got != bobState {
		t.Fatalf("bob's own state moved with alice's mail: %q -> %q", bobState, got)
	}
	if emailState == bobState {
		t.Fatal("shared and own account states are equal")
	}

	// Flag change.
	if _, err := f.space.SetFlags(ctx, alice, item.ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	changes = f.mailChanges(t, "bob", "alice", "Email/changes", emailState)
	if !slices.Equal(stringsOf(t, changes["updated"]), []string{item.ID}) || len(changes["created"].([]any)) != 0 || changes["newState"] == emailState {
		t.Fatalf("flag changes = %#v", changes)
	}
	emailState = changes["newState"].(string)

	// Move between two shared folders.
	if _, err := f.space.MoveItem(ctx, alice, item.ID, archive.ID, ""); err != nil {
		t.Fatal(err)
	}
	changes = f.mailChanges(t, "bob", "alice", "Email/changes", emailState)
	if !slices.Equal(stringsOf(t, changes["updated"]), []string{item.ID}) || len(changes["destroyed"].([]any)) != 0 {
		t.Fatalf("move changes = %#v", changes)
	}
	emailState = changes["newState"].(string)

	// Move out of the shared set is a destroy for the viewer.
	if _, err := f.space.MoveItem(ctx, alice, item.ID, private.ID, ""); err != nil {
		t.Fatal(err)
	}
	changes = f.mailChanges(t, "bob", "alice", "Email/changes", emailState)
	if !slices.Equal(stringsOf(t, changes["destroyed"]), []string{item.ID}) {
		t.Fatalf("move-out changes = %#v", changes)
	}
	emailState = changes["newState"].(string)

	// Destroy.
	other, err := f.space.CreateItem(ctx, alice, inbox.ID, service.ItemInput{Data: []byte("Subject: gone\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	emailState = f.mailChanges(t, "bob", "alice", "Email/changes", emailState)["newState"].(string)
	if err := f.space.DeleteItem(ctx, alice, other.ID); err != nil {
		t.Fatal(err)
	}
	changes = f.mailChanges(t, "bob", "alice", "Email/changes", emailState)
	if !slices.Equal(stringsOf(t, changes["destroyed"]), []string{other.ID}) {
		t.Fatalf("destroy changes = %#v", changes)
	}

	// Mailbox changes follow the owner's folder journal.
	if _, err := f.space.MoveFolder(ctx, alice, archive.ID, "", "Team2"); err != nil {
		t.Fatal(err)
	}
	mailboxChanges := f.mailChanges(t, "bob", "alice", "Mailbox/changes", mailboxState)
	if !slices.Equal(stringsOf(t, mailboxChanges["updated"]), []string{archive.ID}) || mailboxChanges["newState"] == mailboxState {
		t.Fatalf("mailbox changes = %#v", mailboxChanges)
	}
	if got := f.mailState(t, "bob", "alice", "Mailbox/get"); got != mailboxChanges["newState"] {
		t.Fatalf("Mailbox/get state %q != newState %q", got, mailboxChanges["newState"])
	}
	// Bob's own mailboxes are untouched by alice's activity.
	if got := f.mailState(t, "bob", "bob", "Mailbox/get"); got == mailboxChanges["newState"] {
		t.Fatal("bob's own mailbox state equals alice's")
	}
}
