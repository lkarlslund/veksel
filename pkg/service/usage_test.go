package service

import (
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestAccountUsageUsesFolderMetadataIncludingTrashedDescendants(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "usage-test")
	if _, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("mail"), nil); err != nil {
		t.Fatal(err)
	}
	calendar, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), calendar.ID, []byte("event"), nil); err != nil {
		t.Fatal(err)
	}
	parent, err := space.CreateFolder(t.Context(), access, "Projects", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := space.CreateFolder(t.Context(), access, "Old", model.FolderTypeMail, parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), child.ID, []byte("archived"), nil); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().Trash(t.Context(), parent.ID, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	usage, err := space.AccountUsage(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	if usage.AccountID != "alice" || usage.Items != 3 || usage.LogicalBytes != int64(len("mail")+len("event")+len("archived")) {
		t.Fatalf("usage = %+v", usage)
	}
	if !usage.AccountingReady || usage.Folders != 17 {
		t.Fatalf("accounting state = ready %t, folders %d", usage.AccountingReady, usage.Folders)
	}
	byType := make(map[model.FolderType]UsageByType, len(usage.ByType))
	for _, entry := range usage.ByType {
		byType[entry.Type] = entry
	}
	if got := byType[model.FolderTypeMail]; got.Items != 2 || got.LogicalBytes != int64(len("mail")+len("archived")) {
		t.Fatalf("mail usage = %+v", got)
	}
	if got := byType[model.FolderTypeCalendar]; got.Items != 1 || got.LogicalBytes != int64(len("event")) {
		t.Fatalf("calendar usage = %+v", got)
	}
}

func TestAccountUsageRequiresAccountAuthority(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := AccessContext{
		Actor:   model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Mode:    authz.ActingDelegation, Protocol: "usage-test",
	}
	if _, err := space.AccountUsage(t.Context(), access); !errors.Is(err, ErrForbidden) {
		t.Fatalf("usage without delegation error = %v, want forbidden", err)
	}
}
