package model

import (
	"context"
	"testing"
)

func TestShareRoleToRights(t *testing.T) {
	t.Parallel()
	tests := []struct {
		role   string
		expect string
	}{
		{ShareOwner, RightAll},
		{ShareWriter, "lrw"},
		{ShareReader, "lr"},
		{"unknown", "lr"},
	}
	for _, tt := range tests {
		got := ShareRoleToRights(tt.role)
		if got != tt.expect {
			t.Errorf("ShareRoleToRights(%q) = %q, want %q", tt.role, got, tt.expect)
		}
	}
}

func TestShareRightsToRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rights string
		expect string
	}{
		{RightAll, ShareOwner},
		{"lrw", ShareWriter},
		{"lr", ShareReader},
		{"lrwk", ShareWriter},
		{"", ShareReader},
	}
	for _, tt := range tests {
		got := ShareRightsToRole(tt.rights)
		if got != tt.expect {
			t.Errorf("ShareRightsToRole(%q) = %q, want %q", tt.rights, got, tt.expect)
		}
	}
}

func TestNormalizeACLRights(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rights string
		want   string
	}{
		{name: "modern full set", rights: "aetxkpiwsrl", want: RightAll},
		{name: "obsolete create", rights: "lc", want: "lk"},
		{name: "obsolete delete", rights: "ld", want: "lxte"},
		{name: "k is not all", rights: "k", want: "k"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeACLRights(tt.rights); got != tt.want {
				t.Fatalf("NormalizeACLRights(%q) = %q, want %q", tt.rights, got, tt.want)
			}
		})
	}
	if HasACLRights("k", RightRead) {
		t.Fatal("RFC 4314 create-mailbox right k unexpectedly implied read")
	}
}

func TestFolderStoreSetAndGetCalendarSharing(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	// Create a calendar folder
	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share with bob as reader
	if err := fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareReader); err != nil {
		t.Fatalf("set sharing: %v", err)
	}

	// Get the sharing role
	role, err := fs.GetCalendarSharing(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("get sharing: %v", err)
	}
	if role != ShareReader {
		t.Errorf("role = %q, want %q", role, ShareReader)
	}
}

func TestFolderStoreListCalendarSharing(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share with multiple users
	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareReader)
	fs.SetCalendarSharing(ctx, folder.ID, "charlie", ShareWriter)

	sharees, err := fs.ListCalendarSharing(ctx, folder.ID)
	if err != nil {
		t.Fatalf("list sharing: %v", err)
	}

	if len(sharees) != 2 {
		t.Fatalf("expected 2 sharees, got %d", len(sharees))
	}

	// Check roles
	roles := make(map[string]string)
	for _, s := range sharees {
		roles[s.UserID] = s.Role
	}
	if roles["bob"] != ShareReader {
		t.Errorf("bob role = %q, want %q", roles["bob"], ShareReader)
	}
	if roles["charlie"] != ShareWriter {
		t.Errorf("charlie role = %q, want %q", roles["charlie"], ShareWriter)
	}
}

func TestFolderStoreDeleteCalendarSharing(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareReader)

	// Delete sharing
	if err := fs.DeleteCalendarSharing(ctx, folder.ID, "bob"); err != nil {
		t.Fatalf("delete sharing: %v", err)
	}

	// Verify it's gone
	_, err = fs.GetCalendarSharing(ctx, folder.ID, "bob")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestFolderStoreGetShareInfo(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareWriter)

	info, err := fs.GetShareInfo(ctx, folder.ID)
	if err != nil {
		t.Fatalf("get share info: %v", err)
	}

	if info.OwnerID != "alice" {
		t.Errorf("owner = %q, want %q", info.OwnerID, "alice")
	}
	if info.FolderID != folder.ID {
		t.Errorf("folderID = %q, want %q", info.FolderID, folder.ID)
	}
	if len(info.Sharees) != 1 {
		t.Fatalf("expected 1 sharee, got %d", len(info.Sharees))
	}
	if info.Sharees[0].UserID != "bob" {
		t.Errorf("sharee = %q, want %q", info.Sharees[0].UserID, "bob")
	}
}

func TestFolderStoreIsSharedCalendar(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Initially not shared
	shared, err := fs.IsSharedCalendar(ctx, folder.ID)
	if err != nil {
		t.Fatalf("is shared: %v", err)
	}
	if shared {
		t.Error("calendar should not be shared initially")
	}

	// After sharing
	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareReader)
	shared, err = fs.IsSharedCalendar(ctx, folder.ID)
	if err != nil {
		t.Fatalf("is shared after grant: %v", err)
	}
	if !shared {
		t.Error("calendar should be shared after grant")
	}
}

func TestFolderStoreCanAccessCalendar(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Owner can always access
	canAccess, err := fs.CanAccessCalendar(ctx, folder.ID, "alice")
	if err != nil {
		t.Fatalf("can access (owner): %v", err)
	}
	if !canAccess {
		t.Error("owner should always have access")
	}

	// Non-shared user cannot access
	canAccess, err = fs.CanAccessCalendar(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("can access (non-shared): %v", err)
	}
	if canAccess {
		t.Error("non-shared user should not have access")
	}

	// After sharing, bob can access
	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareReader)
	canAccess, err = fs.CanAccessCalendar(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("can access (shared): %v", err)
	}
	if !canAccess {
		t.Error("shared user should have access")
	}
}

func TestFolderStoreUpdateCalendarSharingRole(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	fs := NewFolderStore(ts)
	ctx := context.Background()

	fs.CreateForUser(ctx, "alice")
	folder, err := fs.GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Start as reader
	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareReader)
	role, _ := fs.GetCalendarSharing(ctx, folder.ID, "bob")
	if role != ShareReader {
		t.Errorf("initial role = %q, want %q", role, ShareReader)
	}

	// Upgrade to writer
	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareWriter)
	role, _ = fs.GetCalendarSharing(ctx, folder.ID, "bob")
	if role != ShareWriter {
		t.Errorf("updated role = %q, want %q", role, ShareWriter)
	}

	// Upgrade to owner
	fs.SetCalendarSharing(ctx, folder.ID, "bob", ShareOwner)
	role, _ = fs.GetCalendarSharing(ctx, folder.ID, "bob")
	if role != ShareOwner {
		t.Errorf("final role = %q, want %q", role, ShareOwner)
	}
}
