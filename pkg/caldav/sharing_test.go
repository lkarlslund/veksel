package caldav

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestCalendarSharingSetAndGet(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share alice's calendar with bob as reader
	if err := ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareReader); err != nil {
		t.Fatalf("set sharing: %v", err)
	}

	// Verify via PROPFIND that the calendar shows as shared
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:resourcetype/>
 <D:acl/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/Calendar/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain shared-calendar resource type
	if !strings.Contains(respBody, "shared-calendar") {
		t.Errorf("PROPFIND: body should contain shared-calendar: %s", respBody)
	}
	// Should contain acl property
	if !strings.Contains(respBody, "acl") {
		t.Errorf("PROPFIND: body should contain acl: %s", respBody)
	}
}

func TestCalendarSharingWriter(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share as writer
	if err := ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareWriter); err != nil {
		t.Fatalf("set sharing: %v", err)
	}

	// Verify role
	role, err := ts.FolderStore().GetCalendarSharing(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("get sharing: %v", err)
	}
	if role != model.ShareWriter {
		t.Errorf("role = %q, want %q", role, model.ShareWriter)
	}

	// Check ACL rights
	rights, err := ts.FolderStore().GetUserRights(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("get user rights: %v", err)
	}
	if rights != "lrw" {
		t.Errorf("rights = %q, want %q", rights, "lrw")
	}
}

func TestCalendarSharingOwner(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share as owner
	if err := ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareOwner); err != nil {
		t.Fatalf("set sharing: %v", err)
	}

	// Check ACL rights
	rights, err := ts.FolderStore().GetUserRights(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("get user rights: %v", err)
	}
	if rights != model.RightAll {
		t.Errorf("rights = %q, want %q", rights, model.RightAll)
	}
}

func TestCalendarSharingRemove(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share then remove
	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareReader)
	ts.FolderStore().DeleteCalendarSharing(ctx, folder.ID, "bob")

	// Verify removed
	_, err = ts.FolderStore().GetCalendarSharing(ctx, folder.ID, "bob")
	if err == nil {
		t.Error("expected error after removing sharing")
	}

	// Calendar should no longer be shared
	shared, err := ts.FolderStore().IsSharedCalendar(ctx, folder.ID)
	if err != nil {
		t.Fatalf("is shared: %v", err)
	}
	if shared {
		t.Error("calendar should not be shared after removal")
	}
}

func TestCalendarSharingMultipleUsers(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")
	testUser(t, ts, "charlie", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share with multiple users
	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareReader)
	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "charlie", model.ShareWriter)

	sharees, err := ts.FolderStore().ListCalendarSharing(ctx, folder.ID)
	if err != nil {
		t.Fatalf("list sharing: %v", err)
	}

	if len(sharees) != 2 {
		t.Fatalf("expected 2 sharees, got %d", len(sharees))
	}

	// Verify sharees
	roles := make(map[string]string)
	for _, s := range sharees {
		roles[s.UserID] = s.Role
	}

	if roles["bob"] != model.ShareReader {
		t.Errorf("bob role = %q, want %q", roles["bob"], model.ShareReader)
	}
	if roles["charlie"] != model.ShareWriter {
		t.Errorf("charlie role = %q, want %q", roles["charlie"], model.ShareWriter)
	}
}

func TestCalendarSharingACLResponse(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share with bob
	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareReader)

	// PROPFIND with acl property
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:acl/>
 <D:owner/>
 <D:supported-privilege-set/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/Calendar/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain principal href for bob
	if !strings.Contains(respBody, "bob") {
		t.Errorf("PROPFIND ACL should contain bob: %s", respBody)
	}
	// Should contain read privilege
	if !strings.Contains(respBody, "read") {
		t.Errorf("PROPFIND ACL should contain read privilege: %s", respBody)
	}
}

func TestCalendarSharingCanAccess(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Owner can access
	canAccess, err := ts.FolderStore().CanAccessCalendar(ctx, folder.ID, "alice")
	if err != nil {
		t.Fatalf("can access: %v", err)
	}
	if !canAccess {
		t.Error("owner should have access")
	}

	// Bob cannot access yet
	canAccess, err = ts.FolderStore().CanAccessCalendar(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("can access: %v", err)
	}
	if canAccess {
		t.Error("bob should not have access before sharing")
	}

	// Share with bob
	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareReader)

	// Bob can now access
	canAccess, err = ts.FolderStore().CanAccessCalendar(ctx, folder.ID, "bob")
	if err != nil {
		t.Fatalf("can access after sharing: %v", err)
	}
	if !canAccess {
		t.Error("bob should have access after sharing")
	}
}

func TestCalendarSharingShareInfo(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareWriter)

	info, err := ts.FolderStore().GetShareInfo(ctx, folder.ID)
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
	if info.Sharees[0].Role != model.ShareWriter {
		t.Errorf("sharee role = %q, want %q", info.Sharees[0].Role, model.ShareWriter)
	}
}

func TestBuildACLEntries(t *testing.T) {
	t.Parallel()
	sharees := []model.Sharee{
		{UserID: "bob", Role: model.ShareReader},
		{UserID: "charlie", Role: model.ShareWriter},
	}

	aces := buildACLEntries("alice", sharees)

	// Should have 3 ACEs: owner + 2 sharees
	if len(aces) != 3 {
		t.Fatalf("expected 3 ACEs, got %d", len(aces))
	}

	// Owner ACE should have all privilege
	if aces[0].Privilege.All == nil {
		t.Error("owner ACE should have all privilege")
	}

	// Bob ACE should have read privilege
	if aces[1].Privilege.Read == nil {
		t.Error("bob ACE should have read privilege")
	}

	// Charlie ACE should have write privilege
	if aces[2].Privilege.Write == nil {
		t.Error("charlie ACE should have write privilege")
	}
}

func TestCalendarSharingPROPFINDNonShared(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PROPFIND on a non-shared calendar
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:resourcetype/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/Calendar/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	// Should NOT contain shared-calendar for non-shared calendar
	if strings.Contains(respBody, "shared-calendar") {
		t.Errorf("PROPFIND should not contain shared-calendar for non-shared calendar: %s", respBody)
	}
	// Should contain calendar resource type
	if !strings.Contains(respBody, "calendar") {
		t.Errorf("PROPFIND should contain calendar: %s", respBody)
	}
}

func TestListACLForUser(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	testUser(t, ts, "bob", "pass123")

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get calendar: %v", err)
	}

	// Share with bob
	ts.FolderStore().SetCalendarSharing(ctx, folder.ID, "bob", model.ShareReader)

	// List ACLs for bob
	acls, err := ts.FolderStore().ListACLForUser(ctx, "bob")
	if err != nil {
		t.Fatalf("list ACL for user: %v", err)
	}

	if len(acls) != 1 {
		t.Fatalf("expected 1 ACL entry for bob, got %d", len(acls))
	}

	if _, ok := acls[folder.ID]; !ok {
		t.Errorf("expected ACL entry for folder %q", folder.ID)
	}
}
