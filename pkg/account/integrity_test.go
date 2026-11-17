package account

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestManagerCheckDetectsAndRepairsQuotaTruth(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := typed.ItemStore().Append(t.Context(), inbox.ID, []byte("message"), nil); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().Update(t.Context(), "alice", func(user *model.User) {
		user.CurrentItems = 0
		user.CurrentStorageBytes = 0
	}); err != nil {
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || len(report.Issues) != 1 || report.Issues[0].Code != "quota_usage_mismatch" {
		t.Fatalf("verification report = %+v", report)
	}
	repaired, err := manager.Check(t.Context(), "alice", true)
	if err != nil || !repaired.Healthy || repaired.Repaired != 1 {
		t.Fatalf("repair report = %+v, %v", repaired, err)
	}
	final, err := manager.Check(t.Context(), "alice", false)
	if err != nil || !final.Healthy {
		t.Fatalf("final report = %+v, %v", final, err)
	}
}

func TestManagerCheckRepairsFolderUsageMetadata(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := typed.ItemStore().Append(t.Context(), inbox.ID, []byte("message"), nil); err != nil {
		t.Fatal(err)
	}
	inbox.ItemCount = 0
	inbox.LogicalBytes = 0
	inbox.UsageVersion = 0
	if err := typed.Set(t.Context(), model.NSFolders, inbox.ID, inbox); err != nil {
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", false)
	if err != nil || countIntegrityCode(report.Issues, "folder_usage_mismatch") != 1 {
		t.Fatalf("verification report = %+v, %v", report, err)
	}
	repaired, err := manager.Check(t.Context(), "alice", true)
	if err != nil || !repaired.Healthy || countIntegrityCode(repaired.Issues, "folder_usage_mismatch") != 1 {
		t.Fatalf("repair report = %+v, %v", repaired, err)
	}
}

func TestManagerCheckAccountsForAndRepairsHistoryMetadata(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("history")})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err = typed.FolderStore().Get(t.Context(), inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	inbox.History = model.ItemHistoryPolicy{Enabled: true, RetentionDays: 30, MaxVersions: 10}
	if err := typed.Set(t.Context(), model.NSFolders, inbox.ID, inbox); err != nil {
		t.Fatal(err)
	}
	if _, captured, err := typed.ItemHistoryStore().Capture(t.Context(), item, model.ItemHistoryUpdate); err != nil || !captured {
		t.Fatalf("capture history: captured=%t err=%v", captured, err)
	}
	inbox, err = typed.FolderStore().Get(t.Context(), inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	inbox.HistoryVersionCount = 0
	inbox.HistoryLogicalBytes = 0
	inbox.HistoryUsageVersion = 0
	if err := typed.Set(t.Context(), model.NSFolders, inbox.ID, inbox); err != nil {
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", false)
	if err != nil || report.HistoryVersions != 1 || report.HistoryLogicalBytes != item.Size || countIntegrityCode(report.Issues, "folder_history_usage_mismatch") != 1 {
		t.Fatalf("verification report = %+v, %v", report, err)
	}
	repaired, err := manager.Check(t.Context(), "alice", true)
	if err != nil || !repaired.Healthy || countIntegrityCode(repaired.Issues, "folder_history_usage_mismatch") != 1 {
		t.Fatalf("repair report = %+v, %v", repaired, err)
	}
}

func TestManagerCheckRepairsDerivedItemIndexes(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{
		Data:         []byte("Subject: indexed\r\n\r\nbody"),
		InternalDate: now,
		ExternalIDs:  map[string]string{"migration": "remote-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err = typed.ItemStore().Trash(t.Context(), item.ID, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	missing := []string{
		model.ItemMemberKey(item.FolderID, item.ID),
		model.ItemNameKey(item.FolderID, item.Name),
		model.ExternalItemIndexKey(item.FolderID, "migration", "remote-1"),
		model.TrashedItemKey("alice", item.ID),
	}
	for _, key := range missing {
		if err := typed.Delete(t.Context(), model.NSItems, key); err != nil {
			t.Fatal(err)
		}
	}
	uidKey := model.UIDIndexKey(item.FolderID, item.UID)
	if err := typed.Set(t.Context(), model.NSItems, uidKey, "itm_missing"); err != nil {
		t.Fatal(err)
	}
	orphanKey := model.DateIndexKey(item.FolderID, "19990101", "itm_missing")
	if err := typed.Set(t.Context(), model.NSItems, orphanKey, "itm_missing"); err != nil {
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || countIntegrityCode(report.Issues, "item_index_missing") != len(missing) || countIntegrityCode(report.Issues, "item_index_mismatch") != 1 || countIntegrityCode(report.Issues, "item_index_orphan") != 1 {
		t.Fatalf("verification report = %+v", report)
	}
	repaired, err := manager.Check(t.Context(), "alice", true)
	if err != nil || !repaired.Healthy || repaired.Repaired != len(missing)+2 {
		t.Fatalf("repair report = %+v, %v", repaired, err)
	}

	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	typed = model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	for _, key := range append(missing, uidKey) {
		var target string
		if err := typed.Get(t.Context(), model.NSItems, key, &target); err != nil || target != item.ID {
			t.Fatalf("index %s target=%q err=%v", key, target, err)
		}
	}
	var orphan string
	if err := typed.Get(t.Context(), model.NSItems, orphanKey, &orphan); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("orphan index still present: target=%q err=%v", orphan, err)
	}
}

func TestManagerCheckDetectsFolderGraphCorruptionWithoutRewritingPrimaryRecords(t *testing.T) {
	manager := newIntegrityTestManager(t, store.BackendPebble)
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	folders := typed.FolderStore()
	if err := folders.Create(t.Context(), "alice", "Projects", model.FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	projects, err := folders.GetByPath(t.Context(), "alice", "Projects")
	if err != nil {
		t.Fatal(err)
	}
	if err := folders.Create(t.Context(), "alice", "Projects/Child", model.FolderTypeMail, projects.ID); err != nil {
		t.Fatal(err)
	}
	child, err := folders.GetByPath(t.Context(), "alice", "Projects/Child")
	if err != nil {
		t.Fatal(err)
	}
	projects.ParentID = child.ID
	child.Type = model.FolderTypeCalendar
	if err := typed.Set(t.Context(), model.NSFolders, projects.ID, projects); err != nil {
		t.Fatal(err)
	}
	if err := typed.Set(t.Context(), model.NSFolders, child.ID, child); err != nil {
		t.Fatal(err)
	}

	archive, err := folders.GetByPath(t.Context(), "alice", "Archive")
	if err != nil {
		t.Fatal(err)
	}
	archive.Name = "Wrong"
	if err := typed.Set(t.Context(), model.NSFolders, archive.ID, archive); err != nil {
		t.Fatal(err)
	}
	drafts, err := folders.GetByPath(t.Context(), "alice", "Drafts")
	if err != nil {
		t.Fatal(err)
	}
	sent, err := folders.GetByPath(t.Context(), "alice", "Sent")
	if err != nil {
		t.Fatal(err)
	}
	sent.Name, sent.Path = drafts.Name, drafts.Path
	if err := typed.Set(t.Context(), model.NSFolders, sent.ID, sent); err != nil {
		t.Fatal(err)
	}
	junk, err := folders.GetByPath(t.Context(), "alice", "Junk")
	if err != nil {
		t.Fatal(err)
	}
	junk.ParentID = "fld_missing"
	if err := typed.Set(t.Context(), model.NSFolders, junk.ID, junk); err != nil {
		t.Fatal(err)
	}
	foreign := model.Folder{ID: "fld_foreign", UserID: "bob", Name: "Foreign", Path: "Foreign", Type: model.FolderTypeMail}
	if err := typed.Set(t.Context(), model.NSFolders, foreign.ID, foreign); err != nil {
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	for code, want := range map[string]int{
		"folder_owner_mismatch":       1,
		"folder_path_invalid":         1,
		"folder_path_collision":       1,
		"missing_folder_parent":       1,
		"folder_parent_type_mismatch": 2,
		"folder_parent_cycle":         1,
	} {
		if got := countIntegrityCode(report.Issues, code); got != want {
			t.Errorf("%s findings = %d, want %d; report=%+v", code, got, want, report)
		}
	}
	if report.Healthy {
		t.Fatalf("corrupt folder graph reported healthy: %+v", report)
	}
	repaired, err := manager.Check(t.Context(), "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.Healthy || repaired.Repaired == 0 {
		t.Fatalf("repair should reconcile indexes but retain primary findings: %+v", repaired)
	}
	final, err := manager.Check(t.Context(), "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if countFolderIndexIssues(final.Issues) != 0 || countIntegrityCode(final.Issues, "folder_parent_cycle") != 1 {
		t.Fatalf("follow-up folder integrity = %+v", final)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	typed = model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	unchanged, err := typed.FolderStore().Get(t.Context(), projects.ID)
	if err != nil || unchanged.ParentID != child.ID {
		t.Fatalf("primary cycle was rewritten: folder=%+v err=%v", unchanged, err)
	}
	var ambiguousTarget string
	if err := typed.Get(t.Context(), model.NSFolderIndexes, model.FolderPathIndexKey("alice", drafts.Path), &ambiguousTarget); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ambiguous path index remains as %q: %v", ambiguousTarget, err)
	}
}

func TestManagerCheckReportsUnreadableAndMismatchedFolderRecordsWithoutRewritingThem(t *testing.T) {
	manager := newIntegrityTestManager(t, store.BackendPebble)
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	mismatched := model.Folder{ID: "fld_embedded", UserID: "alice", Name: "Mismatched", Path: "Mismatched", Type: model.FolderTypeMail}
	if err := typed.Set(t.Context(), model.NSFolders, "fld_storage_key", mismatched); err != nil {
		release()
		t.Fatal(err)
	}
	if err := generation.Index.Set(t.Context(), model.NSFolders, "fld_unreadable", []byte("{")); err != nil {
		release()
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || countIntegrityCode(report.Issues, "folder_identity_mismatch") != 1 || countIntegrityCode(report.Issues, "folder_record_unreadable") != 1 {
		t.Fatalf("primary record diagnostics = %+v", report)
	}

	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	typed = model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	var retained model.Folder
	if err := typed.Get(t.Context(), model.NSFolders, "fld_storage_key", &retained); err != nil || retained.ID != mismatched.ID {
		t.Fatalf("mismatched primary record was rewritten: %+v, %v", retained, err)
	}
	if raw, err := generation.Index.Get(t.Context(), model.NSFolders, "fld_unreadable"); err != nil || string(raw) != "{" {
		t.Fatalf("unreadable primary record was rewritten: %q, %v", raw, err)
	}
}

func TestManagerCheckRepairsFolderIndexEntriesIdempotently(t *testing.T) {
	manager := newIntegrityTestManager(t, store.BackendPebble)
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := typed.FolderStore().GetByPath(t.Context(), "alice", "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if err := typed.Delete(t.Context(), model.NSFolderIndexes, model.FolderUserIndexKey("alice", inbox.ID)); err != nil {
		t.Fatal(err)
	}
	if err := typed.Set(t.Context(), model.NSFolderIndexes, model.FolderPathIndexKey("alice", archive.Path), "fld_missing"); err != nil {
		t.Fatal(err)
	}
	orphanUser := model.FolderUserIndexKey("alice", "fld_orphan")
	orphanPath := model.FolderPathIndexKey("alice", "Ghost")
	if err := typed.Set(t.Context(), model.NSFolderIndexes, orphanUser, "fld_orphan"); err != nil {
		t.Fatal(err)
	}
	if err := typed.Set(t.Context(), model.NSFolderIndexes, orphanPath, "fld_orphan"); err != nil {
		t.Fatal(err)
	}
	if err := typed.Set(t.Context(), model.NSFolderIndexes, model.FolderIndexMarkerKey("alice"), 0); err != nil {
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", false)
	if err != nil || report.Healthy || countIntegrityCode(report.Issues, "folder_index_missing") != 1 || countIntegrityCode(report.Issues, "folder_index_mismatch") != 1 || countIntegrityCode(report.Issues, "folder_index_orphan") != 2 || countIntegrityCode(report.Issues, "folder_index_version_mismatch") != 1 {
		t.Fatalf("folder index verification = %+v, %v", report, err)
	}
	repaired, err := manager.Check(t.Context(), "alice", true)
	if err != nil || !repaired.Healthy || repaired.Repaired != 5 {
		t.Fatalf("folder index repair = %+v, %v", repaired, err)
	}
	final, err := manager.Check(t.Context(), "alice", false)
	if err != nil || !final.Healthy || len(final.Issues) != 0 {
		t.Fatalf("idempotent folder index verification = %+v, %v", final, err)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	typed = model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	if resolved, err := typed.FolderStore().GetByPath(t.Context(), "alice", "Archive"); err != nil || resolved.ID != archive.ID {
		t.Fatalf("ordinary FolderStore path lookup after repair = %+v, %v", resolved, err)
	}
	for _, key := range []string{orphanUser, orphanPath} {
		var value string
		if err := typed.Get(t.Context(), model.NSFolderIndexes, key, &value); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("orphan %s remains as %q: %v", key, value, err)
		}
	}
}

func TestManagerCheckDoesNotDowngradeUnknownFolderIndexVersion(t *testing.T) {
	manager := newIntegrityTestManager(t, store.BackendPebble)
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	future := model.FolderIndexVersion + 1
	if err := typed.Set(t.Context(), model.NSFolderIndexes, model.FolderIndexMarkerKey("alice"), future); err != nil {
		release()
		t.Fatal(err)
	}
	release()

	report, err := manager.Check(t.Context(), "alice", true)
	if err != nil || report.Healthy || report.Repaired != 0 || countIntegrityCode(report.Issues, "folder_index_version_unsupported") != 1 {
		t.Fatalf("future folder index report = %+v, %v", report, err)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	typed = model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	var retained int
	if err := typed.Get(t.Context(), model.NSFolderIndexes, model.FolderIndexMarkerKey("alice"), &retained); err != nil || retained != future {
		t.Fatalf("future marker changed to %d: %v", retained, err)
	}
}

func TestManagerCheckRebuildsMissingFolderIndexNamespaceAcrossBackends(t *testing.T) {
	for _, backend := range []store.Backend{store.BackendPebble, store.BackendBadger} {
		t.Run(string(backend), func(t *testing.T) {
			manager := newIntegrityTestManager(t, backend)
			generation, release, err := manager.Acquire("alice")
			if err != nil {
				t.Fatal(err)
			}
			if err := generation.Index.DeleteNamespace(t.Context(), model.NSFolderIndexes); err != nil {
				release()
				t.Fatal(err)
			}
			release()

			report, err := manager.Check(t.Context(), "alice", false)
			if err != nil || report.Healthy || countIntegrityCode(report.Issues, "folder_index_namespace_missing") != 1 {
				t.Fatalf("missing namespace verification = %+v, %v", report, err)
			}
			repaired, err := manager.Check(t.Context(), "alice", true)
			if err != nil || !repaired.Healthy || repaired.Repaired != 1 {
				t.Fatalf("namespace repair = %+v, %v", repaired, err)
			}
			final, err := manager.Check(t.Context(), "alice", false)
			if err != nil || !final.Healthy {
				t.Fatalf("namespace recheck = %+v, %v", final, err)
			}
			generation, release, err = manager.Acquire("alice")
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
			if _, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX"); err != nil {
				t.Fatalf("FolderStore lookup after namespace rebuild: %v", err)
			}
		})
	}
}

func newIntegrityTestManager(t *testing.T, backend store.Backend) *Manager {
	t.Helper()
	manager, err := NewManager(t.TempDir(), backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	return manager
}

func countFolderIndexIssues(issues []IntegrityIssue) int {
	count := 0
	for _, issue := range issues {
		if strings.HasPrefix(issue.Code, "folder_index_") {
			count++
		}
	}
	return count
}

func countIntegrityCode(issues []IntegrityIssue, code string) int {
	count := 0
	for _, issue := range issues {
		if issue.Code == code {
			count++
		}
	}
	return count
}

func TestIntegrityLifecycleJobPersistsProgressAndReport(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	job, err := manager.StartIntegrityCheck("alice", true)
	if err != nil || job.Operation != LifecycleRepair || job.Phase != LifecycleQueued {
		t.Fatalf("start repair job = %+v, %v", job, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, listErr := manager.LifecycleJobs("alice")
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, candidate := range jobs {
			if candidate.ID != job.ID || candidate.Phase != LifecycleCompleted {
				continue
			}
			job = candidate
			goto completed
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("integrity job did not complete: %+v", job)

completed:
	if job.ReportID == "" || job.Integrity == nil || job.Integrity.FoldersScanned != job.Integrity.FoldersTotal || job.Integrity.ItemsScanned != job.Integrity.ItemsTotal {
		t.Fatalf("completed integrity job = %+v", job)
	}
	report, err := manager.IntegrityReport("alice", job.ReportID)
	if err != nil || !report.Healthy || !report.Repair {
		t.Fatalf("integrity report = %+v, %v", report, err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	jobs, err := reopened.LifecycleJobs("alice")
	if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID || jobs[0].Phase != LifecycleCompleted {
		t.Fatalf("reopened jobs = %+v, %v", jobs, err)
	}
	if _, err := reopened.IntegrityReport("alice", job.ReportID); err != nil {
		t.Fatalf("reopened integrity report: %v", err)
	}
}
