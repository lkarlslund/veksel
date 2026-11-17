package service

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type complianceFixture struct {
	ts         *model.TypedStore
	space      *FolderSpaceService
	compliance *Compliance
	alice      AccessContext
	inbox      model.Folder
	archive    model.Folder
	trash      model.Folder
}

func newComplianceFixture(t *testing.T) complianceFixture {
	t.Helper()
	_, ts, _ := testMailService(t)
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	compliance, err := NewCompliance(t.Context(), ts)
	if err != nil {
		t.Fatal(err)
	}
	space := NewFolderSpace(ts, authz.New(ts))
	space.SetLegalHolds(compliance)
	alice := UserAccess("alice", "imap")
	fixture := complianceFixture{ts: ts, space: space, compliance: compliance, alice: alice}
	for path, target := range map[string]*model.Folder{"INBOX": &fixture.inbox, "Archive": &fixture.archive, "Trash": &fixture.trash} {
		folder, err := space.GetFolderByPath(t.Context(), alice, path)
		if err != nil {
			t.Fatal(err)
		}
		*target = folder
	}
	return fixture
}

func (f complianceFixture) message(t *testing.T, folderID, subject string, received time.Time) model.Item {
	t.Helper()
	item, err := f.space.CreateItem(t.Context(), f.alice, folderID, ItemInput{
		Data:         []byte("From: Carol <carol@example.net>\r\nTo: alice@example.test\r\nSubject: " + subject + "\r\n\r\nquarterly merger figures " + subject),
		InternalDate: received,
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func (f complianceFixture) hold(t *testing.T, scope, target string) LegalHold {
	t.Helper()
	hold, err := f.compliance.PlaceHold(t.Context(), LegalHold{Scope: scope, Target: target, Reason: "litigation", CaseID: "CASE-7", CreatedBy: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	return hold
}

func TestRetentionPolicyPrecedence(t *testing.T) {
	f := newComplianceFixture(t)
	put := func(policy RetentionPolicy) RetentionPolicy {
		t.Helper()
		stored, err := f.compliance.PutPolicy(t.Context(), policy)
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	installation := put(RetentionPolicy{Scope: RetentionScopeInstallation, Action: RetentionActionDelete, Days: 3650})
	installationInbox := put(RetentionPolicy{Scope: RetentionScopeInstallation, SpecialUse: model.SpecialUseInbox, Action: RetentionActionArchive, Days: 365})
	domain := put(RetentionPolicy{Scope: RetentionScopeDomain, Target: "example.test", Action: RetentionActionDelete, Days: 730})
	domainPattern := put(RetentionPolicy{Scope: RetentionScopeDomain, Target: "example.test", Pattern: "Projects/**", Action: RetentionActionDelete, Days: 90})
	account := put(RetentionPolicy{Scope: RetentionScopeAccount, Target: "alice", SpecialUse: model.SpecialUseSent, Action: RetentionActionDelete, Days: 30})

	folder := func(path, specialUse string) model.Folder {
		return model.Folder{Path: path, SpecialUse: specialUse, Type: model.FolderTypeMail}
	}
	for _, test := range []struct {
		name, account, domain string
		folder                model.Folder
		want                  string
	}{
		{"account special use wins", "alice", "example.test", folder("Sent", model.SpecialUseSent), account.ID},
		{"domain pattern beats domain-wide", "alice", "example.test", folder("Projects/Alpha", ""), domainPattern.ID},
		{"domain beats installation special use", "alice", "example.test", folder("INBOX", model.SpecialUseInbox), domain.ID},
		{"installation special use outside domain", "bob", "other.test", folder("INBOX", model.SpecialUseInbox), installationInbox.ID},
		{"installation default", "bob", "other.test", folder("Notes", ""), installation.ID},
		{"other account falls back to domain", "bob", "example.test", folder("Sent", model.SpecialUseSent), domain.ID},
	} {
		got, ok := f.compliance.EffectivePolicy(test.account, test.domain, test.folder)
		if !ok || got.ID != test.want {
			t.Errorf("%s: effective = %+v ok=%t, want %s", test.name, got, ok, test.want)
		}
	}
	if _, ok := f.compliance.EffectivePolicy("alice", "example.test", model.Folder{Path: "Calendar", Type: model.FolderTypeCalendar}); ok {
		t.Error("a non-mail folder received a retention policy")
	}
	for _, invalid := range []RetentionPolicy{
		{Scope: RetentionScopeInstallation, Action: RetentionActionDelete, Days: 0},
		{Scope: RetentionScopeDomain, Action: RetentionActionDelete, Days: 10},
		{Scope: RetentionScopeInstallation, Action: "shred", Days: 10},
		{Scope: RetentionScopeInstallation, SpecialUse: model.SpecialUseArchive, Action: RetentionActionArchive, Days: 10},
		{Scope: RetentionScopeInstallation, SpecialUse: model.SpecialUseDrafts, Action: RetentionActionDelete, Days: 10},
		{Scope: RetentionScopeDomain, Target: "missing.test", Action: RetentionActionDelete, Days: 10},
	} {
		if _, err := f.compliance.PutPolicy(t.Context(), invalid); err == nil {
			t.Errorf("invalid policy %+v accepted", invalid)
		}
	}
}

func TestLegalHoldPreservesUserDeletionsAndHidesThem(t *testing.T) {
	f := newComplianceFixture(t)
	item := f.message(t, f.inbox.ID, "evidence", time.Now())
	state, err := f.space.CurrentChangeState(t.Context(), f.alice, ChangeScope{Object: ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	f.hold(t, HoldScopeAccount, "alice")

	if err := f.space.DeleteItem(t.Context(), f.alice, item.ID); err != nil {
		t.Fatalf("held delete: %v", err)
	}
	if _, err := f.space.GetItem(t.Context(), f.alice, item.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user still reads a held-deleted item: %v", err)
	}
	if items, err := f.space.ListItems(t.Context(), f.alice, f.inbox.ID, ItemQuery{}); err != nil || len(items) != 0 {
		t.Fatalf("inbox after held delete = %d items, err=%v", len(items), err)
	}
	folders, err := f.space.ListFolders(t.Context(), f.alice, FolderQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, folder := range folders {
		if model.IsHeldDeletedFolder(folder) {
			t.Fatalf("user sees held-deleted folder %+v", folder)
		}
	}
	heldID := model.HeldDeletedFolderID("alice", model.FolderTypeMail)
	if _, err := f.space.GetFolder(t.Context(), f.alice, heldID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user resolves the held folder: %v", err)
	}
	if _, err := f.space.ListItems(t.Context(), f.alice, heldID, ItemQuery{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user lists the held folder: %v", err)
	}
	if _, err := f.space.CreateItem(t.Context(), f.alice, heldID, ItemInput{Data: []byte("x")}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user writes into the held folder: %v", err)
	}
	page, err := f.space.ListChanges(t.Context(), f.alice, ChangeScope{Object: ChangeObjectItem}, state, 50)
	if err != nil {
		t.Fatal(err)
	}
	var operations []ChangeOperation
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.FolderID == heldID {
				t.Fatalf("user change feed exposes the held folder: %+v", change)
			}
			operations = append(operations, change.Operation)
		}
	}
	if len(operations) != 1 || operations[0] != ChangeDestroy {
		t.Fatalf("user change feed = %v, want one destroy", operations)
	}

	officer := ComplianceAccess("alice")
	preserved, err := f.space.GetItem(t.Context(), officer, item.ID)
	if err != nil || preserved.HeldDeletedAt.IsZero() || preserved.HeldDeletedFrom != "INBOX" || !bytes.Equal(preserved.Data, item.Data) {
		t.Fatalf("compliance read = %+v err=%v", preserved, err)
	}
	held, err := f.space.ListItems(t.Context(), officer, heldID, ItemQuery{})
	if err != nil || len(held) != 1 {
		t.Fatalf("compliance held listing = %d err=%v", len(held), err)
	}
	if err := f.space.DeleteItem(t.Context(), officer, item.ID); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("compliance destroyed a held item: %v", err)
	}
	if err := f.space.DeleteItem(t.Context(), UserAccess("alice", ProtocolRetention), f.message(t, f.inbox.ID, "other", time.Now()).ID); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("retention deletion under hold = %v", err)
	}
}

func TestDomainHoldCoversOnlyAccountsWhosePrimaryIdentityIsInTheDomain(t *testing.T) {
	f := newComplianceFixture(t)
	users := f.ts.UserStore()
	if err := f.ts.DomainStore().Create(t.Context(), "tenant.test"); err != nil {
		t.Fatal(err)
	}
	if err := users.Create(t.Context(), "carol", "Carol", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := users.AddEmailAddress(t.Context(), "carol@tenant.test", "carol", "tenant.test", true); err != nil {
		t.Fatal(err)
	}
	// An alias in example.test does not put another tenant's account under
	// example.test's holds.
	if err := users.AddEmailAddress(t.Context(), "carol.alias@example.test", "carol", "example.test", false); err != nil {
		t.Fatal(err)
	}
	f.hold(t, HoldScopeDomain, "example.test")
	if holds := f.compliance.HoldsFor(t.Context(), "alice"); len(holds) != 1 {
		t.Fatalf("member holds = %+v", holds)
	}
	if holds := f.compliance.HoldsFor(t.Context(), "carol"); len(holds) != 0 {
		t.Fatalf("aliased account holds = %+v", holds)
	}
	f.hold(t, HoldScopeDomain, "tenant.test")
	if holds := f.compliance.HoldsFor(t.Context(), "carol"); len(holds) != 1 || holds[0].Target != "tenant.test" {
		t.Fatalf("own domain holds = %+v", holds)
	}
}

func TestLegalHoldBlocksTrashPurgeAndFolderPurge(t *testing.T) {
	f := newComplianceFixture(t)
	trashed := f.message(t, f.inbox.ID, "trash me", time.Now())
	if _, err := f.space.TrashItem(t.Context(), f.alice, trashed.ID); err != nil {
		t.Fatal(err)
	}
	project, err := f.space.CreateFolder(t.Context(), f.alice, "Project", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	inProject := f.message(t, project.ID, "project", time.Now())
	if err := f.space.DeleteFolder(t.Context(), f.alice, project.ID); err != nil {
		t.Fatal(err)
	}
	f.hold(t, HoldScopeDomain, "example.test")

	if err := f.space.DeleteItem(t.Context(), f.alice, trashed.ID); err != nil {
		t.Fatalf("trash purge under hold: %v", err)
	}
	if trash, err := f.space.ListTrash(t.Context(), f.alice); err != nil || len(trash) != 0 {
		t.Fatalf("trash after held purge = %+v err=%v", trash, err)
	}
	if err := f.space.PurgeFolder(t.Context(), f.alice, project.ID); err != nil {
		t.Fatalf("folder purge under hold: %v", err)
	}
	if _, err := f.space.folders.Get(t.Context(), project.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("purged folder remains: %v", err)
	}
	officer := ComplianceAccess("alice")
	for _, id := range []string{trashed.ID, inProject.ID} {
		item, err := f.space.GetItem(t.Context(), officer, id)
		if err != nil || item.HeldDeletedAt.IsZero() {
			t.Fatalf("item %s not preserved: %+v err=%v", id, item, err)
		}
	}
	if item, _ := f.space.GetItem(t.Context(), officer, inProject.ID); item.HeldDeletedFrom != "Project" {
		t.Fatalf("preserved origin = %q", item.HeldDeletedFrom)
	}
	if err := f.compliance.RequireAccountDeletable(t.Context(), "alice"); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("held account deletable: %v", err)
	}
	if err := f.compliance.RequireAccountDeletable(t.Context(), "nobody"); err != nil {
		t.Fatalf("unheld account refused: %v", err)
	}
}

func TestLegalHoldEndsAtReleaseOrEndDate(t *testing.T) {
	f := newComplianceFixture(t)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f.compliance.SetClock(func() time.Time { return now })
	if _, err := f.compliance.PlaceHold(t.Context(), LegalHold{Scope: HoldScopeAccount, Target: "alice"}); err == nil {
		t.Fatal("hold without reason or case accepted")
	}
	if _, err := f.compliance.PlaceHold(t.Context(), LegalHold{Scope: HoldScopeAccount, Target: "alice", Reason: "x", EndsAt: now.Add(-time.Hour)}); err == nil {
		t.Fatal("hold ending in the past accepted")
	}
	timed, err := f.compliance.PlaceHold(t.Context(), LegalHold{Scope: HoldScopeAccount, Target: "alice", Reason: "audit", EndsAt: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !f.compliance.AccountHeld(t.Context(), "alice") || f.compliance.AccountHeld(t.Context(), "bob") {
		t.Fatal("timed hold scope is wrong")
	}
	now = now.Add(25 * time.Hour)
	if f.compliance.AccountHeld(t.Context(), "alice") {
		t.Fatal("hold outlived its end date")
	}
	manual := f.hold(t, HoldScopeAccount, "alice")
	if _, err := f.compliance.ReleaseHold(t.Context(), manual.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if f.compliance.AccountHeld(t.Context(), "alice") {
		t.Fatal("released hold still applies")
	}
	reloaded, err := NewCompliance(t.Context(), f.ts)
	if err != nil {
		t.Fatal(err)
	}
	if holds := reloaded.ListHolds(); len(holds) != 2 || holds[0].ID == timed.ID && holds[0].ReleasedAt.IsZero() && holds[0].EndsAt.IsZero() {
		t.Fatalf("reloaded holds = %+v", holds)
	}
}

type recordingAudit struct {
	mu      sync.Mutex
	entries []map[string]string
	actions []string
}

func (a *recordingAudit) Log(_, action, _ string, details map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, action)
	a.entries = append(a.entries, details)
}

func TestRetentionJobDeletesAndArchivesByAgeWithInjectedClock(t *testing.T) {
	f := newComplianceFixture(t)
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	old := f.message(t, f.inbox.ID, "old", now.AddDate(0, 0, -40))
	fresh := f.message(t, f.inbox.ID, "fresh", now.AddDate(0, 0, -5))
	oldSent := f.message(t, model.SentFolderID("alice"), "old sent", now.AddDate(0, 0, -40))
	for _, policy := range []RetentionPolicy{
		{Scope: RetentionScopeAccount, Target: "alice", SpecialUse: model.SpecialUseInbox, Action: RetentionActionArchive, Days: 30},
		{Scope: RetentionScopeInstallation, SpecialUse: model.SpecialUseSent, Action: RetentionActionDelete, Days: 30},
	} {
		if _, err := f.compliance.PutPolicy(t.Context(), policy); err != nil {
			t.Fatal(err)
		}
	}
	audit := &recordingAudit{}
	job := NewRetentionJob(f.space, f.compliance, f.ts, audit, nil)
	job.Now, job.ActionDelay = func() time.Time { return now }, 0
	report, err := job.RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if report.Archived != 1 || report.Deleted != 1 || !report.Complete {
		t.Fatalf("report = %+v", report)
	}
	if moved, err := f.space.GetItem(t.Context(), f.alice, old.ID); err != nil || moved.FolderID != f.archive.ID {
		t.Fatalf("old inbox item = %+v err=%v", moved, err)
	}
	if kept, err := f.space.GetItem(t.Context(), f.alice, fresh.ID); err != nil || kept.FolderID != f.inbox.ID {
		t.Fatalf("fresh inbox item = %+v err=%v", kept, err)
	}
	if _, err := f.space.GetItem(t.Context(), ComplianceAccess("alice"), oldSent.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old sent item survived: %v", err)
	}
	if len(audit.actions) != 1 || audit.actions[0] != "retention.run" || audit.entries[0]["deleted"] != "1" || audit.entries[0]["archived"] != "1" {
		t.Fatalf("audit = %v %v", audit.actions, audit.entries)
	}
	if status := job.Status(t.Context()); status.TotalRuns != 1 || status.TotalDeleted != 1 || status.TotalArchived != 1 {
		t.Fatalf("status = %+v", status)
	}
}

func TestRetentionJobSkipsHeldAccountsThenPurgesAfterRelease(t *testing.T) {
	f := newComplianceFixture(t)
	now := time.Now().UTC()
	expired := f.message(t, f.inbox.ID, "expired", now.AddDate(0, 0, -100))
	deleted := f.message(t, f.inbox.ID, "deleted", now)
	if _, err := f.compliance.PutPolicy(t.Context(), RetentionPolicy{Scope: RetentionScopeInstallation, Action: RetentionActionDelete, Days: 30}); err != nil {
		t.Fatal(err)
	}
	hold := f.hold(t, HoldScopeAccount, "alice")
	if err := f.space.DeleteItem(t.Context(), f.alice, deleted.ID); err != nil {
		t.Fatal(err)
	}
	job := NewRetentionJob(f.space, f.compliance, f.ts, nil, nil)
	job.ActionDelay = 0
	report, err := job.RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 0 || report.HeldSkipped != 1 || report.HeldPurged != 0 {
		t.Fatalf("held report = %+v", report)
	}
	if _, err := f.space.GetItem(t.Context(), f.alice, expired.ID); err != nil {
		t.Fatalf("retention deleted under hold: %v", err)
	}
	if _, err := f.compliance.ReleaseHold(t.Context(), hold.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	report, err = job.RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 || report.HeldPurged != 1 {
		t.Fatalf("released report = %+v", report)
	}
	if _, err := f.space.GetItem(t.Context(), ComplianceAccess("alice"), deleted.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("released held-deleted item survived: %v", err)
	}
}

func TestRetentionJobIsRateLimitedAndResumesAfterRestart(t *testing.T) {
	f := newComplianceFixture(t)
	if err := f.ts.FolderStore().CreateForUser(t.Context(), "carol"); err != nil {
		t.Fatal(err)
	}
	if err := f.ts.UserStore().Create(t.Context(), "carol", "Carol", "password123"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, account := range []string{"alice", "bob", "carol"} {
		access := UserAccess(account, "test")
		inbox, err := f.space.GetFolderByPath(t.Context(), access, "INBOX")
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := f.space.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: old\r\n\r\nx"), InternalDate: now.AddDate(-1, 0, 0)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := f.compliance.PutPolicy(t.Context(), RetentionPolicy{Scope: RetentionScopeInstallation, Action: RetentionActionDelete, Days: 30}); err != nil {
		t.Fatal(err)
	}
	var slept []time.Duration
	newJob := func() *RetentionJob {
		job := NewRetentionJob(f.space, f.compliance, f.ts, nil, nil)
		job.MaxActions, job.ActionDelay = 3, time.Second
		job.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
		return job
	}
	first, err := newJob().RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first.Deleted != 3 || first.Complete || first.Cursor != "alice" {
		t.Fatalf("first bounded run = %+v", first)
	}
	if len(slept) != 3 || slept[0] != time.Second {
		t.Fatalf("pacing = %v", slept)
	}
	// A new instance stands in for a restart: it resumes after the persisted
	// cursor, rescanning the interrupted account idempotently.
	second, err := newJob().RunOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if second.Deleted != 3 || !second.Complete {
		t.Fatalf("resumed run = %+v", second)
	}
	for _, account := range []string{"alice", "bob", "carol"} {
		access := UserAccess(account, "test")
		inbox, _ := f.space.GetFolderByPath(t.Context(), access, "INBOX")
		if items, err := f.space.ListItems(t.Context(), access, inbox.ID, ItemQuery{}); err != nil || len(items) != 0 {
			t.Fatalf("%s retains %d expired items err=%v", account, len(items), err)
		}
	}
	if cursor, _ := newJob().loadCursor(t.Context()); cursor != "" {
		t.Fatalf("completed pass left cursor %q", cursor)
	}
}

func TestDiscoveryExportWritesHashedManifestAndHeldItems(t *testing.T) {
	f := newComplianceFixture(t)
	received := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	match := f.message(t, f.inbox.ID, "merger one", received)
	heldDeleted := f.message(t, f.inbox.ID, "merger two", received.Add(time.Hour))
	if _, err := f.space.CreateItem(t.Context(), f.alice, f.inbox.ID, ItemInput{Data: []byte("From: dave@example.org\r\nSubject: lunch\r\n\r\nsandwiches"), InternalDate: received}); err != nil {
		t.Fatal(err)
	}
	f.message(t, f.inbox.ID, "too late", received.AddDate(1, 0, 0))
	f.hold(t, HoldScopeAccount, "alice")
	if err := f.space.DeleteItem(t.Context(), f.alice, heldDeleted.ID); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	report, err := ExportDiscovery(t.Context(), f.space, nil, DiscoveryQuery{
		Accounts: []string{"alice"}, Since: received.AddDate(0, 0, -1), Until: received.AddDate(0, 1, 0),
		Participants: []string{"carol@example.net"}, Keywords: "Merger",
	}, "owner", &archive)
	if err != nil {
		t.Fatal(err)
	}
	if report.Items != 2 || report.Accounts != 1 || report.Truncated {
		t.Fatalf("report = %+v", report)
	}
	manifest, files := readDiscoveryArchive(t, archive.Bytes())
	if manifest.Format != DiscoveryExportFormat || manifest.ExportedBy != "owner" || len(manifest.Items) != 2 {
		t.Fatalf("manifest = %+v", manifest)
	}
	byID := map[string]DiscoveryManifestItem{}
	for _, item := range manifest.Items {
		byID[item.ItemID] = item
		sum := sha256.Sum256(files[item.ArchivePath])
		if hex.EncodeToString(sum[:]) != item.SHA256 || !strings.HasSuffix(item.ArchivePath, ".eml") {
			t.Fatalf("manifest item %+v does not match its archive entry", item)
		}
	}
	if byID[match.ID].HeldDeleted || !byID[heldDeleted.ID].HeldDeleted || byID[heldDeleted.ID].HeldDeletedFrom != "INBOX" {
		t.Fatalf("held flags = %+v", byID)
	}
	if !bytes.Equal(files[byID[match.ID].ArchivePath], match.Data) {
		t.Fatal("exported message differs from the stored item")
	}

	archive.Reset()
	report, err = ExportDiscovery(t.Context(), f.space, nil, DiscoveryQuery{Accounts: []string{"alice"}, HeldOnly: true}, "owner", &archive)
	if err != nil || report.Items != 1 {
		t.Fatalf("held-only export = %+v err=%v", report, err)
	}
	archive.Reset()
	report, err = ExportDiscovery(t.Context(), f.space, nil, DiscoveryQuery{Accounts: []string{"alice"}, MaxItems: 1}, "owner", &archive)
	if err != nil || report.Items != 1 || !report.Truncated {
		t.Fatalf("bounded export = %+v err=%v", report, err)
	}
	if _, err := ExportDiscovery(t.Context(), f.space, nil, DiscoveryQuery{}, "owner", io.Discard); err == nil {
		t.Fatal("export without accounts accepted")
	}
}

type fakeDiscoverySearch struct {
	hits    []SearchHit
	request SearchQuery
}

func (s *fakeDiscoverySearch) Search(_ context.Context, access AccessContext, request SearchQuery) (SearchPage, error) {
	if access.Protocol != ProtocolCompliance {
		return SearchPage{}, ErrForbidden
	}
	s.request = request
	return SearchPage{Hits: s.hits}, nil
}
func (s *fakeDiscoverySearch) SearchStatus(context.Context, AccessContext, string) (SearchIndexStatus, error) {
	return SearchIndexStatus{}, nil
}
func (s *fakeDiscoverySearch) RequestSearchRebuild(context.Context, AccessContext, string) error {
	return nil
}

func TestDiscoveryExportUsesSearchIndexCandidates(t *testing.T) {
	f := newComplianceFixture(t)
	first := f.message(t, f.inbox.ID, "indexed", time.Now())
	f.message(t, f.inbox.ID, "not a hit", time.Now())
	search := &fakeDiscoverySearch{hits: []SearchHit{{ItemID: first.ID}}}
	var archive bytes.Buffer
	report, err := ExportDiscovery(t.Context(), f.space, search, DiscoveryQuery{Accounts: []string{"alice"}, Keywords: "quarterly", Participants: []string{"carol@example.net"}}, "owner", &archive)
	if err != nil || report.Items != 1 || !report.Search {
		t.Fatalf("indexed export = %+v err=%v", report, err)
	}
	if search.request.Text != "quarterly" || search.request.Filter == nil || !search.request.IncludeTrash {
		t.Fatalf("search request = %+v", search.request)
	}
}

func readDiscoveryArchive(t *testing.T, data []byte) (DiscoveryManifest, map[string][]byte) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	var manifest DiscoveryManifest
	for _, file := range reader.File {
		handle, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(handle)
		_ = handle.Close()
		if err != nil {
			t.Fatal(err)
		}
		if file.Name == "manifest.json" {
			if err := json.Unmarshal(content, &manifest); err != nil {
				t.Fatalf("manifest: %v\n%s", err, content)
			}
			continue
		}
		files[file.Name] = content
	}
	return manifest, files
}

func TestAccountFolderSpaceKeepsHeldItemsAddressable(t *testing.T) {
	systemBackend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer systemBackend.Close()
	system := model.NewTypedStore(systemBackend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := system.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	user, _ := system.UserStore().Get(t.Context(), "alice")
	if _, _, err := manager.Ensure(t.Context(), user, "", nil); err != nil {
		t.Fatal(err)
	}
	space, err := NewAccountFolderSpace(t.Context(), system, manager, authz.New(system))
	if err != nil {
		t.Fatal(err)
	}
	compliance, err := NewCompliance(t.Context(), system)
	if err != nil {
		t.Fatal(err)
	}
	var routed FolderSpace = NewCachedFolderSpace(space, FolderCacheConfig{})
	ConfigureLegalHolds(routed, compliance)
	alice := UserAccess("alice", "jmap")
	inbox, err := routed.GetFolderByPath(t.Context(), alice, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item, err := routed.CreateItem(t.Context(), alice, inbox.ID, ItemInput{Data: []byte("Subject: kept\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compliance.PlaceHold(t.Context(), LegalHold{Scope: HoldScopeAccount, Target: "alice", Reason: "case"}); err != nil {
		t.Fatal(err)
	}
	if err := routed.DeleteItem(t.Context(), alice, item.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := routed.GetItem(t.Context(), alice, item.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user reads routed held item: %v", err)
	}
	preserved, err := routed.GetItem(t.Context(), ComplianceAccess("alice"), item.ID)
	if err != nil || preserved.HeldDeletedAt.IsZero() {
		t.Fatalf("routed compliance read = %+v err=%v", preserved, err)
	}
	held, err := routed.ListItems(t.Context(), ComplianceAccess("alice"), model.HeldDeletedFolderID("alice", model.FolderTypeMail), ItemQuery{})
	if err != nil || len(held) != 1 {
		t.Fatalf("routed held listing = %d err=%v", len(held), err)
	}
}
