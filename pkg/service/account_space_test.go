package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type writeCountingStore struct {
	store.Store
	writes atomic.Int64
}

func (s *writeCountingStore) Set(ctx context.Context, namespace, key string, value []byte) error {
	s.writes.Add(1)
	return s.Store.Set(ctx, namespace, key, value)
}

func TestAccountFolderSpaceRoutesMixedEnginesAndFencesConversion(t *testing.T) {
	systemBackend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer systemBackend.Close()
	meteredSystem := &writeCountingStore{Store: systemBackend}
	system := model.NewTypedStore(meteredSystem, store.BackendJSON)
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
	for _, login := range []string{"alice", "bob"} {
		if err := system.UserStore().Create(t.Context(), login, login, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := system.FolderStore().CreateForUser(t.Context(), login); err != nil {
			t.Fatal(err)
		}
		if login == "bob" {
			if err := manager.SetDefaultEngine(store.BackendBadger); err != nil {
				t.Fatal(err)
			}
		}
		user, _ := system.UserStore().Get(t.Context(), login)
		if _, _, err := manager.Ensure(t.Context(), user, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	aliceEntry, _ := manager.ByLogin("alice")
	aliceGeneration, err := account.OpenActive(aliceEntry)
	if err != nil {
		t.Fatal(err)
	}
	aliceStore := model.NewTypedStoreWithObjects(aliceGeneration.Index, aliceGeneration.Engine, aliceGeneration.Objects)
	if err := aliceStore.FolderStore().Create(t.Context(), "alice", "Legacy contacts", model.FolderTypeContacts, ""); err != nil {
		t.Fatal(err)
	}
	legacyFolder, err := aliceStore.FolderStore().GetByPath(t.Context(), "alice", "Legacy contacts")
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceGeneration.Close(); err != nil {
		t.Fatal(err)
	}
	space, err := NewAccountFolderSpace(t.Context(), system, manager, authz.New(system))
	if err != nil {
		t.Fatal(err)
	}
	if mirrored, err := system.FolderStore().Get(t.Context(), legacyFolder.ID); err != nil || mirrored.Path != "Legacy contacts" {
		t.Fatalf("legacy folder catalog was not reconciled: folder=%+v err=%v", mirrored, err)
	}

	for _, login := range []string{"alice", "bob"} {
		access := UserAccess(login, "test")
		item, err := space.CreateItem(t.Context(), access, model.InboxFolderID(login), ItemInput{Data: []byte("Subject: " + login + "\r\n\r\nbody")})
		if err != nil {
			t.Fatalf("CreateItem(%s): %v", login, err)
		}
		got, err := space.GetItem(t.Context(), access, item.ID)
		if err != nil || string(got.Data) != string(item.Data) {
			t.Fatalf("GetItem(%s): got=%+v err=%v", login, got, err)
		}
		if _, err := system.ItemStore().Get(t.Context(), item.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("item %s leaked into system store: %v", item.ID, err)
		}
	}
	alice, _ := manager.ByLogin("alice")
	bob, _ := manager.ByLogin("bob")
	if alice.Manifest.Engine != store.BackendPebble || bob.Manifest.Engine != store.BackendBadger {
		t.Fatalf("mixed engines: alice=%s bob=%s", alice.Manifest.Engine, bob.Manifest.Engine)
	}

	lease, release, err := manager.Acquire("alice")
	if err != nil || lease == nil {
		t.Fatalf("Acquire: generation=%v err=%v", lease, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := manager.Convert(t.Context(), "alice", store.BackendBadger)
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, acquiredRelease, err := manager.Acquire("alice")
		if errors.Is(err, account.ErrTemporarilyUnavailable) {
			break
		}
		if acquiredRelease != nil {
			acquiredRelease()
		}
		if time.Now().After(deadline) {
			t.Fatal("conversion did not publish maintenance fence")
		}
		time.Sleep(time.Millisecond)
	}
	// A different backend/account remains usable while Alice drains.
	if _, err := space.GetFolderByPath(t.Context(), UserAccess("bob", "test"), "INBOX"); err != nil {
		t.Fatalf("Bob unavailable during Alice conversion: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	writesBeforeList := meteredSystem.writes.Load()
	items, err := space.ListItems(t.Context(), UserAccess("alice", "test"), model.InboxFolderID("alice"), ItemQuery{MetadataOnly: true})
	if err != nil || len(items) != 1 {
		t.Fatalf("Alice after conversion: items=%d err=%v", len(items), err)
	}
	if writesAfterList := meteredSystem.writes.Load(); writesAfterList != writesBeforeList {
		t.Fatalf("read-only item list wrote system index: before=%d after=%d", writesBeforeList, writesAfterList)
	}

	access := UserAccess("alice", "test")
	parent, err := space.CreateFolder(t.Context(), access, "Project", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	child, err := space.CreateFolder(t.Context(), access, "Archive", model.FolderTypeMail, parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := space.CreateItem(t.Context(), access, child.ID, ItemInput{Data: []byte("delete me")})
	if err != nil {
		t.Fatal(err)
	}
	if err := space.DeleteItem(t.Context(), access, deleted.ID); err != nil {
		t.Fatal(err)
	}
	var location accountItemLocation
	if err := system.Get(t.Context(), accountItemLocationsNamespace, deleted.ID, &location); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted item location remains: %+v err=%v", location, err)
	}
	toPurge, err := space.CreateItem(t.Context(), access, child.ID, ItemInput{Data: []byte("purge me")})
	if err != nil {
		t.Fatal(err)
	}
	if err := space.DeleteFolder(t.Context(), access, parent.ID); err != nil {
		t.Fatal(err)
	}
	if err := space.PurgeFolder(t.Context(), access, parent.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{parent.ID, child.ID} {
		if _, err := system.FolderStore().Get(t.Context(), id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("purged folder mirror %s remains: %v", id, err)
		}
	}
	if err := system.Get(t.Context(), accountItemLocationsNamespace, toPurge.ID, &location); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("purged item location remains: %+v err=%v", location, err)
	}

	oldState, err := space.CurrentChangeState(t.Context(), access, ChangeScope{Object: ChangeObjectItem})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := space.CreateItem(t.Context(), access, model.InboxFolderID("alice"), ItemInput{Data: []byte("Subject: retention\r\n\r\nbody")}); err != nil {
			t.Fatal(err)
		}
	}
	space.SetChangeRetention(3650, 1)
	pruned, err := space.PruneChanges(t.Context(), time.Now().UTC())
	if err != nil || pruned.AccountsScanned != 2 || pruned.AccountsSkipped != 0 || pruned.ChangesRemoved < 2 {
		t.Fatalf("PruneChanges = %+v, %v", pruned, err)
	}
	if _, err := space.ListChanges(t.Context(), access, ChangeScope{Object: ChangeObjectItem}, oldState, 10); !errors.Is(err, ErrChangeStateExpired) {
		t.Fatalf("old routed state error = %v", err)
	}

	inboxID := model.InboxFolderID("alice")
	configured, err := space.ConfigureItemHistory(t.Context(), access, inboxID, model.ItemHistoryPolicy{Enabled: true, RetentionDays: 1, MaxVersions: 5})
	if err != nil {
		t.Fatal(err)
	}
	if mirrored, mirrorErr := system.FolderStore().Get(t.Context(), inboxID); mirrorErr != nil || mirrored.History != configured.History {
		t.Fatalf("mirrored history policy=%+v err=%v", mirrored.History, mirrorErr)
	}
	versioned, err := space.CreateItem(t.Context(), access, inboxID, ItemInput{Data: []byte("routed-old")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.UpdateItem(t.Context(), access, versioned.ID, []byte("routed-new"), nil); err != nil {
		t.Fatal(err)
	}
	versions, err := space.ListItemVersions(t.Context(), access, inboxID, versioned.ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("routed history=%+v err=%v", versions, err)
	}
	historyPruned, err := space.PruneItemHistory(t.Context(), time.Now().UTC().Add(48*time.Hour))
	if err != nil || historyPruned.AccountsScanned != 2 || historyPruned.AccountsSkipped != 0 || historyPruned.VersionsRemoved != 1 {
		t.Fatalf("PruneItemHistory = %+v, %v", historyPruned, err)
	}
}

func TestAccountFolderSpaceRecreatesPurgedSystemUserOnFirstUse(t *testing.T) {
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
	if err := system.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}

	manager, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	space, err := NewAccountFolderSpace(t.Context(), system, manager, authz.New(system))
	if err != nil {
		t.Fatal(err)
	}

	folders, err := space.ListFolders(t.Context(), UserAccess("alice", "test"), FolderQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) == 0 {
		t.Fatal("first account access returned no default folders")
	}
	if _, found := manager.ByLogin("alice"); !found {
		t.Fatal("first account access did not recreate account storage")
	}
	archive, err := space.GetFolderByPath(t.Context(), UserAccess("alice", "test"), "Archive")
	if err != nil {
		t.Fatal(err)
	}
	if archive.SpecialUse != model.SpecialUseArchive {
		t.Fatalf("Archive special use = %q, want %q", archive.SpecialUse, model.SpecialUseArchive)
	}
}

// Startup reconciliation re-applies the system user record to every account
// store. Usage counters are maintained transactionally in the account store
// with item writes, so a restart must keep them while still applying limits.
func TestAccountQuotaUsageSurvivesRestartReconciliation(t *testing.T) {
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
	users := system.UserStore()
	if err := users.Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if err := users.UpdateQuota(t.Context(), "alice", 0, 2); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	access := UserAccess("alice", "test")
	// start mirrors process startup: open the account manager, reconcile the
	// system user into account storage, and build the folder space.
	start := func() (*account.Manager, *AccountFolderSpace) {
		t.Helper()
		manager, err := account.NewManager(root, store.BackendPebble)
		if err != nil {
			t.Fatal(err)
		}
		user, err := users.Get(t.Context(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := manager.Ensure(t.Context(), user, "", nil); err != nil {
			t.Fatal(err)
		}
		space, err := NewAccountFolderSpace(t.Context(), system, manager, authz.New(system))
		if err != nil {
			t.Fatal(err)
		}
		return manager, space
	}
	usage := func(space *AccountFolderSpace) model.QuotaInfo {
		t.Helper()
		usage, err := space.AccountUsage(t.Context(), access)
		if err != nil {
			t.Fatal(err)
		}
		return usage.Quota
	}
	createItem := func(space *AccountFolderSpace) error {
		_, err := space.CreateItem(t.Context(), access, model.InboxFolderID("alice"), ItemInput{Data: []byte("Subject: hi\r\n\r\nbody")})
		return err
	}

	manager, space := start()
	for range 2 {
		if err := createItem(space); err != nil {
			t.Fatal(err)
		}
	}
	before := usage(space)
	if before.CurrentItems != 2 || before.CurrentStorageBytes == 0 || before.MaxItems != 2 {
		t.Fatalf("quota before restart = %+v", before)
	}
	if err := createItem(space); !errors.Is(err, model.ErrQuotaExceeded) {
		t.Fatalf("third item before restart: %v, want quota exceeded", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	manager, space = start()
	if after := usage(space); after != before {
		t.Fatalf("quota after restart = %+v, want %+v", after, before)
	}
	if err := createItem(space); !errors.Is(err, model.ErrQuotaExceeded) {
		t.Fatalf("third item after restart: %v, want quota exceeded", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	// Limits remain owned by the system record and still reach the account.
	if err := users.UpdateQuota(t.Context(), "alice", 0, 3); err != nil {
		t.Fatal(err)
	}
	manager, space = start()
	defer manager.Close()
	raised := before
	raised.MaxItems = 3
	if after := usage(space); after != raised {
		t.Fatalf("quota after limit change = %+v, want %+v", after, raised)
	}
	if err := createItem(space); err != nil {
		t.Fatalf("item within raised limit: %v", err)
	}
	if err := createItem(space); !errors.Is(err, model.ErrQuotaExceeded) {
		t.Fatalf("item beyond raised limit: %v, want quota exceeded", err)
	}
}
