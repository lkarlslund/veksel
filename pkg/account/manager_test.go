package account

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestManagerEnsureDiscoverAndConvert(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	entry, created, err := manager.Ensure(t.Context(), user, "alice@example.com", []string{"alice@example.com"})
	if err != nil || !created {
		t.Fatalf("Ensure: entry=%+v created=%v err=%v", entry, created, err)
	}
	if entry.Manifest.Engine != store.BackendPebble || len(entry.Manifest.Addresses) != 1 {
		t.Fatalf("manifest = %+v", entry.Manifest)
	}
	generation, err := OpenActive(entry)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).UserStore().Get(t.Context(), "alice")
	if err != nil || owner.DisplayName != "Alice" {
		t.Fatalf("account owner = %+v, err=%v", owner, err)
	}
	if err := generation.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate opening an account created before a newly introduced default
	// folder existed. Ensure must apply additive folder schema updates too.
	generation, err = OpenActive(entry)
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	if err := typed.FolderStore().Delete(t.Context(), model.RecentRecipientsFolderID("alice")); err != nil {
		t.Fatal(err)
	}
	if err := generation.Close(); err != nil {
		t.Fatal(err)
	}
	if _, created, err := manager.Ensure(t.Context(), user, "", nil); err != nil || created {
		t.Fatalf("second Ensure: created=%v err=%v", created, err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).FolderStore().Get(t.Context(), model.RecentRecipientsFolderID("alice")); err != nil {
		release()
		t.Fatalf("default folder was not backfilled: %v", err)
	}
	release()
	job, err := manager.Convert(t.Context(), "alice", store.BackendBadger)
	if err != nil || job.Phase != ConversionCompleted {
		t.Fatalf("Convert: job=%+v err=%v", job, err)
	}
	converted, found := manager.ByLogin("alice")
	if !found || converted.Manifest.Engine != store.BackendBadger {
		t.Fatalf("converted entry = %+v found=%v", converted, found)
	}
	jobs, err := manager.Jobs("alice")
	if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("Jobs: %+v err=%v", jobs, err)
	}
}

func TestManagerClosesAndReopensIdleGeneration(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	user := model.User{ID: "alice", DisplayName: "Alice", PasswordHash: "hash", Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	manager.SetIdleTimeout(time.Second)
	first, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	if closed := manager.ReapIdle(time.Now().Add(2 * time.Second)); closed != 0 {
		t.Fatalf("closed %d leased generations", closed)
	}
	release()
	if closed := manager.ReapIdle(time.Now().Add(2 * time.Second)); closed != 1 {
		t.Fatalf("closed %d idle generations, want 1", closed)
	}
	second, releaseSecond, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()
	if second == first {
		t.Fatal("idle generation was not reopened")
	}
}

func TestAccountIdentityMetadataUpdateDoesNotRewriteContent(t *testing.T) {
	for _, engine := range ProductionEngines {
		t.Run(string(engine), func(t *testing.T) {
			manager, err := NewManager(t.TempDir(), engine)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = manager.Close() }()
			now := time.Now().UTC()
			user := model.User{ID: "alice", DisplayName: "Alice Original", Enabled: true, CreatedAt: now, UpdatedAt: now}
			entry, _, err := manager.Ensure(t.Context(), user, "alice@old.example", []string{"alice@old.example"})
			if err != nil {
				t.Fatal(err)
			}
			generation, release, err := manager.Acquire("alice")
			if err != nil {
				t.Fatal(err)
			}
			typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
			inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
			if err != nil {
				release()
				t.Fatal(err)
			}
			item, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("identity update must not rewrite me")})
			release()
			if err != nil {
				t.Fatal(err)
			}

			user.DisplayName = "Alice Renamed"
			user.UpdatedAt = now.Add(time.Minute)
			updated, created, err := manager.Ensure(t.Context(), user, "alice@new.example", []string{"alice@new.example", "alias@new.example"})
			if err != nil || created {
				t.Fatalf("identity update: created=%v err=%v", created, err)
			}
			if updated.Path != entry.Path || updated.Manifest.ID != entry.Manifest.ID || updated.Manifest.ActiveGeneration != entry.Manifest.ActiveGeneration || updated.Manifest.DisplayName != "Alice Renamed" || updated.Manifest.PrimaryAddress != "alice@new.example" {
				t.Fatalf("updated account = %+v, original = %+v", updated, entry)
			}
			generation, release, err = manager.Acquire("alice")
			if err != nil {
				t.Fatal(err)
			}
			typed = model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
			stored, itemErr := typed.ItemStore().Get(t.Context(), item.ID)
			folder, folderErr := typed.FolderStore().Get(t.Context(), inbox.ID)
			release()
			if itemErr != nil || folderErr != nil || stored.ID != item.ID || stored.FolderID != inbox.ID || folder.ID != inbox.ID || string(stored.Data) != "identity update must not rewrite me" {
				t.Fatalf("content changed: item=%+v itemErr=%v folder=%+v folderErr=%v", stored, itemErr, folder, folderErr)
			}
		})
	}
}
