package account

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestManagerMovesAndPurgesAcrossNamedRoots(t *testing.T) {
	base := t.TempDir()
	manager, err := NewManagerWithRoots([]Root{{ID: "fast", Path: base + "/fast"}, {ID: "bulk", Path: base + "/bulk"}}, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: now, UpdatedAt: now}
	entry, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"})
	if err != nil || entry.RootID != "fast" {
		t.Fatalf("created entry = %+v, %v", entry, err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	item, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("move me")})
	if err != nil {
		t.Fatal(err)
	}
	release()
	moved, report, err := manager.Move(t.Context(), "alice", "bulk")
	if err != nil || moved.RootID != "bulk" || !report.Healthy {
		t.Fatalf("move = %+v, %+v, %v", moved, report, err)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).ItemStore().Get(t.Context(), item.ID)
	release()
	if err != nil || string(restored.Data) != "move me" {
		t.Fatalf("moved item = %+v, %v", restored, err)
	}
	if err := manager.Purge("alice", "wrong"); err == nil {
		t.Fatal("purge accepted wrong confirmation")
	}
	if err := manager.Purge("alice", "purge:"+moved.Manifest.ID); err != nil {
		t.Fatal(err)
	}
	if _, found := manager.ByLogin("alice"); found {
		t.Fatal("purged account remains discoverable")
	}
}

func TestManagerRejectsOverlappingRoots(t *testing.T) {
	base := t.TempDir()
	if _, err := NewManagerWithRoots([]Root{{ID: "one", Path: base}, {ID: "two", Path: base + "/nested"}}, "one", store.BackendPebble); err == nil {
		t.Fatal("overlapping roots accepted")
	}
}

func TestManagerRejectsSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	realRoot := base + "/real"
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := base + "/link"
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManagerWithRoots([]Root{{ID: "linked", Path: linkRoot}}, "linked", store.BackendPebble); err == nil {
		t.Fatal("expected symlink account root to be rejected")
	}
}

func TestAccountLifecycleLeaseRejectsConflictingOperations(t *testing.T) {
	base := t.TempDir()
	manager, err := NewManagerWithRoots([]Root{{ID: "fast", Path: base + "/fast"}, {ID: "bulk", Path: base + "/bulk"}}, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := manager.reserveLifecycle(entry.Manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertConflict := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrLifecycleConflict) {
			t.Fatalf("%s error = %v, want lifecycle conflict", name, err)
		}
	}
	_, _, err = manager.Move(t.Context(), "alice", "bulk")
	assertConflict("move", err)
	_, err = manager.StartConversion("alice", store.BackendBadger)
	assertConflict("conversion", err)
	_, err = manager.Check(t.Context(), "alice", true)
	assertConflict("repair", err)
	err = manager.Purge("alice", "purge:"+entry.Manifest.ID)
	assertConflict("purge", err)
	runtime.lifecycle.Store(false)

	job, err := manager.StartMove("alice", "bulk")
	if err != nil {
		t.Fatal(err)
	}
	waitLifecyclePhase(t, manager, job.ID, LifecycleCompleted)
}

func TestManagerRecoversInterruptedMoves(t *testing.T) {
	for _, state := range []string{"prepared", "source-hidden", "target-active"} {
		t.Run(state, func(t *testing.T) {
			base := t.TempDir()
			roots := []Root{{ID: "fast", Path: base + "/fast"}, {ID: "bulk", Path: base + "/bulk"}}
			manager, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			moveID := "mov_recovery"
			staging := roots[1].Path + "/." + moveID
			final := roots[1].Path + "/" + entry.Manifest.ID
			hidden := roots[0].Path + "/.moved-" + entry.Manifest.ID + "-" + moveID
			if err := os.CopyFS(staging, os.DirFS(entry.Path)); err != nil {
				t.Fatal(err)
			}
			journal := moveJournal{Version: moveJournalVersion, MoveID: moveID, AccountID: entry.Manifest.ID, Source: entry.Path, HiddenSource: hidden, Staging: staging, Final: final}
			if err := writeMoveJournal(journal.filename(roots[1].Path), journal); err != nil {
				t.Fatal(err)
			}
			if state != "prepared" {
				if err := os.Rename(entry.Path, hidden); err != nil {
					t.Fatal(err)
				}
			}
			if state == "target-active" {
				if err := os.Rename(staging, final); err != nil {
					t.Fatal(err)
				}
			}

			recovered, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = recovered.Close() }()
			got, found := recovered.ByLogin("alice")
			wantRoot := "bulk"
			if state == "prepared" {
				wantRoot = "fast"
			}
			if !found || got.RootID != wantRoot {
				t.Fatalf("recovered account = %+v, found=%v, want root %q", got, found, wantRoot)
			}
			if _, err := os.Lstat(journal.filename(roots[1].Path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("move journal remains after recovery: %v", err)
			}
		})
	}
}

func TestLifecycleJobsPersistAndReconcileAcrossRestart(t *testing.T) {
	base := t.TempDir()
	roots := []Root{{ID: "fast", Path: base + "/fast"}, {ID: "bulk", Path: base + "/bulk"}}
	manager, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	moveJob, err := manager.StartMove("alice", "bulk")
	if err != nil || moveJob.Phase != LifecycleQueued {
		t.Fatalf("start move = %+v, %v", moveJob, err)
	}
	waitLifecyclePhase(t, manager, moveJob.ID, LifecycleCompleted)
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := reopened.newLifecycleJob(Entry{Manifest: entry.Manifest, RootID: "bulk"}, LifecycleMove, "fast")
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	reconciled, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reconciled.Close() }()
	jobs, err := reconciled.LifecycleJobs("alice")
	if err != nil {
		t.Fatal(err)
	}
	phases := make(map[string]LifecyclePhase, len(jobs))
	for _, job := range jobs {
		phases[job.ID] = job.Phase
	}
	if phases[moveJob.ID] != LifecycleCompleted || phases[interrupted.ID] != LifecycleFailed {
		t.Fatalf("reconciled lifecycle phases = %+v", phases)
	}
}

func TestLifecycleMoveRollbackAndRetainedCleanup(t *testing.T) {
	base := t.TempDir()
	roots := []Root{{ID: "fast", Path: base + "/fast"}, {ID: "bulk", Path: base + "/bulk"}}
	manager, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	if _, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}

	move, err := manager.StartMove("alice", "bulk")
	if err != nil {
		t.Fatal(err)
	}
	waitLifecyclePhase(t, manager, move.ID, LifecycleCompleted)
	move = lifecycleJobByID(t, manager, move.ID)
	if move.RetainedSource == "" {
		t.Fatal("completed move did not record its retained source")
	}
	if _, err := os.Stat(move.RetainedSource); err != nil {
		t.Fatalf("retained source: %v", err)
	}
	if _, err := manager.StartRollback("alice", move.ID, "rollback:wrong"); err == nil {
		t.Fatal("rollback accepted an invalid confirmation")
	}
	rollback, err := manager.StartRollback("alice", move.ID, "rollback:"+move.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitLifecyclePhase(t, manager, rollback.ID, LifecycleCompleted)
	entry, found := manager.ByLogin("alice")
	if !found || entry.RootID != "fast" {
		t.Fatalf("rolled-back entry = %+v, found=%v", entry, found)
	}
	rollback = lifecycleJobByID(t, manager, rollback.ID)
	if rollback.ParentJobID != move.ID || rollback.RetainedSource == "" {
		t.Fatalf("rollback job = %+v", rollback)
	}

	if _, err := manager.StartRetainedCleanup("alice", move.ID, "cleanup:wrong"); err == nil {
		t.Fatal("cleanup accepted an invalid confirmation")
	}
	cleanup, err := manager.StartRetainedCleanup("alice", move.ID, "cleanup:"+move.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitLifecyclePhase(t, manager, cleanup.ID, LifecycleCompleted)
	if _, err := os.Stat(move.RetainedSource); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleaned retained source still exists: %v", err)
	}
	move = lifecycleJobByID(t, manager, move.ID)
	if move.RetainedSource != "" || move.RetainedPurgedAt == nil || move.RetainedPurgedAt.IsZero() {
		t.Fatalf("cleaned move job = %+v", move)
	}
}

func TestReapRetainedQueuesDurableMoveCleanup(t *testing.T) {
	base := t.TempDir()
	roots := []Root{{ID: "fast", Path: base + "/fast"}, {ID: "bulk", Path: base + "/bulk"}}
	manager, err := NewManagerWithRoots(roots, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	if _, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	move, err := manager.StartMove("alice", "bulk")
	if err != nil {
		t.Fatal(err)
	}
	waitLifecyclePhase(t, manager, move.ID, LifecycleCompleted)
	move = lifecycleJobByID(t, manager, move.ID)
	retainedPath := move.RetainedSource
	move.CompletedAt = now.Add(-8 * 24 * time.Hour)
	move.UpdatedAt = move.CompletedAt
	if err := manager.writeLifecycleJob(move); err != nil {
		t.Fatal(err)
	}
	manager.SetRetainedCleanupDays(7)

	started, err := manager.ReapRetained(now)
	if err != nil || len(started) != 1 || started[0].Operation != LifecycleCleanup || started[0].ParentJobID != move.ID {
		t.Fatalf("ReapRetained = %+v, %v", started, err)
	}
	waitLifecyclePhase(t, manager, started[0].ID, LifecycleCompleted)
	if _, err := os.Stat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained source remains: %v", err)
	}
	move = lifecycleJobByID(t, manager, move.ID)
	if move.RetainedSource != "" || move.RetainedPurgedAt == nil {
		t.Fatalf("move cleanup was not recorded: %+v", move)
	}
	if repeated, err := manager.ReapRetained(now.Add(time.Hour)); err != nil || len(repeated) != 0 {
		t.Fatalf("repeated ReapRetained = %+v, %v", repeated, err)
	}
}

func waitLifecyclePhase(t *testing.T, manager *Manager, id string, phase LifecyclePhase) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err := manager.LifecycleJobs("")
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range jobs {
			if job.ID == id && job.Phase == phase {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lifecycle job %s did not reach %s", id, phase)
}

func lifecycleJobByID(t *testing.T, manager *Manager, id string) LifecycleJob {
	t.Helper()
	job, err := manager.lifecycleJob(id)
	if err != nil {
		t.Fatal(err)
	}
	return job
}
