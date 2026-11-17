package app

import (
	"context"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/migration"
)

type completedSyncSource struct{}

func (*completedSyncSource) ID() string { return "fake://restart/alice" }
func (*completedSyncSource) Folders(context.Context) ([]migration.Folder, error) {
	return nil, nil
}
func (*completedSyncSource) Items(context.Context, migration.Folder, string) (migration.Page, error) {
	return migration.Page{Done: true}, nil
}
func (*completedSyncSource) Close() error { return nil }

func TestInterruptedManualSyncResumesImmediately(t *testing.T) {
	handler, ts := testHandler(t)
	ownerEvents, cancelOwnerEvents := handler.events.Subscribe("alice")
	t.Cleanup(cancelOwnerEvents)
	otherEvents, cancelOtherEvents := handler.events.Subscribe("bob")
	t.Cleanup(cancelOtherEvents)
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	started := make(chan migration.SourceOptions, 1)
	handler.migrationSources["fake"] = func(_ context.Context, options migration.SourceOptions) (migration.Source, error) {
		started <- options
		return &completedSyncSource{}, nil
	}
	job, err := handler.migrationJobs.Create(t.Context(), migration.Job{
		OwnerID: "alice", DestinationID: "alice", SourceType: "fake",
		Connection: migration.NewConnectionProfile(migration.SourceOptions{Endpoint: "source.example.test", Username: "alice"}),
		Schedule:   migration.ScheduleManual, CredentialStored: true, State: migration.StateInterrupted,
	})
	if err != nil {
		t.Fatal(err)
	}
	job.State = migration.StateInterrupted
	if err := handler.migrationJobs.SaveCredential(t.Context(), job.ID, "source-secret"); err != nil {
		t.Fatal(err)
	}
	if err := handler.migrationJobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}

	handler.runScheduledSyncs(t.Context(), time.Now().UTC())
	select {
	case event := <-ownerEvents:
		if event.Type != "sync.started" || event.Resource != job.ID || len(event.Data) != 0 {
			t.Fatalf("start event = %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sync start event was not published")
	}
	select {
	case event := <-otherEvents:
		t.Fatalf("sync start event leaked to another user: %#v", event)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case options := <-started:
		if options.Password != "source-secret" {
			t.Fatalf("resume password = %q", options.Password)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("interrupted manual sync was not resumed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stored, getErr := handler.migrationJobs.Get(t.Context(), job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.State == migration.StateCompleted {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	stored, _ := handler.migrationJobs.Get(t.Context(), job.ID)
	t.Fatalf("resumed sync state = %q", stored.State)
}

func TestExplicitlyPausedManualSyncDoesNotAutoResume(t *testing.T) {
	handler, _ := testHandler(t)
	started := make(chan struct{}, 1)
	handler.migrationSources["fake"] = func(context.Context, migration.SourceOptions) (migration.Source, error) {
		started <- struct{}{}
		return &completedSyncSource{}, nil
	}
	job, err := handler.migrationJobs.Create(t.Context(), migration.Job{
		OwnerID: "alice", DestinationID: "alice", SourceType: "fake",
		Schedule: migration.ScheduleManual, CredentialStored: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job.State = migration.StatePaused
	if err := handler.migrationJobs.SaveCredential(t.Context(), job.ID, "source-secret"); err != nil {
		t.Fatal(err)
	}
	if err := handler.migrationJobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	handler.runScheduledSyncs(t.Context(), time.Now().UTC())
	select {
	case <-started:
		t.Fatal("explicitly paused manual sync auto-resumed")
	case <-time.After(50 * time.Millisecond):
	}
	stored, err := handler.migrationJobs.Get(t.Context(), job.ID)
	if err != nil || stored.State != migration.StatePaused {
		t.Fatalf("paused sync = %#v, %v", stored, err)
	}
}
