package account

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func createConvertibleAccount(t *testing.T, engine store.Backend) (string, Manifest) {
	t.Helper()
	manifest, err := NewManifest("alice", "Alice", "alice@example.com", nil, engine, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	accountPath := filepath.Join(t.TempDir(), manifest.ID)
	generation, err := CreateGeneration(accountPath, manifest.ActiveGeneration, manifest.Engine)
	if err != nil {
		t.Fatal(err)
	}
	seedGeneration(t, generation)
	if err := generation.Close(); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(filepath.Join(accountPath, ManifestFilename), manifest); err != nil {
		t.Fatal(err)
	}
	return accountPath, manifest
}

func TestConvertActivatesVerifiedTargetAndRetainsSource(t *testing.T) {
	accountPath, original := createConvertibleAccount(t, store.BackendPebble)
	job, err := Convert(t.Context(), accountPath, store.BackendBadger)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if job.Phase != ConversionCompleted || job.Stats.Items != 2 || job.Stats.Digest == "" {
		t.Fatalf("job: %+v", job)
	}
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Engine != store.BackendBadger || manifest.ActiveGeneration != job.TargetGeneration || manifest.State != StateReady || manifest.ConversionID != "" {
		t.Fatalf("activated manifest: %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(accountPath, "generations", original.ActiveGeneration)); err != nil {
		t.Fatalf("source generation was not retained: %v", err)
	}
	active, err := OpenActive(Entry{Manifest: manifest, Path: accountPath})
	if err != nil {
		t.Fatalf("OpenActive: %v", err)
	}
	defer active.Close()
	verified, err := VerifyTransfer(t.Context(), active)
	if err != nil || verified.Digest != job.Stats.Digest {
		t.Fatalf("active verification: %+v, %v", verified, err)
	}
	storedJob, err := ReadConversionJob(accountPath, job.ID)
	if err != nil || storedJob.Phase != ConversionCompleted {
		t.Fatalf("ReadConversionJob: %+v, %v", storedJob, err)
	}
}

func TestResumeInterruptedConversion(t *testing.T) {
	accountPath, manifest := createConvertibleAccount(t, store.BackendBadger)
	targetGeneration := "gen_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	target, err := CreateGeneration(accountPath, targetGeneration, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	job := ConversionJob{
		SchemaVersion:    1,
		ID:               "cnv_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AccountID:        manifest.ID,
		SourceEngine:     manifest.Engine,
		SourceGeneration: manifest.ActiveGeneration,
		TargetEngine:     store.BackendPebble,
		TargetGeneration: targetGeneration,
		OriginalState:    StateReady,
		Phase:            ConversionCopying,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	if err := writeConversionJob(accountPath, job); err != nil {
		t.Fatal(err)
	}
	manifest.State = StateConverting
	manifest.ConversionID = job.ID
	manifest.UpdatedAt = time.Now().UTC()
	if err := WriteManifest(filepath.Join(accountPath, ManifestFilename), manifest); err != nil {
		t.Fatal(err)
	}

	completed, err := ResumeConversion(t.Context(), accountPath, job.ID)
	if err != nil {
		t.Fatalf("ResumeConversion: %v", err)
	}
	if completed.Phase != ConversionCompleted || completed.TargetEngine != store.BackendPebble {
		t.Fatalf("completed job: %+v", completed)
	}
}

func TestConversionRecoversEveryDurableInterruptionBoundary(t *testing.T) {
	tests := []struct {
		name    string
		prepare bool
	}{
		{name: "prepared", prepare: true},
		{name: "target_created", prepare: true},
		{name: "fenced", prepare: true},
		{name: "copying"},
		{name: "copied"},
		{name: "verifying"},
		{name: "verified"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			accountPath, _ := createConvertibleAccount(t, store.BackendPebble)
			hooks := &conversionHooks{interrupt: func(boundary string, _ ConversionJob) error {
				if boundary == tc.name {
					return errConversionInterrupted
				}
				return nil
			}}
			var job ConversionJob
			var err error
			if tc.prepare {
				job, err = prepareConversion(accountPath, ConversionTarget{Engine: store.BackendBadger}, nil, hooks)
			} else {
				job, err = PrepareConversion(accountPath, store.BackendBadger)
				if err == nil {
					job, err = resumeConversion(t.Context(), accountPath, job.ID, nil, hooks)
				}
			}
			if !errors.Is(err, errConversionInterrupted) {
				t.Fatalf("interruption at %s = %+v, %v", tc.name, job, err)
			}

			manager, err := NewManager(filepath.Dir(accountPath), store.BackendPebble)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = manager.Close() }()
			completed := waitConversionPhase(t, manager, job.ID, ConversionCompleted)
			if completed.TargetEngine != store.BackendBadger || completed.Stats.Digest == "" {
				t.Fatalf("recovered conversion = %+v", completed)
			}
			entry, found := manager.ByLogin("alice")
			if !found || entry.Manifest.Engine != store.BackendBadger || entry.Manifest.State != StateReady || entry.Manifest.ConversionID != "" {
				t.Fatalf("recovered manifest = %+v, found=%v", entry.Manifest, found)
			}
		})
	}
}

func TestDurableConversionCancellationRestoresSource(t *testing.T) {
	accountPath, original := createConvertibleAccount(t, store.BackendPebble)
	job, err := PrepareConversion(accountPath, store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	job.CancelRequested = true
	if err := writeConversionJob(accountPath, job); err != nil {
		t.Fatal(err)
	}
	canceled, err := ResumeConversion(t.Context(), accountPath, job.ID)
	if !errors.Is(err, ErrConversionCanceled) || canceled.Phase != ConversionCanceled {
		t.Fatalf("canceled conversion = %+v, %v", canceled, err)
	}
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != StateReady || manifest.Engine != original.Engine || manifest.ActiveGeneration != original.ActiveGeneration || manifest.ConversionID != "" {
		t.Fatalf("restored source manifest = %+v", manifest)
	}
}

func TestConversionRollbackPreservesCurrentDataAndCleanupRemovesOldSource(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	if _, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	conversion, err := manager.StartConversion("alice", store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	conversion = waitConversionPhase(t, manager, conversion.ID, ConversionCompleted)
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
	item, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("written after cutover")})
	release()
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := manager.StartConversionRollback("alice", conversion.ID)
	if err != nil {
		t.Fatal(err)
	}
	rollback = waitConversionPhase(t, manager, rollback.ID, ConversionCompleted)
	if rollback.ParentJobID != conversion.ID || rollback.TargetEngine != store.BackendPebble {
		t.Fatalf("rollback job = %+v", rollback)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).ItemStore().Get(t.Context(), item.ID)
	release()
	if err != nil || string(restored.Data) != "written after cutover" {
		t.Fatalf("post-cutover item = %+v, %v", restored, err)
	}
	if _, err := manager.CleanupConversionSource("alice", conversion.ID, "cleanup:wrong"); err == nil {
		t.Fatal("cleanup accepted invalid confirmation")
	}
	cleaned, err := manager.CleanupConversionSource("alice", conversion.ID, "cleanup:"+conversion.ID)
	if err != nil || cleaned.SourcePurgedAt == nil || cleaned.SourcePurgedAt.IsZero() {
		t.Fatalf("cleanup = %+v, %v", cleaned, err)
	}
	if _, err := os.Stat(filepath.Join(root, cleaned.AccountID, "generations", cleaned.SourceGeneration)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained source remains: %v", err)
	}
}

func TestReapRetainedQueuesDurableConversionCleanup(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	conversion, err := manager.StartConversion("alice", store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	conversion = waitConversionPhase(t, manager, conversion.ID, ConversionCompleted)
	conversion.CompletedAt = now.Add(-31 * 24 * time.Hour)
	conversion.UpdatedAt = conversion.CompletedAt
	entry, found := manager.ByLogin("alice")
	if !found {
		t.Fatal("converted account is not discoverable")
	}
	if err := writeConversionJob(entry.Path, conversion); err != nil {
		t.Fatal(err)
	}
	retainedPath := filepath.Join(entry.Path, "generations", conversion.SourceGeneration)
	manager.SetRetainedCleanupDays(30)
	started, err := manager.ReapRetained(now)
	if err != nil || len(started) != 1 || started[0].Operation != LifecycleCleanupConversion || started[0].ParentJobID != conversion.ID {
		t.Fatalf("ReapRetained = %+v, %v", started, err)
	}
	waitLifecyclePhase(t, manager, started[0].ID, LifecycleCompleted)
	if _, err := os.Stat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained generation remains: %v", err)
	}
	cleaned, err := ReadConversionJob(entry.Path, conversion.ID)
	if err != nil || cleaned.SourcePurgedAt == nil {
		t.Fatalf("cleaned conversion = %+v, %v", cleaned, err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	cleanup := lifecycleJobByID(t, reopened, started[0].ID)
	if cleanup.Phase != LifecycleCompleted || cleanup.ParentJobID != conversion.ID {
		t.Fatalf("persisted cleanup = %+v", cleanup)
	}
}

func TestConversionCleanupReconcilesDeletionInterruptedBeforeJobUpdate(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	conversion, err := manager.StartConversion("alice", store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	conversion = waitConversionPhase(t, manager, conversion.ID, ConversionCompleted)
	entry, _ := manager.ByLogin("alice")
	cleanup, err := manager.newLifecycleJob(entry, LifecycleCleanupConversion, "")
	if err != nil {
		t.Fatal(err)
	}
	cleanup.ParentJobID = conversion.ID
	cleanup.Phase = LifecycleRunning
	if err := manager.writeLifecycleJob(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(entry.Path, "generations", conversion.SourceGeneration)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	reconciled := lifecycleJobByID(t, reopened, cleanup.ID)
	if reconciled.Phase != LifecycleCompleted {
		t.Fatalf("reconciled cleanup = %+v", reconciled)
	}
	entry, _ = reopened.ByLogin("alice")
	conversion, err = ReadConversionJob(entry.Path, conversion.ID)
	if err != nil || conversion.SourcePurgedAt == nil {
		t.Fatalf("reconciled conversion = %+v, %v", conversion, err)
	}
}

func waitConversionPhase(t *testing.T, manager *Manager, id string, phase ConversionPhase) ConversionJob {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err := manager.Jobs("alice")
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range jobs {
			if job.ID == id && job.Phase == phase {
				return job
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("conversion %s did not reach %s", id, phase)
	return ConversionJob{}
}

func TestResumeConversionInterruptedBeforeManifestActivation(t *testing.T) {
	accountPath, _ := createConvertibleAccount(t, store.BackendPebble)
	job, err := PrepareConversion(accountPath, store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	copyConversionTarget(t, accountPath, job)
	job.Phase = ConversionActivating
	job.UpdatedAt = time.Now().UTC()
	if err := writeConversionJob(accountPath, job); err != nil {
		t.Fatal(err)
	}

	completed, err := ResumeConversion(t.Context(), accountPath, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != ConversionCompleted {
		t.Fatalf("resumed job = %+v", completed)
	}
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Engine != job.TargetEngine || manifest.ActiveGeneration != job.TargetGeneration || manifest.State != StateReady {
		t.Fatalf("activated manifest = %+v", manifest)
	}
}

func TestManagerReconcilesConversionInterruptedAfterManifestActivation(t *testing.T) {
	accountPath, _ := createConvertibleAccount(t, store.BackendPebble)
	job, err := PrepareConversion(accountPath, store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	copyConversionTarget(t, accountPath, job)
	job.Phase = ConversionActivating
	job.UpdatedAt = time.Now().UTC()
	if err := writeConversionJob(accountPath, job); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Engine = job.TargetEngine
	manifest.ActiveGeneration = job.TargetGeneration
	manifest.State = job.OriginalState
	manifest.ConversionID = ""
	manifest.UpdatedAt = time.Now().UTC()
	if err := WriteManifest(filepath.Join(accountPath, ManifestFilename), manifest); err != nil {
		t.Fatal(err)
	}

	manager, err := NewManager(filepath.Dir(accountPath), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	completed, err := ReadConversionJob(accountPath, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != ConversionCompleted || completed.CompletedAt.IsZero() {
		t.Fatalf("reconciled job = %+v", completed)
	}
	if _, release, err := manager.Acquire("alice"); err != nil {
		t.Fatalf("acquire reconciled account: %v", err)
	} else {
		release()
	}
}

func copyConversionTarget(t *testing.T, accountPath string, job ConversionJob) {
	t.Helper()
	source, err := OpenGeneration(accountPath, job.SourceGeneration, job.SourceEngine)
	if err != nil {
		t.Fatal(err)
	}
	target, err := OpenGeneration(accountPath, job.TargetGeneration, job.TargetEngine)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if _, err := Transfer(t.Context(), source, target); err != nil {
		_ = source.Close()
		_ = target.Close()
		t.Fatal(err)
	}
	if err := errors.Join(source.Close(), target.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenActiveReturnsMaintenanceError(t *testing.T) {
	accountPath, manifest := createConvertibleAccount(t, store.BackendPebble)
	manifest.State = StateConverting
	manifest.ConversionID = "cnv_cccccccccccccccccccccccccccccccc"
	if _, err := OpenActive(Entry{Manifest: manifest, Path: accountPath}); !errors.Is(err, ErrTemporarilyUnavailable) {
		t.Fatalf("OpenActive: got %v, want temporary unavailable", err)
	}
}

func TestConvertRejectsSameEngineWithoutFencing(t *testing.T) {
	accountPath, original := createConvertibleAccount(t, store.BackendPebble)
	if _, err := Convert(t.Context(), accountPath, store.BackendPebble); !errors.Is(err, ErrConversionConflict) {
		t.Fatalf("Convert: got %v, want conflict", err)
	}
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != original.State || manifest.ActiveGeneration != original.ActiveGeneration {
		t.Fatalf("manifest changed after rejected conversion: %+v", manifest)
	}
}
