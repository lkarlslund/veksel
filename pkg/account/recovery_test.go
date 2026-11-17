package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const recoveryCorpusItems = 775

func seedRecoveryCorpus(t *testing.T, generation *Generation, manifest Manifest) TransferStats {
	t.Helper()
	ctx := t.Context()
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(ctx, namespace); err != nil && !errors.Is(err, store.ErrExists) {
			t.Fatal(err)
		}
	}
	fixed := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	user := model.User{ID: manifest.Login, DisplayName: manifest.DisplayName, Enabled: true, CreatedAt: fixed, UpdatedAt: fixed}
	if err := typed.Set(ctx, model.NSUsers, user.ID, user); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().EnsureForUser(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().Create(ctx, user.ID, "Projects", model.FolderTypeMail, ""); err != nil && !errors.Is(err, store.ErrExists) {
		t.Fatal(err)
	}
	projects, err := typed.FolderStore().GetByPath(ctx, user.ID, "Projects")
	if err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().Create(ctx, user.ID, "Projects/2026", model.FolderTypeMail, projects.ID); err != nil && !errors.Is(err, store.ErrExists) {
		t.Fatal(err)
	}
	if err := typed.FolderStore().Create(ctx, user.ID, "Notes", model.FolderTypeNotes, ""); err != nil && !errors.Is(err, store.ErrExists) {
		t.Fatal(err)
	}
	folders := make(map[model.FolderType]model.Folder)
	for folderType, path := range map[model.FolderType]string{
		model.FolderTypeMail: "INBOX", model.FolderTypeCalendar: "Calendar", model.FolderTypeContacts: "Contacts", model.FolderTypeFiles: "Files", model.FolderTypeNotes: "Notes",
	} {
		folder, err := typed.FolderStore().GetByPath(ctx, user.ID, path)
		if err != nil {
			t.Fatal(err)
		}
		folders[folderType] = folder
	}
	mailFolder := folders[model.FolderTypeMail]
	mailFolder.History = model.ItemHistoryPolicy{Enabled: true, RetentionDays: 3650, MaxVersions: 20}
	if err := typed.Set(ctx, model.NSFolders, mailFolder.ID, mailFolder); err != nil {
		t.Fatal(err)
	}
	appendItems := func(folderType model.FolderType, count int, content func(int) []byte) {
		folder := folders[folderType]
		for index := range count {
			payload := content(index)
			item, err := typed.ItemStore().AppendItem(ctx, folder.ID, model.Item{
				Name: fmt.Sprintf("%s-%04d", folderType, index), Data: payload,
				Headers:      map[string]string{"X-Recovery-Corpus": "true", "X-Sequence": fmt.Sprint(index)},
				ExternalIDs:  map[string]string{"fixture": fmt.Sprintf("%s/%04d", folderType, index)},
				InternalDate: fixed.Add(time.Duration(index) * time.Minute),
			})
			if err != nil {
				t.Fatal(err)
			}
			if folderType == model.FolderTypeMail && index%100 == 0 {
				if _, captured, err := typed.ItemHistoryStore().Capture(ctx, item, model.ItemHistoryUpdate); err != nil || !captured {
					t.Fatalf("capture history item %d: captured=%t err=%v", index, captured, err)
				}
			}
		}
	}
	appendItems(model.FolderTypeMail, 600, func(index int) []byte {
		return []byte(fmt.Sprintf("From: sender-%d@example.test\r\nTo: alice@example.test\r\nSubject: Recovery %d\r\n\r\nDeterministic body %08d", index%17, index, index))
	})
	appendItems(model.FolderTypeCalendar, 50, func(index int) []byte {
		start := fixed.AddDate(0, 0, index)
		return []byte(fmt.Sprintf("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:recovery-%d@example.test\r\nDTSTART:%s\r\nDTEND:%s\r\nSUMMARY:Recovery event %d\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n", index, start.Format("20060102T150405Z"), start.Add(time.Hour).Format("20060102T150405Z"), index))
	})
	appendItems(model.FolderTypeContacts, 50, func(index int) []byte {
		return []byte(fmt.Sprintf("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:contact-%d\r\nFN:Recovery Contact %d\r\nEMAIL:contact-%d@example.test\r\nEND:VCARD\r\n", index, index, index))
	})
	appendItems(model.FolderTypeFiles, 50, func(index int) []byte {
		return append([]byte{0, 1, 2, byte(index)}, bytes.Repeat([]byte{byte(index % 251)}, 256+index)...)
	})
	appendItems(model.FolderTypeNotes, 25, func(index int) []byte {
		return []byte(fmt.Sprintf("Recovery note %d\ncustom:value-%d", index, index))
	})
	custom := map[string]any{"schema": 1, "features": []string{"folders", "history", "external-identities"}, "enabled": true}
	if err := typed.Put(ctx, model.NSMetadata, "recovery:custom", custom); err != nil {
		t.Fatal(err)
	}
	stats, err := VerifyTransfer(ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Items != recoveryCorpusItems || stats.HistoryVersions != 6 {
		t.Fatalf("corpus stats = %#v", stats)
	}
	entry := Entry{Manifest: manifest, Path: filepath.Dir(filepath.Dir(generation.Path))}
	report, err := CheckGeneration(ctx, entry, generation, false)
	if err != nil || !report.Healthy {
		t.Fatalf("corpus integrity = %#v, %v", report, err)
	}
	return stats
}

func TestRecoveryCorpusBundleAcrossProductionEngines(t *testing.T) {
	for _, engines := range [][2]store.Backend{{store.BackendPebble, store.BackendBadger}, {store.BackendBadger, store.BackendPebble}} {
		t.Run(string(engines[0])+"-to-"+string(engines[1]), func(t *testing.T) {
			root := t.TempDir()
			manifest, err := NewManifest("alice", "Alice", "alice@example.test", []string{"alice@example.test", "alias@example.test"}, engines[0], time.Now())
			if err != nil {
				t.Fatal(err)
			}
			accountPath := filepath.Join(root, manifest.ID)
			source, err := CreateGeneration(accountPath, manifest.ActiveGeneration, engines[0])
			if err != nil {
				t.Fatal(err)
			}
			want := seedRecoveryCorpus(t, source, manifest)
			var bundle bytes.Buffer
			if err := ExportBundle(t.Context(), Entry{Manifest: manifest, Path: accountPath}, source, &bundle); err != nil {
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			targetID, err := NewGenerationID()
			if err != nil {
				t.Fatal(err)
			}
			targetPath := filepath.Join(root, "target")
			target, err := CreateGeneration(targetPath, targetID, engines[1])
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = target.Close() }()
			if _, err := ImportBundle(t.Context(), bytes.NewReader(bundle.Bytes()), target); err != nil {
				t.Fatal(err)
			}
			got, err := VerifyTransfer(t.Context(), target)
			if err != nil || !sameTransferImage(want, got) {
				t.Fatalf("restored stats = %#v, want %#v, err=%v", got, want, err)
			}
			objectsBefore, err := target.Objects.Scan(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ImportBundle(t.Context(), bytes.NewReader(bundle.Bytes()), target); err != nil {
				t.Fatalf("repeat import: %v", err)
			}
			objectsAfter, err := target.Objects.Scan(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(objectsAfter) != len(objectsBefore) {
				t.Fatalf("repeat import appended objects: before=%d after=%d", len(objectsBefore), len(objectsAfter))
			}
			targetManifest := manifest
			targetManifest.Engine, targetManifest.ActiveGeneration = engines[1], targetID
			report, err := CheckGeneration(t.Context(), Entry{Manifest: targetManifest, Path: targetPath}, target, false)
			if err != nil || !report.Healthy || report.Digest != want.Digest {
				t.Fatalf("restored integrity = %#v, %v", report, err)
			}
		})
	}
}

type limitedFailureWriter struct {
	remaining int
}

func (w *limitedFailureWriter) Write(data []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("injected insufficient space")
	}
	if len(data) > w.remaining {
		written := w.remaining
		w.remaining = 0
		return written, errors.New("injected insufficient space")
	}
	w.remaining -= len(data)
	return len(data), nil
}

func TestFailedExportAndDamagedRestorePreserveActiveGeneration(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: now, UpdatedAt: now}
	entry, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	want := seedRecoveryCorpus(t, generation, entry.Manifest)
	release()
	if err := manager.Export(t.Context(), "alice", &limitedFailureWriter{remaining: 4096}); err == nil || !strings.Contains(err.Error(), "insufficient space") {
		t.Fatalf("failed export error = %v", err)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	afterFailedExport, err := VerifyTransfer(t.Context(), generation)
	release()
	if err != nil || !sameTransferImage(want, afterFailedExport) {
		t.Fatalf("active image after failed export = %#v, %v", afterFailedExport, err)
	}
	var bundle bytes.Buffer
	if err := manager.Export(t.Context(), "alice", &bundle); err != nil {
		t.Fatal(err)
	}
	records := readBundleRecords(t, bundle.Bytes())
	for index := range records {
		if strings.HasPrefix(records[index].name, "items/") {
			records = append(records[:index], records[index+1:]...)
			break
		}
	}
	generationRoot := filepath.Join(entry.Path, "generations")
	before, err := os.ReadDir(generationRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Restore(t.Context(), "alice", bytes.NewReader(writeBundleRecords(t, records)), store.BackendBadger); err == nil || !strings.Contains(err.Error(), "verification mismatch") {
		t.Fatalf("damaged restore error = %v", err)
	}
	after, err := os.ReadDir(generationRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed restore leaked a generation: before=%d after=%d", len(before), len(after))
	}
	current, found := manager.ByLogin("alice")
	if !found || current.Manifest.ActiveGeneration != entry.Manifest.ActiveGeneration || current.Manifest.Engine != store.BackendPebble {
		t.Fatalf("active manifest changed after failed restore: %#v", current.Manifest)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyTransfer(context.Background(), generation)
	release()
	if err != nil || !sameTransferImage(want, got) {
		t.Fatalf("active image after failed restore = %#v, %v", got, err)
	}
}

func TestInterruptedRestoreRollsBackAndRemovesTargetOnRestart(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true}, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	targetID, err := NewGenerationID()
	if err != nil {
		t.Fatal(err)
	}
	target, err := CreateGeneration(entry.Path, targetID, store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	job, err := manager.newLifecycleJob(entry, LifecycleRestore, entry.RootID)
	if err != nil {
		t.Fatal(err)
	}
	job.Phase = LifecycleRunning
	job.SourceGeneration = entry.Manifest.ActiveGeneration
	job.TargetGeneration = targetID
	job.TargetEngine = store.BackendBadger
	if err := manager.writeLifecycleJob(job); err != nil {
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
	reconciled := lifecycleJobByID(t, reopened, job.ID)
	if reconciled.Phase != LifecycleFailed || !strings.Contains(reconciled.Error, "prior active state was preserved") {
		t.Fatalf("reconciled restore = %+v", reconciled)
	}
	if _, err := os.Stat(filepath.Join(entry.Path, "generations", targetID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted target generation remains: %v", err)
	}
	current, found := reopened.ByLogin("alice")
	if !found || current.Manifest.ActiveGeneration != entry.Manifest.ActiveGeneration {
		t.Fatalf("active account changed after interrupted restore: %+v, found=%v", current, found)
	}
}

func TestSuccessfulRestoreRecordsAndCleansRetainedGeneration(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(root, store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true}, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	seedRecoveryCorpus(t, generation, entry.Manifest)
	var bundle bytes.Buffer
	if err := manager.Export(t.Context(), "alice", &bundle); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if _, err := manager.Restore(t.Context(), "alice", bytes.NewReader(bundle.Bytes()), store.BackendBadger); err != nil {
		t.Fatal(err)
	}
	jobs, err := manager.LifecycleJobs("alice")
	if err != nil {
		t.Fatal(err)
	}
	var restore LifecycleJob
	for _, candidate := range jobs {
		if candidate.Operation == LifecycleRestore {
			restore = candidate
			break
		}
	}
	if restore.Phase != LifecycleCompleted || restore.SourceGeneration != entry.Manifest.ActiveGeneration || restore.RetainedSource == "" {
		t.Fatalf("completed restore lifecycle = %+v", restore)
	}
	if _, err := os.Stat(restore.RetainedSource); err != nil {
		t.Fatalf("retained restore generation: %v", err)
	}
	cleanup, err := manager.StartRetainedCleanup("alice", restore.ID, "cleanup:"+restore.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitLifecyclePhase(t, manager, cleanup.ID, LifecycleCompleted)
	if _, err := os.Stat(restore.RetainedSource); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained restore generation remains: %v", err)
	}
}
