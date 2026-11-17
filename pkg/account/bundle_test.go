package account

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type bundleRecord struct {
	name string
	data []byte
}

func readBundleRecords(t *testing.T, data []byte) []bundleRecord {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	var records []bundleRecord
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, bundleRecord{name: header.Name, data: payload})
	}
}

func writeBundleRecords(t *testing.T, records []bundleRecord) []byte {
	t.Helper()
	var result bytes.Buffer
	gzipWriter := gzip.NewWriter(&result)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, record := range records {
		if err := writeTarRecord(tarWriter, record.name, record.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

type viewAssertingStore struct {
	store.Store
	t      *testing.T
	viewed bool
	reads  int
}

func (s *viewAssertingStore) View(ctx context.Context, fn func(context.Context) error) error {
	s.viewed = true
	return store.View(ctx, s.Store, fn)
}

func (s *viewAssertingStore) assertView(ctx context.Context) {
	s.t.Helper()
	if !store.InView(ctx, s) {
		s.t.Fatal("account bundle read escaped the stable store view")
	}
	s.reads++
}

func (s *viewAssertingStore) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	s.assertView(ctx)
	return s.Store.Get(ctx, namespace, key)
}

func (s *viewAssertingStore) ListNamespaces(ctx context.Context) ([]string, error) {
	s.assertView(ctx)
	return s.Store.ListNamespaces(ctx)
}

func (s *viewAssertingStore) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	s.assertView(ctx)
	return s.Store.Scan(ctx, namespace, prefix)
}

func (s *viewAssertingStore) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	s.assertView(ctx)
	return s.Store.Iterate(ctx, namespace, prefix, fn)
}

func TestBundleRestoresAcrossEngines(t *testing.T) {
	root := t.TempDir()
	manifest, err := NewManifest("alice", "Alice", "alice@example.test", []string{"alice@example.test"}, store.BackendPebble, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := root + "/" + manifest.ID
	source, err := CreateGeneration(sourcePath, manifest.ActiveGeneration, manifest.Engine)
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(source.Index, source.Engine, source.Objects)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := typed.Put(t.Context(), model.NSUsers, user.ID, user); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	inbox, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	created, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("Subject: bundle\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	inbox, _ = typed.FolderStore().Get(t.Context(), inbox.ID)
	inbox.History = model.ItemHistoryPolicy{Enabled: true, RetentionDays: 30, MaxVersions: 10}
	if err := typed.Set(t.Context(), model.NSFolders, inbox.ID, inbox); err != nil {
		t.Fatal(err)
	}
	version, captured, err := typed.ItemHistoryStore().Capture(t.Context(), created, model.ItemHistoryUpdate)
	if err != nil || !captured {
		t.Fatalf("capture history: captured=%t err=%v", captured, err)
	}
	var bundle bytes.Buffer
	if err := ExportBundle(t.Context(), Entry{Manifest: manifest, Path: sourcePath}, source, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	targetID, _ := NewGenerationID()
	target, err := CreateGeneration(root+"/target", targetID, store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	restoredManifest, err := ImportBundle(t.Context(), bytes.NewReader(bundle.Bytes()), target)
	if err != nil {
		t.Fatal(err)
	}
	if restoredManifest.ID != manifest.ID {
		t.Fatalf("restored manifest ID = %s", restoredManifest.ID)
	}
	targetModel := model.NewTypedStoreWithObjects(target.Index, target.Engine, target.Objects)
	restored, err := targetModel.ItemStore().Get(t.Context(), created.ID)
	if err != nil || !bytes.Equal(restored.Data, created.Data) {
		t.Fatalf("restored item = %+v, %v", restored, err)
	}
	restoredVersion, err := targetModel.ItemHistoryStore().Get(t.Context(), inbox.ID, created.ID, version.ID)
	if err != nil || !bytes.Equal(restoredVersion.Item.Data, created.Data) {
		t.Fatalf("restored history = %+v, %v", restoredVersion, err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBundleV3UsesStableVerifiedSnapshot(t *testing.T) {
	root := t.TempDir()
	manifest, err := NewManifest("alice", "Alice", "alice@example.test", []string{"alice@example.test"}, store.BackendPebble, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	source, err := CreateGeneration(root+"/source", manifest.ActiveGeneration, manifest.Engine)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	typed := model.NewTypedStoreWithObjects(source.Index, source.Engine, source.Objects)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if err := typed.Put(t.Context(), model.NSUsers, "alice", model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	inbox, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if _, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("Subject: snapshot\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	asserting := &viewAssertingStore{Store: source.Index, t: t}
	viewGeneration := *source
	viewGeneration.Index = asserting
	var bundle bytes.Buffer
	if err := ExportBundle(t.Context(), Entry{Manifest: manifest, Path: root + "/source"}, &viewGeneration, &bundle); err != nil {
		t.Fatal(err)
	}
	if !asserting.viewed || asserting.reads == 0 {
		t.Fatalf("stable view used=%t reads=%d", asserting.viewed, asserting.reads)
	}
	records := readBundleRecords(t, bundle.Bytes())
	var header bundleHeader
	if len(records) == 0 || records[0].name != "bundle.json" || json.Unmarshal(records[0].data, &header) != nil {
		t.Fatal("bundle does not begin with a valid header")
	}
	if header.Version != bundleVersion || header.Verification == nil || header.Verification.Digest == "" || len(header.Namespaces) != header.Verification.Namespaces {
		t.Fatalf("bundle header = %#v", header)
	}
}

func TestBundleV3RejectsMissingAndMisidentifiedRecords(t *testing.T) {
	root := t.TempDir()
	manifest, err := NewManifest("alice", "Alice", "alice@example.test", []string{"alice@example.test"}, store.BackendPebble, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	source, err := CreateGeneration(root+"/source", manifest.ActiveGeneration, manifest.Engine)
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(source.Index, source.Engine, source.Objects)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if err := typed.Put(t.Context(), model.NSUsers, "alice", model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	inbox, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if _, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("Subject: retained\r\n\r\nbody")}); err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if err := ExportBundle(t.Context(), Entry{Manifest: manifest, Path: root + "/source"}, source, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	records := readBundleRecords(t, bundle.Bytes())
	itemIndex := -1
	for index := range records {
		if strings.HasPrefix(records[index].name, "items/") {
			itemIndex = index
			break
		}
	}
	if itemIndex < 0 {
		t.Fatal("test bundle has no item record")
	}
	tests := []struct {
		name    string
		mutate  func([]bundleRecord) []bundleRecord
		wantErr string
	}{
		{name: "missing item", mutate: func(input []bundleRecord) []bundleRecord {
			return append(append([]bundleRecord(nil), input[:itemIndex]...), input[itemIndex+1:]...)
		}, wantErr: "verification mismatch"},
		{name: "misidentified item", mutate: func(input []bundleRecord) []bundleRecord {
			result := append([]bundleRecord(nil), input...)
			result[itemIndex].name = "items/itm_wrong.json"
			return result
		}, wantErr: "filename does not match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := CreateGeneration(root+"/target-"+strings.ReplaceAll(test.name, " ", "-"), "gen_11111111111111111111111111111111", store.BackendBadger)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = target.Close() }()
			_, err = ImportBundle(t.Context(), bytes.NewReader(writeBundleRecords(t, test.mutate(records))), target)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ImportBundle error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestManagerRestoreActivatesVerifiedBundle(t *testing.T) {
	manager, err := NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.test", []string{"alice@example.test"}); err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	created, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("restore me")})
	if err != nil {
		t.Fatal(err)
	}
	release()
	var bundle bytes.Buffer
	if err := manager.Export(t.Context(), "alice", &bundle); err != nil {
		t.Fatal(err)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).ItemStore().Delete(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	release()
	report, err := manager.Restore(t.Context(), "alice", bytes.NewReader(bundle.Bytes()), store.BackendBadger)
	if err != nil || !report.Healthy {
		t.Fatalf("restore report = %+v, %v", report, err)
	}
	entry, found := manager.ByLogin("alice")
	if !found || entry.Manifest.Engine != store.BackendBadger {
		t.Fatalf("restored entry = %+v", entry)
	}
	generation, release, err = manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	item, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).ItemStore().Get(t.Context(), created.ID)
	if err != nil || string(item.Data) != "restore me" {
		t.Fatalf("restored item = %+v, %v", item, err)
	}
}
