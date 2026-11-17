package backup_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func populateStore(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()

	namespaces := []string{"domains", "users", "emails", "folders", "items"}
	for _, ns := range namespaces {
		if err := s.CreateNamespace(ctx, ns); err != nil {
			t.Fatalf("CreateNamespace %s: %v", ns, err)
		}
	}

	// Add some data
	tests := []struct {
		ns  string
		key string
		val []byte
	}{
		{"domains", "example.com", []byte(`{"id":"example.com","enabled":true}`)},
		{"domains", "test.org", []byte(`{"id":"test.org","enabled":true}`)},
		{"users", "alice", []byte(`{"id":"alice","display_name":"Alice"}`)},
		{"users", "bob", []byte(`{"id":"bob","display_name":"Bob"}`)},
		{"emails", "addr:alice@example.com", []byte(`{"id":"alice@example.com","user_id":"alice"}`)},
		{"folders", "alice:INBOX", []byte(`{"id":"alice:INBOX","path":"INBOX"}`)},
		{"items", "alice:INBOX:msg1", []byte(`{"id":"alice:INBOX:msg1","data":"hello"}`)},
	}

	for _, tt := range tests {
		if err := s.Set(ctx, tt.ns, tt.key, tt.val); err != nil {
			t.Fatalf("Set %s/%s: %v", tt.ns, tt.key, err)
		}
	}
}

func TestBackupCreatesValidTarGz(t *testing.T) {
	s := newTestStore(t)
	populateStore(t, s)

	var buf bytes.Buffer
	if err := backup.Backup(s, &buf, "json"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("Backup produced empty output")
	}

	// Validate the backup metadata
	meta, err := backup.ValidateBackup(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ValidateBackup: %v", err)
	}

	if meta.Version != "v2" {
		t.Fatalf("Version: got %q want %q", meta.Version, "v2")
	}
	if meta.Backend != "json" {
		t.Fatalf("Backend: got %q want %q", meta.Backend, "json")
	}
	if len(meta.Namespaces) != 5 {
		t.Fatalf("Namespaces: got %d want 5", len(meta.Namespaces))
	}
	if meta.TotalKeys != 7 {
		t.Fatalf("TotalKeys: got %d want 7", meta.TotalKeys)
	}
}

func TestVerifyDetectsRepackedRecordCorruptionAndRestoreDoesNotMutate(t *testing.T) {
	source := newTestStore(t)
	populateStore(t, source)
	data, err := backup.BackupToBytes(source, "json")
	if err != nil {
		t.Fatal(err)
	}
	verification, err := backup.Verify(bytes.NewReader(data))
	if err != nil || !verification.Verified || verification.Algorithm != "sha256" || verification.Records != 8 || verification.Metadata.Version != "v2" {
		t.Fatalf("verification = %#v, %v", verification, err)
	}
	corrupt := rewriteBackup(t, data, func(name string, value []byte) (bool, []byte) {
		if name == "users/alice" {
			return true, append(bytes.Clone(value), 'x')
		}
		return true, value
	})
	if _, err := backup.Verify(bytes.NewReader(corrupt)); err == nil {
		t.Fatal("repacked record corruption passed verification")
	}
	destination := newTestStore(t)
	if err := destination.CreateNamespace(t.Context(), "prior"); err != nil {
		t.Fatal(err)
	}
	if err := destination.Set(t.Context(), "prior", "key", []byte("safe")); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Restore(destination, bytes.NewReader(corrupt), backup.Replace); err == nil {
		t.Fatal("corrupt backup restored")
	}
	if got, err := destination.Get(t.Context(), "prior", "key"); err != nil || string(got) != "safe" {
		t.Fatalf("failed integrity restore mutated destination: %q, %v", got, err)
	}
}

func TestVerifyRejectsMissingAndForgedManifestRecords(t *testing.T) {
	source := newTestStore(t)
	populateStore(t, source)
	data, err := backup.BackupToBytes(source, "json")
	if err != nil {
		t.Fatal(err)
	}
	withoutManifest := rewriteBackup(t, data, func(name string, value []byte) (bool, []byte) { return name != "manifest.json", value })
	if _, err := backup.Verify(bytes.NewReader(withoutManifest)); err == nil {
		t.Fatal("v2 backup without manifest passed verification")
	}
	withExtra := rewriteBackup(t, data, func(name string, value []byte) (bool, []byte) { return true, value })
	withExtra = appendBackupEntry(t, withExtra, "users/extra", []byte("extra"))
	if _, err := backup.Verify(bytes.NewReader(withExtra)); err == nil {
		t.Fatal("backup with undeclared extra record passed verification")
	}
}

func TestVerifyAndRestoreRetainExplicitV1Compatibility(t *testing.T) {
	metadata, err := json.Marshal(backup.Metadata{Version: "v1", Backend: "json", Namespaces: []string{"legacy"}, TotalKeys: 1})
	if err != nil {
		t.Fatal(err)
	}
	archive := writeBackupEntries(t, []backupEntry{
		{header: &tar.Header{Name: "metadata.json", Size: int64(len(metadata)), Mode: 0o600, Typeflag: tar.TypeReg}, data: metadata},
		{header: &tar.Header{Name: "legacy/key", Size: 5, Mode: 0o600, Typeflag: tar.TypeReg}, data: []byte("value")},
	})
	verification, err := backup.Verify(bytes.NewReader(archive))
	if err != nil || verification.Verified || !verification.Legacy || verification.Metadata.Version != "v1" {
		t.Fatalf("legacy verification = %#v, %v", verification, err)
	}
	destination := newTestStore(t)
	if _, err := backup.Restore(destination, bytes.NewReader(archive), backup.Merge); err != nil {
		t.Fatal(err)
	}
	if value, err := destination.Get(t.Context(), "legacy", "key"); err != nil || string(value) != "value" {
		t.Fatalf("legacy value = %q, %v", value, err)
	}
}

func TestVerifyContextHonorsCancellationWhileReading(t *testing.T) {
	source := newTestStore(t)
	populateStore(t, source)
	data, err := backup.BackupToBytes(source, "json")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backup.VerifyContext(ctx, bytes.NewReader(data)); !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyContext() error = %v, want context.Canceled", err)
	}
}

type backupEntry struct {
	header *tar.Header
	data   []byte
}

func rewriteBackup(t *testing.T, input []byte, rewrite func(string, []byte) (bool, []byte)) []byte {
	t.Helper()
	var entries []backupEntry
	for _, entry := range readBackupEntries(t, input) {
		keep, data := rewrite(entry.header.Name, entry.data)
		if !keep {
			continue
		}
		entry.header.Size = int64(len(data))
		entries = append(entries, backupEntry{entry.header, data})
	}
	return writeBackupEntries(t, entries)
}

func appendBackupEntry(t *testing.T, input []byte, name string, value []byte) []byte {
	entries := readBackupEntries(t, input)
	entries = append(entries, backupEntry{header: &tar.Header{Name: name, Size: int64(len(value)), Mode: 0o600, Typeflag: tar.TypeReg}, data: value})
	return writeBackupEntries(t, entries)
}

func readBackupEntries(t *testing.T, input []byte) []backupEntry {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	var entries []backupEntry
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		copyHeader := *header
		entries = append(entries, backupEntry{&copyHeader, data})
	}
	return entries
}

func writeBackupEntries(t *testing.T, entries []backupEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	writer := tar.NewWriter(gz)
	for _, entry := range entries {
		if err := writer.WriteHeader(entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestBackupEmptyStore(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateNamespace(ctx, "empty"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	var buf bytes.Buffer
	if err := backup.Backup(s, &buf, "json"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	meta, err := backup.ValidateBackup(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ValidateBackup: %v", err)
	}

	if meta.TotalKeys != 0 {
		t.Fatalf("TotalKeys: got %d want 0", meta.TotalKeys)
	}
}

func TestRestoreRecoversAllData(t *testing.T) {
	// Create source store and populate
	src := newTestStore(t)
	populateStore(t, src)

	// Create backup
	var buf bytes.Buffer
	if err := backup.Backup(src, &buf, "json"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Create fresh store and restore
	dst := newTestStore(t)
	meta, err := backup.Restore(dst, bytes.NewReader(buf.Bytes()), backup.Merge)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if meta.TotalKeys != 7 {
		t.Fatalf("TotalKeys: got %d want 7", meta.TotalKeys)
	}

	// Verify all data was restored
	ctx := context.Background()
	tests := []struct {
		ns   string
		key  string
		want string
	}{
		{"domains", "example.com", `{"id":"example.com","enabled":true}`},
		{"domains", "test.org", `{"id":"test.org","enabled":true}`},
		{"users", "alice", `{"id":"alice","display_name":"Alice"}`},
		{"users", "bob", `{"id":"bob","display_name":"Bob"}`},
		{"emails", "addr:alice@example.com", `{"id":"alice@example.com","user_id":"alice"}`},
		{"folders", "alice:INBOX", `{"id":"alice:INBOX","path":"INBOX"}`},
		{"items", "alice:INBOX:msg1", `{"id":"alice:INBOX:msg1","data":"hello"}`},
	}

	for _, tt := range tests {
		val, err := dst.Get(ctx, tt.ns, tt.key)
		if err != nil {
			t.Fatalf("Get %s/%s: %v", tt.ns, tt.key, err)
		}
		if string(val) != tt.want {
			t.Fatalf("Get %s/%s: got %q want %q", tt.ns, tt.key, val, tt.want)
		}
	}
}

func TestRestoreMergeMode(t *testing.T) {
	// Create store with existing data
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateNamespace(ctx, "domains"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s.Set(ctx, "domains", "existing.com", []byte(`{"id":"existing.com"}`)); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Create backup with different data
	src := newTestStore(t)
	if err := src.CreateNamespace(ctx, "domains"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := src.Set(ctx, "domains", "new.com", []byte(`{"id":"new.com"}`)); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var buf bytes.Buffer
	if err := backup.Backup(src, &buf, "json"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Restore in merge mode
	if _, err := backup.Restore(s, bytes.NewReader(buf.Bytes()), backup.Merge); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Both keys should exist
	_, err := s.Get(ctx, "domains", "existing.com")
	if err != nil {
		t.Fatalf("Get existing.com after merge: %v", err)
	}
	_, err = s.Get(ctx, "domains", "new.com")
	if err != nil {
		t.Fatalf("Get new.com after merge: %v", err)
	}
}

func TestRestoreReplaceMode(t *testing.T) {
	// Create store with existing data
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateNamespace(ctx, "domains"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s.Set(ctx, "domains", "old.com", []byte(`{"id":"old.com"}`)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.CreateNamespace(ctx, "users"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := s.Set(ctx, "users", "olduser", []byte(`{"id":"olduser"}`)); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Create backup with different data
	src := newTestStore(t)
	if err := src.CreateNamespace(ctx, "domains"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if err := src.Set(ctx, "domains", "new.com", []byte(`{"id":"new.com"}`)); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var buf bytes.Buffer
	if err := backup.Backup(src, &buf, "json"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Restore in replace mode
	if _, err := backup.Restore(s, bytes.NewReader(buf.Bytes()), backup.Replace); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Old data should be gone
	_, err := s.Get(ctx, "domains", "old.com")
	if err != store.ErrNotFound {
		t.Fatalf("Get old.com after replace: expected ErrNotFound, got %v", err)
	}
	_, err = s.Get(ctx, "users", "olduser")
	if err != store.ErrNotFound {
		t.Fatalf("Get olduser after replace: expected ErrNotFound, got %v", err)
	}

	// New data should exist
	val, err := s.Get(ctx, "domains", "new.com")
	if err != nil {
		t.Fatalf("Get new.com after replace: %v", err)
	}
	if string(val) != `{"id":"new.com"}` {
		t.Fatalf("Get new.com: got %q", val)
	}
}

func TestRestoreCommitFailureLeavesPriorStoreUntouched(t *testing.T) {
	for _, mode := range []backup.Mode{backup.Merge, backup.Replace} {
		t.Run(map[backup.Mode]string{backup.Merge: "merge", backup.Replace: "replace"}[mode], func(t *testing.T) {
			destination := newTestStore(t)
			if err := destination.CreateNamespace(t.Context(), "domains"); err != nil {
				t.Fatal(err)
			}
			if err := destination.Set(t.Context(), "domains", "existing.test", []byte("existing")); err != nil {
				t.Fatal(err)
			}
			source := newTestStore(t)
			if err := source.CreateNamespace(t.Context(), "domains"); err != nil {
				t.Fatal(err)
			}
			if err := source.CreateNamespace(t.Context(), "new_namespace"); err != nil {
				t.Fatal(err)
			}
			if err := source.Set(t.Context(), "domains", "new.test", []byte("new")); err != nil {
				t.Fatal(err)
			}
			archive, err := backup.BackupToBytes(source, "json")
			if err != nil {
				t.Fatal(err)
			}
			failing := faultstore.New(destination)
			failing.Fail("batch_commit", 1)
			if _, err := backup.Restore(failing, bytes.NewReader(archive), mode); !errors.Is(err, faultstore.ErrInjected) {
				t.Fatalf("Restore error = %v", err)
			}
			if got, err := destination.Get(t.Context(), "domains", "existing.test"); err != nil || string(got) != "existing" {
				t.Fatalf("prior value = %q, %v", got, err)
			}
			if _, err := destination.Get(t.Context(), "domains", "new.test"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("new value error = %v", err)
			}
			if exists, _ := destination.NamespaceExists(t.Context(), "new_namespace"); exists {
				t.Fatal("failed restore leaked a namespace")
			}
		})
	}
}

func TestValidateBackupInvalidGzip(t *testing.T) {
	_, err := backup.ValidateBackup(bytes.NewReader([]byte("not a gzip file")))
	if err == nil {
		t.Fatal("expected error for invalid gzip")
	}
}

func TestValidateBackupMissingMetadata(t *testing.T) {
	// Create a valid gzip but without metadata.json
	var buf bytes.Buffer
	// Minimal gzip header + invalid content
	buf.Write([]byte{0x1f, 0x8b, 0x08}) // gzip magic
	_, err := backup.ValidateBackup(&buf)
	if err == nil {
		t.Fatal("expected error for missing metadata")
	}
}

func TestRestoreInvalidArchive(t *testing.T) {
	s := newTestStore(t)
	_, err := backup.Restore(s, bytes.NewReader([]byte("not a backup")), backup.Merge)
	if err == nil {
		t.Fatal("expected error for invalid archive")
	}
}

func TestBackupToBytes(t *testing.T) {
	s := newTestStore(t)
	populateStore(t, s)

	data, err := backup.BackupToBytes(s, "json")
	if err != nil {
		t.Fatalf("BackupToBytes: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("BackupToBytes produced empty output")
	}

	// Restore from bytes
	s2 := newTestStore(t)
	meta, err := backup.Restore(s2, bytes.NewReader(data), backup.Merge)
	if err != nil {
		t.Fatalf("Restore from bytes: %v", err)
	}

	if meta.TotalKeys != 7 {
		t.Fatalf("TotalKeys: got %d want 7", meta.TotalKeys)
	}
}

func TestInfoFromMetadata(t *testing.T) {
	meta := &backup.Metadata{
		Version:    "v1",
		Backend:    "json",
		Namespaces: []string{"a", "b"},
		TotalKeys:  10,
	}

	info := backup.InfoFromMetadata(meta)
	if info.Version != "v1" {
		t.Fatalf("Version: got %q want %q", info.Version, "v1")
	}
	if info.TotalKeys != 10 {
		t.Fatalf("TotalKeys: got %d want 10", info.TotalKeys)
	}
	if len(info.Names) != 2 {
		t.Fatalf("Names: got %d want 2", len(info.Names))
	}
}

func TestBackupAndRestoreBinaryData(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateNamespace(ctx, "bin"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}

	// Binary data that could be corrupted by text processing
	original := []byte{0x00, 0xff, 0xfe, 0x80, 0x01, 0x02, 0x03}
	if err := s.Set(ctx, "bin", "data", original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var buf bytes.Buffer
	if err := backup.Backup(s, &buf, "json"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	s2 := newTestStore(t)
	if _, err := backup.Restore(s2, bytes.NewReader(buf.Bytes()), backup.Merge); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	val, err := s2.Get(ctx, "bin", "data")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if len(val) != len(original) {
		t.Fatalf("length: got %d want %d", len(val), len(original))
	}
	for i := range original {
		if val[i] != original[i] {
			t.Fatalf("byte[%d]: got 0x%02x want 0x%02x", i, val[i], original[i])
		}
	}
}
