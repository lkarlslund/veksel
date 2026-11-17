package jsonstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
)

func TestBatchReadYourWritesAndCommit(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.CreateNamespace(t.Context(), "items"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(t.Context(), "items", "old", []byte("old")); err != nil {
		t.Fatal(err)
	}
	err = store.Batch(t.Context(), s, func(ctx context.Context) error {
		if err := s.Set(ctx, "items", "new", []byte("new")); err != nil {
			return err
		}
		if got, err := s.Get(ctx, "items", "new"); err != nil || string(got) != "new" {
			t.Fatalf("batch Get = %q, %v", got, err)
		}
		if err := s.Delete(ctx, "items", "old"); err != nil {
			return err
		}
		keys, err := s.List(ctx, "items")
		if err != nil || len(keys) != 1 || keys[0] != "new" {
			t.Fatalf("batch List = %v, %v", keys, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(t.Context(), "items", "new"); err != nil || string(got) != "new" {
		t.Fatalf("committed Get = %q, %v", got, err)
	}
	if _, err := s.Get(t.Context(), "items", "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted Get error = %v", err)
	}
}

func TestBatchRollbackDoesNotMutateStore(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.CreateNamespace(t.Context(), "items"); err != nil {
		t.Fatal(err)
	}
	want := errors.New("rollback")
	err = store.Batch(t.Context(), s, func(ctx context.Context) error {
		if err := s.Set(ctx, "items", "new", []byte("new")); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("Batch error = %v", err)
	}
	if _, err := s.Get(t.Context(), "items", "new"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back key error = %v", err)
	}
}

func TestBatchNamespaceChangesCommitAndRollback(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.CreateNamespace(t.Context(), "existing"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(t.Context(), "existing", "retained", []byte("value")); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback")
	err = store.Batch(t.Context(), s, func(ctx context.Context) error {
		if err := s.CreateNamespace(ctx, "created"); err != nil {
			return err
		}
		if err := s.Set(ctx, "created", "key", []byte("value")); err != nil {
			return err
		}
		if err := s.DeleteNamespace(ctx, "existing"); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("Batch error = %v", err)
	}
	if exists, _ := s.NamespaceExists(t.Context(), "created"); exists {
		t.Fatal("rolled-back namespace exists")
	}
	if got, err := s.Get(t.Context(), "existing", "retained"); err != nil || string(got) != "value" {
		t.Fatalf("existing value after rollback = %q, %v", got, err)
	}
	if err := store.Batch(t.Context(), s, func(ctx context.Context) error {
		if err := s.CreateNamespace(ctx, "created"); err != nil {
			return err
		}
		if err := s.Set(ctx, "created", "key", []byte("committed")); err != nil {
			return err
		}
		return s.DeleteNamespace(ctx, "existing")
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(t.Context(), "created", "key"); err != nil || string(got) != "committed" {
		t.Fatalf("created value = %q, %v", got, err)
	}
	if exists, _ := s.NamespaceExists(t.Context(), "existing"); exists {
		t.Fatal("deleted namespace still exists")
	}
}

func TestOpenRecoversCommittedBatchJournal(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNamespace(t.Context(), "items"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(t.Context(), "items", "remove", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err := json.Marshal(diskBatch{Changes: []diskBatchChange{
		{Namespace: "items", Key: "created", Value: []byte("recovered")},
		{Namespace: "items", Key: "remove", Deleted: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, batchJournalName), journal, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if got, err := reopened.Get(t.Context(), "items", "created"); err != nil || string(got) != "recovered" {
		t.Fatalf("recovered value = %q, %v", got, err)
	}
	if _, err := reopened.Get(t.Context(), "items", "remove"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovered delete error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, batchJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains: %v", err)
	}
}

func TestOpenRecoversNamespaceBatchJournal(t *testing.T) {
	directory := t.TempDir()
	s, err := New(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNamespace(t.Context(), "removed"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err := json.Marshal(diskBatch{
		Namespaces: []diskNamespaceChange{{Namespace: "created", Exists: true}, {Namespace: "removed", Exists: false}},
		Changes:    []diskBatchChange{{Namespace: "created", Key: "key", Value: []byte("recovered")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, batchJournalName), journal, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if got, err := reopened.Get(t.Context(), "created", "key"); err != nil || string(got) != "recovered" {
		t.Fatalf("recovered namespace value = %q, %v", got, err)
	}
	if exists, _ := reopened.NamespaceExists(t.Context(), "removed"); exists {
		t.Fatal("journal-deleted namespace still exists")
	}
}
