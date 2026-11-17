package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// changeVisitCountingStore counts the journal records an engine hands to
// iteration callbacks and every full key listing, so tests can assert that a
// journal read touches only the records it returns.
type changeVisitCountingStore struct {
	store.Store
	visits int
	scans  int
}

func (s *changeVisitCountingStore) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	s.scans++
	return s.Store.Scan(ctx, namespace, prefix)
}

func (s *changeVisitCountingStore) List(ctx context.Context, namespace string) ([]string, error) {
	s.scans++
	return s.Store.List(ctx, namespace)
}

func (s *changeVisitCountingStore) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	return s.IterateFrom(ctx, namespace, prefix, "", fn)
}

func (s *changeVisitCountingStore) IterateFrom(ctx context.Context, namespace, prefix, start string, fn store.IterCallback) error {
	return store.IterateFrom(ctx, s.Store, namespace, prefix, start, func(key string, value []byte) (bool, error) {
		s.visits++
		return fn(key, value)
	})
}

func (s *changeVisitCountingStore) Batch(ctx context.Context, fn func(context.Context) error) error {
	return s.Store.(store.Batcher).Batch(ctx, fn)
}

func (s *changeVisitCountingStore) View(ctx context.Context, fn func(context.Context) error) error {
	return s.Store.(store.Viewer).View(ctx, fn)
}

// recordChangeRun appends count single-effect records in one batch, with
// committed-at times advancing by a second from base.
func recordChangeRun(t testing.TB, ts *model.TypedStore, changes *ChangeStore, first, count int) {
	t.Helper()
	if err := store.Batch(t.Context(), ts.Store(), func(ctx context.Context) error {
		for index := first; index < first+count; index++ {
			if _, err := changes.Record(ctx, []Change{{Object: ChangeObjectItem, Operation: ChangeCreate, ID: fmt.Sprintf("item-%06d", index), FolderID: "inbox"}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestChangeJournalReadsSeekPastStateOnEveryEngine(t *testing.T) {
	const journal = 400
	for _, tc := range changeJournalEngines(t) {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := tc.open(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			counted := &changeVisitCountingStore{Store: backend}
			ts := model.NewTypedStore(counted, store.Backend(tc.name))
			changes := NewChangeStore(ts)
			changes.SetRetention(3650, journal/2)
			if err := changes.Ensure(t.Context()); err != nil {
				t.Fatal(err)
			}
			recordChangeRun(t, ts, changes, 0, journal)

			// The head is a single metadata read.
			counted.visits, counted.scans = 0, 0
			current, err := changes.CurrentState(t.Context())
			if err != nil || current != encodeChangeState(journal) || counted.visits != 0 || counted.scans != 0 {
				t.Fatalf("CurrentState = %q, %v after %d visit(s), %d scan(s)", current, err, counted.visits, counted.scans)
			}

			// A consumer three records behind reads three records.
			counted.visits = 0
			page, err := changes.List(t.Context(), ChangeScope{Object: ChangeObjectItem}, encodeChangeState(journal-3), 100)
			if err != nil || len(page.Records) != 3 || page.Records[0].Sequence != journal-2 || page.NewState != current || page.HasMoreChanges {
				t.Fatalf("tail page = %+v, %v", page, err)
			}
			if counted.visits != 3 || counted.scans != 0 {
				t.Fatalf("tail read visited %d record(s) with %d scan(s), want 3 and 0", counted.visits, counted.scans)
			}

			// A full page stops at the limit and reports the remainder.
			counted.visits = 0
			page, err = changes.List(t.Context(), ChangeScope{}, encodeChangeState(100), 5)
			if err != nil || len(page.Records) != 5 || page.Records[0].Sequence != 101 || page.NewState != encodeChangeState(105) || !page.HasMoreChanges {
				t.Fatalf("middle page = %+v, %v", page, err)
			}
			if counted.visits != 5 {
				t.Fatalf("middle page visited %d record(s), want 5", counted.visits)
			}

			// Pruning to the entry limit reads the expired records plus the
			// first retained one, and later reads skip the pruned range.
			counted.visits = 0
			removed, err := changes.Prune(t.Context(), time.Now().UTC())
			if err != nil || removed != journal/2 {
				t.Fatalf("Prune = %d, %v", removed, err)
			}
			if counted.visits != journal/2+1 || counted.scans != 0 {
				t.Fatalf("Prune visited %d record(s) with %d scan(s), want %d and 0", counted.visits, counted.scans, journal/2+1)
			}
			if _, err := changes.List(t.Context(), ChangeScope{}, encodeChangeState(journal/2-1), 10); !errors.Is(err, ErrChangeStateExpired) {
				t.Fatalf("expired state error = %v", err)
			}
			counted.visits = 0
			page, err = changes.List(t.Context(), ChangeScope{}, encodeChangeState(journal/2), 1)
			if err != nil || len(page.Records) != 1 || page.Records[0].Sequence != journal/2+1 || !page.HasMoreChanges {
				t.Fatalf("floor page = %+v, %v", page, err)
			}
			if counted.visits != 1 {
				t.Fatalf("floor page visited %d record(s), want 1", counted.visits)
			}
			counted.visits = 0
			if removed, err := changes.Prune(t.Context(), time.Now().UTC()); err != nil || removed != 0 {
				t.Fatalf("idle Prune = %d, %v", removed, err)
			}
			if counted.visits != 1 {
				t.Fatalf("idle Prune visited %d record(s), want 1", counted.visits)
			}

			// A scoped read filters records but still starts at the state.
			recordChangeRun(t, ts, changes, journal, 1)
			if err := store.Batch(t.Context(), ts.Store(), func(ctx context.Context) error {
				_, err := changes.Record(ctx, []Change{{Object: ChangeObjectFolder, Operation: ChangeUpdate, ID: "inbox", FolderID: "inbox"}})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			counted.visits = 0
			page, err = changes.List(t.Context(), ChangeScope{Object: ChangeObjectItem}, current, 100)
			if err != nil || len(page.Records) != 1 || page.NewState != encodeChangeState(journal+2) || counted.visits != 2 {
				t.Fatalf("scoped page = %+v, %v after %d visit(s)", page, err, counted.visits)
			}
		})
	}
}

// BenchmarkChangeJournalTail measures the journal reads a caught-up consumer
// makes, the head lookup and a read of the last few records, against journals
// of growing length. Their cost stays flat; the full key listing the reads
// used before grows with the journal.
func BenchmarkChangeJournalTail(b *testing.B) {
	for _, length := range []int{1_000, 10_000, 100_000} {
		backend, err := changeJournalEngines(b)[0].open(filepath.Join(b.TempDir(), "journal"))
		if err != nil {
			b.Fatal(err)
		}
		ts := model.NewTypedStore(backend, store.BackendPebble)
		changes := NewChangeStore(ts)
		if err := changes.Ensure(b.Context()); err != nil {
			b.Fatal(err)
		}
		for first := 0; first < length; first += 10_000 {
			recordChangeRun(b, ts, changes, first, min(10_000, length-first))
		}
		since := encodeChangeState(uint64(length - 10))
		b.Run(fmt.Sprintf("records=%d/head", length), func(b *testing.B) {
			for b.Loop() {
				if _, err := changes.CurrentState(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("records=%d/since-tail-10", length), func(b *testing.B) {
			for b.Loop() {
				page, err := changes.List(b.Context(), ChangeScope{Object: ChangeObjectItem}, since, 100)
				if err != nil || len(page.Records) != 10 {
					b.Fatalf("page = %d records, %v", len(page.Records), err)
				}
			}
		})
		b.Run(fmt.Sprintf("records=%d/full-listing-reference", length), func(b *testing.B) {
			for b.Loop() {
				if _, err := ts.Scan(b.Context(), model.NSChanges, changeRecordPrefix); err != nil {
					b.Fatal(err)
				}
			}
		})
		if err := backend.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
