package folderindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestSnapshotsAreStoredBinaryWithoutMaterializationsAndLegacyJSONStillLoads(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	space := &testSpace{folder: model.Folder{ID: "folder", HighestModSeq: 1, ItemCount: 1, Indexes: []model.FolderIndex{{Name: "test-name", Version: 3}}}, items: []model.Item{{ID: "item", Name: "value"}}}
	access := service.UserAccess("alice", "test")
	key := indexKey("test-name", "folder")
	stored := func() []byte {
		raw, err := backend.Get(t.Context(), namespace, key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// A legacy JSON snapshot, materializations included, loads without a
	// rebuild and is rewritten in the binary encoding without them.
	legacy, err := json.Marshal(map[string]any{"definition": "test-name", "version": 3, "folder_id": "folder", "highest_mod_seq": 1, "item_count": 1,
		"buckets": map[string]any{"all": []any{map[string]any{"item_id": "item", "keys": []string{"all"}, "value": "value"}}}, "materialized": map[string]any{"2026-01": []any{map[string]any{"item_id": "item"}}}, "built_at": time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureNamespace(t.Context(), backend); err != nil {
		t.Fatal(err)
	}
	if err := backend.Set(t.Context(), namespace, key, legacy); err != nil {
		t.Fatal(err)
	}
	err = New(backend).WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(snapshot *Snapshot) error {
		if len(snapshot.Buckets["all"]) != 1 || len(snapshot.Materialized) != 0 {
			t.Fatalf("legacy snapshot buckets=%v materialized=%v", snapshot.Buckets, snapshot.Materialized)
		}
		snapshot.Materialized = map[string][]Document{"2026-01": {DecodedDocument("item", "occurrence")}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if space.pages != 0 || !bytes.HasPrefix(stored(), []byte(binaryPrefix)) || bytes.Contains(stored(), []byte("occurrence")) {
		t.Fatalf("legacy snapshot rebuilt=%d binary=%t", space.pages, bytes.HasPrefix(stored(), []byte(binaryPrefix)))
	}
	// The binary snapshot loads in a new process, and an empty projection
	// accepts caught-up documents.
	space.items = nil
	space.folder.HighestModSeq, space.folder.ItemCount = 2, 0
	if err := New(backend).WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	err = New(backend).WithSnapshot(t.Context(), space, access, space.folder, testDefinition{}, func(snapshot *Snapshot) error {
		if snapshot.Buckets == nil || len(snapshot.Buckets["all"]) != 0 {
			t.Fatalf("empty binary snapshot buckets=%v", snapshot.Buckets)
		}
		addDocument(snapshot, Document{ItemID: "new", Keys: []string{"all"}})
		return nil
	})
	if err != nil || space.pages != 1 {
		t.Fatalf("empty snapshot reload err=%v pages=%d", err, space.pages)
	}
}

func TestBinarySnapshotOmitsMaterializations(t *testing.T) {
	snapshot := Snapshot{Definition: "test-name", Buckets: map[string][]Document{}, Materialized: map[string][]Document{"2026-01": {DecodedDocument("item", "occurrence")}, "2026-02": {}}}
	raw, err := encodeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	// A stored month would be treated as expanded after a restart while its
	// documents carry no value.
	if len(decoded.Materialized) != 0 {
		t.Fatalf("decoded materializations = %v", decoded.Materialized)
	}
	if len(snapshot.Materialized) != 2 {
		t.Fatalf("encoding changed the caller's materializations: %v", snapshot.Materialized)
	}
}

type parallelDefinition struct{ calls *atomic.Int64 }

func (parallelDefinition) Name() string          { return "test-name" }
func (parallelDefinition) Version() int          { return 3 }
func (parallelDefinition) ParallelProject() bool { return true }
func (d parallelDefinition) Project(item model.Item) (Document, error) {
	d.calls.Add(1)
	if item.UID%7 == 0 {
		return Document{}, fmt.Errorf("unprojectable %d", item.UID)
	}
	return Document{Keys: []string{fmt.Sprint(item.UID % 3)}}, nil
}

func TestParallelProjectionKeepsEnumerationOrder(t *testing.T) {
	items := make([]model.Item, 0, 1000)
	for n := range 1000 {
		items = append(items, model.Item{ID: fmt.Sprintf("item-%04d", n), UID: uint32(n + 1)})
	}
	calls := &atomic.Int64{}
	documents := project(parallelDefinition{calls: calls}, items, 4)
	var want []string
	for _, item := range items {
		if item.UID%7 != 0 {
			want = append(want, item.ID)
		}
	}
	got := make([]string, 0, len(documents))
	for _, document := range documents {
		got = append(got, document.ItemID)
	}
	if !slices.Equal(got, want) || calls.Load() != int64(len(items)) {
		t.Fatalf("parallel projection order differs or skipped items: calls=%d got %d want %d", calls.Load(), len(got), len(want))
	}
	if workers := projectWorkers(parallelDefinition{calls: calls}); workers < 1 || workers > maxProjectWorkers {
		t.Fatalf("parallel workers=%d", workers)
	}
	if workers := projectWorkers(testDefinition{}); workers != 1 {
		t.Fatalf("sequential definition workers=%d", workers)
	}
}
