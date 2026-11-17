package account

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestManagerSetRootsAddsRootsAndChangesPrimary(t *testing.T) {
	base := t.TempDir()
	first, second := filepath.Join(base, "one"), filepath.Join(base, "two")
	manager, err := NewManagerWithRoots([]Root{{ID: "one", Path: first}}, "one", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.SetRoots([]Root{{ID: "one", Path: first}, {ID: "two", Path: second}}, "two"); err != nil {
		t.Fatal(err)
	}
	if ids := rootIDs(manager.Roots()); !slices.Equal(ids, []string{"one", "two"}) {
		t.Fatalf("roots = %v", ids)
	}
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	entry, _, err := manager.Ensure(t.Context(), user, "alice@example.com", []string{"alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(entry.Path, second) {
		t.Fatalf("new account was not placed in the new primary root: %+v", entry)
	}
	if _, _, err := manager.Move(t.Context(), "alice", "one"); err != nil {
		t.Fatalf("original root was not selectable as a move target: %v", err)
	}
}

func TestManagerSetRootsRejectsRemovingRootWithAccounts(t *testing.T) {
	base := t.TempDir()
	first, second := filepath.Join(base, "one"), filepath.Join(base, "two")
	manager, err := NewManagerWithRoots([]Root{{ID: "one", Path: first}, {ID: "two", Path: second}}, "one", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if _, _, err := manager.Ensure(t.Context(), user, "alice@example.com", []string{"alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetRoots([]Root{{ID: "two", Path: second}}, "two"); err == nil || !strings.Contains(err.Error(), "still holds accounts") {
		t.Fatalf("removing a populated root error = %v", err)
	}
	if err := manager.SetRoots([]Root{{ID: "one", Path: filepath.Join(base, "elsewhere")}, {ID: "two", Path: second}}, "one"); err == nil {
		t.Fatal("repointing a populated root must fail")
	}
	if ids := rootIDs(manager.Roots()); !slices.Equal(ids, []string{"one", "two"}) || manager.Root() != first {
		t.Fatalf("failed update changed state: roots=%v primary=%s", ids, manager.Root())
	}
	if _, found := manager.ByLogin("alice"); !found {
		t.Fatal("account lost after rejected update")
	}
	if err := manager.SetRoots([]Root{{ID: "one", Path: first}}, "one"); err != nil {
		t.Fatalf("removing an empty root: %v", err)
	}
}

func rootIDs(roots []Root) []string {
	ids := make([]string, 0, len(roots))
	for _, root := range roots {
		ids = append(ids, root.ID)
	}
	return ids
}
