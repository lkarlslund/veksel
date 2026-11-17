package account

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type recordingRelocationObserver struct {
	manager  *Manager
	events   []string
	paths    []string
	retained string
	fenced   bool
}

func (o *recordingRelocationObserver) AccountRelocating(login, path string) {
	o.events = append(o.events, "relocating:"+login)
	o.paths = append(o.paths, path)
	if _, err := os.Stat(path); err != nil {
		o.events = append(o.events, "source-missing")
	}
	_, release, err := o.manager.Acquire(login)
	if err == nil {
		release()
	}
	o.fenced = err != nil
}

func (o *recordingRelocationObserver) AccountRelocated(login, path, retained string) {
	o.events = append(o.events, "relocated:"+login)
	o.paths = append(o.paths, path)
	o.retained = retained
}

// TestMoveNotifiesRelocationObservers checks the contract derived per-account
// state relies on: observers hear of a move while the account is fenced and
// its directory is still in place, and afterwards learn the final path and
// where the previous contents were retained.
func TestMoveNotifiesRelocationObservers(t *testing.T) {
	base := t.TempDir()
	manager, err := NewManagerWithRoots([]Root{{ID: "fast", Path: filepath.Join(base, "fast")}, {ID: "bulk", Path: filepath.Join(base, "bulk")}}, "fast", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	now := time.Now().UTC()
	user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, CreatedAt: now, UpdatedAt: now}
	source, _, err := manager.Ensure(t.Context(), user, "alice@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	observer := &recordingRelocationObserver{manager: manager}
	stop := manager.OnRelocation(observer)
	moved, _, err := manager.Move(t.Context(), "alice", "bulk")
	if err != nil {
		t.Fatal(err)
	}
	if len(observer.events) != 2 || observer.events[0] != "relocating:alice" || observer.events[1] != "relocated:alice" {
		t.Fatalf("observer events = %v", observer.events)
	}
	if !observer.fenced {
		t.Fatal("observer ran before the account was fenced")
	}
	if observer.paths[0] != source.Path || observer.paths[1] != moved.Path {
		t.Fatalf("observer paths = %v, want %s then %s", observer.paths, source.Path, moved.Path)
	}
	if observer.retained == "" || filepath.Dir(observer.retained) != filepath.Dir(source.Path) {
		t.Fatalf("retained path = %q", observer.retained)
	}
	if _, err := os.Stat(observer.retained); err != nil {
		t.Fatalf("retained directory: %v", err)
	}

	// A failed move reports the unchanged path and nothing retained.
	if _, _, err := manager.Move(t.Context(), "alice", "bulk"); err == nil {
		t.Fatal("move to the current root succeeded")
	}
	if err := os.MkdirAll(filepath.Join(base, "fast", moved.Manifest.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	observer.events, observer.paths = nil, nil
	if _, _, err := manager.Move(t.Context(), "alice", "fast"); err == nil {
		t.Fatal("move onto an existing account path succeeded")
	}
	if len(observer.events) != 2 || observer.paths[1] != moved.Path || observer.retained != "" {
		t.Fatalf("failed move notified %v %v retained %q", observer.events, observer.paths, observer.retained)
	}

	stop()
	observer.events = nil
	if err := os.Remove(filepath.Join(base, "fast", moved.Manifest.ID)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Move(t.Context(), "alice", "fast"); err != nil {
		t.Fatal(err)
	}
	if len(observer.events) != 0 {
		t.Fatalf("unregistered observer was notified: %v", observer.events)
	}
}
