package search

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestWorkerPoolResizeKeepsWaiters(t *testing.T) {
	pool := newWorkerPool(1)
	ctx := t.Context()
	if err := pool.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	go func() {
		if pool.acquire(ctx) == nil {
			close(acquired)
		}
	}()
	select {
	case <-acquired:
		t.Fatal("second worker acquired beyond the limit")
	case <-time.After(30 * time.Millisecond):
	}
	pool.resize(2)
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("queued worker did not acquire after growing the pool")
	}
	pool.resize(1)
	pool.release()
	waiting, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if err := pool.acquire(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shrunk pool admitted a worker while full: %v", err)
	}
	pool.release()
	if err := pool.acquire(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSearchReconfigureDisablesAndResumesIndexingLive(t *testing.T) {
	ctx := t.Context()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	system := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := system.EnsureNamespace(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	accounts, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	user, _ := system.UserStore().Get(ctx, "alice")
	if _, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil); err != nil {
		t.Fatal(err)
	}
	engine := authz.New(system)
	routed, err := service.NewAccountFolderSpace(ctx, system, accounts, engine)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := service.NewDurableFolderSpace(ctx, backend, routed)
	if err != nil {
		t.Fatal(err)
	}
	access := service.UserAccess("alice", "test")
	create := func(subject string) {
		t.Helper()
		data := fmt.Sprintf("From: sender@example.test\r\nSubject: %s\r\n\r\nlive-reconfigure-marker body", subject)
		if _, err := durable.CreateItem(ctx, access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte(data)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		create(fmt.Sprintf("before %d", i))
	}
	base := Config{Enabled: true, Workers: 1, BatchSize: 2, IdleClose: time.Minute, QueryMaxResults: 100}
	manager, err := New(ctx, accounts, durable, engine, base)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	query := service.SearchQuery{Text: "live-reconfigure-marker"}
	waitReady(t, manager, access, "alice")
	waitHits(t, manager, access, query, 3)

	disabled := base
	disabled.Enabled = false
	if err := manager.Reconfigure(disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Search(ctx, access, query); !errors.Is(err, service.ErrSearchUnavailable) {
		t.Fatalf("disabled search error = %v, want ErrSearchUnavailable", err)
	}
	create("while disabled")
	time.Sleep(50 * time.Millisecond)
	if _, err := manager.Search(ctx, access, query); !errors.Is(err, service.ErrSearchUnavailable) {
		t.Fatalf("disabled search error = %v, want ErrSearchUnavailable", err)
	}

	enabled := base
	enabled.Workers = 3
	enabled.BatchSize = 1
	enabled.QueryMaxResults = 2
	if err := manager.Reconfigure(enabled); err != nil {
		t.Fatal(err)
	}
	if got := manager.settings(); got.Workers != 3 || got.BatchSize != 1 || got.QueryMaxResults != 2 {
		t.Fatalf("effective settings = %+v", got)
	}
	// The mutation made while disabled is caught up from the checkpoint and
	// the new query cap bounds a page that would otherwise hold four hits.
	waitHits(t, manager, access, service.SearchQuery{Text: "live-reconfigure-marker", Limit: 50}, 2)
	unlimited := enabled
	unlimited.QueryMaxResults = 100
	if err := manager.Reconfigure(unlimited); err != nil {
		t.Fatal(err)
	}
	waitHits(t, manager, access, service.SearchQuery{Text: "live-reconfigure-marker", Limit: 50}, 4)

	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconfigure(base); err == nil {
		t.Fatal("reconfigure after close succeeded")
	}
}
