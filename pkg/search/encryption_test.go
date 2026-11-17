package search

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// TestEncryptedAccountsAreNotIndexed proves a full-text index, which holds
// plaintext terms, never survives on disk once an account is encrypted.
func TestEncryptedAccountsAreNotIndexed(t *testing.T) {
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
	ring, err := keyring.For(ctx, backend)
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := account.NewManager(t.TempDir(), store.BackendPebble, account.WithKeyRing(ring))
	if err != nil {
		t.Fatal(err)
	}
	defer accounts.Close()
	if err := system.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := system.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	user, _ := system.UserStore().Get(ctx, "alice")
	entry, _, err := accounts.Ensure(ctx, user, "alice@example.test", nil)
	if err != nil {
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
	if _, err := durable.CreateItem(ctx, access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: indexed\r\n\r\nplaintext-needle")}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, accounts, durable, engine, Config{Enabled: true, Workers: 1, BatchSize: 10, IdleClose: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	waitReady(t, manager, access, "alice")
	searchRoot := filepath.Join(entry.Path, "search")
	if _, err := os.Stat(searchRoot); err != nil {
		t.Fatalf("plaintext account has no index: %v", err)
	}

	job, err := accounts.StartConversionTo("alice", account.ConversionTarget{Engine: store.BackendPebble, Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		jobs, _ := accounts.Jobs("alice")
		if len(jobs) > 0 && jobs[0].ID == job.ID && jobs[0].Phase == account.ConversionCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("encryption conversion did not complete: %+v", jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := manager.Search(ctx, access, service.SearchQuery{Text: "plaintext-needle"}); !errors.Is(err, service.ErrSearchNotIndexed) {
		t.Fatalf("search of encrypted account = %v, want ErrSearchNotIndexed", err)
	}
	if _, err := os.Stat(searchRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext index survived encryption: %v", err)
	}
	status, err := manager.SearchStatus(ctx, access, "alice")
	if err != nil || status.State != notIndexedState {
		t.Fatalf("status = %+v, %v", status, err)
	}

	// An administrator may opt encrypted accounts back into indexing.
	config := Config{Enabled: true, Workers: 1, BatchSize: 10, IdleClose: time.Minute, IndexEncryptedAccounts: true}
	if err := manager.Reconfigure(config); err != nil {
		t.Fatal(err)
	}
	waitReady(t, manager, access, "alice")
	if page, err := manager.Search(ctx, access, service.SearchQuery{Text: "plaintext-needle"}); err != nil || len(page.Hits) != 1 {
		t.Fatalf("opted-in search = %+v, %v", page, err)
	}
	config.IndexEncryptedAccounts = false
	if err := manager.Reconfigure(config); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Search(ctx, access, service.SearchQuery{Text: "plaintext-needle"}); !errors.Is(err, service.ErrSearchNotIndexed) {
		t.Fatalf("search after opting out = %v", err)
	}
	// A catch-up started before the change finishes first; the next
	// maintenance pass then removes the index.
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(searchRoot); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("index survived opting out")
		}
		_, _ = manager.SearchStatus(ctx, access, "alice")
		time.Sleep(10 * time.Millisecond)
	}
}
