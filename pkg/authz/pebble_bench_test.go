package authz

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// BenchmarkCheckPebbleSystemStore measures one non-owner decision against a
// Pebble system store whose co-resident namespaces hold an installation-sized
// history, half of it already pruned. "idle" shows that namespace-bounded
// range reads do not grow with unrelated data; "concurrent-synced-writes"
// shows the decision while another goroutine commits durable writes, as the
// audit log, sessions, and metrics do on a live server.
//
// b.TempDir lives under TMPDIR, which is usually tmpfs where fsync is free.
// Run with TMPDIR on a disk-backed filesystem to measure real WAL syncs:
//
//	TMPDIR=$PWD/.bench go test ./pkg/authz -run '^$' -bench CheckPebbleSystemStore
func BenchmarkCheckPebbleSystemStore(b *testing.B) {
	ctx := context.Background()
	backend, err := pebblestore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(ctx, namespace); err != nil {
			b.Fatal(err)
		}
	}
	for _, id := range []string{"alice", "bob"} {
		if err := model.NewUserStore(ts).Create(ctx, id, id, "password123"); err != nil {
			b.Fatal(err)
		}
	}
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	bobAccount := model.ResourceRef{Kind: model.ResourceAccount, ID: "bob"}
	if _, err := model.NewPolicyStore(ts).Create(ctx, model.PolicyBinding{
		Principal: alice, Resource: bobAccount, Effect: model.EffectAllow,
		Permissions: []string{string(FolderItemsRead)}, Inheritance: model.InheritanceSubtree, GrantedBy: "bob",
	}); err != nil {
		b.Fatal(err)
	}
	const records = 100_000
	payload := []byte(`{"detail":"` + strings.Repeat("x", 300) + `"}`)
	for _, namespace := range []string{model.NSAudit, model.NSMessageTrace, model.NSQueue, model.NSItemHistory} {
		for start := 0; start < records; start += 10_000 {
			if err := store.Batch(ctx, backend, func(batchCtx context.Context) error {
				for index := start; index < start+10_000; index++ {
					if err := backend.Set(batchCtx, namespace, fmt.Sprintf("%020d", index), payload); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
		if err := store.Batch(ctx, backend, func(batchCtx context.Context) error {
			for index := range records / 2 {
				if err := backend.Delete(batchCtx, namespace, fmt.Sprintf("%020d", index)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	engine := New(ts)
	request := Request{Actor: alice, Action: FolderItemsRead, Resource: bobAccount}
	check := func(b *testing.B) {
		for b.Loop() {
			decision, err := engine.Check(ctx, request)
			if err != nil || !decision.Allowed {
				b.Fatalf("check: %+v %v", decision, err)
			}
		}
	}

	b.Run("idle", check)
	b.Run("concurrent-synced-writes", func(b *testing.B) {
		stop := make(chan struct{})
		var writer sync.WaitGroup
		writer.Go(func() {
			for index := 0; ; index++ {
				select {
				case <-stop:
					return
				default:
				}
				if err := backend.Set(ctx, model.NSAudit, fmt.Sprintf("w%019d", index), payload); err != nil {
					b.Error(err)
					return
				}
			}
		})
		check(b)
		close(stop)
		writer.Wait()
	})
}
