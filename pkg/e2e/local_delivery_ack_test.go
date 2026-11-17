package e2e

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestLocalDeliveryAcknowledgementLossDoesNotDuplicate(t *testing.T) {
	for _, engine := range []store.Backend{store.BackendPebble, store.BackendBadger} {
		t.Run(string(engine), func(t *testing.T) {
			backend := openDeliveryStore(t, engine)
			defer func() { _ = backend.Close() }()
			typed := model.NewTypedStore(backend, engine)
			for _, namespace := range model.Namespaces() {
				if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
					t.Fatal(err)
				}
			}
			if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
				t.Fatal(err)
			}
			if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
				t.Fatal(err)
			}
			space := service.NewFolderSpace(typed, authz.New(typed))
			access := service.UserAccess("alice", "system-queue-test")
			inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
			if err != nil {
				t.Fatal(err)
			}
			var attempts atomic.Int32
			mailQueue, err := queue.NewPersistent(t.Context(), backend, &queue.Config{
				Workers: 1, ProcessPeriod: time.Millisecond, RetryInitial: time.Millisecond, RetryMax: time.Millisecond,
				Delivery: func(ctx context.Context, message *queue.Message) error {
					_, createErr := service.CreateItemIdempotent(ctx, space, access, inbox.ID, queue.DeliveryExternalIDNamespace, message.ID, service.ItemInput{Data: message.Content})
					if createErr != nil {
						return createErr
					}
					if attempts.Add(1) == 1 {
						return &queue.DeliveryError{Class: queue.DeliveryTemporary, Response: "acknowledgement lost after local commit"}
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer mailQueue.Close()
			if err := mailQueue.Enqueue(&queue.Message{ID: "accepted-local", Recipient: "alice@example.test", Content: []byte("Subject: once\r\n\r\nbody")}); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for mailQueue.Get("accepted-local") != nil && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if mailQueue.Get("accepted-local") != nil || attempts.Load() != 2 {
				t.Fatalf("queue did not converge after acknowledgement loss: attempts=%d message=%+v", attempts.Load(), mailQueue.Get("accepted-local"))
			}
			items, err := space.ListItems(t.Context(), access, inbox.ID, service.ItemQuery{})
			if err != nil || len(items) != 1 || string(items[0].Data) != "Subject: once\r\n\r\nbody" {
				t.Fatalf("delivered items = %+v, %v", items, err)
			}
		})
	}
}

func openDeliveryStore(t *testing.T, engine store.Backend) store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	var (
		backend store.Store
		err     error
	)
	if engine == store.BackendPebble {
		backend, err = pebblestore.New(path)
	} else {
		backend, err = badgerstore.New(path)
	}
	if err != nil {
		t.Fatal(err)
	}
	return backend
}
