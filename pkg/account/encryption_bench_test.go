package account

import (
	"bytes"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// BenchmarkEncryptedItemPaths measures the item list and read paths of one
// Pebble account with and without encryption at rest.
func BenchmarkEncryptedItemPaths(b *testing.B) {
	const items = 500
	backend, err := jsonstore.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()
	ring, err := keyring.Load(b.Context(), backend)
	if err != nil {
		b.Fatal(err)
	}
	payload := append([]byte("Subject: benchmark\r\n\r\n"), bytes.Repeat([]byte("body text "), 400)...)
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "encrypted"
		}
		manager, err := NewManager(b.TempDir(), store.BackendPebble, WithKeyRing(ring))
		if err != nil {
			b.Fatal(err)
		}
		if err := manager.SetEncryptionDefault(encrypted); err != nil {
			b.Fatal(err)
		}
		now := time.Now().UTC()
		if _, _, err := manager.Ensure(b.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", nil); err != nil {
			b.Fatal(err)
		}
		generation, release, err := manager.Acquire("alice")
		if err != nil {
			b.Fatal(err)
		}
		typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
		inbox, err := typed.FolderStore().GetByPath(b.Context(), "alice", "INBOX")
		if err != nil {
			b.Fatal(err)
		}
		ids := make([]string, 0, items)
		for range items {
			item, err := typed.ItemStore().AppendItem(b.Context(), inbox.ID, model.Item{Data: payload})
			if err != nil {
				b.Fatal(err)
			}
			ids = append(ids, item.ID)
		}
		b.Run(name+"/list-page-metadata", func(b *testing.B) {
			for b.Loop() {
				if _, _, _, err := typed.ItemStore().ListMetadataPage(b.Context(), inbox.ID, 0, 100); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(name+"/list-page-with-payload", func(b *testing.B) {
			for b.Loop() {
				if _, _, _, err := typed.ItemStore().ListPage(b.Context(), inbox.ID, 0, 100); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(name+"/get-item", func(b *testing.B) {
			for i := 0; b.Loop(); i++ {
				if _, err := typed.ItemStore().Get(b.Context(), ids[i%items]); err != nil {
					b.Fatal(err)
				}
			}
		})
		release()
		_ = manager.Close()
	}
}
