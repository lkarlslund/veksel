package account

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestConcurrentQuotaReservationAcrossProductionEngines(t *testing.T) {
	for _, engine := range ProductionEngines {
		t.Run(string(engine), func(t *testing.T) {
			manifest, err := NewManifest("alice", "Alice", "", nil, engine, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			generation, err := CreateGeneration(t.TempDir()+"/"+manifest.ID, manifest.ActiveGeneration, engine)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = generation.Close() }()
			typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
			for _, namespace := range model.Namespaces() {
				if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			user := model.User{ID: "alice", DisplayName: "Alice", Enabled: true, MaxItems: 8, MaxStorageBytes: 8, CreatedAt: now, UpdatedAt: now}
			if err := typed.Put(t.Context(), model.NSUsers, user.ID, user); err != nil {
				t.Fatal(err)
			}
			if err := typed.FolderStore().CreateForUser(t.Context(), user.ID); err != nil {
				t.Fatal(err)
			}
			inbox, _ := typed.FolderStore().GetByPath(t.Context(), user.ID, "INBOX")
			var successes atomic.Int32
			var workers sync.WaitGroup
			for range 32 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					_, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte("x")})
					if err == nil {
						successes.Add(1)
						return
					}
					if !errors.Is(err, model.ErrQuotaExceeded) {
						t.Errorf("append error = %v", err)
					}
				}()
			}
			workers.Wait()
			if successes.Load() != 8 {
				t.Fatalf("successful reservations = %d, want 8", successes.Load())
			}
			quota, err := typed.UserStore().GetQuota(t.Context(), user.ID)
			if err != nil || quota.CurrentItems != 8 || quota.CurrentStorageBytes != 8 {
				t.Fatalf("quota = %+v, %v", quota, err)
			}
		})
	}
}

func TestDirectItemUpsertEnforcesQuotaAcrossProductionEngines(t *testing.T) {
	for _, engine := range ProductionEngines {
		t.Run(string(engine), func(t *testing.T) {
			manifest, err := NewManifest("alice", "Alice", "", nil, engine, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			generation, err := CreateGeneration(t.TempDir()+"/"+manifest.ID, manifest.ActiveGeneration, engine)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = generation.Close() }()
			typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
			for _, namespace := range model.Namespaces() {
				if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			user := model.User{ID: "alice", Enabled: true, MaxItems: 1, MaxStorageBytes: 5, CreatedAt: now, UpdatedAt: now}
			if err := typed.Put(t.Context(), model.NSUsers, user.ID, user); err != nil {
				t.Fatal(err)
			}
			if err := typed.FolderStore().CreateForUser(t.Context(), user.ID); err != nil {
				t.Fatal(err)
			}
			inbox, _ := typed.FolderStore().GetByPath(t.Context(), user.ID, "INBOX")
			item := model.Item{ID: "itm_quota-upsert", Name: "quota", FolderID: inbox.ID, Data: []byte("1234"), Size: 4, CreatedAt: now, UpdatedAt: now}
			if err := typed.ItemStore().SetItem(t.Context(), item); err != nil {
				t.Fatal(err)
			}
			item.Data, item.Size = []byte("12345"), 5
			if err := typed.ItemStore().SetItem(t.Context(), item); err != nil {
				t.Fatal(err)
			}
			item.Data, item.Size = []byte("123456"), 6
			if err := typed.ItemStore().SetItem(t.Context(), item); !errors.Is(err, model.ErrQuotaExceeded) {
				t.Fatalf("oversized replacement error = %v", err)
			}
			stored, err := typed.ItemStore().Get(t.Context(), item.ID)
			if err != nil || string(stored.Data) != "12345" {
				t.Fatalf("rolled-back item = %q, %v", stored.Data, err)
			}
			quota, err := typed.UserStore().GetQuota(t.Context(), user.ID)
			if err != nil || quota.CurrentItems != 1 || quota.CurrentStorageBytes != 5 {
				t.Fatalf("quota = %+v, %v", quota, err)
			}
		})
	}
}
