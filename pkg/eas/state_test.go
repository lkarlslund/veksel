package eas

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func testStateBackends(t *testing.T, test func(*testing.T, store.Store)) {
	t.Helper()
	factories := map[string]func(string) (store.Store, error){
		"json":   func(path string) (store.Store, error) { return jsonstore.New(path) },
		"pebble": func(path string) (store.Store, error) { return pebblestore.New(path) },
		"badger": func(path string) (store.Store, error) { return badgerstore.New(path) },
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			backend, err := factory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if closer, ok := backend.(io.Closer); ok {
				t.Cleanup(func() { _ = closer.Close() })
			}
			test(t, backend)
		})
	}
}

func TestStateStoreInventoryLegacyIsolationOrderingAndRemoval(t *testing.T) {
	testStateBackends(t, func(t *testing.T, backend store.Store) {
		registry, err := NewStateStore(t.Context(), backend)
		if err != nil {
			t.Fatal(err)
		}
		older := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		legacy, err := json.Marshal(DeviceState{UserID: "alice", DeviceID: "OLD1", DeviceType: "Phone", UpdatedAt: older})
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.Set(t.Context(), stateNamespace, "alice/OLD1", legacy); err != nil {
			t.Fatal(err)
		}
		if err := registry.Save(t.Context(), DeviceState{UserID: "alice", DeviceID: "NEW2", DeviceType: "Tablet", FirstSeenAt: older, LastSeenAt: older.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := registry.Save(t.Context(), DeviceState{UserID: "bob", DeviceID: "OTHER3", DeviceType: "Hidden"}); err != nil {
			t.Fatal(err)
		}

		devices, err := registry.List(t.Context(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) != 2 || devices[0].DeviceID != "NEW2" || devices[1].DeviceID != "OLD1" {
			t.Fatalf("devices = %#v", devices)
		}
		if !devices[1].FirstSeenAt.Equal(older) || !devices[1].LastSeenAt.Equal(older) {
			t.Fatalf("legacy timestamps = %v / %v, want %v", devices[1].FirstSeenAt, devices[1].LastSeenAt, older)
		}
		removed, err := registry.Remove(t.Context(), "alice", "OLD1")
		if err != nil || !removed {
			t.Fatalf("first remove = %v, %v", removed, err)
		}
		removed, err = registry.Remove(t.Context(), "alice", "OLD1")
		if err != nil || removed {
			t.Fatalf("idempotent remove = %v, %v", removed, err)
		}
		bob, err := registry.List(t.Context(), "bob")
		if err != nil || len(bob) != 1 || bob[0].DeviceID != "OTHER3" {
			t.Fatalf("bob inventory = %#v, %v", bob, err)
		}
	})
}

func TestStateStoreRemovalWaitsForInFlightDeviceUpdate(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	registry, err := NewStateStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, updated := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		updated <- registry.Update(context.Background(), "alice", "PHONE1", func(state *DeviceState) error {
			close(entered)
			<-release
			state.LastCommand = "Sync"
			return nil
		})
	}()
	<-entered
	other := make(chan error, 1)
	go func() {
		other <- registry.Update(context.Background(), "alice", "TABLET2", func(state *DeviceState) error {
			state.LastCommand = "Ping"
			return nil
		})
	}()
	select {
	case err := <-other:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("an unrelated device was serialized behind the in-flight partnership")
	}
	removed := make(chan error, 1)
	go func() {
		_, err := registry.Remove(context.Background(), "alice", "PHONE1")
		removed <- err
	}()
	select {
	case err := <-removed:
		t.Fatalf("remove completed before in-flight update: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	devices, err := registry.List(t.Context(), "alice")
	if err != nil || len(devices) != 1 || devices[0].DeviceID != "TABLET2" {
		t.Fatalf("inventory after removal = %#v, %v", devices, err)
	}
}

// TestDeviceStateReadsBareEchoIDs keeps partnership states written with
// echoes as bare item IDs loadable.
func TestDeviceStateReadsBareEchoIDs(t *testing.T) {
	var state DeviceState
	if err := json.Unmarshal([]byte(`{"collection_echoes":{"f1":["itm_a",{"id":"itm_b","mod_seq":4}]}}`), &state); err != nil {
		t.Fatal(err)
	}
	if echoes := state.CollectionEchoes["f1"]; len(echoes) != 2 || echoes[0].ID != "itm_a" || echoes[1].ModSeq != 4 {
		t.Fatalf("echoes = %#v", echoes)
	}
}
