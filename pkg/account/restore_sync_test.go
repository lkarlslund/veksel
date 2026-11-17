package account

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// syncState is the client-visible synchronization state of alice's account.
type syncState struct {
	folders map[string]model.Folder
	uids    map[string]uint32
	journal model.ChangeJournalMeta
	records int
}

func readSyncState(t *testing.T, generation *Generation) syncState {
	t.Helper()
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	state := syncState{folders: map[string]model.Folder{}, uids: map[string]uint32{}}
	folderIDs, err := typed.Scan(t.Context(), model.NSFolders, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range folderIDs {
		var folder model.Folder
		if err := typed.Get(t.Context(), model.NSFolders, id, &folder); err != nil {
			t.Fatal(err)
		}
		state.folders[id] = folder
	}
	itemIDs, err := typed.Scan(t.Context(), model.NSItems, "itm_")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range itemIDs {
		item, err := typed.ItemStore().Get(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		state.uids[id] = item.UID
	}
	if err := typed.Get(t.Context(), model.NSChanges, model.ChangeJournalMetaKey, &state.journal); err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	records, err := typed.Scan(t.Context(), model.NSChanges, model.ChangeJournalRecordPrefix)
	if err != nil {
		t.Fatal(err)
	}
	state.records = len(records)
	return state
}

func assertRebased(t *testing.T, before, after syncState) {
	t.Helper()
	if len(after.folders) != len(before.folders) || len(after.folders) == 0 {
		t.Fatalf("restored %d folders, want %d", len(after.folders), len(before.folders))
	}
	for id, old := range before.folders {
		restored := after.folders[id]
		// RFC 3501 §2.3.1.1: UIDs that may have been reused need a greater
		// UIDVALIDITY, or clients keep messages the restore does not hold.
		if restored.UIDValidity <= old.UIDValidity {
			t.Errorf("%s UIDVALIDITY %d, want greater than %d", old.Path, restored.UIDValidity, old.UIDValidity)
		}
		if restored.HighestModSeq < old.HighestModSeq+restoredSyncGap || restored.NextUID != old.NextUID {
			t.Errorf("%s counters = modseq %d next UID %d, want modseq >= %d and next UID %d", old.Path, restored.HighestModSeq, restored.NextUID, old.HighestModSeq+restoredSyncGap, old.NextUID)
		}
	}
	for id, uid := range before.uids {
		if after.uids[id] != uid {
			t.Errorf("item %s UID %d, want %d", id, after.uids[id], uid)
		}
	}
	// Every change state the lost installation issued must now be expired.
	if after.journal.Floor != after.journal.Current || after.journal.Current < before.journal.Current+restoredSyncGap || after.records != 0 {
		t.Errorf("restored journal = %+v with %d records, want floor = current >= %d and no records", after.journal, after.records, before.journal.Current+restoredSyncGap)
	}
}

func TestRestoreRebasesClientSyncState(t *testing.T) {
	manager := newEncryptionManager(t, t.TempDir(), nil)
	ensureAlice(t, manager)
	appendCanary(t, manager, "Subject: sync state")
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	// Journal entries as the folder space records them.
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	if err := typed.EnsureNamespace(t.Context(), model.NSChanges); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{model.ChangeJournalRecordPrefix + "00000000000000000001", model.ChangeJournalRecordPrefix + "00000000000000000002"} {
		if err := typed.Set(t.Context(), model.NSChanges, key, map[string]any{"changes": []any{}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.Set(t.Context(), model.NSChanges, model.ChangeJournalMetaKey, model.ChangeJournalMeta{Current: 2, EntryCount: 2}); err != nil {
		t.Fatal(err)
	}
	before := readSyncState(t, generation)
	release()
	var bundle bytes.Buffer
	if err := manager.Export(t.Context(), "alice", &bundle); err != nil {
		t.Fatal(err)
	}

	t.Run("installation restore", func(t *testing.T) {
		root := t.TempDir()
		if _, err := ImportAccount(t.Context(), root, bytes.NewReader(bundle.Bytes()), store.BackendPebble, nil); err != nil {
			t.Fatal(err)
		}
		restored := newEncryptionManager(t, root, nil)
		generation, release, err := restored.Acquire("alice")
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		assertRebased(t, before, readSyncState(t, generation))
	})
	t.Run("account restore", func(t *testing.T) {
		if report, err := manager.Restore(t.Context(), "alice", bytes.NewReader(bundle.Bytes()), store.BackendPebble); err != nil || !report.Healthy {
			t.Fatalf("Restore = %+v, %v", report, err)
		}
		generation, release, err := manager.Acquire("alice")
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		assertRebased(t, before, readSyncState(t, generation))
	})
}
