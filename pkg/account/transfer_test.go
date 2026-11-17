package account

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
)

func TestTransferBetweenProductionEngines(t *testing.T) {
	for _, sourceEngine := range ProductionEngines {
		for _, targetEngine := range ProductionEngines {
			if sourceEngine == targetEngine {
				continue
			}
			t.Run(string(sourceEngine)+"_to_"+string(targetEngine), func(t *testing.T) {
				accountPath := t.TempDir()
				source, err := CreateGeneration(accountPath, "gen_11111111111111111111111111111111", sourceEngine)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				target, err := CreateGeneration(accountPath, "gen_22222222222222222222222222222222", targetEngine)
				if err != nil {
					t.Fatal(err)
				}
				defer target.Close()
				seedGeneration(t, source)

				sourceDigest, err := VerifyTransfer(t.Context(), source)
				if err != nil {
					t.Fatal(err)
				}
				var checkpoints []TransferStats
				stats, err := TransferWithProgress(t.Context(), source, target, func(progress TransferStats) error {
					checkpoints = append(checkpoints, progress)
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if stats.Items != 2 || stats.HistoryVersions != 1 || stats.PayloadBytes == 0 || stats.Digest != sourceDigest.Digest || stats.NamespacesCompleted != stats.Namespaces {
					t.Fatalf("Transfer stats: got %+v, source %+v", stats, sourceDigest)
				}
				if len(checkpoints) == 0 {
					t.Fatal("transfer emitted no progress checkpoints")
				}
				for index := 1; index < len(checkpoints); index++ {
					if checkpoints[index].NamespacesCompleted < checkpoints[index-1].NamespacesCompleted || checkpoints[index].Items < checkpoints[index-1].Items || checkpoints[index].PayloadBytes < checkpoints[index-1].PayloadBytes {
						t.Fatalf("non-monotonic checkpoints: %+v then %+v", checkpoints[index-1], checkpoints[index])
					}
				}
				// A repeated transfer must not append duplicate payload records.
				before, err := target.Objects.Scan(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Transfer(t.Context(), source, target); err != nil {
					t.Fatal(err)
				}
				after, err := target.Objects.Scan(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if len(after) != len(before) {
					t.Fatalf("repeated transfer appended objects: before=%d after=%d", len(before), len(after))
				}
			})
		}
	}
}

func TestTransferRetriesInjectedProductionEngineReadAndWriteFailures(t *testing.T) {
	for _, sourceEngine := range ProductionEngines {
		for _, targetEngine := range ProductionEngines {
			if sourceEngine == targetEngine {
				continue
			}
			t.Run(string(sourceEngine)+"_to_"+string(targetEngine), func(t *testing.T) {
				accountPath := t.TempDir()
				source, err := CreateGeneration(accountPath, "gen_55555555555555555555555555555555", sourceEngine)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = source.Close() }()
				target, err := CreateGeneration(accountPath, "gen_66666666666666666666666666666666", targetEngine)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = target.Close() }()
				seedGeneration(t, source)
				want, err := VerifyTransfer(t.Context(), source)
				if err != nil {
					t.Fatal(err)
				}

				sourceFaults := faultstore.New(source.Index)
				source.Index = sourceFaults
				sourceFaults.Fail("get", 1)
				if _, err := Transfer(t.Context(), source, target); !errors.Is(err, faultstore.ErrInjected) {
					t.Fatalf("injected source read = %v", err)
				}

				targetFaults := faultstore.New(target.Index)
				target.Index = targetFaults
				targetFaults.Fail("set", 2)
				if _, err := Transfer(t.Context(), source, target); !errors.Is(err, faultstore.ErrInjected) {
					t.Fatalf("injected target write = %v", err)
				}
				targetFaults.Fail("", 0)
				got, err := Transfer(t.Context(), source, target)
				if err != nil {
					t.Fatal(err)
				}
				if !sameTransferImage(want, got) {
					t.Fatalf("retried transfer = %#v, want %#v", got, want)
				}
			})
		}
	}
}

func seedGeneration(t *testing.T, generation *Generation) {
	t.Helper()
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSACL, model.NSMetadata} {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "acc_owner", "Owner", "password"); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "acc_owner"); err != nil {
		t.Fatal(err)
	}
	inputs := []model.Item{
		{Data: []byte("Subject: one\r\n\r\nfirst"), Flags: []string{model.FlagSeen}, InternalDate: time.Unix(100, 0).UTC(), ExternalIDs: map[string]string{"sync": "one"}},
		{Data: []byte("Subject: two\r\n\r\nsecond"), Flags: []string{model.FlagFlagged}, InternalDate: time.Unix(200, 0).UTC(), ExternalIDs: map[string]string{"sync": "two"}},
	}
	var first model.Item
	for _, input := range inputs {
		created, err := typed.ItemStore().AppendItem(t.Context(), model.InboxFolderID("acc_owner"), input)
		if err != nil {
			t.Fatal(err)
		}
		if first.ID == "" {
			first = created
		}
	}
	inbox, err := typed.FolderStore().Get(t.Context(), model.InboxFolderID("acc_owner"))
	if err != nil {
		t.Fatal(err)
	}
	inbox.History = model.ItemHistoryPolicy{Enabled: true, RetentionDays: 30, MaxVersions: 10}
	if err := typed.Set(t.Context(), model.NSFolders, inbox.ID, inbox); err != nil {
		t.Fatal(err)
	}
	if _, captured, err := typed.ItemHistoryStore().Capture(t.Context(), first, model.ItemHistoryUpdate); err != nil || !captured {
		t.Fatalf("capture history: captured=%t err=%v", captured, err)
	}
	if err := typed.Set(t.Context(), model.NSMetadata, "custom", map[string]any{"enabled": true}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferPreservesLogicalPayload(t *testing.T) {
	accountPath := t.TempDir()
	source, err := CreateGeneration(accountPath, "gen_33333333333333333333333333333333", store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := CreateGeneration(accountPath, "gen_44444444444444444444444444444444", store.BackendBadger)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	seedGeneration(t, source)
	if _, err := Transfer(t.Context(), source, target); err != nil {
		t.Fatal(err)
	}
	sourceModel := model.NewTypedStoreWithObjects(source.Index, source.Engine, source.Objects)
	targetModel := model.NewTypedStoreWithObjects(target.Index, target.Engine, target.Objects)
	ids, err := source.Index.Scan(t.Context(), model.NSItems, "itm_")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		sourceItem, err := sourceModel.ItemStore().Get(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		targetItem, err := targetModel.ItemStore().Get(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sourceItem.Data, targetItem.Data) || sourceItem.UID != targetItem.UID || sourceItem.ModSeq != targetItem.ModSeq {
			t.Fatalf("item %s differs: source=%+v target=%+v", id, sourceItem, targetItem)
		}
	}
	sourceVersions, err := sourceModel.ItemHistoryStore().ListAll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	targetVersions, err := targetModel.ItemHistoryStore().ListAll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceVersions) != 1 || len(targetVersions) != 1 || !bytes.Equal(sourceVersions[0].Item.Data, targetVersions[0].Item.Data) {
		t.Fatalf("history differs: source=%+v target=%+v", sourceVersions, targetVersions)
	}
}
