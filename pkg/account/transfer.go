package account

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// TransferStats describes a logical account copy.
type TransferStats struct {
	Namespaces          int    `json:"namespaces"`
	NamespacesCompleted int    `json:"namespaces_completed"`
	MetadataKeys        int    `json:"metadata_keys"`
	Items               int    `json:"items"`
	HistoryVersions     int    `json:"history_versions"`
	PayloadBytes        int64  `json:"payload_bytes"`
	Digest              string `json:"digest"`
}

// Transfer copies one logical account image without exposing either physical engine.
// It is safe to repeat against the same target generation.
func Transfer(ctx context.Context, source, target *Generation) (TransferStats, error) {
	return TransferWithProgress(ctx, source, target, nil)
}

// TransferWithProgress performs the same idempotent logical copy as Transfer
// and reports monotonic checkpoints. The callback may stop the transfer.
func TransferWithProgress(ctx context.Context, source, target *Generation, progress func(TransferStats) error) (TransferStats, error) {
	if source == nil || target == nil {
		return TransferStats{}, errors.New("source and target generations are required")
	}
	sourceModel := model.NewTypedStoreWithObjects(source.Index, source.Engine, source.Objects)
	targetModel := model.NewTypedStoreWithObjects(target.Index, target.Engine, target.Objects)

	namespaces, err := source.Index.ListNamespaces(ctx)
	if err != nil {
		return TransferStats{}, fmt.Errorf("list account namespaces: %w", err)
	}
	slices.Sort(namespaces)
	stats := TransferStats{Namespaces: len(namespaces)}
	for _, namespace := range namespaces {
		if err := ensureNamespace(ctx, target.Index, namespace); err != nil {
			return stats, err
		}
		if namespace == model.NSItems || namespace == model.NSItemHistory {
			continue
		}
		err := source.Index.Iterate(ctx, namespace, "", func(key string, value []byte) (bool, error) {
			if err := target.Index.Set(ctx, namespace, key, value); err != nil {
				return false, fmt.Errorf("copy account metadata %s/%s: %w", namespace, key, err)
			}
			stats.MetadataKeys++
			return true, nil
		})
		if err != nil {
			return stats, err
		}
		stats.NamespacesCompleted++
		if progress != nil {
			if err := progress(stats); err != nil {
				return stats, err
			}
		}
	}
	if slices.Contains(namespaces, model.NSItems) {
		itemIDs, err := source.Index.Scan(ctx, model.NSItems, "itm_")
		if err != nil {
			return stats, fmt.Errorf("list account items: %w", err)
		}
		slices.Sort(itemIDs)
		for _, itemID := range itemIDs {
			if err := ctx.Err(); err != nil {
				return stats, err
			}
			item, err := sourceModel.ItemStore().Get(ctx, itemID)
			if err != nil {
				return stats, fmt.Errorf("read account item %s: %w", itemID, err)
			}
			if err := targetModel.ItemStore().RestoreItem(ctx, item); err != nil {
				return stats, fmt.Errorf("write account item %s: %w", itemID, err)
			}
			stats.Items++
			stats.PayloadBytes += int64(len(item.Data))
			if progress != nil {
				if err := progress(stats); err != nil {
					return stats, err
				}
			}
		}
		stats.NamespacesCompleted++
	}
	if slices.Contains(namespaces, model.NSItemHistory) {
		versions, err := sourceModel.ItemHistoryStore().ListAll(ctx)
		if err != nil {
			return stats, fmt.Errorf("list account item history: %w", err)
		}
		for _, version := range versions {
			if err := ctx.Err(); err != nil {
				return stats, err
			}
			if err := targetModel.ItemHistoryStore().RestoreSnapshot(ctx, version); err != nil {
				return stats, fmt.Errorf("write account item history %s: %w", version.ID, err)
			}
			stats.HistoryVersions++
			stats.PayloadBytes += int64(len(version.Item.Data))
			if progress != nil {
				if err := progress(stats); err != nil {
					return stats, err
				}
			}
		}
		stats.NamespacesCompleted++
	}
	verification, err := VerifyTransfer(ctx, target)
	if err != nil {
		return stats, err
	}
	stats.Digest = verification.Digest
	return stats, nil
}

// VerifyTransfer computes a deterministic digest over logical metadata and item payloads.
func VerifyTransfer(ctx context.Context, generation *Generation) (TransferStats, error) {
	if generation == nil {
		return TransferStats{}, errors.New("generation is required")
	}
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	namespaces, err := generation.Index.ListNamespaces(ctx)
	if err != nil {
		return TransferStats{}, fmt.Errorf("list verification namespaces: %w", err)
	}
	slices.Sort(namespaces)
	hash := sha256.New()
	stats := TransferStats{Namespaces: len(namespaces)}
	for _, namespace := range namespaces {
		if namespace == model.NSItems || namespace == model.NSItemHistory {
			continue
		}
		err := generation.Index.Iterate(ctx, namespace, "", func(key string, value []byte) (bool, error) {
			writeDigestPart(hash, namespace, key, value)
			stats.MetadataKeys++
			return true, nil
		})
		if err != nil {
			return stats, fmt.Errorf("verify namespace %s: %w", namespace, err)
		}
	}
	if slices.Contains(namespaces, model.NSItems) {
		itemIDs, err := generation.Index.Scan(ctx, model.NSItems, "itm_")
		if err != nil {
			return stats, fmt.Errorf("list verification items: %w", err)
		}
		slices.Sort(itemIDs)
		for _, itemID := range itemIDs {
			item, err := typed.ItemStore().Get(ctx, itemID)
			if err != nil {
				return stats, fmt.Errorf("verify item %s: %w", itemID, err)
			}
			logical, err := json.Marshal(item)
			if err != nil {
				return stats, fmt.Errorf("encode verification item %s: %w", itemID, err)
			}
			writeDigestPart(hash, model.NSItems, itemID, logical)
			stats.Items++
			stats.PayloadBytes += int64(len(item.Data))
		}
	}
	if slices.Contains(namespaces, model.NSItemHistory) {
		versions, err := typed.ItemHistoryStore().ListAll(ctx)
		if err != nil {
			return stats, fmt.Errorf("verify item history: %w", err)
		}
		for _, version := range versions {
			logical, err := json.Marshal(version)
			if err != nil {
				return stats, fmt.Errorf("encode verification history %s: %w", version.ID, err)
			}
			writeDigestPart(hash, model.NSItemHistory, version.ID, logical)
			stats.HistoryVersions++
			stats.PayloadBytes += int64(len(version.Item.Data))
		}
	}
	stats.Digest = hex.EncodeToString(hash.Sum(nil))
	return stats, nil
}

func ensureNamespace(ctx context.Context, destination store.Store, namespace string) error {
	exists, err := destination.NamespaceExists(ctx, namespace)
	if err != nil {
		return fmt.Errorf("check target namespace %q: %w", namespace, err)
	}
	if exists {
		return nil
	}
	if err := destination.CreateNamespace(ctx, namespace); err != nil {
		return fmt.Errorf("create target namespace %q: %w", namespace, err)
	}
	return nil
}

func writeDigestPart(hash interface{ Write([]byte) (int, error) }, namespace, key string, value []byte) {
	_, _ = hash.Write([]byte(strings.Join([]string{namespace, key, fmt.Sprintf("%d", len(value))}, "\x00")))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
}
