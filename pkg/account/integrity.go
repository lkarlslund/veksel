package account

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// IntegrityIssue is one independently actionable account consistency finding.
type IntegrityIssue struct {
	Code       string `json:"code"`
	ResourceID string `json:"resource_id,omitempty"`
	Message    string `json:"message"`
	Repairable bool   `json:"repairable"`
}

// IntegrityReport is a durable result from verifying or repairing one account.
type IntegrityReport struct {
	ID                  string           `json:"id"`
	AccountID           string           `json:"account_id"`
	Login               string           `json:"login"`
	Engine              store.Backend    `json:"engine"`
	Generation          string           `json:"generation"`
	Repair              bool             `json:"repair"`
	Healthy             bool             `json:"healthy"`
	Folders             int              `json:"folders"`
	Items               int              `json:"items"`
	HistoryVersions     int              `json:"history_versions"`
	HistoryLogicalBytes int64            `json:"history_logical_bytes"`
	LogicalBytes        int64            `json:"logical_bytes"`
	Repaired            int              `json:"repaired"`
	Digest              string           `json:"digest,omitempty"`
	Issues              []IntegrityIssue `json:"issues"`
	StartedAt           time.Time        `json:"started_at"`
	CompletedAt         time.Time        `json:"completed_at"`
}

// IntegrityProgress is a durable, payload-free snapshot suitable for
// lifecycle APIs while a verification or repair is running.
type IntegrityProgress struct {
	FoldersScanned int `json:"folders_scanned"`
	FoldersTotal   int `json:"folders_total"`
	ItemsScanned   int `json:"items_scanned"`
	ItemsTotal     int `json:"items_total"`
	IssuesFound    int `json:"issues_found"`
	RepairsApplied int `json:"repairs_applied"`
}

type itemIndexRepair struct {
	key    string
	value  string
	delete bool
}

type folderIndexRepair struct {
	key    string
	value  string
	delete bool
}

// CheckGeneration validates account truth and optionally repairs derived
// indexes and quota counters. Ambiguous payloads and index collisions are
// reported but never modified.
func CheckGeneration(ctx context.Context, entry Entry, generation *Generation, repair bool) (IntegrityReport, error) {
	return checkGeneration(ctx, entry, generation, repair, nil)
}

func checkGeneration(ctx context.Context, entry Entry, generation *Generation, repair bool, progress func(IntegrityProgress) error) (IntegrityReport, error) {
	id, err := randomID("chk")
	if err != nil {
		return IntegrityReport{}, err
	}
	report := IntegrityReport{ID: id, AccountID: entry.Manifest.ID, Login: entry.Manifest.Login, Engine: generation.Engine, Generation: generation.ID, Repair: repair, Issues: []IntegrityIssue{}, StartedAt: time.Now().UTC()}
	if err := entry.Manifest.Validate(); err != nil {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "manifest_invalid", Message: err.Error()})
	}
	verification, err := VerifyTransfer(ctx, generation)
	if err != nil {
		return report, fmt.Errorf("verify logical account image: %w", err)
	}
	report.Digest = verification.Digest
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	folderKeys, err := typed.Scan(ctx, model.NSFolders, "")
	if err != nil {
		return report, fmt.Errorf("scan account folders: %w", err)
	}
	slices.Sort(folderKeys)
	folders := make([]model.Folder, 0, len(folderKeys))
	folderByID := make(map[string]model.Folder, len(folderKeys))
	validPaths := make(map[string]bool, len(folderKeys))
	pathClaims := make(map[string][]string)
	currentProgress := IntegrityProgress{FoldersTotal: len(folderKeys)}
	for _, key := range folderKeys {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		currentProgress.FoldersScanned++
		var folder model.Folder
		if err := typed.Get(ctx, model.NSFolders, key, &folder); err != nil {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_record_unreadable", ResourceID: key, Message: err.Error()})
			continue
		}
		if folder.ID != key {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_identity_mismatch", ResourceID: key, Message: fmt.Sprintf("stored folder identity %q does not match its primary key", folder.ID)})
			continue
		}
		if folder.UserID != entry.Manifest.Login {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_owner_mismatch", ResourceID: folder.ID, Message: fmt.Sprintf("folder belongs to %s instead of this account", folder.UserID)})
			continue
		}
		folders = append(folders, folder)
		folderByID[folder.ID] = folder
		validPaths[folder.ID] = validFolderPath(folder)
		if !validPaths[folder.ID] {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_path_invalid", ResourceID: folder.ID, Message: "folder name and path are not a canonical non-empty hierarchy"})
		} else if folder.TrashedAt.IsZero() {
			pathClaims[folder.Path] = append(pathClaims[folder.Path], folder.ID)
		}
	}
	report.Folders = len(folders)
	pathCollisions := make(map[string]struct{})
	paths := make([]string, 0, len(pathClaims))
	for folderPath := range pathClaims {
		paths = append(paths, folderPath)
	}
	slices.Sort(paths)
	for _, folderPath := range paths {
		ids := pathClaims[folderPath]
		if len(ids) < 2 {
			continue
		}
		slices.Sort(ids)
		pathCollisions[folderPath] = struct{}{}
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_path_collision", ResourceID: ids[0], Message: fmt.Sprintf("live path %q is claimed by %s", folderPath, strings.Join(ids, ", "))})
	}
	for _, folder := range folders {
		if folder.ID == "" {
			continue
		}
		if folder.ParentID == "" {
			if validPaths[folder.ID] && strings.Contains(folder.Path, "/") {
				report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_hierarchy_mismatch", ResourceID: folder.ID, Message: "nested folder path has no parent"})
			}
			continue
		}
		parent, ok := folderByID[folder.ParentID]
		if !ok {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "missing_folder_parent", ResourceID: folder.ID, Message: "folder parent does not exist in this account"})
			continue
		}
		if parent.Type != folder.Type {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_parent_type_mismatch", ResourceID: folder.ID, Message: fmt.Sprintf("folder type %s differs from parent type %s", folder.Type, parent.Type)})
		}
		if validPaths[folder.ID] && validPaths[parent.ID] {
			separator := strings.LastIndex(folder.Path, "/")
			if separator < 0 {
				report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_hierarchy_mismatch", ResourceID: folder.ID, Message: "top-level folder path has a linked parent"})
			} else if expectedParentPath := folder.Path[:separator]; parent.Path != expectedParentPath {
				report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_hierarchy_mismatch", ResourceID: folder.ID, Message: fmt.Sprintf("path parent is %q but linked parent path is %q", expectedParentPath, parent.Path)})
			}
		}
	}
	for _, cycle := range folderParentCycles(folderByID) {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_parent_cycle", ResourceID: cycle[0], Message: "folder parent cycle includes " + strings.Join(cycle, ", ")})
	}
	if err := checkFolderIndexes(ctx, generation, typed, entry.Manifest.Login, folders, validPaths, pathCollisions, repair, &report, &currentProgress); err != nil {
		return report, err
	}
	itemIDs, err := generation.Index.Scan(ctx, model.NSItems, "itm_")
	if err != nil {
		return report, fmt.Errorf("scan account items: %w", err)
	}
	slices.Sort(itemIDs)
	currentProgress.ItemsTotal = len(itemIDs)
	if err := publishIntegrityProgress(progress, currentProgress, report); err != nil {
		return report, err
	}
	primaryItems := make(map[string]model.Item, len(itemIDs))
	type folderUsage struct {
		items int64
		bytes int64
	}
	folderUsageTruth := make(map[string]folderUsage, len(folders))
	expectedIndexes := make(map[string]string)
	indexConflicts := make(map[string][2]string)
	for _, itemID := range itemIDs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		currentProgress.ItemsScanned++
		metadata, metadataErr := typed.ItemStore().GetMetadata(ctx, itemID)
		if metadataErr != nil {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "item_metadata_unreadable", ResourceID: itemID, Message: metadataErr.Error()})
			if err := publishIntegrityProgress(progress, currentProgress, report); err != nil {
				return report, err
			}
			continue
		}
		primaryItems[itemID] = metadata
		report.Items++
		report.LogicalBytes += metadata.Size
		usage := folderUsageTruth[metadata.FolderID]
		usage.items++
		usage.bytes += metadata.Size
		folderUsageTruth[metadata.FolderID] = usage
		_, getErr := typed.ItemStore().Get(ctx, itemID)
		if getErr != nil {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "item_payload_unreadable", ResourceID: itemID, Message: getErr.Error()})
		}
		if _, ok := folderByID[metadata.FolderID]; !ok {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "item_folder_missing", ResourceID: metadata.ID, Message: "item references a missing folder"})
			if err := publishIntegrityProgress(progress, currentProgress, report); err != nil {
				return report, err
			}
			continue
		}
		folder, folderErr := typed.FolderStore().Get(ctx, metadata.FolderID)
		if folderErr != nil {
			return report, fmt.Errorf("read item folder %s: %w", metadata.FolderID, folderErr)
		}
		for key, value := range expectedIndexesForItem(metadata, folder.UserID) {
			if previous, exists := expectedIndexes[key]; exists && previous != value {
				indexConflicts[key] = [2]string{previous, value}
				delete(expectedIndexes, key)
				continue
			}
			if _, conflicted := indexConflicts[key]; !conflicted {
				expectedIndexes[key] = value
			}
		}
		if err := publishIntegrityProgress(progress, currentProgress, report); err != nil {
			return report, err
		}
	}
	historyUsageTruth := make(map[string]folderUsage, len(folders))
	historyExists, err := generation.Index.NamespaceExists(ctx, model.NSItemHistory)
	if err != nil {
		return report, fmt.Errorf("check account item history namespace: %w", err)
	}
	if historyExists {
		historyKeys, err := typed.Scan(ctx, model.NSItemHistory, "version:")
		if err != nil {
			return report, fmt.Errorf("scan account item history: %w", err)
		}
		slices.Sort(historyKeys)
		for _, key := range historyKeys {
			versionID := strings.TrimPrefix(key, "version:")
			version, versionErr := typed.ItemHistoryStore().GetByID(ctx, versionID)
			if versionErr != nil {
				report.Issues = append(report.Issues, IntegrityIssue{Code: "history_payload_unreadable", ResourceID: versionID, Message: versionErr.Error()})
				continue
			}
			report.HistoryVersions++
			report.HistoryLogicalBytes += version.Item.Size
			report.LogicalBytes += version.Item.Size
			usage := historyUsageTruth[version.FolderID]
			usage.items++
			usage.bytes += version.Item.Size
			historyUsageTruth[version.FolderID] = usage
			if _, ok := folderByID[version.FolderID]; !ok {
				report.Issues = append(report.Issues, IntegrityIssue{Code: "history_folder_missing", ResourceID: version.ID, Message: "history version references a missing folder"})
			}
			if version.ItemID != version.Item.ID || version.FolderID != version.Item.FolderID || version.UserID != entry.Manifest.Login {
				report.Issues = append(report.Issues, IntegrityIssue{Code: "history_scope_mismatch", ResourceID: version.ID, Message: "history version identity does not match its snapshot or account"})
			}
		}
	}
	conflictKeys := make([]string, 0, len(indexConflicts))
	for key := range indexConflicts {
		conflictKeys = append(conflictKeys, key)
	}
	slices.Sort(conflictKeys)
	for _, key := range conflictKeys {
		conflict := indexConflicts[key]
		report.Issues = append(report.Issues, IntegrityIssue{Code: "item_index_collision", ResourceID: key, Message: fmt.Sprintf("index is claimed by both %s and %s", conflict[0], conflict[1])})
	}
	indexRepairs, err := checkItemIndexes(ctx, typed, primaryItems, expectedIndexes, indexConflicts, &report)
	if err != nil {
		return report, err
	}
	if repair && len(indexRepairs) > 0 {
		if err := store.Batch(ctx, generation.Index, func(batchCtx context.Context) error {
			for _, operation := range indexRepairs {
				if operation.delete {
					if err := typed.Delete(batchCtx, model.NSItems, operation.key); err != nil && !errors.Is(err, store.ErrNotFound) {
						return err
					}
					continue
				}
				if err := typed.Set(batchCtx, model.NSItems, operation.key, operation.value); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return report, fmt.Errorf("repair item indexes: %w", err)
		}
		report.Repaired += len(indexRepairs)
		currentProgress.RepairsApplied = report.Repaired
	}
	for _, folder := range folders {
		usage := folderUsageTruth[folder.ID]
		if folder.UsageVersion == 1 && folder.ItemCount == usage.items && folder.LogicalBytes == usage.bytes {
			continue
		}
		report.Issues = append(report.Issues, IntegrityIssue{
			Code: "folder_usage_mismatch", ResourceID: folder.ID,
			Message:    fmt.Sprintf("stored=%d items/%d bytes actual=%d items/%d bytes", folder.ItemCount, folder.LogicalBytes, usage.items, usage.bytes),
			Repairable: true,
		})
		if repair {
			folder.ItemCount = usage.items
			folder.LogicalBytes = usage.bytes
			folder.UsageVersion = 1
			folder.UpdatedAt = time.Now().UTC()
			if err := typed.Set(ctx, model.NSFolders, folder.ID, folder); err != nil {
				return report, fmt.Errorf("repair folder usage counters: %w", err)
			}
			report.Repaired++
			currentProgress.RepairsApplied = report.Repaired
		}
	}
	for _, folder := range folders {
		usage := historyUsageTruth[folder.ID]
		legacyEmpty := folder.HistoryUsageVersion == 0 && folder.HistoryVersionCount == 0 && folder.HistoryLogicalBytes == 0 && usage.items == 0 && usage.bytes == 0
		if legacyEmpty || (folder.HistoryUsageVersion == 1 && folder.HistoryVersionCount == usage.items && folder.HistoryLogicalBytes == usage.bytes) {
			continue
		}
		report.Issues = append(report.Issues, IntegrityIssue{
			Code: "folder_history_usage_mismatch", ResourceID: folder.ID,
			Message:    fmt.Sprintf("stored=%d versions/%d bytes actual=%d versions/%d bytes", folder.HistoryVersionCount, folder.HistoryLogicalBytes, usage.items, usage.bytes),
			Repairable: true,
		})
		if repair {
			folder.HistoryVersionCount = usage.items
			folder.HistoryLogicalBytes = usage.bytes
			folder.HistoryUsageVersion = 1
			folder.UpdatedAt = time.Now().UTC()
			if err := typed.Set(ctx, model.NSFolders, folder.ID, folder); err != nil {
				return report, fmt.Errorf("repair folder history usage counters: %w", err)
			}
			report.Repaired++
			currentProgress.RepairsApplied = report.Repaired
		}
	}
	owner, err := typed.UserStore().Get(ctx, entry.Manifest.Login)
	if err != nil {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "account_owner_missing", ResourceID: entry.Manifest.Login, Message: err.Error()})
	} else if owner.CurrentItems != report.Items || owner.CurrentStorageBytes != report.LogicalBytes {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "quota_usage_mismatch", ResourceID: owner.ID, Message: fmt.Sprintf("stored=%d items/%d bytes actual=%d items/%d bytes", owner.CurrentItems, owner.CurrentStorageBytes, report.Items, report.LogicalBytes), Repairable: true})
		if repair {
			if err := typed.UserStore().Update(ctx, owner.ID, func(user *model.User) {
				user.CurrentItems = report.Items
				user.CurrentStorageBytes = report.LogicalBytes
			}); err != nil {
				return report, fmt.Errorf("repair quota counters: %w", err)
			}
			report.Repaired++
			currentProgress.RepairsApplied = report.Repaired
		}
	}
	report.Healthy = len(report.Issues) == 0 || (repair && report.Repaired == len(report.Issues))
	report.CompletedAt = time.Now().UTC()
	if err := publishIntegrityProgress(progress, currentProgress, report); err != nil {
		return report, err
	}
	return report, nil
}

func publishIntegrityProgress(callback func(IntegrityProgress) error, progress IntegrityProgress, report IntegrityReport) error {
	if callback == nil {
		return nil
	}
	progress.IssuesFound = len(report.Issues)
	progress.RepairsApplied = report.Repaired
	return callback(progress)
}

func validFolderPath(folder model.Folder) bool {
	if folder.Path == "" || folder.Name == "" || strings.Trim(folder.Path, "/") != folder.Path || strings.Contains(folder.Path, "//") {
		return false
	}
	separator := strings.LastIndex(folder.Path, "/")
	return folder.Name == folder.Path[separator+1:]
}

func folderParentCycles(folders map[string]model.Folder) [][]string {
	ids := make([]string, 0, len(folders))
	for id := range folders {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	done := make(map[string]struct{}, len(ids))
	cyclesByKey := make(map[string][]string)
	for _, start := range ids {
		if _, complete := done[start]; complete {
			continue
		}
		chain := make([]string, 0)
		positions := make(map[string]int)
		current := start
		for current != "" {
			if _, complete := done[current]; complete {
				break
			}
			folder, exists := folders[current]
			if !exists {
				break
			}
			if position, repeated := positions[current]; repeated {
				cycle := slices.Clone(chain[position:])
				slices.Sort(cycle)
				cyclesByKey[strings.Join(cycle, "\x00")] = cycle
				break
			}
			positions[current] = len(chain)
			chain = append(chain, current)
			current = folder.ParentID
		}
		for _, id := range chain {
			done[id] = struct{}{}
		}
	}
	keys := make([]string, 0, len(cyclesByKey))
	for key := range cyclesByKey {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	cycles := make([][]string, 0, len(keys))
	for _, key := range keys {
		cycles = append(cycles, cyclesByKey[key])
	}
	return cycles
}

func checkFolderIndexes(ctx context.Context, generation *Generation, typed *model.TypedStore, ownerID string, folders []model.Folder, validPaths map[string]bool, pathCollisions map[string]struct{}, repair bool, report *IntegrityReport, progress *IntegrityProgress) error {
	expected := make(map[string]string, len(folders)*2)
	for _, folder := range folders {
		if folder.ID == "" {
			continue
		}
		expected[model.FolderUserIndexKey(ownerID, folder.ID)] = folder.ID
		if folder.TrashedAt.IsZero() && validPaths[folder.ID] {
			if _, collision := pathCollisions[folder.Path]; !collision {
				expected[model.FolderPathIndexKey(ownerID, folder.Path)] = folder.ID
			}
		}
	}

	exists, err := generation.Index.NamespaceExists(ctx, model.NSFolderIndexes)
	if err != nil {
		return fmt.Errorf("check folder index namespace: %w", err)
	}
	if !exists {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_namespace_missing", Message: "derived folder index namespace is missing", Repairable: true})
		if !repair {
			return nil
		}
		if err := generation.Index.CreateNamespace(ctx, model.NSFolderIndexes); err != nil && !errors.Is(err, store.ErrExists) {
			return fmt.Errorf("recreate folder index namespace: %w", err)
		}
		if err := writeCompleteFolderIndexes(ctx, generation, typed, ownerID, expected); err != nil {
			return err
		}
		report.Repaired++
		progress.RepairsApplied = report.Repaired
		return nil
	}

	markerRepair := false
	var version int
	if err := typed.Get(ctx, model.NSFolderIndexes, model.FolderIndexMarkerKey(ownerID), &version); errors.Is(err, store.ErrNotFound) || (err == nil && version < model.FolderIndexVersion) {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_version_mismatch", Message: fmt.Sprintf("folder index version is %d instead of %d", version, model.FolderIndexVersion), Repairable: true})
		markerRepair = true
	} else if err != nil {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_version_unreadable", Message: "folder index version marker is unreadable", Repairable: true})
		markerRepair = true
	} else if version > model.FolderIndexVersion {
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_version_unsupported", Message: fmt.Sprintf("folder index version %d is newer than supported version %d", version, model.FolderIndexVersion)})
		return nil
	}

	repairs := make(map[string]folderIndexRepair)
	expectedKeys := make([]string, 0, len(expected))
	for key := range expected {
		expectedKeys = append(expectedKeys, key)
	}
	slices.Sort(expectedKeys)
	for _, key := range expectedKeys {
		want := expected[key]
		var got string
		if err := typed.Get(ctx, model.NSFolderIndexes, key, &got); errors.Is(err, store.ErrNotFound) {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_missing", ResourceID: key, Message: "derived folder index is missing", Repairable: true})
			repairs[key] = folderIndexRepair{key: key, value: want}
		} else if err != nil || got != want {
			message := fmt.Sprintf("derived folder index points to %q instead of %q", got, want)
			if err != nil {
				message = "derived folder index value is unreadable"
			}
			report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_mismatch", ResourceID: key, Message: message, Repairable: true})
			repairs[key] = folderIndexRepair{key: key, value: want}
		}
	}

	actualKeys := make([]string, 0)
	for _, prefix := range []string{model.FolderUserIndexPrefix(ownerID), model.FolderPathIndexPrefix(ownerID)} {
		keys, err := typed.Scan(ctx, model.NSFolderIndexes, prefix)
		if err != nil {
			return fmt.Errorf("scan folder index prefix %s: %w", prefix, err)
		}
		actualKeys = append(actualKeys, keys...)
	}
	slices.Sort(actualKeys)
	for _, key := range actualKeys {
		if _, wanted := expected[key]; wanted {
			continue
		}
		report.Issues = append(report.Issues, IntegrityIssue{Code: "folder_index_orphan", ResourceID: key, Message: "derived folder index is not backed by account folder truth", Repairable: true})
		repairs[key] = folderIndexRepair{key: key, delete: true}
	}

	if !repair || (len(repairs) == 0 && !markerRepair) {
		return nil
	}
	keys := make([]string, 0, len(repairs))
	for key := range repairs {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if err := store.Batch(ctx, generation.Index, func(batchCtx context.Context) error {
		for _, key := range keys {
			operation := repairs[key]
			if operation.delete {
				if err := typed.Delete(batchCtx, model.NSFolderIndexes, key); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
				continue
			}
			if err := typed.Set(batchCtx, model.NSFolderIndexes, key, operation.value); err != nil {
				return err
			}
		}
		if markerRepair {
			return typed.Set(batchCtx, model.NSFolderIndexes, model.FolderIndexMarkerKey(ownerID), model.FolderIndexVersion)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("repair folder indexes: %w", err)
	}
	report.Repaired += len(repairs)
	if markerRepair {
		report.Repaired++
	}
	progress.RepairsApplied = report.Repaired
	return nil
}

func writeCompleteFolderIndexes(ctx context.Context, generation *Generation, typed *model.TypedStore, ownerID string, expected map[string]string) error {
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if err := store.Batch(ctx, generation.Index, func(batchCtx context.Context) error {
		for _, key := range keys {
			if err := typed.Set(batchCtx, model.NSFolderIndexes, key, expected[key]); err != nil {
				return err
			}
		}
		return typed.Set(batchCtx, model.NSFolderIndexes, model.FolderIndexMarkerKey(ownerID), model.FolderIndexVersion)
	}); err != nil {
		return fmt.Errorf("rebuild folder indexes: %w", err)
	}
	return nil
}

func expectedIndexesForItem(item model.Item, ownerID string) map[string]string {
	result := map[string]string{
		model.ItemMemberKey(item.FolderID, item.ID): item.ID,
		model.ItemNameKey(item.FolderID, item.Name): item.ID,
	}
	if item.UID != 0 {
		result[model.UIDIndexKey(item.FolderID, item.UID)] = item.ID
	}
	if !item.InternalDate.IsZero() {
		result[model.DateIndexKey(item.FolderID, item.InternalDate.Format("20060102"), item.ID)] = item.ID
	}
	for namespace, externalID := range item.ExternalIDs {
		if namespace != "" && externalID != "" {
			result[model.ExternalItemIndexKey(item.FolderID, namespace, externalID)] = item.ID
		}
	}
	if !item.TrashedAt.IsZero() && ownerID != "" {
		result[model.TrashedItemKey(ownerID, item.ID)] = item.ID
	}
	return result
}

func checkItemIndexes(ctx context.Context, typed *model.TypedStore, primaryItems map[string]model.Item, expected map[string]string, conflicts map[string][2]string, report *IntegrityReport) ([]itemIndexRepair, error) {
	repairs := make([]itemIndexRepair, 0)
	expectedKeys := make([]string, 0, len(expected))
	for key := range expected {
		expectedKeys = append(expectedKeys, key)
	}
	slices.Sort(expectedKeys)
	for _, key := range expectedKeys {
		want := expected[key]
		var got string
		err := typed.Get(ctx, model.NSItems, key, &got)
		if errors.Is(err, store.ErrNotFound) {
			report.Issues = append(report.Issues, IntegrityIssue{Code: "item_index_missing", ResourceID: key, Message: "index entry is missing", Repairable: true})
			repairs = append(repairs, itemIndexRepair{key: key, value: want})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read item index %s: %w", key, err)
		}
		if got == want {
			continue
		}
		_, targetExists := primaryItems[got]
		repairable := !targetExists
		report.Issues = append(report.Issues, IntegrityIssue{Code: "item_index_mismatch", ResourceID: key, Message: fmt.Sprintf("stored target=%s expected=%s", got, want), Repairable: repairable})
		if repairable {
			repairs = append(repairs, itemIndexRepair{key: key, value: want})
		}
	}

	actualKeys := make([]string, 0)
	for _, prefix := range []string{"member:", "name:", "uid:", "date:", "external:", "trash:"} {
		keys, err := typed.Scan(ctx, model.NSItems, prefix)
		if err != nil {
			return nil, fmt.Errorf("scan item index prefix %s: %w", prefix, err)
		}
		actualKeys = append(actualKeys, keys...)
	}
	slices.Sort(actualKeys)
	for _, key := range actualKeys {
		if _, ok := expected[key]; ok {
			continue
		}
		if _, conflicted := conflicts[key]; conflicted {
			continue
		}
		var target string
		if err := typed.Get(ctx, model.NSItems, key, &target); err != nil {
			return nil, fmt.Errorf("read orphan item index %s: %w", key, err)
		}
		report.Issues = append(report.Issues, IntegrityIssue{Code: "item_index_orphan", ResourceID: key, Message: fmt.Sprintf("index target %s is not consistent with account items", target), Repairable: true})
		repairs = append(repairs, itemIndexRepair{key: key, delete: true})
	}
	return repairs, nil
}

func writeIntegrityReport(accountPath string, report IntegrityReport) error {
	if !validIntegrityReportID(report.ID) {
		return errors.New("invalid integrity report ID")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(accountPath, "maintenance", "checks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, report.ID+".json")
	if _, err := os.Lstat(path); err == nil {
		return store.ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".check-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

// IntegrityReport returns one completed durable check result for an account.
func (m *Manager) IntegrityReport(login, reportID string) (IntegrityReport, error) {
	entry, found := m.ByLogin(login)
	if !found {
		return IntegrityReport{}, store.ErrNotFound
	}
	report, err := readIntegrityReport(entry.Path, reportID)
	if err != nil {
		return IntegrityReport{}, err
	}
	if report.AccountID != entry.Manifest.ID || report.Login != entry.Manifest.Login {
		return IntegrityReport{}, errors.New("integrity report does not belong to account")
	}
	return report, nil
}

func readIntegrityReport(accountPath, reportID string) (IntegrityReport, error) {
	if !validIntegrityReportID(reportID) {
		return IntegrityReport{}, errors.New("invalid integrity report ID")
	}
	path := filepath.Join(accountPath, "maintenance", "checks", reportID+".json")
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return IntegrityReport{}, store.ErrNotFound
		}
		return IntegrityReport{}, err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestSize+1))
	decoder.DisallowUnknownFields()
	var report IntegrityReport
	if err := decoder.Decode(&report); err != nil {
		return IntegrityReport{}, err
	}
	if report.ID != reportID || !validIntegrityReportID(report.ID) {
		return IntegrityReport{}, errors.New("invalid integrity report identity")
	}
	return report, nil
}

func validIntegrityReportID(id string) bool {
	if !strings.HasPrefix(id, "chk_") || len(id) != len("chk_")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "chk_"))
	return err == nil
}
