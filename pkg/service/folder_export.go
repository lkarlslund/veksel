package service

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	FolderExportFormat   = "veksel-folder-export"
	FolderExportVersion  = 1
	AccountExportFormat  = "veksel-account-export"
	AccountExportVersion = 1
	folderExportPageSize = 200
)

// FolderExportManifest describes a portable, exact-folder archive. Manifest
// item records deliberately omit backend and synchronization identifiers.
type FolderExportManifest struct {
	Format     string                     `json:"format"`
	Version    int                        `json:"version"`
	ExportedAt time.Time                  `json:"exported_at"`
	Folder     FolderExportFolder         `json:"folder"`
	Items      []FolderExportManifestItem `json:"items"`
}

type FolderExportFolder struct {
	ID           string           `json:"id"`
	OwnerID      string           `json:"owner_id"`
	Name         string           `json:"name"`
	Path         string           `json:"path"`
	Type         model.FolderType `json:"type"`
	ItemCount    int64            `json:"item_count"`
	LogicalBytes int64            `json:"logical_bytes"`
}

type FolderExportManifestItem struct {
	ID           string            `json:"id"`
	Name         string            `json:"name,omitempty"`
	ArchivePath  string            `json:"archive_path"`
	Size         int64             `json:"size"`
	UID          uint32            `json:"uid,omitempty"`
	ModSeq       uint64            `json:"mod_seq,omitempty"`
	Flags        []string          `json:"flags,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	InternalDate time.Time         `json:"internal_date,omitzero"`
	CreatedAt    time.Time         `json:"created_at,omitzero"`
	UpdatedAt    time.Time         `json:"updated_at,omitzero"`
}

type FolderExportReport struct {
	Folder model.Folder
	Items  int64
	Bytes  int64
}

type AccountExportManifest struct {
	Format       string                        `json:"format"`
	Version      int                           `json:"version"`
	ExportedAt   time.Time                     `json:"exported_at"`
	AccountID    string                        `json:"account_id"`
	SettingsPath string                        `json:"settings_path"`
	Folders      []AccountExportManifestFolder `json:"folders"`
}

type AccountExportManifestFolder struct {
	Folder      FolderExportFolder `json:"folder"`
	ArchivePath string             `json:"archive_path"`
	Items       int64              `json:"items"`
	Bytes       int64              `json:"bytes"`
}

type AccountExportReport struct {
	Folders int64
	Items   int64
	Bytes   int64
}

// ExportFolder writes one folder's current items as a portable ZIP. It pages
// metadata and resolves one full item at a time through FolderSpace, keeping
// memory bounded independently of the folder's item count.
func ExportFolder(ctx context.Context, space FolderSpace, access AccessContext, folderID string, destination io.Writer) (report FolderExportReport, err error) {
	if space == nil {
		return report, errors.New("folder export requires a folder space")
	}
	if destination == nil {
		return report, errors.New("folder export requires a destination")
	}
	folder, err := space.GetFolder(ctx, access, folderID)
	if err != nil {
		return report, err
	}
	if _, ok := space.(FolderItemPager); !ok {
		return report, errors.New("folder export requires bounded item paging")
	}
	archive := zip.NewWriter(destination)
	report, exportErr := exportFolderToArchive(ctx, space, access, folder, archive, "")
	return report, errors.Join(exportErr, archive.Close())
}

// ExportAccount writes every active folder owned by access.Subject into one
// portable archive. The caller supplies an already-redacted settings document;
// the service validates it but never reaches around FolderSpace for account
// storage. Shared folders and recoverable trash are intentionally excluded.
func ExportAccount(ctx context.Context, space FolderSpace, access AccessContext, accountID string, settings json.RawMessage, destination io.Writer) (report AccountExportReport, err error) {
	if space == nil {
		return report, errors.New("account export requires a folder space")
	}
	if destination == nil {
		return report, errors.New("account export requires a destination")
	}
	if err := access.Validate(); err != nil {
		return report, err
	}
	if accountID == "" || access.Subject.Kind != model.PrincipalUser || access.Subject.ID != accountID {
		return report, ErrForbidden
	}
	if len(settings) == 0 || len(settings) > 1<<20 || !json.Valid(settings) {
		return report, errors.New("account export settings must be valid bounded JSON")
	}
	if _, ok := space.(FolderItemPager); !ok {
		return report, errors.New("account export requires bounded item paging")
	}
	folders, err := space.ListFolders(ctx, access, FolderQuery{})
	if err != nil {
		return report, err
	}
	owned := folders[:0]
	for _, folder := range folders {
		if folder.UserID == accountID && folder.TrashedAt.IsZero() {
			owned = append(owned, folder)
		}
	}
	sort.Slice(owned, func(i, j int) bool {
		if owned[i].Path == owned[j].Path {
			return owned[i].ID < owned[j].ID
		}
		return owned[i].Path < owned[j].Path
	})

	archive := zip.NewWriter(destination)
	settingsPath := "settings.json"
	settingsEntry, err := archive.CreateHeader(&zip.FileHeader{Name: settingsPath, Method: zip.Deflate, Modified: time.Now().UTC()})
	if err != nil {
		return report, errors.Join(fmt.Errorf("create account settings entry: %w", err), archive.Close())
	}
	if _, err := settingsEntry.Write(settings); err != nil {
		return report, errors.Join(fmt.Errorf("write account settings entry: %w", err), archive.Close())
	}

	manifest := AccountExportManifest{
		Format: AccountExportFormat, Version: AccountExportVersion, ExportedAt: time.Now().UTC(),
		AccountID: accountID, SettingsPath: settingsPath,
		Folders: make([]AccountExportManifestFolder, 0, len(owned)),
	}
	for index, folder := range owned {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, archive.Close())
		}
		label := safeExportName(strings.ReplaceAll(folder.Path, "/", " - "))
		prefix := fmt.Sprintf("folders/%04d-%s/", index+1, label)
		folderReport, err := exportFolderToArchive(ctx, space, access, folder, archive, prefix)
		if err != nil {
			return report, errors.Join(err, archive.Close())
		}
		manifest.Folders = append(manifest.Folders, AccountExportManifestFolder{
			Folder: exportFolderProjection(folder), ArchivePath: prefix,
			Items: folderReport.Items, Bytes: folderReport.Bytes,
		})
		report.Folders++
		report.Items += folderReport.Items
		report.Bytes += folderReport.Bytes
	}
	manifestEntry, err := archive.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: manifest.ExportedAt})
	if err != nil {
		return report, errors.Join(fmt.Errorf("create account export manifest: %w", err), archive.Close())
	}
	if err := json.NewEncoder(manifestEntry).Encode(manifest); err != nil {
		return report, errors.Join(fmt.Errorf("write account export manifest: %w", err), archive.Close())
	}
	return report, archive.Close()
}

func exportFolderToArchive(ctx context.Context, space FolderSpace, access AccessContext, folder model.Folder, archive *zip.Writer, archivePrefix string) (report FolderExportReport, err error) {
	pager, ok := space.(FolderItemPager)
	if !ok {
		return report, errors.New("folder export requires bounded item paging")
	}
	report.Folder = folder
	// An export reads every item once; it must not displace interactive
	// sessions' cached listings.
	ctx = WithBulkRead(ctx)

	manifest, err := os.CreateTemp("", "veksel-folder-export-manifest-*.json")
	if err != nil {
		return report, fmt.Errorf("create folder export manifest: %w", err)
	}
	manifestName := manifest.Name()
	defer func() {
		if closeErr := manifest.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close folder export manifest: %w", closeErr)
		}
		_ = os.Remove(manifestName)
	}()
	manifestBuffer := bufio.NewWriter(manifest)
	if err := writeManifestStart(manifestBuffer, folder); err != nil {
		return report, err
	}

	var beforeUID uint32
	firstManifestItem := true
	sequence := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		page, err := pager.ListItemPage(ctx, access, folder.ID, ItemPageQuery{BeforeUID: beforeUID, Limit: folderExportPageSize})
		if err != nil {
			return report, fmt.Errorf("list folder export page: %w", err)
		}
		for _, summary := range page.Items {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			item, err := space.GetItem(ctx, access, summary.ID)
			if err != nil {
				return report, fmt.Errorf("read folder export item %q: %w", summary.ID, err)
			}
			if item.FolderID != folder.ID || !item.TrashedAt.IsZero() {
				return report, fmt.Errorf("folder export item %q changed during export", summary.ID)
			}
			sequence++
			archivePath := folderExportArchivePath(folder.Type, item, sequence)
			entry, err := archive.CreateHeader(&zip.FileHeader{
				Name:     archivePrefix + archivePath,
				Method:   zip.Deflate,
				Modified: exportItemTime(item),
			})
			if err != nil {
				return report, fmt.Errorf("create folder export entry: %w", err)
			}
			written, err := entry.Write(item.Data)
			if err != nil {
				return report, fmt.Errorf("write folder export item %q: %w", item.ID, err)
			}
			if written != len(item.Data) {
				return report, io.ErrShortWrite
			}
			manifestItem := FolderExportManifestItem{
				ID: item.ID, Name: item.Name, ArchivePath: archivePath, Size: item.Size,
				UID: item.UID, ModSeq: item.ModSeq, Flags: item.Flags, Headers: item.Headers,
				InternalDate: item.InternalDate, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
			}
			if !firstManifestItem {
				if _, err := manifestBuffer.WriteString(","); err != nil {
					return report, fmt.Errorf("write folder export manifest separator: %w", err)
				}
			}
			firstManifestItem = false
			encoded, err := json.Marshal(manifestItem)
			if err != nil {
				return report, fmt.Errorf("encode folder export item manifest: %w", err)
			}
			if _, err := manifestBuffer.Write(encoded); err != nil {
				return report, fmt.Errorf("write folder export item manifest: %w", err)
			}
			report.Items++
			report.Bytes += int64(len(item.Data))
		}
		if page.NextBeforeUID == 0 {
			break
		}
		if page.NextBeforeUID == beforeUID || len(page.Items) == 0 {
			return report, errors.New("folder export paging did not advance")
		}
		beforeUID = page.NextBeforeUID
	}
	if _, err := manifestBuffer.WriteString("]}"); err != nil {
		return report, fmt.Errorf("finish folder export manifest: %w", err)
	}
	if err := manifestBuffer.Flush(); err != nil {
		return report, fmt.Errorf("flush folder export manifest: %w", err)
	}
	if _, err := manifest.Seek(0, io.SeekStart); err != nil {
		return report, fmt.Errorf("rewind folder export manifest: %w", err)
	}
	manifestEntry, err := archive.CreateHeader(&zip.FileHeader{Name: archivePrefix + "manifest.json", Method: zip.Deflate, Modified: time.Now().UTC()})
	if err != nil {
		return report, fmt.Errorf("create folder export manifest entry: %w", err)
	}
	if _, err := io.Copy(manifestEntry, manifest); err != nil {
		return report, fmt.Errorf("write folder export manifest entry: %w", err)
	}
	return report, nil
}

func exportFolderProjection(folder model.Folder) FolderExportFolder {
	return FolderExportFolder{
		ID: folder.ID, OwnerID: folder.UserID, Name: folder.Name, Path: folder.Path,
		Type: folder.Type, ItemCount: folder.ItemCount, LogicalBytes: folder.LogicalBytes,
	}
}

func writeManifestStart(writer io.Writer, folder model.Folder) error {
	header := struct {
		Format     string             `json:"format"`
		Version    int                `json:"version"`
		ExportedAt time.Time          `json:"exported_at"`
		Folder     FolderExportFolder `json:"folder"`
	}{
		Format: FolderExportFormat, Version: FolderExportVersion, ExportedAt: time.Now().UTC(),
		Folder: exportFolderProjection(folder),
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("encode folder export manifest: %w", err)
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] != '}' {
		return errors.New("encode folder export manifest: invalid object")
	}
	_, err = writer.Write(append(encoded[:len(encoded)-1], []byte(`,"items":[`)...))
	if err != nil {
		return fmt.Errorf("write folder export manifest: %w", err)
	}
	return nil
}

func folderExportArchivePath(folderType model.FolderType, item model.Item, sequence int64) string {
	name := item.Name
	extension := ""
	switch folderType {
	case model.FolderTypeMail:
		extension = ".eml"
	case model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeScheduleInbox, model.FolderTypeScheduleOutbox:
		extension = ".ics"
	case model.FolderTypeContacts:
		extension = ".vcf"
	case model.FolderTypeNotes:
		extension = ".txt"
	case model.FolderTypeSieve:
		extension = ".sieve"
	case model.FolderTypeSavedSearch, model.FolderTypeMailTemplate:
		extension = ".json"
	}
	if folderType != model.FolderTypeFiles || strings.TrimSpace(name) == "" {
		name = item.ID
	}
	name = safeExportName(name)
	if extension != "" && !strings.EqualFold(path.Ext(name), extension) {
		name += extension
	}
	return fmt.Sprintf("items/%08d-%s", sequence, name)
}

func safeExportName(value string) string {
	value = path.Base(strings.ReplaceAll(value, "\\", "/"))
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, value)
	value = strings.Trim(value, " .")
	if value == "" || value == "." || value == ".." {
		value = "item"
	}
	runes := []rune(value)
	if len(runes) > 180 {
		extension := path.Ext(value)
		limit := 180 - len([]rune(extension))
		if limit < 1 {
			limit = 180
			extension = ""
		}
		value = string(runes[:limit]) + extension
	}
	return value
}

func exportItemTime(item model.Item) time.Time {
	for _, candidate := range []time.Time{item.UpdatedAt, item.InternalDate, item.CreatedAt} {
		if !candidate.IsZero() {
			return candidate.UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}
