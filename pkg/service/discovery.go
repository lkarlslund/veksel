package service

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	DiscoveryExportFormat  = "veksel-ediscovery-export"
	DiscoveryExportVersion = 1
	DefaultDiscoveryItems  = 10000
	MaxDiscoveryItems      = 100000
	discoveryPageSize      = 200
)

// DiscoveryQuery selects mail items for an eDiscovery export. Every set
// criterion must match: the internal date within [Since, Until), any of the
// participants in From, To, Cc, or Bcc, and every keyword in the message.
type DiscoveryQuery struct {
	Accounts     []string  `json:"accounts"`
	Since        time.Time `json:"since,omitzero"`
	Until        time.Time `json:"until,omitzero"`
	Participants []string  `json:"participants,omitempty"`
	Keywords     string    `json:"keywords,omitempty"`
	HeldOnly     bool      `json:"held_only,omitempty"`
	MaxItems     int       `json:"max_items,omitempty"`
}

// DiscoveryManifest is written last to manifest.json. Each item carries the
// SHA-256 of its archived .eml so the export can be verified independently.
type DiscoveryManifest struct {
	Format     string                  `json:"format"`
	Version    int                     `json:"version"`
	ExportedAt time.Time               `json:"exported_at"`
	ExportedBy string                  `json:"exported_by"`
	Query      DiscoveryQuery          `json:"query"`
	Truncated  bool                    `json:"truncated"`
	Items      []DiscoveryManifestItem `json:"items"`
}

type DiscoveryManifestItem struct {
	Account         string    `json:"account"`
	ItemID          string    `json:"item_id"`
	ArchivePath     string    `json:"archive_path"`
	Folder          string    `json:"folder"`
	HeldDeleted     bool      `json:"held_deleted,omitempty"`
	HeldDeletedAt   time.Time `json:"held_deleted_at,omitzero"`
	HeldDeletedFrom string    `json:"held_deleted_from,omitempty"`
	Trashed         bool      `json:"trashed,omitempty"`
	InternalDate    time.Time `json:"internal_date"`
	Subject         string    `json:"subject,omitempty"`
	From            string    `json:"from,omitempty"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
}

// DiscoveryReport summarizes a completed export for the audit log.
type DiscoveryReport struct {
	Accounts  int
	Items     int
	Bytes     int64
	Truncated bool
	Search    bool
}

// NormalizeDiscoveryQuery validates and bounds a query.
func NormalizeDiscoveryQuery(query DiscoveryQuery) (DiscoveryQuery, error) {
	if len(query.Accounts) == 0 {
		return query, errors.New("no account is in the export scope")
	}
	if !query.Since.IsZero() && !query.Until.IsZero() && !query.Until.After(query.Since) {
		return query, errors.New("the end date must be after the start date")
	}
	participants := query.Participants[:0]
	for _, participant := range query.Participants {
		if participant = strings.ToLower(strings.TrimSpace(participant)); participant != "" {
			participants = append(participants, participant)
		}
	}
	query.Participants = participants
	query.Keywords = strings.TrimSpace(query.Keywords)
	if len(query.Keywords) > 512 || len(query.Participants) > 50 {
		return query, errors.New("too many keywords or participants")
	}
	if query.MaxItems <= 0 {
		query.MaxItems = DefaultDiscoveryItems
	}
	query.MaxItems = min(query.MaxItems, MaxDiscoveryItems)
	return query, nil
}

// ExportDiscovery streams matching mail items of query.Accounts as a ZIP of
// .eml files plus a hashed manifest. Candidates come from the account search
// index when search is available and from a bounded folder scan otherwise;
// either way each item is read through FolderSpace with compliance access,
// re-checked against the query, and written before the next is read. The
// manifest is spooled to a temporary file, so memory stays bounded.
func ExportDiscovery(ctx context.Context, space FolderSpace, search SearchReader, query DiscoveryQuery, actor string, destination io.Writer) (report DiscoveryReport, err error) {
	query, err = NormalizeDiscoveryQuery(query)
	if err != nil {
		return report, err
	}
	if space == nil || destination == nil {
		return report, errors.New("discovery export requires a folder space and destination")
	}
	spool, err := os.CreateTemp("", "veksel-ediscovery-manifest-*.json")
	if err != nil {
		return report, fmt.Errorf("create discovery manifest: %w", err)
	}
	defer func() {
		_ = spool.Close()
		_ = os.Remove(spool.Name())
	}()
	exporter := &discoveryExporter{
		space: space, search: search, query: query,
		archive: zip.NewWriter(destination), manifest: bufio.NewWriter(spool), first: true,
	}
	for _, accountID := range query.Accounts {
		if exporter.full() {
			exporter.truncated = true
			break
		}
		if err := exporter.exportAccount(ctx, strings.ToLower(accountID)); err != nil {
			_ = exporter.archive.Close()
			return exporter.report(), fmt.Errorf("export %s: %w", accountID, err)
		}
		exporter.accounts++
	}
	if err := exporter.finish(spool, actor); err != nil {
		return exporter.report(), err
	}
	return exporter.report(), nil
}

type discoveryExporter struct {
	space     FolderSpace
	search    SearchReader
	query     DiscoveryQuery
	archive   *zip.Writer
	manifest  *bufio.Writer
	first     bool
	accounts  int
	items     int
	bytes     int64
	truncated bool
	searched  bool
	// indexed is true while the current account's candidates come from the
	// search index, which already applied the keywords.
	indexed bool
}

func (e *discoveryExporter) report() DiscoveryReport {
	return DiscoveryReport{Accounts: e.accounts, Items: e.items, Bytes: e.bytes, Truncated: e.truncated, Search: e.searched}
}

func (e *discoveryExporter) full() bool { return e.items >= e.query.MaxItems }

func (e *discoveryExporter) exportAccount(ctx context.Context, accountID string) error {
	access := ComplianceAccess(accountID)
	var folders []model.Folder
	var err error
	if lister, ok := e.space.(OwnFolderLister); ok {
		folders, err = lister.ListOwnFolders(ctx, access, FolderQuery{Type: model.FolderTypeMail, IncludeTrashed: true})
	} else {
		folders, err = e.space.ListFolders(ctx, access, FolderQuery{Type: model.FolderTypeMail, IncludeTrashed: true})
	}
	if err != nil {
		return err
	}
	byID := make(map[string]model.Folder, len(folders))
	for _, folder := range folders {
		if strings.EqualFold(folder.UserID, accountID) {
			byID[folder.ID] = folder
		}
	}
	seen := make(map[string]struct{})
	visit := func(itemID string) (bool, error) {
		if _, done := seen[itemID]; done {
			return true, nil
		}
		seen[itemID] = struct{}{}
		if e.full() {
			e.truncated = true
			return false, nil
		}
		return true, e.exportItem(ctx, access, accountID, itemID, byID)
	}
	if e.search != nil && !e.query.HeldOnly {
		e.indexed = true
		searched, err := e.searchAccount(ctx, access, accountID, visit)
		e.indexed = false
		if searched || err != nil {
			e.searched = e.searched || searched
			return err
		}
	}
	return e.scanAccount(ctx, access, byID, visit)
}

// searchAccount pages index hits; it reports false when the index cannot
// answer so the caller falls back to scanning.
func (e *discoveryExporter) searchAccount(ctx context.Context, access AccessContext, accountID string, visit func(string) (bool, error)) (bool, error) {
	var filters []SearchFilter
	if !e.query.Since.IsZero() || !e.query.Until.IsZero() {
		from, to := e.query.Since, e.query.Until
		if from.IsZero() {
			from = time.Unix(0, 0)
		}
		if to.IsZero() {
			to = time.Now().AddDate(100, 0, 0)
		}
		filters = append(filters, SearchFilter{Operator: SearchBetween, Field: "date", From: from.UTC().Format(time.RFC3339), To: to.UTC().Format(time.RFC3339)})
	}
	if len(e.query.Participants) > 0 {
		anyOf := SearchFilter{Operator: SearchAny}
		for _, participant := range e.query.Participants {
			anyOf.Children = append(anyOf.Children,
				SearchFilter{Operator: SearchContains, Field: "from", Value: participant},
				SearchFilter{Operator: SearchContains, Field: "to", Value: participant})
		}
		filters = append(filters, anyOf)
	}
	request := SearchQuery{AccountID: accountID, Text: e.query.Keywords, Types: []model.FolderType{model.FolderTypeMail}, IncludeTrash: true, Limit: discoveryPageSize, OmitSnippets: true}
	if len(filters) == 1 {
		request.Filter = &filters[0]
	} else if len(filters) > 1 {
		request.Filter = &SearchFilter{Operator: SearchAll, Children: filters}
	}
	for {
		page, err := e.search.Search(ctx, access, request)
		if errors.Is(err, ErrSearchUnavailable) && request.Cursor == "" {
			return false, nil
		}
		if err != nil {
			return true, err
		}
		for _, hit := range page.Hits {
			more, err := visit(hit.ItemID)
			if err != nil || !more {
				return true, err
			}
		}
		if page.NextCursor == "" || len(page.Hits) == 0 {
			return true, nil
		}
		request.Cursor = page.NextCursor
	}
}

// scanAccount pages every mail folder, including trash and held-deleted
// folders, newest UID first.
func (e *discoveryExporter) scanAccount(ctx context.Context, access AccessContext, folders map[string]model.Folder, visit func(string) (bool, error)) error {
	pager, ok := e.space.(FolderItemPager)
	if !ok {
		return errors.New("discovery export requires bounded item paging")
	}
	for _, folder := range folders {
		if e.query.HeldOnly && !model.IsHeldDeletedFolder(folder) || !folder.TrashedAt.IsZero() {
			continue
		}
		var beforeUID uint32
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			page, err := pager.ListItemPage(ctx, access, folder.ID, ItemPageQuery{BeforeUID: beforeUID, Limit: discoveryPageSize})
			if err != nil {
				return err
			}
			for _, item := range page.Items {
				if !e.dateMatches(item.InternalDate) {
					continue
				}
				more, err := visit(item.ID)
				if err != nil || !more {
					return err
				}
			}
			if page.NextBeforeUID == 0 || page.NextBeforeUID == beforeUID || len(page.Items) == 0 {
				break
			}
			beforeUID = page.NextBeforeUID
		}
	}
	return nil
}

func (e *discoveryExporter) dateMatches(value time.Time) bool {
	return (e.query.Since.IsZero() || !value.Before(e.query.Since)) && (e.query.Until.IsZero() || value.Before(e.query.Until))
}

// matches re-checks an item against the query from its raw message.
func (e *discoveryExporter) matches(item model.Item, header mail.Header) bool {
	if !e.dateMatches(item.InternalDate) || e.query.HeldOnly && item.HeldDeletedAt.IsZero() {
		return false
	}
	if len(e.query.Participants) > 0 {
		addresses := strings.ToLower(strings.Join([]string{header.Get("From"), header.Get("To"), header.Get("Cc"), header.Get("Bcc")}, " "))
		found := false
		for _, participant := range e.query.Participants {
			if strings.Contains(addresses, participant) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if e.query.Keywords != "" && !e.indexed {
		data := bytes.ToLower(item.Data)
		for _, keyword := range strings.Fields(strings.ToLower(e.query.Keywords)) {
			if !bytes.Contains(data, []byte(keyword)) {
				return false
			}
		}
	}
	return true
}

func (e *discoveryExporter) exportItem(ctx context.Context, access AccessContext, accountID, itemID string, folders map[string]model.Folder) error {
	item, err := e.space.GetItem(ctx, access, itemID)
	if err != nil {
		// An item removed between listing and reading is simply absent.
		return nil
	}
	folder, ok := folders[item.FolderID]
	if !ok {
		return nil
	}
	var header mail.Header
	if message, parseErr := mail.ReadMessage(bytes.NewReader(item.Data)); parseErr == nil {
		header = message.Header
	}
	if !e.matches(item, header) {
		return nil
	}
	sum := sha256.Sum256(item.Data)
	archivePath := fmt.Sprintf("%s/%s/%s.eml", safeExportName(accountID), discoveryFolderPath(folder), safeExportName(item.ID))
	entry, err := e.archive.CreateHeader(&zip.FileHeader{Name: archivePath, Method: zip.Deflate, Modified: exportItemTime(item)})
	if err != nil {
		return err
	}
	if _, err := entry.Write(item.Data); err != nil {
		return err
	}
	record := DiscoveryManifestItem{
		Account: accountID, ItemID: item.ID, ArchivePath: archivePath, Folder: folder.Path,
		HeldDeleted: !item.HeldDeletedAt.IsZero(), HeldDeletedAt: item.HeldDeletedAt, HeldDeletedFrom: item.HeldDeletedFrom,
		Trashed: !item.TrashedAt.IsZero(), InternalDate: item.InternalDate,
		Subject: header.Get("Subject"), From: header.Get("From"), Size: int64(len(item.Data)), SHA256: hex.EncodeToString(sum[:]),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if !e.first {
		if err := e.manifest.WriteByte(','); err != nil {
			return err
		}
	}
	e.first = false
	if _, err := e.manifest.Write(encoded); err != nil {
		return err
	}
	e.items++
	e.bytes += int64(len(item.Data))
	return nil
}

func discoveryFolderPath(folder model.Folder) string {
	segments := strings.Split(folder.Path, "/")
	for index, segment := range segments {
		segments[index] = safeExportName(segment)
	}
	return strings.Join(segments, "/")
}

// finish writes manifest.json from the spool and closes the archive.
func (e *discoveryExporter) finish(spool *os.File, actor string) error {
	if err := e.manifest.Flush(); err != nil {
		return err
	}
	header, err := json.Marshal(DiscoveryManifest{
		Format: DiscoveryExportFormat, Version: DiscoveryExportVersion, ExportedAt: time.Now().UTC(),
		ExportedBy: actor, Query: e.query, Truncated: e.truncated, Items: []DiscoveryManifestItem{},
	})
	if err != nil {
		return err
	}
	// The encoded header ends with `"items":[]}`; splice the spooled items in.
	prefix := bytes.TrimSuffix(header, []byte("]}"))
	entry, err := e.archive.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: time.Now().UTC()})
	if err != nil {
		return err
	}
	if _, err := entry.Write(prefix); err != nil {
		return err
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(entry, spool); err != nil {
		return err
	}
	if _, err := entry.Write([]byte("]}")); err != nil {
		return err
	}
	return e.archive.Close()
}
