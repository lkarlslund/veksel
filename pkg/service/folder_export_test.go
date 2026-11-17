package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

type oneItemPageSpace struct {
	FolderSpace
	pagerCalls int
}

func (s *oneItemPageSpace) ListItemPage(ctx context.Context, access AccessContext, folderID string, query ItemPageQuery) (ItemPage, error) {
	s.pagerCalls++
	query.Limit = 1
	return s.FolderSpace.(FolderItemPager).ListItemPage(ctx, access, folderID, query)
}

func TestExportFolderPortablePayloadsManifestAndPaging(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	space := &oneItemPageSpace{FolderSpace: base}
	access := UserAccess("alice", "test")
	folder, err := space.CreateFolder(t.Context(), access, "Portable", model.FolderTypeFiles, "")
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	items := []ItemInput{
		{Name: "report.txt", Data: []byte("first"), Headers: map[string]string{"Content-Type": "text/plain"}},
		{Name: "report 2.txt", Data: []byte("second")},
		{Name: "notes.txt", Data: []byte("third")},
	}
	created := make([]model.Item, 0, len(items))
	for _, input := range items {
		item, createErr := space.CreateItem(t.Context(), access, folder.ID, input)
		if createErr != nil {
			t.Fatalf("create item: %v", createErr)
		}
		created = append(created, item)
	}

	var output bytes.Buffer
	report, err := ExportFolder(t.Context(), space, access, folder.ID, &output)
	if err != nil {
		t.Fatalf("export folder: %v", err)
	}
	if report.Items != 3 || report.Bytes != 16 {
		t.Fatalf("report = %#v", report)
	}
	if space.pagerCalls < 3 {
		t.Fatalf("pager calls = %d, want multiple pages", space.pagerCalls)
	}

	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	entries := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") || strings.Contains(file.Name, "\\") {
			t.Fatalf("unsafe archive path %q", file.Name)
		}
		stream, openErr := file.Open()
		if openErr != nil {
			t.Fatalf("open %q: %v", file.Name, openErr)
		}
		payload, readErr := io.ReadAll(stream)
		_ = stream.Close()
		if readErr != nil {
			t.Fatalf("read %q: %v", file.Name, readErr)
		}
		entries[file.Name] = payload
	}
	manifestBytes, ok := entries["manifest.json"]
	if !ok {
		t.Fatal("manifest.json missing")
	}
	var manifest FolderExportManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v\n%s", err, manifestBytes)
	}
	if manifest.Format != FolderExportFormat || manifest.Version != FolderExportVersion || manifest.Folder.ID != folder.ID || len(manifest.Items) != 3 {
		t.Fatalf("manifest = %#v", manifest)
	}
	for _, record := range manifest.Items {
		payload, exists := entries[record.ArchivePath]
		if !exists {
			t.Fatalf("manifest path %q missing", record.ArchivePath)
		}
		matched := slices.IndexFunc(created, func(item model.Item) bool { return item.ID == record.ID })
		if matched < 0 || !bytes.Equal(payload, created[matched].Data) {
			t.Fatalf("payload mismatch for %q", record.ID)
		}
	}
	if len(entries) != 4 {
		t.Fatalf("archive entries = %d, want 4", len(entries))
	}
}

func TestSafeExportNameRejectsArchiveTraversal(t *testing.T) {
	for input, want := range map[string]string{
		"../report.txt":       "report.txt",
		"subdir\\notes.txt":   "notes.txt",
		"/absolute/file.txt":  "file.txt",
		"..":                  "item",
		"control\x00name.txt": "control_name.txt",
	} {
		if got := safeExportName(input); got != want {
			t.Errorf("safeExportName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestExportFolderExtensionsAndEmptyArchive(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	access := UserAccess("alice", "test")
	tests := []struct {
		name       string
		folderType model.FolderType
		extension  string
	}{
		{name: "mail", folderType: model.FolderTypeMail, extension: ".eml"},
		{name: "calendar", folderType: model.FolderTypeCalendar, extension: ".ics"},
		{name: "schedule inbox", folderType: model.FolderTypeScheduleInbox, extension: ".ics"},
		{name: "schedule outbox", folderType: model.FolderTypeScheduleOutbox, extension: ".ics"},
		{name: "saved search", folderType: model.FolderTypeSavedSearch, extension: ".json"},
		{name: "message template", folderType: model.FolderTypeMailTemplate, extension: ".json"},
		{name: "contacts", folderType: model.FolderTypeContacts, extension: ".vcf"},
		{name: "files", folderType: model.FolderTypeFiles, extension: "source"},
		{name: "notes", folderType: model.FolderTypeNotes, extension: ".txt"},
		{name: "sieve", folderType: model.FolderTypeSieve, extension: ".sieve"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var folder model.Folder
			var err error
			if test.folderType == model.FolderTypeSavedSearch || test.folderType == model.FolderTypeMailTemplate {
				path := model.FolderPathSavedSearch
				if test.folderType == model.FolderTypeMailTemplate {
					path = model.FolderPathMailTemplate
				}
				folder, err = space.GetFolderByPath(t.Context(), access, path)
			} else {
				folder, err = space.CreateFolder(t.Context(), access, "Export "+test.name, test.folderType, "")
			}
			if err != nil {
				t.Fatalf("create folder: %v", err)
			}
			if _, err := space.CreateItem(t.Context(), access, folder.ID, ItemInput{Name: "source", Data: []byte("payload")}); err != nil {
				t.Fatalf("create item: %v", err)
			}
			var output bytes.Buffer
			if _, err := ExportFolder(t.Context(), space, access, folder.ID, &output); err != nil {
				t.Fatalf("export folder: %v", err)
			}
			reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
			if err != nil {
				t.Fatalf("open archive: %v", err)
			}
			if len(reader.File) != 2 || !strings.HasSuffix(reader.File[0].Name, test.extension) {
				t.Fatalf("entries = %#v, want payload with %s and manifest", reader.File, test.extension)
			}
		})
	}

	empty, err := space.CreateFolder(t.Context(), access, "Empty", model.FolderTypeFiles, "")
	if err != nil {
		t.Fatalf("create empty folder: %v", err)
	}
	var output bytes.Buffer
	report, err := ExportFolder(t.Context(), space, access, empty.ID, &output)
	if err != nil || report.Items != 0 {
		t.Fatalf("empty export report=%#v err=%v", report, err)
	}
	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil || len(reader.File) != 1 || reader.File[0].Name != "manifest.json" {
		t.Fatalf("empty archive entries=%#v err=%v", reader.File, err)
	}
}

func TestExportFolderHonorsReadGrant(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	alice := UserAccess("alice", "test")
	bob := UserAccess("bob", "test")
	folder := model.InboxFolderID("alice")
	if _, err := space.CreateItem(t.Context(), alice, folder, ItemInput{Data: []byte("private")}); err != nil {
		t.Fatalf("create item: %v", err)
	}
	if _, err := ExportFolder(t.Context(), space, bob, folder, io.Discard); err == nil {
		t.Fatal("ungranted export succeeded")
	}
	listOnly, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: bob.Actor, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder},
		Effect: model.EffectAllow, Permissions: []string{string(authz.FolderDiscover), string(authz.FolderItemsList)},
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create list-only grant: %v", err)
	}
	if _, err := ExportFolder(t.Context(), space, bob, folder, io.Discard); err == nil {
		t.Fatal("list-only export exposed payloads")
	}
	if err := model.NewPolicyStore(ts).Delete(t.Context(), listOnly.ID); err != nil {
		t.Fatalf("delete list-only grant: %v", err)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: bob.Actor, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder},
		Effect: model.EffectAllow, RoleID: authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatalf("create viewer grant: %v", err)
	}
	var output bytes.Buffer
	if _, err := ExportFolder(t.Context(), space, bob, folder, &output); err != nil || output.Len() == 0 {
		t.Fatalf("delegated export bytes=%d err=%v", output.Len(), err)
	}
}

func TestExportAccountStreamsOwnedFoldersAndSafeSettingsOnly(t *testing.T) {
	_, ts, _ := testMailService(t)
	base := NewFolderSpace(ts, authz.New(ts))
	space := &oneItemPageSpace{FolderSpace: base}
	alice := UserAccess("alice", "test")
	for _, definition := range []struct {
		name       string
		folderType model.FolderType
		data       []byte
	}{
		{name: "Portable calendar", folderType: model.FolderTypeCalendar, data: []byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n")},
		{name: "Portable contacts", folderType: model.FolderTypeContacts, data: []byte("BEGIN:VCARD\r\nFN:Alice\r\nEND:VCARD\r\n")},
		{name: "Portable files", folderType: model.FolderTypeFiles, data: []byte("file payload")},
		{name: "Portable notes", folderType: model.FolderTypeNotes, data: []byte("note payload")},
	} {
		folder, err := space.CreateFolder(t.Context(), alice, definition.name, definition.folderType, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := space.CreateItem(t.Context(), alice, folder.ID, ItemInput{Name: definition.name, Data: definition.data}); err != nil {
			t.Fatal(err)
		}
	}
	bobFolder := model.InboxFolderID("bob")
	if _, err := space.CreateItem(t.Context(), UserAccess("bob", "test"), bobFolder, ItemInput{Data: []byte("bob private payload")}); err != nil {
		t.Fatal(err)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: alice.Actor, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: bobFolder},
		Effect: model.EffectAllow, RoleID: authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	settings := json.RawMessage(`{"account_id":"alice","display_name":"Alice","identities":[{"address":"alice@example.test"}]}`)
	var output bytes.Buffer
	report, err := ExportAccount(t.Context(), space, alice, "alice", settings, &output)
	if err != nil {
		t.Fatalf("export account: %v", err)
	}
	if report.Folders < 4 || report.Items < 4 || report.Bytes == 0 || space.pagerCalls < 4 {
		t.Fatalf("report=%#v pager calls=%d", report, space.pagerCalls)
	}
	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") || strings.Contains(file.Name, "\\") {
			t.Fatalf("unsafe archive path %q", file.Name)
		}
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		entries[file.Name], err = io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(entries["settings.json"], settings) {
		t.Fatalf("settings = %s", entries["settings.json"])
	}
	var manifest AccountExportManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Format != AccountExportFormat || manifest.Version != AccountExportVersion || manifest.AccountID != "alice" || len(manifest.Folders) != int(report.Folders) {
		t.Fatalf("manifest = %#v", manifest)
	}
	extensions := map[model.FolderType]string{
		model.FolderTypeCalendar: ".ics", model.FolderTypeContacts: ".vcf",
		model.FolderTypeFiles: "", model.FolderTypeNotes: ".txt",
	}
	seenTypes := make(map[model.FolderType]bool)
	for _, folder := range manifest.Folders {
		if folder.Folder.OwnerID != "alice" || folder.Folder.ID == bobFolder {
			t.Fatalf("foreign folder exported: %#v", folder)
		}
		folderManifestBytes, ok := entries[folder.ArchivePath+"manifest.json"]
		if !ok {
			t.Fatalf("folder manifest %q missing", folder.ArchivePath)
		}
		var folderManifest FolderExportManifest
		if err := json.Unmarshal(folderManifestBytes, &folderManifest); err != nil {
			t.Fatal(err)
		}
		if folderManifest.Folder.ID != folder.Folder.ID {
			t.Fatalf("folder manifest mismatch: %#v / %#v", folder, folderManifest.Folder)
		}
		if extension, tracked := extensions[folder.Folder.Type]; tracked && len(folderManifest.Items) > 0 {
			seenTypes[folder.Folder.Type] = true
			if extension != "" && !strings.HasSuffix(folderManifest.Items[0].ArchivePath, extension) {
				t.Fatalf("%s item path = %q", folder.Folder.Type, folderManifest.Items[0].ArchivePath)
			}
			if _, ok := entries[folder.ArchivePath+folderManifest.Items[0].ArchivePath]; !ok {
				t.Fatalf("payload %q missing", folder.ArchivePath+folderManifest.Items[0].ArchivePath)
			}
		}
	}
	for folderType := range extensions {
		if !seenTypes[folderType] {
			t.Errorf("folder type %s not represented", folderType)
		}
	}
	for name, payload := range entries {
		if bytes.Contains(payload, []byte("bob private payload")) {
			t.Fatalf("shared foreign payload leaked into account export entry %q", name)
		}
	}
}

func TestExportAccountRejectsDifferentSubjectAndInvalidSettingsBeforeWriting(t *testing.T) {
	_, ts, _ := testMailService(t)
	space := NewFolderSpace(ts, authz.New(ts))
	for name, test := range map[string]struct {
		accountID string
		settings  json.RawMessage
	}{
		"different account": {accountID: "bob", settings: json.RawMessage(`{}`)},
		"invalid settings":  {accountID: "alice", settings: json.RawMessage(`{"broken"`)},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if _, err := ExportAccount(t.Context(), space, UserAccess("alice", "test"), test.accountID, test.settings, &output); err == nil {
				t.Fatal("export succeeded")
			}
			if output.Len() != 0 {
				t.Fatalf("wrote %d bytes before rejecting request", output.Len())
			}
		})
	}
	withoutPager := struct{ FolderSpace }{FolderSpace: space}
	for name, export := range map[string]func(*bytes.Buffer) error{
		"folder": func(output *bytes.Buffer) error {
			_, err := ExportFolder(t.Context(), withoutPager, UserAccess("alice", "test"), model.InboxFolderID("alice"), output)
			return err
		},
		"account": func(output *bytes.Buffer) error {
			_, err := ExportAccount(t.Context(), withoutPager, UserAccess("alice", "test"), "alice", json.RawMessage(`{}`), output)
			return err
		},
	} {
		t.Run(name+" requires bounded paging", func(t *testing.T) {
			var output bytes.Buffer
			if err := export(&output); err == nil || !strings.Contains(err.Error(), "bounded item paging") {
				t.Fatalf("error = %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("wrote %d bytes before rejecting unbounded export", output.Len())
			}
		})
	}
}
