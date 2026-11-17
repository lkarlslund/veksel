package eas_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/eas"
	"github.com/lkarlslund/veksel/pkg/migration"
	easmigration "github.com/lkarlslund/veksel/pkg/migration/eas"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// TestMigrationClientReadsEveryClass points Veksel' own EAS client, built to
// read Exchange mailboxes, at the server: mail, calendar and contacts must
// survive the round trip through MS-ASEMAIL, MS-ASCAL and MS-ASCNTC.
func TestMigrationClientReadsEveryClass(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	handler, err := eas.New(t.Context(), eas.Config{Space: space, Store: backend, Authenticate: func(_ context.Context, username, password string) (string, error) {
		if username == "alice" && password == "secret" {
			return "alice", nil
		}
		return "", errors.New("denied")
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	access := service.UserAccess("alice", "test")
	put := func(path string, data string) {
		folder, err := space.GetFolderByPath(t.Context(), access, path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := space.CreateItem(t.Context(), access, folder.ID, service.ItemInput{Data: []byte(data)}); err != nil {
			t.Fatal(err)
		}
	}
	put("INBOX", "From: bob@example.test\r\nTo: alice@example.test\r\nSubject: Round trip\r\nContent-Type: text/plain\r\n\r\nHello through EAS")
	put("Calendar", "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:rt-1@example.test\r\nDTSTAMP:20261001T080000Z\r\nDTSTART:20261105T100000Z\r\nDTEND:20261105T110000Z\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\nSUMMARY:Review\r\nLOCATION:Office\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	put("Contacts", "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:rt-contact\r\nFN:Erik Lund\r\nN:Lund;Erik;;;\r\nEMAIL:erik@example.org\r\nTEL;TYPE=CELL:+45 22 33 44 55\r\nEND:VCARD\r\n")

	source, err := easmigration.New(easmigration.Config{Endpoint: server.URL + "/Microsoft-Server-ActiveSync", Username: "alice", Password: "secret", DeviceID: "MIGRATION1", Version: "14.1"})
	if err != nil {
		t.Fatal(err)
	}
	folders, err := source.Folders(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, folder := range folders {
		if folder.Name != "INBOX" && folder.Name != "Calendar" && folder.Name != "Contacts" {
			continue
		}
		checkpoint := ""
		for range 10 {
			page, err := source.Items(t.Context(), folder, checkpoint)
			if err != nil {
				t.Fatalf("Items(%s): %v", folder.Name, err)
			}
			for _, item := range page.Items {
				contents[folder.Name] += string(item.Data)
			}
			if len(page.ItemFailures) > 0 {
				t.Fatalf("item failures in %s: %#v", folder.Name, page.ItemFailures)
			}
			checkpoint = page.Checkpoint
			if page.Done {
				break
			}
		}
		if folder.Type != map[string]model.FolderType{"INBOX": model.FolderTypeMail, "Calendar": model.FolderTypeCalendar, "Contacts": model.FolderTypeContacts}[folder.Name] {
			t.Errorf("folder %s type = %s", folder.Name, folder.Type)
		}
	}
	for folder, wants := range map[string][]string{
		"INBOX":    {"Subject: Round trip", "Hello through EAS"},
		"Calendar": {"SUMMARY:Review", "LOCATION:Office", "FREQ=WEEKLY", "COUNT=4", "20261105T100000Z"},
		"Contacts": {"Erik", "Lund", "erik@example.org", "+45 22 33 44 55"},
	} {
		for _, want := range wants {
			if !strings.Contains(contents[folder], want) {
				t.Errorf("%s lacks %q:\n%s", folder, want, contents[folder])
			}
		}
	}
	var _ migration.Source = source
}
