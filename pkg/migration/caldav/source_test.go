package caldav

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vekselcaldav "github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestSourceAgainstVekselCalDAVServer(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL} {
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
	if err := ts.FolderStore().Create(t.Context(), "alice", "Work", model.FolderTypeCalendar, ""); err != nil {
		t.Fatal(err)
	}
	handler := vekselcaldav.New(ts, nil)
	server := httptest.NewServer(handler)
	defer server.Close()
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Veksel Test//EN\r\nBEGIN:VEVENT\r\nUID:test-1\r\nDTSTAMP:20260816T100000Z\r\nDTSTART:20260816T120000Z\r\nDTEND:20260816T130000Z\r\nSUMMARY:Test event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/dav/alice/Work/test.ics", strings.NewReader(ics))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "text/calendar")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status=%d", response.StatusCode)
	}

	source, err := New(Config{Endpoint: server.URL + "/dav/alice/", Username: "alice", Password: "secret", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	folders, err := source.Inventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var workIndex = -1
	for i := range folders {
		if folders[i].Name == "Work" {
			workIndex = i
		}
	}
	if workIndex < 0 || folders[workIndex].Estimate != 1 {
		t.Fatalf("folders=%#v", folders)
	}
	page, err := source.Items(t.Context(), folders[workIndex], "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !strings.Contains(string(page.Items[0].Data), "SUMMARY:Test event") {
		t.Fatalf("page=%#v", page)
	}
	unchanged, err := source.Items(t.Context(), folders[workIndex], page.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.Items) != 0 || !unchanged.Done {
		t.Fatalf("unchanged=%#v", unchanged)
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodDelete, server.URL+"/dav/alice/Work/test.ics", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status=%d", response.StatusCode)
	}
	deleted, err := source.Items(t.Context(), folders[workIndex], unchanged.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.DeletedIDs) != 1 || !strings.HasSuffix(deleted.DeletedIDs[0], "/test.ics") {
		t.Fatalf("deleted=%#v", deleted)
	}
}
