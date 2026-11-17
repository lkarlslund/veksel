package carddav

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

func TestSourceAgainstVekselCardDAVServer(t *testing.T) {
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
	if err := ts.FolderStore().Create(t.Context(), "alice", "People", model.FolderTypeContacts, ""); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(vekselcaldav.New(ts, nil))
	defer server.Close()
	vcard := "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:test-1\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.test\r\nEND:VCARD\r\n"
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/dav/alice/People/ada.vcf", strings.NewReader(vcard))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "text/vcard")
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
	peopleIndex := -1
	for i := range folders {
		if folders[i].Name == "People" {
			peopleIndex = i
		}
	}
	if peopleIndex < 0 || folders[peopleIndex].Estimate != 1 || folders[peopleIndex].Type != model.FolderTypeContacts {
		t.Fatalf("folders=%#v", folders)
	}
	page, err := source.Items(t.Context(), folders[peopleIndex], "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !strings.Contains(string(page.Items[0].Data), "FN:Ada Lovelace") {
		t.Fatalf("page=%#v", page)
	}
	unchanged, err := source.Items(t.Context(), folders[peopleIndex], page.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.Items) != 0 || !unchanged.Done {
		t.Fatalf("unchanged=%#v", unchanged)
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodDelete, server.URL+"/dav/alice/People/ada.vcf", nil)
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
	deleted, err := source.Items(t.Context(), folders[peopleIndex], unchanged.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.DeletedIDs) != 1 || !strings.HasSuffix(deleted.DeletedIDs[0], "/ada.vcf") {
		t.Fatalf("deleted=%#v", deleted)
	}
}
