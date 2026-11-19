package ews

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func ewsEnvelope(inner string) string {
	return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Body>` + inner + `</s:Body></s:Envelope>`
}

// danishMailbox answers FindFolder with a Danish mailbox. With wellKnown it
// also answers GetFolder for the distinguished folders; otherwise GetFolder
// fails as on servers that do not support it.
func danishMailbox(t *testing.T, wellKnown bool) *Source {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		request := string(body)
		switch {
		case strings.Contains(request, "<m:GetFolder>"):
			if !wellKnown {
				_, _ = io.WriteString(w, ewsEnvelope(`<s:Fault><faultcode>s:Client</faultcode><faultstring>not supported</faultstring></s:Fault>`))
				return
			}
			var out strings.Builder
			for _, id := range []string{"f-indbakke", "f-sendt", "f-kladder", "f-slettet", ""} {
				if id == "" {
					out.WriteString(`<m:GetFolderResponseMessage ResponseClass="Error"><m:ResponseCode>ErrorFolderNotFound</m:ResponseCode></m:GetFolderResponseMessage>`)
					continue
				}
				out.WriteString(`<m:GetFolderResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Folders><t:Folder><t:FolderId Id="` + id + `"/></t:Folder></m:Folders></m:GetFolderResponseMessage>`)
			}
			_, _ = io.WriteString(w, ewsEnvelope(`<m:GetFolderResponse><m:ResponseMessages>`+out.String()+`</m:ResponseMessages></m:GetFolderResponse>`))
		case strings.Contains(request, "msgfolderroot"):
			folder := func(id, name string) string {
				return `<t:Folder><t:FolderId Id="` + id + `"/><t:FolderClass>IPF.Note</t:FolderClass><t:DisplayName>` + name + `</t:DisplayName><t:TotalCount>1</t:TotalCount></t:Folder>`
			}
			_, _ = io.WriteString(w, ewsEnvelope(`<m:FindFolderResponse><m:ResponseMessages><m:FindFolderResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootFolder><t:Folders>`+
				folder("f-indbakke", "Indbakke")+folder("f-sendt", "Sendt post")+folder("f-kladder", "Kladder")+folder("f-slettet", "Slettet post")+folder("f-sent", "Sent")+
				`</t:Folders></m:RootFolder></m:FindFolderResponseMessage></m:ResponseMessages></m:FindFolderResponse>`))
		default:
			_, _ = io.WriteString(w, ewsEnvelope(`<m:FindFolderResponse><m:ResponseMessages><m:FindFolderResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootFolder><t:Folders/></m:RootFolder></m:FindFolderResponseMessage></m:ResponseMessages></m:FindFolderResponse>`))
		}
	}))
	t.Cleanup(server.Close)
	source, err := New(Config{Endpoint: server.URL + "/EWS/Exchange.asmx", Username: "alice", Password: "secret", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func specialUses(t *testing.T, source *Source) map[string]string {
	t.Helper()
	folders, err := source.Folders(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, folder := range folders {
		result[folder.Name] = folder.Special
	}
	return result
}

// Exchange names well-known folders in the mailbox's language; the
// distinguished folder IDs identify them, and an ordinary folder that
// happens to be called "Sent" stays ordinary.
func TestFoldersRecognisesLocalizedWellKnownFolders(t *testing.T) {
	got := specialUses(t, danishMailbox(t, true))
	want := map[string]string{
		"Indbakke": model.SpecialUseInbox, "Sendt post": model.SpecialUseSent, "Kladder": model.SpecialUseDrafts,
		"Slettet post": model.SpecialUseTrash, "Sent": "",
	}
	for name, special := range want {
		if got[name] != special {
			t.Errorf("%s: special use %q, want %q", name, got[name], special)
		}
	}
}

// Without GetFolder the localized display names still identify the
// well-known folders.
func TestFoldersFallsBackToLocalizedNames(t *testing.T) {
	got := specialUses(t, danishMailbox(t, false))
	for name, special := range map[string]string{"Indbakke": model.SpecialUseInbox, "Sendt post": model.SpecialUseSent, "Kladder": model.SpecialUseDrafts, "Slettet post": model.SpecialUseTrash} {
		if got[name] != special {
			t.Errorf("%s: special use %q, want %q", name, got[name], special)
		}
	}
}

// An item Exchange answers without MIME content, or leaves out of the
// GetItem response, is reported as an item failure instead of vanishing
// while the folder's checkpoint moves past it.
func TestItemsReportsItemsWithoutContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		if strings.Contains(string(body), "SyncFolderItems") {
			_, _ = io.WriteString(w, ewsEnvelope(`<m:SyncFolderItemsResponse><m:ResponseMessages><m:SyncFolderItemsResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:SyncState>s1</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes>`+
				`<t:Create><t:Message><t:ItemId Id="a" ChangeKey="ka"/></t:Message></t:Create><t:Create><t:MeetingRequest><t:ItemId Id="b" ChangeKey="kb"/></t:MeetingRequest></t:Create><t:Create><t:Message><t:ItemId Id="c" ChangeKey="kc"/></t:Message></t:Create>`+
				`</m:Changes></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>`))
			return
		}
		_, _ = io.WriteString(w, ewsEnvelope(`<m:GetItemResponse><m:ResponseMessages>`+
			`<m:GetItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:Message><t:MimeContent CharacterSet="UTF-8">U3ViamVjdDogYQ0KDQpib2R5</t:MimeContent><t:ItemId Id="a" ChangeKey="ka"/></t:Message></m:Items></m:GetItemResponseMessage>`+
			`<m:GetItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:MeetingRequest><t:ItemId Id="b" ChangeKey="kb"/></t:MeetingRequest></m:Items></m:GetItemResponseMessage>`+
			`</m:ResponseMessages></m:GetItemResponse>`))
	}))
	defer server.Close()
	source, err := New(Config{Endpoint: server.URL + "/EWS/Exchange.asmx", Username: "alice", Password: "secret", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), source.folders["inbox"], "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "a" {
		t.Fatalf("items = %+v", page.Items)
	}
	failed := map[string]string{}
	for _, failure := range page.ItemFailures {
		failed[failure.ID] = failure.Error
	}
	if !strings.Contains(failed["b"], "MeetingRequest without MIME content") || !strings.Contains(failed["c"], "no content") || len(failed) != 2 {
		t.Fatalf("item failures = %v", failed)
	}
}
