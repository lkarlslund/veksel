package ews

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/migration"
)

// TestFoldersReportsNonEWSResponse covers an endpoint that reaches a web
// page instead of Exchange (a firewall redirect or portal): the error names
// the status, media type, redirect target and server instead of an XML
// parse failure.
func TestFoldersReportsNonEWSResponse(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://portal.example/login")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("<html><head><link></head></html>"))
		},
		"html page": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><head><link></head><body>Sign in</body></html>"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			source, err := New(Config{Endpoint: server.URL + "/EWS/Exchange.asmx", Username: "alice", Password: "secret", HTTPClient: client, PageSize: 10})
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.Folders(t.Context())
			if err == nil {
				t.Fatal("non-EWS response accepted")
			}
			message := err.Error()
			for _, want := range []string{"not an EWS response", "text/html", strings.TrimPrefix(server.URL, "http://")} {
				if !strings.Contains(message, want) {
					t.Errorf("error %q lacks %q", message, want)
				}
			}
			if name == "redirect" && !strings.Contains(message, "redirect to https://portal.example/login") {
				t.Errorf("error %q lacks the redirect target", message)
			}
			if strings.Contains(message, "XML syntax") {
				t.Errorf("error %q still reports an XML parse failure", message)
			}
		})
	}
}

// TestItemsSplitsOversizeResponses: a GetItem response over the size limit
// is retried in halves; a message too large on its own becomes an item
// failure and the rest of the page is imported.
func TestItemsSplitsOversizeResponses(t *testing.T) {
	messages := map[string]string{
		"a": "Subject: a\r\n\r\nshort",
		"b": "Subject: b\r\n\r\nshort",
		"c": "Subject: c\r\n\r\n" + strings.Repeat("x", 6000),
	}
	idPattern := regexp.MustCompile(`<t:ItemId Id="([^"]+)"/>`)
	var getCalls []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		envelope := func(inner string) string {
			return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Body>` + inner + `</s:Body></s:Envelope>`
		}
		if strings.Contains(string(body), "SyncFolderItems") {
			_, _ = io.WriteString(w, envelope(`<m:SyncFolderItemsResponse><m:ResponseMessages><m:SyncFolderItemsResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:SyncState>s1</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes>`+
				`<t:Create><t:Message><t:ItemId Id="a" ChangeKey="ka"/></t:Message></t:Create><t:Create><t:Message><t:ItemId Id="b" ChangeKey="kb"/></t:Message></t:Create><t:Create><t:Message><t:ItemId Id="c" ChangeKey="kc"/></t:Message></t:Create>`+
				`</m:Changes></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>`))
			return
		}
		ids := idPattern.FindAllStringSubmatch(string(body), -1)
		getCalls = append(getCalls, len(ids))
		var out strings.Builder
		for _, match := range ids {
			out.WriteString(`<m:GetItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:Message><t:MimeContent CharacterSet="UTF-8">` +
				base64.StdEncoding.EncodeToString([]byte(messages[match[1]])) + `</t:MimeContent><t:ItemId Id="` + match[1] + `" ChangeKey="k` + match[1] + `"/><t:DateTimeReceived>2026-11-01T10:00:00Z</t:DateTimeReceived></t:Message></m:Items></m:GetItemResponseMessage>`)
		}
		_, _ = io.WriteString(w, envelope(`<m:GetItemResponse><m:ResponseMessages>`+out.String()+`</m:ResponseMessages></m:GetItemResponse>`))
	}))
	defer server.Close()
	source, err := New(Config{Endpoint: server.URL, Username: "alice", Password: "secret", HTTPClient: server.Client(), PageSize: 10, MaxResponseBytes: 5000})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "inbox"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != "a" || page.Items[1].ID != "b" {
		t.Fatalf("items = %+v", page.Items)
	}
	if len(page.ItemFailures) != 1 || page.ItemFailures[0].ID != "c" || !strings.Contains(page.ItemFailures[0].Error, "larger than") {
		t.Fatalf("failures = %+v", page.ItemFailures)
	}
	if fmt.Sprint(getCalls) != "[3 1 2 1 1]" {
		t.Fatalf("GetItem batch sizes = %v", getCalls)
	}
	if !page.Done || page.Checkpoint != "s1" {
		t.Fatalf("page = %+v", page)
	}
}
