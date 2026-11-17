package app

import (
	"bytes"
	"encoding/csv"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/contactport"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestWorkspaceContactPortabilityPreviewImportAndExport(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	contacts, err := typed.FolderStore().GetByPath(t.Context(), "alice", "Contacts")
	if err != nil {
		t.Fatal(err)
	}
	bundle := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Åse Example\r\nX-VENDOR;P=opaque:value\r\nEND:VCARD\r\n" +
		"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bob Example\r\nEMAIL:bob@example.test\r\nEND:VCARD\r\n"
	previewResponse := contactUploadRequest(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import/preview?folder_id="+url.QueryEscape(contacts.ID), csrf, "people.vcf", bundle)
	var preview contactImportProjection
	decodeResponse(t, previewResponse, &preview)
	if previewResponse.StatusCode != http.StatusOK || !preview.Valid || preview.Format != contactport.FormatVCard || preview.Contacts != 2 || len(preview.SampleNames) != 2 || preview.MaxContacts != contactport.MaxContacts {
		t.Fatalf("preview status=%d payload=%+v", previewResponse.StatusCode, preview)
	}
	if keys, err := typed.ItemStore().List(t.Context(), contacts.ID); err != nil || len(keys) != 0 {
		t.Fatalf("preview wrote contacts: keys=%v err=%v", keys, err)
	}

	withoutCSRF := contactUploadRequest(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import?folder_id="+url.QueryEscape(contacts.ID), "", "people.vcf", bundle)
	if withoutCSRF.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(withoutCSRF.Body)
		_ = withoutCSRF.Body.Close()
		t.Fatalf("import without CSRF status=%d body=%s", withoutCSRF.StatusCode, body)
	}
	_ = withoutCSRF.Body.Close()

	importResponse := contactUploadRequest(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import?folder_id="+url.QueryEscape(contacts.ID), csrf, "people.vcf", bundle)
	var imported contactImportResult
	decodeResponse(t, importResponse, &imported)
	if importResponse.StatusCode != http.StatusCreated || imported.FolderID != contacts.ID || imported.Imported != 2 {
		t.Fatalf("import status=%d payload=%+v", importResponse.StatusCode, imported)
	}
	keys, err := typed.ItemStore().List(t.Context(), contacts.ID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("imported keys=%v err=%v", keys, err)
	}

	vcardResponse, err := client.Get(server.URL + "/api/v1/workspace/contacts/export?folder_id=" + url.QueryEscape(contacts.ID) + "&format=vcard")
	if err != nil {
		t.Fatal(err)
	}
	vcardBody, _ := io.ReadAll(vcardResponse.Body)
	_ = vcardResponse.Body.Close()
	if vcardResponse.StatusCode != http.StatusOK || !strings.HasPrefix(vcardResponse.Header.Get("Content-Type"), "text/vcard") || !strings.Contains(vcardResponse.Header.Get("Content-Disposition"), "Contacts.vcf") || vcardResponse.Header.Get("Cache-Control") != "private, no-store" || !bytes.Contains(vcardBody, []byte("X-VENDOR;P=opaque:value")) || bytes.Count(vcardBody, []byte("BEGIN:VCARD")) != 2 {
		t.Fatalf("vCard export status=%d headers=%v body=%s", vcardResponse.StatusCode, vcardResponse.Header, vcardBody)
	}

	csvResponse, err := client.Get(server.URL + "/api/v1/workspace/contacts/export?folder_id=" + url.QueryEscape(contacts.ID) + "&format=csv")
	if err != nil {
		t.Fatal(err)
	}
	csvBody, _ := io.ReadAll(csvResponse.Body)
	_ = csvResponse.Body.Close()
	rows, parseErr := csv.NewReader(bytes.NewReader(csvBody)).ReadAll()
	if csvResponse.StatusCode != http.StatusOK || parseErr != nil || len(rows) != 3 || len(rows[0]) != len(contactport.CSVColumns()) || !strings.Contains(csvResponse.Header.Get("Content-Disposition"), "Contacts.csv") {
		t.Fatalf("CSV export status=%d rows=%#v parse=%v headers=%v", csvResponse.StatusCode, rows, parseErr, csvResponse.Header)
	}

	entries, err := audit.New(typed).Query(t.Context(), time.Time{}, "contacts.import", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Target != contacts.ID || entries[0].Details["items"] != "2" || entries[0].Details["format"] != "vcard" {
		t.Fatalf("import audit = %+v, %v", entries, err)
	}
	exports, err := audit.New(typed).Query(t.Context(), time.Time{}, "contacts.export", "alice", 10)
	if err != nil || len(exports) != 2 {
		t.Fatalf("export audit = %+v, %v", exports, err)
	}
}

func TestWorkspaceContactImportRejectsWholeInvalidDocumentWithoutPartialWrite(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	contacts, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "Contacts")
	bundle := "BEGIN:VCARD\nVERSION:3.0\nFN:Valid\nEND:VCARD\nBEGIN:VCARD\nVERSION:2.1\nFN:Invalid\nEND:VCARD\n"
	response := contactUploadRequest(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import?folder_id="+url.QueryEscape(contacts.ID), csrf, "mixed.vcf", bundle)
	var projection contactImportProjection
	decodeResponse(t, response, &projection)
	if response.StatusCode != http.StatusUnprocessableEntity || projection.Valid || projection.Contacts != 1 || len(projection.Problems) != 1 {
		t.Fatalf("invalid import status=%d projection=%+v", response.StatusCode, projection)
	}
	if keys, err := typed.ItemStore().List(t.Context(), contacts.ID); err != nil || len(keys) != 0 {
		t.Fatalf("invalid atomic import wrote contacts: keys=%v err=%v", keys, err)
	}
}

func TestWorkspaceContactPortabilityHonorsFolderReadAndCreateGrants(t *testing.T) {
	server, typed := testApp(t)
	owner := testClient(t)
	setupAndLogin(t, server, owner, "alice")
	contacts, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "Contacts")
	if _, err := typed.ItemStore().Append(t.Context(), contacts.ID, []byte("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Shared\r\nEND:VCARD\r\n"), nil); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	policies := model.NewPolicyStore(typed)
	viewer, err := policies.Create(t.Context(), model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: contacts.ID}, Effect: model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSelf, GrantedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob := testClient(t)
	bobCSRF := loginExistingUser(t, bob, server.URL, "bob")
	exportResponse, err := bob.Get(server.URL + "/api/v1/workspace/contacts/export?folder_id=" + url.QueryEscape(contacts.ID) + "&format=vcard")
	if err != nil {
		t.Fatal(err)
	}
	exportBody, _ := io.ReadAll(exportResponse.Body)
	_ = exportResponse.Body.Close()
	if exportResponse.StatusCode != http.StatusOK || !bytes.Contains(exportBody, []byte("FN:Shared")) {
		t.Fatalf("viewer export status=%d body=%s", exportResponse.StatusCode, exportBody)
	}
	card := "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Contributed\r\nEND:VCARD\r\n"
	denied := contactUploadRequest(t, bob, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import?folder_id="+url.QueryEscape(contacts.ID), bobCSRF, "one.vcf", card)
	if denied.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(denied.Body)
		_ = denied.Body.Close()
		t.Fatalf("viewer import status=%d body=%s", denied.StatusCode, body)
	}
	_ = denied.Body.Close()
	if err := policies.Delete(t.Context(), viewer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Create(t.Context(), model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: contacts.ID}, Effect: model.EffectAllow, RoleID: authz.RoleFolderContributor, Inheritance: model.InheritanceSelf, GrantedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	allowed := contactUploadRequest(t, bob, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import?folder_id="+url.QueryEscape(contacts.ID), bobCSRF, "one.vcf", card)
	if allowed.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(allowed.Body)
		_ = allowed.Body.Close()
		t.Fatalf("contributor import status=%d body=%s", allowed.StatusCode, body)
	}
	_ = allowed.Body.Close()
	entries, err := audit.New(typed).Query(t.Context(), time.Time{}, "contacts.import", "bob", 10)
	if err != nil || len(entries) != 1 || entries[0].Details["subject_id"] != "bob" {
		t.Fatalf("delegated folder import audit=%+v err=%v", entries, err)
	}
}

func TestWorkspaceContactPortabilityRejectsWrongFolderAndFormat(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	card := "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Alice\r\nEND:VCARD\r\n"
	wrongFolder := contactUploadRequest(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import/preview?folder_id="+url.QueryEscape(model.InboxFolderID("alice")), csrf, "one.vcf", card)
	if wrongFolder.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(wrongFolder.Body)
		_ = wrongFolder.Body.Close()
		t.Fatalf("wrong folder status=%d body=%s", wrongFolder.StatusCode, body)
	}
	_ = wrongFolder.Body.Close()
	contacts, _ := typed.FolderStore().GetByPath(t.Context(), "alice", "Contacts")
	unsupported := contactUploadRequest(t, client, http.MethodPost, server.URL+"/api/v1/workspace/contacts/import/preview?folder_id="+url.QueryEscape(contacts.ID), csrf, "one.json", "{}")
	if unsupported.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(unsupported.Body)
		_ = unsupported.Body.Close()
		t.Fatalf("unsupported format status=%d body=%s", unsupported.StatusCode, body)
	}
	_ = unsupported.Body.Close()
	badExport, err := client.Get(server.URL + "/api/v1/workspace/contacts/export?folder_id=" + url.QueryEscape(contacts.ID) + "&format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer badExport.Body.Close()
	if badExport.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad export format status=%d", badExport.StatusCode)
	}
}

func contactUploadRequest(t *testing.T, client *http.Client, method, endpoint, csrf, filename, content string) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, endpoint, &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
