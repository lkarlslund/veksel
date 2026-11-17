package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestAdminAccountProvisionPreviewApplyAndIdempotentRerun(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "admin")
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	csv := "id,display_name,password,enabled,primary_email\n" +
		"bob,Bob Example,password123,true,bob@example.test\n"

	preview := provisionRequest(t, client, server.URL, csrf, "preview", csv)
	if !preview.Valid || preview.Creates != 1 || preview.Applied != 0 || preview.Rows[0].Action != "create" {
		t.Fatalf("preview = %+v", preview)
	}
	if _, err := typed.UserStore().Get(t.Context(), "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("preview created account: %v", err)
	}

	applied := provisionRequest(t, client, server.URL, csrf, "apply", csv)
	if !applied.Valid || applied.Creates != 1 || applied.Applied != 1 || applied.Failed != 0 {
		t.Fatalf("apply = %+v", applied)
	}
	user, err := typed.UserStore().Get(t.Context(), "bob")
	if err != nil || user.DisplayName != "Bob Example" || !user.Enabled || !auth.ComparePassword("password123", user.PasswordHash) {
		t.Fatalf("user = %+v, %v", user, err)
	}
	if _, err := typed.FolderStore().GetByPath(t.Context(), "bob", "INBOX"); err != nil {
		t.Fatalf("default INBOX: %v", err)
	}
	identity, err := typed.UserStore().GetEmailAddress(t.Context(), "bob@example.test")
	if err != nil || identity.UserID != "bob" || !identity.Primary || !identity.Enabled {
		t.Fatalf("identity = %+v, %v", identity, err)
	}

	rerun := provisionRequest(t, client, server.URL, csrf, "apply", csv)
	if !rerun.Valid || rerun.Unchanged != 1 || rerun.Applied != 0 || rerun.Rows[0].Action != "unchanged" {
		t.Fatalf("idempotent rerun = %+v", rerun)
	}

	updateCSV := "id,display_name,password,enabled,primary_email\n" +
		"bob,Robert Example,new-password-456,false,bob@example.test\n"
	updated := provisionRequest(t, client, server.URL, csrf, "apply", updateCSV)
	if !updated.Valid || updated.Updates != 1 || updated.Applied != 1 {
		t.Fatalf("update = %+v", updated)
	}
	user, err = typed.UserStore().Get(t.Context(), "bob")
	if err != nil || user.DisplayName != "Robert Example" || user.Enabled || !auth.ComparePassword("new-password-456", user.PasswordHash) {
		t.Fatalf("updated user = %+v, %v", user, err)
	}
	updateRerun := provisionRequest(t, client, server.URL, csrf, "apply", updateCSV)
	if !updateRerun.Valid || updateRerun.Unchanged != 1 || updateRerun.Applied != 0 {
		t.Fatalf("idempotent update rerun = %+v", updateRerun)
	}
}

func TestAdminAccountProvisionRejectsWholeInvalidBatchAndHidesPasswords(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "admin")
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	csv := "id,password,primary_email\ncharlie,very-secret-password,charlie@example.test\nbad user,password123,bad@example.test\n"
	body := `{"mode":"preview","csv":` + mustJSONProvisionString(t, csv) + `}`
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/users/provision", csrf, body)
	raw, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("preview status=%d body=%s err=%v", response.StatusCode, raw, err)
	}
	if strings.Contains(string(raw), "very-secret-password") || strings.Contains(string(raw), "password123") {
		t.Fatalf("preview leaked password: %s", raw)
	}

	body = `{"mode":"apply","csv":` + mustJSONProvisionString(t, csv) + `}`
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/users/provision", csrf, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		failedBody, _ := io.ReadAll(response.Body)
		t.Fatalf("invalid apply status=%d body=%s", response.StatusCode, failedBody)
	}
	if _, err := typed.UserStore().Get(t.Context(), "charlie"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("valid row from rejected batch was written: %v", err)
	}
}

func TestAccountProvisionRequiresAdministrator(t *testing.T) {
	server, typed := testApp(t)
	adminClient := testClient(t)
	adminCSRF := setupAndLogin(t, server, adminClient, "admin")
	if response := authenticatedJSON(t, adminClient, http.MethodPost, server.URL+"/api/v1/admin/users", adminCSRF, `{"id":"bob","display_name":"Bob","password":"password123"}`); response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("create bob status = %d", response.StatusCode)
	} else {
		response.Body.Close()
	}
	_ = typed
	client := testClient(t)
	csrf := loginExistingUser(t, client, server.URL, "bob")
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/users/provision", csrf, `{"mode":"preview","csv":"id\\nbill\\n"}`)
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin preview status = %d", response.StatusCode)
	}
}

func TestAdminAccountProvisionRejectsIdentityOwnedByAnotherAccount(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "admin")
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().AddEmailAddress(t.Context(), "admin@example.test", "admin", "example.test", true); err != nil {
		t.Fatal(err)
	}
	result := provisionRequest(t, client, server.URL, csrf, "preview", "id,password,primary_email\nbob,password123,admin@example.test\n")
	if result.Valid || result.Failed != 1 || !strings.Contains(result.Rows[0].Error, "another account") {
		t.Fatalf("identity ownership result = %+v", result)
	}
}

func provisionRequest(t *testing.T, client *http.Client, serverURL, csrf, mode, source string) accountProvisionResult {
	t.Helper()
	body := `{"mode":` + mustJSONProvisionString(t, mode) + `,"csv":` + mustJSONProvisionString(t, source) + `}`
	response := authenticatedJSON(t, client, http.MethodPost, serverURL+"/api/v1/admin/users/provision", csrf, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("provision %s status=%d body=%s", mode, response.StatusCode, raw)
	}
	var result accountProvisionResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func mustJSONProvisionString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
