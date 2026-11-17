package app

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestAdminBackupDownloadAndVerifyWorkflow(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	download, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/backup/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	download.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("download = %d, %v", response.StatusCode, err)
	}
	if got := response.Header.Get("Content-Type"); got != "application/x-tar" {
		t.Fatalf("download content type = %q", got)
	}
	verification, err := backup.VerifyArchive(t.Context(), bytes.NewReader(archive), t.TempDir())
	if err != nil || verification.Kind != backup.ArchiveKindInstallation || !verification.Verified || verification.Metadata.Version != "v2" {
		t.Fatalf("download verification = %#v, %v", verification, err)
	}
	keysBefore, err := ts.Store().List(t.Context(), "users")
	if err != nil {
		t.Fatal(err)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("backup", "veksel-backup.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/backup/verify", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result backup.ArchiveVerification
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result.Kind != backup.ArchiveKindInstallation || result.Installation == nil || !result.Verified || result.Metadata.TotalKeys == 0 {
		t.Fatalf("verify response = %d, %#v", response.StatusCode, result)
	}
	keysAfter, err := ts.Store().List(t.Context(), "users")
	if err != nil || len(keysAfter) != len(keysBefore) {
		t.Fatalf("verification mutated users: before=%d after=%d err=%v", len(keysBefore), len(keysAfter), err)
	}
}

func TestAdminBackupVerifyRejectsUnauthenticatedNonAdminAndInvalidArchives(t *testing.T) {
	server, ts := testApp(t)
	unauthenticated, err := http.Post(server.URL+"/api/v1/admin/backup/verify", "application/gzip", bytes.NewBufferString("invalid"))
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.StatusCode)
	}

	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	if err := ts.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	ordinaryCSRF := loginExistingUser(t, ordinary, server.URL, "ordinary")
	forbidden, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/backup/verify", bytes.NewBufferString("invalid"))
	if err != nil {
		t.Fatal(err)
	}
	forbidden.Header.Set("Content-Type", "application/gzip")
	forbidden.Header.Set("X-CSRF-Token", ordinaryCSRF)
	response, err := ordinary.Do(forbidden)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", response.StatusCode)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/backup/verify", bytes.NewBufferString("invalid"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/gzip")
	request.Header.Set("X-CSRF-Token", csrf)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid archive status = %d", response.StatusCode)
	}
}

// TestAdminBackupDownloadBreaksConnectionOnFailure fails an installation
// backup after the archive has started streaming. The client must see a
// failed transfer, not a 200 response that ends like a complete file.
func TestAdminBackupDownloadBreaksConnectionOnFailure(t *testing.T) {
	handler, _ := testHandler(t)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	// A closed manager still lists its account but cannot export it, so the
	// backup fails after the system store member is written.
	manager, err := account.NewManager(t.TempDir(), store.BackendPebble)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true}, "alice@example.test", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	handler.ConfigureAccountStorage(manager)

	download, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/backup/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	download.Header.Set("X-CSRF-Token", csrf)
	response, err := client.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	archive, err := io.ReadAll(response.Body)
	if err == nil {
		t.Fatalf("failed backup ended as a complete %d response of %d bytes", response.StatusCode, len(archive))
	}
	if response.StatusCode != http.StatusOK || len(archive) == 0 {
		t.Fatalf("download = %d with %d bytes before the break", response.StatusCode, len(archive))
	}
}
