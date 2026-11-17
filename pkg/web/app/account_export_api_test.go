package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

type failingAccountExportSpace struct {
	service.FolderSpace
	err error
}

func (space failingAccountExportSpace) ListFolders(context.Context, service.AccessContext, service.FolderQuery) ([]model.Folder, error) {
	return nil, space.err
}

func (space failingAccountExportSpace) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	return space.FolderSpace.(service.FolderItemPager).ListItemPage(ctx, access, folderID, query)
}

func TestUserAccountExportDownloadIsPortableScopedAndSecretFree(t *testing.T) {
	server, typed := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	if err := typed.UserStore().Update(t.Context(), "alice", func(user *model.User) {
		user.DisplayName = "Alice Portable"
		user.ForwardTo = "archive@example.net"
		user.SieveActive = true
		user.SieveScript = `require ["fileinto"];`
		user.SpamEnabled = true
		user.SpamThreshold = 4.5
		user.VacationEnabled = true
		user.VacationStart = start
		user.VacationEnd = start.Add(24 * time.Hour)
		user.VacationSubject = "Away"
		user.VacationMessage = "Portable vacation message"
	}); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().UpdateMailSignature(t.Context(), "alice", "alice@example.test", model.MailSignature{Text: "Alice signature", NewMessages: true}); err != nil {
		t.Fatal(err)
	}
	folders, err := typed.FolderStore().ListForUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, folder := range folders {
		if folder.SpecialUse == model.SpecialUseInbox {
			if _, err := typed.ItemStore().Append(t.Context(), folder.ID, []byte("Subject: Portable\r\n\r\nmail body"), map[string]string{"Subject": "Portable"}); err != nil {
				t.Fatal(err)
			}
		}
		if folder.SpecialUse == model.SpecialUseFiles {
			if _, err := typed.ItemStore().AppendItem(t.Context(), folder.ID, model.Item{Name: "portable.txt", Data: []byte("file body")}); err != nil {
				t.Fatal(err)
			}
		}
	}

	response, err := client.Get(server.URL + "/api/v1/user/export?subject_id=somebody-else")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/zip" || !strings.Contains(response.Header.Get("Content-Disposition"), "alice-veksel-export.zip") {
		t.Fatalf("status=%d headers=%#v body=%s", response.StatusCode, response.Header, body)
	}
	if response.Header.Get("Cache-Control") != "private, no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %#v", response.Header)
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
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
	var manifest service.AccountExportManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.AccountID != "alice" || manifest.Format != service.AccountExportFormat || len(manifest.Folders) != len(folders) {
		t.Fatalf("manifest = %#v", manifest)
	}
	var settings accountSettingsExport
	if err := json.Unmarshal(entries[manifest.SettingsPath], &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Format != accountSettingsExportFormat || settings.Account.ID != "alice" || settings.Account.DisplayName != "Alice Portable" || len(settings.Identities) != 1 || settings.Identities[0].Signature == nil || settings.Identities[0].Signature.Text != "Alice signature" || settings.Mail.ForwardTo != "archive@example.net" || !settings.Mail.Vacation || settings.Mail.VacationMessage != "Portable vacation message" {
		t.Fatalf("settings = %#v", settings)
	}
	settingsBytes := entries[manifest.SettingsPath]
	for _, forbidden := range []string{"password_hash", "api_key_hash", "secret_hash", "sync_password", "credential"} {
		if bytes.Contains(settingsBytes, []byte(forbidden)) {
			t.Errorf("settings contain forbidden marker %q: %s", forbidden, settingsBytes)
		}
	}
	entriesAudit, err := audit.New(typed).Query(t.Context(), time.Time{}, "account.export", "alice", 10)
	if err != nil || len(entriesAudit) != 1 || entriesAudit[0].Details["result"] != "succeeded" || entriesAudit[0].Details["folders"] != strconv.Itoa(len(folders)) {
		t.Fatalf("audit = %#v, %v", entriesAudit, err)
	}
}

func TestUserAccountExportFailureIsJSONAndAuditedBeforeStreaming(t *testing.T) {
	handler, typed := testHandler(t)
	handler.folderSpace = failingAccountExportSpace{FolderSpace: handler.folderSpace, err: errors.New("export inventory unavailable")}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")

	response, err := client.Get(server.URL + "/api/v1/user/export")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(response.Header.Get("Content-Type"), "application/json") || response.Header.Get("Content-Disposition") != "" || !json.Valid(body) || !strings.Contains(string(body), "export inventory unavailable") {
		t.Fatalf("status=%d headers=%#v body=%s", response.StatusCode, response.Header, body)
	}
	entries, err := audit.New(typed).Query(t.Context(), time.Time{}, "account.export", "alice", 10)
	if err != nil || len(entries) != 1 || entries[0].Details["result"] != "failed" {
		t.Fatalf("audit = %#v, %v", entries, err)
	}
}
