package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestWorkspaceFolderExportDownload(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	folderID := model.InboxFolderID("alice")
	payload := []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Portable\r\n\r\nbody")
	if _, err := ts.ItemStore().Append(t.Context(), folderID, payload, map[string]string{"Subject": "Portable"}); err != nil {
		t.Fatalf("append message: %v", err)
	}

	response, err := client.Get(server.URL + "/api/v1/workspace/folders/" + url.PathEscape(folderID) + "/export")
	if err != nil {
		t.Fatalf("download export: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if response.Header.Get("Content-Type") != "application/zip" || !strings.Contains(response.Header.Get("Content-Disposition"), "INBOX.zip") {
		t.Fatalf("download headers = %#v", response.Header)
	}
	if response.Header.Get("Cache-Control") != "private, no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %#v", response.Header)
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open export: %v", err)
	}
	if len(reader.File) != 2 || !strings.HasSuffix(reader.File[0].Name, ".eml") || reader.File[1].Name != "manifest.json" {
		t.Fatalf("archive entries = %#v", reader.File)
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatalf("open message: %v", err)
	}
	exported, err := io.ReadAll(entry)
	_ = entry.Close()
	if err != nil || !bytes.Equal(exported, payload) {
		t.Fatalf("message payload=%q err=%v", exported, err)
	}
	manifestEntry, err := reader.File[1].Open()
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	var manifest service.FolderExportManifest
	if err := json.NewDecoder(manifestEntry).Decode(&manifest); err != nil {
		_ = manifestEntry.Close()
		t.Fatalf("decode manifest: %v", err)
	}
	_ = manifestEntry.Close()
	if manifest.Folder.ID != folderID || len(manifest.Items) != 1 {
		t.Fatalf("manifest = %#v", manifest)
	}
}

func TestWorkspaceFolderExportRejectsUnreadableFolder(t *testing.T) {
	server, ts := testApp(t)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "owner")
	for _, userID := range []string{"alice", "bob"} {
		if err := ts.UserStore().Create(t.Context(), userID, strings.ToUpper(userID), "password123"); err != nil {
			t.Fatalf("create %s: %v", userID, err)
		}
		if err := ts.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatalf("create %s folders: %v", userID, err)
		}
	}
	client := testClient(t)
	loginExistingUser(t, client, server.URL, "alice")

	response, err := client.Get(server.URL + "/api/v1/workspace/folders/" + url.PathEscape(model.InboxFolderID("bob")) + "/export")
	if err != nil {
		t.Fatalf("request export: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if strings.Contains(response.Header.Get("Content-Type"), "application/zip") {
		t.Fatalf("denied response exposed ZIP headers: %#v", response.Header)
	}
}
