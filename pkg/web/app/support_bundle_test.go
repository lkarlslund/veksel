package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/diagnostics"
	"github.com/lkarlslund/veksel/pkg/health"
)

func TestAdminSupportBundlePreviewAndDownloadAreBoundedAndRedacted(t *testing.T) {
	server, typed, configuration, _, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	if err := typed.UserStore().Create(t.Context(), "ordinary", "Ordinary Person", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.DomainStore().Create(t.Context(), "private.example.test"); err != nil {
		t.Fatal(err)
	}
	current := configuration.Current()
	if _, err := configuration.Patch(current.Revision, map[string]any{
		"relay_username": "private-operator", "relay_password": "never-export-this-secret",
		"acme_email": "owner@private.example.test", "acme_domains": "private.example.test",
	}); err != nil {
		t.Fatal(err)
	}
	logDir := configuration.Current().Config.LogDir
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logContents := strings.Join([]string{
		"2026-08-27T08:00:00Z INFO web: ordinary event owner=owner",
		"2026-08-27T09:00:00Z ERROR smtp: delivery failed recipient=owner@private.example.test password=never-export-this-secret",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(logDir, "veksel-2026-08-27.log"), []byte(logContents), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := health.New()
	handler.ConfigureRuntimeHealth(registry, func(context.Context) {
		if err := registry.Replace(time.Now(), []health.Observation{{
			ID: filepath.Join(logDir, "private-listener"), Label: "Private host", Kind: "listener",
			Desired: true, Required: true, State: health.StateDegraded, Reason: "owner@private.example.test failed",
			Details: map[string]string{"address": "10.0.0.8:8472"},
		}}); err != nil {
			t.Errorf("replace health: %v", err)
		}
	})

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/support-bundle/preview", "", "")
	previewBody, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("preview status=%d err=%v body=%s", response.StatusCode, err, previewBody)
	}
	assertSupportPayloadPrivate(t, previewBody, logDir)
	var preview diagnostics.SupportManifest
	if err := json.Unmarshal(previewBody, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SchemaVersion != diagnostics.SupportBundleSchema || len(preview.Files) != 5 || preview.TotalBytes <= 0 || preview.TotalBytes > diagnostics.MaxSupportBytes {
		t.Fatalf("preview=%+v", preview)
	}
	if !slices.IsSortedFunc(preview.Files, func(left, right diagnostics.SupportFile) int { return strings.Compare(left.Name, right.Name) }) {
		t.Fatalf("files are not sorted: %+v", preview.Files)
	}

	missingCSRF := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/support-bundle/download", "", "")
	_ = missingCSRF.Body.Close()
	if missingCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", missingCSRF.StatusCode)
	}
	download := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/support-bundle/download", csrf, "")
	archiveData, err := io.ReadAll(download.Body)
	_ = download.Body.Close()
	if err != nil || download.StatusCode != http.StatusOK || download.Header.Get("Content-Type") != "application/zip" || !strings.Contains(download.Header.Get("Content-Disposition"), "veksel-support-") {
		t.Fatalf("download status=%d type=%q disposition=%q err=%v", download.StatusCode, download.Header.Get("Content-Type"), download.Header.Get("Content-Disposition"), err)
	}
	assertSupportPayloadPrivate(t, archiveData, logDir)
	verifySupportArchive(t, archiveData)

	auditResponse := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/audit", "", "")
	defer auditResponse.Body.Close()
	var entries []struct {
		Action  string            `json:"action"`
		Target  string            `json:"target"`
		Details map[string]string `json:"details"`
	}
	if err := json.NewDecoder(auditResponse.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action != "support_bundle.download" {
			continue
		}
		found = entry.Target == "system" && entry.Details["result"] == "succeeded" && entry.Details["sections"] == "5" && entry.Details["bytes"] != "" && len(entry.Details) == 3
	}
	if !found {
		t.Fatalf("support bundle audit entry missing or unsafe: %+v", entries)
	}
}

func TestAdminSupportBundleRequiresAdministrator(t *testing.T) {
	server, typed, _, _, _ := managedTestApp(t)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "owner")
	if err := typed.UserStore().Create(t.Context(), "ordinary", "Ordinary", "password123"); err != nil {
		t.Fatal(err)
	}
	ordinary := testClient(t)
	csrf := loginExistingUser(t, ordinary, server.URL, "ordinary")
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/admin/support-bundle/preview"},
		{method: http.MethodPost, path: "/api/v1/admin/support-bundle/download"},
	} {
		response := authenticatedJSON(t, ordinary, test.method, server.URL+test.path, csrf, "")
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s status=%d", test.method, test.path, response.StatusCode)
		}
	}
	unauthenticated, err := http.Get(server.URL + "/api/v1/admin/support-bundle/preview")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauthenticated.StatusCode)
	}
}

func TestSupportBundleMarksUnavailableOptionalSources(t *testing.T) {
	handler, _ := testHandler(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/admin/support-bundle/preview", nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := handler.buildSupportBundle(request)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := bundle.WriteArchive(&archive); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		if !slices.Contains([]string{"configuration.json", "health.json", "severe-logs.json"}, file.Name) {
			continue
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(entry)
		_ = entry.Close()
		if err != nil || !strings.Contains(string(data), `"available": false`) {
			t.Fatalf("%s optional-source document=%s err=%v", file.Name, data, err)
		}
	}
}

func assertSupportPayloadPrivate(t *testing.T, payload []byte, logDir string) {
	t.Helper()
	for _, forbidden := range []string{
		"never-export-this-secret", "private-operator", "owner@private.example.test", "private.example.test",
		"Ordinary Person", logDir, "delivery failed", "ordinary event", "Private host", "10.0.0.8:8472",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Errorf("support payload contains forbidden value %q", forbidden)
		}
	}
}

func verifySupportArchive(t *testing.T, data []byte) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(reader.File))
	contents := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents[file.Name], err = io.ReadAll(entry)
		_ = entry.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"manifest.json", "configuration.json", "health.json", "inventory.json", "runtime.json", "severe-logs.json"}
	if !slices.Equal(names, want) {
		t.Fatalf("archive members=%v", names)
	}
	var manifest diagnostics.SupportManifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		digest := sha256.Sum256(contents[file.Name])
		if file.Bytes != int64(len(contents[file.Name])) || file.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("integrity mismatch for %s", file.Name)
		}
	}
	configuration := string(contents["configuration.json"])
	for _, marker := range []string{`[redacted]`, `[identity omitted]`, `[network/location omitted]`, `[path omitted]`} {
		if !strings.Contains(configuration, marker) {
			t.Errorf("configuration projection is missing %q", marker)
		}
	}
	var logs struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(contents["severe-logs.json"], &logs); err != nil {
		t.Fatal(err)
	}
	if len(logs.Records) != 1 || logs.Records[0]["level"] != "ERROR" || logs.Records[0]["module"] != "smtp" || len(logs.Records[0]) != 4 {
		t.Fatalf("severe log projection=%+v", logs.Records)
	}
	var healthData struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(contents["health.json"], &healthData); err != nil {
		t.Fatal(err)
	}
	if len(healthData.Components) != 1 || healthData.Components[0]["component_fingerprint"] == "" || healthData.Components[0]["id"] != nil || healthData.Components[0]["reason"] != nil || healthData.Components[0]["details"] != nil {
		t.Fatalf("health projection=%+v", healthData.Components)
	}
}
