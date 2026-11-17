package app

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/migration"
)

func TestPOP3SyncProfileRejectsUnsupportedSourceDeletionPolicy(t *testing.T) {
	handler, _ := testHandler(t)
	handler.migrationSources["pop3"] = func(context.Context, migration.SourceOptions) (migration.Source, error) { return nil, nil }
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	body := `{"source_type":"pop3","folder_ids":["INBOX"],"connection":{"endpoint":"mail.example.test:995","username":"owner","tls_mode":"implicit"},"schedule":"manual","source_deletion_policy":"trash","conflict_policy":"source_wins"}`
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/sync-jobs", csrf, body)
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "does not provide deletion tracking") {
		t.Fatalf("unsupported deletion status=%d body=%s", response.StatusCode, data)
	}
	body = strings.Replace(body, `"source_deletion_policy":"trash"`, `"source_deletion_policy":"retain"`, 1)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/sync-jobs", csrf, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		data, _ = io.ReadAll(response.Body)
		t.Fatalf("retained deletion status=%d body=%s", response.StatusCode, data)
	}
}
