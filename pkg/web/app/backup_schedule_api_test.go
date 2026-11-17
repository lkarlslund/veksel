package app

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/backup/schedule"
)

func TestAdminBackupScheduleRunNowAndDownload(t *testing.T) {
	handler, ts := testHandler(t)
	dataDir := t.TempDir()
	scheduler, err := backup.NewScheduler(t.Context(), backup.SchedulerOptions{Store: ts, Source: handler.installationSource, Audit: handler.audit})
	if err != nil {
		t.Fatal(err)
	}
	daily, _ := schedule.Parse("daily")
	policy := backup.SchedulePolicy{Schedule: daily, Directory: filepath.Join(dataDir, "backups"), DataDir: dataDir, KeepDaily: 7, KeepWeekly: 4}
	if err := scheduler.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	handler.ConfigureBackupScheduler(scheduler)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	request := func(method, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	status := func() backup.ScheduleStatus {
		t.Helper()
		response := request(http.MethodGet, "/api/v1/admin/backup/schedule")
		defer response.Body.Close()
		var result backup.ScheduleStatus
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil {
			t.Fatalf("schedule status = %d", response.StatusCode)
		}
		return result
	}
	if current := status(); !current.Enabled || current.Schedule != "daily 03:00" || current.State.NextRunAt.IsZero() || len(current.Archives) != 0 {
		t.Fatalf("initial status = %+v", current)
	}

	if response := request(http.MethodPost, "/api/v1/admin/backup/run"); response.StatusCode != http.StatusAccepted {
		t.Fatalf("run now = %d", response.StatusCode)
	}
	deadline := time.Now().Add(30 * time.Second)
	current := status()
	for current.Running || current.State.LastResult != backup.ResultSucceeded {
		if time.Now().After(deadline) || current.State.LastResult == backup.ResultFailed {
			t.Fatalf("run now did not succeed: %+v", current.State)
		}
		time.Sleep(10 * time.Millisecond)
		current = status()
	}
	if len(current.Archives) != 1 || !current.Archives[0].Present || !current.Downloadable || current.State.LastTrigger != backup.TriggerManual {
		t.Fatalf("status after run = %+v", current)
	}
	archive := current.Archives[0]
	response := request(http.MethodGet, "/api/v1/admin/backup/archives/"+archive.Name)
	downloaded, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	stored, err := os.ReadFile(filepath.Join(archive.Directory, archive.Name))
	if err != nil || response.StatusCode != http.StatusOK || string(downloaded) != string(stored) {
		t.Fatalf("archive download = %d, %d bytes, want %d", response.StatusCode, len(downloaded), len(stored))
	}
	if response := request(http.MethodGet, "/api/v1/admin/backup/archives/veksel-scheduled-20200101T000000Z.tar"); response.StatusCode != http.StatusNotFound {
		t.Fatalf("download of an unknown archive = %d", response.StatusCode)
	}

	// A manual download while another backup runs is refused, not queued.
	holding, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = scheduler.Exclusive(func() error { close(holding); <-release; return nil })
	}()
	<-holding
	conflict := request(http.MethodPost, "/api/v1/admin/backup/download")
	_ = conflict.Body.Close()
	runConflict := request(http.MethodPost, "/api/v1/admin/backup/run")
	_ = runConflict.Body.Close()
	close(release)
	if conflict.StatusCode != http.StatusConflict || runConflict.StatusCode != http.StatusConflict {
		t.Fatalf("download/run during another backup = %d/%d", conflict.StatusCode, runConflict.StatusCode)
	}

	// Archives outside the data directory are listed but not served.
	policy.Directory = filepath.Join(t.TempDir(), "offsite")
	if err := scheduler.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if current := status(); current.Downloadable {
		t.Fatal("an offsite directory is reported as downloadable")
	}
}
