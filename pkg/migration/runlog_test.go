package migration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	veksellog "github.com/lkarlslund/veksel/pkg/log"
)

// TestRunnerLogsRunStartAndOutcome checks that a run writes its start and
// outcome to the log file under the sync module.
func TestRunnerLogsRunStartAndOutcome(t *testing.T) {
	dir := t.TempDir()
	if err := veksellog.Setup(dir, "text", veksellog.LevelOff, veksellog.LevelInfo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = veksellog.Close() })
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &explicitEmptySource{}); err != nil {
		t.Fatal(err)
	}
	_ = veksellog.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	var text strings.Builder
	for _, file := range files {
		data, _ := os.ReadFile(file)
		text.Write(data)
	}
	for _, want := range []string{"sync: sync run started", "sync: sync run completed", "job=" + job.ID, "owner=alice"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, text.String())
		}
	}
}
