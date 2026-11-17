package backup_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/backup/archivecrypt"
	"github.com/lkarlslund/veksel/pkg/backup/schedule"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type auditEntry struct {
	actor, action string
	details       map[string]string
}

type recordingAudit struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (a *recordingAudit) Log(actor, action, _ string, details map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, auditEntry{actor, action, details})
}

func (a *recordingAudit) find(action, result string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.ContainsFunc(a.entries, func(entry auditEntry) bool {
		return entry.action == action && entry.details["result"] == result
	})
}

type fixedCapacity uint64

func (c fixedCapacity) Capacity(string) (health.Capacity, error) {
	return health.Capacity{AvailableBytes: uint64(c), TotalBytes: 1 << 40}, nil
}

type schedulerFixture struct {
	ts        *model.TypedStore
	scheduler *backup.Scheduler
	audit     *recordingAudit
	dir       string
	now       time.Time
	source    backup.InstallationSource
}

// newSchedulerFixture builds a scheduler over an initialized system store
// with a controllable clock in UTC.
func newSchedulerFixture(t *testing.T, policy backup.SchedulePolicy) *schedulerFixture {
	t.Helper()
	ts := model.NewTypedStore(newTestStore(t), store.BackendJSON)
	if err := model.InitializeSystemStore(t.Context(), ts); err != nil {
		t.Fatal(err)
	}
	fixture := &schedulerFixture{ts: ts, audit: &recordingAudit{}, dir: filepath.Join(t.TempDir(), "backups"), now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	fixture.source = backup.InstallationSource{System: ts.Store(), SystemBackend: store.BackendJSON, TempDir: t.TempDir()}
	fixture.scheduler = fixture.open(t)
	if policy.Directory == "" {
		policy.Directory = fixture.dir
	}
	if err := fixture.scheduler.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *schedulerFixture) open(t *testing.T) *backup.Scheduler {
	t.Helper()
	scheduler, err := backup.NewScheduler(t.Context(), backup.SchedulerOptions{
		Store: f.ts, Source: func() backup.InstallationSource { return f.source }, Audit: f.audit,
		Now: func() time.Time { return f.now }, Location: time.UTC,
	})
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func dailyPolicy(t *testing.T, keepDaily, keepWeekly int) backup.SchedulePolicy {
	t.Helper()
	parsed, err := schedule.Parse("daily 03:00")
	if err != nil {
		t.Fatal(err)
	}
	return backup.SchedulePolicy{Schedule: parsed, KeepDaily: keepDaily, KeepWeekly: keepWeekly}
}

func directoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestScheduledRunWritesEncryptedVerifiedArchive(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	policy := dailyPolicy(t, 7, 4)
	policy.Recipients = []age.Recipient{identity.Recipient()}
	fixture := newSchedulerFixture(t, policy)

	archive, err := fixture.scheduler.Run(t.Context(), backup.TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !archive.Encrypted || !strings.HasSuffix(archive.Name, ".tar.age") || !strings.HasPrefix(archive.Name, "veksel-scheduled-20261001T120000Z") {
		t.Fatalf("archive = %+v", archive)
	}
	if names := directoryNames(t, fixture.dir); !slices.Equal(names, []string{archive.Name}) {
		t.Fatalf("backup directory = %q, want only the published archive", names)
	}
	contents, err := os.ReadFile(filepath.Join(fixture.dir, archive.Name))
	if err != nil || int64(len(contents)) != archive.Size {
		t.Fatalf("stored archive size = %d, recorded %d, %v", len(contents), archive.Size, err)
	}
	if _, err := backup.VerifyArchive(t.Context(), bytes.NewReader(contents), t.TempDir()); !errors.Is(err, archivecrypt.ErrIdentityRequired) {
		t.Fatalf("verifying ciphertext without identity = %v, want ErrIdentityRequired", err)
	}
	plaintext, encrypted, err := archivecrypt.Open(bytes.NewReader(contents), []age.Identity{identity})
	if err != nil || !encrypted {
		t.Fatalf("decrypt = %v, %v", encrypted, err)
	}
	verification, err := backup.VerifyArchive(t.Context(), plaintext, t.TempDir())
	if err != nil || verification.Kind != backup.ArchiveKindInstallation || !verification.Verified {
		t.Fatalf("decrypted archive verification = %+v, %v", verification, err)
	}
	status := fixture.scheduler.Status()
	if status.State.LastResult != backup.ResultSucceeded || status.State.LastSize != archive.Size || len(status.Archives) != 1 || !status.Archives[0].Present || !status.Encrypted {
		t.Fatalf("status = %+v", status)
	}
	if !fixture.audit.find("backup.scheduled", backup.ResultSucceeded) {
		t.Fatalf("no successful backup audit entry: %+v", fixture.audit.entries)
	}
}

func TestScheduledBackupsAreSingleFlightWithManualDownloads(t *testing.T) {
	fixture := newSchedulerFixture(t, dailyPolicy(t, 7, 4))
	holding, release := make(chan struct{}), make(chan struct{})
	done := make(chan error)
	go func() {
		done <- fixture.scheduler.Exclusive(func() error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	if !fixture.scheduler.Status().Running {
		t.Fatal("status does not report the running download")
	}
	if _, err := fixture.scheduler.Run(t.Context(), backup.TriggerSchedule, "system"); !errors.Is(err, backup.ErrBackupRunning) {
		t.Fatalf("scheduled run during a download = %v", err)
	}
	if err := fixture.scheduler.Trigger("admin"); !errors.Is(err, backup.ErrBackupRunning) {
		t.Fatalf("run-now during a download = %v", err)
	}
	if err := fixture.scheduler.Exclusive(func() error { return nil }); !errors.Is(err, backup.ErrBackupRunning) {
		t.Fatalf("second download = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.scheduler.Run(t.Context(), backup.TriggerSchedule, "system"); err != nil {
		t.Fatalf("run after the download finished = %v", err)
	}
	var nilScheduler *backup.Scheduler
	if err := nilScheduler.Exclusive(func() error { return nil }); err != nil {
		t.Fatalf("nil scheduler Exclusive = %v", err)
	}
}

func TestWriteFileAtomicPublishesOnlyCompleteFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "archive.tar")
	if _, err := backup.WriteFileAtomic(path, func(w io.Writer) error {
		_, _ = w.Write([]byte("partial"))
		return errors.New("producer failed")
	}); err == nil {
		t.Fatal("a failed producer published a file")
	}
	if names := directoryNames(t, dir); len(names) != 0 {
		t.Fatalf("failed write left %q behind", names)
	}
	written, err := backup.WriteFileAtomic(path, func(w io.Writer) error {
		_, err := w.Write([]byte("complete archive"))
		return err
	})
	if err != nil || written.Size != int64(len("complete archive")) || len(written.SHA256) != 64 {
		t.Fatalf("WriteFileAtomic = %+v, %v", written, err)
	}
	if contents, _ := os.ReadFile(path); string(contents) != "complete archive" {
		t.Fatalf("published contents = %q", contents)
	}
	if _, err := backup.WriteFileAtomic(path, func(io.Writer) error { return nil }); err == nil {
		t.Fatal("an existing file was overwritten")
	}
	if names := directoryNames(t, dir); !slices.Equal(names, []string{"archive.tar"}) {
		t.Fatalf("directory = %q", names)
	}
}

func TestRetentionDeletesOnlySchedulerOwnedArchives(t *testing.T) {
	fixture := newSchedulerFixture(t, dailyPolicy(t, 3, 2))
	if err := os.MkdirAll(fixture.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []string{"operator-notes.txt", "veksel-scheduled-20200101T000000Z.tar", "veksel-backup-2026.tar"}
	for _, name := range foreign {
		if err := os.WriteFile(filepath.Join(fixture.dir, name), []byte("not yours"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An interrupted run left a partial file behind; it is scheduler-owned.
	if err := os.WriteFile(filepath.Join(fixture.dir, ".veksel-scheduled-20200101T000000Z.tar.partial-123"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var created []backup.ScheduledArchive
	// Thursday 1 October through Sunday 18 October 2026, one run a day.
	for day := range 18 {
		fixture.now = time.Date(2026, 10, 1+day, 3, 0, 0, 0, time.UTC)
		archive, err := fixture.scheduler.Run(t.Context(), backup.TriggerSchedule, "system")
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, archive)
		if day == 0 {
			// Someone replaced the oldest archive; it is no longer ours to delete.
			if err := os.WriteFile(filepath.Join(fixture.dir, archive.Name), []byte("replaced by an operator"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	names := directoryNames(t, fixture.dir)
	for _, name := range foreign {
		if !slices.Contains(names, name) {
			t.Fatalf("retention deleted foreign file %s", name)
		}
	}
	if slices.ContainsFunc(names, func(name string) bool { return strings.Contains(name, ".partial-") }) {
		t.Fatalf("stale partial file survived: %q", names)
	}
	if !slices.Contains(names, created[0].Name) {
		t.Fatal("retention deleted an archive that no longer matches the ledger")
	}
	// Three newest days (16, 17, 18 Oct) plus the newest of the two most
	// recent ISO weeks (18 Oct for week 42, 11 Oct for week 41).
	want := []string{created[10].Name, created[15].Name, created[16].Name, created[17].Name}
	var kept []string
	for _, archive := range fixture.scheduler.Status().Archives {
		kept = append(kept, archive.Name)
		if !slices.Contains(names, archive.Name) {
			t.Fatalf("ledger lists %s but it is not on disk", archive.Name)
		}
	}
	slices.Sort(kept)
	if !slices.Equal(kept, want) {
		t.Fatalf("retained %q, want %q", kept, want)
	}
	for _, archive := range created[1:] {
		if slices.Contains(names, archive.Name) != slices.Contains(want, archive.Name) {
			t.Fatalf("archive %s on disk = %t, want %t", archive.Name, slices.Contains(names, archive.Name), slices.Contains(want, archive.Name))
		}
	}
	if !fixture.audit.find("backup.retention.delete", backup.ResultSucceeded) || !fixture.audit.find("backup.retention.delete", backup.ResultFailed) {
		t.Fatal("retention deletions and refusals are not audited")
	}
}

func TestFailedScheduledBackupRaisesDurableAlert(t *testing.T) {
	fixture := newSchedulerFixture(t, dailyPolicy(t, 7, 4))
	alerts, err := health.NewAlertStore(t.Context(), fixture.ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	evaluate := func() []health.Alert {
		t.Helper()
		registry := health.New()
		if err := registry.Replace(fixture.now, []health.Observation{fixture.scheduler.Observation(fixture.now)}); err != nil {
			t.Fatal(err)
		}
		if _, err := alerts.Evaluate(t.Context(), registry.Snapshot(fixture.now)); err != nil {
			t.Fatal(err)
		}
		active, err := alerts.List(t.Context(), health.AlertStateActive, 10)
		if err != nil {
			t.Fatal(err)
		}
		return active
	}
	if active := evaluate(); len(active) != 0 {
		t.Fatalf("alerts before any run = %+v", active)
	}

	good := fixture.source
	fixture.source = backup.InstallationSource{}
	if _, err := fixture.scheduler.Run(t.Context(), backup.TriggerSchedule, "system"); err == nil {
		t.Fatal("a backup without a system store succeeded")
	}
	if !fixture.audit.find("backup.scheduled", backup.ResultFailed) {
		t.Fatal("the failure is not audited")
	}
	if names := directoryNames(t, fixture.dir); len(names) != 0 {
		t.Fatalf("a failed run left %q behind", names)
	}
	active := evaluate()
	if len(active) != 1 || active[0].ComponentID != "scheduled-backup" || active[0].Severity != health.SeverityCritical {
		t.Fatalf("alerts after a failed run = %+v", active)
	}

	// The failure survives a restart.
	fixture.scheduler = fixture.open(t)
	policy := dailyPolicy(t, 7, 4)
	policy.Directory = fixture.dir
	if err := fixture.scheduler.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if state := fixture.scheduler.Status().State; state.LastResult != backup.ResultFailed {
		t.Fatalf("state after restart = %+v", state)
	}
	if active := evaluate(); len(active) != 1 {
		t.Fatalf("alert did not persist across restart: %+v", active)
	}

	fixture.source = good
	if _, err := fixture.scheduler.Run(t.Context(), backup.TriggerManual, "admin"); err != nil {
		t.Fatal(err)
	}
	if active := evaluate(); len(active) != 0 {
		t.Fatalf("a successful run did not resolve the alert: %+v", active)
	}
}

func TestSchedulerStateIsRestartSafe(t *testing.T) {
	fixture := newSchedulerFixture(t, dailyPolicy(t, 7, 4))
	if next := fixture.scheduler.Status().State.NextRunAt; !next.Equal(time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("next run = %v", next)
	}
	fixture.now = time.Date(2026, 10, 2, 3, 0, 10, 0, time.UTC)
	if _, err := fixture.scheduler.Run(t.Context(), backup.TriggerSchedule, "system"); err != nil {
		t.Fatal(err)
	}
	// Restart five days later with the same schedule: exactly one catch-up.
	fixture.now = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	restarted := fixture.open(t)
	policy := dailyPolicy(t, 7, 4)
	policy.Directory = fixture.dir
	if err := restarted.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	status := restarted.Status()
	if !status.State.LastAttemptAt.Equal(time.Date(2026, 10, 2, 3, 0, 10, 0, time.UTC)) || !status.State.NextRunAt.Equal(fixture.now) {
		t.Fatalf("restarted state = %+v", status.State)
	}
	stop := restarted.Start(t.Context())
	deadline := time.Now().Add(30 * time.Second)
	for restarted.Status().State.LastResult != backup.ResultSucceeded || !restarted.Status().State.LastAttemptAt.Equal(fixture.now) {
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("catch-up run did not happen: %+v", restarted.Status().State)
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if next := restarted.Status().State.NextRunAt; !next.Equal(time.Date(2026, 10, 8, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("next run after catch-up = %v", next)
	}
	// Changing the schedule does not run immediately for an earlier slot.
	policy.Schedule, _ = schedule.Parse("daily 08:00")
	if err := restarted.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if next := restarted.Status().State.NextRunAt; !next.Equal(time.Date(2026, 10, 8, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("next run after a schedule change = %v", next)
	}
}

func TestScheduledRunRefusesWhenSpaceIsShort(t *testing.T) {
	fixture := newSchedulerFixture(t, dailyPolicy(t, 7, 4))
	scheduler, err := backup.NewScheduler(t.Context(), backup.SchedulerOptions{
		Store: fixture.ts, Source: func() backup.InstallationSource { return fixture.source }, Capacity: fixedCapacity(1 << 20),
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := dailyPolicy(t, 7, 4)
	policy.Directory = fixture.dir
	if err := scheduler.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.Run(t.Context(), backup.TriggerManual, "admin"); err == nil || !strings.Contains(err.Error(), "free") {
		t.Fatalf("run with 1 MiB free = %v", err)
	}
}
