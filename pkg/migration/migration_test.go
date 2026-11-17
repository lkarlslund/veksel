package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type fakeSource struct {
	pages int
}

type deletionSource struct{}

type mixedHierarchySource struct{}
type specialFolderSource struct{}
type selectiveSource struct {
	requested []string
}
type parallelSource struct {
	started   chan string
	release   chan struct{}
	cancelErr error
}
type stalledPageSource struct {
	stalls int
	calls  int
}

type partlyFailingSource struct {
	fail bool
}

type pressureFailingSource struct {
	requested []string
}

type explicitEmptySource struct{}

type terminalItemFailureSource struct{}

func (*terminalItemFailureSource) ID() string { return "fake://terminal-item/alice" }
func (*terminalItemFailureSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "archive", Name: "Archive", Type: model.FolderTypeMail, Estimate: 2, EstimateKnown: true}}, nil
}
func (*terminalItemFailureSource) Items(_ context.Context, _ Folder, checkpoint string) (Page, error) {
	if checkpoint == "done" {
		return Page{Checkpoint: "done", Done: true}, nil
	}
	return Page{
		Items:                   []Item{{ID: "good-item", Version: "1", Data: []byte("Subject: retained\r\n\r\nbody")}},
		ItemFailures:            []ItemFailure{{ID: "password=source-id-secret", Error: "source item malformed; Authorization: Basic source-token-secret"}},
		Checkpoint:              "done",
		Done:                    true,
		InitialCoverageComplete: true,
	}, nil
}
func (*terminalItemFailureSource) Close() error { return nil }

func (*explicitEmptySource) ID() string { return "fake://empty/alice" }
func (*explicitEmptySource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "calendar", Name: "Calendar", Type: model.FolderTypeCalendar}}, nil
}
func (*explicitEmptySource) Items(context.Context, Folder, string) (Page, error) {
	return Page{Checkpoint: "covered", Done: true, InitialCoverageComplete: true, SourceExplicitlyEmpty: true}, nil
}
func (*explicitEmptySource) Close() error { return nil }

type pressureAlongsideHealthySource struct {
	pressureSeen chan struct{}
}

func (*pressureAlongsideHealthySource) ID() string { return "fake://pressure-with-inflight/alice" }
func (*pressureAlongsideHealthySource) Folders(context.Context) ([]Folder, error) {
	return []Folder{
		{ID: "mail", Name: "Mail", Type: model.FolderTypeMail},
		{ID: "calendar", Name: "Calendar", Type: model.FolderTypeCalendar},
	}, nil
}
func (s *pressureAlongsideHealthySource) Items(ctx context.Context, folder Folder, _ string) (Page, error) {
	if folder.ID == "mail" {
		close(s.pressureSeen)
		return Page{}, MarkSourcePressure(errors.New("server asked to retry later"))
	}
	select {
	case <-s.pressureSeen:
		return Page{Items: []Item{{ID: "event", Data: []byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n")}}, Checkpoint: "calendar-done", Done: true, InitialCoverageComplete: true}, nil
	case <-ctx.Done():
		return Page{}, ctx.Err()
	}
}
func (*pressureAlongsideHealthySource) Close() error           { return nil }
func (*pressureAlongsideHealthySource) FolderConcurrency() int { return 2 }

func (*pressureFailingSource) ID() string { return "fake://pressure/alice" }
func (*pressureFailingSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{
		{ID: "first", Name: "First", Type: model.FolderTypeMail},
		{ID: "second", Name: "Second", Type: model.FolderTypeMail},
	}, nil
}
func (s *pressureFailingSource) Items(_ context.Context, folder Folder, _ string) (Page, error) {
	s.requested = append(s.requested, folder.ID)
	return Page{}, MarkSourcePressure(errors.New("remote server requested retry later"))
}
func (*pressureFailingSource) Close() error           { return nil }
func (*pressureFailingSource) FolderConcurrency() int { return 1 }

func (*partlyFailingSource) ID() string { return "fake://partial/alice" }
func (*partlyFailingSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{
		{ID: "good", Name: "Good", Type: model.FolderTypeMail},
		{ID: "bad", Name: "Unavailable", Type: model.FolderTypeMail},
	}, nil
}
func (s *partlyFailingSource) Items(_ context.Context, folder Folder, checkpoint string) (Page, error) {
	if folder.ID == "bad" && s.fail {
		return Page{}, errors.New("remote collection unavailable")
	}
	if checkpoint == "done" {
		return Page{Checkpoint: "done", Done: true}, nil
	}
	return Page{Items: []Item{{ID: folder.ID, Version: "1", Data: []byte("Subject: " + folder.Name + "\r\n\r\nbody")}}, Checkpoint: "done", Done: true}, nil
}
func (*partlyFailingSource) Close() error           { return nil }
func (*partlyFailingSource) FolderConcurrency() int { return 2 }

type bulkSource struct {
	items int
}

func (s *bulkSource) ID() string { return "fake://bulk/alice" }
func (*bulkSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "bulk", Name: "Bulk", Type: model.FolderTypeMail}}, nil
}
func (s *bulkSource) Items(_ context.Context, _ Folder, checkpoint string) (Page, error) {
	if checkpoint == "done" {
		return Page{Checkpoint: checkpoint, Done: true}, nil
	}
	items := make([]Item, s.items)
	for index := range items {
		id := fmt.Sprintf("item-%03d", index)
		items[index] = Item{ID: id, Version: "1", Data: []byte("Subject: " + id + "\r\n\r\nbody")}
	}
	return Page{Items: items, Checkpoint: "done", Done: true}, nil
}
func (*bulkSource) Close() error { return nil }

type failingCreateSpace struct {
	service.FolderSpace
	creates int
	failAt  int
}

type countingBatchCreateSpace struct {
	service.FolderSpace
	batchCreates  int
	singleCreates int
	failBatch     bool
}

func (s *countingBatchCreateSpace) CreateItem(ctx context.Context, access service.AccessContext, folderID string, input service.ItemInput) (model.Item, error) {
	s.singleCreates++
	return s.FolderSpace.CreateItem(ctx, access, folderID, input)
}

func (s *countingBatchCreateSpace) CreateItems(ctx context.Context, access service.AccessContext, folderID string, inputs []service.ItemInput) ([]model.Item, error) {
	s.batchCreates++
	if s.failBatch {
		return nil, errors.New("injected batch failure")
	}
	return s.FolderSpace.(service.FolderItemBatchCreator).CreateItems(ctx, access, folderID, inputs)
}

type rejectingBatchSpace struct {
	service.FolderSpace
	batches int
}

func (s *rejectingBatchSpace) Batch(context.Context, func(context.Context) error) error {
	s.batches++
	return errors.New("cross-store batch must not be used")
}

func (s *failingCreateSpace) CreateItem(ctx context.Context, access service.AccessContext, folderID string, input service.ItemInput) (model.Item, error) {
	s.creates++
	if s.creates == s.failAt {
		return model.Item{}, errors.New("injected create failure")
	}
	return s.FolderSpace.CreateItem(ctx, access, folderID, input)
}

func (s *stalledPageSource) ID() string { return "fake://stalled/alice" }
func (*stalledPageSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "inbox", Name: "Inbox", Type: model.FolderTypeMail}}, nil
}
func (s *stalledPageSource) Items(_ context.Context, _ Folder, checkpoint string) (Page, error) {
	s.calls++
	if s.calls <= s.stalls {
		return Page{Checkpoint: checkpoint}, nil
	}
	return Page{Checkpoint: checkpoint, Done: true}, nil
}
func (*stalledPageSource) Close() error { return nil }

func (*parallelSource) ID() string { return "fake://parallel/alice" }
func (*parallelSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{
		{ID: "one", Name: "One", Type: model.FolderTypeMail},
		{ID: "two", Name: "Two", Type: model.FolderTypeMail},
	}, nil
}
func (s *parallelSource) Items(ctx context.Context, folder Folder, _ string) (Page, error) {
	s.started <- folder.ID
	select {
	case <-s.release:
		return Page{Done: true}, nil
	case <-ctx.Done():
		if s.cancelErr != nil {
			return Page{}, s.cancelErr
		}
		return Page{}, ctx.Err()
	}
}
func (*parallelSource) Close() error           { return nil }
func (*parallelSource) FolderConcurrency() int { return 2 }

func (*selectiveSource) ID() string { return "fake://selective/alice" }
func (*selectiveSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{
		{ID: "parent", Name: "Parent", Type: model.FolderTypeMail},
		{ID: "selected", ParentID: "parent", Name: "Selected", Type: model.FolderTypeMail},
		{ID: "ignored", ParentID: "parent", Name: "Ignored", Type: model.FolderTypeMail},
	}, nil
}
func (s *selectiveSource) Items(_ context.Context, folder Folder, _ string) (Page, error) {
	s.requested = append(s.requested, folder.ID)
	return Page{Done: true}, nil
}
func (*selectiveSource) Close() error { return nil }

func (*mixedHierarchySource) ID() string { return "fake://mixed/alice" }
func (*mixedHierarchySource) Folders(context.Context) ([]Folder, error) {
	return []Folder{
		{ID: "mail-parent", Name: "Container", Type: model.FolderTypeMail},
		{ID: "calendar-child", ParentID: "mail-parent", Name: "JYPA", Type: model.FolderTypeCalendar},
	}, nil
}
func (*mixedHierarchySource) Items(context.Context, Folder, string) (Page, error) {
	return Page{Done: true}, nil
}
func (*mixedHierarchySource) Close() error { return nil }

func (*specialFolderSource) ID() string { return "fake://special/alice" }
func (*specialFolderSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "remote-inbox", Name: "Inbox from source", Type: model.FolderTypeMail, Special: "\\Inbox"}}, nil
}
func (*specialFolderSource) Items(context.Context, Folder, string) (Page, error) {
	return Page{Done: true}, nil
}
func (*specialFolderSource) Close() error { return nil }

func (s *fakeSource) ID() string { return "fake://source/alice" }
func (s *fakeSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "remote-inbox", Name: "Imported Inbox", Type: model.FolderTypeMail, Estimate: 1, EstimateKnown: true}}, nil
}
func (s *fakeSource) Items(_ context.Context, _ Folder, checkpoint string) (Page, error) {
	s.pages++
	if checkpoint == "done" {
		return Page{Checkpoint: "done", Done: true}, nil
	}
	return Page{Items: []Item{{ID: "42", Version: "1", Data: []byte("Subject: migrated\r\n\r\nbody"), Headers: map[string]string{"Subject": "migrated"}}}, Checkpoint: "done", Done: true}, nil
}
func (s *fakeSource) Close() error { return nil }

func (*deletionSource) ID() string { return "fake://source/alice" }
func (*deletionSource) Folders(context.Context) ([]Folder, error) {
	return []Folder{{ID: "remote-inbox", Name: "Imported Inbox", Type: model.FolderTypeMail, EstimateKnown: true}}, nil
}
func (*deletionSource) Items(_ context.Context, _ Folder, checkpoint string) (Page, error) {
	if checkpoint == "deleted" {
		return Page{Checkpoint: checkpoint, Done: true}, nil
	}
	return Page{DeletedIDs: []string{"42", "already-absent"}, Checkpoint: "deleted", Done: true}, nil
}
func (*deletionSource) Close() error { return nil }

func TestFolderJSONUsesPublicAPIFieldNames(t *testing.T) {
	data, err := json.Marshal(Folder{ID: "inbox", Name: "Inbox", Type: model.FolderTypeMail, Estimate: 4, EstimateKnown: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["name"] != "Inbox" || decoded["type"] != "mail" || decoded["estimate"] != float64(4) || decoded["estimate_known"] != true {
		t.Fatalf("folder JSON = %s", data)
	}
	for _, legacy := range []string{"Name", "Type", "Estimate"} {
		if _, exists := decoded[legacy]; exists {
			t.Errorf("folder JSON contains legacy field %q: %s", legacy, data)
		}
	}
}

func TestConnectionProfileNeverPersistsPassword(t *testing.T) {
	profile := NewConnectionProfile(SourceOptions{
		Endpoint: " mail.example.test:993 ", Username: " alice ", Password: "secret", TLSMode: "implicit", Insecure: true, PageSize: 25,
	})
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || containsJSONValue(data, "secret") {
		t.Fatalf("connection profile contains password: %s", data)
	}
	options := profile.SourceOptions("next-secret")
	if options.Endpoint != "mail.example.test:993" || options.Username != "alice" || options.Password != "next-secret" {
		t.Fatalf("source options = %#v", options)
	}
}

func TestLegacyConnectionProfileUsesPersistedSourceIdentity(t *testing.T) {
	profile := legacyConnectionProfile("eas", `eas://DOMAIN\alice@mail.example.test/Microsoft-Server-ActiveSync`)
	if profile.Username != `DOMAIN\alice` || profile.Endpoint != "https://mail.example.test/Microsoft-Server-ActiveSync" || profile.TLSMode != "https" {
		t.Fatalf("legacy profile = %#v", profile)
	}
}

func containsJSONValue(data []byte, value string) bool {
	var decoded any
	if json.Unmarshal(data, &decoded) != nil {
		return false
	}
	return strings.Contains(string(data), value)
}

func migrationTestSetup(t *testing.T) (*Store, *Runner, service.FolderSpace) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	jobs, err := NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	return jobs, NewRunner(jobs, space), space
}

func TestRunnerImportsAndCheckpointsIdempotently(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &fakeSource{}); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil || completed.State != StateCompleted || completed.ImportedItems != 1 || completed.Checkpoints["remote-inbox"] != "done" {
		t.Fatalf("job=%#v err=%v", completed, err)
	}
	if completed.RunStartedAt.IsZero() || completed.RunFinishedAt.IsZero() || completed.RunFinishedAt.Before(completed.RunStartedAt) {
		t.Fatalf("run timestamps = %s to %s", completed.RunStartedAt, completed.RunFinishedAt)
	}
	if completed.RunFoldersTotal != 1 || completed.RunFoldersDone != 1 || completed.RunImportedItems != 1 || completed.RunImportedBytes == 0 || completed.RunSkippedItems != 0 || completed.RunItemsPerSecond <= 0 || completed.RunBytesPerSecond <= 0 {
		t.Fatalf("run telemetry = %#v", completed)
	}
	if completed.RunOutcome != RunOutcomeCompleted || !completed.RunSourceItemsKnown || completed.RunSourceItems != 1 || completed.RunItemsExamined != 1 || completed.RunItemsFailed != 0 || !completed.RunItemsRemainingKnown || completed.RunItemsRemaining != 0 || !completed.RunTraversalComplete {
		t.Fatalf("run progress outcome = %#v", completed)
	}
	if completed.RunLastCheckpointFolderID != "remote-inbox" || completed.RunLastCheckpointFolderName != "Imported Inbox" || completed.RunLastCheckpointAt.IsZero() {
		t.Fatalf("run checkpoint evidence = %#v", completed)
	}
	if completed.RunSourceCalls != 1 || completed.RunSourceConcurrency != 1 || completed.RunSourcePeak != 1 || completed.SourceConcurrencyHint != 1 {
		t.Fatalf("source telemetry = %#v", completed)
	}
	if len(completed.RunFolderResults) != 1 {
		t.Fatalf("folder reconciliation = %#v", completed.RunFolderResults)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 20)
	if err != nil || len(runs) != 1 || runs[0].State != StateCompleted || runs[0].Outcome != RunOutcomeCompleted || runs[0].ImportedItems != 1 || runs[0].ItemsExamined != 1 || !runs[0].TraversalComplete || runs[0].LastCheckpointFolderID != "remote-inbox" || len(runs[0].FolderResults) != 1 {
		t.Fatalf("first retained run = %#v, %v", runs, err)
	}
	reconciled := completed.RunFolderResults[0]
	if reconciled.State != "matched" || !reconciled.SourceItemsKnown || reconciled.SourceItems != 1 || reconciled.DestinationItemsBefore != 0 || reconciled.DestinationItemsAfter != 1 || reconciled.ImportedItems != 1 || reconciled.Checkpoint != "done" || reconciled.CompletedAt.IsZero() {
		t.Fatalf("folder reconciliation = %#v", reconciled)
	}
	folder, err := space.GetFolder(t.Context(), service.UserAccess("alice", "test"), completed.FolderMap["remote-inbox"])
	if err != nil {
		t.Fatal(err)
	}
	items, err := space.ListItems(t.Context(), service.UserAccess("alice", "test"), folder.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%v err=%v", items, err)
	}
	if items[0].ExternalIDs["fake://source/alice"] != "42" || completed.IndexedSources["remote-inbox"] != "fake://source/alice" {
		t.Fatalf("external index item=%v folders=%v", items[0].ExternalIDs, completed.IndexedSources)
	}
	if indexed, lookupErr := space.GetItemByExternalID(t.Context(), service.UserAccess("alice", "test"), folder.ID, "fake://source/alice", "42"); lookupErr != nil || indexed.ID != items[0].ID {
		t.Fatalf("indexed=%#v err=%v", indexed, lookupErr)
	}

	completed.State = StatePaused
	completed.Checkpoints["remote-inbox"] = ""
	if err := jobs.Save(t.Context(), completed); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &fakeSource{}); err != nil {
		t.Fatal(err)
	}
	completed, _ = jobs.Get(t.Context(), job.ID)
	if completed.ImportedItems != 1 || completed.SkippedItems != 1 {
		t.Fatalf("idempotent counters=%#v", completed)
	}
	if completed.RunFoldersTotal != 1 || completed.RunFoldersDone != 1 || completed.RunImportedItems != 0 || completed.RunSkippedItems != 1 {
		t.Fatalf("second-run telemetry=%#v", completed)
	}
	if len(completed.RunFolderResults) != 1 || completed.RunFolderResults[0].State != "matched" || completed.RunFolderResults[0].DestinationItemsBefore != 1 || completed.RunFolderResults[0].DestinationItemsAfter != 1 || completed.RunFolderResults[0].SkippedItems != 1 {
		t.Fatalf("second-run reconciliation=%#v", completed.RunFolderResults)
	}
	runs, err = jobs.Runs(t.Context(), job.ID, 20)
	if err != nil || len(runs) != 2 || !runs[0].StartedAt.After(runs[1].StartedAt) || runs[0].SkippedItems != 1 {
		t.Fatalf("retained run history = %#v, %v", runs, err)
	}
	updatedData := []byte("Subject: migrated update\r\n\r\nnew body")
	outcome, err := runner.importItem(t.Context(), service.UserAccess("alice", "test"), "fake://source/alice", folder.ID, Item{
		ID: "42", Version: "2", Data: updatedData, Headers: map[string]string{"Subject": "migrated update"}, Flags: []string{model.FlagSeen},
	}, ConflictSourceWins)
	if err != nil || !outcome.imported {
		t.Fatalf("update outcome=%+v err=%v", outcome, err)
	}
	items, err = space.ListItems(t.Context(), service.UserAccess("alice", "test"), folder.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 || items[0].Headers["Subject"] != "migrated update" {
		t.Fatalf("updated items=%v err=%v", items, err)
	}
}

func TestRunnerRetainsExplicitEmptyInitialCoverageEvidence(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &explicitEmptySource{}); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil || len(completed.RunFolderResults) != 1 {
		t.Fatalf("job=%#v error=%v", completed, err)
	}
	result := completed.RunFolderResults[0]
	if !result.InitialCoverageComplete || !result.SourceExplicitlyEmpty || !result.SourceItemsKnown || result.SourceItems != 0 || result.State != "matched" || !result.TraversalComplete {
		t.Fatalf("reconciliation=%#v", result)
	}
}

func TestRunnerLetsInflightFolderCheckpointAfterSourcePressure(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	source := &pressureAlongsideHealthySource{pressureSeen: make(chan struct{})}
	if err := runner.Run(t.Context(), job.ID, source); err == nil || !isSourcePressure(err) {
		t.Fatalf("run error=%v", err)
	}
	failed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Checkpoints["calendar"] != "calendar-done" || failed.RunImportedItems != 1 {
		t.Fatalf("healthy in-flight folder was not retained: %#v", failed)
	}
	var calendar *FolderReconciliation
	for index := range failed.RunFolderResults {
		if failed.RunFolderResults[index].SourceFolderID == "calendar" {
			calendar = &failed.RunFolderResults[index]
		}
	}
	if calendar == nil || !calendar.TraversalComplete || calendar.ImportedItems != 1 {
		t.Fatalf("calendar result=%#v all=%#v", calendar, failed.RunFolderResults)
	}
}

func TestSuccessfulCutoverRetainsEvidenceAndDisablesSchedule(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{
		OwnerID: "alice", DestinationID: "alice", SourceType: "fake",
		Schedule: ScheduleHourly, CutoverRequested: true, CutoverState: "pending",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &fakeSource{}); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil || completed.Schedule != ScheduleManual || completed.CutoverState != "completed" || completed.CutoverAt.IsZero() || !completed.NextRunAt.IsZero() {
		t.Fatalf("cutover job = %#v, %v", completed, err)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 1 || !runs[0].Cutover || runs[0].State != StateCompleted {
		t.Fatalf("cutover evidence = %#v, %v", runs, err)
	}
	if err := jobs.Delete(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	runs, err = jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 0 {
		t.Fatalf("run evidence remained after profile deletion = %#v, %v", runs, err)
	}
}

func TestRunHistoryPagesAreStableNewestFirst(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.August, 20, 8, 0, 0, 0, time.UTC)
	for index := 0; index < 5; index++ {
		job.RunStartedAt = base.Add(time.Duration(index) * time.Minute)
		job.RunFinishedAt = job.RunStartedAt.Add(30 * time.Second)
		job.State = StateCompleted
		job.RunOutcome = RunOutcomeCompleted
		job.RunImportedItems = int64(index)
		if err := jobs.SaveRun(t.Context(), job); err != nil {
			t.Fatal(err)
		}
	}

	first, total, cursor, err := jobs.RunsPage(t.Context(), job.ID, "", 2)
	if err != nil || total != 5 || len(first) != 2 || first[0].ImportedItems != 4 || first[1].ImportedItems != 3 || cursor != first[1].ID {
		t.Fatalf("first page runs=%#v total=%d cursor=%q err=%v", first, total, cursor, err)
	}
	retained, err := jobs.Run(t.Context(), job.ID, first[0].ID)
	if err != nil || retained.ID != first[0].ID || retained.ImportedItems != 4 {
		t.Fatalf("retained run=%#v err=%v", retained, err)
	}
	second, secondTotal, nextCursor, err := jobs.RunsPage(t.Context(), job.ID, cursor, 2)
	if err != nil || secondTotal != 5 || len(second) != 2 || second[0].ImportedItems != 2 || second[1].ImportedItems != 1 || nextCursor != second[1].ID {
		t.Fatalf("second page runs=%#v total=%d cursor=%q err=%v", second, secondTotal, nextCursor, err)
	}
	last, lastTotal, lastCursor, err := jobs.RunsPage(t.Context(), job.ID, nextCursor, 2)
	if err != nil || lastTotal != 5 || len(last) != 1 || last[0].ImportedItems != 0 || lastCursor != "" {
		t.Fatalf("last page runs=%#v total=%d cursor=%q err=%v", last, lastTotal, lastCursor, err)
	}
	if _, _, _, err := jobs.RunsPage(t.Context(), job.ID, job.ID+":missing", 2); err == nil {
		t.Fatal("missing cursor was accepted")
	}
	other, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := jobs.RunsPage(t.Context(), other.ID, cursor, 2); err == nil {
		t.Fatal("cursor from another job was accepted")
	}
	if _, err := jobs.Run(t.Context(), other.ID, first[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-job run lookup error=%v", err)
	}
}

func TestFolderPreflightIsNonMutatingAndModelsHierarchy(t *testing.T) {
	_, runner, space := migrationTestSetup(t)
	access := service.UserAccess("alice", "test")
	before, err := space.ListFolders(t.Context(), access, service.FolderQuery{})
	if err != nil {
		t.Fatal(err)
	}
	folders := []Folder{
		{ID: "remote-inbox", Name: "Remote inbox", Type: model.FolderTypeMail, Special: "\\Inbox"},
		{ID: "calendar-name", Name: "Calendar", Type: model.FolderTypeMail},
		{ID: "child", ParentID: "calendar-name", Name: "Child", Type: model.FolderTypeMail},
	}
	plan, err := runner.PreflightFolders(t.Context(), "alice", folders, []string{"remote-inbox", "child"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || plan.Reuses != 1 || plan.Creates != 2 || plan.Conflicts != 0 || len(plan.Mappings) != 3 {
		t.Fatalf("preflight summary = %#v", plan)
	}
	bySource := make(map[string]FolderMapping, len(plan.Mappings))
	for _, mapping := range plan.Mappings {
		bySource[mapping.SourceFolderID] = mapping
	}
	if inbox := bySource["remote-inbox"]; inbox.Action != FolderMappingReuse || inbox.Reason != "special-use" || inbox.DestinationFolderID != model.InboxFolderID("alice") || !inbox.Transfer {
		t.Fatalf("inbox mapping = %#v", inbox)
	}
	if parent := bySource["calendar-name"]; parent.Action != FolderMappingCreate || parent.DestinationPath != "Calendar (mail)" || parent.Transfer {
		t.Fatalf("parent mapping = %#v", parent)
	}
	if child := bySource["child"]; child.Action != FolderMappingCreate || child.DestinationPath != "Calendar (mail)/Child" || !child.Transfer {
		t.Fatalf("child mapping = %#v", child)
	}
	after, err := space.ListFolders(t.Context(), access, service.FolderQuery{})
	if err != nil || len(after) != len(before) {
		t.Fatalf("preflight mutated folders: before=%d after=%d err=%v", len(before), len(after), err)
	}
}

func TestFolderPreflightValidatesExplicitTargets(t *testing.T) {
	_, runner, space := migrationTestSetup(t)
	access := service.UserAccess("alice", "test")
	archive, err := space.GetFolderByPath(t.Context(), access, "Archive")
	if err != nil {
		t.Fatal(err)
	}
	calendar, err := space.GetFolderByPath(t.Context(), access, "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	folders := []Folder{
		{ID: "mapped", Name: "Mapped", Type: model.FolderTypeMail},
		{ID: "invalid", Name: "Invalid", Type: model.FolderTypeMail},
	}
	plan, err := runner.PreflightFolders(t.Context(), "alice", folders, nil, map[string]string{
		"mapped": archive.ID, "invalid": calendar.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready || plan.Reuses != 1 || plan.Conflicts != 1 || plan.Mappings[0].DestinationFolderID != archive.ID || plan.Mappings[1].Action != FolderMappingConflict || plan.Mappings[1].Error == "" {
		t.Fatalf("explicit target plan = %#v", plan)
	}
}

func TestFolderPreflightDoesNotMergeDistinctAutomaticSources(t *testing.T) {
	_, runner, _ := migrationTestSetup(t)
	folders := []Folder{
		{ID: "first", Name: "Archive", Type: model.FolderTypeMail},
		{ID: "second", Name: "Archive", Type: model.FolderTypeMail},
	}
	plan, err := runner.PreflightFolders(t.Context(), "alice", folders, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || plan.Reuses != 1 || plan.Creates != 1 || plan.Mappings[0].DestinationPath != "Archive" || plan.Mappings[1].DestinationPath != "Archive (mail)" {
		t.Fatalf("duplicate source plan = %#v", plan)
	}
}

func TestStorePreservesExplicitFolderTargets(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	created, err := jobs.Create(t.Context(), Job{
		OwnerID: "alice", DestinationID: "alice", SourceType: "fake",
		FolderTargets: map[string]string{"remote": "local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.FolderTargets["remote"] != "local" {
		t.Fatalf("created job = %#v", created)
	}
	created.FolderTargets["remote"] = "mutated"
	stored, err := jobs.Get(t.Context(), created.ID)
	if err != nil || stored.FolderTargets["remote"] != "local" {
		t.Fatalf("stored job = %#v, %v", stored, err)
	}
}

func TestImportConflictPoliciesForExistingDestinationName(t *testing.T) {
	for _, test := range []struct {
		name       string
		policy     ConflictPolicy
		wantItems  int
		wantSource string
	}{
		{name: "source wins", policy: ConflictSourceWins, wantItems: 1, wantSource: "source"},
		{name: "destination wins", policy: ConflictDestinationWins, wantItems: 1, wantSource: "local"},
		{name: "keep both", policy: ConflictKeepBoth, wantItems: 2, wantSource: "source"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, runner, space := migrationTestSetup(t)
			access := service.UserAccess("alice", "test")
			contacts, err := space.GetFolderByPath(t.Context(), access, "Contacts")
			if err != nil {
				t.Fatal(err)
			}
			local, err := space.CreateItem(t.Context(), access, contacts.ID, service.ItemInput{Name: "person.vcf", Data: []byte("local")})
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := runner.importItem(t.Context(), access, "source", contacts.ID, Item{
				ID: "person-1", Version: "1", Name: "person.vcf", Data: []byte("source"),
			}, test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if !outcome.conflict || outcome.imported != (test.policy != ConflictDestinationWins) || outcome.preserved != (test.policy == ConflictKeepBoth) {
				t.Fatalf("outcome = %+v", outcome)
			}
			items, err := space.ListItems(t.Context(), access, contacts.ID, service.ItemQuery{})
			if err != nil || len(items) != test.wantItems {
				t.Fatalf("items = %#v, %v", items, err)
			}
			if test.policy == ConflictDestinationWins {
				retained, err := space.GetItem(t.Context(), access, local.ID)
				if err != nil || string(retained.Data) != test.wantSource {
					t.Fatalf("retained destination = %#v, %v", retained, err)
				}
				return
			}
			tracked, err := space.GetItemByExternalID(t.Context(), access, contacts.ID, "source", "person-1")
			if err != nil || string(tracked.Data) != test.wantSource {
				t.Fatalf("tracked source = %#v, %v", tracked, err)
			}
		})
	}
}

func TestImportConflictPoliciesForConcurrentSourceAndDestinationEdits(t *testing.T) {
	for _, test := range []struct {
		name       string
		policy     ConflictPolicy
		wantSource string
		wantItems  int
	}{
		{name: "source wins", policy: ConflictSourceWins, wantSource: "source-v2", wantItems: 1},
		{name: "destination wins", policy: ConflictDestinationWins, wantSource: "local-edit", wantItems: 1},
		{name: "keep both", policy: ConflictKeepBoth, wantSource: "source-v2", wantItems: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, runner, space := migrationTestSetup(t)
			access := service.UserAccess("alice", "test")
			inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
			if err != nil {
				t.Fatal(err)
			}
			first, err := runner.importItem(t.Context(), access, "source", inbox.ID, Item{ID: "42", Version: "1", Data: []byte("source-v1")}, ConflictSourceWins)
			if err != nil || !first.imported {
				t.Fatalf("initial import = %+v, %v", first, err)
			}
			tracked, err := space.GetItemByExternalID(t.Context(), access, inbox.ID, "source", "42")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := space.UpdateItem(t.Context(), access, tracked.ID, []byte("local-edit"), map[string]string{"Subject": "local"}); err != nil {
				t.Fatal(err)
			}
			outcome, err := runner.importItem(t.Context(), access, "source", inbox.ID, Item{ID: "42", Version: "2", Data: []byte("source-v2")}, test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if !outcome.conflict || outcome.imported != (test.policy != ConflictDestinationWins) || outcome.preserved != (test.policy == ConflictKeepBoth) {
				t.Fatalf("conflict outcome = %+v", outcome)
			}
			tracked, err = space.GetItemByExternalID(t.Context(), access, inbox.ID, "source", "42")
			if err != nil || string(tracked.Data) != test.wantSource {
				t.Fatalf("tracked item = %#v, %v", tracked, err)
			}
			items, err := space.ListItems(t.Context(), access, inbox.ID, service.ItemQuery{})
			if err != nil || len(items) != test.wantItems {
				t.Fatalf("items = %#v, %v", items, err)
			}
			if test.policy == ConflictKeepBoth {
				foundLocal := false
				for _, candidate := range items {
					if string(candidate.Data) == "local-edit" && candidate.ID != tracked.ID {
						foundLocal = true
					}
				}
				if !foundLocal {
					t.Fatalf("local preservation copy missing from %#v", items)
				}
			}
		})
	}
}

func TestImportSkipsUnchangedContentReplayedUnderNewSourceVersion(t *testing.T) {
	_, runner, space := migrationTestSetup(t)
	access := service.UserAccess("alice", "test")
	inbox, err := space.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	item := Item{ID: "remote-42", Version: "sync-key-1", Data: []byte("Subject: unchanged\r\n\r\nbody"), Headers: map[string]string{"Subject": "unchanged"}, Flags: []string{model.FlagSeen}}
	first, err := runner.importItem(t.Context(), access, "source", inbox.ID, item, ConflictSourceWins)
	if err != nil || !first.imported {
		t.Fatalf("first import = %+v, %v", first, err)
	}
	tracked, err := space.GetItemByExternalID(t.Context(), access, inbox.ID, "source", item.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeModSeq := tracked.ModSeq
	item.Version = "sync-key-after-reset"
	replayed, err := runner.importItem(t.Context(), access, "source", inbox.ID, item, ConflictSourceWins)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.imported || replayed.bytes != 0 || replayed.conflict || replayed.preserved {
		t.Fatalf("unchanged replay = %+v, want skipped", replayed)
	}
	tracked, err = space.GetItemByExternalID(t.Context(), access, inbox.ID, "source", item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tracked.ModSeq != beforeModSeq || tracked.Headers[migrationItemHeader] != "remote-42@sync-key-1" {
		t.Fatalf("unchanged replay rewrote metadata: before modseq=%d after=%#v", beforeModSeq, tracked)
	}
}

func TestRunnerAppliesSourceDeletionPolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		policy  SourceDeletionPolicy
		trashed bool
	}{
		{name: "retain destination item", policy: SourceDeletionRetain},
		{name: "move destination item to trash", policy: SourceDeletionTrash, trashed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			jobs, runner, space := migrationTestSetup(t)
			job, err := jobs.Create(t.Context(), Job{
				OwnerID: "alice", DestinationID: "alice", SourceType: "fake", SourceDeletionPolicy: test.policy,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := runner.Run(t.Context(), job.ID, &fakeSource{}); err != nil {
				t.Fatal(err)
			}
			job, err = jobs.Get(t.Context(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			job.State = StatePaused
			job.Checkpoints["remote-inbox"] = ""
			if err := jobs.Save(t.Context(), job); err != nil {
				t.Fatal(err)
			}
			if err := runner.Run(t.Context(), job.ID, &deletionSource{}); err != nil {
				t.Fatal(err)
			}

			completed, err := jobs.Get(t.Context(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if completed.SourceDeletedItems != 2 || completed.RunSourceDeletedItems != 2 {
				t.Fatalf("source deletion counters = total %d run %d", completed.SourceDeletedItems, completed.RunSourceDeletedItems)
			}
			wantTrashed := int64(0)
			if test.trashed {
				wantTrashed = 1
			}
			if completed.RunTrashedItems != wantTrashed || completed.Checkpoints["remote-inbox"] != "deleted" {
				t.Fatalf("completed deletion run = %#v", completed)
			}
			if len(completed.RunFolderResults) != 1 || completed.RunFolderResults[0].SourceDeletedItems != 2 || completed.RunFolderResults[0].TrashedItems != wantTrashed {
				t.Fatalf("deletion reconciliation = %#v", completed.RunFolderResults)
			}
			wantState := "drift"
			if test.trashed {
				wantState = "matched"
			}
			if completed.RunFolderResults[0].State != wantState {
				t.Fatalf("deletion reconciliation state = %q, want %q", completed.RunFolderResults[0].State, wantState)
			}
			access := service.UserAccess("alice", "test")
			if test.trashed {
				recoverable := space.(service.RecoverableFolderSpace)
				trash, err := recoverable.ListTrash(t.Context(), access)
				if err != nil {
					t.Fatal(err)
				}
				if len(trash) != 1 || trash[0].OriginalFolderID != completed.FolderMap["remote-inbox"] {
					t.Fatalf("trash = %#v", trash)
				}
			} else {
				item, err := space.GetItemMetadataByExternalID(
					t.Context(), access, completed.FolderMap["remote-inbox"], "fake://source/alice", "42",
				)
				if err != nil || !item.TrashedAt.IsZero() {
					t.Fatalf("retained item = %#v, err = %v", item, err)
				}
			}
		})
	}
}

func TestRunnerPersistsBoundedProgressWithoutAdvancingPageCheckpoint(t *testing.T) {
	jobs, _, space := migrationTestSetup(t)
	failing := &failingCreateSpace{FolderSpace: space, failAt: transferCommitChunkSize + 2}
	runner := NewRunner(jobs, failing)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	err = runner.Run(t.Context(), job.ID, &bulkSource{items: transferCommitChunkSize*2 + 5})
	if err == nil || !strings.Contains(err.Error(), "injected create failure") {
		t.Fatalf("Run error = %v", err)
	}
	failed, getErr := jobs.Get(t.Context(), job.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if failed.State != StateFailed || failed.ImportedItems != transferCommitChunkSize+1 {
		t.Fatalf("failed job = %#v", failed)
	}
	if failed.RunOutcome != RunOutcomeFatalFailure || failed.RunItemsExamined != transferCommitChunkSize+2 || failed.RunItemsFailed != 1 || failed.RunTraversalComplete || failed.RunFatalError == "" {
		t.Fatalf("failed run outcome = %#v", failed)
	}
	if failure := failed.RunTerminalFailure; failure == nil || failure.Phase != FailurePhaseDestinationWrite || failure.FolderID != "bulk" || failure.ItemID == "" || failure.OccurredAt.IsZero() || failure.RetryDisposition != RetryManualReview {
		t.Fatalf("structured item failure = %#v", failure)
	}
	if failed.RunSourceItemsKnown || failed.RunItemsRemainingKnown {
		t.Fatalf("unknown source estimate presented as exact = %#v", failed)
	}
	if checkpoint := failed.Checkpoints["bulk"]; checkpoint != "" {
		t.Fatalf("checkpoint advanced past a partially committed page: %q", checkpoint)
	}
}

func TestRunnerBatchesConflictFreeCreatesWithinCheckpointChunks(t *testing.T) {
	jobs, _, space := migrationTestSetup(t)
	counting := &countingBatchCreateSpace{FolderSpace: space}
	runner := NewRunner(jobs, counting)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	itemCount := transferCommitChunkSize*2 + 5
	if err := runner.Run(t.Context(), job.ID, &bulkSource{items: itemCount}); err != nil {
		t.Fatal(err)
	}
	if counting.batchCreates != 3 || counting.singleCreates != 0 {
		t.Fatalf("create calls = %d batch, %d single; want 3 batch, 0 single", counting.batchCreates, counting.singleCreates)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.RunImportedItems != int64(itemCount) || completed.RunItemsExamined != int64(itemCount) || completed.Checkpoints["bulk"] != "done" {
		t.Fatalf("completed job = %#v", completed)
	}
}

func TestTransferChunkEndBoundsItemsAndPayloadBytes(t *testing.T) {
	small := make([]Item, transferCommitChunkSize+7)
	if end := transferChunkEnd(small, 0); end != transferCommitChunkSize {
		t.Fatalf("small-item chunk end = %d, want %d", end, transferCommitChunkSize)
	}
	if end := transferChunkEnd(small, transferCommitChunkSize); end != len(small) {
		t.Fatalf("tail chunk end = %d, want %d", end, len(small))
	}

	halfLimit := make([]byte, transferCommitChunkBytes/2)
	large := []Item{{Data: halfLimit}, {Data: halfLimit}, {Data: []byte("overflow")}}
	if end := transferChunkEnd(large, 0); end != 2 {
		t.Fatalf("byte-bounded chunk end = %d, want 2", end)
	}
	oversized := []Item{{Data: make([]byte, transferCommitChunkBytes+1)}, {Data: []byte("next")}}
	if end := transferChunkEnd(oversized, 0); end != 1 {
		t.Fatalf("oversized-item chunk end = %d, want 1", end)
	}
}

func TestRunnerFallsBackToItemCreatesWhenAtomicBatchFails(t *testing.T) {
	jobs, _, space := migrationTestSetup(t)
	counting := &countingBatchCreateSpace{FolderSpace: space, failBatch: true}
	runner := NewRunner(jobs, counting)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	itemCount := transferCommitChunkSize + 1
	if err := runner.Run(t.Context(), job.ID, &bulkSource{items: itemCount}); err != nil {
		t.Fatal(err)
	}
	if counting.batchCreates != 2 || counting.singleCreates != itemCount {
		t.Fatalf("create calls = %d batch, %d single; want 2 batch attempts, %d single", counting.batchCreates, counting.singleCreates, itemCount)
	}
}

func TestRunnerDoesNotHoldCrossStoreBatchWhileWritingItems(t *testing.T) {
	jobs, _, space := migrationTestSetup(t)
	guarded := &rejectingBatchSpace{FolderSpace: space}
	runner := NewRunner(jobs, guarded)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &bulkSource{items: transferCommitChunkSize + 1}); err != nil {
		t.Fatal(err)
	}
	if guarded.batches != 0 {
		t.Fatalf("cross-store batches = %d, want 0", guarded.batches)
	}
}

func TestReadAdvancingPageRetriesTransientSourceStall(t *testing.T) {
	source := &stalledPageSource{stalls: 2}
	page, stats, err := readAdvancingPageObserved(t.Context(), source, Folder{ID: "inbox"}, "checkpoint", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Done || source.calls != 3 {
		t.Fatalf("page=%#v calls=%d, want completed page after 3 calls", page, source.calls)
	}
	if stats.calls != 1 || stats.attempts != 3 || stats.retries != 2 {
		t.Fatalf("read stats = %+v", stats)
	}
}

func TestReadAdvancingPageRejectsPersistentSourceStall(t *testing.T) {
	source := &stalledPageSource{stalls: 4}
	_, err := readAdvancingPage(t.Context(), source, Folder{ID: "inbox"}, "checkpoint", 3, 0)
	if err == nil || !strings.Contains(err.Error(), "empty non-advancing page after 3 attempts") {
		t.Fatalf("err=%v calls=%d", err, source.calls)
	}
	if source.calls != 3 {
		t.Fatalf("calls=%d, want 3", source.calls)
	}
}

func TestSourceConcurrencyControllerUsesAdditiveIncreaseAndMultiplicativeDecrease(t *testing.T) {
	controller := newSourceConcurrencyController(4, 0)
	if controller.limitValue() != 2 {
		t.Fatalf("initial limit = %d, want 2", controller.limitValue())
	}
	if err := controller.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	controller.release(sourceReadStats{calls: 1, retries: 1}, nil)
	if controller.limitValue() != 1 {
		t.Fatalf("limit after pressure = %d, want 1", controller.limitValue())
	}
	for range 4 {
		if err := controller.acquire(t.Context()); err != nil {
			t.Fatal(err)
		}
		controller.release(sourceReadStats{calls: 1}, nil)
	}
	if controller.limitValue() != 2 {
		t.Fatalf("limit after healthy reads = %d, want 2", controller.limitValue())
	}
}

func TestSourceConcurrencyControllerDoesNotReuseSerializedHint(t *testing.T) {
	controller := newSourceConcurrencyController(4, 1)
	if controller.limitValue() != 2 {
		t.Fatalf("initial limit = %d, want stale hint raised to 2", controller.limitValue())
	}
}

func TestRunnerFlattensMixedTypeSourceHierarchy(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	access := service.UserAccess("alice", "test")
	wrongType, err := space.CreateFolder(t.Context(), access, "JYPA", model.FolderTypeMail, "")
	if err != nil {
		t.Fatal(err)
	}
	job.FolderMap["calendar-child"] = wrongType.ID
	if err := jobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &mixedHierarchySource{}); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := space.GetFolder(t.Context(), access, completed.FolderMap["calendar-child"])
	if err != nil {
		t.Fatal(err)
	}
	if child.Type != model.FolderTypeCalendar || child.ParentID != "" || child.Path != "JYPA (calendar)" {
		t.Fatalf("flattened child = %#v", child)
	}
}

func TestRunnerMapsProtocolSpecialUseToExistingFolder(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &specialFolderSource{}); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := completed.FolderMap["remote-inbox"]; got != model.InboxFolderID("alice") {
		t.Fatalf("mapped inbox = %q, want %q", got, model.InboxFolderID("alice"))
	}
}

func TestRunnerImportsOnlySelectedFoldersAndCreatesAncestors(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{
		OwnerID: "alice", DestinationID: "alice", SourceType: "fake", SelectedFolderIDs: []string{"selected"},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &selectiveSource{}
	if err := runner.Run(t.Context(), job.ID, source); err != nil {
		t.Fatal(err)
	}
	if len(source.requested) != 1 || source.requested[0] != "selected" {
		t.Fatalf("requested folders = %v", source.requested)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.FolderMap["parent"] == "" || completed.FolderMap["selected"] == "" || completed.FolderMap["ignored"] != "" {
		t.Fatalf("folder map = %#v", completed.FolderMap)
	}
	selected, err := space.GetFolder(t.Context(), service.UserAccess("alice", "test"), completed.FolderMap["selected"])
	if err != nil {
		t.Fatal(err)
	}
	if selected.ParentID != completed.FolderMap["parent"] {
		t.Fatalf("selected parent = %q, want %q", selected.ParentID, completed.FolderMap["parent"])
	}
}

func TestRunnerTransfersIndependentFoldersConcurrently(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	source := &parallelSource{started: make(chan string, 2), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- runner.Run(t.Context(), job.ID, source) }()
	for range 2 {
		select {
		case <-source.started:
		case <-time.After(2 * time.Second):
			close(source.release)
			t.Fatal("folders did not transfer concurrently")
		}
	}
	running, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		close(source.release)
		t.Fatal(err)
	}
	if running.State != StateRunning || running.RunFoldersTotal != 2 || running.RunFoldersDone != 0 {
		close(source.release)
		t.Fatalf("running telemetry = %#v", running)
	}
	close(source.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil || completed.RunFoldersTotal != 2 || completed.RunFoldersDone != 2 {
		t.Fatalf("completed telemetry = %#v, err=%v", completed, err)
	}
}

func TestMigrationFolderPriorityPreventsCalendarStarvation(t *testing.T) {
	ordered := []model.FolderType{
		model.FolderTypeCalendar,
		model.FolderTypeContacts,
		model.FolderTypeNotes,
		model.FolderTypeFiles,
		model.FolderTypeMail,
	}
	for index := 1; index < len(ordered); index++ {
		if migrationFolderPriority(ordered[index-1]) >= migrationFolderPriority(ordered[index]) {
			t.Fatalf("priority order is not increasing: %v", ordered)
		}
	}
}

func TestRunnerCompletesTraversalWithTerminalItemFailureAndResumesWithoutDuplicates(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	source := &terminalItemFailureSource{}
	if err := runner.Run(t.Context(), job.ID, source); err != nil {
		t.Fatalf("Run error = %v", err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateCompletedWithErrors || completed.RunOutcome != RunOutcomeCompletedWithErrors || !completed.RunTraversalComplete || completed.RunFoldersTotal != 1 || completed.RunFoldersDone != 1 || completed.RunFoldersFailed != 0 {
		t.Fatalf("completed telemetry = %#v", completed)
	}
	if completed.RunItemsExamined != 2 || completed.RunItemsFailed != 1 || completed.RunImportedItems != 1 || completed.Checkpoints["archive"] != "done" || !strings.Contains(completed.LastError, "all folders were traversed") {
		t.Fatalf("terminal item telemetry = %#v", completed)
	}
	if len(completed.RunFolderFailures) != 0 || completed.RunTerminalFailure != nil || len(completed.RunFolderResults) != 1 {
		t.Fatalf("terminal item was presented as a folder/fatal failure: %#v", completed)
	}
	result := completed.RunFolderResults[0]
	if result.State != "completed_with_errors" || !result.TraversalComplete || result.FailedItems != 1 || result.ImportedItems != 1 || len(result.ItemFailures) != 1 {
		t.Fatalf("folder result = %#v", result)
	}
	encoded, err := json.Marshal(completed)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := string(encoded)
	if strings.Contains(diagnostic, "source-id-secret") || strings.Contains(diagnostic, "source-token-secret") || !strings.Contains(diagnostic, "[redacted]") {
		t.Fatalf("stored diagnostic was not redacted: %s", diagnostic)
	}

	items, err := space.ListItems(t.Context(), service.UserAccess("alice", "test"), completed.FolderMap["archive"], service.ItemQuery{})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if err := runner.Run(t.Context(), job.ID, source); err != nil {
		t.Fatal(err)
	}
	resumed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	items, err = space.ListItems(t.Context(), service.UserAccess("alice", "test"), resumed.FolderMap["archive"], service.ItemQuery{})
	if err != nil || len(items) != 1 || resumed.ImportedItems != 1 || resumed.RunImportedItems != 0 || resumed.RunItemsFailed != 0 || !resumed.RunTraversalComplete || resumed.State != StateCompleted {
		t.Fatalf("restart resume job=%#v items=%#v err=%v", resumed, items, err)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 2 || runs[1].Outcome != RunOutcomeCompletedWithErrors || !runs[1].TraversalComplete || runs[1].ItemsFailed != 1 || len(runs[1].FolderResults) != 1 || len(runs[1].FolderResults[0].ItemFailures) != 1 {
		t.Fatalf("retained run history = %#v, %v", runs, err)
	}
}

func TestRunnerRetainsSuccessfulFoldersWhenOneSourceFolderFails(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	source := &partlyFailingSource{fail: true}
	err = runner.Run(t.Context(), job.ID, source)
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	failed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != StateCompletedWithErrors || failed.RunOutcome != RunOutcomeCompletedWithErrors || failed.RunTraversalComplete || failed.RunFoldersTotal != 2 || failed.RunFoldersDone != 1 || failed.RunFoldersFailed != 1 {
		t.Fatalf("failed telemetry = %#v", failed)
	}
	if failed.RunTerminalFailure != nil {
		t.Fatalf("isolated folder failure was presented as terminal: %#v", failed.RunTerminalFailure)
	}
	if failed.RunSourceConcurrency != 2 || failed.SourceConcurrencyHint != 2 {
		t.Fatalf("deterministic folder failure reduced source concurrency: run=%d hint=%d", failed.RunSourceConcurrency, failed.SourceConcurrencyHint)
	}
	if len(failed.RunFolderFailures) != 1 || failed.RunFolderFailures[0].FolderID != "bad" || !strings.Contains(failed.RunFolderFailures[0].Error, "remote collection unavailable") {
		t.Fatalf("folder failures = %#v", failed.RunFolderFailures)
	}
	if len(failed.RunFolderResults) != 2 {
		t.Fatalf("folder reconciliation = %#v", failed.RunFolderResults)
	}
	states := make(map[string]string, len(failed.RunFolderResults))
	for _, result := range failed.RunFolderResults {
		states[result.SourceFolderID] = result.State
	}
	if states["good"] != "unverified" || states["bad"] != "failed" {
		t.Fatalf("folder reconciliation states = %#v", states)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].State != StateCompletedWithErrors || runs[0].Outcome != RunOutcomeCompletedWithErrors || runs[0].TraversalComplete || len(runs[0].FolderFailures) != 1 || len(runs[0].FolderResults) != 2 {
		t.Fatalf("failed run evidence = %#v, %v", runs, err)
	}
	goodItems, err := space.ListItems(t.Context(), service.UserAccess("alice", "test"), failed.FolderMap["good"], service.ItemQuery{})
	if err != nil || len(goodItems) != 1 || failed.Checkpoints["good"] != "done" {
		t.Fatalf("successful folder items=%#v checkpoint=%q err=%v", goodItems, failed.Checkpoints["good"], err)
	}

	source.fail = false
	if err := runner.Run(t.Context(), job.ID, source); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateCompleted || completed.RunFoldersDone != 2 || completed.RunFoldersFailed != 0 || len(completed.RunFolderFailures) != 0 {
		t.Fatalf("retried telemetry = %#v", completed)
	}
	badItems, err := space.ListItems(t.Context(), service.UserAccess("alice", "test"), completed.FolderMap["bad"], service.ItemQuery{})
	if err != nil || len(badItems) != 1 {
		t.Fatalf("retried folder items=%#v err=%v", badItems, err)
	}
}

func TestRunnerAbortsPersistentSourcePressureWithoutTryingEveryFolder(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	source := &pressureFailingSource{}
	err = runner.Run(t.Context(), job.ID, source)
	if err == nil || !strings.Contains(err.Error(), "retry later") {
		t.Fatalf("Run error = %v", err)
	}
	if len(source.requested) != 1 || source.requested[0] != "first" {
		t.Fatalf("requested folders = %v, want only first pressure failure", source.requested)
	}
	failed, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != StateFailed || failed.RunFoldersFailed != 1 || len(failed.RunFolderFailures) != 1 {
		t.Fatalf("failed telemetry = %#v", failed)
	}
	if failed.RunOutcome != RunOutcomeFatalFailure || failed.RunTraversalComplete || failed.RunFatalError == "" {
		t.Fatalf("fatal pressure outcome = %#v", failed)
	}
	if failure := failed.RunTerminalFailure; failure == nil || failure.Phase != FailurePhaseSourceRead || failure.FolderID != "first" || failure.FolderName == "" || !failure.RetryRecommended || failure.RetryDisposition != RetryRecommended || !strings.Contains(failure.RetryAdvice, "back off") || failure.OccurredAt.IsZero() {
		t.Fatalf("source pressure diagnostic = %#v", failure)
	}
	if failed.RunSourceCalls != 1 || failed.RunSourceRetryEvents != 1 || failed.RunSourcePressure != 0.5 {
		t.Fatalf("source pressure telemetry = %#v", failed)
	}
	prepared, err := jobs.PrepareRun(t.Context(), failed)
	if err != nil || prepared.RunTerminalFailure == nil {
		t.Fatalf("preflight cleared terminal evidence before a run started: job=%#v err=%v", prepared, err)
	}
	if err := runner.Run(t.Context(), job.ID, &partlyFailingSource{}); err != nil {
		t.Fatal(err)
	}
	completed, err := jobs.Get(t.Context(), job.ID)
	if err != nil || completed.RunTerminalFailure != nil || completed.RunOutcome != RunOutcomeCompleted {
		t.Fatalf("successful retry retained stale terminal evidence: job=%#v err=%v", completed, err)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 2 || runs[0].TerminalFailure != nil || runs[1].TerminalFailure == nil {
		t.Fatalf("retry history did not retain only the failed attempt: runs=%#v err=%v", runs, err)
	}
}

func TestStoreRecordsSourceConnectionAsFatalAttempt(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "imap"})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := jobs.RecordFatalAttempt(t.Context(), job.ID, errors.New("dial source: connection refused"))
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != StateFailed || failed.RunOutcome != RunOutcomeFatalFailure || failed.RunTraversalComplete || failed.RunItemsExamined != 0 || failed.RunFatalError != "dial source: connection refused" || failed.RunStartedAt.IsZero() || failed.RunFinishedAt.IsZero() {
		t.Fatalf("fatal connection attempt = %#v", failed)
	}
	if failure := failed.RunTerminalFailure; failure == nil || failure.Phase != FailurePhaseConnect || failure.RetryDisposition != RetryRecommended || !failure.RetryRecommended || failure.OccurredAt != failed.RunFinishedAt {
		t.Fatalf("fatal connection diagnostic = %#v", failure)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].Outcome != RunOutcomeFatalFailure || runs[0].FatalError != failed.RunFatalError || runs[0].TerminalFailure == nil || runs[0].TerminalFailure.Message != failed.RunTerminalFailure.Message {
		t.Fatalf("fatal connection history = %#v, %v", runs, err)
	}
}

func TestTerminalFailureRedactsSecretsBeforePersistence(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "eas"})
	if err != nil {
		t.Fatal(err)
	}
	runErr := errors.New(`request https://alice:hunter2@example.test/Microsoft-Server-ActiveSync?access_token=source-token failed password=hidden client_secret=client-private Authorization: Bearer bearer-secret Cookie: session-secret`)
	failed, err := jobs.RecordFatalAttempt(t.Context(), job.ID, runErr, FailureContext{Phase: FailurePhaseConnect})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2", "source-token", "hidden", "client-private", "bearer-secret", "session-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("terminal diagnostic leaked %q: %s", secret, encoded)
		}
	}
	if failure := failed.RunTerminalFailure; failure == nil || !strings.Contains(failure.Message, "[redacted]") || failure.Phase != FailurePhaseConnect {
		t.Fatalf("redacted terminal diagnostic = %#v", failure)
	}
	runs, err := jobs.Runs(t.Context(), job.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].TerminalFailure == nil || runs[0].TerminalFailure.Message != failed.RunTerminalFailure.Message {
		t.Fatalf("persisted terminal diagnostic = %#v, err=%v", runs, err)
	}
}

func TestTerminalFailureClassifiesCredentialAndConfigurationAction(t *testing.T) {
	job := Job{Checkpoints: map[string]string{"calendar": "retained"}}
	credential := terminalFailure(job, errors.New("authentication failed password=private"), time.Now().UTC(), FailureContext{Phase: FailurePhaseConnect})
	if credential.RetryDisposition != RetryCredentialsRequired || credential.RetryRecommended || !strings.Contains(credential.RetryAdvice, "credentials") || strings.Contains(credential.Message, "private") {
		t.Fatalf("credential failure=%#v", credential)
	}
	configuration := terminalFailure(job, errors.New("source is unavailable in this build"), time.Now().UTC(), FailureContext{Phase: FailurePhaseConnect})
	if configuration.RetryDisposition != RetryConfigurationRequired || configuration.RetryRecommended || !strings.Contains(configuration.RetryAdvice, "connection settings") {
		t.Fatalf("configuration failure=%#v", configuration)
	}
	temporary := terminalFailure(job, fmt.Errorf("write destination: %w", account.ErrTemporarilyUnavailable), time.Now().UTC(), FailureContext{Phase: FailurePhaseDestinationWrite})
	if temporary.RetryDisposition != RetryRecommended || !temporary.RetryRecommended || !strings.Contains(temporary.RetryAdvice, "destination account") {
		t.Fatalf("temporary destination failure=%#v", temporary)
	}
}

func TestStoreSynthesizesStableStructuredEvidenceForLegacyFatalRun(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "eas"})
	if err != nil {
		t.Fatal(err)
	}
	job.State = StateFailed
	job.RunOutcome = RunOutcomeFatalFailure
	job.RunStartedAt = time.Now().UTC().Add(-time.Minute)
	job.RunFinishedAt = time.Now().UTC().Add(-30 * time.Second)
	job.RunFatalError = `read source folder "Calendar": server error; retry later`
	job.LastError = job.RunFatalError
	job.RunFolderFailures = []FolderFailure{{FolderID: "calendar", FolderName: "Calendar", Error: job.RunFatalError}}
	job.Checkpoints["calendar"] = "retained-key"
	if err := jobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	first, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunTerminalFailure == nil || second.RunTerminalFailure == nil || *first.RunTerminalFailure != *second.RunTerminalFailure {
		t.Fatalf("unstable legacy evidence first=%#v second=%#v", first.RunTerminalFailure, second.RunTerminalFailure)
	}
	failure := first.RunTerminalFailure
	if failure.Phase != FailurePhaseSourceRead || failure.FolderID != "calendar" || failure.FolderName != "Calendar" || failure.Checkpoint != "retained-key" || failure.OccurredAt != job.RunFinishedAt || !failure.RetryRecommended {
		t.Fatalf("legacy terminal evidence=%#v", failure)
	}
}

func TestSourceConcurrencyControllerReducesOnlyForPressure(t *testing.T) {
	controller := newSourceConcurrencyController(4, 4)

	controller.release(sourceReadStats{}, errors.New("unsupported remote collection"))
	if limit, _ := controller.snapshot(); limit != 4 {
		t.Fatalf("deterministic failure limit = %d, want 4", limit)
	}

	controller.release(sourceReadStats{}, MarkSourcePressure(errors.New("remote service unavailable")))
	if limit, _ := controller.snapshot(); limit != 2 {
		t.Fatalf("pressure failure limit = %d, want 2", limit)
	}

	controller.release(sourceReadStats{retries: 1}, nil)
	if limit, _ := controller.snapshot(); limit != 1 {
		t.Fatalf("non-advancing page retry limit = %d, want 1", limit)
	}
}

func TestMarkInterruptedPreservesStoredCredentials(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "imap", CredentialStored: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.SaveCredential(t.Context(), job.ID, "source-secret"); err != nil {
		t.Fatal(err)
	}
	job.State = StateRunning
	if err := jobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if err := jobs.MarkInterrupted(t.Context()); err != nil {
		t.Fatal(err)
	}
	job, _ = jobs.Get(t.Context(), job.ID)
	if job.State != StateInterrupted || !job.CredentialStored {
		t.Fatalf("state=%q credential_stored=%v", job.State, job.CredentialStored)
	}
	if password, err := jobs.Credential(t.Context(), job.ID); err != nil || password != "source-secret" {
		t.Fatalf("credential=%q err=%v", password, err)
	}
}

func TestRunnerDistinguishesRestartFromExplicitPause(t *testing.T) {
	tests := []struct {
		name      string
		stop      func(context.CancelFunc, *Runner, string)
		wantState State
		wantRun   RunOutcome
	}{
		{name: "server shutdown", stop: func(cancel context.CancelFunc, _ *Runner, _ string) { cancel() }, wantState: StateInterrupted, wantRun: RunOutcomeInterrupted},
		{name: "user pause", stop: func(_ context.CancelFunc, runner *Runner, id string) {
			if !runner.Pause(id) {
				t.Error("running job could not be paused")
			}
		}, wantState: StatePaused, wantRun: RunOutcomePaused},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jobs, runner, _ := migrationTestSetup(t)
			job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := &parallelSource{started: make(chan string, 2), release: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- runner.Run(ctx, job.ID, source) }()
			select {
			case <-source.started:
			case <-time.After(2 * time.Second):
				t.Fatal("sync did not start")
			}
			test.stop(cancel, runner, job.ID)
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run error = %v", err)
			}
			stored, err := jobs.Get(t.Context(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.State != test.wantState || stored.RunOutcome != test.wantRun || stored.RunTraversalComplete {
				t.Fatalf("stopped run = %#v, want state %q outcome %q", stored, test.wantState, test.wantRun)
			}
		})
	}
}

func TestRunnerTreatsShutdownDependencyErrorAsInterrupted(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	source := &parallelSource{
		started: make(chan string, 2), release: make(chan struct{}),
		cancelErr: account.ErrTemporarilyUnavailable,
	}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, job.ID, source) }()
	select {
	case <-source.started:
	case <-time.After(2 * time.Second):
		t.Fatal("sync did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, account.ErrTemporarilyUnavailable) {
		t.Fatalf("Run error = %v", err)
	}
	stored, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != StateInterrupted || stored.RunOutcome != RunOutcomeInterrupted || stored.RunTerminalFailure != nil {
		t.Fatalf("shutdown run = %#v, want resumable interruption", stored)
	}
}

func TestMarkInterruptedRequiresMissingCredential(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "imap", CredentialStored: true})
	if err != nil {
		t.Fatal(err)
	}
	job.State = StateRunning
	if err := jobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if err := jobs.MarkInterrupted(t.Context()); err != nil {
		t.Fatal(err)
	}
	job, _ = jobs.Get(t.Context(), job.ID)
	if job.State != StateCredentialsRequired || job.CredentialStored {
		t.Fatalf("state=%q credential_stored=%v", job.State, job.CredentialStored)
	}
}

func TestStoredCredentialIsSeparateAndDeletedWithJob(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "imap", Schedule: ScheduleHourly, CredentialStored: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.SaveCredential(t.Context(), job.ID, "source-secret"); err != nil {
		t.Fatal(err)
	}
	loaded, err := jobs.Get(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "source-secret") {
		t.Fatal("job API data contains stored password")
	}
	if password, err := jobs.Credential(t.Context(), job.ID); err != nil || password != "source-secret" {
		t.Fatalf("credential=%q err=%v", password, err)
	}
	if err := jobs.Delete(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Credential(t.Context(), job.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential delete err=%v", err)
	}
}

func TestScheduleIntervals(t *testing.T) {
	tests := map[Schedule]time.Duration{ScheduleManual: 0, ScheduleHourly: time.Hour, ScheduleEvery6Hours: 6 * time.Hour, ScheduleDaily: 24 * time.Hour, ScheduleWeekly: 7 * 24 * time.Hour}
	for schedule, want := range tests {
		if got := schedule.Interval(); got != want || !schedule.Valid() {
			t.Errorf("%q interval=%v valid=%v", schedule, got, schedule.Valid())
		}
	}
	if Schedule("sometimes").Valid() {
		t.Fatal("unknown schedule is valid")
	}
}

func TestEASJobGetsStableDeviceIdentity(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "eas"})
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Connection.ClientID) != 32 {
		t.Fatalf("client ID=%q", job.Connection.ClientID)
	}
	if job.Connection.StateVersion != easStateVersion {
		t.Fatalf("state version=%d", job.Connection.StateVersion)
	}
	loaded, err := jobs.Get(t.Context(), job.ID)
	if err != nil || loaded.Connection.ClientID != job.Connection.ClientID {
		t.Fatalf("loaded=%#v err=%v", loaded.Connection, err)
	}
}

func TestPrepareRunResetsLegacyEASDeviceScopedStateWithoutRotatingDevice(t *testing.T) {
	jobs, _, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "imap"})
	if err != nil {
		t.Fatal(err)
	}
	job.SourceType, job.Connection.ClientID, job.Connection.StateVersion = "eas", "old-device", 1
	job.Checkpoints["inbox"] = "old-device-key"
	job.FolderMap["inbox"] = "destination-inbox"
	job.FolderTargets["archive"] = "destination-archive"
	job.IndexedSources["inbox"] = "eas://old-source"
	job.SelectedFolderIDs = []string{"inbox", "archive"}
	job.ImportedItems, job.ImportedBytes, job.SkippedItems = 10, 1000, 2
	if err := jobs.Save(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	prepared, err := jobs.PrepareRun(t.Context(), job)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Connection.ClientID != "old-device" || prepared.Connection.StateVersion != easStateVersion || len(prepared.Checkpoints) != 0 || len(prepared.FolderMap) != 0 || len(prepared.FolderTargets) != 0 || len(prepared.IndexedSources) != 0 || prepared.ImportedItems != 0 || prepared.ImportedBytes != 0 || prepared.SkippedItems != 0 {
		t.Fatalf("prepared=%#v", prepared)
	}
	if !slices.Equal(prepared.SelectedFolderIDs, []string{"inbox", "archive"}) {
		t.Fatalf("selected folders changed during stable-device upgrade: %v", prepared.SelectedFolderIDs)
	}
}

func TestLastSuccessAtSurvivesLaterFatalAttempt(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(t.Context(), job.ID, &fakeSource{}); err != nil {
		t.Fatal(err)
	}
	ok, err := jobs.Get(t.Context(), job.ID)
	if err != nil || ok.RunOutcome != RunOutcomeCompleted || ok.LastSuccessAt.IsZero() || !ok.LastSuccessAt.Equal(ok.RunFinishedAt) {
		t.Fatalf("completed job last success = %v finished=%v err=%v", ok.LastSuccessAt, ok.RunFinishedAt, err)
	}
	failed, err := jobs.RecordFatalAttempt(t.Context(), job.ID, errors.New("dial source: connection refused"))
	if err != nil || failed.RunOutcome != RunOutcomeFatalFailure || !failed.LastSuccessAt.Equal(ok.LastSuccessAt) {
		t.Fatalf("failed attempt last success = %v want %v err=%v", failed.LastSuccessAt, ok.LastSuccessAt, err)
	}
}
