package migration

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// localizedInboxSource is a source inbox named in Danish. recognised says
// whether the source reports it as the inbox; items is what a full read
// returns, and a read from the checkpoint returns no changes.
type localizedInboxSource struct {
	recognised bool
	items      []string
}

func (*localizedInboxSource) ID() string { return "fake://localized/alice" }
func (s *localizedInboxSource) Folders(context.Context) ([]Folder, error) {
	folder := Folder{ID: "remote-inbox", Name: "Indbakke", Type: model.FolderTypeMail, Estimate: 3, EstimateKnown: true}
	if s.recognised {
		folder.Special = model.SpecialUseInbox
	}
	return []Folder{folder}, nil
}
func (s *localizedInboxSource) Items(_ context.Context, _ Folder, checkpoint string) (Page, error) {
	if checkpoint != "" {
		return Page{Checkpoint: checkpoint, Done: true}, nil
	}
	page := Page{Checkpoint: "after-full-read", Done: true, InitialCoverageComplete: true}
	for _, id := range s.items {
		page.Items = append(page.Items, Item{ID: id, Version: "1", Data: []byte("Subject: " + id + "\r\n\r\nbody\r\n")})
	}
	return page, nil
}
func (*localizedInboxSource) Close() error { return nil }

// An inbox an earlier run imported into a duplicate folder moves into the
// real inbox once the source reports it as the inbox, a shortfall against
// the source total is reported, and a re-read imports what was missing
// without copying anything twice.
func TestRunnerRehomesWellKnownFolderAndRereadsShortfall(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	ctx, access := t.Context(), service.UserAccess("alice", "test")
	job, err := jobs.Create(ctx, Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, job.ID, &localizedInboxSource{items: []string{"one", "two"}}); err != nil {
		t.Fatal(err)
	}
	first, _ := jobs.Get(ctx, job.ID)
	duplicate := first.FolderMap["remote-inbox"]
	if duplicate == "" || duplicate == model.InboxFolderID("alice") {
		t.Fatalf("first run mapped the unrecognised inbox to %q", duplicate)
	}

	if err := runner.Run(ctx, job.ID, &localizedInboxSource{recognised: true, items: []string{"one", "two", "three"}}); err != nil {
		t.Fatal(err)
	}
	second, _ := jobs.Get(ctx, job.ID)
	if second.FolderMap["remote-inbox"] != model.InboxFolderID("alice") {
		t.Fatalf("recognised inbox maps to %q", second.FolderMap["remote-inbox"])
	}
	if _, err := space.GetFolder(ctx, access, duplicate); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("emptied duplicate folder still exists: %v", err)
	}
	inbox, err := space.ListItems(ctx, access, model.InboxFolderID("alice"), service.ItemQuery{})
	if err != nil || len(inbox) != 2 {
		t.Fatalf("inbox holds %d items after the move (err %v), want 2", len(inbox), err)
	}
	if result := second.RunFolderResults[0]; result.State != "missing" || result.DriftItems != -1 || !result.SourceItemsKnown {
		t.Fatalf("checkpointed folder reconciliation = %+v, want 1 missing item", result)
	}

	cleared, err := runner.Reread(ctx, job.ID, nil)
	if err != nil || cleared != 1 {
		t.Fatalf("reread cleared %d folders, err %v", cleared, err)
	}
	if err := runner.Run(ctx, job.ID, &localizedInboxSource{recognised: true, items: []string{"one", "two", "three"}}); err != nil {
		t.Fatal(err)
	}
	third, _ := jobs.Get(ctx, job.ID)
	if third.RunImportedItems != 1 || third.RunFolderResults[0].State != "matched" {
		t.Fatalf("re-read imported %d items with state %q, want 1 and matched", third.RunImportedItems, third.RunFolderResults[0].State)
	}
	inbox, _ = space.ListItems(ctx, access, model.InboxFolderID("alice"), service.ItemQuery{})
	if len(inbox) != 3 {
		t.Fatalf("inbox holds %d items after the re-read, want 3", len(inbox))
	}
}

// A folder holding mail that did not come from the source is kept when its
// synced items move out.
func TestRunnerRehomeKeepsFolderWithOtherMail(t *testing.T) {
	jobs, runner, space := migrationTestSetup(t)
	ctx, access := t.Context(), service.UserAccess("alice", "test")
	job, err := jobs.Create(ctx, Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, job.ID, &localizedInboxSource{items: []string{"one"}}); err != nil {
		t.Fatal(err)
	}
	first, _ := jobs.Get(ctx, job.ID)
	duplicate := first.FolderMap["remote-inbox"]
	if _, err := space.CreateItem(ctx, access, duplicate, service.ItemInput{Data: []byte("Subject: filed by hand\r\n\r\nbody\r\n")}); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, job.ID, &localizedInboxSource{recognised: true, items: []string{"one"}}); err != nil {
		t.Fatal(err)
	}
	kept, err := space.ListItems(ctx, access, duplicate, service.ItemQuery{})
	if err != nil || len(kept) != 1 {
		t.Fatalf("folder with other mail holds %d items (err %v), want the 1 filed by hand", len(kept), err)
	}
}

func TestRereadRefusesRunningJob(t *testing.T) {
	jobs, runner, _ := migrationTestSetup(t)
	job, err := jobs.Create(t.Context(), Job{OwnerID: "alice", DestinationID: "alice", SourceType: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.cancels[job.ID] = func() {}
	runner.mu.Unlock()
	if _, err := runner.Reread(t.Context(), job.ID, nil); !errors.Is(err, ErrJobRunning) {
		t.Fatalf("reread of a running job: %v", err)
	}
}
