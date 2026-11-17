package mailstate

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func fixture(t *testing.T) (*Service, *model.TypedStore, service.FolderSpace, *time.Time) {
	t.Helper()
	backend, err := jsonstore.New(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, ns := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), ns); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(t.Context(), id, id, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	space := service.NewFolderSpace(typed, authz.New(typed))
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	states, err := New(t.Context(), typed, space, Config{Batch: 2})
	if err != nil {
		t.Fatal(err)
	}
	states.SetClock(func() time.Time { return now })
	return states, typed, space, &now
}

func seed(t *testing.T, space service.FolderSpace, owner, subject string, flags ...string) model.Item {
	t.Helper()
	item, err := space.CreateItem(t.Context(), service.UserAccess(owner, "test"), model.InboxFolderID(owner), service.ItemInput{Name: subject + ".eml",
		Data: []byte("From: x@example.net\r\nSubject: " + subject + "\r\n\r\nbody"), Flags: flags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestSnoozeWakesIntoInboxUnreadAfterRestart(t *testing.T) {
	states, typed, space, now := fixture(t)
	alice := service.UserAccess("alice", "test")
	item := seed(t, space, "alice", "Later", model.FlagSeen)
	if _, err := states.Snooze(t.Context(), alice, item.ID, *now); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("snooze into the past err = %v", err)
	}
	if _, err := states.Snooze(t.Context(), service.UserAccess("bob", "test"), item.ID, now.Add(time.Hour)); err == nil {
		t.Fatal("bob snoozed alice's message")
	}
	snoozed, err := states.Snooze(t.Context(), alice, item.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	folder, err := space.GetFolder(t.Context(), alice, snoozed.FolderID)
	if err != nil || folder.Name != SnoozedFolder || folder.UserID != "alice" {
		t.Fatalf("snoozed folder = %+v err=%v", folder, err)
	}
	records, err := states.Snoozes(t.Context(), "alice")
	if err != nil || !records[item.ID].WakeAt.Equal(now.Add(time.Hour)) || records[item.ID].FolderID != folder.ID {
		t.Fatalf("records = %+v err=%v", records, err)
	}
	if settled, err := states.RunOnce(t.Context()); err != nil || settled != 0 {
		t.Fatalf("early run settled=%d err=%v", settled, err)
	}
	// A new service over the same store (a restart) wakes the message.
	restarted, err := New(t.Context(), typed, space, Config{})
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetClock(func() time.Time { return now.Add(time.Hour) })
	if settled, err := restarted.RunOnce(t.Context()); err != nil || settled != 1 {
		t.Fatalf("wake settled=%d err=%v", settled, err)
	}
	woken, err := space.GetItem(t.Context(), alice, item.ID)
	if err != nil || woken.FolderID != model.InboxFolderID("alice") || slices.Contains(woken.Flags, model.FlagSeen) {
		t.Fatalf("woken = %+v err=%v", woken, err)
	}
	if records, _ := restarted.Snoozes(t.Context(), "alice"); len(records) != 0 {
		t.Fatalf("records after wake = %+v", records)
	}
}

func TestSnoozeWakeIsBoundedAndSkipsMovedMessages(t *testing.T) {
	states, _, space, now := fixture(t)
	alice := service.UserAccess("alice", "test")
	var items []model.Item
	for _, subject := range []string{"one", "two", "three"} {
		item := seed(t, space, "alice", subject)
		if _, err := states.Snooze(t.Context(), alice, item.ID, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
	}
	archive, err := service.EnsureFolderPath(t.Context(), space, alice, "Archive", model.FolderTypeMail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.MoveItem(t.Context(), alice, items[0].ID, archive.ID, ""); err != nil {
		t.Fatal(err)
	}
	states.SetClock(func() time.Time { return now.Add(time.Hour) })
	if settled, err := states.RunOnce(t.Context()); err != nil || settled != 2 {
		t.Fatalf("first batch settled=%d err=%v", settled, err)
	}
	if settled, err := states.RunOnce(t.Context()); err != nil || settled != 1 {
		t.Fatalf("second batch settled=%d err=%v", settled, err)
	}
	moved, _ := space.GetItem(t.Context(), alice, items[0].ID)
	if moved.FolderID != archive.ID {
		t.Fatalf("message the owner moved out of Snoozed was woken into %s", moved.FolderID)
	}
	unsnoozeTarget := seed(t, space, "alice", "manual")
	if _, err := states.Snooze(t.Context(), alice, unsnoozeTarget.ID, now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if item, err := states.Unsnooze(t.Context(), alice, unsnoozeTarget.ID); err != nil || item.FolderID != model.InboxFolderID("alice") {
		t.Fatalf("unsnooze = %+v err=%v", item, err)
	}
}

func TestFollowUpFlagsRecordsAndRemindsOnce(t *testing.T) {
	states, _, space, now := fixture(t)
	alice := service.UserAccess("alice", "test")
	item := seed(t, space, "alice", "Report")
	flagged, record, err := states.SetFollowUp(t.Context(), alice, item.ID, now.Add(24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(flagged.Flags, model.FlagFlagged) || !record.DueAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("follow-up item=%+v record=%+v", flagged, record)
	}
	if due, err := states.DueReminders(t.Context(), "alice", 10); err != nil || len(due) != 0 {
		t.Fatalf("early reminders = %+v err=%v", due, err)
	}
	states.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	due, err := states.DueReminders(t.Context(), "alice", 10)
	if err != nil || len(due) != 1 || due[0].ItemID != item.ID {
		t.Fatalf("due reminders = %+v err=%v", due, err)
	}
	if err := states.DismissReminder(t.Context(), "alice", item.ID); err != nil {
		t.Fatal(err)
	}
	if due, _ := states.DueReminders(t.Context(), "alice", 10); len(due) != 0 {
		t.Fatalf("dismissed reminder still due: %+v", due)
	}
	if err := states.ForgetFollowUp(t.Context(), "alice", item.ID); err != nil {
		t.Fatal(err)
	}
	if records, _ := states.FollowUps(t.Context(), "alice"); len(records) != 0 {
		t.Fatalf("records after forget = %+v", records)
	}
	if err := states.ForgetFollowUp(t.Context(), "alice", item.ID); err != nil {
		t.Fatalf("forgetting twice: %v", err)
	}
}
