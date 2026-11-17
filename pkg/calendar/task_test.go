package calendar

import (
	"strings"
	"testing"
	"time"
)

func ref[T any](value T) *T { return &value }

func TestTaskCreateProjectAndUpdate(t *testing.T) {
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	data, err := CreateTask(TaskUpdate{
		Summary: ref("File taxes"), Description: ref("Bring receipts"), Due: ref("2026-10-30"), Start: ref("2026-10-24"),
		Priority: ref(1), Categories: &[]string{"Work", "work", "Finance"}, RelatedTo: ref("parent-uid"),
		ReminderAt: ref("2026-10-29T08:00:00Z"),
	}, "task-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if !IsTask(data) || strings.Contains(string(data), "VEVENT") {
		t.Fatalf("payload = %s", data)
	}
	task, err := ProjectTask(data)
	if err != nil {
		t.Fatal(err)
	}
	if task.UID != "task-1" || task.Summary != "File taxes" || task.Description != "Bring receipts" || task.Due != "2026-10-30" || task.Start != "2026-10-24" ||
		task.Priority != 1 || len(task.Categories) != 2 || task.RelatedTo != "parent-uid" || task.ReminderAt != "2026-10-29T08:00:00Z" || task.Status != TaskNeedsAction || task.Completed {
		t.Fatalf("task = %+v", task)
	}
	data, err = UpdateTask(data, TaskUpdate{Due: ref(""), Priority: ref(0), RelatedTo: ref(""), ReminderAt: ref("")}, now)
	if err != nil {
		t.Fatal(err)
	}
	task, _ = ProjectTask(data)
	if task.Due != "" || task.Priority != 0 || task.RelatedTo != "" || task.ReminderAt != "" || task.Summary != "File taxes" {
		t.Fatalf("updated task = %+v", task)
	}
	if _, err := UpdateTask(data, TaskUpdate{Due: ref("2026-10-01")}, now); err == nil {
		t.Fatal("due before start was accepted")
	}
	if _, err := CreateTask(TaskUpdate{Summary: ref(" ")}, "x", now); err == nil {
		t.Fatal("empty title was accepted")
	}
	if _, err := CreateTask(TaskUpdate{Summary: ref("Loop"), Recurrence: ref("weekly")}, "x", now); err == nil {
		t.Fatal("repeating task without a date was accepted")
	}
}

func TestCompleteRepeatingTaskAdvancesSeriesAndRecordsOccurrence(t *testing.T) {
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	data, err := CreateTask(TaskUpdate{Summary: ref("Water plants"), Due: ref("2026-10-23"), Recurrence: ref("FREQ=WEEKLY;COUNT=3")}, "series", now)
	if err != nil {
		t.Fatal(err)
	}
	updated, done, err := CompleteTask(data, true, "series-done-1", now)
	if err != nil {
		t.Fatal(err)
	}
	series, _ := ProjectTask(updated)
	if series.UID != "series" || series.Due != "2026-10-30" || series.Completed || !strings.Contains(series.RRule, "COUNT=2") {
		t.Fatalf("series = %+v", series)
	}
	record, _ := ProjectTask(done)
	if record.UID != "series-done-1" || record.Due != "2026-10-23" || !record.Completed || record.RRule != "" || record.CompletedAt == "" {
		t.Fatalf("record = %+v", record)
	}
	// The last occurrence completes the series itself.
	updated, _, _ = CompleteTask(updated, true, "series-done-2", now)
	last, done, err := CompleteTask(updated, true, "series-done-3", now)
	if err != nil || done != nil {
		t.Fatalf("last completion done=%v err=%v", done != nil, err)
	}
	if task, _ := ProjectTask(last); !task.Completed {
		t.Fatalf("final task = %+v", task)
	}
	reopened, _, err := CompleteTask(last, false, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if task, _ := ProjectTask(reopened); task.Completed || task.CompletedAt != "" || task.Status != TaskNeedsAction {
		t.Fatalf("reopened = %+v", task)
	}
}

func TestReplaceCategoriesOnEventsAndTasks(t *testing.T) {
	event := []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:e\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260101T100000Z\r\nSUMMARY:Meet\r\nCATEGORIES:Old\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	updated, err := ReplaceCategories(event, []string{"Old", "Work"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ItemCategories(updated); len(got) != 2 || got[1] != "Work" {
		t.Fatalf("categories = %v", got)
	}
	if projected, _ := Project(updated); projected.Summary != "Meet" {
		t.Fatalf("event changed: %+v", projected)
	}
}
