package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQueryManagedLogsNewestFirstAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "veksel-2026-08-26.log", strings.Join([]string{
		"2026-08-26T08:00:00Z INFO imap: older",
		"2026-08-26T09:00:00Z WARN smtp: old warning",
	}, "\n")+"\n")
	writeTestLog(t, dir, "veksel-2026-08-27.log", strings.Join([]string{
		"2026-08-27T08:00:00Z DEBUG web: first today",
		"2026-08-27T09:00:00Z ERROR smtp: newest failure recipient=redacted",
	}, "\n")+"\n")
	writeTestLog(t, dir, "other.log", "2026-08-27T10:00:00Z FATAL system: must not appear\n")

	first, err := QueryManagedLogs(dir, LogQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := messages(first.Records); strings.Join(got, ",") != "newest failure,first today" {
		t.Fatalf("first page = %q", got)
	}
	if first.Records[0].Fields["recipient"] != "redacted" {
		t.Fatalf("text fields = %+v", first.Records[0].Fields)
	}
	if first.NextCursor == "" {
		t.Fatal("first page has no continuation")
	}
	second, err := QueryManagedLogs(dir, LogQuery{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := messages(second.Records); strings.Join(got, ",") != "old warning,older" {
		t.Fatalf("second page = %q", got)
	}
	if second.NextCursor != "" {
		t.Fatalf("unexpected final cursor %q", second.NextCursor)
	}
}

func TestQueryManagedLogsParsesTextFieldsAndCaller(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "veksel-2026-08-27.log", "2026-08-27T08:00:00Z INFO system: listener started services=[web dav jmap] addr=0.0.0.0:8472 caller=/tmp/main.go:12\n")
	page, err := QueryManagedLogs(dir, LogQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("records = %+v", page.Records)
	}
	record := page.Records[0]
	if record.Message != "listener started" || record.Fields["services"] != "[web dav jmap]" || record.Fields["addr"] != "0.0.0.0:8472" || record.Caller != "/tmp/main.go:12" {
		t.Fatalf("parsed text record = %+v", record)
	}
}

func TestQueryManagedLogsFiltersTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	entry := Entry{Timestamp: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Level: "WARN", Module: "eas", Message: "remote retry", Fields: map[string]any{"folder": "Inbox", "attempt": 2}}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	writeTestLog(t, dir, "veksel-2026-08-27.log", string(encoded)+"\n2026-08-27T11:00:00Z INFO eas: ordinary event\n2026-08-27T12:00:00Z WARN smtp: Inbox elsewhere\n")

	page, err := QueryManagedLogs(dir, LogQuery{Level: "warn", Module: "eas", Text: "inBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].Message != "remote retry" || page.Records[0].Fields["attempt"] != "2" {
		t.Fatalf("filtered records = %+v", page.Records)
	}
}

func TestQueryManagedLogsSkipsUnsafeMalformedAndIncompleteInput(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "veksel-2026-08-27.log", "malformed\n2026-08-27T08:00:00Z INFO web: complete\n{\"ts\":")
	writeTestLog(t, dir, "veksel-2026-08-27.log.evil", "2026-08-27T09:00:00Z FATAL system: evil\n")
	if err := os.Symlink(filepath.Join(dir, "veksel-2026-08-27.log"), filepath.Join(dir, "veksel-2026-08-28.log")); err != nil {
		t.Fatal(err)
	}

	page, err := QueryManagedLogs(dir, LogQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].Message != "complete" {
		t.Fatalf("records = %+v", page.Records)
	}
	for _, cursor := range []string{"not-base64", encodeLogCursor(logCursor{File: "../../etc/passwd", Offset: 1}), encodeLogCursor(logCursor{File: "veksel-2026-08-27.log", Offset: 1 << 30})} {
		if _, err := QueryManagedLogs(dir, LogQuery{Cursor: cursor}); !errorsIs(err, ErrLogCursor) {
			t.Fatalf("cursor %q error = %v", cursor, err)
		}
	}
}

func TestQueryManagedLogsBounds(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "veksel-2026-08-27.log", "2026-08-27T08:00:00Z INFO web: "+strings.Repeat("x", maxLogLineBytes)+"\n2026-08-27T09:00:00Z INFO web: retained\n")
	page, err := QueryManagedLogs(dir, LogQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].Message != "retained" || page.NextCursor != "" {
		t.Fatalf("bounded page = %+v", page)
	}
	for _, limit := range []int{-1, maxLogPageSize + 1} {
		if _, err := QueryManagedLogs(dir, LogQuery{Limit: limit}); err == nil {
			t.Fatalf("limit %d accepted", limit)
		}
	}
}

func writeTestLog(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func messages(records []LogRecord) []string {
	values := make([]string, len(records))
	for index := range records {
		values[index] = records[index].Message
	}
	return values
}

func errorsIs(err, target error) bool {
	return err != nil && (err == target || strings.Contains(err.Error(), target.Error()))
}

func TestQueryManagedLogsMinimumLevel(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "veksel-2026-08-27.log", strings.Join([]string{
		"2026-08-27T08:00:00Z DEBUG web: debug",
		"2026-08-27T08:01:00Z INFO web: info",
		"2026-08-27T08:02:00Z WARN web: warn",
		"2026-08-27T08:03:00Z ERROR web: error",
	}, "\n")+"\n")
	page, err := QueryManagedLogs(dir, LogQuery{MinLevel: "warn"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(messages(page.Records), ","); got != "error,warn" {
		t.Fatalf("min level page = %q", got)
	}
	if _, err := QueryManagedLogs(dir, LogQuery{MinLevel: "loud"}); !errorsIs(err, ErrLogQuery) {
		t.Fatalf("invalid min level error = %v", err)
	}
}

func TestQueryManagedLogsFollowsNewRecordsAfterHead(t *testing.T) {
	dir := t.TempDir()
	writeTestLog(t, dir, "veksel-2026-08-27.log", "2026-08-27T08:00:00Z INFO web: first\n2026-08-27T08:01:00Z INFO web: partial")
	page, err := QueryManagedLogs(dir, LogQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(messages(page.Records), ","); got != "first" || page.HeadCursor == "" {
		t.Fatalf("initial page = %+v", page)
	}
	unchanged, err := QueryManagedLogs(dir, LogQuery{After: page.HeadCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.Records) != 0 || unchanged.HeadCursor != page.HeadCursor {
		t.Fatalf("idle follow = %+v", unchanged)
	}

	appendTestLog(t, dir, "veksel-2026-08-27.log", " done\n2026-08-27T08:02:00Z WARN smtp: second\n")
	writeTestLog(t, dir, "veksel-2026-08-28.log", "2026-08-28T00:00:01Z ERROR smtp: next day\n")
	follow, err := QueryManagedLogs(dir, LogQuery{After: page.HeadCursor, Module: "smtp"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(messages(follow.Records), ","); got != "next day,second" || follow.Truncated || follow.NextCursor != "" {
		t.Fatalf("follow page = %+v", follow)
	}
	all, err := QueryManagedLogs(dir, LogQuery{After: page.HeadCursor, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(messages(all.Records), ","); got != "next day,second" || !all.Truncated {
		t.Fatalf("truncated follow = %+v", all)
	}
	again, err := QueryManagedLogs(dir, LogQuery{After: follow.HeadCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Records) != 0 {
		t.Fatalf("follow after new head = %+v", again.Records)
	}
	if _, err := QueryManagedLogs(dir, LogQuery{After: page.HeadCursor, Cursor: page.HeadCursor}); !errorsIs(err, ErrLogQuery) {
		t.Fatalf("cursor with after error = %v", err)
	}
}

func appendTestLog(t *testing.T, dir, name, contents string) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(contents); err != nil {
		t.Fatal(err)
	}
}
