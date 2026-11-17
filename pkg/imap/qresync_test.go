package imap

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

type expiredQResyncChangeSpace struct {
	service.FolderSpace
}

func (space *expiredQResyncChangeSpace) CurrentChangeState(context.Context, service.AccessContext, service.ChangeScope) (string, error) {
	return "", service.ErrChangeStateExpired
}

func (space *expiredQResyncChangeSpace) ListChanges(context.Context, service.AccessContext, service.ChangeScope, string, int) (service.ChangePage, error) {
	return service.ChangePage{}, service.ErrChangeStateExpired
}

func TestParseQResyncSelectOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		options []string
		wantNil bool
		wantErr bool
		check   func(*testing.T, *qresyncRequest)
	}{
		{name: "none", wantNil: true},
		{name: "condstore only", options: []string{"(CONDSTORE)"}, wantNil: true},
		{
			name:    "minimal",
			options: []string{"(QRESYNC", "(77", "42))"},
			check: func(t *testing.T, request *qresyncRequest) {
				if request.UIDValidity != 77 || request.ModSeq != 42 || request.HasKnownUIDs || request.Match != nil {
					t.Fatalf("request=%+v", request)
				}
			},
		},
		{
			name:    "complete with condstore",
			options: []string{"(CONDSTORE", "QRESYNC", "(77", "42", "9:5,12", "(1:3", "5:7)))"},
			check: func(t *testing.T, request *qresyncRequest) {
				if !request.HasKnownUIDs || formatQResyncSet(request.KnownUIDs) != "5:9,12" || request.Match == nil {
					t.Fatalf("request=%+v", request)
				}
			},
		},
		{name: "outer list required", options: []string{"QRESYNC", "(77", "42)"}, wantErr: true},
		{name: "enable data incomplete", options: []string{"(QRESYNC)"}, wantErr: true},
		{name: "empty parameter list", options: []string{"()"}, wantErr: true},
		{name: "zero uidvalidity", options: []string{"(QRESYNC", "(0", "42))"}, wantErr: true},
		{name: "zero modseq", options: []string{"(QRESYNC", "(77", "0))"}, wantErr: true},
		{name: "modseq overflow", options: []string{"(QRESYNC", "(77", "9223372036854775808))"}, wantErr: true},
		{name: "known uid wildcard", options: []string{"(QRESYNC", "(77", "42", "1:*))"}, wantErr: true},
		{name: "descending match range", options: []string{"(QRESYNC", "(77", "42", "1:8", "(3:1", "5:7)))"}, wantErr: true},
		{name: "unordered match values", options: []string{"(QRESYNC", "(77", "42", "1:8", "(1,3,2", "5:7)))"}, wantErr: true},
		{name: "match cardinality", options: []string{"(QRESYNC", "(77", "42", "1:8", "(1:2", "5:7)))"}, wantErr: true},
		{name: "match resource bound", options: []string{"(QRESYNC", "(77", "42", "1:8", "(1:100001", "1:100001)))"}, wantErr: true},
		{name: "duplicate", options: []string{"(QRESYNC", "(77", "42)", "QRESYNC", "(77", "42))"}, wantErr: true},
		{name: "unknown", options: []string{"(FUTURE)"}, wantErr: true},
		{name: "trailing data", options: []string{"(CONDSTORE)", "extra"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, err := parseQResyncSelectOptions(test.options)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v", err)
			}
			if test.wantErr {
				return
			}
			if (request == nil) != test.wantNil {
				t.Fatalf("request=%+v wantNil=%v", request, test.wantNil)
			}
			if test.check != nil {
				test.check(t, request)
			}
		})
	}
}

func TestQResyncMissingUIDsAndSequenceMatchStayRangeBounded(t *testing.T) {
	t.Parallel()
	items := []model.Item{{UID: 1}, {UID: 3}, {UID: 5}}
	scope := []qresyncUIDRange{{first: 1, last: 6}, {first: 100, last: ^uint32(0)}}
	missing := qresyncMissingUIDs(scope, items, 4)
	if got := formatQResyncSet(missing); got != "4,6,100:4294967295" {
		t.Fatalf("missing=%q", got)
	}
	match := qresyncSequenceMatch{
		sequences: []qresyncUIDRange{{first: 1, last: 2}},
		uids:      []qresyncUIDRange{{first: 1, last: 1}, {first: 3, last: 3}},
	}
	if got := qresyncMatchLowerBound(match, items); got != 4 {
		t.Fatalf("lower bound=%d", got)
	}
}

func TestQResyncRequiresEnableAndValidSyntaxBeforeSelection(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, _, _ string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	c.send("A001", "LOGIN alice secret")

	if _, code, _ := c.send("A002", "SELECT INBOX (QRESYNC (1 1))"); code != "BAD" {
		t.Fatalf("QRESYNC without ENABLE code=%s", code)
	}
	if _, code, _ := c.send("A003", "ENABLE QRESYNC"); code != "OK" {
		t.Fatalf("ENABLE code=%s", code)
	}
	if _, code, _ := c.send("A004", "SELECT INBOX (QRESYNC (1 nope))"); code != "BAD" {
		t.Fatalf("malformed QRESYNC code=%s", code)
	}
	if _, code, _ := c.send("A005", "SELECT INBOX"); code != "OK" {
		t.Fatalf("regular SELECT after rejected parameters code=%s", code)
	}
}

func TestQResyncScopesFlagChangesAndNarrowsVanishedWithSequenceMatch(t *testing.T) {
	ts := setupTestStore(t)
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, _, _ string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	}
	c := makeTestServer(t, cfg)
	c.send("A001", "LOGIN alice secret")
	access := service.UserAccess("alice", "qresync-test")
	inbox, err := cfg.FolderSpace.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 3; index++ {
		if _, err := cfg.FolderSpace.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte(fmt.Sprintf("Subject: %d\r\n\r\nBody\r\n", index))}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := cfg.FolderSpace.GetFolder(t.Context(), access, inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cfg.FolderSpace.GetItemByUID(t.Context(), access, inbox.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.FolderSpace.DeleteItem(t.Context(), access, second.ID); err != nil {
		t.Fatal(err)
	}
	third, err := cfg.FolderSpace.GetItemByUID(t.Context(), access, inbox.ID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.FolderSpace.SetFlags(t.Context(), access, third.ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := c.send("A002", "ENABLE QRESYNC"); code != "OK" {
		t.Fatalf("ENABLE code=%s", code)
	}

	lines, code := sendQResyncTestCommand(t, c, "A003", fmt.Sprintf("SELECT INBOX (QRESYNC (%d %d 1:2 (1 1)))", inbox.UIDValidity, before.HighestModSeq))
	if code != "OK" || !containsQResyncLine(lines, "VANISHED (EARLIER) 2") {
		t.Fatalf("code=%s lines=%q", code, lines)
	}
	if containsQResyncLine(lines, "FETCH (UID 3") {
		t.Fatalf("UID 3 flag update escaped known UID scope: %q", lines)
	}

	lines, code = sendQResyncTestCommand(t, c, "A004", fmt.Sprintf("SELECT INBOX (QRESYNC (%d %d 1:3 (2 3)))", inbox.UIDValidity, before.HighestModSeq))
	if code != "OK" || containsQResyncLine(lines, "VANISHED") {
		t.Fatalf("matching sequence data should suppress known earlier expunge: code=%s lines=%q", code, lines)
	}
	if !containsQResyncLine(lines, "FETCH (UID 3") {
		t.Fatalf("expected scoped UID 3 flag update: %q", lines)
	}

	lines, code = sendQResyncTestCommand(t, c, "A005", fmt.Sprintf("SELECT INBOX (QRESYNC (%d %d 1:3))", inbox.UIDValidity+1, before.HighestModSeq))
	if code != "OK" || containsQResyncLine(lines, "VANISHED") || containsQResyncLine(lines, "FETCH (UID") {
		t.Fatalf("UIDVALIDITY mismatch returned dynamic data: code=%s lines=%q", code, lines)
	}
}

func TestQResyncFallsBackToCurrentUIDComparisonWhenHistoryExpired(t *testing.T) {
	ts := setupTestStore(t)
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, _, _ string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	}
	c := makeTestServer(t, cfg)
	cfg.FolderSpace = &expiredQResyncChangeSpace{FolderSpace: cfg.FolderSpace}
	c.send("A001", "LOGIN alice secret")
	access := service.UserAccess("alice", "qresync-expired")
	inbox, err := cfg.FolderSpace.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, err := cfg.FolderSpace.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: fallback\r\n\r\nBody")}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := cfg.FolderSpace.GetFolder(t.Context(), access, inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cfg.FolderSpace.GetItemByUID(t.Context(), access, inbox.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.FolderSpace.DeleteItem(t.Context(), access, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := c.send("A002", "ENABLE QRESYNC"); code != "OK" {
		t.Fatalf("ENABLE code=%s", code)
	}
	lines, code := sendQResyncTestCommand(t, c, "A003", fmt.Sprintf("SELECT INBOX (QRESYNC (%d %d 1:3))", inbox.UIDValidity, before.HighestModSeq))
	if code != "OK" || !containsQResyncLine(lines, "VANISHED (EARLIER) 2") || containsQResyncLine(lines, "NOMODSEQ") {
		t.Fatalf("code=%s lines=%q", code, lines)
	}
}

func sendQResyncTestCommand(t *testing.T, client *tc, tag, command string) ([]string, string) {
	t.Helper()
	if _, err := fmt.Fprintf(client.Conn, "%s %s\r\n", tag, command); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for {
		line, err := client.readLine()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, tag+" ") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 2 {
				return lines, ""
			}
			return lines, parts[1]
		}
	}
}

func containsQResyncLine(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
