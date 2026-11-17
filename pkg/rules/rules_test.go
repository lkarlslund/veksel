package rules

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type rulesFixture struct {
	backend store.Store
	typed   *model.TypedStore
	space   service.FolderSpace
	access  service.AccessContext
}

func newRulesFixture(t *testing.T) *rulesFixture {
	t.Helper()
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatalf("ensure namespace %s: %v", namespace, err)
		}
	}
	for _, login := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(t.Context(), login, strings.ToUpper(login), "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), login); err != nil {
			t.Fatal(err)
		}
	}
	base := service.NewFolderSpace(typed, authz.New(typed))
	durable, err := service.NewDurableFolderSpace(t.Context(), backend, base)
	if err != nil {
		t.Fatal(err)
	}
	return &rulesFixture{backend: backend, typed: typed, space: durable, access: service.UserAccess("alice", "rules-test")}
}

func (f *rulesFixture) folder(t *testing.T, path string) model.Folder {
	t.Helper()
	folder, err := f.space.GetFolderByPath(t.Context(), f.access, path)
	if err != nil {
		t.Fatal(err)
	}
	return folder
}

func (f *rulesFixture) createFolder(t *testing.T, path string, folderType model.FolderType) model.Folder {
	t.Helper()
	if err := f.typed.FolderStore().Create(t.Context(), "alice", path, folderType, ""); err != nil {
		t.Fatal(err)
	}
	return f.folder(t, path)
}

func newTestEngine(t *testing.T, fixture *rulesFixture, space service.FolderSpace) *Engine {
	t.Helper()
	engine, err := NewEngine(t.Context(), fixture.backend, space)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func createRule(t *testing.T, engine *Engine, access service.AccessContext, rule Rule) Document {
	t.Helper()
	document, err := engine.Document(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	document, err = engine.CreateRule(t.Context(), access, document.Revision, rule)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func waitRun(t *testing.T, engine *Engine, access service.AccessContext, id string) Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runs, err := engine.Runs(t.Context(), access)
		if err != nil {
			t.Fatal(err)
		}
		for _, run := range runs {
			if run.ID != id {
				continue
			}
			switch run.Status {
			case RunCompleted, RunCompletedWithErrors, RunCancelled, RunFailed:
				return run
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("automation run %s did not finish", id)
	return Run{}
}

func TestFolderSpaceRetainsConditionalItemUpdates(t *testing.T) {
	fixture := newRulesFixture(t)
	engine := newTestEngine(t, fixture, fixture.space)
	decorated, err := NewFolderSpace(fixture.space, engine)
	if err != nil {
		t.Fatal(err)
	}
	updater, ok := any(decorated).(service.ConditionalItemUpdater)
	if !ok {
		t.Fatal("automation FolderSpace dropped the conditional update capability")
	}
	inbox := fixture.folder(t, "INBOX")
	created, err := decorated.CreateItem(t.Context(), fixture.access, inbox.ID, service.ItemInput{Data: []byte("Subject: one\r\n\r\nbody"), Headers: map[string]string{"Subject": "one"}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := updater.UpdateItemIfModSeq(t.Context(), fixture.access, created.ID, created.ModSeq, []byte("Subject: two\r\n\r\nbody"), map[string]string{"Subject": "two"})
	if err != nil || updated.ModSeq <= created.ModSeq || updated.Headers["Subject"] != "two" {
		t.Fatalf("conditional update through automation = %+v, %v", updated, err)
	}
	if _, err := updater.UpdateItemIfModSeq(t.Context(), fixture.access, created.ID, created.ModSeq, []byte("stale"), nil); !errors.Is(err, service.ErrItemUpdateConflict) {
		t.Fatalf("stale conditional update error = %v", err)
	}
}

func TestActiveRunPreventsRuleDeletion(t *testing.T) {
	fixture := newRulesFixture(t)
	engine := newTestEngine(t, fixture, fixture.space)
	document := createRule(t, engine, fixture.access, Rule{Name: "Protected while running", Enabled: true, Match: MatchAll, FolderTypes: []model.FolderType{model.FolderTypeMail}, Actions: []Action{{Type: ActionAddTag, Value: "test"}}})
	rule := document.Rules[0]
	now := time.Now().UTC()
	run := Run{ID: "run_active", OwnerID: "alice", RuleID: rule.ID, RuleName: rule.Name, Status: RunRunning, CreatedAt: now, UpdatedAt: now, RuleSnapshot: rule}
	if err := engine.repository.SaveRun(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.DeleteRule(t.Context(), fixture.access, document.Revision, rule.ID); !errors.Is(err, store.ErrPreconditionFailed) {
		t.Fatalf("delete with active run error = %v", err)
	}
	run.Status, run.FinishedAt, run.UpdatedAt = RunCompleted, now, now
	if err := engine.repository.SaveRun(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	deleted, err := engine.DeleteRule(t.Context(), fixture.access, document.Revision, rule.ID)
	if err != nil || len(deleted.Rules) != 0 {
		t.Fatalf("delete after terminal run = %+v, %v", deleted, err)
	}
}

func TestMatchEvaluatesProtocolNeutralFieldsAndMultiValueNegation(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	mailFolder := model.Folder{ID: "mail", Type: model.FolderTypeMail}
	mailItem := model.Item{
		Data: []byte("From: sender@example.test\r\nTo: alice@example.test, bob@example.test\r\nSubject: Quarterly Report\r\nX-Project: North\r\n\r\nRevenue grew"),
		Size: 220, InternalDate: now, Flags: []string{model.FlagSeen}, Headers: map[string]string{"Content-Type": "message/rfc822", tagHeader: "finance, review"},
	}
	rule := Rule{ID: "mail-rule", Name: "Mail", Enabled: false, Match: MatchAll, FolderTypes: []model.FolderType{model.FolderTypeMail}, Conditions: []Condition{
		{Field: FieldFrom, Operator: OperatorContains, Value: "SENDER@EXAMPLE.TEST"},
		{Field: FieldTo, Operator: OperatorNotEquals, Value: "nobody@example.test"},
		{Field: FieldSubject, Operator: OperatorPrefix, Value: "quarterly"},
		{Field: "header", Header: "X-Project", Operator: OperatorEquals, Value: "north"},
		{Field: FieldContent, Operator: OperatorContains, Value: "revenue"},
		{Field: FieldFlag, Operator: OperatorEquals, Value: model.FlagSeen},
		{Field: FieldTag, Operator: OperatorEquals, Value: "finance"},
		{Field: FieldSize, Operator: OperatorGreater, Value: "100"},
		{Field: FieldDate, Operator: OperatorAfter, Value: "2026-08-01T00:00:00Z"},
	}, Actions: []Action{{Type: ActionAddTag, Value: "matched"}}}
	if result := Match(rule, mailFolder, mailItem); !result.Matched || len(result.Conditions) != len(rule.Conditions) {
		t.Fatalf("mail match = %#v", result)
	}
	rule.Conditions[1].Value = "bob@example.test"
	if Match(rule, mailFolder, mailItem).Matched {
		t.Fatal("not_equals matched when one recipient equalled the unwanted value")
	}
	rule.Match = MatchAny
	if !Match(rule, mailFolder, mailItem).Matched {
		t.Fatal("any-mode did not retain the other matching conditions")
	}

	calendar := model.Item{Data: []byte("BEGIN:VCALENDAR\r\nSUMMARY:Planning session\r\nORGANIZER:mailto:owner@example.test\r\nATTENDEE;CN=Ada:mailto:ada@exam\r\n ple.test\r\nEND:VCALENDAR\r\n")}
	calendarRule := Rule{ID: "calendar-rule", Name: "Calendar", Enabled: true, Match: MatchAll, FolderTypes: []model.FolderType{model.FolderTypeCalendar}, Conditions: []Condition{
		{Field: FieldSummary, Operator: OperatorContains, Value: "planning"},
		{Field: FieldOrganizer, Operator: OperatorContains, Value: "owner@example.test"},
		{Field: FieldAttendee, Operator: OperatorContains, Value: "ada@example.test"},
	}, Actions: []Action{{Type: ActionAddTag, Value: "calendar"}}}
	if !Match(calendarRule, model.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, calendar).Matched {
		t.Fatal("calendar properties, including a folded attendee, did not match")
	}

	contact := model.Item{Data: []byte("BEGIN:VCARD\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.test\r\nORG:Analytical Engines\r\nEND:VCARD\r\n")}
	contactRule := Rule{ID: "contact-rule", Name: "Contact", Enabled: true, Match: MatchAll, Conditions: []Condition{
		{Field: FieldEmail, Operator: OperatorSuffix, Value: "@example.test"},
		{Field: FieldOrganization, Operator: OperatorContains, Value: "engines"},
	}, Actions: []Action{{Type: ActionAddTag, Value: "contact"}}}
	if !Match(contactRule, model.Folder{ID: "contacts", Type: model.FolderTypeContacts}, contact).Matched {
		t.Fatal("contact properties did not match")
	}
}

func TestRuleValidationRejectsUnsafeOrUnboundedDefinitions(t *testing.T) {
	valid := Rule{ID: "valid", Name: "Valid", Match: MatchAll, Actions: []Action{{Type: ActionAddTag, Value: "tag"}}}
	if err := ValidateRule(valid); err != nil {
		t.Fatal(err)
	}
	tests := map[string]Rule{
		"invalid id":         {ID: "bad id", Name: "Bad", Match: MatchAll, Actions: valid.Actions},
		"missing name":       {ID: "bad", Match: MatchAll, Actions: valid.Actions},
		"unknown type":       {ID: "bad", Name: "Bad", Match: MatchAll, FolderTypes: []model.FolderType{"unknown"}, Actions: valid.Actions},
		"missing action":     {ID: "bad", Name: "Bad", Match: MatchAll},
		"header without key": {ID: "bad", Name: "Bad", Match: MatchAll, Conditions: []Condition{{Field: "header", Operator: OperatorEquals, Value: "x"}}, Actions: valid.Actions},
		"trash before final": {ID: "bad", Name: "Bad", Match: MatchAll, Actions: []Action{{Type: ActionTrash}, {Type: ActionAddTag, Value: "later"}}},
		"trash with value":   {ID: "bad", Name: "Bad", Match: MatchAll, Actions: []Action{{Type: ActionTrash, Value: "now"}}},
		"trash destination":  {ID: "bad", Name: "Bad", Match: MatchAll, Actions: []Action{{Type: ActionTrash, DestinationFolderID: "folder"}}},
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRule(candidate); err == nil {
				t.Fatal("validation succeeded")
			}
		})
	}
}

func TestRepositoryCASPersistenceAndChronologicalRetention(t *testing.T) {
	fixture := newRulesFixture(t)
	repository, err := NewRepository(t.Context(), fixture.backend)
	if err != nil {
		t.Fatal(err)
	}
	document, err := repository.Load(t.Context(), "alice")
	if err != nil || document.Revision != "initial" || document.Rules == nil {
		t.Fatalf("initial document = %#v, %v", document, err)
	}
	candidate := document
	candidate.Rules = append(candidate.Rules, Rule{ID: "persisted", Name: "Persisted", Enabled: true, Match: MatchAll, Actions: []Action{{Type: ActionAddTag, Value: "stored"}}})
	saved, err := repository.Replace(t.Context(), "alice", document.Revision, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Replace(t.Context(), "alice", document.Revision, candidate); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale replace error = %v", err)
	}
	reloaded, err := repository.Load(t.Context(), "alice")
	if err != nil || reloaded.Revision != saved.Revision || len(reloaded.Rules) != 1 {
		t.Fatalf("reloaded document = %#v, %v", reloaded, err)
	}

	base := time.Now().UTC().Add(-time.Hour)
	for index := 0; index < MaxRunHistoryPerOwner+1; index++ {
		status := RunCompleted
		if index == 0 {
			status = RunRunning
		}
		run := Run{ID: fmt.Sprintf("run-%03d", index), OwnerID: "alice", RuleID: "persisted", Status: status, CreatedAt: base.Add(time.Duration(index) * time.Second)}
		if err := repository.SaveRun(t.Context(), run); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := repository.ListRuns(t.Context(), "alice")
	if err != nil || len(runs) != MaxRunHistoryPerOwner {
		t.Fatalf("retained runs = %d, %v", len(runs), err)
	}
	if !slices.ContainsFunc(runs, func(run Run) bool { return run.ID == "run-000" && run.Status == RunRunning }) {
		t.Fatal("active oldest run was pruned")
	}
	if slices.ContainsFunc(runs, func(run Run) bool { return run.ID == "run-001" }) {
		t.Fatal("oldest terminal run was not pruned")
	}
}

func TestFolderSpaceAppliesOrderedRulesAndStopSemantics(t *testing.T) {
	fixture := newRulesFixture(t)
	archive := fixture.createFolder(t, "Rules Archive", model.FolderTypeMail)
	engine := newTestEngine(t, fixture, fixture.space)
	document := createRule(t, engine, fixture.access, Rule{
		Name: "Tag invoices", Enabled: true, Match: MatchAll, Stop: true,
		SourceFolderIDs: []string{model.InboxFolderID("alice")}, Conditions: []Condition{{Field: FieldSubject, Operator: OperatorContains, Value: "invoice"}},
		Actions: []Action{{Type: ActionAddTag, Value: "finance"}},
	})
	firstID := document.Rules[0].ID
	document, err := engine.CreateRule(t.Context(), fixture.access, document.Revision, Rule{
		Name: "Archive invoices", Enabled: true, Match: MatchAll,
		SourceFolderIDs: []string{model.InboxFolderID("alice")}, Conditions: []Condition{{Field: FieldSubject, Operator: OperatorContains, Value: "invoice"}},
		Actions: []Action{{Type: ActionMove, DestinationFolderID: archive.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decorated, err := NewFolderSpace(fixture.space, engine)
	if err != nil {
		t.Fatal(err)
	}
	first, err := decorated.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: Invoice 1\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if first.FolderID != model.InboxFolderID("alice") || first.Headers[tagHeader] != "finance" {
		t.Fatalf("stopped item = %#v", first)
	}
	evidence, err := engine.Evidence(t.Context(), fixture.access, "", 10)
	if err != nil || len(evidence) != 1 || evidence[0].RuleID != firstID || !evidence[0].Succeeded {
		t.Fatalf("first evidence = %#v, %v", evidence, err)
	}

	firstRule := document.Rules[0]
	firstRule.Stop = false
	document, err = engine.UpdateRule(t.Context(), fixture.access, document.Revision, firstRule.ID, firstRule)
	if err != nil {
		t.Fatal(err)
	}
	second, err := decorated.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: Invoice 2\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if second.FolderID != archive.ID || second.Headers[tagHeader] != "finance" {
		t.Fatalf("continued item = %#v", second)
	}
	if document.Rules[0].Priority >= document.Rules[1].Priority {
		t.Fatalf("rule priorities = %d, %d", document.Rules[0].Priority, document.Rules[1].Priority)
	}
}

func TestArrivalRulesTrashEveryTypedItemRecoverably(t *testing.T) {
	fixture := newRulesFixture(t)
	engine := newTestEngine(t, fixture, fixture.space)
	types := []model.FolderType{
		model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts,
		model.FolderTypeFiles, model.FolderTypeNotes, model.FolderTypeScheduleInbox,
		model.FolderTypeScheduleOutbox,
	}
	folders := make([]model.Folder, 0, len(types))
	document, err := engine.Document(t.Context(), fixture.access)
	if err != nil {
		t.Fatal(err)
	}
	for index, folderType := range types {
		folder := fixture.createFolder(t, fmt.Sprintf("Trash rule %02d", index), folderType)
		folders = append(folders, folder)
		document, err = engine.CreateRule(t.Context(), fixture.access, document.Revision, Rule{
			Name: "Trash " + string(folderType), Enabled: true, Match: MatchAll, Stop: true,
			SourceFolderIDs: []string{folder.ID},
			Actions:         []Action{{Type: ActionAddTag, Value: "before-trash"}, {Type: ActionTrash}},
		})
		if err != nil {
			t.Fatalf("create %s trash rule: %v", folderType, err)
		}
	}
	decorated, err := NewFolderSpace(fixture.space, engine)
	if err != nil {
		t.Fatal(err)
	}
	for index, folder := range folders {
		item, err := decorated.CreateItem(t.Context(), fixture.access, folder.ID, service.ItemInput{Name: fmt.Sprintf("item-%02d", index), Data: []byte("content")})
		if err != nil {
			t.Fatalf("create %s item: %v", folder.Type, err)
		}
		if item.TrashedAt.IsZero() || item.OriginalFolderID != folder.ID || item.Headers[tagHeader] != "before-trash" {
			t.Fatalf("%s item was not recoverably trashed after prior action: %#v", folder.Type, item)
		}
		restored, err := decorated.RestoreItem(t.Context(), fixture.access, item.ID)
		if err != nil {
			t.Fatalf("restore %s item: %v", folder.Type, err)
		}
		if restored.FolderID != folder.ID || !restored.TrashedAt.IsZero() || restored.Headers[tagHeader] != "before-trash" {
			t.Fatalf("restored %s item = %#v", folder.Type, restored)
		}
	}
	evidence, err := engine.Evidence(t.Context(), fixture.access, "", 20)
	if err != nil || len(evidence) != len(types) {
		t.Fatalf("trash evidence = %#v, %v", evidence, err)
	}
	for _, execution := range evidence {
		if !execution.Succeeded || !execution.FinalTrashed || len(execution.Actions) != 2 || execution.Actions[1].Type != ActionTrash || !execution.Actions[1].Succeeded {
			t.Fatalf("trash execution evidence = %#v", execution)
		}
	}
}

func TestTrashActionEndsArrivalRuleEvaluation(t *testing.T) {
	fixture := newRulesFixture(t)
	engine := newTestEngine(t, fixture, fixture.space)
	document := createRule(t, engine, fixture.access, Rule{
		Name: "Trash first", Enabled: true, Match: MatchAll, Stop: false,
		SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions:         []Action{{Type: ActionTrash}},
	})
	if _, err := engine.CreateRule(t.Context(), fixture.access, document.Revision, Rule{
		Name: "Must not run", Enabled: true, Match: MatchAll,
		SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions:         []Action{{Type: ActionAddTag, Value: "after-trash"}},
	}); err != nil {
		t.Fatal(err)
	}
	decorated, err := NewFolderSpace(fixture.space, engine)
	if err != nil {
		t.Fatal(err)
	}
	item, err := decorated.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: terminal trash\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if item.TrashedAt.IsZero() || item.Headers[tagHeader] != "" {
		t.Fatalf("later rule mutated trashed item: %#v", item)
	}
	evidence, err := engine.Evidence(t.Context(), fixture.access, "", 10)
	if err != nil || len(evidence) != 1 || evidence[0].RuleName != "Trash first" {
		t.Fatalf("terminal trash evidence = %#v, %v", evidence, err)
	}
}

func TestManualTrashRunDryRunThenAppliesAndRestores(t *testing.T) {
	fixture := newRulesFixture(t)
	item, err := fixture.space.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: remove existing\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(t, fixture, fixture.space)
	document := createRule(t, engine, fixture.access, Rule{
		Name: "Trash existing", Enabled: false, Match: MatchAll,
		SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions:         []Action{{Type: ActionTrash}},
	})
	ruleID := document.Rules[0].ID
	dry, err := engine.StartRun(t.Context(), fixture.access, ruleID, true)
	if err != nil {
		t.Fatal(err)
	}
	dry = waitRun(t, engine, fixture.access, dry.ID)
	if dry.Status != RunCompleted || dry.ItemsMatched != 1 || dry.ItemsSucceeded != 1 {
		t.Fatalf("dry trash run = %#v", dry)
	}
	if _, err := fixture.space.GetItem(t.Context(), fixture.access, item.ID); err != nil {
		t.Fatalf("dry run changed item: %v", err)
	}
	apply, err := engine.StartRun(t.Context(), fixture.access, ruleID, false)
	if err != nil {
		t.Fatal(err)
	}
	apply = waitRun(t, engine, fixture.access, apply.ID)
	if apply.Status != RunCompleted || apply.ItemsSucceeded != 1 || apply.ItemsFailed != 0 {
		t.Fatalf("applied trash run = %#v", apply)
	}
	recovery := fixture.space.(service.RecoverableFolderSpace)
	trash, err := recovery.ListTrash(t.Context(), fixture.access)
	if err != nil || !slices.ContainsFunc(trash, func(summary service.ItemSummary) bool { return summary.ID == item.ID }) {
		t.Fatalf("manual run trash = %#v, %v", trash, err)
	}
	if restored, err := recovery.RestoreItem(t.Context(), fixture.access, item.ID); err != nil || restored.FolderID != model.InboxFolderID("alice") {
		t.Fatalf("restore manually trashed item = %#v, %v", restored, err)
	}
}

func TestPreviewAndManualRunsAreBoundedDryRunCapableAndCopyIdempotent(t *testing.T) {
	fixture := newRulesFixture(t)
	copyFolder := fixture.createFolder(t, "Rule Copies", model.FolderTypeMail)
	original, err := fixture.space.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: Copy me\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(t, fixture, fixture.space)
	document := createRule(t, engine, fixture.access, Rule{
		Name: "Copy selected mail", Enabled: false, Match: MatchAll,
		SourceFolderIDs: []string{model.InboxFolderID("alice")}, Conditions: []Condition{{Field: FieldSubject, Operator: OperatorEquals, Value: "Copy me"}},
		Actions: []Action{{Type: ActionCopy, DestinationFolderID: copyFolder.ID}},
	})
	ruleID := document.Rules[0].ID
	preview, err := engine.Preview(t.Context(), fixture.access, ruleID, 10)
	if err != nil || preview.Examined != 1 || preview.Matched != 1 || len(preview.Items) != 1 || preview.Items[0].ItemID != original.ID {
		t.Fatalf("preview = %#v, %v", preview, err)
	}
	dry, err := engine.StartRun(t.Context(), fixture.access, ruleID, true)
	if err != nil {
		t.Fatal(err)
	}
	dry = waitRun(t, engine, fixture.access, dry.ID)
	if dry.Status != RunCompleted || dry.ItemsMatched != 1 || dry.ItemsSucceeded != 1 {
		t.Fatalf("dry run = %#v", dry)
	}
	if items, err := fixture.space.ListItems(t.Context(), fixture.access, copyFolder.ID, service.ItemQuery{}); err != nil || len(items) != 0 {
		t.Fatalf("dry-run destination = %#v, %v", items, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		run, err := engine.StartRun(t.Context(), fixture.access, ruleID, false)
		if err != nil {
			t.Fatal(err)
		}
		run = waitRun(t, engine, fixture.access, run.ID)
		if run.Status != RunCompleted || run.ItemsFailed != 0 {
			t.Fatalf("copy run %d = %#v", attempt, run)
		}
	}
	items, err := fixture.space.ListItems(t.Context(), fixture.access, copyFolder.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 || string(items[0].Data) != string(original.Data) {
		t.Fatalf("idempotent copies = %#v, %v", items, err)
	}
}

type failingMoveSpace struct{ service.FolderSpace }

type noRecoverySpace struct{ service.FolderSpace }

type failingTrashSpace struct {
	service.FolderSpace
	service.RecoverableFolderSpace
}

func (s *failingTrashSpace) Batch(ctx context.Context, fn func(context.Context) error) error {
	return service.Batch(ctx, s.FolderSpace, fn)
}

func (s *failingTrashSpace) TrashItem(context.Context, service.AccessContext, string) (model.Item, error) {
	return model.Item{}, errors.New("injected trash failure")
}

func (s *failingMoveSpace) Batch(ctx context.Context, fn func(context.Context) error) error {
	return service.Batch(ctx, s.FolderSpace, fn)
}

func (s *failingMoveSpace) MoveItem(context.Context, service.AccessContext, string, string, string) (model.Item, error) {
	return model.Item{}, errors.New("injected move failure")
}

func TestActionFailureRollsBackPriorActionsWithoutFailingIngestion(t *testing.T) {
	fixture := newRulesFixture(t)
	archive := fixture.createFolder(t, "Atomic Archive", model.FolderTypeMail)
	failing := &failingMoveSpace{FolderSpace: fixture.space}
	engine := newTestEngine(t, fixture, failing)
	createRule(t, engine, fixture.access, Rule{
		Name: "Atomic actions", Enabled: true, Match: MatchAll, SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions: []Action{{Type: ActionAddFlag, Value: model.FlagFlagged}, {Type: ActionMove, DestinationFolderID: archive.ID}},
	})
	decorated, err := NewFolderSpace(failing, engine)
	if err != nil {
		t.Fatal(err)
	}
	created, err := decorated.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: durable first\r\n\r\nbody")})
	if err != nil {
		t.Fatalf("committed ingestion returned action failure: %v", err)
	}
	stored, err := fixture.space.GetItem(t.Context(), fixture.access, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.FolderID != model.InboxFolderID("alice") || slices.Contains(stored.Flags, model.FlagFlagged) {
		t.Fatalf("partially committed actions = %#v", stored)
	}
	evidence, err := engine.Evidence(t.Context(), fixture.access, "", 10)
	if err != nil || len(evidence) != 1 || evidence[0].Succeeded || len(evidence[0].Actions) != 2 || !evidence[0].Actions[0].RolledBack || evidence[0].Actions[1].Succeeded || !strings.Contains(evidence[0].Error, "injected move failure") {
		t.Fatalf("rollback evidence = %#v, %v", evidence, err)
	}
}

func TestTrashActionFailsSafelyWithoutRecoverableFolderCapability(t *testing.T) {
	fixture := newRulesFixture(t)
	limited := &noRecoverySpace{FolderSpace: fixture.space}
	engine := newTestEngine(t, fixture, limited)
	createRule(t, engine, fixture.access, Rule{
		Name: "Require recovery", Enabled: true, Match: MatchAll, Stop: true,
		SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions:         []Action{{Type: ActionTrash}},
	})
	decorated, err := NewFolderSpace(limited, engine)
	if err != nil {
		t.Fatal(err)
	}
	created, err := decorated.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: retained\r\n\r\nbody")})
	if err != nil {
		t.Fatalf("ingestion returned automation capability failure: %v", err)
	}
	if _, err := fixture.space.GetItem(t.Context(), fixture.access, created.ID); err != nil {
		t.Fatalf("item was lost after unavailable trash action: %v", err)
	}
	evidence, err := engine.Evidence(t.Context(), fixture.access, "", 10)
	if err != nil || len(evidence) != 1 || evidence[0].Succeeded || len(evidence[0].Actions) != 1 || evidence[0].Actions[0].Succeeded || !strings.Contains(evidence[0].Error, "recoverable item trash is unavailable") {
		t.Fatalf("unavailable trash evidence = %#v, %v", evidence, err)
	}
}

func TestTrashFailureRollsBackEarlierActions(t *testing.T) {
	fixture := newRulesFixture(t)
	failing := &failingTrashSpace{FolderSpace: fixture.space, RecoverableFolderSpace: fixture.space.(service.RecoverableFolderSpace)}
	engine := newTestEngine(t, fixture, failing)
	createRule(t, engine, fixture.access, Rule{
		Name: "Atomic trash", Enabled: true, Match: MatchAll, Stop: true,
		SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions:         []Action{{Type: ActionAddFlag, Value: model.FlagFlagged}, {Type: ActionTrash}},
	})
	decorated, err := NewFolderSpace(failing, engine)
	if err != nil {
		t.Fatal(err)
	}
	created, err := decorated.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte("Subject: atomic trash\r\n\r\nbody")})
	if err != nil {
		t.Fatalf("committed ingestion returned trash action failure: %v", err)
	}
	stored, err := fixture.space.GetItem(t.Context(), fixture.access, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TrashedAt.IsZero() || slices.Contains(stored.Flags, model.FlagFlagged) {
		t.Fatalf("trash failure partially committed actions: %#v", stored)
	}
	evidence, err := engine.Evidence(t.Context(), fixture.access, "", 10)
	if err != nil || len(evidence) != 1 || evidence[0].Succeeded || len(evidence[0].Actions) != 2 || !evidence[0].Actions[0].RolledBack || evidence[0].Actions[1].Succeeded || !strings.Contains(evidence[0].Error, "injected trash failure") {
		t.Fatalf("trash rollback evidence = %#v, %v", evidence, err)
	}
}

type blockingPager struct {
	service.FolderSpace
	calls   atomic.Int32
	blocked chan struct{}
	once    sync.Once
}

func (s *blockingPager) ListItemPage(ctx context.Context, access service.AccessContext, folderID string, query service.ItemPageQuery) (service.ItemPage, error) {
	if s.calls.Add(1) > 1 {
		s.once.Do(func() { close(s.blocked) })
		<-ctx.Done()
		return service.ItemPage{}, ctx.Err()
	}
	pager := s.FolderSpace.(service.FolderItemPager)
	return pager.ListItemPage(ctx, access, folderID, query)
}

func TestManualRunResumesFromDurablePageCheckpointAfterEngineRestart(t *testing.T) {
	fixture := newRulesFixture(t)
	for index := 0; index < 120; index++ {
		if _, err := fixture.space.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte(fmt.Sprintf("Subject: item %03d\r\n\r\nbody", index))}); err != nil {
			t.Fatal(err)
		}
	}
	blocked := make(chan struct{})
	interruptible := &blockingPager{FolderSpace: fixture.space, blocked: blocked}
	engine, err := NewEngine(t.Context(), fixture.backend, interruptible)
	if err != nil {
		t.Fatal(err)
	}
	document := createRule(t, engine, fixture.access, Rule{
		Name: "Flag existing", Enabled: true, Match: MatchAll, SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions: []Action{{Type: ActionAddFlag, Value: model.FlagFlagged}},
	})
	run, err := engine.StartRun(t.Context(), fixture.access, document.Rules[0].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not reach its second page")
	}
	engine.Close()
	repository, err := NewRepository(t.Context(), fixture.backend)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := repository.GetRun(t.Context(), "alice", run.ID)
	if err != nil || interrupted.Status != RunRunning || interrupted.CheckpointBeforeUID == 0 || interrupted.ItemsExamined != 100 || len(interrupted.FolderIDs) != 1 || interrupted.RuleSnapshot.ID == "" {
		t.Fatalf("interrupted run = %#v, %v", interrupted, err)
	}
	resumed, err := NewEngine(t.Context(), fixture.backend, fixture.space)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resumed.Close)
	completed := waitRun(t, resumed, fixture.access, run.ID)
	if completed.Status != RunCompleted || completed.ItemsExamined != 120 || completed.ItemsSucceeded != 120 || completed.FoldersDone != 1 {
		t.Fatalf("resumed run = %#v", completed)
	}
}

func TestManualRunCancellationRetainsCommittedCheckpoint(t *testing.T) {
	fixture := newRulesFixture(t)
	for index := 0; index < 120; index++ {
		if _, err := fixture.space.CreateItem(t.Context(), fixture.access, model.InboxFolderID("alice"), service.ItemInput{Data: []byte(fmt.Sprintf("Subject: cancel %03d\r\n\r\nbody", index))}); err != nil {
			t.Fatal(err)
		}
	}
	blocked := make(chan struct{})
	interruptible := &blockingPager{FolderSpace: fixture.space, blocked: blocked}
	engine := newTestEngine(t, fixture, interruptible)
	document := createRule(t, engine, fixture.access, Rule{
		Name: "Cancel existing run", Enabled: true, Match: MatchAll, SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions: []Action{{Type: ActionAddTag, Value: "cancelled-run"}},
	})
	run, err := engine.StartRun(t.Context(), fixture.access, document.Rules[0].ID, true)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not reach its second page")
	}
	if _, err := engine.CancelRun(t.Context(), fixture.access, run.ID); err != nil {
		t.Fatal(err)
	}
	cancelled := waitRun(t, engine, fixture.access, run.ID)
	if cancelled.Status != RunCancelled || cancelled.ItemsExamined != 100 || cancelled.CheckpointBeforeUID == 0 || !cancelled.CancelRequested {
		t.Fatalf("cancelled run = %#v", cancelled)
	}
}

func TestRulesAPIRejectsForgedDelegationAndIncompatibleFolderActions(t *testing.T) {
	fixture := newRulesFixture(t)
	engine := newTestEngine(t, fixture, fixture.space)
	forged := service.AccessContext{
		Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Mode: authz.ActingDelegation, Protocol: "test",
	}
	if _, err := engine.Document(t.Context(), forged); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("forged delegation error = %v", err)
	}
	document, err := engine.Document(t.Context(), fixture.access)
	if err != nil {
		t.Fatal(err)
	}
	calendar := fixture.folder(t, "Calendar")
	_, err = engine.CreateRule(t.Context(), fixture.access, document.Revision, Rule{
		Name: "Invalid cross-type move", Enabled: true, Match: MatchAll, SourceFolderIDs: []string{model.InboxFolderID("alice")},
		Actions: []Action{{Type: ActionMove, DestinationFolderID: calendar.ID}},
	})
	if err == nil || !strings.Contains(err.Error(), "differs from source type") {
		t.Fatalf("cross-type action error = %v", err)
	}
}

func TestCategoryActionAndConditionAcrossItemTypes(t *testing.T) {
	fixture := newRulesFixture(t)
	engine := newTestEngine(t, fixture, fixture.space)
	createRule(t, engine, fixture.access, Rule{Name: "Categorize", Enabled: true, Match: MatchAny, Conditions: []Condition{{Field: FieldSubject, Operator: OperatorContains, Value: "north"}, {Field: FieldSummary, Operator: OperatorContains, Value: "north"}}, Actions: []Action{{Type: ActionAddCategory, Value: "Project North"}}})
	createRule(t, engine, fixture.access, Rule{Name: "Flag categorized", Enabled: true, Match: MatchAll, FolderTypes: []model.FolderType{model.FolderTypeMail}, Conditions: []Condition{{Field: FieldCategory, Operator: OperatorEquals, Value: "project north"}}, Actions: []Action{{Type: ActionAddFlag, Value: model.FlagFlagged}}})
	inbox := fixture.folder(t, "INBOX")
	created, err := fixture.space.CreateItem(t.Context(), fixture.access, inbox.ID, service.ItemInput{Data: []byte("Subject: North update\r\n\r\nbody"), Headers: map[string]string{"Subject": "North update"}})
	if err != nil {
		t.Fatal(err)
	}
	applied := engine.Apply(t.Context(), fixture.access, created)
	if !slices.Contains(applied.Flags, "project_north") || !slices.Contains(applied.Flags, model.FlagFlagged) {
		t.Fatalf("mail flags = %v", applied.Flags)
	}
	calendar := fixture.folder(t, "Calendar")
	event, err := fixture.space.CreateItem(t.Context(), fixture.access, calendar.ID, service.ItemInput{Data: []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260101T100000Z\r\nSUMMARY:North planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"), Headers: map[string]string{"UID": "e1"}})
	if err != nil {
		t.Fatal(err)
	}
	applied = engine.Apply(t.Context(), fixture.access, event)
	if !strings.Contains(string(applied.Data), "CATEGORIES:Project North") {
		t.Fatalf("event data = %s", applied.Data)
	}
	rule := Rule{ID: "rule_has", Name: "Has", Enabled: true, Match: MatchAll, Conditions: []Condition{{Field: FieldCategory, Operator: OperatorEquals, Value: "PROJECT NORTH"}}, Actions: []Action{{Type: ActionRemoveCategory, Value: "Project North"}}}
	if !Match(rule, calendar, applied).Matched {
		t.Fatal("event category condition did not match")
	}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("category rule rejected: %v", err)
	}
}

// announcingSpace is a folder space that only announces commits.
type announcingSpace struct {
	service.FolderSpace
	listener func(string, []string)
}

func (s *announcingSpace) OnChangesCommitted(listener func(string, []string)) func() {
	s.listener = listener
	return func() { s.listener = nil }
}

// TestFolderSpaceForwardsCommitNotifications: the automation layer, the
// outermost folder space in production, passes commit listeners through.
func TestFolderSpaceForwardsCommitNotifications(t *testing.T) {
	inner := &announcingSpace{}
	var space service.FolderSpace = &FolderSpace{FolderSpace: inner}
	notifier, ok := space.(service.FolderChangeNotifier)
	if !ok {
		t.Fatal("the automated folder space does not announce commits")
	}
	remove := notifier.OnChangesCommitted(func(string, []string) {})
	if inner.listener == nil {
		t.Fatal("listener not forwarded")
	}
	remove()
	if inner.listener != nil {
		t.Fatal("listener not removed")
	}
}
