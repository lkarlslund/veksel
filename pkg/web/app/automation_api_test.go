package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestAutomationAPILifecycle(t *testing.T) {
	server, typedStore, _, accounts, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	owner, err := typedStore.UserStore().Get(t.Context(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := accounts.Ensure(t.Context(), owner, "owner@example.test", []string{"owner@example.test"}); err != nil {
		t.Fatal(err)
	}

	engine, err := rules.NewEngine(t.Context(), typedStore.Store(), handler.folderSpace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	handler.ConfigureAutomation(engine)

	access := service.UserAccess("owner", "test")
	if _, err := handler.folderSpace.CreateItem(t.Context(), access, model.InboxFolderID("owner"), service.ItemInput{
		Name: "matching.eml",
		Data: []byte("From: sender@example.test\r\nTo: owner@example.test\r\nSubject: API automation match\r\n\r\nbody"),
	}); err != nil {
		t.Fatal(err)
	}

	initial := automationRequest[automationResponse](t, client, http.MethodGet, server.URL+"/api/v1/automation", "", "", http.StatusOK)
	if initial.Document.OwnerID != "owner" || len(initial.Document.Rules) != 0 {
		t.Fatalf("initial automation document = %+v", initial.Document)
	}

	createBody := automationJSON(t, automationRuleRequest{
		Revision: initial.Document.Revision,
		Rule: rules.Rule{
			Name: "Tag matching messages", Enabled: true, Match: rules.MatchAll,
			SourceFolderIDs: []string{model.InboxFolderID("owner")},
			Conditions:      []rules.Condition{{Field: rules.FieldSubject, Operator: rules.OperatorContains, Value: "automation match"}},
			Actions:         []rules.Action{{Type: rules.ActionAddTag, Value: "matched"}, {Type: rules.ActionTrash}},
		},
	})
	document := automationRequest[rules.Document](t, client, http.MethodPost, server.URL+"/api/v1/automation/rules", csrf, createBody, http.StatusCreated)
	if len(document.Rules) != 1 || document.Rules[0].ID == "" || len(document.Rules[0].Actions) != 2 || document.Rules[0].Actions[1].Type != rules.ActionTrash {
		t.Fatalf("created rules = %+v", document.Rules)
	}
	ruleID := document.Rules[0].ID
	invalidTrash := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/automation/rules", csrf, automationJSON(t, automationRuleRequest{
		Revision: document.Revision,
		Rule: rules.Rule{Name: "Invalid trash order", Match: rules.MatchAll, Actions: []rules.Action{
			{Type: rules.ActionTrash}, {Type: rules.ActionAddTag, Value: "too-late"},
		}},
	}))
	defer invalidTrash.Body.Close()
	if invalidTrash.StatusCode != http.StatusBadRequest {
		contents, _ := io.ReadAll(invalidTrash.Body)
		t.Fatalf("non-final trash status = %d, want %d, body = %s", invalidTrash.StatusCode, http.StatusBadRequest, contents)
	}

	stale := authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/automation/rules/"+url.PathEscape(ruleID), csrf,
		automationJSON(t, automationRuleRequest{Revision: initial.Document.Revision, Rule: document.Rules[0]}))
	defer func() { _ = stale.Body.Close() }()
	if stale.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(stale.Body)
		t.Fatalf("stale update status = %d, body = %s", stale.StatusCode, body)
	}

	preview := automationRequest[rules.Preview](t, client, http.MethodPost, server.URL+"/api/v1/automation/rules/"+url.PathEscape(ruleID)+"/preview", csrf, `{"limit":10}`, http.StatusOK)
	if preview.Examined != 1 || preview.Matched != 1 || len(preview.Items) != 1 {
		t.Fatalf("preview = %+v", preview)
	}

	run := automationRequest[rules.Run](t, client, http.MethodPost, server.URL+"/api/v1/automation/rules/"+url.PathEscape(ruleID)+"/runs", csrf, `{"dry_run":true}`, http.StatusAccepted)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runs := automationRequest[[]rules.Run](t, client, http.MethodGet, server.URL+"/api/v1/automation/runs", "", "", http.StatusOK)
		for _, candidate := range runs {
			if candidate.ID == run.ID {
				run = candidate
			}
		}
		if run.Status == rules.RunCompleted || run.Status == rules.RunCompletedWithErrors || run.Status == rules.RunFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if run.Status != rules.RunCompleted || run.ItemsExamined != 1 || run.ItemsMatched != 1 {
		t.Fatalf("completed dry run = %+v", run)
	}

	evidence := automationRequest[[]rules.Execution](t, client, http.MethodGet, server.URL+"/api/v1/automation/evidence?rule_id="+url.QueryEscape(ruleID), "", "", http.StatusOK)
	if len(evidence) != 1 || evidence[0].RuleID != ruleID || !evidence[0].Succeeded {
		t.Fatalf("evidence = %+v", evidence)
	}

	deleted := automationRequest[rules.Document](t, client, http.MethodDelete, server.URL+"/api/v1/automation/rules/"+url.PathEscape(ruleID), csrf,
		automationJSON(t, automationRevisionRequest{Revision: document.Revision}), http.StatusOK)
	if len(deleted.Rules) != 0 {
		t.Fatalf("rules after delete = %+v", deleted.Rules)
	}
	retainedRuns := automationRequest[[]rules.Run](t, client, http.MethodGet, server.URL+"/api/v1/automation/runs", "", "", http.StatusOK)
	if len(retainedRuns) != 1 || retainedRuns[0].RuleID != ruleID || retainedRuns[0].RuleSnapshot.ID != ruleID || retainedRuns[0].RuleSnapshot.Name != "Tag matching messages" {
		t.Fatalf("deleted-rule run evidence was not retained: %+v", retainedRuns)
	}
	retryDeleted := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/automation/rules/"+url.PathEscape(ruleID)+"/runs", csrf, `{"dry_run":true}`)
	defer retryDeleted.Body.Close()
	if retryDeleted.StatusCode != http.StatusNotFound {
		contents, _ := io.ReadAll(retryDeleted.Body)
		t.Fatalf("run deleted rule status = %d, want %d, body = %s", retryDeleted.StatusCode, http.StatusNotFound, contents)
	}
}

func automationJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func automationRequest[T any](t *testing.T, client *http.Client, method, endpoint, csrf, body string, wantStatus int) T {
	t.Helper()
	response := authenticatedJSON(t, client, method, endpoint, csrf, body)
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s status = %d, want %d, body = %s", method, endpoint, response.StatusCode, wantStatus, strings.TrimSpace(string(contents)))
	}
	var result T
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
