package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
)

func TestAdminMailPolicyLifecycleSimulationAndStats(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	policies, err := mailpolicy.NewService(t.Context(), mailpolicy.NewRepository(ts.Store()))
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureMailPolicies(policies)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/mail-policies", "", "")
	var initial mailPolicyResponse
	decodeResponse(t, response, &initial)
	if response.StatusCode != http.StatusOK || initial.Document.Revision != "initial" || initial.Stats.Revision != "initial" {
		t.Fatalf("initial response = %+v status=%d", initial, response.StatusCode)
	}

	createBody := policyRuleJSON(t, initial.Document.Revision, mailpolicy.Rule{
		Name: "Reject large inbound mail", Enabled: true, Priority: 20,
		Conditions: []mailpolicy.Condition{{Field: mailpolicy.FieldDirection, Operator: mailpolicy.OperatorEquals, Value: "inbound"}, {Field: mailpolicy.FieldSizeBytes, Operator: mailpolicy.OperatorGreaterThan, Value: "1000"}},
		Actions:    []mailpolicy.Action{{Type: mailpolicy.ActionReject, Value: "message too large", EnhancedStatusCode: "5.3.4"}},
	})
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/rules", csrf, createBody)
	var created mailPolicyResponse
	decodeResponse(t, response, &created)
	if response.StatusCode != http.StatusCreated || len(created.Document.Rules) != 1 || !strings.HasPrefix(created.Document.Rules[0].ID, "rule_") || created.Document.Revision == initial.Document.Revision {
		t.Fatalf("created response = %+v status=%d", created, response.StatusCode)
	}
	ruleID := created.Document.Rules[0].ID
	secondBody := policyRuleJSON(t, created.Document.Revision, mailpolicy.Rule{
		Name: "Accept outbound mail", Enabled: true, Priority: 30,
		Conditions: []mailpolicy.Condition{{Field: mailpolicy.FieldDirection, Operator: mailpolicy.OperatorEquals, Value: "outbound"}},
		Actions:    []mailpolicy.Action{{Type: mailpolicy.ActionAccept}},
	})
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/rules", csrf, secondBody)
	var withSecond mailPolicyResponse
	decodeResponse(t, response, &withSecond)
	if response.StatusCode != http.StatusCreated || len(withSecond.Document.Rules) != 2 {
		t.Fatalf("second create response = %+v status=%d", withSecond, response.StatusCode)
	}
	secondID := withSecond.Document.Rules[1].ID
	reorder, _ := json.Marshal(mailPolicyReorderRequest{Revision: withSecond.Document.Revision, RuleIDs: []string{secondID, ruleID}})
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/reorder", csrf, string(reorder))
	var reordered mailPolicyResponse
	decodeResponse(t, response, &reordered)
	if response.StatusCode != http.StatusOK || reordered.Document.Rules[0].ID != secondID || reordered.Document.Rules[0].Priority != 0 || reordered.Document.Rules[1].ID != ruleID || reordered.Document.Rules[1].Priority != 10 {
		t.Fatalf("reordered response = %+v status=%d", reordered, response.StatusCode)
	}

	simulation, _ := json.Marshal(mailPolicySimulationRequest{Message: mailpolicy.Message{Direction: mailpolicy.DirectionInbound, EnvelopeFrom: "sender@example.test", EnvelopeTo: []string{"user@example.test"}, SizeBytes: 2048, HeaderSubject: "Large"}})
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/simulate", csrf, string(simulation))
	var simulated mailPolicySimulationResponse
	decodeResponse(t, response, &simulated)
	if response.StatusCode != http.StatusOK || !simulated.Decision.Rejected || simulated.Decision.EnhancedStatusCode != "5.3.4" || len(simulated.Result.MatchedRuleIDs()) != 1 {
		t.Fatalf("simulation = %+v status=%d", simulated, response.StatusCode)
	}
	if policies.Stats().Evaluations != 0 {
		t.Fatal("simulation changed live execution counters")
	}
	policies.Evaluate(mailpolicy.Message{Direction: mailpolicy.DirectionInbound, SizeBytes: 2048})
	response = authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/mail-policies", "", "")
	var withStats mailPolicyResponse
	decodeResponse(t, response, &withStats)
	if withStats.Stats.Evaluations != 1 || withStats.Stats.Rejected != 1 || withStats.Stats.RuleMatches[ruleID] != 1 {
		t.Fatalf("runtime stats = %+v", withStats.Stats)
	}

	updatedRule := reordered.Document.Rules[1]
	updatedRule.Name, updatedRule.Enabled = "Updated rule", false
	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/mail-policies/rules/"+ruleID, csrf, policyRuleJSON(t, reordered.Document.Revision, updatedRule))
	var updated mailPolicyResponse
	decodeResponse(t, response, &updated)
	if response.StatusCode != http.StatusOK || updated.Document.Rules[1].Name != "Updated rule" || updated.Document.Rules[1].Enabled || updated.Stats.Evaluations != 0 {
		t.Fatalf("updated response = %+v status=%d", updated, response.StatusCode)
	}

	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/mail-policies/rules/"+ruleID, csrf, policyRuleJSON(t, created.Document.Revision, updatedRule))
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale update status = %d", response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/mail-policies/rules/"+ruleID, csrf, `{"revision":"`+updated.Document.Revision+`"}`)
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusNoContent || len(policies.Document().Rules) != 1 {
		t.Fatalf("delete status=%d document=%+v", response.StatusCode, policies.Document())
	}

	entries, err := audit.New(ts).QueryReverse(t.Context(), time.Time{}, "", "owner", 20)
	if err != nil {
		t.Fatal(err)
	}
	var policyAudits int
	for _, entry := range entries {
		if strings.HasPrefix(entry.Action, "mail_policy.") {
			policyAudits++
		}
	}
	if policyAudits < 4 {
		t.Fatalf("mail policy audit entries = %d", policyAudits)
	}
}

func TestAdminMailPolicyRequiresAdministrator(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	policies, err := mailpolicy.NewService(t.Context(), mailpolicy.NewRepository(ts.Store()))
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureMailPolicies(policies)
	owner := testClient(t)
	setupAndLogin(t, server, owner, "owner")
	if err := ts.UserStore().Create(t.Context(), "reader", "Reader", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "reader"); err != nil {
		t.Fatal(err)
	}
	reader := testClient(t)
	setupAndLogin(t, server, reader, "reader")
	response := authenticatedJSON(t, reader, http.MethodGet, server.URL+"/api/v1/admin/mail-policies", "", "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func TestAdminMailPolicyValidationCSRFAndAvailability(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/mail-policies", "", "")
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured service status = %d", response.StatusCode)
	}
	policies, err := mailpolicy.NewService(t.Context(), mailpolicy.NewRepository(ts.Store()))
	if err != nil {
		t.Fatal(err)
	}
	handler.ConfigureMailPolicies(policies)
	rule := mailpolicy.Rule{ID: "invalid", Name: "Invalid", Enabled: true, Conditions: []mailpolicy.Condition{{Field: mailpolicy.FieldDirection, Operator: "unknown", Value: "inbound"}}, Actions: []mailpolicy.Action{{Type: mailpolicy.ActionAccept}}}
	body := policyRuleJSON(t, policies.Document().Revision, rule)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/rules", "", body)
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", response.StatusCode)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/rules", csrf, body)
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusBadRequest || len(policies.Document().Rules) != 0 {
		t.Fatalf("invalid rule status = %d document=%+v", response.StatusCode, policies.Document())
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/mail-policies/simulate", csrf, `{"message":{"direction":"inbound","header_subject":"`+strings.Repeat("x", 9000)+`"}}`)
	_ = readResponseBody(t, response)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized simulation status = %d", response.StatusCode)
	}
}

func policyRuleJSON(t *testing.T, revision string, rule mailpolicy.Rule) string {
	t.Helper()
	encoded, err := json.Marshal(mailPolicyRuleRequest{Revision: revision, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
