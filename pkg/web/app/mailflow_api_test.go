package app

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestAdminMailFlowRulesSealCredentialsAndAudit(t *testing.T) {
	server, ts, _, _, handler := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	base := server.URL + "/api/v1/admin/mail-flow"
	call := func(method, path, body string, want int, target any) {
		t.Helper()
		response := authenticatedJSON(t, client, method, base+path, csrf, body)
		if response.StatusCode != want {
			t.Fatalf("%s %s = %d: %s", method, path, response.StatusCode, readResponseBody(t, response))
		}
		if target != nil {
			decodeResponse(t, response, target)
		} else {
			_ = readResponseBody(t, response)
		}
	}

	var route senderRouteView
	call(http.MethodPost, "/sender-routes", `{"sender":"example.test","transport":"relay","relay_host":"smtp.provider.test","relay_port":587,"username":"smarthost","password":"s3cret","require_tls":true,"enabled":true}`, http.StatusCreated, &route)
	if route.ID == "" || !route.HasPassword || route.SealedPassword != nil || route.Sender != "@example.test" {
		t.Fatalf("created route = %+v", route)
	}
	stored, err := ts.SenderRouteStore().Get(t.Context(), route.ID)
	if err != nil || len(stored.SealedPassword) == 0 || strings.Contains(string(stored.SealedPassword), "s3cret") {
		t.Fatalf("stored route credential = %q, %v", stored.SealedPassword, err)
	}
	if opened, err := handler.SecretSealer().OpenSecret(model.SenderRouteSecretPurpose, route.ID, stored.SealedPassword); err != nil || string(opened) != "s3cret" {
		t.Fatalf("opened credential = %q, %v", opened, err)
	}
	// An update without a password keeps it; an empty one removes it.
	call(http.MethodPut, "/sender-routes/"+route.ID, `{"sender":"example.test","destination":"partner.test","transport":"relay","relay_host":"smtp.provider.test","relay_port":587,"username":"smarthost","enabled":true}`, http.StatusOK, &route)
	if !route.HasPassword || route.Destination != "partner.test" {
		t.Fatalf("updated route = %+v", route)
	}
	call(http.MethodPut, "/sender-routes/"+route.ID, `{"sender":"example.test","transport":"relay","relay_host":"smtp.provider.test","password":"","enabled":true}`, http.StatusOK, &route)
	if route.HasPassword {
		t.Fatalf("password not removed: %+v", route)
	}

	var rewrite model.AddressRewrite
	call(http.MethodPost, "/rewrites", `{"direction":"outbound","pattern":"internal.example","replacement":"example.test","envelope_sender":true,"header_from":true,"enabled":true}`, http.StatusCreated, &rewrite)
	call(http.MethodPost, "/rewrites", `{"direction":"outbound","pattern":"example.test","replacement":"public.example","envelope_sender":true}`, http.StatusBadRequest, nil)
	var journal model.JournalRule
	call(http.MethodPost, "/journal", `{"inbound":true,"outbound":true,"address":"journal@example.test","enabled":true}`, http.StatusCreated, &journal)
	var bcc model.BCCRule
	call(http.MethodPost, "/bcc", `{"match":"recipient","pattern":"ceo@example.test","address":"assistant@example.test","enabled":true}`, http.StatusCreated, &bcc)
	call(http.MethodPost, "/unknown", `{}`, http.StatusNotFound, nil)

	var listed map[string][]map[string]any
	call(http.MethodGet, "", "", http.StatusOK, &listed)
	if len(listed["sender-routes"]) != 1 || len(listed["rewrites"]) != 1 || len(listed["journal"]) != 1 || len(listed["bcc"]) != 1 {
		t.Fatalf("listed = %v", listed)
	}
	if _, leaked := listed["sender-routes"][0]["sealed_password"]; leaked {
		t.Fatalf("listing leaks the sealed password: %v", listed["sender-routes"][0])
	}
	call(http.MethodDelete, "/bcc/"+bcc.ID, "", http.StatusNoContent, nil)
	call(http.MethodDelete, "/bcc/"+bcc.ID, "", http.StatusNotFound, nil)

	entries, err := audit.New(ts).Query(t.Context(), route.CreatedAt.Add(-1), "", "owner", 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.Action] = true
		if strings.Contains(strings.Join(slices.Collect(maps.Values(entry.Details)), " "), "s3cret") {
			t.Fatalf("audit entry leaks the password: %+v", entry)
		}
	}
	for _, action := range []string{"mail_flow.sender-routes.create", "mail_flow.sender-routes.update", "mail_flow.rewrites.create", "mail_flow.journal.create", "mail_flow.bcc.create", "mail_flow.bcc.delete"} {
		if !seen[action] {
			t.Fatalf("audit lacks %s: %v", action, seen)
		}
	}
}
