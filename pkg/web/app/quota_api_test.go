package app

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestAccountUsageAndAdminPressureInventory(t *testing.T) {
	server, ts := testApp(t)
	admin := testClient(t)
	setupAndLogin(t, server, admin, "alice")
	createQuotaAccount := func(id string, used, limit int) {
		t.Helper()
		if id != "alice" {
			if err := ts.UserStore().Create(t.Context(), id, "Account "+id, "password123"); err != nil {
				t.Fatal(err)
			}
			if err := ts.FolderStore().CreateForUser(t.Context(), id); err != nil {
				t.Fatal(err)
			}
		}
		if err := ts.UserStore().UpdateQuota(t.Context(), id, 0, limit); err != nil {
			t.Fatal(err)
		}
		for range used {
			if _, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID(id), []byte("x"), nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	createQuotaAccount("alice", 8, 10)
	createQuotaAccount("bob", 9, 10)
	createQuotaAccount("charlie", 10, 10)
	createQuotaAccount("dave", 0, 0)

	response := authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/account/usage", "", "")
	var own accountUsageResponse
	if err := json.NewDecoder(response.Body).Decode(&own); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || own.Usage.AccountID != "alice" || own.Usage.Items != 8 || own.Status.State != service.QuotaPressureWarning || own.Status.Percent != 80 {
		t.Fatalf("self usage status=%d response=%+v", response.StatusCode, own)
	}

	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/accounts/usage?state=warning&sort=percent&direction=desc&page_size=1&page=1", "", "")
	var first adminAccountUsagePage
	if err := json.NewDecoder(response.Body).Decode(&first); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || first.Total != 2 || first.TotalPages != 2 || len(first.Items) != 1 || first.Items[0].AccountID != "bob" || first.StateCounts[service.QuotaPressureExceeded] != 1 || first.StateCounts[service.QuotaPressureUnlimited] != 1 {
		t.Fatalf("first pressure page status=%d response=%+v", response.StatusCode, first)
	}
	response = authenticatedJSON(t, admin, http.MethodGet, server.URL+"/api/v1/admin/accounts/usage?state=warning&sort=percent&direction=desc&page_size=1&page=2", "", "")
	var second adminAccountUsagePage
	if err := json.NewDecoder(response.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(second.Items) != 1 || second.Items[0].AccountID != "alice" {
		t.Fatalf("second pressure page = %+v", second)
	}

	bob := testClient(t)
	loginExistingUser(t, bob, server.URL, "bob")
	response = authenticatedJSON(t, bob, http.MethodGet, server.URL+"/api/v1/admin/accounts/usage", "", "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin pressure inventory status = %d", response.StatusCode)
	}
}

func TestAdminPressureInventoryValidatesQuery(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	for _, query := range []string{"page=0", "page_size=101", "state=panic", "sort=size", "direction=sideways"} {
		response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/accounts/usage?"+query, "", "")
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("query %q status = %d, want 400", query, response.StatusCode)
		}
	}
}
