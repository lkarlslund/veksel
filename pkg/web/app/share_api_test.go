package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/sharing"
)

func TestShareLinkHTTPLifecycleIsScopedAndSecretSafe(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	space := service.NewFolderSpace(ts, authz.New(ts))
	inbox, err := space.GetFolder(t.Context(), service.UserAccess("alice", "test"), model.InboxFolderID("alice"))
	if err != nil {
		t.Fatal(err)
	}
	item, err := space.CreateItem(t.Context(), service.UserAccess("alice", "test"), inbox.ID, service.ItemInput{Name: "shared.txt", Data: []byte("shared body"), Headers: map[string]string{"Content-Type": "text/plain"}})
	if err != nil {
		t.Fatal(err)
	}

	withoutCSRF := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/share-links", "", `{"target_kind":"item","item_id":"`+item.ID+`","access":"read"}`)
	if withoutCSRF.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(withoutCSRF.Body)
		_ = withoutCSRF.Body.Close()
		t.Fatalf("create without CSRF status=%d body=%s", withoutCSRF.StatusCode, body)
	}
	_ = withoutCSRF.Body.Close()

	createdResponse := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/share-links", csrf, `{"target_kind":"item","item_id":"`+item.ID+`","access":"read","max_uses":3}`)
	var created struct {
		Link  sharing.Link `json:"link"`
		Token string       `json:"token"`
		Path  string       `json:"path"`
	}
	decodeResponse(t, createdResponse, &created)
	if createdResponse.StatusCode != http.StatusCreated || created.Link.ItemID != item.ID || created.Token == "" || created.Path != "/share/#"+created.Token {
		t.Fatalf("created status=%d payload=%+v", createdResponse.StatusCode, created)
	}

	listResponse, err := client.Get(server.URL + "/api/v1/share-links")
	if err != nil {
		t.Fatal(err)
	}
	listBody, _ := io.ReadAll(listResponse.Body)
	_ = listResponse.Body.Close()
	if listResponse.StatusCode != http.StatusOK || strings.Contains(string(listBody), created.Token) || strings.Contains(string(listBody), "secret_hash") {
		t.Fatalf("management list status=%d leaked secret or omitted link: %s", listResponse.StatusCode, listBody)
	}
	var links []sharing.Link
	if err := json.Unmarshal(listBody, &links); err != nil || len(links) != 1 || links[0].ID != created.Link.ID {
		t.Fatalf("management links=%+v err=%v", links, err)
	}

	pageResponse, err := http.Get(server.URL + "/share/")
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(pageResponse.Body)
	_ = pageResponse.Body.Close()
	if pageResponse.StatusCode != http.StatusOK || !strings.Contains(string(pageBody), "Veksel secure sharing") || pageResponse.Header.Get("Cache-Control") != "no-store" || pageResponse.Header.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(pageResponse.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("public page status=%d headers=%v body=%s", pageResponse.StatusCode, pageResponse.Header, pageBody)
	}

	resourceResponse := publicShareRequest(t, http.MethodGet, server.URL+"/api/v1/public/share?limit=10", created.Token, "")
	resourceBody, _ := io.ReadAll(resourceResponse.Body)
	_ = resourceResponse.Body.Close()
	var resource sharing.Resource
	if err := json.Unmarshal(resourceBody, &resource); err != nil {
		t.Fatal(err)
	}
	if resourceResponse.StatusCode != http.StatusOK || resource.Item == nil || resource.Item.ID != item.ID || string(resource.Item.Data) != "shared body" || resource.Remaining == nil || *resource.Remaining != 2 {
		t.Fatalf("public resource status=%d resource=%+v", resourceResponse.StatusCode, resource)
	}
	for _, privateField := range []string{`"created_by"`, `"target_owner_id"`, `"folder_id"`, `"parent_id"`, `"uid_validity"`} {
		if strings.Contains(string(resourceBody), privateField) {
			t.Fatalf("public resource leaked private field %s: %s", privateField, resourceBody)
		}
	}

	readOnlyResponse := publicShareRequest(t, http.MethodPut, server.URL+"/api/v1/public/share/items/"+item.ID, created.Token, `{"data":"YmxvY2tlZA=="}`)
	if readOnlyResponse.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(readOnlyResponse.Body)
		_ = readOnlyResponse.Body.Close()
		t.Fatalf("read-only mutation status=%d body=%s", readOnlyResponse.StatusCode, body)
	}
	_ = readOnlyResponse.Body.Close()
	managedResponse, err := client.Get(server.URL + "/api/v1/share-links/" + created.Link.ID)
	if err != nil {
		t.Fatal(err)
	}
	var managed sharing.Link
	decodeResponse(t, managedResponse, &managed)
	if managed.UseCount != 1 {
		t.Fatalf("rejected mutation consumed use: %+v", managed)
	}

	revokeResponse := authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/share-links/"+created.Link.ID, csrf, "")
	_ = revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status=%d", revokeResponse.StatusCode)
	}
	closedResponse := publicShareRequest(t, http.MethodGet, server.URL+"/api/v1/public/share", created.Token, "")
	_ = closedResponse.Body.Close()
	if closedResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked public status=%d", closedResponse.StatusCode)
	}
	for _, check := range []struct {
		action, actor string
	}{
		{action: "share.link.create", actor: "alice"},
		{action: "share.link.use", actor: "capability:" + created.Link.ID},
		{action: "share.link.revoke", actor: "alice"},
	} {
		entries, err := audit.New(ts).QueryReverse(t.Context(), time.Time{}, check.action, check.actor, 10)
		if err != nil || len(entries) != 1 || entries[0].Target != created.Link.ID {
			t.Fatalf("audit %s/%s entries=%+v err=%v", check.action, check.actor, entries, err)
		}
	}

	unauthenticated, err := http.Get(server.URL + "/api/v1/share-links")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated management status=%d", unauthenticated.StatusCode)
	}
}

func TestPublicShareRejectsMalformedRequestsWithoutDisclosure(t *testing.T) {
	server, _ := testApp(t)
	for _, test := range []struct {
		name, endpoint, token string
		want                  int
	}{
		{name: "missing token", endpoint: "/api/v1/public/share", want: http.StatusNotFound},
		{name: "invalid token", endpoint: "/api/v1/public/share", token: "v1.invalid.secret", want: http.StatusNotFound},
		{name: "invalid page", endpoint: "/api/v1/public/share?limit=101", token: "irrelevant", want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := publicShareRequest(t, http.MethodGet, server.URL+test.endpoint, test.token, "")
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode != test.want || response.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), "jsonstore") {
				t.Fatalf("status=%d want=%d headers=%v body=%s", response.StatusCode, test.want, response.Header, body)
			}
		})
	}
}

func publicShareRequest(t *testing.T, method, endpoint, token, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Share "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
