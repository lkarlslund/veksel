package app

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestItemHistoryRESTPolicyListRetrieveAndRestore(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	inboxID := model.InboxFolderID("alice")
	policyURL := server.URL + "/api/v1/workspace/folders/" + url.PathEscape(inboxID) + "/history"

	response := authenticatedJSON(t, client, http.MethodPatch, policyURL, csrf, `{"enabled":true,"retention_days":30,"max_versions":5}`)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("configure status=%d body=%s", response.StatusCode, body)
	}
	var folder model.Folder
	if err := json.Unmarshal(body, &folder); err != nil || !folder.History.Enabled || folder.History.MaxVersions != 5 {
		t.Fatalf("configured folder=%+v err=%v", folder, err)
	}

	space := service.NewFolderSpace(ts, authz.New(ts))
	access := service.UserAccess("alice", "test")
	item, err := space.CreateItem(t.Context(), access, inboxID, service.ItemInput{Name: "versioned", Data: []byte("original")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.UpdateItem(t.Context(), access, item.ID, []byte("current"), map[string]string{"Subject": "current"}); err != nil {
		t.Fatal(err)
	}
	versionsURL := server.URL + "/api/v1/workspace/folders/" + url.PathEscape(inboxID) + "/items/" + url.PathEscape(item.ID) + "/versions"
	response, err = client.Get(versionsURL)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Versions []model.ItemVersion `json:"versions"`
		Count    int                 `json:"count"`
	}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || list.Count != 1 || len(list.Versions) != 1 || len(list.Versions[0].Item.Data) != 0 {
		t.Fatalf("list status=%d payload=%+v", response.StatusCode, list)
	}

	versionURL := versionsURL + "/" + url.PathEscape(list.Versions[0].ID)
	response, err = client.Get(versionURL)
	if err != nil {
		t.Fatal(err)
	}
	var version model.ItemVersion
	if err := json.NewDecoder(response.Body).Decode(&version); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(version.Item.Data) != "original" {
		t.Fatalf("version status=%d item=%+v base64=%s", response.StatusCode, version.Item, base64.StdEncoding.EncodeToString(version.Item.Data))
	}

	response = authenticatedJSON(t, client, http.MethodPost, versionURL+"/restore", csrf, `{}`)
	var restored model.Item
	if err := json.NewDecoder(response.Body).Decode(&restored); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(restored.Data) != "original" || restored.ID != item.ID {
		t.Fatalf("restore status=%d item=%+v", response.StatusCode, restored)
	}

	response, err = client.Get(policyURL)
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Accounting struct {
			Versions int64 `json:"versions"`
			Ready    bool  `json:"ready"`
		} `json:"accounting"`
	}
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !status.Accounting.Ready || status.Accounting.Versions != 2 {
		t.Fatalf("policy status=%d payload=%+v", response.StatusCode, status)
	}
}

func TestItemHistoryRESTMutationsRequireCSRF(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	setupAndLogin(t, server, client, "alice")
	endpoint := server.URL + "/api/v1/workspace/folders/" + url.PathEscape(model.InboxFolderID("alice")) + "/history"
	response := authenticatedJSON(t, client, http.MethodPatch, endpoint, "invalid", `{"enabled":true}`)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}
