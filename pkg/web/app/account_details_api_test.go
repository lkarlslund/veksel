package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestAdminAccountUsageUsesFolderMetadataAndUpdatesQuota(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	calendar, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("mail"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), calendar.ID, []byte("calendar"), nil); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().Create(t.Context(), "alice", "Projects", model.FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	projects, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Projects")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().Create(t.Context(), "alice", "Projects/Old", model.FolderTypeMail, projects.ID); err != nil {
		t.Fatal(err)
	}
	oldProjects, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Projects/Old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), oldProjects.ID, []byte("archived"), nil); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().Trash(t.Context(), projects.ID, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/users/alice/usage", "", "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("usage status = %d", response.StatusCode)
	}
	var usage adminUserUsage
	if err := json.NewDecoder(response.Body).Decode(&usage); err != nil {
		t.Fatal(err)
	}
	if usage.ActualItems != 3 || usage.ActualBytes != int64(len("mail")+len("calendar")+len("archived")) {
		t.Fatalf("usage totals = %+v", usage)
	}
	if !usage.AccountingReady {
		t.Fatal("new folders should have initialized usage metadata")
	}
	if usage.Status.State != service.QuotaPressureUnlimited {
		t.Fatalf("quota pressure = %+v, want unlimited", usage.Status)
	}
	byType := make(map[model.FolderType]adminUserUsageType, len(usage.ByType))
	for _, entry := range usage.ByType {
		byType[entry.Type] = entry
	}
	if byType[model.FolderTypeMail].Items != 2 || byType[model.FolderTypeMail].Bytes != int64(len("mail")+len("archived")) {
		t.Fatalf("mail usage = %+v", byType[model.FolderTypeMail])
	}
	if byType[model.FolderTypeCalendar].Items != 1 || byType[model.FolderTypeCalendar].Bytes != int64(len("calendar")) {
		t.Fatalf("calendar usage = %+v", byType[model.FolderTypeCalendar])
	}
	if _, present := byType[model.FolderTypeFiles]; !present {
		t.Fatal("zero-usage file type is missing")
	}

	response = authenticatedJSON(t, client, http.MethodPatch, server.URL+"/api/v1/admin/users/alice", csrf,
		`{"display_name":"Alice","enabled":true,"max_storage_bytes":1048576,"max_items":500}`)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("quota update status = %d", response.StatusCode)
	}
	quota, err := ts.UserStore().GetQuota(t.Context(), "alice")
	if err != nil || quota.MaxStorageBytes != 1048576 || quota.MaxItems != 500 {
		t.Fatalf("updated quota = %+v, %v", quota, err)
	}
}
