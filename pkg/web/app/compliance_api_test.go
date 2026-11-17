package app

import (
	"archive/zip"
	"bytes"
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
)

// seedComplianceMail stores one message in alice's Inbox.
func seedComplianceMail(t *testing.T, f domainAdminFixture, subject string) model.Item {
	t.Helper()
	if err := f.ts.FolderStore().EnsureForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(f.ts, authz.New(f.ts))
	item, err := space.CreateItem(t.Context(), service.UserAccess("alice", "test"), model.InboxFolderID("alice"), service.ItemInput{
		Data: []byte("From: carol@example.net\r\nTo: alice@a.test\r\nSubject: " + subject + "\r\n\r\nmerger details"), InternalDate: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestLegalHoldBlocksWebDeletionAndAccountDeletion(t *testing.T) {
	f := newDomainAdminFixture(t)
	item := seedComplianceMail(t, f, "evidence")
	alice, aliceTok := loginAs(t, f.server, "alice")

	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/admin/compliance/holds", `{"scope":"account","target":"alice","reason":"x"}`, http.StatusForbidden)
	hold := decodeInto[service.LegalHold](t, f.expect(t, f.owner, f.ownerTok, http.MethodPost, "/api/v1/admin/compliance/holds",
		`{"scope":"account","target":"alice","reason":"Litigation","case_id":"CASE-1","ends_at":"2099-01-01"}`, http.StatusCreated))
	if hold.ID == "" || hold.CaseID != "CASE-1" || hold.EndsAt.IsZero() {
		t.Fatalf("hold = %+v", hold)
	}

	// The user's purge succeeds in the view sense: the item disappears.
	f.expect(t, alice, aliceTok, http.MethodPost, "/api/v1/workspace/items/actions", `{"item_ids":["`+item.ID+`"],"action":"purge"}`, http.StatusOK)
	inbox := decodeInto[[]map[string]any](t, f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/workspace/items?folder_id="+model.InboxFolderID("alice"), "", http.StatusOK))
	if len(inbox) != 0 {
		t.Fatalf("inbox after held purge = %+v", inbox)
	}
	f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/workspace/items?folder_id="+model.HeldDeletedFolderID("alice", model.FolderTypeMail), "", http.StatusNotFound)
	held := decodeInto[struct {
		Items []struct {
			ID              string `json:"id"`
			Subject         string `json:"subject"`
			HeldDeletedFrom string `json:"held_deleted_from"`
		} `json:"items"`
	}](t, f.expect(t, f.owner, f.ownerTok, http.MethodGet, "/api/v1/admin/compliance/held-items?account=alice", "", http.StatusOK))
	if len(held.Items) != 1 || held.Items[0].ID != item.ID || held.Items[0].Subject != "evidence" || held.Items[0].HeldDeletedFrom != "INBOX" {
		t.Fatalf("held items = %+v", held)
	}
	f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/admin/compliance/held-items?account=alice", "", http.StatusForbidden)

	body := string(f.expect(t, f.owner, f.ownerTok, http.MethodDelete, "/api/v1/admin/users/alice", "", http.StatusConflict))
	if !strings.Contains(body, "legal hold") {
		t.Fatalf("account deletion error = %s", body)
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodPost, "/api/v1/admin/compliance/holds/"+hold.ID+"/release", "", http.StatusOK)
	entries, err := audit.New(f.ts).QueryReverse(t.Context(), time.Time{}, "", "owner", 50)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, entry := range entries {
		actions[entry.Action] = true
	}
	if !actions["legal_hold.place"] || !actions["legal_hold.release"] || !actions["legal_hold.held_items.read"] {
		t.Fatalf("audit actions = %v", actions)
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodDelete, "/api/v1/admin/users/alice", "", http.StatusNoContent)
}

func TestDomainAdminComplianceFollowsLiveSettings(t *testing.T) {
	f := newDomainAdminFixture(t)
	hold := `{"scope":"account","target":"alice","reason":"case"}`
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/holds", hold, http.StatusForbidden)
	f.patchConfig(t, `{"legal_hold_domain_admins":true,"retention_min_days":60}`)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/holds", hold, http.StatusCreated)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/holds", `{"scope":"account","target":"bob","reason":"case"}`, http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/holds", `{"scope":"domain","target":"b.test","reason":"case"}`, http.StatusForbidden)

	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/policies", `{"scope":"installation","action":"delete","days":90}`, http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/policies", `{"scope":"domain","target":"b.test","action":"delete","days":90}`, http.StatusForbidden)
	body := string(f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/policies", `{"scope":"domain","target":"a.test","action":"delete","days":30}`, http.StatusBadRequest))
	if !strings.Contains(body, "60 days") {
		t.Fatalf("floor error = %s", body)
	}
	policy := decodeInto[service.RetentionPolicy](t, f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/policies",
		`{"scope":"domain","target":"a.test","special_use":"inbox","action":"archive","days":30}`, http.StatusCreated))
	installation := decodeInto[service.RetentionPolicy](t, f.expect(t, f.owner, f.ownerTok, http.MethodPost, "/api/v1/admin/compliance/policies",
		`{"scope":"installation","action":"delete","days":3650}`, http.StatusCreated))
	f.expect(t, f.dana, f.danaTok, http.MethodDelete, "/api/v1/admin/compliance/policies/"+installation.ID, "", http.StatusForbidden)

	view := decodeInto[struct {
		Scope    string                    `json:"scope"`
		Holds    []service.LegalHold       `json:"holds"`
		Policies []service.RetentionPolicy `json:"policies"`
		CanHold  bool                      `json:"can_hold"`
	}](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/compliance", "", http.StatusOK))
	if view.Scope != "domain" || len(view.Holds) != 1 || len(view.Policies) != 1 || view.Policies[0].ID != policy.ID || !view.CanHold {
		t.Fatalf("domain admin view = %+v", view)
	}

	// Users see the effective policy on folder properties.
	seedComplianceMail(t, f, "x")
	alice, _ := loginAs(t, f.server, "alice")
	retention := decodeInto[struct {
		Policy struct {
			Action string `json:"action"`
			Days   int    `json:"days"`
			Scope  string `json:"scope"`
		} `json:"policy"`
	}](t, f.expect(t, alice, "", http.MethodGet, "/api/v1/workspace/folders/"+model.InboxFolderID("alice")+"/retention", "", http.StatusOK))
	if retention.Policy.Action != "archive" || retention.Policy.Days != 30 || retention.Policy.Scope != "domain" {
		t.Fatalf("inbox retention = %+v", retention)
	}

	// A domain export reaches only the accounts the domain administrator
	// could export one by one: not bob, whose primary identity is in
	// b.test, nor the owner, though both hold an identity in a.test.
	for _, alias := range []struct{ address, user string }{{"bob@a.test", "bob"}, {"postmaster@a.test", "owner"}} {
		if err := f.ts.UserStore().AddEmailAddress(t.Context(), alias.address, alias.user, "a.test", false); err != nil {
			t.Fatal(err)
		}
	}
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/compliance/export?scope=account&target=bob", "", http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/compliance/export?scope=domain&target=a.test", "", http.StatusOK)
	entries, err := audit.New(f.ts).QueryReverse(t.Context(), time.Time{}, "ediscovery.export", "dana", 1)
	if err != nil || len(entries) != 1 || entries[0].Details["accounts"] != "2" {
		t.Fatalf("domain admin export audit = %+v err=%v", entries, err)
	}

	f.patchConfig(t, `{"legal_hold_domain_admins":false}`)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/compliance/holds/"+view.Holds[0].ID+"/release", "", http.StatusForbidden)
}

func TestDiscoveryExportIsAdminOnlyAndAudited(t *testing.T) {
	f := newDomainAdminFixture(t)
	item := seedComplianceMail(t, f, "merger")
	alice, aliceTok := loginAs(t, f.server, "alice")
	path := "/api/v1/admin/compliance/export?scope=account&target=alice&keywords=merger&participants=carol@example.net&since=2000-01-01"
	f.expect(t, alice, aliceTok, http.MethodGet, path, "", http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, path, "", http.StatusForbidden)
	data := f.expect(t, f.owner, f.ownerTok, http.MethodGet, path, "", http.StatusOK)
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest service.DiscoveryManifest
	emls := 0
	for _, file := range reader.File {
		handle, _ := file.Open()
		content, _ := io.ReadAll(handle)
		_ = handle.Close()
		if file.Name == "manifest.json" {
			if err := json.Unmarshal(content, &manifest); err != nil {
				t.Fatal(err)
			}
		} else if strings.HasSuffix(file.Name, ".eml") {
			emls++
		}
	}
	if emls != 1 || len(manifest.Items) != 1 || manifest.Items[0].ItemID != item.ID || manifest.Items[0].SHA256 == "" || manifest.ExportedBy != "owner" {
		t.Fatalf("export: %d eml, manifest %+v", emls, manifest)
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodGet, "/api/v1/admin/compliance/export?scope=domain&target=a.test&held_only=1", "", http.StatusOK)
	entries, err := audit.New(f.ts).QueryReverse(t.Context(), time.Time{}, "ediscovery.export", "owner", 10)
	if err != nil || len(entries) != 2 || entries[1].Details["items"] != "1" || entries[1].Details["result"] != "succeeded" {
		t.Fatalf("export audit = %+v err=%v", entries, err)
	}
}
