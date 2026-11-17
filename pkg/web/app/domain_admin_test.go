package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/sendguard"
)

// domainAdminFixture is an installation with an owner, two domains, an
// account in each, and dana, the delegated administrator of a.test.
type domainAdminFixture struct {
	server   *httptest.Server
	ts       *model.TypedStore
	owner    *http.Client
	ownerTok string
	dana     *http.Client
	danaTok  string
	traces   *messagetrace.Store
	queue    *queue.Queue
}

func newDomainAdminFixture(t *testing.T) domainAdminFixture {
	t.Helper()
	handler, ts := testHandler(t)
	traces, err := messagetrace.New(t.Context(), ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	handler.SetMessageTrace(traces)
	mailQueue := queue.New(&queue.Config{ProcessPeriod: time.Hour})
	t.Cleanup(mailQueue.Close)
	handler.SetSystemQueue(mailQueue)
	guard, err := sendguard.New(t.Context(), ts, sendguard.Config{Defaults: sendguard.Limits{MessagesPerHour: 100, RecipientsPerHour: 50, RecipientsPerDay: 500}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guard.Wait)
	handler.ConfigureSendGuard(guard)
	configuration, err := config.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.ConfigureManagedConfiguration(configuration); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	f := domainAdminFixture{server: server, ts: ts, owner: testClient(t), traces: traces, queue: mailQueue}
	f.ownerTok = setupAndLogin(t, server, f.owner, "owner")
	for _, domain := range []string{"a.test", "b.test"} {
		if err := ts.DomainStore().Create(t.Context(), domain); err != nil {
			t.Fatal(err)
		}
	}
	for _, account := range []struct{ id, address string }{{"dana", "dana@a.test"}, {"alice", "alice@a.test"}, {"bob", "bob@b.test"}} {
		if err := ts.UserStore().Create(t.Context(), account.id, account.id, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := ts.UserStore().AddEmailAddress(t.Context(), account.address, account.id, addressDomain(account.address), true); err != nil {
			t.Fatal(err)
		}
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodPost, "/api/v1/admin/domains/a.test/admins", `{"user_id":"dana"}`, http.StatusCreated)
	f.dana, f.danaTok = loginAs(t, server, "dana")
	return f
}

func loginAs(t *testing.T, server *httptest.Server, username string) (*http.Client, string) {
	t.Helper()
	client := testClient(t)
	page, err := client.Get(server.URL + "/app/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = page.Body.Close()
	csrf := csrfCookieValue(t, client, server.URL)
	response, err := client.PostForm(server.URL+"/app/login", url.Values{"_csrf": {csrf}, "username": {username}, "password": {"password123"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return client, csrf
}

// expect performs a JSON request and fails unless it answers status. It
// returns the response body.
func (f domainAdminFixture) expect(t *testing.T, client *http.Client, csrf, method, path, body string, status int) []byte {
	t.Helper()
	response := authenticatedJSON(t, client, method, f.server.URL+path, csrf, body)
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != status {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, response.StatusCode, status, data)
	}
	return data
}

func decodeInto[T any](t *testing.T, data []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return value
}

func TestDomainAdminListingsFilterToItsDomains(t *testing.T) {
	f := newDomainAdminFixture(t)
	users := decodeInto[[]struct {
		ID string `json:"id"`
	}](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/users", "", http.StatusOK))
	ids := map[string]bool{}
	for _, user := range users {
		ids[user.ID] = true
	}
	if !ids["alice"] || !ids["dana"] || ids["bob"] || ids["owner"] {
		t.Fatalf("domain admin sees accounts %v, want only a.test accounts", ids)
	}
	usage := decodeInto[adminAccountUsagePage](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/accounts/usage", "", http.StatusOK))
	if usage.Total != 2 {
		t.Fatalf("domain admin quota inventory = %+v, want the two a.test accounts", usage.Items)
	}
	for _, entry := range usage.Items {
		if entry.Error != "" {
			t.Fatalf("domain admin cannot read %s usage: %s", entry.AccountID, entry.Error)
		}
		if entry.AccountID != "alice" && entry.AccountID != "dana" {
			t.Fatalf("domain admin quota inventory includes %s", entry.AccountID)
		}
	}
	domains := decodeInto[[]adminDomainResponse](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/domains", "", http.StatusOK))
	if len(domains) != 1 || domains[0].ID != "a.test" || domains[0].Usage == nil || domains[0].Usage.Accounts != 2 {
		t.Fatalf("domain admin sees domains %+v", domains)
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodPost, "/api/v1/admin/recipient-aliases", `{"address":"sales@b.test","targets":["bob@b.test"],"enabled":true}`, http.StatusCreated)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/recipient-aliases", `{"address":"team@a.test","targets":["alice@a.test"],"enabled":true}`, http.StatusCreated)
	aliases := decodeInto[[]model.RecipientAlias](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/recipient-aliases", "", http.StatusOK))
	if len(aliases) != 1 || aliases[0].Address != "team@a.test" {
		t.Fatalf("domain admin sees aliases %+v", aliases)
	}

	for _, record := range []messagetrace.Record{
		{QueueID: "trace-a", Direction: "outbound", EnvelopeSender: "alice@a.test", Recipient: "someone@remote.test"},
		{QueueID: "trace-b", Direction: "outbound", EnvelopeSender: "bob@b.test", Recipient: "someone@remote.test"},
		// Inbound mail claiming an a.test sender belongs to b.test.
		{QueueID: "trace-spoof", Direction: "inbound", EnvelopeSender: "ceo@a.test", Recipient: "bob@b.test"},
	} {
		if err := f.traces.Record(t.Context(), record, messagetrace.Event{Time: time.Now().UTC(), Status: "queued"}); err != nil {
			t.Fatal(err)
		}
	}
	page := decodeInto[messagetrace.Page](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/message-trace", "", http.StatusOK))
	if len(page.Records) != 1 || page.Records[0].QueueID != "trace-a" || page.Stats.Records != 0 {
		t.Fatalf("domain admin trace page = %+v", page)
	}
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/message-trace/trace-a", "", http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/message-trace/trace-b", "", http.StatusNotFound)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/message-trace/trace-spoof", "", http.StatusNotFound)
	ownerPage := decodeInto[messagetrace.Page](t, f.expect(t, f.owner, f.ownerTok, http.MethodGet, "/api/v1/admin/message-trace", "", http.StatusOK))
	if len(ownerPage.Records) != 3 {
		t.Fatalf("owner trace page = %+v", ownerPage)
	}

	for _, message := range []*queue.Message{
		{ID: "queue-a", Direction: queue.DirectionOutbound, EnvelopeSender: "alice@a.test", Recipient: "x@remote.test"},
		{ID: "queue-b", Direction: queue.DirectionOutbound, EnvelopeSender: "bob@b.test", Recipient: "x@remote.test"},
	} {
		if err := f.queue.Enqueue(message); err != nil {
			t.Fatal(err)
		}
	}
	queued := decodeInto[[]queue.Message](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/queue", "", http.StatusOK))
	if len(queued) != 1 || queued[0].ID != "queue-a" {
		t.Fatalf("domain admin queue = %+v", queued)
	}
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/queue/queue-b", "", http.StatusNotFound)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/queue/queue-a/hold", "{}", http.StatusForbidden)
}

func TestDomainAdminIsForbiddenOutsideItsDomainsAndSystem(t *testing.T) {
	f := newDomainAdminFixture(t)
	forbidden := []struct{ method, path, body string }{
		{http.MethodPatch, "/api/v1/admin/users/bob", `{"display_name":"Bob"}`},
		{http.MethodDelete, "/api/v1/admin/users/bob", ""},
		{http.MethodGet, "/api/v1/admin/users/bob/identities", ""},
		{http.MethodGet, "/api/v1/admin/users/bob/usage", ""},
		{http.MethodPost, "/api/v1/admin/users/bob/credentials/reset", `{}`},
		{http.MethodDelete, "/api/v1/admin/users/bob/two-factor", ""},
		{http.MethodGet, "/api/v1/admin/users/bob/sending", ""},
		{http.MethodPost, "/api/v1/admin/users", `{"id":"eve","password":"password123","address":"eve@b.test"}`},
		{http.MethodPost, "/api/v1/admin/identities", `{"address":"bob2@b.test","user_id":"bob"}`},
		{http.MethodPost, "/api/v1/admin/identities", `{"address":"alice@b.test","user_id":"alice"}`},
		{http.MethodPost, "/api/v1/admin/identities", `{"address":"bob@a.test","user_id":"bob"}`},
		{http.MethodPatch, "/api/v1/admin/identities/bob@b.test", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/admin/identities/bob@b.test", ""},
		{http.MethodPost, "/api/v1/admin/recipient-aliases", `{"address":"x@b.test","targets":["bob@b.test"],"enabled":true}`},
		{http.MethodPost, "/api/v1/admin/recipient-aliases", `{"address":"x@a.test","targets":["bob@b.test"],"enabled":true}`},
		{http.MethodPatch, "/api/v1/admin/domains/b.test", `{"catch_all":"bob@b.test"}`},
		{http.MethodPatch, "/api/v1/admin/domains/a.test", `{"enabled":false}`},
		{http.MethodPatch, "/api/v1/admin/domains/a.test", `{"catch_all":"bob@b.test"}`},
		{http.MethodGet, "/api/v1/admin/domains/b.test/dns", ""},
		{http.MethodGet, "/api/v1/admin/domains/b.test/dkim", ""},
		// System endpoints and administration of the domain itself.
		{http.MethodPost, "/api/v1/admin/domains", `{"id":"c.test"}`},
		{http.MethodDelete, "/api/v1/admin/domains/a.test", ""},
		{http.MethodPost, "/api/v1/admin/domains/a.test/dkim/keys", `{}`},
		{http.MethodPut, "/api/v1/admin/domains/a.test/limits", `{"max_accounts":100}`},
		{http.MethodGet, "/api/v1/admin/domains/a.test/admins", ""},
		{http.MethodPost, "/api/v1/admin/domains/a.test/admins", `{"user_id":"alice"}`},
		{http.MethodGet, "/api/v1/admin/settings", ""},
		{http.MethodPatch, "/api/v1/admin/settings", `{"settings":{}}`},
		{http.MethodGet, "/api/v1/admin/certificates", ""},
		{http.MethodGet, "/api/v1/admin/routes", ""},
		{http.MethodGet, "/api/v1/admin/audit", ""},
		{http.MethodGet, "/api/v1/admin/health", ""},
		{http.MethodGet, "/api/v1/admin/account-storage", ""},
		{http.MethodGet, "/api/v1/admin/message-trace/status", ""},
		{http.MethodGet, "/api/v1/admin/outbound/holds", ""},
		{http.MethodPost, "/api/v1/admin/users/provision", `{}`},
	}
	for _, request := range forbidden {
		f.expect(t, f.dana, f.danaTok, request.method, request.path, request.body, http.StatusForbidden)
	}
	// The owner's account holds system administration, so it is out of
	// reach even with its primary identity inside dana's domain.
	if err := f.ts.UserStore().AddEmailAddress(t.Context(), "owner@a.test", "owner", "a.test", true); err != nil {
		t.Fatal(err)
	}
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users/owner/credentials/reset", `{}`, http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/owner", `{"enabled":false}`, http.StatusForbidden)

	for path, status := range map[string]int{
		"/app/admin/settings": http.StatusForbidden, "/app/admin/certificates": http.StatusForbidden,
		"/app/admin/operations/queue": http.StatusForbidden, "/app/admin/protocols/smtp": http.StatusForbidden,
		"/app/admin/domains": http.StatusOK, "/app/admin/accounts": http.StatusOK, "/app/admin/recipients": http.StatusOK,
		"/app/admin/operations/trace": http.StatusOK,
	} {
		response, err := f.dana.Get(f.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("GET %s = %d, want %d", path, response.StatusCode, status)
		}
		if !strings.Contains(string(body), `data-admin-scope="domain"`) || strings.Contains(string(body), `href="/app/admin/settings"`) {
			t.Fatalf("GET %s does not render the domain-scoped administration", path)
		}
		// System-only pages render the in-app role notice, not a bare error page.
		if denied := strings.Contains(string(body), `data-denied="true"`); denied != (status == http.StatusForbidden) {
			t.Fatalf("GET %s denied view = %v, status %d", path, denied, status)
		}
	}
	// Ordinary users still get a plain refusal.
	alice, _ := loginAs(t, f.server, "alice")
	if response, err := alice.Get(f.server.URL + "/app/admin/settings"); err != nil {
		t.Fatal(err)
	} else if body, _ := io.ReadAll(response.Body); response.StatusCode != http.StatusForbidden || strings.Contains(string(body), "admin-control-plane") {
		t.Fatalf("ordinary user admin page = %d", response.StatusCode)
	}
	response, err := f.dana.Get(f.server.URL + "/app/admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.Request.URL.Path != "/app/admin/domains" {
		t.Fatalf("/app/admin landed on %s, want the domain list", response.Request.URL.Path)
	}
}

func TestDomainAdminManagesItsDomainAndIsAudited(t *testing.T) {
	f := newDomainAdminFixture(t)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"display_name":"Alice A"}`, http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users", `{"id":"carol","password":"password123"}`, http.StatusBadRequest)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users", `{"id":"carol","display_name":"Carol","password":"password123","address":"carol@a.test"}`, http.StatusCreated)
	if identity, err := f.ts.UserStore().GetEmailAddress(t.Context(), "carol@a.test"); err != nil || identity.UserID != "carol" || !identity.Primary {
		t.Fatalf("created account identity = %+v, %v", identity, err)
	}
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/identities", `{"address":"ali@a.test","user_id":"alice"}`, http.StatusCreated)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/identities/ali@a.test", `{"enabled":false}`, http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodDelete, "/api/v1/admin/identities/ali@a.test", "", http.StatusNoContent)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/domains/a.test", `{"catch_all":"alice@a.test"}`, http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/domains/a.test/dns", "", http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/domains/a.test/dkim", "", http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/users/alice/usage", "", http.StatusOK)
	reset := decodeInto[credentialReset](t, f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users/alice/credentials/reset", `{}`, http.StatusOK))
	if !reset.PasswordReset || reset.GeneratedPassword == "" {
		t.Fatalf("credential reset = %+v", reset)
	}
	f.expect(t, f.dana, f.danaTok, http.MethodDelete, "/api/v1/admin/users/alice/two-factor", "", http.StatusNoContent)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/carol", `{"enabled":false}`, http.StatusOK)
	f.expect(t, f.dana, f.danaTok, http.MethodDelete, "/api/v1/admin/users/carol", "", http.StatusNoContent)

	entries, err := audit.New(f.ts).QueryReverse(t.Context(), time.Time{}, "", "dana", 100)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, entry := range entries {
		if entry.Details["admin_scope"] != "domain:a.test" {
			t.Fatalf("delegated audit entry lacks its domain scope: %+v", entry)
		}
		actions[entry.Action] = true
	}
	for _, action := range []string{"account.update", "account.create", "account.delete", "identity.create", "identity.update", "identity.delete", "domain.update", "account.credentials.reset", "account.two_factor.reset"} {
		if !actions[action] {
			t.Fatalf("audit lacks %s by dana: %v", action, actions)
		}
	}

	admins := decodeInto[[]domainAdministrator](t, f.expect(t, f.owner, f.ownerTok, http.MethodGet, "/api/v1/admin/domains/a.test/admins", "", http.StatusOK))
	if len(admins) != 1 || admins[0].UserID != "dana" || admins[0].GrantedBy != "owner" {
		t.Fatalf("domain administrators = %+v", admins)
	}
	f.expect(t, f.owner, f.ownerTok, http.MethodDelete, "/api/v1/admin/domains/a.test/admins/dana", "", http.StatusNoContent)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/users", "", http.StatusForbidden)
}

func TestDomainLimitsAreEnforcedOnCreateAndUpdate(t *testing.T) {
	f := newDomainAdminFixture(t)
	f.expect(t, f.owner, f.ownerTok, http.MethodPut, "/api/v1/admin/domains/a.test/limits", `{"default_account_storage_bytes":2000,"max_account_storage_bytes":1000}`, http.StatusBadRequest)
	// dana and alice already count: two of three accounts, both unlimited.
	f.expect(t, f.owner, f.ownerTok, http.MethodPatch, "/api/v1/admin/users/dana", `{"max_storage_bytes":500}`, http.StatusOK)
	f.expect(t, f.owner, f.ownerTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"max_storage_bytes":500}`, http.StatusOK)
	f.expect(t, f.owner, f.ownerTok, http.MethodPut, "/api/v1/admin/domains/a.test/limits",
		`{"max_accounts":3,"max_aliases":1,"max_storage_bytes":3000,"default_account_storage_bytes":1000,"max_account_storage_bytes":1500,"default_send_limits":{"recipients_per_hour":10}}`, http.StatusOK)

	created := decodeInto[map[string]any](t, f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users", `{"id":"carol","password":"password123","address":"carol@a.test"}`, http.StatusCreated))
	if created["max_storage_bytes"] != float64(1000) {
		t.Fatalf("new account did not receive the domain default quota: %+v", created)
	}
	body := string(f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users", `{"id":"dave","password":"password123","address":"dave@a.test"}`, http.StatusConflict))
	if !strings.Contains(body, "at most 3 accounts") {
		t.Fatalf("account limit error = %s", body)
	}
	if _, err := f.ts.UserStore().Get(t.Context(), "dave"); err == nil {
		t.Fatal("rejected account was created")
	}
	// Assigned: 500 + 500 + 1000 = 2000 of 3000.
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"max_storage_bytes":2000}`, http.StatusConflict)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"max_storage_bytes":0}`, http.StatusConflict)
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"max_storage_bytes":1500}`, http.StatusOK)
	// The system administrator is not bound by the per-account maximum,
	// but the domain storage ceiling binds everyone: 500 + 1000 + 1600.
	f.expect(t, f.owner, f.ownerTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"max_storage_bytes":1600}`, http.StatusConflict)
	f.expect(t, f.owner, f.ownerTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"max_storage_bytes":1400}`, http.StatusOK)

	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/identities", `{"address":"ali@a.test","user_id":"alice"}`, http.StatusCreated)
	f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/recipient-aliases", `{"address":"team@a.test","targets":["alice@a.test"],"enabled":true}`, http.StatusConflict)
	f.expect(t, f.owner, f.ownerTok, http.MethodPost, "/api/v1/admin/identities", `{"address":"al@a.test","user_id":"alice"}`, http.StatusConflict)

	// Domain default send limits feed the guard and cap dana's overrides.
	status := decodeInto[sendguard.AccountStatus](t, f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/users/alice/sending", "", http.StatusOK))
	if status.Defaults.RecipientsPerHour != 10 || status.Defaults.MessagesPerHour != 100 {
		t.Fatalf("inherited send limits = %+v", status.Defaults)
	}
	f.expect(t, f.dana, f.danaTok, http.MethodPut, "/api/v1/admin/users/alice/sending/limits", `{"recipients_per_hour":20}`, http.StatusConflict)
	f.expect(t, f.dana, f.danaTok, http.MethodPut, "/api/v1/admin/users/alice/sending/limits", `{"recipients_per_hour":0}`, http.StatusConflict)
	f.expect(t, f.dana, f.danaTok, http.MethodPut, "/api/v1/admin/users/alice/sending/limits", `{"recipients_per_hour":5}`, http.StatusOK)
	f.expect(t, f.owner, f.ownerTok, http.MethodPut, "/api/v1/admin/users/alice/sending/limits", `{"recipients_per_hour":20}`, http.StatusOK)

	domains := decodeInto[[]adminDomainResponse](t, f.expect(t, f.owner, f.ownerTok, http.MethodGet, "/api/v1/admin/domains", "", http.StatusOK))
	for _, domain := range domains {
		if domain.ID == "a.test" && (domain.Limits.MaxAccounts != 3 || domain.Usage == nil || domain.Usage.Accounts != 3 || domain.Usage.Aliases != 1 || domain.Usage.AssignedStorageBytes != 2900) {
			t.Fatalf("a.test limits and usage = %+v %+v", domain.Limits, domain.Usage)
		}
	}
}

func TestDomainAdminCannotManageAccountsWithCustomSystemRoles(t *testing.T) {
	f := newDomainAdminFixture(t)
	if err := model.NewRoleStore(f.ts).Set(t.Context(), model.Role{ID: "trace.operator", Name: "Trace operator", ResourceKinds: []model.ResourceKind{model.ResourceSystem}, Permissions: []string{string(authz.DomainTraceRead)}}); err != nil {
		t.Fatal(err)
	}
	policies := model.NewPolicyStore(f.ts)
	system := model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}
	// olga holds a custom system role directly, and gus through a group;
	// both have their primary identity in dana's domain. Resetting either
	// would hand dana installation-wide trace access.
	for _, account := range []string{"olga", "gus"} {
		if err := f.ts.UserStore().Create(t.Context(), account, account, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := f.ts.UserStore().AddEmailAddress(t.Context(), account+"@a.test", account, "a.test", true); err != nil {
			t.Fatal(err)
		}
	}
	if err := model.NewGroupStore(f.ts).Set(t.Context(), model.Group{ID: "operators", Name: "Operators", Members: []string{"gus"}}); err != nil {
		t.Fatal(err)
	}
	for _, principal := range []model.PrincipalRef{{Kind: model.PrincipalUser, ID: "olga"}, {Kind: model.PrincipalGroup, ID: "operators"}} {
		if _, err := policies.Create(t.Context(), model.PolicyBinding{Principal: principal, Resource: system, Effect: model.EffectAllow, RoleID: "trace.operator", Inheritance: model.InheritanceSubtree, GrantedBy: "owner"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, account := range []string{"olga", "gus"} {
		f.expect(t, f.dana, f.danaTok, http.MethodPost, "/api/v1/admin/users/"+account+"/credentials/reset", `{}`, http.StatusForbidden)
		f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/"+account, `{"display_name":"Renamed"}`, http.StatusForbidden)
	}
	// An ordinary member of the domain stays manageable.
	f.expect(t, f.dana, f.danaTok, http.MethodPatch, "/api/v1/admin/users/alice", `{"display_name":"Alice A"}`, http.StatusOK)
	// Delegated eDiscovery does not reach them either.
	f.patchConfig(t, `{"legal_hold_domain_admins":true}`)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/compliance/export?scope=account&target=olga", "", http.StatusForbidden)
	f.expect(t, f.dana, f.danaTok, http.MethodGet, "/api/v1/admin/compliance/export?scope=account&target=alice", "", http.StatusOK)
}

func TestSystemAdminRoleAdministersWithoutOwnerAuthority(t *testing.T) {
	f := newDomainAdminFixture(t)
	if err := f.ts.UserStore().Create(t.Context(), "sam", "Sam", "password123"); err != nil {
		t.Fatal(err)
	}
	if _, err := model.NewPolicyStore(f.ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "sam"}, Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
		Effect: model.EffectAllow, RoleID: authz.RoleSystemAdmin, Inheritance: model.InheritanceSubtree, GrantedBy: "owner",
	}); err != nil {
		t.Fatal(err)
	}
	sam, tok := loginAs(t, f.server, "sam")
	f.expect(t, sam, tok, http.MethodGet, "/api/v1/admin/settings", "", http.StatusOK)
	f.expect(t, sam, tok, http.MethodGet, "/api/v1/admin/users", "", http.StatusOK)
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/users/bob", `{"display_name":"Bob B"}`, http.StatusOK)
	f.expect(t, sam, tok, http.MethodPut, "/api/v1/admin/domains/b.test/limits", `{"max_accounts":10}`, http.StatusOK)
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/admin/domains/b.test/admins", `{"user_id":"bob"}`, http.StatusCreated)
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/settings", `{"settings":{"ldap_admin_role":"owner"}}`, http.StatusForbidden)
	// The directory server and its trust decide who becomes an owner too.
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/settings", `{"settings":{"ldap_urls":"ldap://attacker.example"}}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/settings", `{"settings":{"ldap_bind_dn":"cn=x"}}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/settings", `{"settings":{"ldap_timeout_seconds":7}}`, http.StatusOK)
	// Archives hold the configuration secrets and owner data.
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/admin/backup/download?scope=system", ``, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/admin/backup/download", ``, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodGet, "/api/v1/admin/backup/archives/veksel-backup-x.tar", ``, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodGet, "/api/v1/admin/compliance/export?scope=account&target=owner", ``, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/admin/compliance/holds", `{"scope":"account","target":"owner","reason":"x"}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/config", `{}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/admin/backup/restore", `{}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/admin/users/owner/credentials/reset", `{}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPatch, "/api/v1/admin/users/owner", `{"enabled":false}`, http.StatusForbidden)
	f.expect(t, sam, tok, http.MethodPost, "/api/v1/roles", `{"id":"escalate","name":"Escalate","resource_kinds":["system"],"permissions":["*"]}`, http.StatusForbidden)
	f.expect(t, f.owner, f.ownerTok, http.MethodPatch, "/api/v1/admin/settings", `{"settings":{"ldap_admin_role":"admin"}}`, http.StatusOK)
	response, err := sam.Get(f.server.URL + "/app/admin/settings")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-admin-scope="system"`) {
		t.Fatalf("system admin settings page = %d", response.StatusCode)
	}
}
