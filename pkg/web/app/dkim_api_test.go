package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestAdminDKIMLifecycleIsConflictSafeAuditedAndRedacted(t *testing.T) {
	server, ts := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains", csrf, `{"id":"example.test"}`)
	assertDKIMStatus(t, response, http.StatusCreated)

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys", csrf, `{"selector":"next","revision":0}`)
	staged := decodeDKIMResponse(t, response, http.StatusCreated)
	if staged.Revision != 1 || len(staged.Keys) != 1 || staged.Keys[0].Selector != "next" || staged.Keys[0].State != model.DKIMKeyStaged {
		t.Fatalf("staged=%+v", staged)
	}
	if staged.Keys[0].ActivatedAt != nil {
		t.Fatalf("staged key has activation time %v", staged.Keys[0].ActivatedAt)
	}
	if !strings.HasPrefix(staged.Keys[0].DNSRecord, "v=DKIM1; k=rsa; p=") || staged.Keys[0].DNSName != "next._domainkey.example.test" {
		t.Fatalf("DNS projection=%+v", staged.Keys[0])
	}

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/next/activate", csrf, `{"revision":0}`)
	assertDKIMStatus(t, response, http.StatusConflict)
	domain, err := ts.DomainStore().Get(t.Context(), "example.test")
	if err != nil || domain.DKIMRevision != 1 || domain.DkimPrivateKey != "" {
		t.Fatalf("stale activation changed domain=%+v err=%v", domain, err)
	}

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/next/activate", csrf, `{"revision":1}`)
	active := decodeDKIMResponse(t, response, http.StatusOK)
	if active.Revision != 2 || active.Keys[0].State != model.DKIMKeyActive {
		t.Fatalf("active=%+v", active)
	}
	if active.Keys[0].ActivatedAt == nil {
		t.Fatal("active key is missing activation time")
	}
	domain, err = ts.DomainStore().Get(t.Context(), "example.test")
	if err != nil || domain.DkimPrivateKey == "" || domain.DkimSelector != "next" {
		t.Fatalf("persisted active domain=%+v err=%v", domain, err)
	}
	privateMarker := domain.DkimPrivateKey

	response, err = client.Get(server.URL + "/api/v1/admin/domains")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), privateMarker) || strings.Contains(string(body), "dkim_private_key") || strings.Contains(string(body), "dkim_public_key") || strings.Contains(string(body), "dkim_keys") {
		t.Fatalf("domain projection leaked key material: status=%d body=%s", response.StatusCode, body)
	}
	var domains []adminDomainResponse
	if err := json.Unmarshal(body, &domains); err != nil || len(domains) != 1 || !domains[0].DKIMConfigured || domains[0].DKIMSelector != "next" {
		t.Fatalf("domains=%+v err=%v", domains, err)
	}

	response, err = client.Get(server.URL + "/api/v1/admin/domains/example.test/dkim")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), privateMarker) || strings.Contains(string(body), "private_key") {
		t.Fatalf("lifecycle projection leaked private key: status=%d body=%s", response.StatusCode, body)
	}

	response, err = client.Get(server.URL + "/api/v1/admin/audit")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(body), privateMarker) || !strings.Contains(string(body), "domain.dkim.stage") || !strings.Contains(string(body), "domain.dkim.activate") {
		t.Fatalf("audit evidence status=%d body=%s", response.StatusCode, body)
	}
}

func TestAdminDKIMLifecycleOverlapRollbackAndRetirement(t *testing.T) {
	server, _ := testApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains", csrf, `{"id":"example.test"}`)
	assertDKIMStatus(t, response, http.StatusCreated)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys", csrf, `{"selector":"first","revision":0}`)
	assertDKIMStatus(t, response, http.StatusCreated)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/first/activate", csrf, `{"revision":1}`)
	assertDKIMStatus(t, response, http.StatusOK)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys", csrf, `{"selector":"second","revision":2}`)
	assertDKIMStatus(t, response, http.StatusCreated)
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/second/activate", csrf, `{"revision":3}`)
	overlap := decodeDKIMResponse(t, response, http.StatusOK)
	if len(overlap.Keys) != 2 || overlap.Keys[0].State != model.DKIMKeyRetiring || overlap.Keys[1].State != model.DKIMKeyActive {
		t.Fatalf("overlap=%+v", overlap)
	}
	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/first/activate", csrf, `{"revision":4}`)
	rollback := decodeDKIMResponse(t, response, http.StatusOK)
	if rollback.Keys[0].State != model.DKIMKeyActive || rollback.Keys[1].State != model.DKIMKeyRetiring {
		t.Fatalf("rollback=%+v", rollback)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/first", csrf, `{"revision":5}`)
	assertDKIMStatus(t, response, http.StatusConflict)
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/domains/example.test/dkim/keys/second", csrf, `{"revision":5}`)
	retired := decodeDKIMResponse(t, response, http.StatusOK)
	if retired.Revision != 6 || len(retired.Keys) != 1 || retired.Keys[0].Selector != "first" {
		t.Fatalf("retired=%+v", retired)
	}
}

func TestAdminDKIMLifecycleRequiresAdminAndCSRF(t *testing.T) {
	server, ts := testApp(t)
	admin := testClient(t)
	csrf := setupAndLogin(t, server, admin, "owner")
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(t.Context(), "viewer", "Viewer", "password123"); err != nil {
		t.Fatal(err)
	}
	viewer := testClient(t)
	viewerCSRF := loginExistingUser(t, viewer, server.URL, "viewer")

	response, err := admin.Post(server.URL+"/api/v1/admin/domains/example.test/dkim/keys", "application/json", strings.NewReader(`{"selector":"next","revision":0}`))
	if err != nil {
		t.Fatal(err)
	}
	assertDKIMStatus(t, response, http.StatusForbidden)
	response = authenticatedJSON(t, viewer, http.MethodPost, server.URL+"/api/v1/admin/domains/example.test/dkim/keys", viewerCSRF, `{"selector":"next","revision":0}`)
	assertDKIMStatus(t, response, http.StatusForbidden)
	response, err = viewer.Get(server.URL + "/api/v1/admin/domains/example.test/dkim")
	if err != nil {
		t.Fatal(err)
	}
	assertDKIMStatus(t, response, http.StatusForbidden)
	_ = csrf
}

func decodeDKIMResponse(t *testing.T, response *http.Response, wantStatus int) adminDKIMKeysResponse {
	t.Helper()
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != wantStatus {
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, wantStatus, body)
	}
	if strings.Contains(string(body), "PRIVATE KEY") || strings.Contains(string(body), "private_key") {
		t.Fatalf("private key leaked in response: %s", body)
	}
	var decoded adminDKIMKeysResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode response: %v body=%s", err, body)
	}
	return decoded
}

func assertDKIMStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, want, body)
	}
}
