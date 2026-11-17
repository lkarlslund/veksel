package app

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/dnsprovider/dnsprovidertest"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestDNSPublishDiffApplyAndDKIMRotationHooks(t *testing.T) {
	handler, _ := testHandler(t)
	cfg := config.Default()
	cfg.SmtpServerName = "mail.example.test"
	handler.ConfigureAdministration(cfg, nil)
	// No resolver answers, so SPF cannot be shown to authorize the server.
	handler.SetDNSResolver(fakeDNSResolver{mx: map[string][]*net.MX{}, txt: map[string][]string{}, host: map[string][]string{}, addr: map[string][]string{}})
	memory := &dnsprovidertest.Memory{}
	var openedSecret string
	handler.DNSZones().SetFactory(func(_ model.DNSZone, secret string) (dnsprovider.Provider, error) {
		openedSecret = secret
		return memory, nil
	})
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	call := func(method, path, body string, want int, target any) string {
		t.Helper()
		response := authenticatedJSON(t, client, method, server.URL+path, csrf, body)
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, response.StatusCode, want, raw)
		}
		if target != nil {
			if err := json.Unmarshal(raw, target); err != nil {
				t.Fatal(err)
			}
		}
		return string(raw)
	}

	call(http.MethodPost, "/api/v1/admin/domains", `{"id":"example.test"}`, http.StatusCreated, nil)
	call(http.MethodGet, "/api/v1/admin/domains/example.test/dns/publish", "", http.StatusConflict, nil)
	body := call(http.MethodPut, "/api/v1/admin/dns/zones/example.test", `{"provider":"cloudflare","settings":{"zone_id":"z1"},"secret":"cf-token-secret"}`, http.StatusOK, nil)
	listed := call(http.MethodGet, "/api/v1/admin/dns/zones", "", http.StatusOK, nil)
	if strings.Contains(body+listed, "cf-token-secret") || !strings.Contains(listed, `"secret_set":true`) {
		t.Fatalf("zone API must redact the credential: %s %s", body, listed)
	}
	var guidance dnsGuidanceResponse
	call(http.MethodGet, "/api/v1/admin/domains/example.test/dns", "", http.StatusOK, &guidance)
	if guidance.Provider == nil || guidance.Provider.Zone != "example.test" {
		t.Fatalf("guidance does not report the provider: %+v", guidance.Provider)
	}

	// Staging a key publishes its selector automatically.
	var keys adminDKIMKeysResponse
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dkim/keys", `{"selector":"s1","revision":0}`, http.StatusCreated, &keys)
	if keys.DNSPublish == nil || keys.DNSPublish.Error != "" || len(memory.Values("TXT", "s1._domainkey.example.test")) != 1 || openedSecret != "cf-token-secret" {
		t.Fatalf("staged key was not published: %+v %v", keys.DNSPublish, memory.Values("TXT", "s1._domainkey.example.test"))
	}

	memory.Add("TXT", "example.test", "v=spf1 include:elsewhere.test -all")
	var plan dnsPublishResponse
	call(http.MethodGet, "/api/v1/admin/domains/example.test/dns/publish", "", http.StatusOK, &plan)
	actions := map[string]string{}
	for _, change := range plan.Changes {
		actions[change.Type+" "+change.Name] = change.Action
	}
	want := map[string]string{"MX example.test": "create", "TXT example.test": "conflict", "TXT _dmarc.example.test": "create", "TXT s1._domainkey.example.test": "unchanged"}
	for key, action := range want {
		if actions[key] != action {
			t.Errorf("%s: %s, want %s (%v)", key, actions[key], action, actions)
		}
	}
	if len(memory.Values("MX", "example.test")) != 0 {
		t.Fatal("the plan changed DNS")
	}
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dns/publish", `{}`, http.StatusOK, &plan)
	if got := memory.Values("TXT", "example.test"); len(got) != 1 || !strings.Contains(got[0], "elsewhere") {
		t.Fatalf("foreign SPF replaced without confirmation: %v", got)
	}
	if len(memory.Values("MX", "example.test")) != 1 || len(memory.Values("TXT", "_dmarc.example.test")) != 1 {
		t.Fatal("missing records were not created")
	}
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dns/publish", `{"overwrite_conflicts":true}`, http.StatusOK, &plan)
	if got := memory.Values("TXT", "example.test"); len(got) != 1 || got[0] != "v=spf1 mx -all" {
		t.Fatalf("confirmed overwrite: %v", got)
	}

	// Rotation: stage s2, activate it, retire s1; s1's record is removed.
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dkim/keys", `{"selector":"s2","revision":`+jsonNumber(keys.Revision)+`}`, http.StatusCreated, &keys)
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dkim/keys/s2/activate", `{"revision":`+jsonNumber(keys.Revision)+`}`, http.StatusOK, &keys)
	if len(memory.Values("TXT", "s1._domainkey.example.test")) != 1 {
		t.Fatal("the retiring selector must stay published during the overlap")
	}
	call(http.MethodDelete, "/api/v1/admin/domains/example.test/dkim/keys/s1", `{"revision":`+jsonNumber(keys.Revision)+`}`, http.StatusOK, &keys)
	if len(memory.Values("TXT", "s1._domainkey.example.test")) != 0 || len(memory.Values("TXT", "s2._domainkey.example.test")) != 1 {
		t.Fatal("retiring s1 did not remove its record")
	}

	// A failed rotation publish is reported and degrades health.
	memory.FailWrites = errors.New("provider rejected the change")
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dkim/keys", `{"selector":"s3","revision":`+jsonNumber(keys.Revision)+`}`, http.StatusCreated, &keys)
	if keys.DNSPublish == nil || !strings.Contains(keys.DNSPublish.Error, "provider rejected") {
		t.Fatalf("failure not reported: %+v", keys.DNSPublish)
	}
	if obs := handler.DNSZones().Observation(t.Context()); obs.State != health.StateDegraded {
		t.Fatalf("health after failure: %+v", obs)
	}
	entries, err := handler.audit.Query(t.Context(), keys.Keys[0].CreatedAt.AddDate(-1, 0, 0), "", "", 500)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.Action] = true
	}
	for _, action := range []string{"dns.zone.configure", "dns.record.create", "dns.record.update", "dns.record.delete", "dns.record.failed"} {
		if !seen[action] {
			t.Errorf("audit missing %s", action)
		}
	}
}

func jsonNumber(value uint64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
