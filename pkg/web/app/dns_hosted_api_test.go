package app

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/dnsserver"
	"github.com/miekg/dns"
)

func TestBuiltinDNSZoneRecordsDKIMAndServing(t *testing.T) {
	handler, _ := testHandler(t)
	cfg := config.Default()
	cfg.SmtpServerName = "mail.example.test"
	handler.ConfigureAdministration(cfg, nil)
	handler.SetDNSResolver(fakeDNSResolver{mx: map[string][]*net.MX{}, txt: map[string][]string{}, host: map[string][]string{}, addr: map[string][]string{}})
	server := dnsserver.New(handler.DNSZones().Hosted())
	server.RateLimit = -1
	if err := server.Apply(dnsserver.Settings{Enabled: true, Listen: "127.0.0.1:0", Nameservers: []string{"ns1.example.test"}, DNSSEC: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	handler.ConfigureDNSServer(server)
	query := func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), qtype)
		reply, _, err := (&dns.Client{Net: "tcp", Timeout: 2 * time.Second}).Exchange(msg, server.Addr())
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}

	mux := http.NewServeMux()
	handler.Register(mux)
	app := serveTestApp(t, handler, mux)
	t.Cleanup(app.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, app, client, "owner")
	call := func(method, path, body string, want int, target any) {
		t.Helper()
		response := authenticatedJSON(t, client, method, app.URL+path, csrf, body)
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
	}

	call(http.MethodPost, "/api/v1/admin/domains", `{"id":"example.test"}`, http.StatusCreated, nil)
	call(http.MethodGet, "/api/v1/admin/dns/zones/example.test/records", "", http.StatusNotFound, nil)
	call(http.MethodPut, "/api/v1/admin/dns/zones/example.test", `{"provider":"builtin","settings":{}}`, http.StatusOK, nil)
	if reply := query("example.test", dns.TypeSOA); reply.Rcode != dns.RcodeSuccess || !reply.Authoritative {
		t.Fatalf("new zone is not served: %v", reply)
	}

	// Publishing through the existing plan creates the mail records.
	var plan dnsPublishResponse
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dns/publish", `{}`, http.StatusOK, &plan)
	if plan.Provider != dnsprovider.KindBuiltin || plan.Error != "" {
		t.Fatalf("publish: %+v", plan)
	}
	if reply := query("example.test", dns.TypeMX); len(reply.Answer) != 1 {
		t.Fatalf("published MX not served: %v", reply)
	}

	// The DKIM rotation hook publishes the staged selector.
	var keys adminDKIMKeysResponse
	call(http.MethodPost, "/api/v1/admin/domains/example.test/dkim/keys", `{"selector":"s1","revision":0}`, http.StatusCreated, &keys)
	if keys.DNSPublish == nil || keys.DNSPublish.Error != "" {
		t.Fatalf("DKIM publish: %+v", keys.DNSPublish)
	}
	if reply := query("s1._domainkey.example.test", dns.TypeTXT); len(reply.Answer) != 1 || !strings.HasPrefix(strings.Join(reply.Answer[0].(*dns.TXT).Txt, ""), "v=DKIM1") {
		t.Fatalf("DKIM TXT not served: %v", reply)
	}

	// Administrator records sit next to the published ones.
	var added dnsprovider.Record
	call(http.MethodPost, "/api/v1/admin/dns/zones/example.test/records", `{"type":"A","name":"mail.example.test","value":"192.0.2.25","ttl":600}`, http.StatusCreated, &added)
	call(http.MethodPost, "/api/v1/admin/dns/zones/example.test/records", `{"type":"NS","name":"sub.example.test","value":"ns.example.net."}`, http.StatusBadRequest, nil)
	if reply := query("mail.example.test", dns.TypeA); len(reply.Answer) != 1 || reply.Answer[0].Header().Ttl != 600 {
		t.Fatalf("custom A not served: %v", reply)
	}
	var zone hostedZoneResponse
	call(http.MethodGet, "/api/v1/admin/dns/zones/example.test/records", "", http.StatusOK, &zone)
	owners := map[string]string{}
	for _, rec := range zone.Records {
		owners[rec.Type+" "+rec.Name] = rec.Owner
	}
	if owners["MX example.test"] != "example.test" || owners["A mail.example.test"] != "" || len(zone.Keys) != 1 || !strings.Contains(zone.Keys[0].DS, "IN\tDS\t") {
		t.Fatalf("records view: %+v", zone)
	}
	if !zone.Server.Running || !zone.Server.DNSSEC || zone.Server.Nameservers[0] != "ns1.example.test." {
		t.Fatalf("server status: %+v", zone.Server)
	}
	var rollover struct {
		Step string             `json:"step"`
		Zone hostedZoneResponse `json:"zone"`
	}
	call(http.MethodPost, "/api/v1/admin/dns/zones/example.test/dnssec/rollover", `{}`, http.StatusOK, &rollover)
	if rollover.Step != "staged" || len(rollover.Zone.Keys) != 2 {
		t.Fatalf("rollover: %+v", rollover)
	}
	call(http.MethodDelete, "/api/v1/admin/dns/zones/example.test/records/"+added.ID, "", http.StatusNoContent, nil)
	if reply := query("mail.example.test", dns.TypeA); len(reply.Answer) != 0 {
		t.Fatalf("deleted record still served: %v", reply)
	}

	// Removing the zone stops serving it.
	call(http.MethodDelete, "/api/v1/admin/dns/zones/example.test", "", http.StatusNoContent, nil)
	if reply := query("example.test", dns.TypeSOA); reply.Rcode != dns.RcodeRefused {
		t.Fatalf("removed zone still served: %v", reply)
	}
}
