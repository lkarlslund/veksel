package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestBuiltinDNSServerUI keeps the built-in DNS provider choice, the zone
// records table with DNSSEC DS records and rollover, and the DNS server
// settings on the Domains page.
func TestBuiltinDNSServerUI(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"['builtin','Veksel built-in DNS server']",
		"data-dns-records",
		"`/api/v1/admin/dns/zones/${encodeURIComponent(data.provider.zone)}`",
		"`${zoneURL}/records`",
		"`${zoneURL}/dnssec/rollover`",
		"data-dns-ds-copy",
		"title:'Delete DNS record'",
		"setting.category==='dns'?'/app/admin/domains'",
		"settingsCards(dnsSettings,['dns'])",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("app.js lacks %q", required)
		}
	}
}
