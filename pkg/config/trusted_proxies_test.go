package config

import "testing"

func TestTrustedProxiesValidation(t *testing.T) {
	cfg := DefaultAt(t.TempDir())
	cfg.HTTPTrustedProxies = []string{"127.0.0.1", "10.0.0.0/8", "2001:db8::/32", " ::1 "}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"10.0.0.0/33", "not-an-ip", "", "fe80::1%eth0", "10.0.0.1/abc"} {
		cfg.HTTPTrustedProxies = []string{invalid}
		if err := Validate(cfg); err == nil {
			t.Fatalf("invalid trusted proxy %q accepted", invalid)
		}
	}
	prefixes, err := ParseTrustedProxies([]string{"::ffff:192.0.2.0/120", "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	if prefixes[0].String() != "192.0.2.0/24" || prefixes[1].String() != "192.0.2.7/32" {
		t.Fatalf("prefixes = %v", prefixes)
	}
}

func TestMailProxyProtocolValidation(t *testing.T) {
	cfg := DefaultAt(t.TempDir())
	cfg.MailProxyProtocol = []string{"smtp", " IMAPS ", "managesieve-tls"}
	cfg.MailProxyProtocolTrusted = []string{"10.0.0.5", "2001:db8::/64"}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct{ entries, trusted []string }{
		{[]string{"smtp-25"}, []string{"10.0.0.5"}},
		{[]string{"imap"}, nil},
		{[]string{"imap"}, []string{"10.0.0.0/33"}},
		{nil, []string{"not-an-ip"}},
	} {
		cfg.MailProxyProtocol, cfg.MailProxyProtocolTrusted = invalid.entries, invalid.trusted
		if err := Validate(cfg); err == nil {
			t.Fatalf("invalid PROXY protocol settings %q / %q accepted", invalid.entries, invalid.trusted)
		}
	}
	if !MailProxyProtocolEnabled([]string{" IMAPS "}, "imap", "imaps") || MailProxyProtocolEnabled([]string{"imaps"}, "imap", "imap-starttls") {
		t.Fatal("listener selection mismatch")
	}
}

func TestPatchTrustedProxiesAppliesLiveAndRejectsInvalid(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registerNoopAppliers(t, service)
	before := service.Current()
	if _, err := service.Patch(before.Revision, map[string]any{"http_trusted_proxies": []any{"10.0.0.0/8", "bad/cidr"}}); err == nil {
		t.Fatal("invalid CIDR accepted through patch API")
	}
	_, plan, err := service.PreviewPatch(before.Revision, map[string]any{"http_trusted_proxies": []any{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RestartRequired || len(plan.LiveApplyKeys) != 1 || plan.LiveApplyKeys[0] != "http_trusted_proxies" {
		t.Fatalf("plan = %+v", plan)
	}
	after, err := service.Patch(before.Revision, map[string]any{"http_trusted_proxies": []any{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Config.HTTPTrustedProxies) != 1 || after.Config.HTTPTrustedProxies[0] != "10.0.0.0/8" {
		t.Fatalf("trusted proxies = %q", after.Config.HTTPTrustedProxies)
	}
}
