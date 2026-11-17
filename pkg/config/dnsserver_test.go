package config

import "testing"

func TestDNSServerSettingsValidation(t *testing.T) {
	const secret = "MDEyMzQ1Njc4OWFiY2RlZg=="
	key, err := ParseDNSServerTSIG("xfr.example.test.:" + secret)
	if err != nil || key.Algorithm != "hmac-sha256" || key.Name != "xfr.example.test" || key.Secret != secret {
		t.Fatalf("default algorithm: %+v %v", key, err)
	}
	if key, err := ParseDNSServerTSIG("HMAC-SHA512:xfr:" + secret); err != nil || key.Algorithm != "hmac-sha512" {
		t.Fatalf("explicit algorithm: %+v %v", key, err)
	}
	if key, err := ParseDNSServerTSIG(" "); key != nil || err != nil {
		t.Fatalf("empty disables transfers: %+v %v", key, err)
	}
	for _, bad := range []string{"xfr", "md5:xfr:" + secret, "xfr:c2hvcnQ=", "bad name:" + secret, "a:b:c:d"} {
		if _, err := ParseDNSServerTSIG(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}

	cfg := Default()
	cfg.DNSServerNameservers = []string{"ns1.example.test.", "ns2.example.net"}
	cfg.DNSServerAXFRTSIG = "xfr:" + secret
	if err := validateDNSServer(cfg); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.DNSServerListen = "53" },
		func(c *Config) { c.DNSServerNameservers = []string{"localhost"} },
		func(c *Config) { c.DNSServerNameservers = []string{"ns1.example.test/24"} },
		func(c *Config) { c.DNSServerAXFRTSIG = "nope" },
	} {
		candidate := *cfg
		mutate(&candidate)
		if err := validateDNSServer(&candidate); err == nil {
			t.Errorf("invalid settings accepted: %+v", candidate.DNSServerNameservers)
		}
	}
	if !sensitiveSetting("dns_server_axfr_tsig") {
		t.Fatal("the transfer key must be redacted")
	}
}
