package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLegacyHTTPSettingsMigrateToSharedListeners(t *testing.T) {
	dir := t.TempDir()
	legacy := DefaultAt(dir)
	legacy.HTTPListeners = nil
	legacy.ListenAddr = "127.0.0.1:9000"
	legacy.HTTPSEnabled = true
	legacy.HTTPSListen = "127.0.0.1:9443"
	legacy.HTTPSCertificate = "stored:web"
	contents, err := defaultDocument(legacy)
	if err != nil {
		t.Fatal(err)
	}
	contents = []byte(strings.Replace(string(contents), "http_listeners = []\n", "", 1))
	if err := os.WriteFile(filepath.Join(dir, configFileName), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	listeners := service.Current().Config.HTTPListeners
	if len(listeners) != 2 || listeners[0].Address != "127.0.0.1:9000" || listeners[1].Address != "127.0.0.1:9443" || listeners[1].Certificate != "stored:web" {
		t.Fatalf("migrated listeners = %#v", listeners)
	}
	if !slices.Contains(listeners[0].Services, "mcp") || !slices.Contains(listeners[1].Services, "mcp") {
		t.Fatalf("migrated listeners do not expose managed MCP binding: %#v", listeners)
	}
}

func TestPatchHTTPListenersPreservesDocumentAndValidatesLockout(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	current := service.Current()
	listeners := slices.Clone(current.Config.HTTPListeners)
	hstsDays := 365
	listeners = append(listeners, HTTPListener{ID: "mobile", Name: "Mobile", Enabled: true, Transport: HTTPSTransport, Address: "127.0.0.1:8480", Certificate: "stored:mobile", HSTSMaxAgeDays: &hstsDays, HSTSIncludeSubdomains: true, HSTSPreload: true, LogLevel: "debug", Services: []string{"eas"}})
	next, err := service.Patch(current.Revision, map[string]any{"http_listeners": listeners})
	if err != nil {
		t.Fatalf("patch listeners: %v", err)
	}
	if len(next.Config.HTTPListeners) != 2 || next.Config.HTTPListeners[1].ID != "mobile" || next.Config.HTTPListeners[1].HSTSMaxAgeDays == nil || *next.Config.HTTPListeners[1].HSTSMaxAgeDays != 365 || !next.Config.HTTPListeners[1].HSTSPreload {
		t.Fatalf("listeners after patch = %#v", next.Config.HTTPListeners)
	}
	*next.Config.HTTPListeners[1].HSTSMaxAgeDays = 30
	if got := service.Current().Config.HTTPListeners[1].HSTSMaxAgeDays; got == nil || *got != 365 {
		t.Fatalf("mutating returned HSTS age changed managed snapshot: %v", got)
	}
	*next.Config.HTTPListeners[1].HSTSMaxAgeDays = 365
	contents, err := os.ReadFile(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "http_listeners = [") || !strings.Contains(string(contents), `id = 'mobile'`) && !strings.Contains(string(contents), `id = "mobile"`) || !strings.Contains(string(contents), "hsts_max_age_days") || !strings.Contains(string(contents), "hsts_preload") {
		t.Fatalf("listener collection was not persisted as TOML:\n%s", contents)
	}
	lockedOut := slices.Clone(next.Config.HTTPListeners)
	for i := range lockedOut {
		lockedOut[i].Services = slices.DeleteFunc(lockedOut[i].Services, func(service string) bool { return service == "web" })
	}
	if _, err := service.Patch(next.Revision, map[string]any{"http_listeners": lockedOut}); err == nil || !strings.Contains(err.Error(), "web service") {
		t.Fatalf("web lockout patch error = %v", err)
	}
}

func TestValidateHTTPListenersRejectsUnsafeDefinitions(t *testing.T) {
	base := Default()
	days := func(value int) *int { return &value }
	tests := []HTTPListener{
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPSTransport, Address: "0.0.0.0:8472", Services: []string{"web"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPTransport, Address: "0.0.0.0:8472", Certificate: "stored:x", Services: []string{"web"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPTransport, Address: "0.0.0.0:8472", Services: []string{"smtp"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPTransport, Address: "0.0.0.0:8472", HSTSPreload: true, Services: []string{"web"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPSTransport, Address: "0.0.0.0:8472", Certificate: "stored:x", HSTSIncludeSubdomains: true, Services: []string{"web"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPSTransport, Address: "0.0.0.0:8472", Certificate: "stored:x", HSTSMaxAgeDays: days(364), HSTSIncludeSubdomains: true, HSTSPreload: true, Services: []string{"web"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPSTransport, Address: "0.0.0.0:8472", Certificate: "stored:x", HSTSMaxAgeDays: days(365), HSTSPreload: true, Services: []string{"web"}, LogLevel: "inherit"},
		{ID: "bad", Name: "Bad", Enabled: true, Transport: HTTPSTransport, Address: "0.0.0.0:8472", Certificate: "stored:x", HSTSMaxAgeDays: days(MaxHSTSMaxAgeDays + 1), Services: []string{"web"}, LogLevel: "inherit"},
	}
	for _, listener := range tests {
		copy := *base
		copy.HTTPListeners = []HTTPListener{listener}
		if err := Validate(&copy); err == nil {
			t.Errorf("unsafe listener accepted: %#v", listener)
		}
	}
}

func TestValidateAllowsProxiedHSTSOnHTTPListener(t *testing.T) {
	copy := *Default()
	days := 365
	copy.HTTPListeners = []HTTPListener{{ID: "proxied", Name: "Behind TLS proxy", Enabled: true, Transport: HTTPTransport, Address: "127.0.0.1:8472", HSTSMaxAgeDays: &days, HSTSIncludeSubdomains: true, HSTSPreload: true, Services: []string{"web"}, LogLevel: "inherit"}}
	if err := Validate(&copy); err != nil {
		t.Fatalf("HSTS for a TLS-terminating proxy rejected on HTTP listener: %v", err)
	}
}

func TestValidateRejectsHTTPAndProtocolPortCollision(t *testing.T) {
	cfg := Default()
	cfg.HTTPListeners[0].Address = "0.0.0.0:143"
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("listener collision error = %v", err)
	}
}
