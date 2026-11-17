package main

import (
	"os"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
)

func TestSetupURL(t *testing.T) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	listeners := []config.HTTPListener{
		{Enabled: false, Transport: "https", Address: "mail.example.com:443", Services: []string{"web"}},
		{Enabled: true, Transport: "http", Address: "0.0.0.0:8472", Services: []string{"dav"}},
		{Enabled: true, Transport: "https", Address: "0.0.0.0:8443", Services: []string{"dav", "web"}},
	}
	if got, want := setupURL(listeners, "a b"), "https://"+hostname+":8443/app/setup?token=a+b"; got != want {
		t.Fatalf("setupURL = %q, want %q", got, want)
	}
	listeners[2].Address = "mail.example.com:8443"
	if got, want := setupURL(listeners, "t"), "https://mail.example.com:8443/app/setup?token=t"; got != want {
		t.Fatalf("setupURL = %q, want %q", got, want)
	}
	if got := setupURL(nil, "t"); got != "/app/setup?token=t" {
		t.Fatalf("setupURL without listeners = %q", got)
	}
}
