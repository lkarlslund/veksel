package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/spam"
)

type refusingResolver struct{}

func (refusingResolver) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.New("tests never resolve blocklists")
}

func TestSpamFilteringApplierSwapsEngineLive(t *testing.T) {
	s := testDeliveryServer(t)
	s.delivery.spamDNS = spam.NewDNS(refusingResolver{}, spam.DNSOptions{})
	apply := applierFor(t, s, "antispam_junk_threshold")
	thresholds := func() spam.Thresholds {
		value, enabled := s.delivery.spam.Thresholds()
		if !enabled {
			t.Fatal("spam scoring is not enabled")
		}
		return value
	}
	cfg := config.Default()
	if err := apply(cfg); err != nil {
		t.Fatal(err)
	}
	if thresholds() != spam.DefaultThresholds() {
		t.Fatalf("default thresholds = %+v", thresholds())
	}
	tuned := *cfg
	tuned.AntispamJunkThreshold, tuned.AntispamDNSResolver = 8, "127.0.0.1"
	if err := apply(&tuned); err != nil {
		t.Fatal(err)
	}
	if thresholds().Junk != 8 {
		t.Fatalf("tuned thresholds = %+v", thresholds())
	}
	for name, mutate := range map[string]func(*config.Config){
		"unknown symbol":   func(c *config.Config) { c.AntispamSymbolScores = []string{"NO_SUCH_SYMBOL=1"} },
		"bad zone":         func(c *config.Config) { c.AntispamDNSBLZones = []string{"zone"} },
		"bad network":      func(c *config.Config) { c.AntispamTrustedNetworks = []string{"not-a-network"} },
		"bad resolver":     func(c *config.Config) { c.AntispamDNSResolver = "resolver.example.net" },
		"inverted actions": func(c *config.Config) { c.AntispamRejectThreshold = 2 },
		"short brand":      func(c *config.Config) { c.AntispamProtectedBrands = []string{"ab"} },
		"bad shortener":    func(c *config.Config) { c.AntispamURLShorteners = []string{"https://bit.ly/"} },
	} {
		invalid := tuned
		mutate(&invalid)
		if err := apply(&invalid); err == nil {
			t.Fatalf("%s: invalid settings accepted", name)
		}
		if thresholds().Junk != 8 {
			t.Fatalf("%s: engine changed after rejection", name)
		}
	}
	if observation := s.spamHealthObservation(&tuned); observation.State != health.StateHealthy || observation.Details["resolver"] != "127.0.0.1:53" {
		t.Fatalf("health = %+v", observation)
	}
	disabled := tuned
	disabled.AntispamEnabled = false
	if err := apply(&disabled); err != nil {
		t.Fatal(err)
	}
	if s.delivery.spam.Enabled() || s.spamHealthObservation(&disabled).State != health.StateDisabled {
		t.Fatal("disabled spam scoring is still active")
	}
}

func TestSpamFilteringAppliesPhishingSettingsLive(t *testing.T) {
	s := testDeliveryServer(t)
	s.delivery.spamDNS = spam.NewDNS(refusingResolver{}, spam.DNSOptions{})
	apply := applierFor(t, s, "antispam_protected_brands")
	if applierFor(t, s, "antispam_url_shorteners") == nil {
		t.Fatal("antispam_url_shorteners has no applier")
	}
	phish := func() map[string]bool {
		result, _ := s.delivery.spam.Check(t.Context(), spam.Message{
			Content: []byte("From: \"Contoso Bank\" <x@partner.org>\r\nContent-Type: text/html\r\n\r\n<a href=\"https://go.example.net/x\">x</a>\r\n"),
			Headers: map[string]string{"From": `"Contoso Bank" <x@partner.org>`},
		})
		found := map[string]bool{}
		for _, symbol := range result.Symbols {
			found[symbol.Name] = true
		}
		return found
	}
	cfg := config.Default()
	if err := apply(cfg); err != nil {
		t.Fatal(err)
	}
	if found := phish(); found["PHISH_BRAND"] || found["PHISH_URL_SHORTENER"] {
		t.Fatalf("default settings flagged %v", found)
	}
	tuned := *cfg
	tuned.AntispamProtectedBrands, tuned.AntispamURLShorteners = []string{"Contoso Bank"}, []string{"go.example.net"}
	if err := apply(&tuned); err != nil {
		t.Fatal(err)
	}
	if found := phish(); !found["PHISH_BRAND"] || !found["PHISH_URL_SHORTENER"] {
		t.Fatalf("tuned settings flagged %v", found)
	}
}
