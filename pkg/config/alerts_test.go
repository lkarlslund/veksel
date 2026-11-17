package config

import "testing"

func TestAlertDeliveryValidation(t *testing.T) {
	recipients, err := ParseAlertEmailRecipients([]string{"Ops@Example.com", " ops@example.com ", "oncall@example.net"})
	if err != nil || len(recipients) != 2 || recipients[0] != "ops@example.com" {
		t.Fatalf("recipients=%v err=%v", recipients, err)
	}
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.AlertEmailRecipients = []string{"Ops <ops@example.com>"} },
		func(cfg *Config) { cfg.AlertEmailRecipients = []string{"not-an-address"} },
		func(cfg *Config) { cfg.AlertNotifyURL = "ftp://push.example.com" },
		func(cfg *Config) { cfg.AlertNotifyURL = "/relative" },
		func(cfg *Config) { cfg.AlertNotifyToken = "has space" },
		func(cfg *Config) { cfg.AlertMinIntervalMinutes = -1 },
		func(cfg *Config) { cfg.AlertMinIntervalMinutes = 1441 },
		func(cfg *Config) { cfg.AlertDigest = "weekly" },
	} {
		cfg := Default()
		mutate(cfg)
		if err := validateAlertDelivery(cfg); err == nil {
			t.Errorf("invalid alert delivery accepted: %+v", cfg.AlertEmailRecipients)
		}
	}
	cfg := Default()
	cfg.AlertEmailRecipients, cfg.AlertNotifyURL, cfg.AlertNotifyToken, cfg.AlertDigest = []string{"ops@example.com"}, "https://push.example.com/message", "abc", AlertDigestDaily
	if err := validateAlertDelivery(cfg); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"alert_notify_token", "alert_notify_url"} {
		if !sensitiveSetting(key) {
			t.Fatalf("%s is not redacted", key)
		}
	}
}
