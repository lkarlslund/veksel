package config

import (
	"slices"
	"testing"
	"time"
)

func TestParseBanThreshold(t *testing.T) {
	for value, want := range map[string]BanThreshold{
		"20/10m": {20, 10 * time.Minute}, " 5 / 1h ": {5, time.Hour}, "3/1d": {3, 24 * time.Hour},
		"0": {}, "off": {}, "0/10m": {},
	} {
		got, err := ParseBanThreshold("ban_auth_failures", value)
		if err != nil || got != want {
			t.Errorf("ParseBanThreshold(%q) = %+v, %v; want %+v", value, got, err, want)
		}
	}
	for _, value := range []string{"", "20", "x/10m", "-1/10m", "10001/10m", "5/1s", "5/2d", "5/soon"} {
		if _, err := ParseBanThreshold("ban_auth_failures", value); err == nil {
			t.Errorf("ParseBanThreshold(%q) accepted", value)
		}
	}
}

func TestParseBanDurations(t *testing.T) {
	got, err := ParseBanDurations(Default().BanDurations)
	if want := []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}; err != nil || !slices.Equal(got, want) {
		t.Fatalf("default durations = %v, %v", got, err)
	}
	for _, values := range [][]string{nil, {"30s"}, {"1h", "10m"}, {"4000d"}, {"1x"}, make([]string, 11)} {
		if _, err := ParseBanDurations(values); err == nil {
			t.Errorf("ParseBanDurations(%q) accepted", values)
		}
	}
	cfg := Default()
	cfg.BanIPv6Prefix = 16
	if err := Validate(cfg); err == nil {
		t.Error("ban_ipv6_prefix 16 accepted")
	}
}
