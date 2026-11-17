package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/contentscan"
	"github.com/lkarlslund/veksel/pkg/greylist"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/virus"
)

// fakeRelay is a minimal SMTP server on 127.0.0.1 that counts accepted
// messages and records the latest envelope sender and AUTH PLAIN response.
type fakeRelay struct {
	port     int
	accepted atomic.Int32
	sender   atomic.Pointer[string]
	auth     atomic.Pointer[string]
}

func startFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	relay := &fakeRelay{port: listener.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go relay.serve(conn)
		}
	}()
	return relay
}

func (relay *fakeRelay) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	reply := func(line string) { _, _ = rw.WriteString(line + "\r\n"); _ = rw.Flush() }
	reply("220 fake ESMTP")
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		switch command := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			reply("250-fake")
			reply("250 AUTH PLAIN")
		case strings.HasPrefix(command, "AUTH PLAIN "):
			decoded, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line)[len("AUTH PLAIN "):])
			credential := string(decoded)
			relay.auth.Store(&credential)
			reply("235 2.7.0 authenticated")
		case strings.HasPrefix(command, "MAIL FROM:"):
			path, _, _ := strings.Cut(strings.TrimSpace(line)[len("MAIL FROM:"):], " ")
			sender := strings.Trim(path, "<>")
			relay.sender.Store(&sender)
			reply("250 OK")
		case strings.HasPrefix(command, "DATA"):
			reply("354 go ahead")
			for {
				dataLine, dataErr := rw.ReadString('\n')
				if dataErr != nil {
					return
				}
				if strings.TrimSpace(dataLine) == "." {
					break
				}
			}
			relay.accepted.Add(1)
			reply("250 queued")
		case strings.HasPrefix(command, "QUIT"):
			reply("221 bye")
			return
		default:
			reply("250 OK")
		}
	}
}

func applierFor(t *testing.T, s *server, key string) config.Applier {
	t.Helper()
	for _, setting := range s.deliverySettings() {
		if slices.Contains(setting.keys, key) {
			return setting.apply
		}
	}
	t.Fatalf("no delivery applier for %s", key)
	return nil
}

func testDeliveryServer(t *testing.T) *server {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	cfg := config.Default()
	s := withTestBackground(t, &server{cfg: cfg, protocolControl: &protocolControlImpl{controllers: &protocolControllers{cfg: cfg}}})
	if s.greylisting, err = greylist.New(t.Context(), backend, greylistConfig(cfg)); err != nil {
		t.Fatal(err)
	}
	s.mailQueue = queue.New(&queue.Config{})
	t.Cleanup(s.mailQueue.Close)
	s.delivery.outbound.Store(s.buildOutboundRoutes(cfg))
	guardConfig, err := cfg.OutboundProtection()
	if err != nil {
		t.Fatal(err)
	}
	if s.sendGuard, err = sendguard.New(t.Context(), model.NewTypedStore(backend, store.BackendJSON), guardConfig); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRelayApplierRoutesNewDeliveriesToNewRelay(t *testing.T) {
	s := testDeliveryServer(t)
	first, second := startFakeRelay(t), startFakeRelay(t)
	applyRelay := applierFor(t, s, "relay_host")
	deliver := func() error {
		return s.deliverOutbound(t.Context(), &queue.Message{ID: "m", EnvelopeSender: "a@example.test", Recipient: "b@remote.test",
			Headers: map[string]string{"Subject": "relay swap"}, Body: []byte("body")})
	}
	for _, step := range []struct {
		relay       *fakeRelay
		first, next int32
	}{{first, 1, 0}, {second, 1, 1}} {
		cfg := config.Default()
		cfg.RelayHost, cfg.RelayPort = "127.0.0.1", step.relay.port
		if err := applyRelay(cfg); err != nil {
			t.Fatal(err)
		}
		if err := deliver(); err != nil {
			t.Fatal(err)
		}
		if got, want := [2]int32{first.accepted.Load(), second.accepted.Load()}, [2]int32{step.first, step.next}; got != want {
			t.Fatalf("relay deliveries = %v, want %v", got, want)
		}
	}
	unrouted := config.Default()
	unrouted.RelayHost, unrouted.SmtpDirectMXEnabled = "", false
	if err := applyRelay(unrouted); err != nil {
		t.Fatal(err)
	}
	if err := deliver(); err == nil || !strings.Contains(err.Error(), "no outbound relay") {
		t.Fatalf("delivery without relay = %v", err)
	}
}

func TestContentScanningApplierSwapsScannersForNextMessage(t *testing.T) {
	s := testDeliveryServer(t)
	applyScanning := applierFor(t, s, "virus_scan_enabled")
	engines := func() []string {
		var names []string
		for _, status := range s.delivery.scanning.Status() {
			names = append(names, status.Name)
		}
		return names
	}
	builtin := config.Default()
	builtin.VirusScanEnabled, builtin.BuiltinScannerEnabled, builtin.ClamdEnabled, builtin.RspamdEnabled = true, true, false, false
	if err := applyScanning(builtin); err != nil {
		t.Fatal(err)
	}
	report := s.delivery.scanning.Scan(t.Context(), contentscan.Message{Content: []byte(virus.EICARTestString)})
	if !s.delivery.virusScanEnabled.Load() || !slices.Equal(engines(), []string{"builtin"}) || report.Decision != contentscan.DecisionQuarantine {
		t.Fatalf("builtin scanning: engines=%v decision=%s", engines(), report.Decision)
	}

	rspamd := *builtin
	rspamd.BuiltinScannerEnabled, rspamd.RspamdEnabled, rspamd.RspamdEndpoint = false, true, "http://127.0.0.1:1"
	if err := applyScanning(&rspamd); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(engines(), []string{"rspamd"}) || !s.delivery.scanning.TrainingAvailable() {
		t.Fatalf("rspamd scanning: engines=%v", engines())
	}

	for name, mutate := range map[string]func(*config.Config){
		"bad policy": func(cfg *config.Config) { cfg.RspamdFailurePolicy = "bogus" },
		"no engines": func(cfg *config.Config) { cfg.RspamdEnabled = false },
	} {
		invalid := rspamd
		mutate(&invalid)
		if err := applyScanning(&invalid); err == nil {
			t.Fatalf("%s: invalid scanning accepted", name)
		}
		if !slices.Equal(engines(), []string{"rspamd"}) {
			t.Fatalf("%s: engines after rejection = %v", name, engines())
		}
	}

	disabled := rspamd
	disabled.VirusScanEnabled = false
	if err := applyScanning(&disabled); err != nil {
		t.Fatal(err)
	}
	if s.delivery.virusScanEnabled.Load() || len(engines()) != 0 || s.delivery.scanning.TrainingAvailable() {
		t.Fatalf("disabled scanning still active: %v", engines())
	}
}

func TestDeliverySettingsApplyLiveThroughManagedConfiguration(t *testing.T) {
	s := testDeliveryServer(t)
	service, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.cfgService, s.cfg = service, service.Current().Config
	if err := s.registerDeliverySettings(); err != nil {
		t.Fatal(err)
	}
	unapplied := service.UnappliedKeys()
	for _, setting := range s.deliverySettings() {
		for _, key := range setting.keys {
			if slices.Contains(unapplied, key) {
				t.Errorf("%s still requires a restart", key)
			}
		}
	}

	changes := map[string]any{"greylist_enabled": true, "greylist_minimum_delay_seconds": int64(120), "greylist_auto_whitelist_passes": int64(3), "greylist_auto_whitelist_days": int64(10), "greylist_skip_spf_pass": true, "greylist_spf_pool_triplets": false, "queue_workers": int64(3), "queue_max_per_destination": int64(2),
		"outbound_rate_limits": []string{"messages_per_hour=7", "recipients_per_day=70"}, "outbound_compromise_threshold": 120.0, "outbound_hold_enabled": false}
	snapshot, err := service.Patch(service.Current().Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	service.Apply(snapshot, changes)
	if config := s.greylisting.Config(); !config.Enabled || config.MinimumDelay.Seconds() != 120 || config.AutoWhitelistPasses != 3 || config.AutoWhitelistLifetime != 240*time.Hour || !config.SkipSPFPass || config.SPFPoolTriplets {
		t.Fatalf("greylisting = %+v", config)
	}
	if limits := s.mailQueue.Limits(); limits.Workers != 3 || limits.MaxPerDestination != 2 {
		t.Fatalf("queue limits = %+v", limits)
	}
	if guard := s.sendGuard.Config(); guard.Defaults != (sendguard.Limits{MessagesPerHour: 7, RecipientsPerDay: 70}) || guard.CompromiseThreshold != 120 || guard.HoldEnabled {
		t.Fatalf("outbound protection = %+v", guard)
	}
	if !s.cfg.GreylistEnabled || s.cfg.QueueWorkers != 3 {
		t.Fatal("applied settings were not adopted into the runtime configuration")
	}
	for _, status := range service.ApplyStates() {
		if _, changed := changes[status.Key]; changed && status.State != config.ApplyEffective {
			t.Fatalf("%s apply state = %s (%s)", status.Key, status.State, status.Error)
		}
	}

	// A configuration the runtime rejects keeps the previous behaviour.
	invalid := service.Current().Config
	invalid.GreylistRetryWindowMinutes, invalid.GreylistMinimumDelaySeconds = 1, 600
	if err := applierFor(t, s, "greylist_enabled")(invalid); err == nil {
		t.Fatal("invalid greylisting accepted")
	}
	if s.greylisting.Config().MinimumDelay.Seconds() != 120 {
		t.Fatalf("greylisting changed after rejection: %+v", s.greylisting.Config())
	}
	invalid = service.Current().Config
	invalid.OutboundRateLimits = []string{"messages_per_minute=1"}
	if err := applierFor(t, s, "outbound_rate_limits")(invalid); err == nil {
		t.Fatal("invalid outbound rate limits accepted")
	}
	if s.sendGuard.Config().Defaults.MessagesPerHour != 7 {
		t.Fatalf("outbound protection changed after rejection: %+v", s.sendGuard.Config())
	}
}
