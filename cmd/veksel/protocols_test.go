package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/certificates"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// TestProtocolControlRestartsProtocols exercises the admin start/stop path,
// which builds its servers with the same code as startup.
func TestProtocolControlRestartsProtocols(t *testing.T) {
	control := newTestProtocolControl(t)
	control.controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{}})

	tests := []struct {
		name    string
		start   func()
		stop    func()
		running func() bool
		banner  string
	}{
		{"imap", control.StartIMAP, control.StopIMAP, control.IsIMAPRunning, "* OK"},
		{"pop3", control.StartPOP3, control.StopPOP3, control.IsPOP3Running, "+OK"},
		{"smtp", control.StartSMTP, control.StopSMTP, control.IsSMTPRunning, "220 "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.start()
			status := control.ProtocolRuntimeStatus(test.name)
			// Without a certificate the listener runs, reporting that it is
			// plaintext only.
			if !test.running() || len(status.Listeners) != 1 || !strings.Contains(status.Error, "no assigned certificate, so STARTTLS is unavailable") {
				t.Fatalf("started %s status: %#v", test.name, status)
			}
			conn, err := net.DialTimeout("tcp", status.Listeners[0], 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if err != nil || !strings.HasPrefix(line, test.banner) {
				t.Fatalf("%s greeting = %q, %v", test.name, line, err)
			}
			test.stop()
			if test.running() {
				t.Fatalf("%s still running after stop", test.name)
			}
			if conn, err := net.DialTimeout("tcp", status.Listeners[0], time.Second); err == nil {
				_ = conn.Close()
				t.Fatalf("%s still accepts connections after stop", test.name)
			}
			waitForReleasedConnections(t, control, test.name)
		})
	}
}

// waitForReleasedConnections lets sessions release their connection gauge
// before the metrics store goes away.
func waitForReleasedConnections(t *testing.T, control *protocolControlImpl, protocol string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if active, _, ok := control.controllers.met.CurrentGauge(protocol + "_active_connections"); !ok || active == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s session did not release its connection", protocol)
		}
	}
}

func newTestProtocolControl(t *testing.T) *protocolControlImpl {
	t.Helper()
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	cfg := config.Default()
	cfg.ImapEnabled, cfg.ImapTLSEnabled, cfg.ImapListen = true, false, "127.0.0.1:0"
	cfg.Pop3Enabled, cfg.Pop3TLSEnabled, cfg.Pop3Listen = true, false, "127.0.0.1:0"
	cfg.SmtpEnabled, cfg.SmtpListen = true, "127.0.0.1:0"
	cfg.SmtpSubmissionEnabled, cfg.SmtpImplicitTLSEnabled = false, false
	// PROXY-relayed test clients are not loopback; skip the greeting delay.
	cfg.SmtpGreetDelayMs = 0
	cfg.ManageSieveEnabled, cfg.ManageSieveTLSEnabled, cfg.ManageSieveListen = true, false, "127.0.0.1:0"
	ts := model.NewTypedStore(backend, cfg.StoreBackend)
	if err := ts.EnsureNamespace(t.Context(), model.NSCerts); err != nil {
		t.Fatal(err)
	}
	provider, err := certificates.New(ts, nil)
	if err != nil {
		t.Fatal(err)
	}
	control := &protocolControlImpl{controllers: &protocolControllers{
		cfg: cfg, ts: ts, met: metrics.New(backend), certificates: provider, protocolAuth: protocolauth.New(ts),
		sieveScripts: service.NewSieveRepository(nil),
	}}
	t.Cleanup(func() {
		// Sessions release their metrics before the store closes.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		drain(ctx, control.controllers.beginShutdown())
	})
	return control
}

// TestProtocolControlSMTPStartWaitsForDelivery reports, rather than ignores,
// an admin SMTP start before the delivery chain exists.
func TestProtocolControlSMTPStartWaitsForDelivery(t *testing.T) {
	control := newTestProtocolControl(t)
	control.StartSMTP()
	if status := control.ProtocolRuntimeStatus("smtp"); status.Running || status.Error == "" {
		t.Fatalf("SMTP status without delivery = %#v", status)
	}
	// A configuration change before then is kept for the delayed start.
	next := *control.controllers.config()
	next.SmtpServerName = "later.example.test"
	if err := control.controllers.reconfigure(&next, &smtpProtocol); err != nil {
		t.Fatalf("reconfigure before delivery: %v", err)
	}
	control.controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{}})
	control.StartSMTP()
	if line := smtpProbe.greeting(t, control.ProtocolRuntimeStatus("smtp").Listeners[0], nil); !strings.Contains(line, "later.example.test") {
		t.Fatalf("delayed SMTP start greeting = %q", line)
	}
}

// TestIMAPRestartStartsFreshServer checks that a restarted IMAP listener
// serves from a new server rather than the stopped one. Deliveries reach its
// IDLE sessions through the folder space's commit notifications, which every
// running server follows.
func TestIMAPRestartStartsFreshServer(t *testing.T) {
	control := newTestProtocolControl(t)
	imapState := &control.controllers.imap
	control.StartIMAP()
	original := imapState.active[0].server
	control.StopIMAP()
	control.StartIMAP()
	defer control.StopIMAP()
	if restarted := imapState.active[0].server; restarted == original {
		t.Fatal("restarted IMAP reuses the stopped server")
	}
}

// protocolProbe speaks just enough of a protocol to read what a new session
// is offered.
type protocolProbe struct {
	// greetingEnd reports whether line ends the greeting.
	greetingEnd func(line string) bool
	// capabilities, when set, is sent after the greeting and its response
	// read until "end".
	capabilities, end string
	noop              string
}

var (
	imapProbe        = protocolProbe{greetingEnd: anyLine, noop: "a NOOP\r\n"}
	pop3Probe        = protocolProbe{greetingEnd: anyLine, capabilities: "CAPA\r\n", end: ".", noop: "NOOP\r\n"}
	smtpProbe        = protocolProbe{greetingEnd: anyLine, noop: "NOOP\r\n"}
	manageSieveProbe = protocolProbe{greetingEnd: func(line string) bool { return line == "OK" }, noop: "NOOP\r\n"}
)

func anyLine(string) bool { return true }

// dial opens a session, over TLS when tlsConfig is set, and reads its
// greeting and capabilities.
func (p protocolProbe) dial(t *testing.T, addr string, tlsConfig *tls.Config) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if tlsConfig != nil {
		conn = tls.Client(conn, tlsConfig)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	var transcript strings.Builder
	readUntil := func(end func(string) bool) {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read from %s: %v (after %q)", addr, err, transcript.String())
			}
			transcript.WriteString(line)
			if end(strings.TrimRight(line, "\r\n")) {
				return
			}
		}
	}
	readUntil(p.greetingEnd)
	if p.capabilities != "" {
		if _, err := conn.Write([]byte(p.capabilities)); err != nil {
			t.Fatal(err)
		}
		readUntil(func(line string) bool { return line == p.end })
	}
	return conn, reader, transcript.String()
}

func (p protocolProbe) greeting(t *testing.T, addr string, tlsConfig *tls.Config) string {
	t.Helper()
	conn, _, transcript := p.dial(t, addr, tlsConfig)
	_ = conn.Close()
	return transcript
}

// stillServes reports whether an established session answers a command.
func (p protocolProbe) stillServes(conn net.Conn, reader *bufio.Reader) bool {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(p.noop)); err != nil {
		return false
	}
	line, err := reader.ReadString('\n')
	return err == nil && line != ""
}

func refuses(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
	}
	return err != nil
}

// handedOut remembers the addresses freeAddress returned, so two calls never
// return the same port even though each probe listener is closed at once.
var handedOut sync.Map

// freeAddress returns a loopback address nothing listens on and that no
// earlier call in this test binary returned.
func freeAddress(t *testing.T) string {
	t.Helper()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		if _, taken := handedOut.LoadOrStore(addr, struct{}{}); !taken {
			return addr
		}
	}
}

// TestProtocolSettingsApplyLive changes each protocol's settings through its
// live applier: listeners move, stop, and start without a restart, sessions
// that were already connected keep working, new sessions see new settings,
// and an address that cannot be bound leaves the running listener alone.
func TestProtocolSettingsApplyLive(t *testing.T) {
	tests := []struct {
		name    string
		proto   *protocolDefinition
		probe   protocolProbe
		listen  func(*config.Config, string)
		enable  func(*config.Config, bool)
		setting func(*config.Config, bool) // toggles a per-session setting
		offered func(transcript string) bool
	}{
		{"imap", &imapProtocol, imapProbe,
			func(cfg *config.Config, addr string) { cfg.ImapListen = addr },
			func(cfg *config.Config, on bool) { cfg.ImapEnabled = on },
			func(cfg *config.Config, on bool) { cfg.ImapRequireTLSAuth = on },
			func(transcript string) bool { return strings.Contains(transcript, "LOGINDISABLED") }},
		{"pop3", &pop3Protocol, pop3Probe,
			func(cfg *config.Config, addr string) { cfg.Pop3Listen = addr },
			func(cfg *config.Config, on bool) { cfg.Pop3Enabled = on },
			func(cfg *config.Config, on bool) { cfg.Pop3RequireTLSAuth = on },
			func(transcript string) bool { return !strings.Contains(transcript, "\r\nUSER\r\n") }},
		{"smtp", &smtpProtocol, smtpProbe,
			func(cfg *config.Config, addr string) { cfg.SmtpListen = addr },
			func(cfg *config.Config, on bool) { cfg.SmtpEnabled = on },
			func(cfg *config.Config, on bool) {
				cfg.SmtpServerName = "off.example.test"
				if on {
					cfg.SmtpServerName = "on.example.test"
				}
			},
			func(transcript string) bool { return strings.Contains(transcript, "220 on.example.test") }},
		{"managesieve", &manageSieveProtocol, manageSieveProbe,
			func(cfg *config.Config, addr string) { cfg.ManageSieveListen = addr },
			func(cfg *config.Config, on bool) { cfg.ManageSieveEnabled = on },
			func(cfg *config.Config, on bool) { cfg.ManageSieveRequireTLSAuth = on },
			func(transcript string) bool { return !strings.Contains(transcript, `"SASL" "PLAIN"`) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := newTestProtocolControl(t)
			controllers := control.controllers
			controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{}})
			state := test.proto.state(controllers)
			apply := func(change func(*config.Config)) error {
				next := *controllers.config()
				change(&next)
				return controllers.reconfigure(&next, test.proto)
			}
			listener := func() string {
				status := state.status()
				if !status.Running || len(status.Listeners) != 1 {
					t.Fatalf("%s status = %#v", test.name, status)
				}
				return status.Listeners[0]
			}
			if err := apply(func(cfg *config.Config) { test.setting(cfg, false) }); err != nil {
				t.Fatal(err)
			}
			controllers.start(t.Context(), test.proto)
			original := listener()
			established, reader, _ := test.probe.dial(t, original, nil)

			// A per-session setting reaches the next session on the same listener.
			if err := apply(func(cfg *config.Config) { test.setting(cfg, true) }); err != nil {
				t.Fatal(err)
			}
			if listener() != original || !test.offered(test.probe.greeting(t, original, nil)) {
				t.Fatalf("%s setting not applied to the next session on %s", test.name, original)
			}
			if err := apply(func(cfg *config.Config) { test.setting(cfg, false) }); err != nil {
				t.Fatal(err)
			}
			if test.offered(test.probe.greeting(t, original, nil)) {
				t.Fatalf("%s setting not reverted for the next session", test.name)
			}

			// Moving the listener keeps the established session.
			moved := freeAddress(t)
			if err := apply(func(cfg *config.Config) { test.listen(cfg, moved) }); err != nil {
				t.Fatal(err)
			}
			if listener() != moved || !refuses(original) {
				t.Fatalf("%s listener did not move from %s to %s", test.name, original, moved)
			}
			test.probe.greeting(t, moved, nil)
			if !test.probe.stillServes(established, reader) {
				t.Fatalf("%s dropped the established session when its listener moved", test.name)
			}

			// An address in use is refused and the running listener stays.
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			if err := apply(func(cfg *config.Config) { test.listen(cfg, occupied.Addr().String()) }); err == nil {
				t.Fatalf("%s accepted an address in use", test.name)
			}
			if listener() != moved {
				t.Fatalf("%s failed change replaced the running listener", test.name)
			}
			test.probe.greeting(t, moved, nil)

			// Disabling stops accepting; enabling starts again.
			if err := apply(func(cfg *config.Config) { test.listen(cfg, moved); test.enable(cfg, false) }); err != nil {
				t.Fatal(err)
			}
			if state.isRunning() || !refuses(moved) {
				t.Fatalf("%s still accepts after being disabled", test.name)
			}
			if err := apply(func(cfg *config.Config) { test.enable(cfg, true) }); err != nil {
				t.Fatal(err)
			}
			test.probe.greeting(t, listener(), nil)
			if !test.probe.stillServes(established, reader) {
				t.Fatalf("%s dropped the established session across disable and enable", test.name)
			}
			_ = established.Close()
		})
	}
}

// TestProtocolCertificateAssignmentAppliesToNextHandshake swaps each
// protocol's certificate assignment without rebinding its implicit-TLS
// listener, and keeps the old one when the new assignment cannot load.
func TestProtocolCertificateAssignmentAppliesToNextHandshake(t *testing.T) {
	tests := []struct {
		name   string
		proto  *protocolDefinition
		probe  protocolProbe
		enable func(cfg *config.Config, certificate string)
	}{
		{"imap", &imapProtocol, imapProbe, func(cfg *config.Config, certificate string) {
			cfg.ImapEnabled, cfg.ImapTLSEnabled, cfg.ImapTlsListen, cfg.ImapCertificate = false, true, "127.0.0.1:0", certificate
		}},
		{"pop3", &pop3Protocol, pop3Probe, func(cfg *config.Config, certificate string) {
			cfg.Pop3Enabled, cfg.Pop3TLSEnabled, cfg.Pop3TlsListen, cfg.Pop3Certificate = false, true, "127.0.0.1:0", certificate
		}},
		{"smtp", &smtpProtocol, smtpProbe, func(cfg *config.Config, certificate string) {
			cfg.SmtpEnabled, cfg.SmtpImplicitTLSEnabled, cfg.SmtpTLSListen, cfg.SmtpCertificate = false, true, "127.0.0.1:0", certificate
		}},
		{"managesieve", &manageSieveProtocol, manageSieveProbe, func(cfg *config.Config, certificate string) {
			cfg.ManageSieveEnabled, cfg.ManageSieveTLSEnabled, cfg.ManageSieveTLSListen, cfg.ManageSieveCertificate = false, true, "127.0.0.1:0", certificate
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := newTestProtocolControl(t)
			controllers := control.controllers
			controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{}})
			for _, name := range []string{"one.example.test", "two.example.test"} {
				certPEM, keyPEM := testCertificate(t, name)
				if _, err := controllers.ts.TLSCertStore().Create(t.Context(), name, certPEM, keyPEM); err != nil {
					t.Fatal(err)
				}
			}
			apply := func(certificate string) error {
				next := *controllers.config()
				test.enable(&next, certificate)
				return controllers.reconfigure(&next, test.proto)
			}
			served := func(addr string) string {
				clientTLS := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // inspects the served test certificate
				conn, _, _ := test.probe.dial(t, addr, clientTLS)
				defer conn.Close()
				return conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Subject.CommonName
			}
			if err := apply("stored:one.example.test"); err != nil {
				t.Fatal(err)
			}
			status := test.proto.state(controllers).status()
			if !status.Running || len(status.Listeners) != 1 || status.Error != "" {
				t.Fatalf("%s TLS status = %#v", test.name, status)
			}
			addr := status.Listeners[0]
			if got := served(addr); got != "one.example.test" {
				t.Fatalf("%s served %q", test.name, got)
			}
			if err := apply("stored:two.example.test"); err != nil {
				t.Fatal(err)
			}
			if got := served(addr); got != "two.example.test" {
				t.Fatalf("%s served %q after reassignment", test.name, got)
			}
			if err := apply("stored:missing.example.test"); err == nil {
				t.Fatalf("%s accepted a certificate that cannot load", test.name)
			}
			if got := served(addr); got != "two.example.test" {
				t.Fatalf("%s served %q after a failed reassignment", test.name, got)
			}
		})
	}
}

// TestProtocolSettingsRespectAdminStop validates changes to a protocol the
// administrator stopped without starting it; the next start uses them.
func TestProtocolSettingsRespectAdminStop(t *testing.T) {
	control := newTestProtocolControl(t)
	control.StartIMAP()
	control.StopIMAP()
	next := *control.controllers.config()
	next.ImapServerName = "stopped.example.test"
	if err := control.controllers.reconfigure(&next, &imapProtocol); err != nil {
		t.Fatal(err)
	}
	if control.IsIMAPRunning() {
		t.Fatal("configuration change started an administrator-stopped protocol")
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	invalid := next
	invalid.ImapListen = occupied.Addr().String()
	if err := control.controllers.reconfigure(&invalid, &imapProtocol); err == nil {
		t.Fatal("stopped protocol accepted an address in use")
	}
	if err := control.controllers.reconfigure(&next, &imapProtocol); err != nil {
		t.Fatal(err)
	}
	control.StartIMAP()
	if greeting := imapProbe.greeting(t, control.ProtocolRuntimeStatus("imap").Listeners[0], nil); !strings.Contains(greeting, "stopped.example.test") {
		t.Fatalf("start after stop greeting = %q", greeting)
	}
}

// TestProtocolStartReportsListenerProblems records every problem of a start
// attempt and clears them on a successful retry.
func TestProtocolStartReportsListenerProblems(t *testing.T) {
	control := newTestProtocolControl(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := control.controllers.config()
	cfg.ImapListen, cfg.ImapTLSEnabled, cfg.ImapTlsListen = occupied.Addr().String(), true, "127.0.0.1:0"
	control.StartIMAP()
	status := control.ProtocolRuntimeStatus("imap")
	if status.Running || status.Attempt != 1 || status.AttemptedAt.IsZero() ||
		!strings.Contains(status.Error, "no assigned certificate") || !strings.Contains(status.Error, "address already in use") {
		t.Fatalf("failed start status = %#v", status)
	}
	_ = occupied.Close()
	cfg.ImapTLSEnabled = false
	control.StartIMAP()
	if status = control.ProtocolRuntimeStatus("imap"); !status.Running || status.Error != plaintextOnly("IMAP", cfg.ImapRequireTLSAuth).Error() || status.Attempt != 2 {
		t.Fatalf("successful retry status = %#v", status)
	}
}

// TestProtocolSettingsRegisterAsLive registers every mail protocol setting
// with the managed configuration so none of them requires a restart.
func TestProtocolSettingsRegisterAsLive(t *testing.T) {
	cfgService, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := withTestBackground(t, &server{cfgService: cfgService, protocolControl: newTestProtocolControl(t)})
	if err := s.registerProtocolSettings(); err != nil {
		t.Fatal(err)
	}
	unapplied := cfgService.UnappliedKeys()
	for _, group := range protocolSettings {
		for _, key := range group.keys {
			if slices.Contains(unapplied, key) {
				t.Errorf("%s still requires a restart", key)
			}
		}
	}
	if slices.Contains(unapplied, "smtp_public_address") {
		t.Error("smtp_public_address still requires a restart")
	}
}

// TestSMTPHeloPolicyAppliesLive checks that helo_policy reaches the inbound
// SMTP listener and that a change applies to the next session.
func TestSMTPHeloPolicyAppliesLive(t *testing.T) {
	control := newTestProtocolControl(t)
	controllers := control.controllers
	controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{}})
	apply := func(mode string) {
		t.Helper()
		next := *controllers.config()
		next.HeloPolicy = mode
		if err := controllers.reconfigure(&next, &smtpProtocol); err != nil {
			t.Fatal(err)
		}
	}
	apply("reject")
	controllers.start(t.Context(), &smtpProtocol)
	status := smtpProtocol.state(controllers).status()
	if !status.Running || len(status.Listeners) != 1 {
		t.Fatalf("smtp status = %#v", status)
	}
	addr := status.Listeners[0]
	ehlo := func(name string) string {
		t.Helper()
		conn, reader, _ := smtpProbe.dial(t, addr, nil)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("EHLO " + name + "\r\n")); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	if line := ehlo("localhost"); !strings.HasPrefix(line, "504") {
		t.Fatalf("reject mode accepted an invalid HELO: %q", line)
	}
	if line := ehlo("mx.example.test"); !strings.HasPrefix(line, "250") {
		t.Fatalf("reject mode refused a valid HELO: %q", line)
	}
	apply("warn")
	if line := ehlo("localhost"); !strings.HasPrefix(line, "250") {
		t.Fatalf("warn mode refused an invalid HELO: %q", line)
	}
	apply("reject")
	if line := ehlo("192.0.2.1"); !strings.HasPrefix(line, "504") {
		t.Fatalf("reject mode did not apply live: %q", line)
	}
	apply("off")
	if line := ehlo("localhost"); !strings.HasPrefix(line, "250") {
		t.Fatalf("off mode refused an invalid HELO: %q", line)
	}
}

func testCertificate(t *testing.T, name string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
