package main

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// TestSMTPScreeningAppliesLive changes the connection screening settings and
// checks that the next session of a PROXY-relayed public client follows them.
func TestSMTPScreeningAppliesLive(t *testing.T) {
	control := newTestProtocolControl(t)
	controllers := control.controllers
	controllers.cfg.MailProxyProtocol, controllers.cfg.MailProxyProtocolTrusted = []string{"smtp"}, []string{"127.0.0.1"}
	controllers.setSMTPDependencies(smtpDependencies{delivery: &smtp.Delivery{}})
	apply := func(change func(*config.Config)) {
		t.Helper()
		next := *controllers.config()
		change(&next)
		if err := controllers.reconfigure(&next, &smtpProtocol); err != nil {
			t.Fatal(err)
		}
	}
	apply(func(cfg *config.Config) { cfg.SmtpGreetDelayMs, cfg.SmtpPregreetAction = 300, "reject" })
	controllers.start(t.Context(), &smtpProtocol)
	addr := smtpProtocol.state(controllers).status().Listeners[0]

	// earlyTalker sends EHLO right after the PROXY header and returns the
	// server's lines until it closes or a final non-220- line arrives.
	earlyTalker := func(client string) []string {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "PROXY TCP4 "+client+" 192.0.2.1 40000 25\r\nEHLO early.example.net\r\n"); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return lines
			}
			lines = append(lines, strings.TrimSpace(line))
			if !strings.HasPrefix(line, "220-") {
				return lines
			}
		}
	}
	if lines := earlyTalker("198.51.100.20"); len(lines) != 2 || !strings.HasPrefix(lines[1], "554 5.7.1") {
		t.Fatalf("reject mode served an early talker: %q", lines)
	}
	apply(func(cfg *config.Config) { cfg.SmtpPregreetAction = "score" })
	if lines := earlyTalker("198.51.100.21"); len(lines) != 2 || !strings.HasPrefix(lines[1], "220 ") {
		t.Fatalf("score mode did not finish the greeting: %q", lines)
	}
	apply(func(cfg *config.Config) { cfg.SmtpGreetDelayMs = 0 })
	if lines := earlyTalker("198.51.100.22"); len(lines) != 1 || !strings.HasPrefix(lines[0], "220 ") {
		t.Fatalf("a disabled greeting delay still tested: %q", lines)
	}
	apply(func(cfg *config.Config) {
		cfg.SmtpGreetDelayMs, cfg.SmtpPregreetAction = 300, "reject"
		cfg.MailConnectionLimitExempt = []string{"198.51.100.0/24"}
	})
	if lines := earlyTalker("198.51.100.23"); len(lines) != 1 || !strings.HasPrefix(lines[0], "220 ") {
		t.Fatalf("an exempt client was tested: %q", lines)
	}
}

// TestSMTPScreeningSettings maps the managed settings onto the inbound
// listener's screening and keeps one cache across configurations.
func TestSMTPScreeningSettings(t *testing.T) {
	controllers := &protocolControllers{}
	cfg := config.Default()
	cfg.SmtpGreetDelayMs, cfg.SmtpPregreetAction, cfg.SmtpProtocolViolationLimit = 1500, "reject", 7
	cfg.SmtpTarpitAfterUnknownRcpts, cfg.SmtpFcrdnsCheck = 4, false
	cfg.MailConnectionLimitExempt = []string{"192.0.2.0/24"}
	first, second := controllers.smtpScreening(cfg), controllers.smtpScreening(config.Default())
	if first.GreetDelay != 1500*time.Millisecond || first.Pregreet != smtp.PregreetReject || first.ViolationLimit != 7 ||
		first.TarpitAfterUnknownRcpts != 4 || first.FCrDNS {
		t.Fatalf("screening = %+v", first)
	}
	for _, prefix := range []string{"127.0.0.0/8", "::1/128", "192.0.2.0/24"} {
		if !slices.Contains(first.Exempt, netip.MustParsePrefix(prefix)) {
			t.Errorf("%s is not exempt: %v", prefix, first.Exempt)
		}
	}
	if first.Cache == nil || first.Cache != second.Cache {
		t.Fatal("configurations do not share the screening cache")
	}
	if defaults := config.Default(); defaults.SmtpGreetDelayMs != 2000 || defaults.SmtpPregreetAction != "score" || !defaults.SmtpFcrdnsCheck {
		t.Fatalf("defaults = %d %q %v", defaults.SmtpGreetDelayMs, defaults.SmtpPregreetAction, defaults.SmtpFcrdnsCheck)
	}
}
