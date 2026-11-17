package main

import (
	"bufio"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
)

// TestMailProxyProtocolAppliesLive enables, retargets, and disables the PROXY
// protocol on a running IMAP listener without rebinding it.
func TestMailProxyProtocolAppliesLive(t *testing.T) {
	control := newTestProtocolControl(t)
	controllers := control.controllers
	apply := func(entries, trusted []string) {
		t.Helper()
		next := *controllers.config()
		next.MailProxyProtocol, next.MailProxyProtocolTrusted = entries, trusted
		if err := controllers.reconfigure(&next, &imapProtocol); err != nil {
			t.Fatal(err)
		}
	}
	controllers.start(t.Context(), &imapProtocol)
	status := imapProtocol.state(controllers).status()
	if len(status.Listeners) != 1 {
		t.Fatalf("imap status = %#v", status)
	}
	addr := status.Listeners[0]
	// firstLine sends prefix and returns the server's first line, empty when
	// the server closes the connection instead.
	firstLine := func(prefix string) string {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if prefix != "" {
			if _, err := io.WriteString(conn, prefix); err != nil {
				t.Fatal(err)
			}
		}
		line, _ := bufio.NewReader(conn).ReadString('\n')
		return line
	}
	const header = "PROXY TCP4 203.0.113.7 192.0.2.1 40000 143\r\n"
	served := func(line string) bool { return strings.HasPrefix(line, "* OK") }

	if !served(firstLine("")) {
		t.Fatal("direct connection refused before PROXY protocol was enabled")
	}
	apply([]string{"imap"}, []string{"127.0.0.1"})
	if !served(firstLine(header)) {
		t.Fatal("trusted proxy header not accepted after enabling")
	}
	if line := firstLine("a1 CAPABILITY\r\n"); line != "" {
		t.Fatalf("trusted source without a header was served: %q", line)
	}

	// The proxy is no longer trusted: direct connections are served and a
	// header is refused.
	apply([]string{"IMAP-STARTTLS"}, []string{"192.0.2.10/32"})
	if !served(firstLine("")) {
		t.Fatal("untrusted direct connection refused")
	}
	if line := firstLine(header + "a1 NOOP\r\n"); strings.Contains(line, "a1 OK") {
		t.Fatalf("untrusted header honoured: %q", line)
	}

	// Selecting another listener leaves this one direct.
	apply([]string{"imaps"}, []string{"127.0.0.1"})
	if !served(firstLine("")) {
		t.Fatal("listener not selected by mail_proxy_protocol still requires a header")
	}
	apply(nil, nil)
	if !served(firstLine("")) || imapProtocol.state(controllers).status().Listeners[0] != addr {
		t.Fatal("disabling PROXY protocol did not apply to the running listener")
	}
}

// TestProxyListenerNamesAreConfigurable keeps the listener names accepted by
// mail_proxy_protocol in step with the listeners each protocol plans.
func TestProxyListenerNamesAreConfigurable(t *testing.T) {
	protocols := map[string]string{
		"SMTP": "smtp", "submission": "smtp", "SMTPS": "smtp",
		"IMAP": "imap", "IMAPS": "imap", "POP3": "pop3", "POP3S": "pop3",
		"ManageSieve": "managesieve", "ManageSieve TLS": "managesieve",
	}
	if len(protocols) != len(proxyListenerNames) {
		t.Fatalf("proxyListenerNames covers %d listeners, want %d", len(proxyListenerNames), len(protocols))
	}
	for listener, protocol := range protocols {
		name, ok := proxyListenerNames[listener]
		if !ok || !slices.Contains(config.MailProxyProtocolTargets[protocol], name) {
			t.Errorf("listener %s is named %q, not one of the %s targets %v", listener, name, protocol, config.MailProxyProtocolTargets[protocol])
		}
		cfg := config.Default()
		cfg.MailProxyProtocol, cfg.MailProxyProtocolTrusted = []string{name}, []string{"10.0.0.1"}
		if mailProxyPolicy(cfg, protocol, listener) == nil {
			t.Errorf("mail_proxy_protocol %q does not enable listener %s", name, listener)
		}
		cfg.MailProxyProtocol = []string{protocol}
		if mailProxyPolicy(cfg, protocol, listener) == nil {
			t.Errorf("mail_proxy_protocol %q does not enable listener %s", protocol, listener)
		}
	}
}
