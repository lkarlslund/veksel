package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
)

type mtastsResolverFunc func(context.Context, string) (mtasts.Result, error)

func (f mtastsResolverFunc) Resolve(ctx context.Context, domain string) (mtasts.Result, error) {
	return f(ctx, domain)
}

type recordingTLSReporter struct {
	mu     sync.Mutex
	events []tlsrpt.Event
}

func (r *recordingTLSReporter) Record(_ context.Context, event tlsrpt.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *recordingTLSReporter) snapshot() []tlsrpt.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]tlsrpt.Event(nil), r.events...)
}

// --- Tests for helper functions ---

func TestExtractDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr string
		want string
	}{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"  user@example.com  ", "example.com"},
		{"User@Example.COM", "example.com"},
		{"user@sub.example.com", "sub.example.com"},
		{"invalid", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractDomain(tt.addr)
		if got != tt.want {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestParseReply(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line     string
		wantCode int
		wantText string
	}{
		{"220 ESMTP Veksel", 220, "ESMTP Veksel"},
		{"250-Hello", 250, "Hello"},
		{"250 OK", 250, "OK"},
		{"550 User unknown", 550, "User unknown"},
		{"354 Send message data", 354, "Send message data"},
		{"235 Authentication successful", 235, "Authentication successful"},
	}
	for _, tt := range tests {
		code, text := parseReply(tt.line)
		if code != tt.wantCode {
			t.Errorf("parseReply(%q) code = %d, want %d", tt.line, code, tt.wantCode)
		}
		if text != tt.wantText {
			t.Errorf("parseReply(%q) text = %q, want %q", tt.line, text, tt.wantText)
		}
	}
}

func TestDotStuff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "no dots at line start",
			in:   "Hello World\r\nNo dots here",
			want: "Hello World\r\nNo dots here",
		},
		{
			name: "dot at line start",
			in:   "Hello\r\n.World",
			want: "Hello\r\n..World",
		},
		{
			name: "multiple dots at line start",
			in:   "Line1\r\n.Dot1\r\n.Dot2",
			want: "Line1\r\n..Dot1\r\n..Dot2",
		},
		{
			name: "dot in middle of line",
			in:   "Hello.World",
			want: "Hello.World",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dotStuff([]byte(tt.in))
			if string(got) != tt.want {
				t.Errorf("dotStuff() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestContainsExtension(t *testing.T) {
	t.Parallel()
	exts := []string{"ESMTP", "STARTTLS", "AUTH PLAIN LOGIN", "PIPELINING", "8BITMIME"}
	if !containsExtension(exts, "STARTTLS") {
		t.Error("expected STARTTLS in extensions")
	}
	if !containsExtension(exts, "starttls") {
		t.Error("expected case-insensitive STARTTLS match")
	}
	if containsExtension(exts, "DSN") {
		t.Error("did not expect DSN in extensions")
	}
}

func TestParseEHLO(t *testing.T) {
	t.Parallel()
	replies := []smtpReply{
		{code: 250, text: "mail.example.com", raw: "250 mail.example.com"},
		{code: 250, text: "STARTTLS", raw: "250-STARTTLS"},
		{code: 250, text: "AUTH PLAIN LOGIN", raw: "250-AUTH PLAIN LOGIN"},
		{code: 250, text: "PIPELINING", raw: "250 PIPELINING"},
	}
	exts := parseEHLO(replies)
	if len(exts) != 4 {
		t.Fatalf("expected 4 extensions, got %d", len(exts))
	}
	if !containsExtension(exts, "STARTTLS") {
		t.Error("expected STARTTLS in parsed extensions")
	}
	if !containsExtension(exts, "AUTH PLAIN LOGIN") {
		t.Error("expected AUTH PLAIN LOGIN in parsed extensions")
	}
}

func TestRelayConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg := &RelayConfig{
		Host: "smtp.example.com",
	}
	client := NewRelayClient(cfg)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.cfg.Host != "smtp.example.com" {
		t.Errorf("expected host smtp.example.com, got %s", client.cfg.Host)
	}
}

func TestRelayMTA_STSEnforcementRejectsUnauthorizedMXBeforeDial(t *testing.T) {
	var resolvedDomain string
	reporter := &recordingTLSReporter{}
	client := NewRelayClient(&RelayConfig{
		LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "wrong.example.test.", Pref: 10}}, nil
		},
		MTASTS: mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
			resolvedDomain = domain
			return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "one", Mode: mtasts.ModeEnforce, MX: []string{"mx.example.test"}}, Source: mtasts.SourceCache}, nil
		}),
		TLSReporter: reporter,
	})
	err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "4.7.5") || !strings.Contains(err.Error(), "does not authorize MX") {
		t.Fatalf("Deliver() error = %v", err)
	}
	if resolvedDomain != "example.test" {
		t.Fatalf("policy domain = %q", resolvedDomain)
	}
	events := reporter.snapshot()
	if len(events) != 1 || events[0].ResultType != tlsrpt.ResultValidationFailure || events[0].FailureReasonCode != "mx-not-authorized-by-sts-policy" {
		t.Fatalf("TLS report events = %#v", events)
	}
}

func TestRelayMTA_STSEnforcementRequiresSTARTTLS(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	_, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	client := NewRelayClient(&RelayConfig{
		Host: "localhost", Port: port,
		MTASTS: mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
			if domain != "localhost" {
				t.Fatalf("smart-host policy domain = %q", domain)
			}
			return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "one", Mode: mtasts.ModeEnforce, MX: []string{"localhost"}}}, nil
		}),
	})
	err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "4.7.5 STARTTLS required") {
		t.Fatalf("Deliver() error = %v", err)
	}
}

func TestRelayMTA_STSEnforcementCannotBypassCertificateValidation(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t))
	defer srv.Close()
	_, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	reporter := &recordingTLSReporter{}
	client := NewRelayClient(&RelayConfig{
		Host: "localhost", Port: port, TLSSkipVerify: true,
		MTASTS: mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
			return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "one", Mode: mtasts.ModeEnforce, MX: []string{"localhost"}}}, nil
		}),
		TLSReporter: reporter,
	})
	err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "4.7.5 MTA-STS TLS handshake") {
		t.Fatalf("Deliver() error = %v", err)
	}
	events := reporter.snapshot()
	if len(events) != 1 || events[0].Success || events[0].ResultType == "" {
		t.Fatalf("TLS report events = %#v", events)
	}
}

func TestRelayMTA_STSTestingModeDoesNotBlockPlaintext(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	_, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	reporter := &recordingTLSReporter{}
	client := NewRelayClient(&RelayConfig{
		Host: "localhost", Port: port,
		MTASTS: mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
			return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "one", Mode: mtasts.ModeTesting, MX: []string{"different.example.test"}}}, nil
		}),
		TLSReporter: reporter,
	})
	if err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body")); err != nil {
		t.Fatalf("testing-mode delivery failed: %v", err)
	}
	events := reporter.snapshot()
	if len(events) != 1 || events[0].ResultType != tlsrpt.ResultSTARTTLSNotSupported || events[0].Policy.Type != tlsrpt.PolicyTypeSTS {
		t.Fatalf("TLS report events = %#v", events)
	}
}

func TestRelayReportsPolicyRefreshFailureAndSessionOutcome(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	_, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	reporter := &recordingTLSReporter{}
	client := NewRelayClient(&RelayConfig{Host: "localhost", Port: port, TLSReporter: reporter,
		MTASTS: mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
			return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "cached", Mode: mtasts.ModeTesting, MX: []string{"localhost"}},
				Source: mtasts.SourceCache, Failure: &mtasts.Failure{Type: mtasts.FailureHTTPS, Message: "remote detail must not be copied"}}, nil
		})})
	ctx := tlsrpt.WithAttemptID(t.Context(), "attempt-1")
	if err := client.Deliver(ctx, "sender@example.test", "user@example.test", nil, []byte("body")); err != nil {
		t.Fatal(err)
	}
	events := reporter.snapshot()
	if len(events) != 2 || events[0].ResultType != tlsrpt.ResultSTSPolicyFetchError || events[0].FailureReasonCode != mtasts.FailureHTTPS || events[1].ResultType != tlsrpt.ResultSTARTTLSNotSupported {
		t.Fatalf("TLS report events = %#v", events)
	}
	for _, event := range events {
		if event.AttemptID != "attempt-1" || strings.Contains(event.FailureReasonCode, "remote detail") {
			t.Fatalf("unsafe or missing event identity = %#v", event)
		}
	}
}

func TestRelayMTA_STSCacheFailureDefersDelivery(t *testing.T) {
	client := NewRelayClient(&RelayConfig{
		Host: "relay.example.test",
		MTASTS: mtastsResolverFunc(func(context.Context, string) (mtasts.Result, error) {
			return mtasts.Result{}, errors.New("disk unavailable")
		}),
	})
	err := client.Deliver(t.Context(), "sender@example.test", "user@example.test", nil, []byte("body"))
	if err == nil || !strings.Contains(err.Error(), "4.7.5 MTA-STS policy cache unavailable") {
		t.Fatalf("Deliver() error = %v", err)
	}
}

func TestRelayTLSReportDeliverySuppressesPolicyAndRecursiveReporting(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	_, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	var policyCalls atomic.Int32
	reporter := &recordingTLSReporter{}
	client := NewRelayClient(&RelayConfig{Host: "localhost", Port: port, TLSReporter: reporter,
		MTASTS: mtastsResolverFunc(func(_ context.Context, domain string) (mtasts.Result, error) {
			policyCalls.Add(1)
			return mtasts.Result{Policy: &mtasts.Policy{PolicyDomain: domain, PolicyID: "enforce", Mode: mtasts.ModeEnforce, MX: []string{"localhost"}}}, nil
		})})
	ctx := tlsrpt.Suppress(tlsrpt.WithAttemptID(t.Context(), "report-attempt"))
	if err := client.Deliver(ctx, "tlsrpt@sender.test", "reports@example.test", nil, []byte("report")); err != nil {
		t.Fatal(err)
	}
	if policyCalls.Load() != 0 || len(reporter.snapshot()) != 0 {
		t.Fatalf("suppressed delivery called policy %d times and recorded %#v", policyCalls.Load(), reporter.snapshot())
	}
}

// --- Integration tests with mock SMTP server ---

// mockSMTPServer is a minimal SMTP server for testing relay delivery.
type mockSMTPServer struct {
	ln            net.Listener
	responses     map[string]string // command prefix -> response
	startTLS      bool              // whether to support STARTTLS
	tlsCert       tls.Certificate
	authUser      string
	rejectRCPT    bool // whether to reject RCPT TO
	dropAfterData bool // close after the terminating dot without a final reply
	dsn           bool
	requireTLS    bool
	mu            sync.Mutex
	commands      []string
	data          string // last DATA content, dot-stuffing intact
}

func newMockSMTP(t *testing.T, opts ...mockSMTPOpt) *mockSMTPServer {
	m := &mockSMTPServer{
		responses: make(map[string]string),
	}
	for _, opt := range opts {
		opt(m)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m.ln = ln

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		m.handle(conn)
	}()

	return m
}

type mockSMTPOpt func(*mockSMTPServer)

func mockWithTLS(t *testing.T) mockSMTPOpt {
	return func(m *mockSMTPServer) {
		m.startTLS = true
		// Generate self-signed cert
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "mock-smtp.test",
			},
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(time.Hour),
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			t.Fatalf("create cert: %v", err)
		}
		keyBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("X509KeyPair: %v", err)
		}
		m.tlsCert = cert
	}
}

func mockRejectRCPT() mockSMTPOpt {
	return func(m *mockSMTPServer) {
		m.rejectRCPT = true
	}
}

func mockDropAfterData() mockSMTPOpt {
	return func(m *mockSMTPServer) { m.dropAfterData = true }
}

func mockWithDSN() mockSMTPOpt {
	return func(m *mockSMTPServer) { m.dsn = true }
}

func mockWithRequireTLS() mockSMTPOpt {
	return func(m *mockSMTPServer) { m.requireTLS = true }
}

func (m *mockSMTPServer) Addr() string {
	return m.ln.Addr().String()
}

func (m *mockSMTPServer) Close() {
	m.ln.Close()
}

func (m *mockSMTPServer) handle(conn net.Conn) {
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	secure := false

	// Send greeting
	fmt.Fprintf(rw, "220 mock-smtp ESMTP\r\n")
	rw.Flush()

	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m.mu.Lock()
		m.commands = append(m.commands, line)
		m.mu.Unlock()

		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			var resp string
			resp = "250-mock-smtp\r\n"
			if m.startTLS {
				resp += "250-STARTTLS\r\n"
			}
			if secure && m.requireTLS {
				resp += "250-REQUIRETLS\r\n"
			}
			if m.authUser != "" {
				resp += "250-AUTH PLAIN LOGIN\r\n"
			}
			if m.dsn {
				resp += "250-DSN\r\n"
			}
			resp += "250 PIPELINING\r\n"
			fmt.Fprint(rw, resp)
		case strings.HasPrefix(upper, "STARTTLS"):
			if !m.startTLS {
				fmt.Fprintf(rw, "502 Not implemented\r\n")
			} else {
				fmt.Fprintf(rw, "220 Ready to start TLS\r\n")
				rw.Flush()

				// Upgrade to TLS
				tlsConn := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{m.tlsCert},
					MinVersion:   tls.VersionTLS12,
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				secure = true
				rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
			}
		case strings.HasPrefix(upper, "AUTH"):
			if m.authUser == "" {
				fmt.Fprintf(rw, "502 Not implemented\r\n")
			} else {
				fmt.Fprintf(rw, "235 Authentication successful\r\n")
			}
		case strings.HasPrefix(upper, "MAIL FROM"):
			fmt.Fprintf(rw, "250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO"):
			if m.rejectRCPT {
				fmt.Fprintf(rw, "550 User unknown\r\n")
			} else {
				fmt.Fprintf(rw, "250 OK\r\n")
			}
		case strings.HasPrefix(upper, "DATA"):
			fmt.Fprintf(rw, "354 Send data\r\n")
			rw.Flush()
			// Read until terminating dot
			var data strings.Builder
			for {
				dl, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(dl) == "." {
					break
				}
				data.WriteString(dl)
			}
			m.mu.Lock()
			m.data = data.String()
			m.mu.Unlock()
			if m.dropAfterData {
				return
			}
			fmt.Fprintf(rw, "250 Message accepted\r\n")
		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprintf(rw, "221 Bye\r\n")
			rw.Flush()
			return
		default:
			fmt.Fprintf(rw, "502 Not implemented\r\n")
		}
		rw.Flush()
	}
}

func TestRelayRequireTLSUsesVerifiedTLSAndPropagatesMailParameter(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t), mockWithRequireTLS())
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	leaf, err := x509.ParseCertificate(srv.tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	client := NewRelayClient(&RelayConfig{Host: host, Port: port, ServerName: "test.veksel", TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
	if err := client.DeliverWithOptions(t.Context(), "sender@example.test", "recipient@example.test", map[string]string{"Subject": "secure"}, []byte("body"), DSNEnvelopeOptions{RequireTLS: true}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	commands := strings.Join(srv.commands, "\n")
	srv.mu.Unlock()
	if !strings.Contains(commands, "STARTTLS") || !strings.Contains(commands, "MAIL FROM:<sender@example.test> REQUIRETLS") {
		t.Fatalf("commands:\n%s", commands)
	}
}

func TestRelayRequireTLSFailsBeforeMailWhenPeerLacksCapability(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t))
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	leaf, _ := x509.ParseCertificate(srv.tlsCert.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	client := NewRelayClient(&RelayConfig{Host: host, Port: port, TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
	err := client.DeliverWithOptions(t.Context(), "sender@example.test", "recipient@example.test", nil, []byte("body"), DSNEnvelopeOptions{RequireTLS: true})
	if err == nil || !strings.Contains(err.Error(), "5.7.30") {
		t.Fatalf("error = %v", err)
	}
	srv.mu.Lock()
	commands := strings.Join(srv.commands, "\n")
	srv.mu.Unlock()
	if strings.Contains(commands, "MAIL FROM") {
		t.Fatalf("message transmitted before capability proof:\n%s", commands)
	}
}

func TestRelayRequireTLSDirectMXNeedsAuthenticatedPolicy(t *testing.T) {
	client := NewRelayClient(&RelayConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
		return []*net.MX{{Host: "mx.example.test", Pref: 10}}, nil
	}})
	err := client.DeliverWithOptions(t.Context(), "sender@example.test", "recipient@example.test", nil, nil, DSNEnvelopeOptions{RequireTLS: true})
	if err == nil || !strings.Contains(err.Error(), "5.7.30") {
		t.Fatalf("error = %v", err)
	}
}

func TestRelayTLSOptionalSkipsRecipientPolicy(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	var calls atomic.Int32
	client := NewRelayClient(&RelayConfig{Host: host, Port: port, MTASTS: mtastsResolverFunc(func(context.Context, string) (mtasts.Result, error) {
		calls.Add(1)
		return mtasts.Result{}, errors.New("policy unavailable")
	})})
	if err := client.DeliverWithOptions(t.Context(), "sender@example.test", "recipient@example.test", nil, []byte("body"), DSNEnvelopeOptions{TLSOptional: true}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("policy resolver calls = %d", calls.Load())
	}
}

func TestRelayPropagatesDSNEnvelopeOptions(t *testing.T) {
	srv := newMockSMTP(t, mockWithDSN())
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	client := NewRelayClient(&RelayConfig{Host: host, Port: port, ServerName: "test.veksel"})
	err := client.DeliverWithOptions(t.Context(), "sender@example.test", "recipient@example.test", map[string]string{"Subject": "DSN"}, []byte("body"), DSNEnvelopeOptions{
		Return: "hdrs", EnvelopeID: "job+2Bid", Notify: "failure,delay", OriginalRecipient: "rfc822;old+40example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	commands := append([]string(nil), srv.commands...)
	srv.mu.Unlock()
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "MAIL FROM:<sender@example.test> RET=HDRS ENVID=job+2Bid") ||
		!strings.Contains(joined, "RCPT TO:<recipient@example.test> NOTIFY=FAILURE,DELAY ORCPT=rfc822;old+40example.test") {
		t.Fatalf("commands:\n%s", joined)
	}
}

func TestRelayDeliver_Plain(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	client := NewRelayClient(&RelayConfig{
		Host:       host,
		Port:       port,
		ServerName: "test.veksel",
	})

	headers := map[string]string{
		"From":    "sender@example.com",
		"To":      "recipient@external.com",
		"Subject": "Test Delivery",
	}
	body := []byte("Hello from relay")

	err := client.Deliver(context.Background(), "sender@example.com", "recipient@external.com", headers, body)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}
}

func TestRelayDeliverMessageSendsExactBytes(t *testing.T) {
	srv := newMockSMTP(t)
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	client := NewRelayClient(&RelayConfig{Host: host, Port: port, ServerName: "test.veksel"})
	message := "Received: from b by c; Mon, 1 Jan 2024 00:00:01 +0000\r\n" +
		"Received: from a\r\n\tby b; Mon, 1 Jan 2024 00:00:00 +0000\r\n" +
		"Subject: exact\r\n\r\n.leading dot\r\n"
	if err := client.DeliverMessage(t.Context(), "sender@example.test", "recipient@example.test", []byte(message), DSNEnvelopeOptions{}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	data := srv.data
	srv.mu.Unlock()
	if want := strings.Replace(message, "\r\n.leading", "\r\n..leading", 1); data != want {
		t.Fatalf("relayed DATA\n%q\nwant\n%q", data, want)
	}
}

func TestRelayDeliverMarksMissingFinalDataReplyUncertain(t *testing.T) {
	srv := newMockSMTP(t, mockDropAfterData())
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr())
	var port int
	_, _ = fmt.Sscanf(portText, "%d", &port)
	client := NewRelayClient(&RelayConfig{Host: host, Port: port, ServerName: "test.veksel"})
	err := client.Deliver(t.Context(), "sender@example.test", "recipient@example.test", map[string]string{"Subject": "uncertain"}, []byte("body"))
	if err == nil || !IsDeliveryUncertain(err) {
		t.Fatalf("delivery error = %v, uncertain=%v", err, IsDeliveryUncertain(err))
	}
}

func TestRelayDeliver_ConnectionRefused(t *testing.T) {
	client := NewRelayClient(&RelayConfig{
		Host: "127.0.0.1",
		Port: 59999,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.Deliver(ctx, "sender@example.com", "recipient@example.com",
		map[string]string{"Subject": "Test"}, []byte("body"))
	if err == nil {
		t.Fatal("expected error for connection refused, got nil")
	}
	if !strings.Contains(err.Error(), "connection refused") &&
		!strings.Contains(err.Error(), "dial") {
		t.Errorf("expected connection refused error, got: %v", err)
	}
}

func TestRelayDeliver_WithTLS(t *testing.T) {
	srv := newMockSMTP(t, mockWithTLS(t))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	client := NewRelayClient(&RelayConfig{
		Host:          host,
		Port:          port,
		ServerName:    "test.veksel",
		TLSSkipVerify: true, // self-signed cert
	})

	headers := map[string]string{
		"From":    "sender@example.com",
		"To":      "recipient@external.com",
		"Subject": "TLS Test",
	}
	body := []byte("Hello over TLS")

	err := client.Deliver(context.Background(), "sender@example.com", "recipient@external.com", headers, body)
	if err != nil {
		t.Fatalf("Deliver with TLS failed: %v", err)
	}
}

func TestRelayDeliver_BadRecipient(t *testing.T) {
	srv := newMockSMTP(t, mockRejectRCPT())
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	client := NewRelayClient(&RelayConfig{
		Host:       host,
		Port:       port,
		ServerName: "test.veksel",
	})

	err := client.Deliver(context.Background(), "sender@example.com", "nobody@example.com",
		map[string]string{"Subject": "Test"}, []byte("body"))
	if err == nil {
		t.Fatal("expected error for bad recipient, got nil")
	}
	if !strings.Contains(err.Error(), "RCPT TO") {
		t.Errorf("expected RCPT TO error, got: %v", err)
	}
}

func TestRelayResolve_WithHost(t *testing.T) {
	client := NewRelayClient(&RelayConfig{
		Host: "smtp.relay.com",
		Port: 587,
	})

	host, port, err := client.resolve(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if host != "smtp.relay.com" {
		t.Errorf("host = %q, want %q", host, "smtp.relay.com")
	}
	if port != 587 {
		t.Errorf("port = %d, want %d", port, 587)
	}
}

func TestRelayResolve_DefaultPort(t *testing.T) {
	client := NewRelayClient(&RelayConfig{
		Host: "smtp.relay.com",
	})

	_, port, err := client.resolve(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if port != 587 {
		t.Errorf("port = %d, want default 587", port)
	}
}

func TestRelayResolve_NoDomain(t *testing.T) {
	client := NewRelayClient(&RelayConfig{})

	_, _, err := client.resolve(context.Background(), "invalid")
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
}

// TestRelayOpportunisticTLSDeliversToUnverifiedCertificate follows RFC 7435:
// without a TLS requirement, a certificate that does not authenticate the
// host leaves the session encrypted but unauthenticated, and mail is
// delivered. Requiring TLS keeps verification mandatory.
func TestRelayOpportunisticTLSDeliversToUnverifiedCertificate(t *testing.T) {
	for _, require := range []bool{false, true} {
		srv := newMockSMTP(t, mockWithTLS(t))
		host, portStr, _ := net.SplitHostPort(srv.Addr())
		port, _ := strconv.Atoi(portStr)
		client := NewRelayClient(&RelayConfig{Host: host, Port: port, ServerName: "test.veksel", RequireTLS: require})
		err := client.Deliver(context.Background(), "sender@example.com", "recipient@external.com", map[string]string{"Subject": "TLS"}, []byte("body"))
		srv.Close()
		if require && (err == nil || !strings.Contains(err.Error(), "TLS handshake")) {
			t.Fatalf("required TLS accepted an unverified certificate: %v", err)
		}
		if !require && err != nil {
			t.Fatalf("opportunistic TLS refused delivery: %v", err)
		}
	}
}
