package smtp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
)

// spfTestResolver is an in-memory DNS for SPF policy tests.
type spfTestResolver struct {
	txt  map[string][]string
	host map[string][]string
}

func spfNotFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r spfTestResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := r.txt[name]; ok {
		return v, nil
	}
	return nil, spfNotFound(name)
}

func (r spfTestResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, spfNotFound(name)
}

func (r spfTestResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	if v, ok := r.host[name]; ok {
		return v, nil
	}
	return nil, spfNotFound(name)
}

func (r spfTestResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, spfNotFound(addr)
}

// spfTestZone publishes a Google-style include chain for example.com and
// a HELO policy for mx.example.net.
func spfTestZone() spfTestResolver {
	return spfTestResolver{txt: map[string][]string{
		"example.com":             {"v=spf1 include:_spf.example.net -all"},
		"_spf.example.net":        {"v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 ~all"},
		"soft.example.com":        {"v=spf1 ~all"},
		"broken.example.com":      {"v=spf1 include:gone.example.com -all"},
		"mx.example.net":          {"v=spf1 a -all"},
		"explained.example.com":   {"v=spf1 exp=why.example.com -all"},
		"why.example.com":         {"%{i} is not authorized\r\nby %{d}"},
		"two.example.com":         {"v=spf1 -all", "v=spf1 +all"},
		"uppercase.example.com":   {"v=spf1 +all"},
		"nonexistent.example.com": nil,
	}, host: map[string][]string{"mx.example.net": {"198.51.100.7"}}}
}

func spfTestPolicy(mode SpfPolicyMode) *SpfPolicy {
	return &SpfPolicy{Mode: mode, Resolver: spfTestZone()}
}

func TestEvaluateSPFOffAndNilPolicy(t *testing.T) {
	t.Parallel()
	for _, policy := range []*SpfPolicy{nil, {Mode: SpfPolicyOff}} {
		result := EvaluateSPF(t.Context(), policy, "sender@example.com", "mx.example.net", "203.0.113.1")
		if result.Result != "skip" || !result.Pass {
			t.Errorf("policy %+v = %+v, want pass skip", policy, result)
		}
	}
}

func TestEvaluateSPFResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, sender, helo, ip string
		mode                   SpfPolicyMode
		want                   string
		pass, reject           bool
		domain                 string
	}{
		{"include pass", "user@example.com", "mx.example.net", "203.0.113.9", SpfPolicyReject, "pass", true, false, "example.com"},
		{"include pass v6", "user@example.com", "mx.example.net", "2001:db8::25", SpfPolicyReject, "pass", true, false, "example.com"},
		{"mapped v4 client", "user@example.com", "mx.example.net", "::ffff:203.0.113.9", SpfPolicyReject, "pass", true, false, "example.com"},
		{"fail rejects", "user@example.com", "mx.example.net", "198.51.100.1", SpfPolicyReject, "fail", false, true, "example.com"},
		{"fail warns", "user@example.com", "mx.example.net", "198.51.100.1", SpfPolicyWarn, "fail", false, false, "example.com"},
		{"softfail is not rejected", "user@soft.example.com", "mx.example.net", "198.51.100.1", SpfPolicyReject, "softfail", false, false, "soft.example.com"},
		{"permerror is not rejected", "user@broken.example.com", "mx.example.net", "198.51.100.1", SpfPolicyReject, "permerror", true, false, "broken.example.com"},
		{"multiple records", "user@two.example.com", "mx.example.net", "198.51.100.1", SpfPolicyReject, "permerror", true, false, "two.example.com"},
		{"no record", "user@nonexistent.example.com", "mx.example.net", "198.51.100.1", SpfPolicyReject, "none", true, false, "nonexistent.example.com"},
		{"angle brackets and case", "<user@UPPERCASE.example.com>", "mx.example.net", "198.51.100.1", SpfPolicyReject, "pass", true, false, "uppercase.example.com"},
		{"null sender checks helo", "", "mx.example.net", "198.51.100.7", SpfPolicyReject, "pass", true, false, "mx.example.net"},
		{"null sender helo fail", "", "mx.example.net", "198.51.100.8", SpfPolicyReject, "fail", false, true, "mx.example.net"},
		{"null sender literal helo", "", "[198.51.100.8]", "198.51.100.8", SpfPolicyReject, "none", true, false, "[198.51.100.8]"},
		{"invalid sender", "no-at-sign", "mx.example.net", "198.51.100.1", SpfPolicyWarn, "permerror", true, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := EvaluateSPF(t.Context(), spfTestPolicy(tc.mode), tc.sender, tc.helo, tc.ip)
			if result.Result != tc.want || result.Pass != tc.pass || result.ShouldReject != tc.reject || result.SenderDomain != tc.domain {
				t.Fatalf("got %+v", result)
			}
			if tc.reject && (result.RejectionCode != 550 || !strings.HasPrefix(result.RejectionText, "5.7.23 ")) {
				t.Fatalf("rejection = %d %q", result.RejectionCode, result.RejectionText)
			}
			if !strings.HasPrefix(result.HeaderValue, tc.want) || !strings.Contains(result.HeaderValue, "client-ip="+tc.ip+";") {
				t.Fatalf("Received-SPF = %q", result.HeaderValue)
			}
		})
	}
}

func TestEvaluateSPFIdentityAndExplanation(t *testing.T) {
	t.Parallel()
	result := EvaluateSPF(t.Context(), spfTestPolicy(SpfPolicyReject), "", "mx.example.net", "198.51.100.7")
	if result.Identity != "helo" || result.Mechanism != "a" {
		t.Fatalf("helo identity = %+v", result)
	}
	if want := `pass (domain of postmaster@mx.example.net designates 198.51.100.7 as permitted sender) client-ip=198.51.100.7; envelope-from=""; helo="mx.example.net"; identity=helo; mechanism="a";`; result.HeaderValue != want {
		t.Fatalf("Received-SPF:\ngot  %s\nwant %s", result.HeaderValue, want)
	}
	result = EvaluateSPF(t.Context(), spfTestPolicy(SpfPolicyReject), "user@explained.example.com", "mx.example.net", "198.51.100.1")
	if result.Identity != "mailfrom" || result.RejectionText != "5.7.23 SPF validation failed: 198.51.100.1 is not authorizedby explained.example.com" {
		t.Fatalf("explanation = %+v", result)
	}
	result = EvaluateSPF(t.Context(), spfTestPolicy(SpfPolicyWarn), "user@broken.example.com", "mx.example.net", "198.51.100.1")
	if !strings.Contains(result.Problem, "gone.example.com") || !strings.Contains(result.HeaderValue, `problem="`) {
		t.Fatalf("problem = %+v", result)
	}
}

func TestEvaluateSPFLocalIPSkipped(t *testing.T) {
	t.Parallel()
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "::1"} {
		for _, sender := range []string{"sender@example.com", ""} {
			result := EvaluateSPF(t.Context(), spfTestPolicy(SpfPolicyReject), sender, "mx.example.net", ip)
			if result.Result != "skip" || !result.Pass {
				t.Errorf("%s %q = %+v, want skip", ip, sender, result)
			}
		}
	}
}

func TestSPFAuthenticationResultsEntry(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		result *SpfResult
		sender string
		want   string
	}{
		{&SpfResult{Result: "pass", Identity: "mailfrom", SenderDomain: "example.com"}, "<user@example.com>", "spf=pass smtp.mailfrom=\"user@example.com\""},
		{&SpfResult{Result: "pass", Identity: "helo", SenderDomain: "mx.example.net"}, "", "spf=pass smtp.helo=mx.example.net"},
		{&SpfResult{Result: "none", Identity: "helo"}, "", `spf=none smtp.mailfrom="<>"`},
		{&SpfResult{Result: "permerror", Identity: "mailfrom", Problem: "multiple SPF records at example.com"}, "a@example.com", `spf=permerror reason="multiple SPF records at example.com" smtp.mailfrom="a@example.com"`},
	} {
		got, err := buildAuthResultsForTest(tc.result, tc.sender)
		if got = strings.ReplaceAll(got, "\r\n\t", " "); err != nil || got != "mx.test; "+tc.want {
			t.Errorf("got %q, %v; want %q", got, err, tc.want)
		}
	}
}

func buildAuthResultsForTest(result *SpfResult, sender string) (string, error) {
	s := &Session{cfg: &Config{ServerName: "mx.test"}, spfResult: result, envelopeSender: sender}
	return s.authenticationResultsHeader(map[string]string{})
}

func TestIsLocalIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"203.0.113.1", false},
		{"8.8.8.8", false},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isLocalIP(tt.ip); got != tt.want {
			t.Errorf("isLocalIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestDefaultSpfPolicy(t *testing.T) {
	t.Parallel()
	if p := DefaultSpfPolicy(); p.Mode != SpfPolicyWarn {
		t.Errorf("expected default mode warn, got %q", p.Mode)
	}
}

// makeRemoteTestServer is makeTestServer with the session seeing the
// connection as coming from remoteIP.
func makeRemoteTestServer(t *testing.T, cfg *Config, remoteIP string) *tc {
	t.Helper()
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		remote := &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 40000}
		sess := newSession(srv.sessionID.Add(1), cfg, addrConn{Conn: conn, remote: remote}, nil, nil)
		sess.run()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	if greeting, err := c.readLine(); err != nil || !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting %q: %v", greeting, err)
	}
	return c
}

func spfSessionConfig(mode SpfPolicyMode, headers *map[string]string) *Config {
	return &Config{
		ServerName: "test.veksel",
		SpfPolicy:  spfTestPolicy(mode),
		Delivery: &Delivery{
			ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
				return "folder", "user", nil
			},
			AppendMessage: func(ctx context.Context, folderID string, data []byte, h map[string]string) (string, error) {
				if headers != nil {
					*headers = h
				}
				return "item-1", nil
			},
		},
	}
}

func TestSPFRejectModeRejectsFailAtRCPT(t *testing.T) {
	t.Parallel()
	c := makeRemoteTestServer(t, spfSessionConfig(SpfPolicyReject, nil), "198.51.100.1")
	c.send("EHLO mx.example.net")
	if code, _ := c.send("MAIL FROM:<user@example.com>"); code != 250 {
		t.Fatalf("MAIL FROM: code=%d", code)
	}
	if code, text := c.send("RCPT TO:<alice@example.com>"); code != 550 || !strings.Contains(text, "5.7.23") {
		t.Fatalf("RCPT TO: %d %s, want 550 5.7.23", code, text)
	}
	// RSET clears the result; an authorized sender is accepted.
	c.send("RSET")
	c.send("MAIL FROM:<user@soft.example.com>")
	if code, _ := c.send("RCPT TO:<alice@example.com>"); code != 250 {
		t.Fatalf("softfail RCPT TO: code=%d, want 250", code)
	}
}

func TestSPFRejectModeAcceptsIncludedSender(t *testing.T) {
	t.Parallel()
	var headers map[string]string
	c := makeRemoteTestServer(t, spfSessionConfig(SpfPolicyReject, &headers), "203.0.113.9")
	c.send("EHLO mx.example.net")
	c.send("MAIL FROM:<user@example.com>")
	if code, _ := c.send("RCPT TO:<alice@example.com>"); code != 250 {
		t.Fatalf("RCPT TO: code=%d, want 250", code)
	}
	c.send("DATA")
	c.writeData("From: user@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d", code)
	}
	if got := headers["Authentication-Results"]; !strings.Contains(got, "spf=pass smtp.mailfrom=\"user@example.com\"") {
		t.Fatalf("Authentication-Results = %q", got)
	}
	if headers["Received-SPF"] != "" {
		t.Fatal("legacy Received-SPF header was emitted")
	}
}

func TestSPFNullSenderUsesHeloIdentity(t *testing.T) {
	t.Parallel()
	var headers map[string]string
	c := makeRemoteTestServer(t, spfSessionConfig(SpfPolicyWarn, &headers), "198.51.100.7")
	c.send("EHLO mx.example.net")
	c.send("MAIL FROM:<>")
	c.send("RCPT TO:<alice@example.com>")
	c.send("DATA")
	c.writeData("From: <>\r\nTo: alice@example.com\r\nSubject: Bounce\r\n\r\nDelivery failure\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d", code)
	}
	if got := headers["Authentication-Results"]; !strings.Contains(got, "spf=pass smtp.helo=mx.example.net") {
		t.Fatalf("Authentication-Results for null sender = %q", got)
	}
}

func TestSPFLocalConnectionSkipsCheck(t *testing.T) {
	t.Parallel()
	var headers map[string]string
	// makeTestServer connects from 127.0.0.1, which SPF skips.
	c := makeTestServer(t, spfSessionConfig(SpfPolicyReject, &headers))
	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<user@example.com>")
	if code, _ := c.send("RCPT TO:<alice@example.com>"); code != 250 {
		t.Fatalf("RCPT TO: code=%d, want 250", code)
	}
	c.send("DATA")
	c.writeData("From: user@example.com\r\nTo: alice@example.com\r\nSubject: Local\r\n\r\nBody\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA end: code=%d", code)
	}
	if strings.Contains(headers["Authentication-Results"], "spf=") || headers["Received-SPF"] != "" {
		t.Fatalf("local connection carried SPF results: %v", headers)
	}
}

func TestSPFOffAndAbsentPolicyAllow(t *testing.T) {
	t.Parallel()
	for _, policy := range []*SpfPolicy{nil, {Mode: SpfPolicyOff}} {
		cfg := spfSessionConfig(SpfPolicyReject, nil)
		cfg.SpfPolicy = policy
		c := makeRemoteTestServer(t, cfg, "198.51.100.1")
		c.send("EHLO mx.example.net")
		c.send("MAIL FROM:<user@example.com>")
		if code, _ := c.send("RCPT TO:<alice@example.com>"); code != 250 {
			t.Fatalf("policy %+v: RCPT TO code=%d, want 250", policy, code)
		}
	}
}
