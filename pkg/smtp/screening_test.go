package smtp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/spam"
)

// dialRaw serves cfg on 127.0.0.1 and connects without reading the greeting.
func dialRaw(t *testing.T, cfg *Config) *tc {
	t.Helper()
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Accept(ctx, ln)
	t.Cleanup(func() { cancel(); srv.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &tc{Conn: conn, r: bufio.NewReader(conn)}
}

// findingsChecker records the connection findings of every scored message.
type findingsChecker struct {
	mu       sync.Mutex
	findings [][]spam.ConnectionFinding
}

func (c *findingsChecker) Check(_ context.Context, message spam.Message) (spam.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, message.Connection)
	return spam.Result{}, false
}

func (c *findingsChecker) symbols() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var names []string
	for _, findings := range c.findings {
		for _, finding := range findings {
			names = append(names, finding.Symbol)
		}
	}
	return names
}

func acceptingDelivery() *Delivery {
	return &Delivery{
		ResolveRecipient: func(context.Context, string) (string, string, error) { return "folder", "user", nil },
		AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) {
			return "item", nil
		},
	}
}

// sendMessage runs one complete transaction on an EHLO'd client.
func sendMessage(t *testing.T, c *tc) {
	t.Helper()
	c.send("MAIL FROM:<sender@example.com>")
	if code, text := c.send("RCPT TO:<alice@example.com>"); code != 250 {
		t.Fatalf("RCPT = %d %s", code, text)
	}
	c.send("DATA")
	c.writeData("From: sender@example.com\r\nSubject: hi\r\n\r\nbody\r\n.\r\n")
	if code, text, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA = %d %s", code, text)
	}
}

func TestPregreetIsDetectedAndActedOn(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		reporter := &recordingReporter{}
		c := dialRaw(t, &Config{ServerName: "mx.test", Abuse: reporter,
			Screening: Screening{GreetDelay: 200 * time.Millisecond, Pregreet: PregreetReject, Cache: &ScreenCache{}}})
		c.writeCmd("EHLO early.example.com")
		if line, _ := c.readLine(); line != "220-mx.test ESMTP Veksel" {
			t.Fatalf("first greeting line = %q", line)
		}
		if line, _ := c.readLine(); !strings.HasPrefix(line, "554 5.7.1") {
			t.Fatalf("early talker answer = %q", line)
		}
		if line, err := c.readLine(); err == nil {
			t.Fatalf("session continued after 554: %q", line)
		}
		if got := reporter.recorded(); !slices.Equal(got, []ban.Trigger{ban.TriggerProtocol}) {
			t.Fatalf("strikes = %v", got)
		}
	})
	t.Run("score", func(t *testing.T) {
		checker := &findingsChecker{}
		cache := &ScreenCache{}
		c := dialRaw(t, &Config{ServerName: "mx.test", Spam: checker, Delivery: acceptingDelivery(),
			Screening: Screening{GreetDelay: 200 * time.Millisecond, Pregreet: PregreetScore, Cache: cache}})
		c.writeCmd("EHLO early.example.com")
		if code, text, _ := c.readReply(); code != 220 || !strings.Contains(text, "mx.test ESMTP Veksel") {
			t.Fatalf("greeting = %d %q", code, text)
		}
		if code, _, _ := c.readReply(); code != 250 {
			t.Fatalf("early EHLO = %d", code)
		}
		sendMessage(t, c)
		if got := checker.symbols(); !slices.Contains(got, spam.SymbolPregreet) {
			t.Fatalf("scored connection symbols = %v", got)
		}
		if cache.Passed("127.0.0.1") {
			t.Fatal("an early talker was remembered as passed")
		}
	})
}

func TestGreetingTestPassesAndSkipsKnownAndTrustedClients(t *testing.T) {
	cache := &ScreenCache{}
	cfg := &Config{ServerName: "mx.test", Screening: Screening{GreetDelay: 50 * time.Millisecond, Pregreet: PregreetReject, Cache: cache}}
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Accept(ctx, ln)
	t.Cleanup(func() { cancel(); srv.Close() })
	firstLine := func() string {
		t.Helper()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		c := &tc{Conn: conn, r: bufio.NewReader(conn)}
		line, _ := c.readLine()
		if strings.HasPrefix(line, "220-") {
			if final, _ := c.readLine(); final != "220 mx.test ESMTP Veksel" {
				t.Fatalf("final greeting line = %q", final)
			}
		}
		c.send("QUIT")
		return line
	}
	if line := firstLine(); !strings.HasPrefix(line, "220-") {
		t.Fatalf("a new client was not tested: %q", line)
	}
	if !cache.Passed("127.0.0.1") {
		t.Fatal("a patient client was not remembered")
	}
	if line := firstLine(); line != "220 mx.test ESMTP Veksel" {
		t.Fatalf("a passed client was tested again: %q", line)
	}

	trusted := &Config{ServerName: "mx.test", Screening: Screening{GreetDelay: time.Hour, Pregreet: PregreetReject,
		Exempt: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	c := dialRaw(t, trusted)
	if line, _ := c.readLine(); line != "220 mx.test ESMTP Veksel" {
		t.Fatalf("an exempt client was tested: %q", line)
	}
	submission := &Config{ServerName: "mx.test", AuthRequired: true, Screening: Screening{GreetDelay: time.Hour, Pregreet: PregreetReject}}
	c = dialRaw(t, submission)
	if line, _ := c.readLine(); line != "220 mx.test ESMTP Veksel" {
		t.Fatalf("a submission client was tested: %q", line)
	}
}

func TestPipeliningWithoutNegotiationIsAViolation(t *testing.T) {
	reporter := &recordingReporter{}
	checker := &findingsChecker{}
	c := makeTestServer(t, &Config{ServerName: "mx.test", Abuse: reporter, Spam: checker, Delivery: acceptingDelivery()})
	// HELO does not negotiate PIPELINING, so MAIL must wait for its reply.
	c.writeData("HELO client.example.com\r\nMAIL FROM:<sender@example.com>\r\n")
	if codes := c.readReplies(2); !slices.Equal(codes, []int{250, 250}) {
		t.Fatalf("replies = %v", codes)
	}
	if code, _ := c.send("RCPT TO:<alice@example.com>"); code != 250 {
		t.Fatalf("RCPT = %d", code)
	}
	c.send("DATA")
	c.writeData("Subject: hi\r\n\r\nbody\r\n.\r\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA = %d", code)
	}
	if got := checker.symbols(); !slices.Contains(got, spam.SymbolPipelining) {
		t.Fatalf("scored connection symbols = %v", got)
	}
	if got := reporter.recorded(); !slices.Equal(got, []ban.Trigger{ban.TriggerProtocol}) {
		t.Fatalf("strikes = %v", got)
	}

	// DATA must end a group even with PIPELINING: the body may only follow 354.
	checker = &findingsChecker{}
	c = makeTestServer(t, &Config{ServerName: "mx.test", Spam: checker, Delivery: acceptingDelivery()})
	c.send("EHLO client.example.com")
	c.writeData("MAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\n")
	if codes := c.readReplies(4); !slices.Equal(codes, []int{250, 250, 354, 250}) {
		t.Fatalf("replies = %v", codes)
	}
	if got := checker.symbols(); !slices.Contains(got, spam.SymbolPipelining) {
		t.Fatalf("message data before 354 was not flagged: %v", got)
	}

	// A properly pipelined group is not a violation.
	checker = &findingsChecker{}
	c = makeTestServer(t, &Config{ServerName: "mx.test", Spam: checker, Delivery: acceptingDelivery()})
	c.send("EHLO client.example.com")
	c.writeData("MAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\n")
	if codes := c.readReplies(3); !slices.Equal(codes, []int{250, 250, 354}) {
		t.Fatalf("replies = %v", codes)
	}
	c.writeData("Subject: hi\r\n\r\nbody\r\n.\r\n")
	c.readReply()
	if got := checker.symbols(); len(got) != 0 {
		t.Fatalf("legitimate pipelining was flagged: %v", got)
	}
}

func TestCommandSyntaxViolationsReachTheLimit(t *testing.T) {
	reporter := &recordingReporter{}
	c := makeTestServer(t, &Config{ServerName: "mx.test", Abuse: reporter, Screening: Screening{ViolationLimit: 3}})
	c.writeData("NOOP\n")
	if code, _, _ := c.readReply(); code != 250 {
		t.Fatalf("bare LF NOOP = %d", code)
	}
	c.writeData("NOOP\n") // bare LF counts once per session
	c.readReply()
	if code, _ := c.send("NOOP \x00"); code != 250 {
		t.Fatalf("NUL NOOP = %d", code)
	}
	if code, text := c.send("NOOP " + strings.Repeat("x", maxCommandLength)); code != 421 {
		t.Fatalf("third violation = %d %s, want 421", code, text)
	}
	if _, err := c.readLine(); err == nil {
		t.Fatal("session continued after 421")
	}
	if got := reporter.recorded(); !slices.Equal(got, []ban.Trigger{ban.TriggerProtocol}) {
		t.Fatalf("strikes = %v", got)
	}
}

func TestOverlongLinesAreDiscardedWithoutEndingTheSession(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "mx.test"})
	if code, _ := c.send("NOOP " + strings.Repeat("x", maxLineLength+100)); code != 500 {
		t.Fatalf("overlong line = %d", code)
	}
	if code, _ := c.send("NOOP " + strings.Repeat("x", maxCommandLength)); code != 500 {
		t.Fatalf("overlong command = %d", code)
	}
	if code, _ := c.send("NOOP"); code != 250 {
		t.Fatalf("NOOP after overlong lines = %d", code)
	}
}

func TestUnknownJunkAndCleartextAuthCommandsAreCounted(t *testing.T) {
	c := makeTestServer(t, &Config{ServerName: "mx.test", Screening: Screening{ViolationLimit: 2}})
	if code, _ := c.send("FOO"); code != 502 {
		t.Fatalf("unknown command = %d", code)
	}
	if code, _ := c.send("BAR"); code != 421 {
		t.Fatalf("second unknown command = %d", code)
	}

	c = makeTestServer(t, &Config{ServerName: "mx.test", Screening: Screening{ViolationLimit: 1}})
	c.send("EHLO client.example.com")
	if code, _ := c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA=="); code != 421 {
		t.Fatalf("cleartext AUTH on the relay listener = %d", code)
	}

	c = makeTestServer(t, &Config{ServerName: "mx.test", Screening: Screening{ViolationLimit: 1}})
	for range junkCommandLimit {
		if code, _ := c.send("NOOP"); code != 250 {
			t.Fatalf("NOOP within the junk limit = %d", code)
		}
	}
	if code, _ := c.send("RSET"); code != 421 {
		t.Fatalf("junk command past the limit = %d", code)
	}
}

func TestUnknownRecipientsAreTarpittedBoundedly(t *testing.T) {
	var delays []time.Duration
	checker := &findingsChecker{}
	known := "alice@example.com"
	c := makeTestServer(t, &Config{ServerName: "mx.test", Spam: checker,
		Screening: Screening{TarpitAfterUnknownRcpts: 2, sleep: func(d time.Duration) { delays = append(delays, d) }},
		Delivery: &Delivery{
			ResolveRecipient: func(_ context.Context, addr string) (string, string, error) {
				if addr == known {
					return "folder", "user", nil
				}
				return "", "", errors.New("unknown")
			},
			AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) { return "item", nil },
		}})
	c.send("EHLO client.example.com")
	c.send("MAIL FROM:<sender@example.com>")
	for _, name := range []string{"a", "b", "c", "d"} {
		if code, _ := c.send("RCPT TO:<" + name + "@example.com>"); code != 550 {
			t.Fatalf("unknown recipient = %d", code)
		}
	}
	if code, _ := c.send("RCPT TO:<" + known + ">"); code != 250 {
		t.Fatalf("known recipient = %d", code)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}; !slices.Equal(delays, want) {
		t.Fatalf("tarpit delays = %v, want %v", delays, want)
	}
	c.send("DATA")
	c.writeData("Subject: hi\r\n\r\nbody\r\n.\r\n")
	c.readReply()
	if got := checker.symbols(); !slices.Contains(got, spam.SymbolUnknownRecipients) {
		t.Fatalf("harvesting was not scored: %v", got)
	}

	session := &Session{cfg: &Config{Screening: Screening{TarpitAfterUnknownRcpts: 1, sleep: func(d time.Duration) { delays = append(delays, d) }}},
		conn: clientConn("198.51.100.9"), unknownRcpts: 1000}
	session.tarpit()
	if last := delays[len(delays)-1]; last != maxTarpitDelay {
		t.Fatalf("tarpit delay = %v, want the %v bound", last, maxTarpitDelay)
	}
}

// clientConn is a connection stub from client ip.
func clientConn(ip string) addrConn {
	return addrConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

// fakeResolver answers PTR and address lookups from maps; missing names
// are NXDOMAIN, and names in temporary fail temporarily.
type fakeResolver struct {
	mu        sync.Mutex
	ptr       map[string][]string
	hosts     map[string][]string
	temporary map[string]bool
	lookups   int
}

func (r *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	if r.temporary[addr] {
		return nil, &net.DNSError{Err: "timeout", Name: addr, IsTimeout: true}
	}
	if names, ok := r.ptr[addr]; ok {
		return names, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (r *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.temporary[host] {
		return nil, &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}
	}
	addrs, ok := r.hosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var result []net.IPAddr
	for _, addr := range addrs {
		result = append(result, net.IPAddr{IP: net.ParseIP(addr)})
	}
	return result, nil
}

func symbolNames(findings []spam.ConnectionFinding) []string {
	var names []string
	for _, finding := range findings {
		names = append(names, finding.Symbol)
	}
	return names
}

func TestFCrDNS(t *testing.T) {
	resolver := &fakeResolver{
		ptr: map[string][]string{
			"203.0.113.10": {"mail.example.net."},
			"203.0.113.11": {"mail.example.org."},
			"203.0.113.12": {"dsl-203-0-113-12.pool.isp.example."},
		},
		hosts: map[string][]string{
			"mail.example.net":                  {"203.0.113.10"},
			"mail.example.org":                  {"192.0.2.99"},
			"dsl-203-0-113-12.pool.isp.example": {"203.0.113.12"},
		},
		temporary: map[string]bool{"203.0.113.14": true},
	}
	tests := []struct {
		ip       string
		known    string
		want     []string
		definite bool
	}{
		{"203.0.113.10", "", nil, true},
		{"203.0.113.11", "", []string{spam.SymbolRDNSNotFCrDNS}, true},
		{"203.0.113.12", "", []string{spam.SymbolRDNSDynamic}, true},
		{"203.0.113.13", "", []string{spam.SymbolRDNSNone}, true},
		{"203.0.113.14", "", nil, false},
		// A PTR name the HELO policy already found is reused.
		{"203.0.113.13", "mail.example.net", []string{spam.SymbolRDNSNotFCrDNS}, true},
	}
	for _, test := range tests {
		findings, definite := checkFCrDNS(context.Background(), resolver, netip.MustParseAddr(test.ip), test.known)
		if got := symbolNames(findings); !slices.Equal(got, test.want) || definite != test.definite {
			t.Errorf("%s (%q) = %v definite=%v, want %v definite=%v", test.ip, test.known, got, definite, test.want, test.definite)
		}
	}

	// Sessions share the cache: the second session does not look up again.
	cache := &ScreenCache{}
	cfg := &Config{Screening: Screening{FCrDNS: true, Resolver: resolver, Cache: cache}}
	resolver.lookups = 0
	for range 2 {
		session := newSession(1, cfg, clientConn("203.0.113.11"), nil, nil)
		if got := symbolNames(session.connectionFindings()); !slices.Equal(got, []string{spam.SymbolRDNSNotFCrDNS}) {
			t.Fatalf("session findings = %v", got)
		}
	}
	if resolver.lookups != 1 {
		t.Fatalf("PTR lookups = %d, want 1 (cached)", resolver.lookups)
	}
	if got := newSession(1, cfg, clientConn("10.0.0.5"), nil, nil).connectionFindings(); len(got) != 0 {
		t.Fatalf("an internal client was checked: %v", got)
	}
}

func TestDynamicHostnames(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.23")
	for name, want := range map[string]bool{
		"mail.example.com":                       false,
		"mx1.dyn.example.com":                    true,
		"adsl123.isp.example":                    true,
		"host-198-51-100-23.isp.example":         true,
		"23.100.51.198.static.example.net":       true,
		"c63364177.isp.example":                  true,
		"198051100023.isp.example":               true,
		"cpe-1-2.example.com":                    true,
		"smtp-out.pool-mail.example.com":         true,
		"outbound.mailchannels.example.com":      false,
		"poolside.example.com":                   false,
		"mail.broadband.example":                 false, // registered domain only
		"relay.customer-service.example.co":      true,
		"ip-198-51-100-24.compute.cloud.example": false,
	} {
		if got := dynamicHostname(name, addr); got != want {
			t.Errorf("dynamicHostname(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHeloFindings(t *testing.T) {
	cfg := &Config{ServerName: "mx.example.test", Delivery: &Delivery{
		IsLocalDomain: func(_ context.Context, domain string) (bool, error) { return domain == "example.test", nil },
	}}
	for helo, want := range map[string][]string{
		"client.example.net": nil,
		"203.0.113.7":        {spam.SymbolHeloBareIP},
		"[203.0.113.7]":      nil,
		"workstation":        {spam.SymbolHeloNotFQDN},
		"mx.example.test":    {spam.SymbolHeloForgedLocal},
		"EXAMPLE.TEST.":      {spam.SymbolHeloForgedLocal},
		"www.example.test":   nil,
	} {
		session := newSession(1, cfg, clientConn("203.0.113.7"), nil, nil)
		session.heloHostname = helo
		if got := symbolNames(session.heloFindings()); !slices.Equal(got, want) {
			t.Errorf("HELO %q = %v, want %v", helo, got, want)
		}
	}
	internal := newSession(1, cfg, clientConn("192.168.1.5"), nil, nil)
	internal.heloHostname = "mx.example.test"
	if got := internal.heloFindings(); len(got) != 0 {
		t.Fatalf("an internal client's HELO was scored: %v", got)
	}
}
