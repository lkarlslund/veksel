package spam

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/contentscan"
)

// fakeResolver answers blocklist queries from a table; unknown names are
// NXDOMAIN. It never touches the network.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	block   bool
	queries []string
	count   atomic.Int64
}

func (r *fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	r.count.Add(1)
	name := strings.TrimSuffix(host, ".")
	r.mu.Lock()
	r.queries = append(r.queries, name)
	answers, err, block := r.answers[name], r.errs[name], r.block
	r.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if answers == nil {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return answers, nil
}

func (r *fakeResolver) queried() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.queries)
}

const publicIP = "203.0.113.7" // TEST-NET-3: public, never private

func newTestEngine(t *testing.T, resolver *fakeResolver, mutate func(*Settings, *Config)) (*Engine, *DNS) {
	t.Helper()
	settings := Settings{Thresholds: DefaultThresholds(), DNSBL: DefaultZones(ZoneDNSBL), RHSBL: DefaultZones(ZoneRHSBL), URIBL: DefaultZones(ZoneURIBL)}
	if mutate != nil {
		mutate(&settings, nil)
	}
	config, err := ParseSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(nil, &config)
	}
	dns := NewDNS(resolver, DNSOptions{QueryTimeout: time.Second})
	engine, err := NewEngine(config, dns)
	if err != nil {
		t.Fatal(err)
	}
	return engine, dns
}

func heuristicEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func rawMessage(headers map[string]string, body string) []byte {
	var builder strings.Builder
	for _, name := range []string{"From", "To", "Subject", "Date", "Message-ID", "DKIM-Signature", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"} {
		if value, ok := headers[name]; ok {
			builder.WriteString(name + ": " + value + "\r\n")
		}
	}
	builder.WriteString("\r\n" + body)
	return []byte(builder.String())
}

func check(t *testing.T, engine *Engine, m Message) Result {
	t.Helper()
	if m.Content == nil {
		m.Content = rawMessage(m.Headers, "body")
	}
	result, ok := engine.Check(context.Background(), m)
	if !ok {
		t.Fatal("engine did not score the message")
	}
	return result
}

func symbolNames(result Result) []string {
	names := make([]string, 0, len(result.Symbols))
	for _, symbol := range result.Symbols {
		names = append(names, symbol.Name)
	}
	return names
}

func findSymbol(result Result, name string) (Symbol, bool) {
	for _, symbol := range result.Symbols {
		if symbol.Name == name {
			return symbol, true
		}
	}
	return Symbol{}, false
}

func completeHeaders() map[string]string {
	return map[string]string{
		"From": "alice@sender.example.com", "Subject": "Meeting tomorrow", "Message-ID": "<abc123@example.com>",
		"Date": time.Now().Format(time.RFC1123Z), "DKIM-Signature": "v=1; d=example.com",
	}
}

func TestHeuristicSymbols(t *testing.T) {
	engine := heuristicEngine(t)
	cases := []struct {
		name   string
		mutate func(map[string]string)
		want   []string
		min    float64
	}{
		{"missing from", func(h map[string]string) { delete(h, "From") }, []string{"MISSING_FROM"}, 2},
		{"missing subject", func(h map[string]string) { delete(h, "Subject") }, []string{"MISSING_SUBJECT"}, 1},
		{"missing message id", func(h map[string]string) { delete(h, "Message-ID") }, []string{"MISSING_MESSAGE_ID"}, 0.5},
		{"missing date", func(h map[string]string) { delete(h, "Date") }, []string{"MISSING_DATE"}, 0.5},
		{"caps and phrase", func(h map[string]string) { h["Subject"] = "BUY VIAGRA NOW!!!" }, []string{"CAPS_SUBJECT", "SPAM_PHRASE"}, 4.5},
		{"unsigned", func(h map[string]string) { delete(h, "DKIM-Signature") }, []string{"DKIM_MISSING"}, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := completeHeaders()
			tc.mutate(headers)
			result := check(t, engine, Message{Headers: headers})
			for _, name := range tc.want {
				if _, ok := findSymbol(result, name); !ok {
					t.Fatalf("symbols = %v, want %s", symbolNames(result), name)
				}
			}
			if result.Score < tc.min {
				t.Fatalf("score = %v, want at least %v", result.Score, tc.min)
			}
		})
	}
	clean := check(t, engine, Message{Headers: completeHeaders(), Content: rawMessage(completeHeaders(), "Hey, are we still on for the meeting tomorrow?")})
	if clean.Score != 0 || len(clean.Symbols) != 0 || clean.Action != ActionNone {
		t.Fatalf("clean message = %+v", clean)
	}
}

func TestContentHeuristicsUseDecodedParts(t *testing.T) {
	engine := heuristicEngine(t)
	headers := completeHeaders()
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = `multipart/alternative; boundary="b"`
	sales := base64.StdEncoding.EncodeToString([]byte("Buy now! Order today! Limited time offer! Act now!"))
	body := "--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + sales + "\r\n" +
		"--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"<html><body><div><span><font><b><i><u><p>H=\r\ni</p></u></i></b></font></span></div></body></html>\r\n--b--\r\n"
	result := check(t, engine, Message{Headers: headers, Content: rawMessage(headers, body)})
	for _, name := range []string{"SALES_LANGUAGE", "HTML_HEAVY"} {
		if _, ok := findSymbol(result, name); !ok {
			t.Fatalf("symbols = %v, want %s", symbolNames(result), name)
		}
	}
}

func TestAuthenticationSymbolsComeFromTheBoundary(t *testing.T) {
	engine := heuristicEngine(t)
	result := check(t, engine, Message{Headers: completeHeaders(), EnvelopeFrom: "bounce@other.example.net", SPF: "fail", DKIM: "fail", DMARC: "fail"})
	for _, name := range []string{"SPF_FAIL", "DKIM_INVALID", "DMARC_FAIL", "FROM_DOMAIN_MISMATCH"} {
		if _, ok := findSymbol(result, name); !ok {
			t.Fatalf("symbols = %v, want %s", symbolNames(result), name)
		}
	}
	if result.Score != 3+2+2+1 || result.Action != ActionJunk {
		t.Fatalf("score/action = %v/%v", result.Score, result.Action)
	}
	softfail := check(t, engine, Message{Headers: completeHeaders(), SPF: "softfail"})
	if _, ok := findSymbol(softfail, "SPF_SOFTFAIL"); !ok || softfail.Score != 1.5 {
		t.Fatalf("softfail = %+v", softfail)
	}
}

func TestThresholdActions(t *testing.T) {
	thresholds := DefaultThresholds()
	for score, want := range map[float64]Action{0: ActionNone, 3.9: ActionNone, 4: ActionGreylist, 5.9: ActionGreylist, 6: ActionJunk, 14.9: ActionJunk, 15: ActionReject, 40: ActionReject} {
		if got := thresholds.Action(score); got != want {
			t.Errorf("Action(%v) = %v, want %v", score, got, want)
		}
	}
	disabled := Thresholds{Junk: 6}
	if disabled.Action(100) != ActionJunk || disabled.Action(5) != ActionNone {
		t.Fatal("zero greylist and reject thresholds must disable those actions")
	}
	if (Result{Score: 7, Action: ActionJunk, Thresholds: thresholds}).Greylist() != true || (Result{Score: 20, Action: ActionReject, Thresholds: thresholds}).Greylist() {
		t.Fatal("greylisting must apply from its threshold up to, but not including, rejection")
	}
	for _, invalid := range []Thresholds{{Junk: 0}, {Junk: 6, Greylist: 7}, {Junk: 6, Reject: 6}, {Junk: -1}, {Junk: 2000}} {
		if invalid.Validate() == nil {
			t.Errorf("thresholds %+v validated", invalid)
		}
	}
}

func TestSymbolScoreOverrides(t *testing.T) {
	config, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: []string{"MISSING_DATE=4", "missing_from = 0"}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	headers := completeHeaders()
	delete(headers, "Date")
	delete(headers, "From")
	result := check(t, engine, Message{Headers: headers})
	if symbol, _ := findSymbol(result, "MISSING_DATE"); symbol.Score != 4 {
		t.Fatalf("override not applied: %+v", result.Symbols)
	}
	if symbol, ok := findSymbol(result, "MISSING_FROM"); !ok || symbol.Score != 0 {
		t.Fatalf("zero override must keep the evidence with no score: %+v", result.Symbols)
	}
	for _, invalid := range [][]string{{"NOT_A_SYMBOL=1"}, {"MISSING_DATE"}, {"MISSING_DATE=abc"}, {"MISSING_DATE=500"}, {"MISSING_DATE=1", "MISSING_DATE=2"}} {
		if _, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: invalid}); err == nil {
			t.Errorf("overrides %q validated", invalid)
		}
	}
	// Symbols defined by known or configured zones may be overridden.
	if _, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: []string{"RBL_SPAMHAUS_PBL=0", "CUSTOM_LIST=2"}, DNSBL: []string{"list.example.net 127.0.0.2=CUSTOM_LIST:3"}}); err != nil {
		t.Fatal(err)
	}
}

func TestReverseIP(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":             "1.2.0.192",
		"::ffff:198.51.100.200": "200.100.51.198",
		"2001:db8::567:89ab":    "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
	}
	for input, want := range cases {
		if got := ReverseIP(netip.MustParseAddr(input)); got != want {
			t.Errorf("ReverseIP(%s) = %s, want %s", input, got, want)
		}
	}
}

func TestDNSBLQueriesAndReturnCodes(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{
		"7.113.0.203.zen.spamhaus.org": {"127.0.0.2", "127.0.0.4", "127.0.0.10"},
		"7.113.0.203.bl.spamcop.net":   {"127.0.0.2"},
	}}
	engine, dns := newTestEngine(t, resolver, nil)
	result := check(t, engine, Message{Headers: completeHeaders(), RemoteIP: publicIP})
	for name, score := range map[string]float64{"RBL_SPAMHAUS_SBL": 4, "RBL_SPAMHAUS_XBL": 5, "RBL_SPAMHAUS_PBL": 1.5, "RBL_SPAMCOP": 3} {
		symbol, ok := findSymbol(result, name)
		if !ok || symbol.Score != score || !slices.Contains(symbol.Options, publicIP) {
			t.Fatalf("symbol %s = %+v (symbols %v)", name, symbol, symbolNames(result))
		}
	}
	if result.Score != 13.5 || result.Action != ActionJunk {
		t.Fatalf("score/action = %v/%v", result.Score, result.Action)
	}
	queried := resolver.queried()
	for _, zone := range DefaultZones(ZoneDNSBL) {
		if !slices.Contains(queried, "7.113.0.203."+zone) {
			t.Fatalf("queries %v lack %s", queried, zone)
		}
	}
	stats := dns.Stats()
	listed := 0
	for _, zone := range stats {
		listed += int(zone.Listed)
	}
	if listed != 2 {
		t.Fatalf("listed zones = %d in %+v", listed, stats)
	}

	ipv6 := &fakeResolver{answers: map[string][]string{
		ReverseIP(netip.MustParseAddr("2001:db8::1")) + ".zen.spamhaus.org": {"127.0.0.9"},
	}}
	engine, _ = newTestEngine(t, ipv6, nil)
	if symbol, ok := findSymbol(check(t, engine, Message{Headers: completeHeaders(), RemoteIP: "2001:db8::1"}), "RBL_SPAMHAUS_DROP"); !ok || symbol.Score != 7 {
		t.Fatalf("IPv6 nibble query did not map DROP: %+v", ipv6.queried())
	}
}

func TestBitmaskAndCustomZones(t *testing.T) {
	zones, err := ParseZones(ZoneURIBL, []string{"multi.surbl.org", "list.example.net 127.0.0.2-127.0.0.3=CUSTOM_RANGE:2 &4=CUSTOM_BIT:1 127.0.0.9=!", "any.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	surbl := zones[0].evaluate([]netip.Addr{netip.MustParseAddr("127.0.0.24")})
	if len(surbl.hits) != 2 || surbl.hits[0].Symbol != "URIBL_SURBL_PHISH" || surbl.hits[1].Symbol != "URIBL_SURBL_MALWARE" {
		t.Fatalf("SURBL bitmask hits = %+v", surbl.hits)
	}
	if verdict := zones[0].evaluate([]netip.Addr{netip.MustParseAddr("127.0.0.1")}); !verdict.refused || len(verdict.hits) != 0 {
		t.Fatalf("SURBL 127.0.0.1 must be a refusal: %+v", verdict)
	}
	custom := zones[1].evaluate([]netip.Addr{netip.MustParseAddr("127.0.0.6")})
	if len(custom.hits) != 1 || custom.hits[0].Symbol != "CUSTOM_BIT" {
		t.Fatalf("custom bit = %+v", custom)
	}
	if !zones[1].evaluate([]netip.Addr{netip.MustParseAddr("127.0.0.9")}).refused {
		t.Fatal("custom refusal sentinel not honoured")
	}
	if generic := zones[2].evaluate([]netip.Addr{netip.MustParseAddr("127.0.0.2")}); len(generic.hits) != 1 || generic.hits[0].Symbol != "URIBL_ANY_EXAMPLE_NET" {
		t.Fatalf("generic zone = %+v", generic)
	}
	if verdict := zones[2].evaluate([]netip.Addr{netip.MustParseAddr("198.51.100.1")}); verdict.err == nil {
		t.Fatal("a non-loopback answer must be an error, not a hit")
	}
	for _, invalid := range []string{"", "nodots", "list.example.net 10.0.0.1=X:1", "list.example.net 127.0.0.2=lower:1", "list.example.net 127.0.0.2=X", "list.example.net &0=X:1", "list.example.net 127.0.0.2=X:999"} {
		if _, err := ParseZones(ZoneDNSBL, []string{invalid}); err == nil {
			t.Errorf("zone %q validated", invalid)
		}
	}
	if _, err := ParseZones(ZoneDNSBL, []string{"a.example.net", "A.example.net."}); err == nil {
		t.Error("duplicate zones validated")
	}
	if dqs, _ := ParseZones(ZoneDNSBL, []string{"key123.zen.dq.spamhaus.net"}); len(dqs[0].Rules) < 5 {
		t.Fatalf("Spamhaus DQS zone did not use the ZEN return codes: %+v", dqs)
	}
}

func TestRefusedSentinelIsAnErrorNotAHit(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{"7.113.0.203.zen.spamhaus.org": {"127.255.255.254"}}}
	engine, dns := newTestEngine(t, resolver, func(settings *Settings, _ *Config) {
		if settings != nil {
			settings.DNSBL, settings.RHSBL, settings.URIBL = []string{"zen.spamhaus.org"}, nil, nil
		}
	})
	result := check(t, engine, Message{Headers: completeHeaders(), RemoteIP: publicIP})
	if result.Score != 0 {
		t.Fatalf("refusal scored: %+v", result.Symbols)
	}
	if symbol, ok := findSymbol(result, "DNS_LOOKUP_ERROR"); !ok || !slices.Contains(symbol.Options, "zen.spamhaus.org") {
		t.Fatalf("refusal lacks lookup-error evidence: %+v", result.Symbols)
	}
	zones, _ := ParseZones(ZoneDNSBL, []string{"zen.spamhaus.org"})
	healthy, reason, details := dns.Health(zones)
	if healthy || !strings.Contains(reason, "refuse") || details["dnsbl:zen.spamhaus.org"] == "" {
		t.Fatalf("health = %v %q %v", healthy, reason, details)
	}
	if stats := dns.Stats(); len(stats) != 1 || stats[0].Refused != 1 || stats[0].Listed != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestURIDomainExtraction(t *testing.T) {
	html := `<html><body><a href="https://user@www.Phish.co.uk/login">Your bank</a>` +
		`<img src="//cdn.tracker-net.com/p.gif"><a href="mailto:sales@mailer-org.com?subject=x">mail</a>` +
		`<a href="/relative">x</a><a href="http://192.0.2.4/">ip</a><a href="http://intranet.test/">t</a>` +
		`<a href="http://%65vil.com/">enc</a><script>var u="http://script-host.biz"</script></body></html>`
	text := "Visit hxxp://defanged[.]com/now or www.bare-www.org, or evil (dot) net, write to x@contact.de, see readme.txt and example.com."
	quoted := "Click =\r\nhttp://soft-break=2Einfo/path"
	encoded := base64.StdEncoding.EncodeToString([]byte("base64 link https://hidden-link.io/x"))
	body := "--b\r\nContent-Type: text/plain\r\n\r\n" + text + "\r\n" +
		"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + quoted + "\r\n" +
		"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n" +
		"--b\r\nContent-Type: text/html\r\n\r\n" + html + "\r\n--b--\r\n"
	headers := map[string]string{"From": "a@b.example", "MIME-Version": "1.0", "Content-Type": `multipart/mixed; boundary="b"`}
	got := extractURIDomains(parseContent(rawMessage(headers, body)), 50)
	want := []string{"phish.co.uk", "tracker-net.com", "mailer-org.com", "evil.com", "defanged.com", "bare-www.org", "evil.net", "contact.de", "soft-break.info", "hidden-link.io"}
	for _, domain := range want {
		if !slices.Contains(got, domain) {
			t.Errorf("domains %v lack %s", got, domain)
		}
	}
	for _, unwanted := range []string{"192.0.2.4", "intranet.test", "example.com", "readme.txt", "script-host.biz", "www.phish.co.uk"} {
		if slices.Contains(got, unwanted) {
			t.Errorf("domains %v include %s", got, unwanted)
		}
	}
	if got[0] != "phish.co.uk" {
		t.Errorf("link attributes must come first: %v", got)
	}
	if capped := extractURIDomains(parseContent(rawMessage(headers, body)), 3); len(capped) != 3 {
		t.Errorf("cap ignored: %v", capped)
	}
}

func TestURIBLAndRHSBLLookups(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{
		"phish.co.uk.dbl.spamhaus.org":    {"127.0.1.4"},
		"phish.co.uk.multi.uribl.com":     {"127.0.0.2"},
		"bad-sender.net.dbl.spamhaus.org": {"127.0.1.2"},
	}}
	hosted := map[string]bool{"hosted.example.net": true}
	engine, _ := newTestEngine(t, resolver, func(_ *Settings, config *Config) {
		if config != nil {
			config.IsLocalDomain = func(_ context.Context, domain string) bool { return hosted[domain] }
			config.MaxURIDomains = 2
		}
	})
	headers := completeHeaders()
	headers["From"] = "Bank <alerts@mail.bad-sender.net>"
	body := `Go to https://www.phish.co.uk/login, https://hosted.example.net/x, https://second-link.biz and https://third-link.io`
	result := check(t, engine, Message{Headers: headers, Content: rawMessage(headers, body), RemoteIP: publicIP, EnvelopeFrom: "bounce@bad-sender.net", Helo: "mx.helo-domain.org"})
	for name, score := range map[string]float64{"URIBL_DBL_PHISH": 7, "URIBL_BLACK": 5, "RHSBL_DBL_SPAM": 4} {
		if symbol, ok := findSymbol(result, name); !ok || symbol.Score != score {
			t.Fatalf("symbol %s missing: %v", name, symbolNames(result))
		}
	}
	queried := resolver.queried()
	for _, name := range []string{"helo-domain.org.dbl.spamhaus.org", "second-link.biz.multi.surbl.org"} {
		if !slices.Contains(queried, name) {
			t.Errorf("queries lack %s: %v", name, queried)
		}
	}
	for _, query := range queried {
		if strings.HasPrefix(query, "hosted.example.net.") || strings.HasPrefix(query, "third-link.io.") || strings.HasPrefix(query, "www.") {
			t.Errorf("unexpected query %s (hosted, over the cap, or not normalized)", query)
		}
	}
	if result.Action != ActionReject {
		t.Fatalf("score %v action %v", result.Score, result.Action)
	}
}

func TestDNSCacheAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{answers: map[string][]string{"7.113.0.203.zen.spamhaus.org": {"127.0.0.2"}}}
	dns := NewDNS(resolver, DNSOptions{Now: func() time.Time { return now }, PositiveTTL: time.Minute, NegativeTTL: 30 * time.Second, MaxEntries: 100})
	config, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), DNSBL: []string{"zen.spamhaus.org", "bl.spamcop.net"}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, dns)
	if err != nil {
		t.Fatal(err)
	}
	message := Message{Headers: completeHeaders(), RemoteIP: publicIP}
	first := check(t, engine, message)
	second := check(t, engine, message)
	if resolver.count.Load() != 2 || first.Score != second.Score {
		t.Fatalf("second check re-queried: %d lookups", resolver.count.Load())
	}
	now = now.Add(45 * time.Second) // negative answer expired, positive still cached
	check(t, engine, message)
	if resolver.count.Load() != 3 {
		t.Fatalf("lookups after negative expiry = %d, want 3", resolver.count.Load())
	}
	now = now.Add(time.Minute)
	check(t, engine, message)
	if resolver.count.Load() != 5 {
		t.Fatalf("lookups after full expiry = %d, want 5", resolver.count.Load())
	}
	dns.SetResolver(resolver, "127.0.0.1:53")
	if dns.CacheLen() != 0 {
		t.Fatal("changing the resolver must clear cached answers")
	}
	for index := range 250 {
		dns.store(string(rune('a'+index%26))+strings.Repeat("x", index), nil)
	}
	if dns.CacheLen() > 100 {
		t.Fatalf("cache grew to %d entries past its bound", dns.CacheLen())
	}
	// Failures are never cached.
	failing := &fakeResolver{errs: map[string]error{"7.113.0.203.zen.spamhaus.org": errors.New("server failure")}}
	dns.SetResolver(failing, "127.0.0.2:53")
	check(t, engine, message)
	check(t, engine, message)
	if failing.count.Load() != 3 {
		t.Fatalf("failing lookups = %d; errors must not be cached", failing.count.Load())
	}
}

func TestDNSBudgetBoundsSlowResolvers(t *testing.T) {
	resolver := &fakeResolver{block: true}
	engine, dns := newTestEngine(t, resolver, func(_ *Settings, config *Config) {
		if config != nil {
			config.Budget = 50 * time.Millisecond
		}
	})
	started := time.Now()
	result := check(t, engine, Message{Headers: completeHeaders(), RemoteIP: publicIP})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("check took %v despite a 50ms budget", elapsed)
	}
	if _, ok := findSymbol(result, "DNS_LOOKUP_ERROR"); !ok || result.Score != 0 {
		t.Fatalf("timeouts must be recorded as lookup errors: %+v", result.Symbols)
	}
	healthy, _, _ := dns.Health(engine.config.DNSBL)
	if healthy {
		t.Fatal("failing zones must degrade health")
	}
}

func TestNoLookupsForTrustedPrivateOrAuthenticated(t *testing.T) {
	resolver := &fakeResolver{}
	engine, _ := newTestEngine(t, resolver, func(_ *Settings, config *Config) {
		if config != nil {
			config.TrustedNetworks = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		}
	})
	headers := completeHeaders()
	content := rawMessage(headers, "https://phish.co.uk")
	for ip, reason := range map[string]string{"127.0.0.1": "loopback or private client address", "10.1.2.3": "loopback or private client address", "fd00::1": "loopback or private client address", "198.51.100.9": "trusted network", "": "no client address"} {
		result := check(t, engine, Message{Headers: headers, Content: content, RemoteIP: ip, EnvelopeFrom: "a@remote.example.net"})
		if result.Skipped != reason {
			t.Errorf("%q skipped = %q, want %q", ip, result.Skipped, reason)
		}
	}
	authenticated := check(t, engine, Message{Headers: headers, Content: content, RemoteIP: publicIP, Authenticated: true})
	if authenticated.Skipped != "authenticated submission" || len(authenticated.Symbols) != 0 {
		t.Fatalf("authenticated = %+v", authenticated)
	}
	if count := resolver.count.Load(); count != 0 {
		t.Fatalf("%d lookups for exempt sources: %v", count, resolver.queried())
	}
}

func TestCheckOutboundScoresContentWithoutHostRules(t *testing.T) {
	resolver := &fakeResolver{}
	engine, _ := newTestEngine(t, resolver, nil)
	headers := completeHeaders()
	ordinary, ok := engine.CheckOutbound(context.Background(), Message{Headers: headers, Content: rawMessage(headers, "See you tomorrow."), RemoteIP: publicIP, SPF: "fail", Authenticated: true})
	if !ok || ordinary.Score >= DefaultThresholds().Junk {
		t.Fatalf("ordinary outbound message = %+v", ordinary)
	}
	if _, found := findSymbol(ordinary, "SPF_FAIL"); found {
		t.Fatal("authentication rules scored an outbound message")
	}
	spammy := map[string]string{"Subject": "FREE MONEY!!! ACT NOW"}
	result, _ := engine.CheckOutbound(context.Background(), Message{Headers: spammy, Content: rawMessage(spammy, "click https://phish.co.uk"), Authenticated: true})
	if result.Score <= ordinary.Score || len(result.Symbols) == 0 {
		t.Fatalf("content rules did not score a spammy submission: %+v", result)
	}
	if count := resolver.count.Load(); count != 0 {
		t.Fatalf("outbound scoring queried blocklists: %v", resolver.queried())
	}
	if _, ok := (*Engine)(nil).CheckOutbound(context.Background(), Message{}); ok {
		t.Fatal("nil engine scored")
	}
}

func TestListMatches(t *testing.T) {
	entries := []string{"trusted@example.com", "partner.com"}
	for sender, want := range map[string]bool{
		"trusted@example.com": true, "TRUSTED@EXAMPLE.COM": true, "Trusted <trusted@example.com>": true,
		"user@partner.com": true, "spammer@evil.com": false, "user@notpartner.com": false, "": false,
	} {
		if got := ListMatches(entries, sender); got != want {
			t.Errorf("ListMatches(%q) = %v, want %v", sender, got, want)
		}
	}
}

func TestAddHeadersAndScanResult(t *testing.T) {
	result := Result{Score: 7.25, Action: ActionJunk, Thresholds: DefaultThresholds(), Symbols: []Symbol{
		{Name: "RBL_SPAMCOP", Score: 3, Description: "Listed by SpamCop", Options: []string{publicIP}},
		{Name: "CAPS_SUBJECT", Score: 1.5},
	}}
	headers := map[string]string{"X-Spam-Flag": "stale"}
	AddHeaders(headers, result, 6, true)
	if headers["X-Spam-Score"] != "7.2" || headers["X-Spam-Flag"] != "YES" ||
		headers["X-Spam-Status"] != "Yes, score=7.2 required=6 tests=[RBL_SPAMCOP,CAPS_SUBJECT]" ||
		headers["X-Spam-Symbols"] != "RBL_SPAMCOP(3), CAPS_SUBJECT(1.5)" {
		t.Fatalf("headers = %#v", headers)
	}
	AddHeaders(headers, Result{}, 6, false)
	if _, flagged := headers["X-Spam-Flag"]; flagged || !strings.HasPrefix(headers["X-Spam-Status"], "No, score=0") || headers["X-Spam-Symbols"] != "" {
		t.Fatalf("clean headers = %#v", headers)
	}
	many := Result{}
	for range 200 {
		many.Symbols = append(many.Symbols, Symbol{Name: "URIBL_DBL_ABUSED_REDIRECTOR", Score: 1})
	}
	AddHeaders(headers, many, 6, false)
	if len(headers["X-Spam-Symbols"]) > maxHeaderBytes || len(headers["X-Spam-Status"]) > maxHeaderBytes+64 {
		t.Fatal("headers are not bounded")
	}
	scan := result.ScanResult()
	if scan.Engine != EngineName || scan.Verdict != contentscan.VerdictSpam || scan.RequiredScore != 6 || scan.Symbols[0].Description != "Listed by SpamCop ["+publicIP+"]" {
		t.Fatalf("scan result = %+v", scan)
	}
	for input, want := range map[float64]string{0: "0", 5: "5", 5.5: "5.5", 3.14: "3.1", -0.01: "0", 99: "99"} {
		if got := formatScore(input); got != want {
			t.Errorf("formatScore(%v) = %q, want %q", input, got, want)
		}
	}
}

func TestSwitchAndResolverAddress(t *testing.T) {
	var scoring Switch
	if _, ok := scoring.Check(context.Background(), Message{}); ok || scoring.Enabled() {
		t.Fatal("an empty switch must not score")
	}
	scoring.Set(heuristicEngine(t))
	if _, ok := scoring.Check(context.Background(), Message{Headers: completeHeaders()}); !ok {
		t.Fatal("installed engine did not score")
	}
	for input, want := range map[string]string{"": "", "127.0.0.1": "127.0.0.1:53", "::1": "[::1]:53", "[::1]:5353": "[::1]:5353", "10.0.0.2:53": "10.0.0.2:53"} {
		if got, err := ResolverAddress(input); err != nil || got != want {
			t.Errorf("ResolverAddress(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, invalid := range []string{"resolver.example.com", "127.0.0.1:0", "127.0.0.1:x"} {
		if _, err := ResolverAddress(invalid); err == nil {
			t.Errorf("ResolverAddress(%q) validated", invalid)
		}
	}
}

func TestIsAllCapsAndPhrases(t *testing.T) {
	for input, want := range map[string]bool{"BUY VIAGRA NOW!!!": true, "URGENT ACTION REQUIRED": true, "Hello World": false, "short": false, "ACT": false, "BUY buy now": false} {
		if got := isAllCaps(input); got != want {
			t.Errorf("isAllCaps(%q) = %v", input, got)
		}
	}
	for subject, want := range map[string]bool{"Check out this viagra deal": true, "You won the lottery!": true, "Congratulations winner!": true, "Meeting notes": false} {
		if got := matchSpamPhrase(subject) != ""; got != want {
			t.Errorf("matchSpamPhrase(%q) = %v", subject, got)
		}
	}
	if calculateHTMLRatio([]byte("plain text only")) != 0 || calculateHTMLRatio([]byte("<html><body><div><span><p>Hi</p></span></div></body></html>")) <= 10 {
		t.Fatal("HTML ratio heuristic changed")
	}
	if !excessiveSalesWords("Buy now! Order today! Limited time offer!") || excessiveSalesWords("Let's catch up sometime.") {
		t.Fatal("sales language heuristic changed")
	}
	for input, want := range map[string]string{"alice@example.com": "example.com", "Alice <alice@Example.com>": "example.com", "Example.com": "example.com"} {
		if got := extractDomain(input); got != want {
			t.Errorf("extractDomain(%q) = %q", input, got)
		}
	}
}
