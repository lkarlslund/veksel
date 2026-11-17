package spam

import (
	"context"
	"strconv"
	"testing"
	"time"
)

type reputationClock struct{ now time.Time }

func (c *reputationClock) Now() time.Time { return c.now }

func newTestReputation(minSamples int) (*Reputation, *reputationClock) {
	clock := &reputationClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	r := &Reputation{Now: clock.Now, MaxEntries: 100}
	r.SetSettings(true, minSamples)
	return r, clock
}

func repSymbol(result Result, name string) (Symbol, bool) {
	for _, symbol := range result.Symbols {
		if symbol.Name == name {
			return symbol, true
		}
	}
	return Symbol{}, false
}

func TestReputationGatesOnMinimumSamplesAndScalesByConfidence(t *testing.T) {
	r, _ := newTestReputation(10)
	keys := ReputationKeys{Domain: "bad.example", Network: "203.0.113.0/24"}
	for range 9 {
		r.Record(keys, RepJunked)
	}
	if signals := r.Assess(keys); len(signals) != 0 {
		t.Fatalf("signals below the minimum = %+v", signals)
	}
	r.Record(keys, RepJunked)
	signals := r.Assess(keys)
	if len(signals) != 2 || signals[0].Symbol != "REP_DOMAIN_BAD" || signals[1].Symbol != "REP_IP_BAD" {
		t.Fatalf("signals = %+v", signals)
	}
	first := signals[0].Scale
	for range 30 {
		r.Record(keys, RepRejected)
	}
	if later := r.Assess(keys)[0].Scale; later <= first || later > 1 {
		t.Fatalf("confidence did not grow: %v then %v", first, later)
	}
}

func TestReputationGoodDomainAndUserFeedback(t *testing.T) {
	r, _ := newTestReputation(5)
	keys := ReputationKeys{Domain: "news.example", Network: "198.51.100.0/24"}
	for range 10 {
		r.Record(keys, RepAccepted)
	}
	signals := r.Assess(keys)
	if len(signals) != 1 || signals[0].Symbol != "REP_DOMAIN_GOOD" {
		t.Fatalf("good sender signals = %+v", signals)
	}
	// Users filing the sender's mail as spam outweigh automatic acceptance.
	headers := map[string]string{ReputationHeader: keys.Header()}
	for range 8 {
		r.Moved(headers, true)
	}
	signals = r.Assess(keys)
	if len(signals) != 2 || signals[0].Symbol != "REP_DOMAIN_BAD" {
		t.Fatalf("after user Junk moves = %+v", signals)
	}
	for range 80 {
		r.Moved(headers, false)
	}
	if signals = r.Assess(keys); len(signals) != 1 || signals[0].Symbol != "REP_DOMAIN_GOOD" {
		t.Fatalf("after user Not-junk moves = %+v", signals)
	}
	r.Released(map[string]string{ReputationHeader: "d=other.example"})
	if report := r.Report(5); report.Tracked != 3 {
		t.Fatalf("tracked = %d", report.Tracked)
	}
}

func TestReputationForgedHeaderValuesAreIgnored(t *testing.T) {
	for _, value := range []string{"", "d=; n=", "n=10.0.0.0/8", "n=203.0.113.9/24x", "d=a b", "d=x;y=z;n=2001:db8::/32"} {
		keys := ParseReputationKeys(value)
		if keys.Network != "" && keys.Network != "2001:db8::/48" {
			t.Fatalf("%q parsed to %+v", value, keys)
		}
		if keys.Domain != "" && keys.Domain != "x" {
			t.Fatalf("%q parsed to %+v", value, keys)
		}
	}
	keys := ParseReputationKeys(ReputationKeys{Domain: "a.example", Network: ReputationNetwork("2001:db8:1:2::9")}.Header())
	if keys.Domain != "a.example" || keys.Network != "2001:db8:1::/48" {
		t.Fatalf("round trip = %+v", keys)
	}
}

func TestReputationDecaysWithTheHalfLife(t *testing.T) {
	r, clock := newTestReputation(10)
	keys := ReputationKeys{Domain: "old.example"}
	for range 40 {
		r.Record(keys, RepJunked)
	}
	if len(r.Assess(keys)) != 1 {
		t.Fatal("fresh evidence did not score")
	}
	clock.now = clock.now.Add(DefaultReputationHalfLife)
	report := r.Report(5)
	if got := report.BadDomains[0].Samples; got < 19.9 || got > 20.1 {
		t.Fatalf("one half-life left %v samples, want 20", got)
	}
	clock.now = clock.now.Add(3 * DefaultReputationHalfLife)
	if signals := r.Assess(keys); len(signals) != 0 {
		t.Fatalf("decayed evidence still scores: %+v", signals)
	}
	r.Record(keys, RepAccepted)
	if report = r.Report(5); len(report.BadDomains) != 0 || report.Tracked != 1 {
		t.Fatalf("report after decay = %+v", report)
	}
}

func TestReputationStoreIsBoundedAndSurvivesSnapshots(t *testing.T) {
	r, clock := newTestReputation(1)
	r.MaxEntries = 3
	for i := range 5 {
		clock.now = clock.now.Add(time.Minute)
		r.Record(ReputationKeys{Domain: "d" + strconv.Itoa(i) + ".example"}, RepJunked)
	}
	report := r.Report(10)
	if report.Tracked != 3 {
		t.Fatalf("tracked = %d, want the cap of 3", report.Tracked)
	}
	for _, entry := range report.BadDomains {
		if entry.Key == "d0.example" || entry.Key == "d1.example" {
			t.Fatalf("least recently updated sender survived: %+v", report.BadDomains)
		}
	}
	data, err := r.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := newTestReputation(1)
	restored.MaxEntries = 2
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}
	if got := restored.Report(10); got.Tracked != 2 || got.BadDomains[0].Key == "d2.example" {
		t.Fatalf("restored = %+v", got)
	}
	restored.Reset()
	if restored.Report(10).Tracked != 0 {
		t.Fatal("reset kept senders")
	}
}

func TestEngineScoresAndRecordsReputation(t *testing.T) {
	r, _ := newTestReputation(5)
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), Reputation: r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	spamMessage := Message{
		Content:    []byte("From: x@bad.example\r\nSubject: FREE CASH NOW!!!\r\n\r\nbuy now\r\n"),
		Headers:    map[string]string{"From": "x@bad.example", "Subject": "FREE CASH NOW!!!"},
		RemoteIP:   publicIP,
		AuthDomain: "bad.example", SPF: "softfail", DKIM: "none", DMARC: "fail",
	}
	for range 5 {
		first, ok := engine.Check(context.Background(), spamMessage)
		if !ok || first.Score < first.Thresholds.Junk {
			t.Fatalf("test message is not junk: %+v", first)
		}
		if _, scored := repSymbol(first, "REP_DOMAIN_BAD"); scored {
			t.Fatalf("reputation scored before the minimum: %+v", first.Symbols)
		}
		if first.Reputation.Domain != "bad.example" || first.Reputation.Network != "203.0.113.0/24" {
			t.Fatalf("keys = %+v", first.Reputation)
		}
	}
	scored, _ := engine.Check(context.Background(), spamMessage)
	domain, ok := repSymbol(scored, "REP_DOMAIN_BAD")
	if !ok || domain.Score <= 0 || domain.Score > 3 {
		t.Fatalf("REP_DOMAIN_BAD = %+v in %+v", domain, scored.Symbols)
	}
	if _, ok := repSymbol(scored, "REP_IP_BAD"); !ok {
		t.Fatalf("REP_IP_BAD missing in %+v", scored.Symbols)
	}
	headers := map[string]string{"x-veksel-reputation": "d=forged.example"}
	StampReputation(headers, scored)
	if len(headers) != 1 || ParseReputationKeys(headers[ReputationHeader]) != scored.Reputation {
		t.Fatalf("stamped headers = %v", headers)
	}

	// Reputation can be switched off live and never tracks trusted networks.
	r.SetSettings(false, 5)
	off, _ := engine.Check(context.Background(), spamMessage)
	if _, ok := repSymbol(off, "REP_DOMAIN_BAD"); ok || off.Reputation != (ReputationKeys{}) {
		t.Fatalf("disabled reputation scored: %+v", off)
	}
	r.SetSettings(true, 5)
	spamMessage.RemoteIP = "10.1.2.3"
	if local, _ := engine.Check(context.Background(), spamMessage); local.Reputation != (ReputationKeys{}) {
		t.Fatalf("private network tracked: %+v", local.Reputation)
	}
}

func TestEngineReputationAppliesSymbolOverridesAndGoodDomains(t *testing.T) {
	r, _ := newTestReputation(3)
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), Reputation: r, SymbolScores: map[string]float64{"REP_DOMAIN_GOOD": -4}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ham := Message{
		Content:  []byte("From: a@good.example\r\nSubject: Minutes\r\nMessage-ID: <1@good.example>\r\nDate: Mon, 1 Jan 2026 00:00:00 +0000\r\n\r\nSee attached notes.\r\n"),
		Headers:  map[string]string{"From": "a@good.example", "Subject": "Minutes", "Message-ID": "<1@good.example>", "Date": "Mon, 1 Jan 2026 00:00:00 +0000"},
		RemoteIP: publicIP, AuthDomain: "good.example", SPF: "pass", DKIM: "pass", DMARC: "pass",
	}
	for range 12 {
		engine.Check(context.Background(), ham)
	}
	result, _ := engine.Check(context.Background(), ham)
	symbol, ok := repSymbol(result, "REP_DOMAIN_GOOD")
	if !ok || symbol.Score >= 0 || symbol.Score < -4 {
		t.Fatalf("REP_DOMAIN_GOOD = %+v in %+v", symbol, result.Symbols)
	}
}

func TestSenderAuthRequiresAlignment(t *testing.T) {
	cases := []struct {
		name        string
		auth        SenderAuth
		wantAddress string
		wantDomain  string
		wantAligned bool
	}{
		{"dmarc pass", SenderAuth{From: "Ann <Ann@Mail.Example.com>", DMARCPass: true}, "ann@mail.example.com", "example.com", true},
		{"aligned dkim", SenderAuth{From: "a@example.com", DKIMPass: true, DKIMDomain: "news.example.com"}, "a@example.com", "example.com", true},
		{"aligned spf", SenderAuth{From: "a@example.com", SPFPass: true, SPFDomain: "bounce.example.com"}, "a@example.com", "example.com", true},
		{"forged from with unrelated dkim", SenderAuth{From: "boss@victim.example", DKIMPass: true, DKIMDomain: "attacker.example"}, "boss@victim.example", "attacker.example", false},
		{"forged from with unrelated spf", SenderAuth{From: "boss@victim.example", SPFPass: true, SPFDomain: "attacker.example"}, "boss@victim.example", "", false},
		{"nothing passed", SenderAuth{From: "a@example.com"}, "a@example.com", "", false},
		{"no address", SenderAuth{From: "undisclosed", DMARCPass: true}, "", "", false},
	}
	for _, tc := range cases {
		address, domain, aligned := tc.auth.Sender()
		if address != tc.wantAddress || domain != tc.wantDomain || aligned != tc.wantAligned {
			t.Errorf("%s: Sender() = %q, %q, %v", tc.name, address, domain, aligned)
		}
	}
}

func TestResultWithSymbolReplacesAndRescores(t *testing.T) {
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), SymbolScores: map[string]float64{SymbolKnownCorrespondent: -2}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	symbol, ok := engine.BuiltinSymbol(SymbolKnownCorrespondent)
	if !ok || symbol.Score != -2 {
		t.Fatalf("symbol = %+v", symbol)
	}
	result := Result{Thresholds: DefaultThresholds(), Score: 7, Action: ActionJunk, Symbols: []Symbol{{Name: "SPAM_PHRASE", Score: 7}}}
	result = result.WithSymbol(symbol).WithSymbol(symbol)
	if result.Score != 5 || result.Action != ActionGreylist || len(result.Symbols) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if _, ok := (*Engine)(nil).BuiltinSymbol(SymbolKnownCorrespondent); ok {
		t.Fatal("a nil engine produced a symbol")
	}
}
