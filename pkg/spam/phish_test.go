package spam

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDirectory struct {
	identities LocalIdentities
	err        error
	loads      atomic.Int64
}

func (d *fakeDirectory) LocalIdentities(context.Context) (LocalIdentities, error) {
	d.loads.Add(1)
	return d.identities, d.err
}

func phishEngine(t *testing.T, brands ...string) *Engine {
	t.Helper()
	config, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), ProtectedBrands: brands, URLShorteners: DefaultURLShorteners()})
	if err != nil {
		t.Fatal(err)
	}
	config.Identities = NewIdentityCache(&fakeDirectory{identities: LocalIdentities{
		Domains:      []string{"acmecorp.com", "Veksel-Mail.dk"},
		DisplayNames: []string{"Alice Andersen", "Admin", "Bob  Builder"},
	}}, time.Minute)
	engine, err := NewEngine(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// phishMessage builds a message from header lines and an optional HTML body.
func phishMessage(dmarc, htmlBody string, headers ...string) Message {
	parsed := map[string]string{}
	var raw strings.Builder
	for _, header := range headers {
		name, value, _ := strings.Cut(header, ": ")
		parsed[name] = value
		raw.WriteString(header + "\r\n")
	}
	if htmlBody != "" {
		raw.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	}
	raw.WriteString("\r\n" + htmlBody + "\r\n")
	return Message{Content: []byte(raw.String()), Headers: parsed, DMARC: dmarc}
}

func phishSymbols(t *testing.T, engine *Engine, m Message) map[string]Symbol {
	t.Helper()
	result, ok := engine.Check(context.Background(), m)
	if !ok {
		t.Fatal("engine did not check")
	}
	found := map[string]Symbol{}
	for _, symbol := range result.Symbols {
		if strings.HasPrefix(symbol.Name, "PHISH_") {
			found[symbol.Name] = symbol
		}
	}
	return found
}

func TestPhishingSymbolsFireWithEvidence(t *testing.T) {
	engine := phishEngine(t, "PayPal", "bankofamerica.com", "Contoso Bank")
	tests := []struct {
		name    string
		message Message
		symbol  string
		option  string
	}{
		{"display address", phishMessage("pass", "", `From: "support@paypal.com" <x@mailer-host.net>`), symbolPhishDisplayAddr, "support@paypal.com"},
		{"display domain", phishMessage("pass", "", `From: "Microsoft.com Security" <x@mailer-host.net>`), symbolPhishDisplayAddr, "Microsoft.com Security"},
		{"local user name", phishMessage("pass", "", `From: "alice  ANDERSEN" <ceo.alice@gmail.com>`), symbolPhishInternalName, "alice  ANDERSEN"},
		{"homoglyph local user", phishMessage("pass", "", `From: "Аlice Andersen" <a@gmail.com>`), symbolPhishInternalName, "Аlice Andersen"},
		{"hosted domain name", phishMessage("pass", "", `From: "AcmeCorp IT Helpdesk" <it@helpdesk-mail.net>`), symbolPhishInternalName, "AcmeCorp IT Helpdesk ~ acmecorp.com"},
		{"lookalike sender", phishMessage("pass", "", "From: billing@acmec0rp.com"), symbolPhishLookalike, "acmec0rp.com ~ acmecorp.com"},
		{"edit distance sender", phishMessage("pass", "", "From: billing@acmecrop.com"), symbolPhishLookalike, "acmecrop.com ~ acmecorp.com"},
		{"rn for m", phishMessage("pass", "", "From: x@bankofarnerica.com"), symbolPhishLookalike, "bankofarnerica.com ~ bankofamerica.com"},
		{"hyphen brand", phishMessage("pass", "", "From: x@paypal-secure.net"), symbolPhishLookalike, "paypal-secure.net ~ PayPal"},
		{"lookalike reply-to", phishMessage("pass", "", "From: a@partner.org", "Reply-To: a@veksel-rnail.dk"), symbolPhishLookalike, "veksel-rnail.dk ~ veksel-mail.dk"},
		{"cyrillic idn", phishMessage("", "", "From: x@xn--pypal-4ve.com"), symbolPhishMixedScript, "pаypal.com"},
		{"cyrillic idn lookalike", phishMessage("", "", "From: x@xn--pypal-4ve.com"), symbolPhishLookalike, "pаypal.com ~ PayPal"},
		{"freemail reply-to", phishMessage("pass", "", "From: boss@gmail.com", "Reply-To: boss@outlook.com"), symbolPhishReplyTo, "gmail.com -> outlook.com"},
		{"hosted reply-to", phishMessage("pass", "", "From: ceo@acmecorp.com", "Reply-To: ceo@acme-payments.net"), symbolPhishReplyTo, "acmecorp.com -> acme-payments.net"},
		{"href mismatch", phishMessage("pass", `<a href="https://login.evil-site.net/x">https://www.paypal.com/signin</a>`, "From: a@shop.org"), symbolPhishHrefMismatch, "paypal.com -> evil-site.net"},
		{"href mismatch nested", phishMessage("pass", `<a href="http://198.51.100.4/"><b>secure.acmecorp.com</b></a>`, "From: a@shop.org"), symbolPhishHrefMismatch, "acmecorp.com -> 198.51.100.4"},
		{"ip link", phishMessage("pass", `<a href="http://198.51.100.4/login">Log in</a>`, "From: a@shop.org"), symbolPhishURLIP, "198.51.100.4"},
		{"decimal ip link", phishMessage("pass", `<a href="http://3325256708/">x</a>`, "From: a@shop.org"), symbolPhishURLIP, "3325256708"},
		{"shortener", phishMessage("pass", `<a href="https://bit.ly/3abc">x</a>`, "From: a@shop.org"), symbolPhishURLShortener, "bit.ly"},
		{"javascript uri", phishMessage("pass", `<a href=" java&#9;script:alert(1)">x</a>`, "From: a@shop.org"), symbolPhishURLScript, " java script:alert(1)"},
		{"data uri", phishMessage("pass", `<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>`, "From: a@shop.org"), symbolPhishURLScript, "data:text/html;base64,PHNjcmlwdD4="},
		{"password field", phishMessage("pass", `<form><input type="Password" name="p"></form>`, "From: a@shop.org"), symbolPhishHTMLForm, "password field"},
		{"off-domain form", phishMessage("pass", `<form action="https://collect.harvest.ru/p" method="post"><input name="u"></form>`, "From: a@shop.org"), symbolPhishHTMLForm, "form posts to harvest.ru"},
		{"brand in display name", phishMessage("pass", "", `From: "PayPal Service" <service@notify-center.com>`), symbolPhishBrand, "PayPal"},
		{"brand in subject", phishMessage("pass", "", "From: x@notify-center.com", "Subject: Your CONTOSO  bank account is locked"), symbolPhishBrand, "Contoso Bank"},
		{"confusable brand in subject", phishMessage("pass", "", "From: x@notify-center.com", "Subject: =?utf-8?b?UGF5UGFJIGFsZXJ0?="), symbolPhishBrand, "PayPal"},
		{"brand without dmarc pass", phishMessage("fail", "", `From: "PayPal" <service@paypal.com>`), symbolPhishBrand, "PayPal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found := phishSymbols(t, engine, test.message)
			symbol, ok := found[test.symbol]
			if !ok {
				t.Fatalf("%s missing; got %+v", test.symbol, found)
			}
			if symbol.Score != builtinSymbols[test.symbol].score || symbol.Description == "" {
				t.Fatalf("symbol = %+v", symbol)
			}
			for _, option := range symbol.Options {
				if option == test.option {
					return
				}
			}
			t.Fatalf("%s options = %q, want %q", test.symbol, symbol.Options, test.option)
		})
	}
}

func TestPhishingFalsePositiveGuards(t *testing.T) {
	engine := phishEngine(t, "PayPal")
	tests := []struct {
		name    string
		message Message
	}{
		{"plain display name", phishMessage("", "", `From: "Carol Jensen" <carol@partner.org>`)},
		{"display shows own domain", phishMessage("", "", `From: "carol@partner.org" <carol@mail.partner.org>`)},
		{"display shows sibling suffix", phishMessage("", "", `From: "Amazon.com" <ship@amazon.de>`)},
		{"display name with dotted title", phishMessage("", "", `From: "Dr.Smith" <s@clinic.org>`)},
		{"single word local name", phishMessage("", "", `From: "Admin" <admin@partner.org>`)},
		{"local user from hosted domain", phishMessage("", "", `From: "Alice Andersen" <alice@acmecorp.com>`)},
		{"same org reply-to", phishMessage("", "", "From: news@mail.partner.org", "Reply-To: support@partner.org")},
		{"external reply-to from company", phishMessage("", "", "From: news@partner.org", "Reply-To: replies@esp-host.net")},
		{"internal links", phishMessage("", `<a href="https://www.partner.org/a">www.partner.org</a> <a href="https://partner.org/b">Read more</a> <img src="cid:logo">`, "From: news@partner.org")},
		{"same label link text", phishMessage("", `<a href="https://shop.partner.de/">partner.com</a>`, "From: news@partner.org")},
		{"inline image data uri", phishMessage("", `<img src="data:image/png;base64,AAAA">`, "From: news@partner.org")},
		{"form on own domain", phishMessage("", `<form action="https://survey.partner.org/s"><input name="q"></form>`, "From: news@partner.org")},
		{"single-script idn", phishMessage("", "", "From: info@xn--mnchen-3ya.de")},
		{"cyrillic idn", phishMessage("", "", "From: info@xn--d1acpjx3f.xn--p1ai")},
		{"japanese mixed idn", phishMessage("", "", "From: info@xn--abc-7k4bocn.jp")},
		{"genuine brand", phishMessage("pass", "", `From: "PayPal" <service@paypal.com>`, "Subject: Your PayPal receipt")},
		{"genuine brand other suffix", phishMessage("pass", "", `From: "PayPal" <service@paypal.de>`)},
		{"brand word inside another", phishMessage("", "", "From: x@partner.org", "Subject: paypalooza festival")},
		{"short unrelated domain", phishMessage("", "", "From: x@acme.org")},
		{"hosted sibling suffix", phishMessage("", "", "From: x@acmecorp.net")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if found := phishSymbols(t, engine, test.message); len(found) > 0 {
				t.Fatalf("false positive: %+v", found)
			}
		})
	}
}

func TestSkeletonAndEditDistance(t *testing.T) {
	for _, pair := range [][2]string{
		{"paypal", "pаypаl"}, // Cyrillic а
		{"paypal", "PAYPAI"}, // capital I for l
		{"google", "g00gle"},
		{"microsoft", "rnicrosoft"},
		{"apple", "аррӏе"},   // whole-script Cyrillic
		{"amazon", "αmαzοn"}, // Greek alpha and omicron
		{"cafe", "café"},
		{"wells", "vvells"},
	} {
		if skeleton(pair[0]) != skeleton(pair[1]) {
			t.Errorf("skeleton(%q)=%q differs from skeleton(%q)=%q", pair[0], skeleton(pair[0]), pair[1], skeleton(pair[1]))
		}
	}
	if skeleton("paypal") == skeleton("paypa") {
		t.Fatal("distinct strings share a skeleton")
	}
	for _, test := range []struct {
		a, b string
		want int
	}{
		{"acmecorp", "acmecorp", 0}, {"acmecorp", "acmecrop", 1}, {"acmecorp", "acmcorp", 1},
		{"acmecorp", "acmecorpp", 1}, {"acmecorp", "axmecorq", 2}, {"kitten", "sitting", 3},
	} {
		if got := editDistance(test.a, test.b); got != test.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", test.a, test.b, got, test.want)
		}
	}
	long := newCandidate("contosobank.com")
	target, _ := newProtected("contosobank.com", "contosobank.com")
	if !imitates(newCandidate("cotnosobnk.com"), target) || imitates(long, target) {
		t.Fatal("distance-two lookalike of a long label")
	}
	short, _ := newProtected("acmecorp.com", "acmecorp.com")
	if imitates(newCandidate("axmecorq.com"), short) {
		t.Fatal("distance two must not match an eight-letter label")
	}
}

func TestMixedScriptAllowsRestrictiveCombinations(t *testing.T) {
	for label, want := range map[string]bool{
		"paypal": false, "pаypal": true, "münchen": false, "пример": false, "αβγ": false,
		"abcテスト": false, "東京abc": false, "한국abc": false, "gοogle": true,
	} {
		if got := mixedScript(label); got != want {
			t.Errorf("mixedScript(%q) = %v, want %v", label, got, want)
		}
	}
}

func TestHTMLAnchorParsing(t *testing.T) {
	evidence := scanHTML(`<p><a href="https://evil.net/a">  <span>www.bank.com</span> </a>
		<a href="https://bank.com/">Sign in</a><a name="x">anchor only</a>
		<script>document.write('<a href="https://x.net">y.com</a>')</script>
		<form action="//collect.example.net/p"><input type=password><button formaction="javascript:go()">Go</button></form>`)
	if len(evidence.anchors) != 2 || strings.TrimSpace(evidence.anchors[0].text) != "www.bank.com" || evidence.anchors[1].text != "Sign in" {
		t.Fatalf("anchors = %+v", evidence.anchors)
	}
	if !evidence.password || len(evidence.forms) != 1 || len(evidence.targets) != 4 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if shown, target, ok := hrefMismatch(evidence.anchors[0]); !ok || shown != "bank.com" || target != "evil.net" {
		t.Fatalf("mismatch = %q %q %v", shown, target, ok)
	}
	if _, _, ok := hrefMismatch(evidence.anchors[1]); ok {
		t.Fatal("ordinary link text reported as a mismatch")
	}
}

func TestPhishingSettingsValidateAndOverride(t *testing.T) {
	for name, settings := range map[string]Settings{
		"short brand":      {ProtectedBrands: []string{"ab"}},
		"bad brand domain": {ProtectedBrands: []string{"brand.invalid"}},
		"long brand":       {ProtectedBrands: []string{strings.Repeat("a", 65)}},
		"bad shortener":    {URLShorteners: []string{"https://bit.ly/"}},
		"too many brands":  {ProtectedBrands: make([]string, maxProtectedBrands+1)},
	} {
		settings.Thresholds = DefaultThresholds()
		if _, err := ParseSettings(settings); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	config, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), ProtectedBrands: []string{" Contoso Bank "}, URLShorteners: []string{"Go.Example.NET."},
		SymbolScores: []string{"PHISH_URL_SHORTENER=2.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if config.URLShorteners[0] != "go.example.net" || config.ProtectedBrands[0] != "Contoso Bank" {
		t.Fatalf("config = %+v", config)
	}
	engine, err := NewEngine(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := phishSymbols(t, engine, phishMessage("", `<a href="https://go.example.net/x">x</a>`, `From: "Contoso Bank" <x@partner.org>`))
	if found[symbolPhishURLShortener].Score != 2.5 || found[symbolPhishBrand].Options[0] != "Contoso Bank" {
		t.Fatalf("symbols = %+v", found)
	}
	long := phishSymbols(t, engine, phishMessage("", "", `From: "Contoso Bank `+strings.Repeat("x", 200)+`" <x@partner.org>`))
	if option := long[symbolPhishBrand].Options[0]; len(option) > maxOptionBytes+len("…") {
		t.Fatalf("option is unbounded: %d bytes", len(option))
	}
	if option := boundOption(strings.Repeat("é", 100)); len(option) > maxOptionBytes+len("…") || !strings.HasSuffix(option, "…") {
		t.Fatalf("bounded option = %q", option)
	}
}

func TestIdentityCacheReloadsAfterTTLAndKeepsStaleOnError(t *testing.T) {
	directory := &fakeDirectory{identities: LocalIdentities{Domains: []string{"acmecorp.com"}}}
	cache := NewIdentityCache(directory, time.Minute)
	now := time.Unix(1000, 0)
	cache.now = func() time.Time { return now }
	for range 3 {
		if got := cache.get(context.Background()); got == nil || !got.domains["acmecorp.com"] {
			t.Fatalf("identities = %+v", got)
		}
	}
	if directory.loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1", directory.loads.Load())
	}
	now = now.Add(2 * time.Minute)
	directory.err = errors.New("store offline")
	if got := cache.get(context.Background()); got == nil || !got.domains["acmecorp.com"] {
		t.Fatal("stale identities dropped on reload error")
	}
	now = now.Add(5 * time.Second)
	cache.get(context.Background())
	if directory.loads.Load() != 2 {
		t.Fatalf("retried before the retry interval: %d loads", directory.loads.Load())
	}
	now = now.Add(identityRetryInterval)
	directory.err = nil
	directory.identities = LocalIdentities{Domains: []string{"other.org"}}
	if got := cache.get(context.Background()); !got.domains["other.org"] || got.domains["acmecorp.com"] {
		t.Fatalf("reloaded identities = %+v", got)
	}
	var nilCache *IdentityCache
	if nilCache.get(context.Background()) != nil {
		t.Fatal("nil cache returned identities")
	}
}
