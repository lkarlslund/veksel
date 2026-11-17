package smtp

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dmarc"
)

// authFixture serves DKIM keys and DMARC records from memory and captures
// what an inbound transaction delivers.
type authFixture struct {
	t       *testing.T
	records map[string]string
	keys    map[string][]byte

	mu        sync.Mutex
	delivered map[string]string
}

func newAuthFixture(t *testing.T) *authFixture {
	return &authFixture{t: t, records: make(map[string]string), keys: make(map[string][]byte)}
}

func (f *authFixture) lookup(_ context.Context, name string) ([]string, error) {
	if record, ok := f.records[strings.TrimSuffix(name, ".")]; ok {
		return []string{record}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// sign adds a DKIM signature for domain with a key published under s1.
func (f *authFixture) sign(message []byte, domain string) []byte {
	f.t.Helper()
	private, ok := f.keys[domain]
	if !ok {
		var public []byte
		var err error
		private, public, err = dkim.GenerateKeyPair()
		if err != nil {
			f.t.Fatal(err)
		}
		f.keys[domain] = private
		f.records["s1._domainkey."+domain] = dkim.DKIMDNSRecord(public)
	}
	signed, err := dkim.Sign(message, domain, "s1", private)
	if err != nil {
		f.t.Fatal(err)
	}
	return signed
}

func (f *authFixture) server(mode DmarcPolicyMode) *tc {
	evaluator := &dmarc.Evaluator{Resolver: smtpTXTResolverFunc(f.lookup), Sample: func(int) bool { return true }}
	return makeTestServer(f.t, &Config{
		ServerName:  "mx.test",
		DkimPolicy:  &DkimPolicy{Mode: DkimPolicyWarn, Verifier: dkim.Verifier{LookupTXT: f.lookup}},
		DmarcPolicy: &DmarcPolicy{Mode: mode, Evaluator: evaluator},
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "folder", "user", nil },
			AppendMessage: func(_ context.Context, _ string, _ []byte, headers map[string]string) (string, error) {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.delivered = headers
				return "item", nil
			},
		},
	})
}

// deliver runs one transaction and returns the final DATA reply code and
// the delivered Authentication-Results.
func (f *authFixture) deliver(mode DmarcPolicyMode, sender string, message []byte) (int, string) {
	f.t.Helper()
	c := f.server(mode)
	c.send("EHLO client.example.net")
	c.send("MAIL FROM:<" + sender + ">")
	c.send("RCPT TO:<user@mx.test>")
	c.send("DATA")
	c.writeData(string(message) + ".\r\n")
	code, _, err := c.readReply()
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return code, f.delivered["Authentication-Results"]
}

const authBody = "To: user@mx.test\r\nSubject: hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <a@example.test>\r\n\r\nHello.\r\n"

// TestDMARCSeesEveryPassingDKIMSignature: a mailing list or ESP signature
// ahead of the author's aligned one used to be the only DKIM domain DMARC
// saw, failing mail the author's own signature authenticates.
func TestDMARCSeesEveryPassingDKIMSignature(t *testing.T) {
	f := newAuthFixture(t)
	f.records["_dmarc.example.test"] = "v=DMARC1; p=reject"
	message := f.sign([]byte("From: Alice <alice@example.test>\r\n"+authBody), "example.test")
	message = f.sign(message, "esp.test")
	code, results := f.deliver(DmarcPolicyReject, "bounce@esp.test", message)
	if code != 250 {
		t.Fatalf("DATA = %d, want 250", code)
	}
	for _, want := range []string{"dmarc=pass", "dkim=pass header.d=esp.test header.s=s1 header.b=", "dkim=pass header.d=example.test header.s=s1 header.b=", "header.from=example.test"} {
		if !strings.Contains(results, want) {
			t.Errorf("Authentication-Results %q lacks %q", results, want)
		}
	}
	if strings.Index(results, "header.d=esp.test") > strings.Index(results, "header.d=example.test") {
		t.Errorf("signatures not reported in header order: %q", results)
	}
}

// TestDMARCEvaluatesEveryFromField: the header map kept only the last From
// field (and only the "From" spelling), so a forged From above an
// attacker's authenticated one, or a "FROM:" field, escaped DMARC.
func TestDMARCEvaluatesEveryFromField(t *testing.T) {
	f := newAuthFixture(t)
	f.records["_dmarc.bank.test"] = "v=DMARC1; p=reject"
	f.records["_dmarc.evil.test"] = "v=DMARC1; p=none"
	for name, message := range map[string][]byte{
		"two From fields":      f.sign([]byte("From: CEO <ceo@bank.test>\r\nFrom: me@evil.test\r\n"+authBody), "evil.test"),
		"two From mailboxes":   f.sign([]byte("From: me@evil.test, CEO <ceo@bank.test>\r\n"+authBody), "evil.test"),
		"upper-case field":     []byte("FROM: ceo@bank.test\r\n" + authBody),
		"bank.test after evil": f.sign([]byte("From: me@evil.test\r\nFrom: ceo@bank.test\r\n"+authBody), "evil.test"),
	} {
		t.Run(name, func(t *testing.T) {
			if code, _ := f.deliver(DmarcPolicyReject, "me@evil.test", message); code != 550 {
				t.Fatalf("DATA = %d, want 550 for the forged bank.test From", code)
			}
		})
	}
	// Every From domain authenticated: the message passes.
	f.records["_dmarc.evil.test"] = "v=DMARC1; p=reject"
	message := f.sign(f.sign([]byte("From: me@evil.test, ceo@bank.test\r\n"+authBody), "evil.test"), "bank.test")
	if code, results := f.deliver(DmarcPolicyReject, "me@evil.test", message); code != 250 || !strings.Contains(results, "dmarc=pass") {
		t.Fatalf("DATA = %d, results %q, want pass", code, results)
	}
}

func TestCombineDMARCRequiresEveryDomainToPass(t *testing.T) {
	pass := &DmarcResult{Result: "pass", Domain: "a.test", Pass: true}
	none := &DmarcResult{Result: "none", Domain: "b.test", Pass: true}
	quarantine := &DmarcResult{Result: "fail", Domain: "c.test", PolicyApplied: true, Disposition: "quarantine"}
	reject := &DmarcResult{Result: "fail", Domain: "d.test", ShouldReject: true, Disposition: "reject"}
	for _, test := range []struct {
		results []*DmarcResult
		want    string
	}{
		{[]*DmarcResult{pass, none}, "b.test"},
		{[]*DmarcResult{pass, quarantine, none}, "c.test"},
		{[]*DmarcResult{quarantine, reject}, "d.test"},
		{[]*DmarcResult{pass}, "a.test"},
	} {
		if got := combineDMARC(test.results); got.Domain != test.want {
			t.Errorf("combined %v = %s, want %s", test.results, got.Domain, test.want)
		}
	}
}

// TestDKIMTestingKeyFailureIsNotRejected follows RFC 6376 section 3.6.1:
// a failed signature under a t=y key is treated as unsigned mail.
func TestDKIMTestingKeyFailureIsNotRejected(t *testing.T) {
	f := newAuthFixture(t)
	message := f.sign([]byte("From: alice@example.test\r\n"+authBody), "example.test")
	f.records["s1._domainkey.example.test"] += "; t=y"
	tampered := []byte(strings.Replace(string(message), "Hello.", "Changed.", 1))
	result := EvaluateDKIM(&DkimPolicy{Mode: DkimPolicyReject, Verifier: dkim.Verifier{LookupTXT: f.lookup}}, tampered)
	if result.Result != "fail" || !result.Testing || result.ShouldReject || !result.Pass {
		t.Fatalf("result = %+v, want unrejected testing-mode fail", result)
	}
}
