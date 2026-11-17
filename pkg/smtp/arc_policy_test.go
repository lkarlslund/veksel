package smtp

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dmarc"
)

// testARCKey is a sealing domain's key, which also seals as an ARCSealer.
type testARCKey struct {
	domain string
	key    *rsa.PrivateKey
	record string
}

func newTestARCKey(t *testing.T, domain string) testARCKey {
	t.Helper()
	private, public, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := dkim.ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return testARCKey{domain: domain, key: key, record: dkim.DKIMDNSRecord(public)}
}

func (k testARCKey) Seal(_ context.Context, domain string, message []byte, authResults, chain string) ([]byte, bool, error) {
	if domain != k.domain {
		return message, false, nil
	}
	sealed, err := dkim.SealARC(message, dkim.ARCSealOptions{Domain: k.domain, Selector: "arc", Key: k.key, AuthResults: authResults, ChainValidation: chain})
	return sealed, err == nil, err
}

func arcKeys(keys ...testARCKey) dkim.Verifier {
	return dkim.Verifier{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		for _, key := range keys {
			if name == "arc._domainkey."+key.domain {
				return []string{key.record}, nil
			}
		}
		return nil, errors.New("no such host")
	}}
}

func rejectingDMARC() *DmarcPolicy {
	return &DmarcPolicy{Mode: DmarcPolicyReject, Evaluator: &dmarc.Evaluator{
		Resolver: smtpTXTResolverFunc(func(context.Context, string) ([]string, error) { return []string{"v=DMARC1; p=reject"}, nil }),
		Sample:   func(int) bool { return true },
	}}
}

const forwardedOriginal = "From: sender@example.test\r\nTo: list@forwarder.test\r\nSubject: forwarded\r\n\r\nBody\r\n"

func TestARCTrustedSealerOverridesDMARCFailure(t *testing.T) {
	forwarder := newTestARCKey(t, "forwarder.test")
	sealed := func(results string) string {
		message, err := dkim.SealARC([]byte(forwardedOriginal), dkim.ARCSealOptions{Domain: "forwarder.test", Selector: "arc", Key: forwarder.key,
			AuthResults: "mx.forwarder.test; " + results, ChainValidation: dkim.ARCNone})
		if err != nil {
			t.Fatal(err)
		}
		return string(message)
	}
	for _, tc := range []struct {
		name, message string
		trusted       []string
		code          int
		results       []string
	}{
		{"trusted sealer saw dmarc pass", sealed("dmarc=pass header.from=example.test"), []string{"forwarder.test"}, 250,
			[]string{"arc=pass header.d=forwarder.test", `dmarc=fail reason="arc trusted sealer forwarder.test"`, "policy.dmarc=none"}},
		{"parent domain trusted", sealed("dmarc=pass"), []string{"test"}, 250, []string{"arc=pass"}},
		{"untrusted sealer", sealed("dmarc=pass"), []string{"other.test"}, 550, nil},
		{"trusted sealer saw dmarc fail", sealed("dmarc=fail"), []string{"forwarder.test"}, 550, nil},
		{"broken chain", strings.Replace(sealed("dmarc=pass"), "Body", "Changed", 1), []string{"forwarder.test"}, 550, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue := &recordingSystemQueue{}
			c := makeTestServer(t, &Config{ServerName: "test.veksel", DmarcPolicy: rejectingDMARC(),
				ARC:      &ARCPolicy{Verify: true, Verifier: arcKeys(forwarder), TrustedSealers: tc.trusted},
				Delivery: &Delivery{ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil }, MailQueue: queue}})
			c.send("EHLO client.example.test")
			c.send("MAIL FROM:<bounces@forwarder.test>")
			c.send("RCPT TO:<alice@example.test>")
			c.send("DATA")
			c.writeData(tc.message + ".\r\n")
			if code, text, err := c.readReply(); err != nil || code != tc.code {
				t.Fatalf("DATA completion = %d %q %v, want %d", code, text, err, tc.code)
			}
			if tc.code != 250 {
				return
			}
			if len(queue.messages) != 1 {
				t.Fatalf("queued = %#v", queue.messages)
			}
			ar := queue.messages[0].Headers["Authentication-Results"]
			for _, want := range tc.results {
				if !strings.Contains(ar, want) {
					t.Fatalf("Authentication-Results %q lacks %q", ar, want)
				}
			}
		})
	}
}

func TestARCResultsInAuthenticationResults(t *testing.T) {
	forwarder := newTestARCKey(t, "forwarder.test")
	sealed, err := dkim.SealARC([]byte(forwardedOriginal), dkim.ARCSealOptions{Domain: "forwarder.test", Selector: "arc", Key: forwarder.key,
		AuthResults: "mx.forwarder.test; spf=pass", ChainValidation: dkim.ARCNone})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, message, want string
		verify              bool
	}{
		{"pass", string(sealed), "arc=pass header.d=forwarder.test", true},
		{"fail", strings.Replace(string(sealed), "i=1; a=rsa-sha256; cv=none", "i=1; a=rsa-sha256; cv=fail", 1), `arc=fail reason="most recent ARC-Seal reports cv=fail"`, true},
		{"none", forwardedOriginal, "arc=none", true},
		{"verification off", string(sealed), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue := &recordingSystemQueue{}
			c := makeTestServer(t, &Config{ServerName: "test.veksel", SpfPolicy: &SpfPolicy{Mode: SpfPolicyOff},
				ARC:      &ARCPolicy{Verify: tc.verify, Verifier: arcKeys(forwarder)},
				Delivery: &Delivery{ResolveRecipient: func(context.Context, string) (string, string, error) { return "alice:INBOX", "alice", nil }, MailQueue: queue}})
			c.send("EHLO client.example.test")
			c.send("MAIL FROM:<bounces@forwarder.test>")
			c.send("RCPT TO:<alice@example.test>")
			c.send("DATA")
			c.writeData(tc.message + ".\r\n")
			if code, text, err := c.readReply(); err != nil || code != 250 {
				t.Fatalf("DATA completion = %d %q %v", code, text, err)
			}
			ar := queue.messages[0].Headers["Authentication-Results"]
			if tc.want == "" && strings.Contains(ar, "arc=") || !strings.Contains(ar, tc.want) {
				t.Fatalf("Authentication-Results = %q, want %q", ar, tc.want)
			}
		})
	}
}

func TestForwardsAndRedirectsAreARCSealed(t *testing.T) {
	ours, upstream := newTestARCKey(t, "example.test"), newTestARCKey(t, "upstream.test")
	verifier := arcKeys(ours, upstream)
	inboundChain, err := dkim.SealARC([]byte(forwardedOriginal), dkim.ARCSealOptions{Domain: "upstream.test", Selector: "arc", Key: upstream.key,
		AuthResults: "mx.upstream.test; dmarc=pass", ChainValidation: dkim.ARCNone})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []struct {
		name      string
		configure func(*Delivery)
	}{
		{"account forward", func(delivery *Delivery) {
			delivery.ResolveForwardTo = func(context.Context, string) (string, error) { return "alice@elsewhere.example", nil }
		}},
		{"sieve redirect", func(delivery *Delivery) {
			delivery.GetSieveScript = func(context.Context, string) (string, bool, error) {
				return `redirect "alice@elsewhere.example";`, true, nil
			}
		}},
	} {
		for _, tc := range []struct {
			name, message string
			instances     int
			seal          bool
		}{
			{"first seal", forwardedOriginal, 1, true},
			{"extends a valid chain", string(inboundChain), 2, true},
			{"sealing off", forwardedOriginal, 0, false},
		} {
			t.Run(path.name+"/"+tc.name, func(t *testing.T) {
				mailQueue := &recordingSystemQueue{}
				delivery := srsDelivery(t, testSRSCodec(t), mailQueue)
				path.configure(delivery)
				policy := &ARCPolicy{Verify: true, Verifier: verifier}
				if tc.seal {
					policy.Sealer = ours
				}
				address, cleanup := startSMTPServer(t, &Config{ServerName: "mx.example.test", ARC: policy, Delivery: delivery})
				t.Cleanup(cleanup)
				if err := dialClient(t, address).SendMail("bob@remote.example", []string{"alice@example.test"}, strings.NewReader(tc.message)); err != nil {
					t.Fatal(err)
				}
				forwarded := outboundTo(mailQueue.messages, "alice@elsewhere.example")
				if forwarded == nil {
					t.Fatalf("no forwarded message in %#v", mailQueue.messages)
				}
				result := verifier.VerifyARC(context.Background(), forwarded.Content)
				if !tc.seal {
					if strings.Contains(string(forwarded.Content), "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.test") {
						t.Fatal("forward sealed while sealing is off")
					}
					return
				}
				if result.Status != dkim.ARCPass || result.Instances != tc.instances || result.Sealer != "example.test" {
					t.Fatalf("forwarded chain = %+v, want %d sets sealed by example.test", result, tc.instances)
				}
				if !strings.Contains(string(forwarded.Content), "ARC-Authentication-Results: i="+string(rune('0'+tc.instances))+"; mx.example.test;") {
					t.Fatalf("our AAR missing:\n%s", forwarded.Content)
				}
			})
		}
	}
}
