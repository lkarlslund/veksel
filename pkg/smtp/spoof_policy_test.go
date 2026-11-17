package smtp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func localExampleDomain(_ context.Context, domain string) (bool, error) {
	return domain == "example.test", nil
}

func TestLocalIdentityPolicyEvidence(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		session *Session
		headers map[string]string
		result  string
		reject  bool
		nil     bool
	}{
		"external":                       {session: &Session{envelopeSender: "outside@remote.test"}, headers: map[string]string{"From": "outside@remote.test"}, nil: true},
		"local envelope unauthenticated": {session: &Session{envelopeSender: "sender@example.test"}, headers: map[string]string{"From": "outside@remote.test"}, result: "fail", reject: true},
		"local header unauthenticated":   {session: &Session{envelopeSender: "outside@remote.test"}, headers: map[string]string{"From": "Local <sender@example.test>"}, result: "fail", reject: true},
		"local identity in address list": {session: &Session{envelopeSender: "outside@remote.test"}, headers: map[string]string{"From": "local@example.test, outside@remote.test"}, result: "fail", reject: true},
		"authenticated local identity":   {session: &Session{authenticated: true, envelopeSender: "sender@example.test"}, headers: map[string]string{"From": "sender@example.test"}, nil: true},
		"SPF and DMARC authenticated":    {session: &Session{envelopeSender: "sender@example.test", spfResult: &SpfResult{Result: "pass"}, dmarcResult: &DmarcResult{Result: "pass"}}, headers: map[string]string{"From": "sender@example.test"}, result: "pass"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.session.cfg = &Config{LocalDomainSpoofPolicy: SpoofPolicyReject, Delivery: &Delivery{IsLocalDomain: localExampleDomain}}
			result, err := test.session.evaluateLocalIdentity(t.Context(), test.headers)
			if err != nil {
				t.Fatal(err)
			}
			if test.nil {
				if result != nil {
					t.Fatalf("result = %+v, want nil", result)
				}
				return
			}
			if result == nil || result.Result != test.result || result.Reject != test.reject {
				t.Fatalf("result = %+v, want result=%s reject=%v", result, test.result, test.reject)
			}
		})
	}
}

func TestLocalIdentityPolicyWarnAndLookupFailure(t *testing.T) {
	t.Parallel()
	session := &Session{envelopeSender: "sender@example.test", cfg: &Config{LocalDomainSpoofPolicy: SpoofPolicyWarn, Delivery: &Delivery{IsLocalDomain: localExampleDomain}}}
	result, err := session.evaluateLocalIdentity(t.Context(), map[string]string{"From": "outside@remote.test"})
	if err != nil || result == nil || result.Result != "fail" || result.Reject {
		t.Fatalf("warn result = %+v error=%v", result, err)
	}
	session.cfg.Delivery.IsLocalDomain = func(context.Context, string) (bool, error) { return false, errors.New("store offline") }
	if _, err := session.evaluateLocalIdentity(t.Context(), map[string]string{"From": "outside@remote.test"}); err == nil {
		t.Fatal("domain lookup failure was ignored")
	}
}

func TestLocalIdentityPolicyRejectsInboundSpoof(t *testing.T) {
	c := makeTestServer(t, &Config{
		ServerName: "mx.example.test", LocalDomainSpoofPolicy: SpoofPolicyReject,
		Delivery: &Delivery{
			IsLocalDomain:    localExampleDomain,
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "alice", nil },
			AppendMessage: func(context.Context, string, []byte, map[string]string) (string, error) {
				t.Fatal("spoofed message reached mailbox delivery")
				return "", nil
			},
		},
	})
	c.send("EHLO attacker.test")
	c.send("MAIL FROM:<outside@remote.test>")
	c.send("RCPT TO:<alice@example.test>")
	c.send("DATA")
	c.writeData("From: Accounts <billing@example.test>\r\nTo: alice@example.test\r\nSubject: urgent\r\n\r\nspoof\r\n.\r\n")
	code, text, _ := c.readReply()
	if code != 550 || !strings.HasPrefix(text, "5.7.1 ") {
		t.Fatalf("DATA reply = %d %q, want 550 5.7.1", code, text)
	}
}

func TestLocalIdentityPolicyWarnAddsTrustedEvidence(t *testing.T) {
	var received map[string]string
	c := makeTestServer(t, &Config{
		ServerName: "mx.example.test", LocalDomainSpoofPolicy: SpoofPolicyWarn,
		Delivery: &Delivery{
			IsLocalDomain:    localExampleDomain,
			ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "alice", nil },
			AppendMessage: func(_ context.Context, _ string, _ []byte, headers map[string]string) (string, error) {
				received = headers
				return "item", nil
			},
		},
	})
	c.send("EHLO attacker.test")
	c.send("MAIL FROM:<outside@remote.test>")
	c.send("RCPT TO:<alice@example.test>")
	c.send("DATA")
	c.writeData("From: billing@example.test\r\nTo: alice@example.test\r\n\r\nwarning\r\n.\r\n")
	if code, text, _ := c.readReply(); code != 250 {
		t.Fatalf("DATA reply = %d %q", code, text)
	}
	if evidence := received["Authentication-Results"]; !strings.Contains(evidence, "policy=fail") || !strings.Contains(evidence, "header.from=example.test") {
		t.Fatalf("Authentication-Results = %q", evidence)
	}
}

// During a migration the server a domain is shared with sends that domain's
// mail; it is trusted for its own domain and nobody else is.
func TestLocalIdentityPolicyTrustsTheDomainsSplitDeliveryServer(t *testing.T) {
	for _, test := range []struct {
		name    string
		trusted bool
		want    int
	}{
		{name: "split-delivery server", trusted: true, want: 250},
		{name: "any other peer", trusted: false, want: 550},
	} {
		t.Run(test.name, func(t *testing.T) {
			var asked []string
			c := makeTestServer(t, &Config{
				ServerName: "mx.example.test", LocalDomainSpoofPolicy: SpoofPolicyReject,
				Delivery: &Delivery{
					IsLocalDomain:    localExampleDomain,
					ResolveRecipient: func(context.Context, string) (string, string, error) { return "inbox", "alice", nil },
					AppendMessage:    func(context.Context, string, []byte, map[string]string) (string, error) { return "item", nil },
					TrustedDomainRelay: func(_ context.Context, domain, peer string) (bool, error) {
						asked = append(asked, domain+" "+peer)
						return test.trusted, nil
					},
				},
			})
			c.send("EHLO exchange.example.test")
			c.send("MAIL FROM:<bob@example.test>")
			c.send("RCPT TO:<alice@example.test>")
			c.send("DATA")
			c.writeData("From: Bob <bob@example.test>\r\nTo: alice@example.test\r\nSubject: internal\r\n\r\nhello\r\n.\r\n")
			code, text, _ := c.readReply()
			if code != test.want {
				t.Fatalf("DATA reply = %d %q, want %d", code, text, test.want)
			}
			if len(asked) == 0 || asked[0] != "example.test 127.0.0.1" {
				t.Fatalf("relay trust asked %q", asked)
			}
		})
	}
}
