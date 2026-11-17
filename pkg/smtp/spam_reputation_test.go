package smtp

import (
	"context"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestKnownCorrespondentRequiresTheSenderToAuthenticate(t *testing.T) {
	symbol := spam.Symbol{Name: spam.SymbolKnownCorrespondent, Score: -3}
	cases := []struct {
		name  string
		setup func(*Session)
		want  bool
	}{
		{"unauthenticated forged From", func(*Session) {}, false},
		{"dmarc pass", func(s *Session) { s.dmarcResult = &DmarcResult{Result: "pass"} }, true},
		{"aligned dkim", func(s *Session) { s.dkimResult = &DkimResult{Result: "pass", Domain: "mail.friend.test"} }, true},
		{"aligned spf", func(s *Session) { s.spfResult = &SpfResult{Result: "pass", SenderDomain: "bounce.friend.test"} }, true},
		{"dkim pass for another domain", func(s *Session) { s.dkimResult = &DkimResult{Result: "pass", Domain: "attacker.test"} }, false},
		{"spf pass for another domain", func(s *Session) { s.spfResult = &SpfResult{Result: "pass", SenderDomain: "attacker.test"} }, false},
		{"dmarc fail", func(s *Session) {
			s.dmarcResult = &DmarcResult{Result: "fail"}
			s.dkimResult = &DkimResult{Result: "fail", Domain: "friend.test"}
		}, false},
	}
	for _, tc := range cases {
		var asked []string
		session := &Session{ctx: context.Background(), cfg: &Config{Delivery: &Delivery{
			KnownCorrespondent: func(_ context.Context, userID, sender string) (spam.Symbol, bool, error) {
				asked = append(asked, userID+":"+sender)
				return symbol, true, nil
			},
		}}}
		tc.setup(session)
		got, known, err := session.knownCorrespondent("alice", map[string]string{"From": "Pal <Pal@Friend.test>"})
		if err != nil || known != tc.want || (known && got.Name != symbol.Name) {
			t.Fatalf("%s: known = %v, symbol %+v, err %v", tc.name, known, got, err)
		}
		if tc.want != (len(asked) == 1) || tc.want && asked[0] != "alice:pal@friend.test" {
			t.Fatalf("%s: history asked %q", tc.name, asked)
		}
	}
}

func TestReputationKeysAreStampedAndPeerClaimsReplaced(t *testing.T) {
	queue := &recordingSystemQueue{}
	config, err := spam.ParseSettings(spam.Settings{Thresholds: spam.DefaultThresholds()})
	if err != nil {
		t.Fatal(err)
	}
	reputation := &spam.Reputation{}
	config.Reputation = reputation
	engine, err := spam.NewEngine(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	delivery := spamTestDelivery(queue, nil)
	delivery.KnownCorrespondent = func(context.Context, string, string) (spam.Symbol, bool, error) {
		t.Error("an unauthenticated sender was looked up as a correspondent")
		return spam.Symbol{}, false, nil
	}
	addr, cleanup := startSMTPServer(t, &Config{ServerName: "test.veksel", Spam: publicSourceChecker{engine: engine}, Delivery: delivery})
	t.Cleanup(cleanup)
	forged := strings.Replace(spamTestMessage, "X-Spam-Flag: NO", spam.ReputationHeader+": d=forged.test", 1)
	if err := dialClient(t, addr).SendMail("sender@remote.test", []string{"alice@example.test"}, strings.NewReader(forged)); err != nil {
		t.Fatal(err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("queued = %#v", queue.messages)
	}
	stamped := queue.messages[0].Headers[spam.ReputationHeader]
	if stamped != "n=203.0.113.0/24" || strings.Contains(string(queue.messages[0].Content), "forged.test") {
		t.Fatalf("%s = %q", spam.ReputationHeader, stamped)
	}
	if report := reputation.Report(5); report.Tracked != 1 {
		t.Fatalf("tracked = %d", report.Tracked)
	}
}
