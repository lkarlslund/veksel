package imap

import (
	"context"
	"fmt"
	"testing"

	imapv2 "github.com/emersion/go-imap/v2"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/bayes"
	"github.com/lkarlslund/veksel/pkg/bayes/bayestest"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestMoveIntoAndOutOfJunkTrainsTheSpamClassifier(t *testing.T) {
	ts := setupIntegrationStore(t)
	rulesStore, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rulesStore.Close() })
	base := service.NewFolderSpace(ts, authz.New(ts))
	automation, err := rules.NewEngine(t.Context(), rulesStore, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(automation.Close)
	space, err := rules.NewFolderSpace(base, automation)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := spam.NewEngine(spam.Config{Thresholds: spam.DefaultThresholds()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var scoring spam.Switch
	scoring.Set(engine)
	accounts := bayestest.NewAccounts(t)
	classifier, err := bayes.New(bayes.Config{Space: space, Accounts: accounts, Symbols: &scoring}, bayes.Settings{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(classifier.Close)
	space.AddItemObserver(classifier)

	addr, cleanup := startTestServer(t, &Config{
		ServerName: "test.veksel", TypedStore: ts, FolderSpace: space,
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
	})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	mustLogin(t, client)
	mustAppend(t, client, "INBOX", "Message-ID: <junk@example.net>\r\nFrom: promo@example.net\r\nSubject: cheap pills\r\n\r\nWinner prize casino\r\n")
	stats := func() bayes.Stats {
		classifier.Wait()
		stats, err := classifier.Stats(t.Context(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		return stats
	}
	mustSelect(t, client, "INBOX")
	if _, err := client.Move(imapv2.SeqSetNum(1), "Junk").Wait(); err != nil {
		t.Fatalf("MOVE to Junk: %v", err)
	}
	if got := stats(); got.Spam != 1 || got.Ham != 0 {
		t.Fatalf("after MOVE to Junk = %+v", got)
	}
	mustSelect(t, client, "Junk")
	if _, err := client.Move(imapv2.SeqSetNum(1), "INBOX").Wait(); err != nil {
		t.Fatalf("MOVE out of Junk: %v", err)
	}
	if got := stats(); got.Spam != 0 || got.Ham != 1 || got.Records != 1 {
		t.Fatalf("after MOVE out of Junk = %+v", got)
	}
}
