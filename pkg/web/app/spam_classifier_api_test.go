package app

import (
	"net/http"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/bayes"
	"github.com/lkarlslund/veksel/pkg/bayes/bayestest"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestWebMovesTrainTheSpamClassifierAndUsersSeeTheirModel(t *testing.T) {
	handler, ts := testHandler(t)
	base := service.NewFolderSpace(ts, authz.New(ts))
	automation, err := rules.NewEngine(t.Context(), ts.Store(), base)
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
	classifier, err := bayes.New(bayes.Config{Space: space, Accounts: bayestest.NewAccounts(t), Symbols: &scoring}, bayes.Settings{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(classifier.Close)
	space.AddItemObserver(classifier)
	handler.ConfigureMigrations(space, nil)
	handler.ConfigureSpamClassifier(classifier)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")

	itemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("Message-ID: <w1@example.net>\r\nSubject: jackpot\r\n\r\ncasino jackpot winner\r\n"), map[string]string{"Subject": "jackpot"})
	if err != nil {
		t.Fatal(err)
	}
	move := func(folderID string) {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/workspace/items/actions", csrf,
			`{"item_ids":["`+itemID+`"],"action":"move","destination_folder_id":"`+folderID+`"}`)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("move status = %d", response.StatusCode)
		}
		classifier.Wait()
	}
	stats := func(method, path string) bayes.Stats {
		t.Helper()
		response := authenticatedJSON(t, client, method, server.URL+path, csrf, "")
		var stats bayes.Stats
		decodeResponse(t, response, &stats)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s %s status = %d", method, path, response.StatusCode)
		}
		return stats
	}

	move(model.JunkFolderID("alice"))
	if got := stats(http.MethodGet, "/api/v1/spam-classifier"); got.Spam != 1 || got.Ham != 0 || got.Ready || got.MinLearns != bayes.DefaultMinLearns || !got.Enabled {
		t.Fatalf("after Mark as junk = %+v", got)
	}
	move(model.InboxFolderID("alice"))
	if got := stats(http.MethodGet, "/api/v1/admin/users/alice/spam-classifier"); got.Spam != 0 || got.Ham != 1 {
		t.Fatalf("after Not junk = %+v", got)
	}
	response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/security/antispam", "", "")
	var status spamFilteringResponse
	decodeResponse(t, response, &status)
	if status.Classifier == nil || !status.Classifier.Enabled || status.Classifier.LearnedSpam != 1 || status.Classifier.LearnedHam != 1 {
		t.Fatalf("admin classifier status = %+v", status.Classifier)
	}
	if got := stats(http.MethodDelete, "/api/v1/spam-classifier"); got.Spam+got.Ham != 0 || got.Tokens != 0 {
		t.Fatalf("after reset = %+v", got)
	}
	response = authenticatedJSON(t, client, http.MethodDelete, server.URL+"/api/v1/admin/security/antispam/classifier", csrf, "")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("shared model reset status = %d", response.StatusCode)
	}
}
