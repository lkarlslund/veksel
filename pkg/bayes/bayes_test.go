package bayes

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/bayes/bayestest"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

type fixture struct {
	space    *rules.FolderSpace
	typed    *model.TypedStore
	service  *Service
	symbols  *spam.Switch
	accounts *bayestest.Accounts
}

func newFixture(t *testing.T, settings Settings) *fixture {
	t.Helper()
	return newFixtureWith(t, settings, nil)
}

// newFixtureWith lets the test adjust the classifier's wiring.
func newFixtureWith(t *testing.T, settings Settings, mutate func(*Config)) *fixture {
	t.Helper()
	backend, err := pebblestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendPebble)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	for _, login := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(t.Context(), login, strings.ToUpper(login), "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), login); err != nil {
			t.Fatal(err)
		}
	}
	base := service.NewFolderSpace(typed, authz.New(typed))
	engine, err := rules.NewEngine(t.Context(), backend, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	space, err := rules.NewFolderSpace(base, engine)
	if err != nil {
		t.Fatal(err)
	}
	symbols := &spam.Switch{}
	scoring, err := spam.NewEngine(spam.Config{Thresholds: spam.DefaultThresholds()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	symbols.Set(scoring)
	accounts := bayestest.NewAccounts(t)
	config := Config{Space: space, Accounts: accounts, Global: backend, Symbols: symbols}
	if mutate != nil {
		mutate(&config)
	}
	classifier, err := New(config, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(classifier.Close)
	space.AddItemObserver(classifier)
	return &fixture{space: space, typed: typed, service: classifier, symbols: symbols, accounts: accounts}
}

func (f *fixture) folder(t *testing.T, user, path string) model.Folder {
	t.Helper()
	folder, err := f.space.GetFolderByPath(t.Context(), service.UserAccess(user, "test"), path)
	if err != nil {
		t.Fatal(err)
	}
	return folder
}

func (f *fixture) stats(t *testing.T, user string) Stats {
	t.Helper()
	f.service.Wait()
	stats, err := f.service.Stats(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	return stats
}

var (
	spamWords = []string{"viagra", "winner", "prize", "casino", "bitcoin", "unsubscribe", "offer", "cheap", "click", "urgent", "loan", "free", "pills", "jackpot"}
	hamWords  = []string{"meeting", "agenda", "project", "invoice", "review", "lunch", "draft", "report", "schedule", "team", "budget", "notes", "minutes", "roadmap"}
)

// message builds a distinct message from words of vocabulary.
func message(random *rand.Rand, vocabulary []string, n int) []byte {
	words := make([]string, 0, 25)
	for range 25 {
		words = append(words, vocabulary[random.IntN(len(vocabulary))])
	}
	return fmt.Appendf(nil, "Message-ID: <%d@example.net>\r\nSubject: %s %s\r\n\r\n%s\r\n", n, words[0], words[1], strings.Join(words, " "))
}

func trainCorpus(f *fixture, user string, random *rand.Rand, count int) {
	for index := range count {
		f.service.Train(user, message(random, spamWords, index), ClassSpam)
		f.service.Train(user, message(random, hamWords, count+index), ClassHam)
	}
	f.service.Wait()
}

func TestClassifierScoresOnlyAfterMinimumTraining(t *testing.T) {
	f := newFixture(t, Settings{Enabled: true, MinLearns: 20})
	random := rand.New(rand.NewPCG(3, 4))
	trainCorpus(f, "alice", random, 19)
	probe := spam.Tokenize(message(random, spamWords, 9999))
	if symbol, ok := f.service.Classify(t.Context(), "alice", probe); ok {
		t.Fatalf("an untrained model scored: %+v", symbol)
	}
	if stats := f.stats(t, "alice"); stats.Ready || stats.Spam != 19 || stats.Ham != 19 || stats.Tokens == 0 || stats.Records != 38 {
		t.Fatalf("stats before minimum = %+v", stats)
	}
	trainCorpus(f, "alice", random, 1)
	symbol, ok := f.service.Classify(t.Context(), "alice", probe)
	if !ok || symbol.Name != "BAYES_SPAM" || symbol.Score != 5 || symbol.Options[1] != "model=user" {
		t.Fatalf("spam symbol = %+v, %t", symbol, ok)
	}
	if symbol, _ := f.service.Classify(t.Context(), "alice", spam.Tokenize(message(random, hamWords, 9998))); symbol.Name != "BAYES_HAM" || symbol.Score != -3 {
		t.Fatalf("ham symbol = %+v", symbol)
	}
	// Per-user isolation: bob's model is untrained and the shared model is off.
	if _, ok := f.service.Classify(t.Context(), "bob", probe); ok {
		t.Fatal("alice's training scored bob's mail")
	}
	if stats := f.stats(t, "bob"); stats.Spam != 0 || stats.Ham != 0 {
		t.Fatalf("bob's model = %+v", stats)
	}
	// Disabling the classifier or the scoring engine silences it live.
	f.service.SetSettings(Settings{Enabled: false, MinLearns: 20})
	if _, ok := f.service.Classify(t.Context(), "alice", probe); ok {
		t.Fatal("a disabled classifier scored")
	}
	f.service.SetSettings(Settings{Enabled: true, MinLearns: 20})
	f.symbols.Set(nil)
	if _, ok := f.service.Classify(t.Context(), "alice", probe); ok {
		t.Fatal("the classifier scored with spam scoring disabled")
	}
	if err := f.service.Reset(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if stats := f.stats(t, "alice"); stats.Spam != 0 || stats.Tokens != 0 {
		t.Fatalf("reset model = %+v", stats)
	}
}

func TestMovesIntoAndOutOfJunkTrainAndRetrain(t *testing.T) {
	f := newFixture(t, Settings{Enabled: true})
	access := service.UserAccess("alice", "imap")
	inbox, junk, trash := f.folder(t, "alice", "INBOX"), f.folder(t, "alice", "Junk"), f.folder(t, "alice", "Trash")
	raw := []byte("Message-ID: <m1@example.net>\r\nSubject: cheap pills\r\n\r\ncheap pills winner prize\r\n")
	item, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if stats := f.stats(t, "alice"); stats.Spam+stats.Ham != 0 {
		t.Fatalf("delivery trained the model: %+v", stats)
	}
	moved, err := f.space.MoveItem(t.Context(), access, item.ID, junk.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats := f.stats(t, "alice"); stats.Spam != 1 || stats.Ham != 0 || stats.Records != 1 {
		t.Fatalf("after move into Junk = %+v", stats)
	}
	// Moving it back corrects the training instead of counting twice.
	moved, err = f.space.MoveItem(t.Context(), access, moved.ID, inbox.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	stats := f.stats(t, "alice")
	if stats.Spam != 0 || stats.Ham != 1 || stats.Records != 1 {
		t.Fatalf("after move out of Junk = %+v", stats)
	}
	tokens := stats.Tokens
	// Repeating an action is idempotent; a copy into Junk retrains spam.
	if moved, err = f.space.MoveItem(t.Context(), access, moved.ID, f.folder(t, "alice", "Archive").ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.space.CopyItem(t.Context(), access, moved.ID, junk.ID, "copy.eml"); err != nil {
		t.Fatal(err)
	}
	if stats := f.stats(t, "alice"); stats.Spam != 1 || stats.Ham != 0 || stats.Tokens != tokens {
		t.Fatalf("after copy into Junk = %+v", stats)
	}
	// Junk to Trash is not a ham judgement, and server-internal moves never
	// train.
	junked, err := f.space.CreateItem(t.Context(), access, junk.ID, service.ItemInput{Data: []byte("Message-ID: <m2@example.net>\r\nSubject: casino\r\n\r\ncasino jackpot\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.space.MoveItem(t.Context(), access, junked.ID, trash.ID, ""); err != nil {
		t.Fatal(err)
	}
	internal, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Data: []byte("Subject: internal\r\n\r\nqueue filing\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.space.MoveItem(t.Context(), service.UserAccess("alice", "system-queue"), internal.ID, junk.ID, ""); err != nil {
		t.Fatal(err)
	}
	if stats := f.stats(t, "alice"); stats.Spam != 1 || stats.Ham != 0 || stats.Records != 1 {
		t.Fatalf("Trash or internal moves trained: %+v", stats)
	}
	if stats := f.stats(t, "bob"); stats.Spam+stats.Ham != 0 {
		t.Fatalf("alice's moves trained bob: %+v", stats)
	}
	status, err := f.service.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.LearnedSpam != 2 || status.LearnedHam != 1 || status.GlobalModel.Spam+status.GlobalModel.Ham != 0 {
		t.Fatalf("status = %+v", status)
	}
}

func TestSharedModelTrainsFromExplicitActionsWhenEnabled(t *testing.T) {
	f := newFixture(t, Settings{Enabled: true, MinLearns: 10, Global: true})
	random := rand.New(rand.NewPCG(5, 6))
	trainCorpus(f, "alice", random, 10)
	probe := spam.Tokenize(message(random, spamWords, 9999))
	for _, user := range []string{"", "bob"} {
		symbol, ok := f.service.Classify(t.Context(), user, probe)
		if !ok || symbol.Name != "BAYES_SPAM" || symbol.Options[1] != "model=global" {
			t.Fatalf("shared model for %q = %+v, %t", user, symbol, ok)
		}
	}
	status, err := f.service.Status(t.Context())
	if err != nil || !status.GlobalModel.Ready || status.GlobalModel.Spam != 10 {
		t.Fatalf("status = %+v, %v", status, err)
	}
	// Turning the shared model off stops scoring with it at once.
	f.service.SetSettings(Settings{Enabled: true, MinLearns: 10})
	if _, ok := f.service.Classify(t.Context(), "bob", probe); ok {
		t.Fatal("a disabled shared model scored")
	}
	if err := f.service.ResetGlobal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.service.Status(t.Context()); status.GlobalModel.Spam != 0 {
		t.Fatalf("reset shared model = %+v", status.GlobalModel)
	}
}

func TestAutolearnLearnsConfidentExtremesWithoutOverridingUsers(t *testing.T) {
	f := newFixture(t, Settings{Enabled: true})
	sample := spam.NewSample([]byte("Message-ID: <a1@example.net>\r\nSubject: prize\r\n\r\nprize winner\r\n"))
	confident := spam.Result{Thresholds: spam.DefaultThresholds(), Score: 12, Symbols: []spam.Symbol{{Name: "RBL", Score: 12}}}
	f.service.Autolearn(t.Context(), "alice", sample, confident, false)
	if stats := f.stats(t, "alice"); stats.Spam != 0 {
		t.Fatal("auto-learning ran while disabled")
	}
	f.service.SetSettings(Settings{Enabled: true, Autolearn: true, Global: true})
	// A classifier symbol never counts toward auto-learning.
	f.service.Autolearn(t.Context(), "alice", sample, confident.WithBayes(spam.Symbol{Name: "BAYES_HAM", Score: -3}), false)
	f.service.Autolearn(t.Context(), "alice", spam.NewSample([]byte("Subject: middling\r\n\r\nordinary words\r\n")), spam.Result{Thresholds: spam.DefaultThresholds(), Score: 7}, false)
	f.service.Autolearn(t.Context(), "alice", spam.NewSample([]byte("Subject: untrusted\r\n\r\nhello there\r\n")), spam.Result{Thresholds: spam.DefaultThresholds()}, false)
	if stats := f.stats(t, "alice"); stats.Spam != 1 || stats.Ham != 0 {
		t.Fatalf("auto-learned = %+v", stats)
	}
	ham := spam.NewSample([]byte("Message-ID: <h1@example.net>\r\nSubject: lunch\r\n\r\nlunch agenda\r\n"))
	f.service.Autolearn(t.Context(), "alice", ham, spam.Result{Thresholds: spam.DefaultThresholds()}, true)
	if stats := f.stats(t, "alice"); stats.Ham != 1 {
		t.Fatalf("trusted ham not learned: %+v", stats)
	}
	// The user's correction wins, and auto-learning cannot undo it.
	f.service.enqueue(job{userID: "alice", sample: sample, class: ClassHam, source: SourceUser})
	f.service.Autolearn(t.Context(), "alice", sample, confident, false)
	status, _ := f.service.Status(t.Context())
	if stats := f.stats(t, "alice"); stats.Spam != 0 || stats.Ham != 2 {
		t.Fatalf("after correction = %+v", stats)
	}
	if status.Autolearned != 2 || status.GlobalModel.Spam != 0 {
		t.Fatalf("auto-learning trained the shared model or miscounted: %+v", status)
	}
}

func TestPruningBoundsTokensAndRecords(t *testing.T) {
	f := newFixture(t, Settings{Enabled: true, MaxTokens: 200, MaxRecords: 10})
	for index := range 30 {
		words := make([]string, 0, 20)
		for word := range 20 {
			words = append(words, fmt.Sprintf("tok%dx%d", index, word))
		}
		f.service.Train("alice", fmt.Appendf(nil, "Message-ID: <p%d@example.net>\r\nSubject: s\r\n\r\n%s common\r\n", index, strings.Join(words, " ")), ClassSpam)
	}
	f.service.Wait()
	if err := f.service.Prune(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	stats := f.stats(t, "alice")
	if stats.Tokens > 200 || stats.Records > 10 || stats.Spam != 30 {
		t.Fatalf("pruned model = %+v", stats)
	}
	var common tokenValue
	err := f.accounts.WithIndex(t.Context(), "alice", func(ctx context.Context, index store.Store) error {
		found, err := tokenModel{store: index, namespace: Namespace}.getJSON(ctx, tokenPrefix+"common", &common)
		if err == nil && !found {
			t.Error("pruning dropped the most frequent token")
		}
		keys, err := index.Scan(ctx, Namespace, tokenPrefix)
		if len(keys) != stats.Tokens {
			t.Errorf("token keys = %d, meta = %d", len(keys), stats.Tokens)
		}
		return err
	})
	if err != nil || common[0] != 30 {
		t.Fatalf("common = %v, %v", common, err)
	}
}
