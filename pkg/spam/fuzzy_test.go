package spam

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// fuzzyText is a deterministic pseudo-prose body of n words.
func fuzzyText(seed uint64, n int) string {
	rng := rand.New(rand.NewPCG(seed, seed))
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf("w%c%c%c%c", 'a'+rng.IntN(26), 'a'+rng.IntN(26), 'a'+rng.IntN(26), 'a'+rng.IntN(26))
	}
	return strings.Join(words, " ")
}

func fuzzyRaw(body string) []byte {
	return []byte("From: a@b.example\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n")
}

func bodySignature(t *testing.T, body string) signature {
	t.Helper()
	sig, ok := messageSignature(parseContent(fuzzyRaw(body)))
	if !ok {
		t.Fatalf("no signature for %q", body)
	}
	return sig
}

func TestFuzzySignatureSurvivesMinorEdits(t *testing.T) {
	base := "Dear Alice, " + fuzzyText(1, 200) + " Order 12345 ships soon. Visit https://shop.example/a?id=1 today."
	original := bodySignature(t, base)
	edits := map[string]string{
		"name":       strings.Replace(base, "Alice", "Robert", 1),
		"numbers":    strings.Replace(base, "12345", "98765 and 4", 1),
		"whitespace": strings.ReplaceAll(base, " ", "  \t"),
		"link":       strings.Replace(base, "shop.example/a?id=1", "other.example/zz?id=77", 1),
		"quoted":     base + "\n> On Monday somebody wrote a long unrelated reply here that is quoted\n> and ignored entirely",
		"case":       strings.ToUpper(base),
	}
	for name, edited := range edits {
		if similarity := original.similarity(bodySignature(t, edited)); similarity < 0.9 {
			t.Errorf("%s edit similarity = %.2f", name, similarity)
		}
	}
	if similarity := original.similarity(bodySignature(t, "Dear Alice, "+fuzzyText(2, 200))); similarity > 0.15 {
		t.Errorf("unrelated message similarity = %.2f", similarity)
	}
	if _, ok := newSignature(fuzzyWords([]string{"too short to compare"})); ok {
		t.Error("a short body got a signature")
	}
}

type fuzzyFixture struct {
	fuzzy  *Fuzzy
	engine *Engine
	clock  *reputationClock
}

func newFuzzyFixture(t *testing.T) fuzzyFixture {
	t.Helper()
	clock := &reputationClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	fuzzy := &Fuzzy{Now: clock.Now, MaxEntries: 4, BulkMaxEntries: 3}
	fuzzy.SetSettings(true, 80, 3)
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), Fuzzy: fuzzy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fuzzyFixture{fuzzy: fuzzy, engine: engine, clock: clock}
}

// check scores body arriving from the nth public network.
func (f fuzzyFixture) check(t *testing.T, body string, n int, headers map[string]string) Result {
	t.Helper()
	if headers == nil {
		headers = map[string]string{}
	}
	raw := fuzzyRaw(body)
	result, ok := f.engine.Check(context.Background(), Message{
		Content: raw, Headers: headers, RemoteIP: fmt.Sprintf("8.%d.8.8", n), EnvelopeFrom: fmt.Sprintf("s%d@sender%d.example", n, n),
		SPF: "pass", DKIM: headers["dkim"], DMARC: "pass",
	})
	if !ok {
		t.Fatal("not scored")
	}
	return result
}

func TestFuzzyJunkMovesTeachAndNotJunkForgets(t *testing.T) {
	f := newFuzzyFixture(t)
	spamBody := "Dear Alice, " + fuzzyText(10, 150) + " code 4711"
	if _, found := repSymbol(f.check(t, spamBody, 1, nil), SymbolFuzzySpam); found {
		t.Fatal("unknown body matched")
	}
	f.fuzzy.Moved(fuzzyRaw(spamBody), true)
	variant := strings.Replace(spamBody, "Alice", "Bob", 1) + " 99"
	symbol, found := repSymbol(f.check(t, variant, 2, nil), SymbolFuzzySpam)
	if !found || symbol.Score < 3 || symbol.Score > 4 {
		t.Fatalf("FUZZY_SPAM = %+v, %v", symbol, found)
	}
	if _, found := repSymbol(f.check(t, fuzzyText(11, 150), 3, nil), SymbolFuzzySpam); found {
		t.Fatal("dissimilar body matched")
	}
	f.fuzzy.Moved(fuzzyRaw(variant), false)
	if _, found := repSymbol(f.check(t, spamBody, 4, nil), SymbolFuzzySpam); found {
		t.Fatal("Not-junk move left the signature in place")
	}

	// The zone can be switched off live.
	f.fuzzy.Moved(fuzzyRaw(spamBody), true)
	f.fuzzy.SetSettings(false, 80, 3)
	if _, found := repSymbol(f.check(t, spamBody, 5, nil), SymbolFuzzySpam); found {
		t.Fatal("disabled detector scored")
	}
	f.fuzzy.SetSettings(true, 100, 3)
	if _, found := repSymbol(f.check(t, variant, 6, nil), SymbolFuzzySpam); found {
		t.Fatal("a 100% threshold matched an edited body")
	}
}

func TestFuzzyLearnsFromHighScoringSpamButNotFromItself(t *testing.T) {
	f := newFuzzyFixture(t)
	body := fuzzyText(20, 120)
	junk := map[string]string{"x-spam-test": "1"}
	f.engine.config.Thresholds = Thresholds{Junk: 0.5, Reject: 100}
	first := f.check(t, body, 1, junk)
	if first.Action != ActionJunk {
		t.Fatalf("test message is not junk: %+v", first)
	}
	if got := f.fuzzy.spam.Len(); got != 1 {
		t.Fatalf("learned %d signatures", got)
	}
	second := f.check(t, body, 2, junk)
	symbol, found := repSymbol(second, SymbolFuzzySpam)
	if !found || symbol.Score <= 0 || symbol.Score >= 4 {
		t.Fatalf("an automatic signature scored %+v, %v", symbol, found)
	}
	// Matching itself never strengthens the signature: only the fuzzy symbol made it junk.
	f.engine.config.Thresholds = Thresholds{Junk: first.Score + 0.1, Reject: 100}
	before := f.fuzzy.spam.Front().Value.(*fuzzyEntry).weight
	f.check(t, body, 3, junk)
	if weight := f.fuzzy.spam.Front().Value.(*fuzzyEntry).weight; weight != before {
		t.Fatalf("weight = %v after %v", weight, before)
	}
}

func TestBulkCountsUnrelatedSendersInAWindow(t *testing.T) {
	f := newFuzzyFixture(t)
	body := fuzzyText(30, 100)
	for i := 1; i <= 3; i++ {
		if _, found := repSymbol(f.check(t, body, i, nil), SymbolBulkSameBody); found {
			t.Fatalf("sender %d at the threshold scored bulk", i)
		}
	}
	// The same sender again does not count twice.
	if _, found := repSymbol(f.check(t, body, 3, nil), SymbolBulkSameBody); found {
		t.Fatal("a repeating sender counted as many")
	}
	symbol, found := repSymbol(f.check(t, body+" and a trailing edit 5", 4, nil), SymbolBulkSameBody)
	if !found || symbol.Score <= 0 || symbol.Options[0] != "senders=4" {
		t.Fatalf("BULK_SAME_BODY = %+v, %v", symbol, found)
	}
	if _, found := repSymbol(f.check(t, fuzzyText(31, 100), 5, nil), SymbolBulkSameBody); found {
		t.Fatal("a different body was counted with the bulk mailing")
	}

	// A DKIM-signed sender offering List-Unsubscribe is a newsletter.
	letter, found := repSymbol(f.check(t, body, 6, map[string]string{"list-unsubscribe": "<mailto:u@x.example>", "dkim": "pass"}), SymbolBulkNewsletter)
	if !found || letter.Score != 0 {
		t.Fatalf("BULK_NEWSLETTER = %+v, %v", letter, found)
	}
	if _, found := repSymbol(f.check(t, body, 7, map[string]string{"list-unsubscribe": "<mailto:u@x.example>"}), SymbolBulkSameBody); !found {
		t.Fatal("an unsigned List-Unsubscribe exempted bulk mail")
	}

	// The count expires with the window.
	f.clock.now = f.clock.now.Add(2 * DefaultBulkWindow)
	if _, found := repSymbol(f.check(t, body, 8, nil), SymbolBulkSameBody); found {
		t.Fatal("expired window still counted")
	}
}

func TestFuzzyStoresAreBoundedAndDecay(t *testing.T) {
	f := newFuzzyFixture(t)
	for seed := range uint64(10) {
		f.fuzzy.Moved(fuzzyRaw(fuzzyText(100+seed, 80)), true)
		f.check(t, fuzzyText(200+seed, 80), int(seed)+1, nil)
	}
	if f.fuzzy.spam.Len() != 4 || f.fuzzy.recent.Len() != 3 {
		t.Fatalf("stores = %d signatures, %d recent bodies", f.fuzzy.spam.Len(), f.fuzzy.recent.Len())
	}
	kept := fuzzyText(109, 80)
	if _, found := repSymbol(f.check(t, kept, 20, nil), SymbolFuzzySpam); !found {
		t.Fatal("the newest signature was evicted")
	}
	if _, found := repSymbol(f.check(t, fuzzyText(100, 80), 21, nil), SymbolFuzzySpam); found {
		t.Fatal("the oldest signature survived the cap")
	}
	f.clock.now = f.clock.now.Add(10 * DefaultFuzzyHalfLife)
	if _, found := repSymbol(f.check(t, kept, 22, nil), SymbolFuzzySpam); found {
		t.Fatal("a decayed signature still scored")
	}

	f.fuzzy.Moved(fuzzyRaw(kept), true)
	data, err := f.fuzzy.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored := &Fuzzy{Now: f.clock.Now, MaxEntries: 2}
	if err := restored.Restore(data); err != nil || restored.spam.Len() != 2 {
		t.Fatalf("restore = %v, %d signatures", err, restored.spam.Len())
	}
	if _, entry := restored.matchSpamLocked(bodySignature(t, kept), f.clock.now); entry == nil {
		t.Fatal("the most recent signature was lost")
	}
	if err := restored.Restore([]byte("not json")); err == nil {
		t.Fatal("garbage restored")
	}
	restored.Reset()
	if restored.spam.Len() != 0 {
		t.Fatal("reset kept signatures")
	}
}
