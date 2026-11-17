package spam

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func TestTokenizeNormalizesSubjectBodiesHeadersAndLinks(t *testing.T) {
	raw := strings.Join([]string{
		"From: \"Shop\" <deals@Promo.Example.NET>",
		"Subject: =?utf-8?q?Gr=C3=B8n_Offer?= today",
		"X-Mailer: BulkSender 4.2",
		"Received: from host-10-1-2-3.dyn.example.net (host-10-1-2-3.dyn.example.net [192.0.2.4]) by mx.local",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=b",
		"",
		"--b",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"Caf=C3=A9 PRICES don't wait 1234567 a an supercalifragilisticexpialidociousness",
		"--b",
		"Content-Type: text/html",
		"",
		"<p>Click <a href=\"https://www.shop-deals.biz/x\">here</a></p><script>hidden</script>",
		"--b--",
		"",
	}, "\r\n")
	tokens := Tokenize([]byte(raw))
	for _, want := range []string{"s:grøn", "s:offer", "s:today", "café", "prices", "don't", "wait", "click", "here",
		"skip:s:30", "from:promo.example.net", "mailer:bulksender", "rcvd:dynamic", "ct:multipart/alternative", "url:shop-deals.biz"} {
		if !slices.Contains(tokens, want) {
			t.Errorf("tokens lack %q: %q", want, tokens)
		}
	}
	for _, unwanted := range []string{"an", "1234567", "hidden", "Offer"} {
		if slices.Contains(tokens, unwanted) {
			t.Errorf("tokens contain %q", unwanted)
		}
	}
	if got := Tokenize([]byte("Subject: x\r\n\r\nhello hello hello")); len(got) != 2 {
		t.Fatalf("tokens repeat: %q", got)
	}
	var long strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&long, "word%d ", i)
	}
	if got := Tokenize([]byte("Subject: x\r\n\r\n" + long.String())); len(got) != MaxSampleTokens {
		t.Fatalf("tokens = %d, want the %d cap", len(got), MaxSampleTokens)
	}
	if relayClass("from [192.0.2.1] by mx") != "literal" || relayClass("from mail.example.com (mail.example.com [192.0.2.1])") != "named" || relayClass("from x (unknown [192.0.2.1])") != "unknown" {
		t.Fatal("relay classes are wrong")
	}
}

func TestSampleKeyIgnoresAddedHeaders(t *testing.T) {
	message := "Message-ID: <a@example.net>\r\nSubject: hi\r\n\r\nbody text\r\n"
	delivered := "X-Spam-Score: 1\r\nReceived: from x by y\r\n" + message
	if NewSample([]byte(message)).Key != NewSample([]byte(delivered)).Key {
		t.Fatal("delivery headers changed the sample key")
	}
	if NewSample([]byte(message)).Key == NewSample([]byte(strings.Replace(message, "<a@", "<b@", 1))).Key {
		t.Fatal("different messages share a key")
	}
}

// syntheticCorpus generates messages whose words come mostly from a
// class-specific vocabulary mixed with shared filler.
func syntheticCorpus(random *rand.Rand, vocabulary []string, count int) [][]string {
	filler := []string{"the", "and", "for", "you", "this", "with", "have", "from", "are", "will", "your", "about"}
	messages := make([][]string, count)
	for index := range messages {
		seen := map[string]bool{}
		for range 30 {
			word := filler[random.IntN(len(filler))]
			if random.IntN(3) > 0 {
				word = vocabulary[random.IntN(len(vocabulary))]
			}
			seen[word] = true
		}
		for word := range seen {
			messages[index] = append(messages[index], word)
		}
	}
	return messages
}

func TestProbabilitySeparatesSyntheticSpamFromHam(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	spamWords := []string{"viagra", "winner", "prize", "casino", "bitcoin", "unsubscribe", "offer", "cheap", "click", "urgent", "loan", "free"}
	hamWords := []string{"meeting", "agenda", "project", "invoice", "review", "lunch", "draft", "report", "schedule", "team", "budget", "notes"}
	counts := map[string]TokenCounts{}
	train := func(messages [][]string, spam bool) {
		for _, tokens := range messages {
			for _, token := range tokens {
				count := counts[token]
				if spam {
					count.Spam++
				} else {
					count.Ham++
				}
				counts[token] = count
			}
		}
	}
	train(syntheticCorpus(random, spamWords, 200), true)
	train(syntheticCorpus(random, hamWords, 200), false)
	classify := func(tokens []string) float64 {
		subset := map[string]TokenCounts{}
		for _, token := range tokens {
			if count, ok := counts[token]; ok {
				subset[token] = count
			}
		}
		return Probability(subset, 200, 200)
	}
	for _, tokens := range syntheticCorpus(random, spamWords, 50) {
		if p := classify(tokens); p < BayesSpamProbability {
			t.Fatalf("spam probability = %v for %q", p, tokens)
		}
	}
	for _, tokens := range syntheticCorpus(random, hamWords, 50) {
		if p := classify(tokens); p > BayesHamProbability {
			t.Fatalf("ham probability = %v for %q", p, tokens)
		}
	}
	if p := classify([]string{"the", "and", "you"}); p < 0.2 || p > 0.8 {
		t.Fatalf("filler-only probability = %v, want unsure", p)
	}
	if p := classify([]string{"never-seen"}); p != 0.5 {
		t.Fatalf("unknown-only probability = %v", p)
	}
	if Probability(counts, 0, 200) != 0.5 {
		t.Fatal("an untrained class scored")
	}
}

func TestBayesSymbolBandsOverridesAndResult(t *testing.T) {
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), SymbolScores: map[string]float64{"BAYES_HAM": -4}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		probability float64
		name        string
		score       float64
	}{{0.999, "BAYES_SPAM", 5}, {0.95, "BAYES_SPAM", 3}, {0.5, "BAYES_UNSURE", 0}, {0.005, "BAYES_HAM", -4}} {
		symbol := engine.BayesSymbol(test.probability, "user")
		if symbol.Name != test.name || symbol.Score != test.score || !slices.Contains(symbol.Options, "model=user") {
			t.Errorf("p=%v symbol = %+v", test.probability, symbol)
		}
	}
	if _, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: []string{"BAYES_SPAM=7"}}); err != nil {
		t.Fatalf("BAYES_SPAM override rejected: %v", err)
	}
	result := Result{Thresholds: DefaultThresholds(), Score: 2, Symbols: []Symbol{{Name: "MISSING_DATE", Score: 2}}}
	result = result.WithBayes(engine.BayesSymbol(0.999, "global"))
	if result.Score != 7 || result.Action != ActionJunk || result.Symbols[0].Name != "BAYES_SPAM" {
		t.Fatalf("with global symbol = %+v", result)
	}
	result = result.WithBayes(engine.BayesSymbol(0.001, "user"))
	if result.Score != -2 || result.Action != ActionNone || len(result.Symbols) != 2 || result.ScoreWithoutBayes() != 2 {
		t.Fatalf("user symbol did not replace the global one: %+v", result)
	}
	var disabled Switch
	if _, ok := disabled.BayesSymbol(0.999, "user"); ok {
		t.Fatal("a disabled switch scored")
	}
}
