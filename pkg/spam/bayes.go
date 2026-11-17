package spam

import (
	"cmp"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
)

// Classifier probability bands. At or above BayesSpamProbability the
// BAYES_SPAM symbol carries its full score, between BayesProbableProbability
// and it 60% of that score, and at or below BayesHamProbability BAYES_HAM
// applies; anything between is BAYES_UNSURE.
const (
	BayesSpamProbability     = 0.99
	BayesProbableProbability = 0.9
	BayesHamProbability      = 0.01
	bayesProbableScale       = 0.6
	bayesSymbolPrefix        = "BAYES_"
)

// Robinson/Fisher combining parameters, as tuned by SpamBayes.
const (
	unknownWordStrength = 0.45
	unknownWordProb     = 0.5
	minProbStrength     = 0.1
	maxDiscriminators   = 150
)

func init() {
	maps.Copy(builtinSymbols, map[string]symbolInfo{
		"BAYES_SPAM":   {5.0, "Statistical classifier judges the message spam"},
		"BAYES_HAM":    {-3.0, "Statistical classifier judges the message legitimate"},
		"BAYES_UNSURE": {0, "Statistical classifier is unsure"},
	})
}

// TokenCounts are the numbers of trained spam and ham messages that
// contained a token.
type TokenCounts struct {
	Spam uint32
	Ham  uint32
}

// Probability combines the evidence of a message's distinct tokens into a
// spam probability with Robinson's smoothed per-token probabilities and
// Fisher's chi-squared combining, as in SpamBayes. counts holds the trained
// counts of the message's tokens; unknown tokens may be omitted. It returns
// 0.5 when no token is informative.
func Probability(counts map[string]TokenCounts, spamMessages, hamMessages uint32) float64 {
	if spamMessages == 0 || hamMessages == 0 {
		return 0.5
	}
	clues := make([]float64, 0, len(counts))
	for _, count := range counts {
		n := float64(count.Spam) + float64(count.Ham)
		if n == 0 {
			continue
		}
		spamRatio := float64(count.Spam) / float64(spamMessages)
		hamRatio := float64(count.Ham) / float64(hamMessages)
		p := spamRatio / (spamRatio + hamRatio)
		f := (unknownWordStrength*unknownWordProb + n*p) / (unknownWordStrength + n)
		if math.Abs(f-0.5) >= minProbStrength {
			clues = append(clues, f)
		}
	}
	if len(clues) == 0 {
		return 0.5
	}
	slices.SortFunc(clues, func(a, b float64) int { return cmp.Compare(math.Abs(b-0.5), math.Abs(a-0.5)) })
	if len(clues) > maxDiscriminators {
		clues = clues[:maxDiscriminators]
	}
	var spamLog, hamLog float64
	for _, f := range clues {
		spamLog += math.Log(1 - f)
		hamLog += math.Log(f)
	}
	degrees := 2 * len(clues)
	spamness := 1 - chi2Q(-2*spamLog, degrees)
	hamness := 1 - chi2Q(-2*hamLog, degrees)
	return (spamness - hamness + 1) / 2
}

// chi2Q is the probability that a chi-squared variable with even degrees of
// freedom exceeds x2.
func chi2Q(x2 float64, degrees int) float64 {
	m := x2 / 2
	term := math.Exp(-m)
	sum := term
	for i := 1; i < degrees/2; i++ {
		term *= m / float64(i)
		sum += term
	}
	return min(sum, 1)
}

// BayesSymbol returns the classifier symbol for probability, scored with
// the engine's overrides. model names the model that judged it, such as
// user or global.
func (e *Engine) BayesSymbol(probability float64, model string) Symbol {
	name, scale := "BAYES_UNSURE", 1.0
	switch {
	case probability >= BayesSpamProbability:
		name = "BAYES_SPAM"
	case probability >= BayesProbableProbability:
		name, scale = "BAYES_SPAM", bayesProbableScale
	case probability <= BayesHamProbability:
		name = "BAYES_HAM"
	}
	info := builtinSymbols[name]
	score := info.score
	if override, ok := e.config.SymbolScores[name]; ok {
		score = override
	}
	return Symbol{
		Name: name, Score: math.Round(score*scale*100) / 100, Description: info.description,
		Options: []string{"p=" + strconv.FormatFloat(probability, 'f', 4, 64), "model=" + model},
	}
}

// BayesSymbol returns the current engine's classifier symbol, or false when
// scoring is disabled.
func (s *Switch) BayesSymbol(probability float64, model string) (Symbol, bool) {
	engine := s.engine.Load()
	if engine == nil {
		return Symbol{}, false
	}
	return engine.BayesSymbol(probability, model), true
}

// WithBayes returns r with symbol replacing any classifier symbol already
// present, and the score and action recomputed.
func (r Result) WithBayes(symbol Symbol) Result {
	symbols := make([]Symbol, 0, len(r.Symbols)+1)
	for _, existing := range r.Symbols {
		if !strings.HasPrefix(existing.Name, bayesSymbolPrefix) {
			symbols = append(symbols, existing)
		}
	}
	r.Symbols = sortSymbols(append(symbols, symbol))
	r.Score = 0
	for _, existing := range r.Symbols {
		r.Score += existing.Score
	}
	r.Score = math.Round(r.Score*100) / 100
	r.Action = r.Thresholds.Action(r.Score)
	return r
}

// ScoreWithoutBayes is the score r reached before any classifier symbol,
// which auto-learning judges so the classifier never trains itself.
func (r Result) ScoreWithoutBayes() float64 {
	score := r.Score
	for _, symbol := range r.Symbols {
		if strings.HasPrefix(symbol.Name, bayesSymbolPrefix) {
			score -= symbol.Score
		}
	}
	return math.Round(score*100) / 100
}
