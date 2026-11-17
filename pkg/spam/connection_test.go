package spam

import (
	"context"
	"testing"
)

func TestConnectionFindingsScoreAsSymbolsWithOverrides(t *testing.T) {
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), SymbolScores: map[string]float64{SymbolRDNSNone: 0}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := engine.Check(context.Background(), Message{Content: []byte("From: a@example.org\r\n\r\nx"), Connection: []ConnectionFinding{
		{Symbol: SymbolPregreet, Detail: "EHLO x"},
		{Symbol: SymbolProtocolViolation, Detail: "bare LF"},
		{Symbol: SymbolProtocolViolation, Detail: "NUL byte"},
		{Symbol: SymbolRDNSNone},
		{Symbol: "SPAM_PHRASE", Detail: "not a connection symbol"},
	}})
	scores := map[string]Symbol{}
	for _, symbol := range result.Symbols {
		scores[symbol.Name] = symbol
	}
	if got := scores[SymbolPregreet]; got.Score != 4 || len(got.Options) != 1 {
		t.Fatalf("pregreet symbol = %+v", got)
	}
	if got := scores[SymbolProtocolViolation]; len(got.Options) != 2 {
		t.Fatalf("violation symbol = %+v", got)
	}
	if got, ok := scores[SymbolRDNSNone]; !ok || got.Score != 0 {
		t.Fatalf("overridden rDNS symbol = %+v", got)
	}
	if _, ok := scores["SPAM_PHRASE"]; ok {
		t.Fatal("a connection finding injected a non-connection symbol")
	}
	if _, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: []string{"HELO_FORGED_LOCAL=5"}}); err != nil {
		t.Fatalf("connection symbols must accept score overrides: %v", err)
	}
}
