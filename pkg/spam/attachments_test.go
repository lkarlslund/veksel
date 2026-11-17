package spam

import (
	"context"
	"testing"

	"github.com/lkarlslund/veksel/pkg/attachment"
)

func TestAttachmentFindingsScoreAsSymbolsWithOverrides(t *testing.T) {
	engine, err := NewEngine(Config{Thresholds: DefaultThresholds(), SymbolScores: map[string]float64{"ATTACH_MACRO": 0}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := engine.Check(context.Background(), Message{Content: []byte("From: a@example.org\r\n\r\nx"), Attachments: []attachment.Finding{
		{Symbol: attachment.SymbolDangerousExt, Detail: "a.exe", Hard: true},
		{Symbol: attachment.SymbolDangerousExt, Detail: "b.scr", Hard: true},
		{Symbol: attachment.SymbolMacro, Detail: "c.docm"},
		{Symbol: "NOT_A_SYMBOL", Detail: "ignored"},
	}})
	scores := map[string]Symbol{}
	for _, symbol := range result.Symbols {
		scores[symbol.Name] = symbol
	}
	if got := scores[attachment.SymbolDangerousExt]; got.Score != 6 || len(got.Options) != 2 {
		t.Fatalf("dangerous symbol = %+v", got)
	}
	if got, ok := scores[attachment.SymbolMacro]; !ok || got.Score != 0 {
		t.Fatalf("overridden macro symbol = %+v", got)
	}
	if _, ok := scores["NOT_A_SYMBOL"]; ok {
		t.Fatal("unregistered finding became a symbol")
	}
	if _, err := ParseSettings(Settings{Thresholds: DefaultThresholds(), SymbolScores: []string{"ATTACH_RTLO=9"}}); err != nil {
		t.Fatalf("attachment symbols must accept score overrides: %v", err)
	}
}

func TestEveryAttachmentSymbolIsRegistered(t *testing.T) {
	for _, name := range []string{
		attachment.SymbolDangerousExt, attachment.SymbolDoubleExt, attachment.SymbolTypeMismatch, attachment.SymbolMacro,
		attachment.SymbolEncryptedArchive, attachment.SymbolArchiveBomb, attachment.SymbolRTLO, attachment.SymbolHTMLForm,
	} {
		if _, ok := builtinSymbols[name]; !ok {
			t.Errorf("%s has no registered score", name)
		}
	}
}
