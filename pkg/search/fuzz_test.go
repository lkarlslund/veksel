package search

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/service"
)

// FuzzExpression feeds end-user search expressions through expansion,
// validation and query compilation.
func FuzzExpression(f *testing.F) {
	for _, seed := range []string{
		`from:alice subject:"quarterly report" -is:read has:attachment after:2024-01-01 before:2024-12-31`,
		`type:calendar is:trashed "unterminated`,
		`"esc\"aped" \ -`,
		`header:x filename:a.pdf attachmenttext:invoice is:flagged -is:unstarred`,
		strings.Repeat("a ", 300),
		"", ":", "-", "\x00\xff",
	} {
		f.Add(seed, "free text")
	}
	f.Fuzz(func(t *testing.T, expression, text string) {
		request := service.SearchQuery{Expression: expression, Text: text}
		_ = ValidateQuery(request)
		expanded, err := expandExpression(request)
		if err != nil {
			return
		}
		if expanded.Expression != "" && strings.TrimSpace(expression) != "" {
			t.Fatalf("expression %q left unexpanded", expression)
		}
		if validateSearchQuery(expanded) == nil {
			_, _ = compileQuery(expanded, []string{"folder"})
		}
		_, _ = decodeCursor(expression)
	})
}

// FuzzSnippets checks that result snippets slice indexed content safely and
// that their highlight ranges lie within the snippet text.
func FuzzSnippets(f *testing.F) {
	for _, seed := range []struct{ content, term string }{
		{"The quarterly report is attached.", "report"},
		{"İstanbul İSTANBUL invoice", "invoice"},
		{"\xff\xfe\xfd needle", "needle"},
		{"ȺȺȺȺ needle in haystack", "in haystack"},
		{"short", "missing words"},
		{"", "x"},
	} {
		f.Add(seed.content, seed.term)
	}
	f.Fuzz(func(t *testing.T, content, term string) {
		for _, snippet := range snippets(content, term) {
			for _, span := range snippet.Ranges {
				if span[0] < 0 || span[1] < span[0] || span[1] > len(snippet.Text) {
					t.Fatalf("range %v outside snippet %q of content %q for %q", span, snippet.Text, content, term)
				}
			}
		}
	})
}
