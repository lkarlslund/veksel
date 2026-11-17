package log

import "testing"

func TestEscapeTextKeepsOneTextLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain æøå":          "plain æøå",
		"HELO \x00\x1b[31mx": `HELO \x00\x1b[31mx`,
		"two\r\nlines\tand":  `two\r\nlines\tand`,
		"bad \xff\xfe utf8":  `bad \xff\xfe utf8`,
		"keeps � literal":    "keeps � literal",
	} {
		if got := escapeText(in); got != want {
			t.Errorf("escapeText(%q) = %q, want %q", in, got, want)
		}
	}
}
