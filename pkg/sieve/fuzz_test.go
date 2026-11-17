package sieve

import (
	"strings"
	"testing"
)

// FuzzSieveScript feeds random bytes into the Sieve tokenizer and parser.
func FuzzSieveScript(f *testing.F) {
	// Seed corpus
	seeds := []string{
		`require "fileinto"; if address :is "from" "user@example.com" { fileinto "inbox"; stop; }`,
		`require ["fileinto"]; if header :contains ["subject", "x-tag"] ["urgent", "asap"] { fileinto "important"; }`,
		`require "reject"; if size :over 1M { reject "Message too large"; }`,
		`if address :domain "from" "spam.com" { discard; }`,
		`redirect "backup@example.com";`,
		`keep;`,
		`require "fileinto"; if header :is "from" "news@example.com" { fileinto "newsletters"; stop; } elsif header :is "from" "social@example.com" { fileinto "social"; } else { keep; }`,
		`if address :matches "from" "*@example.com" { keep; }`,
		`if not header :contains "from" "spam" { keep; }`,
		`if allof (address :is "from" "a", header :is "subject" "b") { discard; }`,
		`if anyof (address :is "from" "a", exists "x-b") { discard; }`,
		`require ["envelope", "subaddress", "fileinto"]; if envelope :detail :matches "to" "*" { fileinto "${1}"; }`,
		`require ["variables", "fileinto"]; if header :matches "subject" "[*] *?" { set :lower :upperfirst "list" "${1}"; fileinto "lists.${list}"; }`,
		`require ["relational", "comparator-i;ascii-numeric"]; if header :count "ge" :comparator "i;ascii-numeric" "received" "3" { discard; }`,
		`require ["vacation", "vacation-seconds"]; vacation :seconds 60 :subject "Away" :addresses ["rcpt@example.org"] text:
Back soon.
..
.
;`,
		`require ["encoded-character", "copy", "fileinto"]; fileinto :copy "${hex:41 42}${unicode:263a}";`,
		`require "ereject"; ereject "no";`,
		// Empty / malformed
		"",
		`"`,
		`"unterminated string`,
		`if { }`,
		`if (`,
		`{ }`,
		`require`,
		`fileinto`,
		`discard`,
		`text:`,
		`/* open`,
		"\x00\xff\xfe",
		strings.Repeat(`if header :contains "x" "y" { `, 100),
		strings.Repeat(`if not `, 100),
		`#!sieve`,
		"# This is a comment\nrequire \"fileinto\";",
		`if header :is "a" "b" { if header :is "c" "d" { if header :is "e" "f" { keep; } } }`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Exercise tokenizer
		tokens, _ := Tokenize(input)
		_ = tokens

		// Exercise parser
		parser, err := NewParser(input)
		if err != nil {
			return
		}
		if script, err := parser.Parse(); err == nil {
			// Run the parsed script against a message whose header values
			// come from the script text, so tests compare fuzzed values.
			message := &Message{
				Headers: map[string][]string{
					"from":    {"\"Sender\" <sender@example.com>", input},
					"to":      {"=?UTF-8?Q?R=C3=A6k?= <rcpt+tag@example.org>"},
					"subject": {input},
					"date":    {"Mon, 01 Jan 2024 10:00:00 +0000"},
				},
				Body:                 []byte(input),
				RawSize:              len(input),
				EnvelopeFrom:         "sender@example.com",
				EnvelopeTo:           "rcpt+tag@example.org",
				SubaddressDelimiters: "+",
			}
			_, _ = NewInterpreter(message).Run(script)
		}

		// Exercise lexer directly
		lex := NewLexer(input)
		for {
			tok, err := lex.Scan()
			if err != nil {
				break
			}
			if tok.Type == TokEOF {
				break
			}
		}
	})
}
