package sieve

import (
	"strings"
	"testing"
)

func TestLexerStringsNumbersAndComments(t *testing.T) {
	tokens, err := Tokenize("/* bracket\n comment */ # hash\n\"a\\\"b\\\\c\\d\" 10K 2m 1G :Over Text:\r\n.. dot\r\nline\r\n.\r\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		typ   TokenType
		value string
		num   int64
	}{
		{TokString, `a"b\cd`, 0},
		{TokNumber, "10240", 10240},
		{TokNumber, "2097152", 2 << 20},
		{TokNumber, "1073741824", 1 << 30},
		{TokTag, "over", 0},
		{TokString, ". dot\r\nline\r\n", 0},
		{TokEOF, "", 0},
	}
	if len(tokens) != len(want) {
		t.Fatalf("tokens = %+v", tokens)
	}
	for index, w := range want {
		if tok := tokens[index]; tok.Type != w.typ || tok.Value != w.value || tok.Num != w.num {
			t.Errorf("token %d = %+v, want %+v", index, tok, w)
		}
	}
}

func TestLexerErrors(t *testing.T) {
	for _, input := range []string{
		`"unterminated`, "/* open comment", "text:\nno end\n", "text: junk\n.\n", `99999999999999999999`,
		`8G00`, `9223372036854775807G`, `: tag`, `@`, "\xff\xfe", `"\`,
	} {
		if _, err := Tokenize(input); err == nil {
			t.Errorf("Tokenize(%q) succeeded", input)
		}
	}
}

func TestParseAcceptsRFC5228Grammar(t *testing.T) {
	for _, script := range []string{
		``,
		`keep;`,
		`require "fileinto"; require ["envelope", "comparator-i;octet"]; fileinto "A";`,
		"require [\"fileinto\"];\r\nif header :contains [\"Subject\", \"X-Tag\"] [\"a\", \"b\"] { fileinto \"A\"; } elsif exists \"x\" { discard; } else { keep; stop; }",
		`if allof (true, not false, anyof (size :over 10K, size :under 1M)) { keep; }`,
		`if address :all :comparator "i;octet" :is "from" "a@b.c" { redirect "x@example.com"; }`,
		`if address :comparator "i;ascii-casemap" :domain :matches ["to", "cc"] "*.example.com" { keep; }`,
		`require ["envelope", "subaddress"]; if envelope :detail "to" "news" { keep; }`,
		`require ["relational", "comparator-i;ascii-numeric"]; if header :count "ge" :comparator "i;ascii-numeric" "received" "3" { discard; }`,
		`require "vacation"; vacation :days 3 :subject "Away" :from "me@example.com" :addresses ["a@example.com"] :mime :handle "h" text:
Content-Type: text/plain

Away.
.
;`,
		`require ["vacation", "vacation-seconds"]; vacation :seconds 0 "Away";`,
		`require ["variables", "fileinto"]; set :lower :upperfirst "name" "${1}"; if string :is "${name}" "" { fileinto "INBOX.${name}"; }`,
		`require ["copy", "fileinto"]; fileinto :copy "A"; redirect :copy "b@example.com";`,
		`require ["reject"]; reject text:
line one
.
;`,
		`require "ereject"; ereject "no";`,
		`require "encoded-character"; if header :is "subject" "${hex:41}${unicode:263a}" { keep; }`,
		`if header :is "x" "${not-a-reference}" { keep; }`,
		`require "variables"; set "a" "${a}${0}${UNKNOWN}";`,
	} {
		if _, err := Parse(script); err != nil {
			t.Errorf("Parse(%q): %v", script, err)
		}
	}
}

func TestParseRejectsInvalidScripts(t *testing.T) {
	for _, tc := range []struct{ name, script, want string }{
		{"unknown extension", `require "imap4flags";`, "unsupported extension"},
		{"unknown extension in list", `require ["fileinto", "body"];`, "unsupported extension"},
		{"fileinto without require", `fileinto "A";`, `"fileinto" extension`},
		{"envelope without require", `if envelope "from" "a" { keep; }`, `"envelope" extension`},
		{"vacation without require", `vacation "x";`, `"vacation" extension`},
		{"reject without require", `reject "x";`, `"reject" extension`},
		{"copy without require", `redirect :copy "a@example.com";`, `"copy" extension`},
		{"subaddress without require", `if address :detail "to" "x" { keep; }`, "subaddress"},
		{"set without require", `set "a" "b";`, `"variables" extension`},
		{"relational without require", `if header :count "gt" "x" "1" { keep; }`, `"relational" extension`},
		{"numeric without require", `if header :comparator "i;ascii-numeric" "x" "1" { keep; }`, "comparator-i;ascii-numeric"},
		{"seconds without require", `require "vacation"; vacation :seconds 1 "x";`, "vacation-seconds"},
		{"require after command", `keep; require "fileinto";`, "before any other command"},
		{"nested require", `if true { require "fileinto"; }`, "before any other command"},
		{"elsif without if", `elsif true { keep; }`, "without a preceding if"},
		{"else after else", `if true { keep; } else { keep; } else { keep; }`, "without a preceding if"},
		{"missing semicolon", `keep`, `expected ";"`},
		{"missing block", `if true keep;`, `takes a test and a block`},
		{"unknown command", `frobnicate;`, "unknown command"},
		{"unknown test", `if frob { keep; }`, "unknown test"},
		{"bad header name", `if header :is "bad name" "x" { keep; }`, "invalid header name"},
		{"bad envelope part", `require "envelope"; if envelope :is "subject" "x" { keep; }`, "unsupported envelope part"},
		{"days and seconds", `require ["vacation", "vacation-seconds"]; vacation :days 1 :seconds 1 "x";`, "not both"},
		{"numeric contains", `require "comparator-i;ascii-numeric"; if header :contains :comparator "i;ascii-numeric" "x" "1" { keep; }`, "substring"},
		{"unknown comparator", `if header :comparator "i;unicode-casemap" "x" "1" { keep; }`, "unsupported comparator"},
		{"two match types", `if header :is :contains "x" "1" { keep; }`, "more than one match type"},
		{"tag after positional", `if header "x" :is "1" { keep; }`, "unexpected tag"},
		{"missing key list", `if header :is "x" { keep; }`, "missing key list"},
		{"invalid redirect", `redirect "not an address";`, "invalid redirect address"},
		{"bad relation", `require "relational"; if header :value "gte" "x" "1" { keep; }`, "invalid relational operator"},
		{"size without tag", `if size 10 { keep; }`, ":over or :under"},
		{"not with list", `if not (true) { keep; }`, "exactly one test"},
		{"anyof without list", `if anyof true { keep; }`, "parenthesized"},
		{"unicode surrogate", `require "encoded-character"; keep; if header :is "x" "${unicode:D800}" { keep; }`, "out of range"},
		{"variable namespace", `require "variables"; set "a" "${env.home}";`, "namespace"},
		{"invalid variable name", `require "variables"; set "1a" "x";`, "invalid variable name"},
		{"conflicting modifiers", `require "variables"; set :lower :upper "a" "x";`, "conflicting set modifier"},
		{"string list as string", `require "fileinto"; fileinto ["a", "b"];`, "must be a string"},
		{"empty mailbox", `require "fileinto"; fileinto "";`, "mailbox name"},
		{"too deep", strings.Repeat("if true {", maxNesting+1) + strings.Repeat("}", maxNesting+1), "nesting"},
		{"too deep tests", "if " + strings.Repeat("not ", maxNesting+1) + "true { keep; }", "nesting"},
	} {
		_, err := Parse(tc.script)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Parse(%q) error = %v, want %q", tc.name, tc.script, err, tc.want)
		}
	}
}

func TestParseErrorPosition(t *testing.T) {
	_, err := Parse("keep;\n  frobnicate;")
	parseErr, ok := err.(*ParseError)
	if !ok || parseErr.Line != 2 || parseErr.Column != 3 {
		t.Fatalf("error = %#v", err)
	}
}

func TestParseBuildsIfChainAndSetModifiers(t *testing.T) {
	script, err := Parse(`require "variables"; if false { keep; } elsif true { discard; } else { stop; } set :length :upper "v" "x";`)
	if err != nil {
		t.Fatal(err)
	}
	chain, ok := script.Commands[0].(*IfCommand)
	if !ok || len(chain.Branches) != 2 || len(chain.Else) != 1 {
		t.Fatalf("if chain = %#v", script.Commands[0])
	}
	set, ok := script.Commands[1].(*SetCommand)
	if !ok || set.Name != "v" || strings.Join(set.Modifiers, ",") != "upper,length" {
		t.Fatalf("set = %#v", script.Commands[1])
	}
}

func TestCapabilitiesListOnlyImplementedExtensions(t *testing.T) {
	for _, extension := range Extensions {
		if _, err := Parse(`require "` + extension + `";`); err != nil {
			t.Errorf("advertised %q is not accepted: %v", extension, err)
		}
	}
	for _, unimplemented := range []string{"imap4flags", "body", "date", "index", "include", "editheader", "duplicate", "spamtest", "virustest", "regex", "notify"} {
		if strings.Contains(" "+Capabilities+" ", " "+unimplemented+" ") {
			t.Errorf("capabilities advertise unimplemented %q", unimplemented)
		}
	}
}
