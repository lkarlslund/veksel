package sieve

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const baseMessage = `From: "Alice Example" <Alice@Example.com>
To: "Doe, John" <rcpt+tag@example.org>, Friends: bob@friends.test, carol@friends.test;
Cc: undisclosed-recipients:;
Reply-To: =?UTF-8?Q?Doe=2C_John?= <john@example.com>
Subject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?= [acme-users] report
List-Name: acme <acme-users@lists.example.com>
X-Tag: first
X-Tag: second
X-Priority: 007
Received: from a
Received: from b
Message-ID: <original@example.com>

body
`

func testMessage(raw string) *Message {
	msg := NewMessage([]byte(strings.ReplaceAll(raw, "\n", "\r\n")))
	msg.EnvelopeFrom, msg.EnvelopeTo, msg.SubaddressDelimiters = "sender@example.net", "rcpt+tag@example.org", "+"
	return msg
}

func runScript(t *testing.T, script string, msg *Message) (*Result, error) {
	t.Helper()
	parsed, err := Parse(script)
	if err != nil {
		t.Fatalf("Parse(%q): %v", script, err)
	}
	return NewInterpreter(msg).Run(parsed)
}

type outcome struct {
	kept      bool
	folders   []string
	redirects []string
	reject    string
	discarded bool
	vacation  bool
	err       bool
}

func checkOutcome(t *testing.T, name, script string, msg *Message, want outcome) *Result {
	t.Helper()
	result, err := runScript(t, script, msg)
	if want.err {
		if err == nil {
			t.Errorf("%s: no runtime error, result %+v", name, result)
		}
		return nil
	}
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return nil
	}
	got := outcome{kept: result.Kept, folders: result.FileIntoFolders, redirects: result.RedirectAddresses,
		reject: result.RejectReason, discarded: result.Discarded, vacation: result.VacationReply != nil}
	if got.kept != want.kept || !slices.Equal(got.folders, want.folders) || !slices.Equal(got.redirects, want.redirects) ||
		got.reject != want.reject || got.discarded != want.discarded || got.vacation != want.vacation {
		t.Errorf("%s: outcome = %+v, want %+v", name, got, want)
	}
	return result
}

func fileInto(folders ...string) outcome { return outcome{folders: folders} }

func TestMatchTypesComparatorsAndAddressParts(t *testing.T) {
	const req = `require ["fileinto", "envelope", "subaddress", "relational", "comparator-i;ascii-numeric"]; `
	hit, miss := fileInto("hit"), outcome{kept: true}
	for _, tc := range []struct {
		name, test string
		want       outcome
	}{
		{"header matches suffix wildcard", `header :matches "from" "*@example.com>"`, hit},
		{"header matches needs whole value", `header :matches "from" "*@example.com"`, miss},
		{"address matches the reported bug", `address :matches "from" "*@example.com"`, hit},
		{"matches is not a regex", `address :matches "from" ".*@example.com"`, miss},
		{"question mark is one character", `address :matches :localpart "from" "?lice"`, hit},
		{"question mark needs a character", `address :matches :localpart "from" "?alice"`, miss},
		{"default comparator folds ASCII", `address :is "from" "ALICE@EXAMPLE.COM"`, hit},
		{"octet comparator is exact", `address :comparator "i;octet" :is "from" "alice@example.com"`, miss},
		{"octet comparator exact hit", `address :comparator "i;octet" :is "from" "Alice@Example.com"`, hit},
		{"contains", `header :contains "subject" "acme"`, hit},
		{"is compares the whole value", `header :is "subject" "acme"`, miss},
		{"header is decoded before matching", `header :contains "subject" "Grüße"`, hit},
		{"header is decoded for matches", `header :matches "subject" "Gr??e *"`, hit},
		{"any of multiple occurrences", `header :is "x-tag" "second"`, hit},
		{"any of several headers", `header :is ["x-missing", "x-tag"] "first"`, hit},
		{"missing header is false", `header :contains "x-missing" ""`, miss},
		{"address all ignores display name", `address :all :is "to" "rcpt+tag@example.org"`, hit},
		{"display name with comma", `address :localpart :is "to" "rcpt+tag"`, hit},
		{"encoded display name comma", `address :count "eq" :comparator "i;ascii-numeric" "reply-to" "1"`, hit},
		{"encoded display name address", `address :is "reply-to" "john@example.com"`, hit},
		{"group members", `address :domain :is "to" "friends.test"`, hit},
		{"empty group", `address :contains "cc" "@"`, miss},
		{"address test skips non-address headers", `address :contains "subject" "acme"`, miss},
		{"localpart", `address :localpart :is "from" "alice"`, hit},
		{"domain", `address :domain :is "from" "example.com"`, hit},
		{"user", `address :user :is "to" "rcpt"`, hit},
		{"detail", `address :detail :is "to" "tag"`, hit},
		{"no detail never matches", `address :detail :matches "from" "*"`, miss},
		{"envelope from", `envelope :all :is "from" "sender@example.net"`, hit},
		{"envelope to domain", `envelope :domain :is "to" "example.org"`, hit},
		{"envelope detail", `envelope :detail "to" "tag"`, hit},
		{"exists all", `exists ["from", "x-tag"]`, hit},
		{"exists needs every header", `exists ["from", "x-missing"]`, miss},
		{"size over", `size :over 100`, hit},
		{"size under", `size :under 1K`, hit},
		{"size boundary", `size :over 100K`, miss},
		{"not", `not header :is "x-tag" "absent"`, hit},
		{"allof", `allof (true, header :is "x-tag" "first")`, hit},
		{"allof false", `allof (true, false)`, miss},
		{"anyof", `anyof (false, header :is "x-tag" "first")`, hit},
		{"count headers", `header :count "eq" :comparator "i;ascii-numeric" "received" "2"`, hit},
		{"count addresses", `address :count "ge" :comparator "i;ascii-numeric" ["to", "cc"] "3"`, hit},
		{"count missing is zero", `header :count "eq" :comparator "i;ascii-numeric" "x-missing" "0"`, hit},
		{"numeric value", `header :value "gt" :comparator "i;ascii-numeric" "x-priority" "6"`, hit},
		{"numeric value leading zeros", `header :is :comparator "i;ascii-numeric" "x-priority" "7"`, hit},
		{"numeric non-digit is infinity", `header :value "gt" :comparator "i;ascii-numeric" "x-tag" "99999999999999999999"`, hit},
		{"casemap value ordering", `header :value "lt" "x-tag" "SECOND"`, hit},
		{"value ne", `header :value "ne" "x-tag" "first"`, hit},
	} {
		checkOutcome(t, tc.name, req+`if `+tc.test+` { fileinto "hit"; }`, testMessage(baseMessage), tc.want)
	}
}

func TestEnvelopeNullSenderComparesEmpty(t *testing.T) {
	msg := testMessage(baseMessage)
	msg.EnvelopeFrom = ""
	checkOutcome(t, "null sender", `require ["envelope", "fileinto"]; if envelope :domain :is "from" "" { fileinto "bounces"; }`, msg, fileInto("bounces"))
	msg.EnvelopeFrom = "<>"
	checkOutcome(t, "bracketed null sender", `require ["envelope", "fileinto"]; if envelope :all :is "from" "" { fileinto "bounces"; }`, msg, fileInto("bounces"))
}

func TestEmptySubaddressDetail(t *testing.T) {
	msg := testMessage(baseMessage)
	msg.EnvelopeTo = "rcpt+@example.org"
	checkOutcome(t, "empty detail", `require ["envelope", "subaddress", "fileinto"]; if envelope :detail :is "to" "" { fileinto "plain"; }`, msg, fileInto("plain"))
}

func TestWildcardMatching(t *testing.T) {
	for _, tc := range []struct {
		value, pattern string
		octet, want    bool
		captures       []string
	}{
		{"alice@example.com", "*@example.com", false, true, []string{"alice@example.com", "alice"}},
		{"[acme-users] [fwd] version 1.0", "[*] *", false, true, []string{"[acme-users] [fwd] version 1.0", "acme-users", "[fwd] version 1.0"}},
		{"acme <acme-users@lists.example.com>", "*<*@*", false, true, []string{"acme <acme-users@lists.example.com>", "acme ", "acme-users", "lists.example.com>"}},
		{"abc", "a?c", false, true, []string{"abc", "b"}},
		{"æbc", "?bc", false, true, []string{"æbc", "æ"}},
		{"æbc", "?bc", true, false, nil},
		{"æbc", "??bc", true, true, nil},
		{"ABC", "abc", false, true, nil},
		{"ABC", "abc", true, false, nil},
		{"a*", `a\*`, false, true, nil},
		{"ab", `a\*`, false, false, nil},
		{"a?", `a\?`, false, true, nil},
		{`a\`, `a\\`, false, true, nil},
		{"", "*", false, true, []string{"", ""}},
		{"", "?", false, false, nil},
		{"abc", "***", false, true, nil},
		{"abcabc", "*bc", false, true, []string{"abcabc", "abca"}},
		{"abcabc", "a*c*", false, true, []string{"abcabc", "b", "abc"}},
		{"xay", "*a*a*", false, false, nil},
		{"aXbXc", "a?b?c", false, true, []string{"aXbXc", "X", "X"}},
		{"abc", "a*?", false, true, []string{"abc", "b", "c"}},
		{"ab", "a*??", false, false, nil},
	} {
		ok, captures := Matcher{Match: MatchMatches, Comparator: map[bool]string{true: ComparatorOctet, false: ComparatorASCIICasemap}[tc.octet]}.matchValue(tc.value, tc.pattern)
		if ok != tc.want || tc.captures != nil && !slices.Equal(captures, tc.captures) {
			t.Errorf("match(%q, %q, octet=%v) = %v %q, want %v %q", tc.value, tc.pattern, tc.octet, ok, captures, tc.want, tc.captures)
		}
	}
}

func TestWildcardMatchingIsLinearOnPathologicalPatterns(t *testing.T) {
	value := strings.Repeat("a", 200000)
	pattern := strings.Repeat("*a", 500) + "*b"
	start := time.Now()
	if ok, _ := (Matcher{Match: MatchMatches, Comparator: ComparatorASCIICasemap}).matchValue(value, pattern); ok {
		t.Fatal("pathological pattern matched")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pathological match took %v", elapsed)
	}
}

func TestNumericComparator(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"7", "007", 0}, {"10", "9", 1}, {"9", "10", -1}, {"abc", "999", 1}, {"abc", "x", 0}, {"12abc", "12", 0}, {"", "0", 1},
	} {
		if got := numericCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("numericCompare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestActionsAndImplicitKeep(t *testing.T) {
	const req = `require ["fileinto", "reject", "ereject", "copy", "vacation"]; `
	for _, tc := range []struct {
		name, script string
		want         outcome
	}{
		{"implicit keep", `if false { discard; }`, outcome{kept: true}},
		{"explicit keep", `keep;`, outcome{kept: true}},
		{"fileinto cancels implicit keep", `fileinto "A";`, fileInto("A")},
		{"fileinto copy keeps", `fileinto :copy "A";`, outcome{kept: true, folders: []string{"A"}}},
		{"keep and fileinto", `keep; fileinto "A";`, outcome{kept: true, folders: []string{"A"}}},
		{"duplicate fileinto once", `fileinto "A"; fileinto "A"; fileinto "B";`, fileInto("A", "B")},
		{"discard", `discard;`, outcome{discarded: true}},
		{"discard does not undo keep", `keep; discard;`, outcome{kept: true, discarded: true}},
		{"discard leaves fileinto", `fileinto "A"; discard;`, outcome{folders: []string{"A"}, discarded: true}},
		{"redirect cancels implicit keep", `redirect "a@example.com";`, outcome{redirects: []string{"a@example.com"}}},
		{"redirect copy keeps", `redirect :copy "a@example.com";`, outcome{kept: true, redirects: []string{"a@example.com"}}},
		{"redirect deduplicated", `redirect "A@example.com"; redirect "a@example.com";`, outcome{redirects: []string{"A@example.com"}}},
		{"redirect display form", `redirect "Bob <bob@example.com>";`, outcome{redirects: []string{"bob@example.com"}}},
		{"stop ends processing", `fileinto "A"; stop; fileinto "B";`, fileInto("A")},
		{"stop keeps implicit keep", `stop; discard;`, outcome{kept: true}},
		{"stop inside block", `if true { stop; } discard;`, outcome{kept: true}},
		{"elsif", `if false { fileinto "A"; } elsif true { fileinto "B"; } else { fileinto "C"; }`, fileInto("B")},
		{"else", `if false { fileinto "A"; } elsif false { fileinto "B"; } else { fileinto "C"; }`, fileInto("C")},
		{"reject", `reject "Go away";`, outcome{reject: "Go away"}},
		{"ereject", `ereject "Go away";`, outcome{reject: "Go away"}},
		{"reject does not stop", `reject "no"; if true { discard; }`, outcome{reject: "no", discarded: true}},
		{"reject with fileinto", `reject "no"; fileinto "A";`, outcome{err: true}},
		{"reject with keep", `keep; reject "no";`, outcome{err: true}},
		{"reject with redirect copy", `redirect :copy "a@example.com"; reject "no";`, outcome{err: true}},
		{"two rejects", `reject "a"; ereject "b";`, outcome{err: true}},
		{"vacation keeps implicit keep", `vacation "away";`, outcome{kept: true, vacation: true}},
		{"vacation does not stop", `vacation "away"; fileinto "A";`, outcome{folders: []string{"A"}, vacation: true}},
		{"two vacations", `vacation "a"; vacation "b";`, outcome{err: true}},
		{"vacation with reject", `vacation "a"; reject "b";`, outcome{err: true}},
	} {
		checkOutcome(t, tc.name, req+tc.script, testMessage(baseMessage), tc.want)
	}
}

func TestTooManyRedirectsIsRuntimeError(t *testing.T) {
	var script strings.Builder
	for index := range MaxRedirects + 1 {
		script.WriteString(`redirect "user` + strings.Repeat("x", index) + `@example.com";`)
	}
	if _, err := runScript(t, script.String(), testMessage(baseMessage)); err == nil {
		t.Fatal("redirect limit not enforced")
	}
}

func TestTestListsShortCircuit(t *testing.T) {
	const req = `require ["variables", "fileinto"]; `
	checkOutcome(t, "anyof stops at first true", req+`if anyof (header :matches "x-tag" "f*", header :matches "x-tag" "s*") { fileinto "${1}"; }`, testMessage(baseMessage), fileInto("irst"))
	checkOutcome(t, "allof stops at first false", req+`if allof (header :matches "x-tag" "f*", false, header :matches "x-tag" "s*") { keep; } fileinto "${1}";`, testMessage(baseMessage), fileInto("irst"))
	checkOutcome(t, "failed match keeps variables", req+`if header :matches "x-tag" "f*" {} if header :matches "x-tag" "nomatch*" {} fileinto "${1}";`, testMessage(baseMessage), fileInto("irst"))
}

func TestVariables(t *testing.T) {
	const req = `require ["variables", "fileinto", "encoded-character", "relational", "comparator-i;ascii-numeric"]; `
	for _, tc := range []struct{ name, script, folder string }{
		{"match variables", `if header :matches "list-name" "*<*@*" { fileinto "lists.${2}"; }`, "lists.acme-users"},
		{"whole match", `if header :matches "x-tag" "f?r*" { fileinto "${0}-${1}-${2}-${3}"; }`, "first-i-st-"},
		{"set and expand", `set "box" "Work"; set "box" "${box}/Reports"; fileinto "${BOX}";`, "Work/Reports"},
		{"unknown variable is empty", `fileinto "a${missing}b";`, "ab"},
		{"malformed reference is literal", `fileinto "a${b";`, "a${b"},
		{"modifier precedence", `set :upperfirst :lower "v" "hELLO wORLD"; fileinto "${v}";`, "Hello world"},
		{"length", `set :length "v" "Grüße"; fileinto "${v}";`, "5"},
		{"upper", `set :upper "v" "abc"; fileinto "${v}";`, "ABC"},
		{"lowerfirst", `set :lowerfirst "v" "ABC"; fileinto "${v}";`, "aBC"},
		{"quotewildcard", `set :quotewildcard "v" "a*b?c\\"; if string :matches "a*b?c\\" "${v}" { fileinto "quoted"; }`, "quoted"},
		{"wildcards from variables are active", `set "v" "f*"; if header :matches "x-tag" "${v}" { fileinto "active"; }`, "active"},
		{"string test", `set "a" "x"; if string :is "${a}" "x" { fileinto "string"; }`, "string"},
		{"string count skips empty", `if string :count "eq" :comparator "i;ascii-numeric" ["a", "", "b"] "2" { fileinto "two"; }`, "two"},
		{"expanded header name", `set "h" "X-Tag"; if header :is "${h}" "first" { fileinto "dynamic"; }`, "dynamic"},
		{"encoded hex", `fileinto "${hex: 41 42}";`, "AB"},
		{"encoded unicode", `fileinto "${UNICODE:263a}";`, "☺"},
		{"encoded is not recursive with variables", `set "x" "y"; fileinto "${hex:24 7b 78 7d}";`, "y"},
	} {
		checkOutcome(t, tc.name, req+tc.script, testMessage(baseMessage), fileInto(tc.folder))
	}
}

func TestStringsAreLiteralWithoutExtensions(t *testing.T) {
	checkOutcome(t, "no variables", `require "fileinto"; fileinto "${hex:41}${x}";`, testMessage(baseMessage), fileInto("${hex:41}${x}"))
}

func TestVariableValueIsCapped(t *testing.T) {
	result, err := runScript(t, `require ["variables", "fileinto"]; set "a" "`+strings.Repeat("x", 4000)+`"; set "a" "${a}${a}${a}${a}${a}${a}"; set "a" "${a}${a}${a}${a}${a}${a}"; fileinto "${a}${a}${a}${a}${a}${a}${a}${a}${a}${a}";`, testMessage(baseMessage))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(result.FileIntoFolders[0]); got > maxExpandedLength {
		t.Fatalf("expanded length = %d", got)
	}
}

func TestVacation(t *testing.T) {
	const req = `require ["vacation", "vacation-seconds", "variables"]; `
	addressed := testMessage(baseMessage)
	result := checkOutcome(t, "defaults", req+`vacation "I am away";`, addressed, outcome{kept: true, vacation: true})
	if reply := result.VacationReply; reply.To != "sender@example.net" || reply.From != "rcpt+tag@example.org" || reply.Subject != "Auto: Grüße [acme-users] report" ||
		reply.Body != "I am away" || reply.Period != 7*24*time.Hour || reply.MessageID != "<original@example.com>" || reply.References != "<original@example.com>" || reply.Handle == "" {
		t.Fatalf("vacation = %+v", reply)
	}

	result = checkOutcome(t, "arguments", req+`set "who" "Alice"; vacation :days 2 :subject "Away ${who}" :from "Me <me@example.org>" :handle "h1" "Back soon";`, addressed, outcome{kept: true, vacation: true})
	if reply := result.VacationReply; reply.Subject != "Away Alice" || reply.From != "Me <me@example.org>" || reply.Period != 48*time.Hour || reply.Handle != "h1" || reply.TrackingKey() != "sieve:h1:sender@example.net" {
		t.Fatalf("vacation = %+v", reply)
	}
	result = checkOutcome(t, "seconds zero", req+`vacation :seconds 0 "x";`, addressed, outcome{kept: true, vacation: true})
	if result.VacationReply.Period != 0 {
		t.Fatalf("period = %v", result.VacationReply.Period)
	}
	result = checkOutcome(t, "days clamp", req+`vacation :days 0 "x";`, addressed, outcome{kept: true, vacation: true})
	if result.VacationReply.Period != 24*time.Hour {
		t.Fatalf("period = %v", result.VacationReply.Period)
	}
	first, _ := runScript(t, req+`vacation "one";`, testMessage(baseMessage))
	second, _ := runScript(t, req+`vacation "two";`, testMessage(baseMessage))
	if first.VacationReply.Handle == second.VacationReply.Handle {
		t.Fatal("different reasons share a default handle")
	}

	notAddressed := testMessage(strings.Replace(baseMessage, "rcpt+tag@example.org", "other@example.org", 1))
	checkOutcome(t, "not addressed to user", req+`vacation "x";`, notAddressed, outcome{kept: true})
	checkOutcome(t, "additional address", req+`vacation :addresses ["Other <other@example.org>"] "x";`, notAddressed, outcome{kept: true, vacation: true})
	subaddressed := testMessage(baseMessage)
	subaddressed.EnvelopeTo = "rcpt@example.org"
	checkOutcome(t, "subaddressed recipient header", req+`vacation "x";`, subaddressed, outcome{kept: true, vacation: true})

	for _, tc := range []struct{ name, header, sender string }{
		{"auto-submitted", "Auto-Submitted: auto-replied\n", ""},
		{"precedence", "Precedence: bulk\n", ""},
		{"list", "List-Id: <x.example.com>\n", ""},
		{"null sender", "", "<>"},
		{"mailer-daemon", "", "MAILER-DAEMON@example.net"},
		{"owner", "", "owner-list@example.net"},
		{"request", "", "list-request@example.net"},
		{"own address", "", "rcpt@example.org"},
	} {
		msg := testMessage(tc.header + baseMessage)
		if tc.sender != "" {
			msg.EnvelopeFrom = tc.sender
		}
		checkOutcome(t, "suppressed "+tc.name, req+`vacation "x";`, msg, outcome{kept: true})
	}
	auto := testMessage("Auto-Submitted: no\n" + baseMessage)
	checkOutcome(t, "auto-submitted no", req+`vacation "x";`, auto, outcome{kept: true, vacation: true})
}

func TestVacationContentHeaders(t *testing.T) {
	plain := &VacationResult{Body: "Grüße"}
	headers, body := plain.ContentHeaders()
	if headers["Content-Type"] != "text/plain; charset=utf-8" || string(body) != "Grüße" {
		t.Fatalf("plain = %v %q", headers, body)
	}
	mimeReply := &VacationResult{Mime: true, Body: "Content-Type: text/html; charset=utf-8\r\nX-Other: dropped\r\n\r\n<p>Away</p>"}
	headers, body = mimeReply.ContentHeaders()
	if headers["Content-Type"] != "text/html; charset=utf-8" || headers["X-Other"] != "" || string(body) != "<p>Away</p>" {
		t.Fatalf("mime = %v %q", headers, body)
	}
}

func TestRunIsRepeatable(t *testing.T) {
	script, err := Parse(`require "fileinto"; fileinto "A";`)
	if err != nil {
		t.Fatal(err)
	}
	interpreter := NewInterpreter(testMessage(baseMessage))
	for range 2 {
		result, err := interpreter.Run(script)
		if err != nil || !slices.Equal(result.FileIntoFolders, []string{"A"}) {
			t.Fatalf("result = %+v, %v", result, err)
		}
	}
}

func TestNotify(t *testing.T) {
	const req = `require ["enotify", "variables", "fileinto"]; `
	result, err := runScript(t, req+`notify :importance "1" :from "Me <me@example.org>" :message "New: ${subject}" "mailto:a@example.com,b@example.com?cc=c@example.com&subject=Alert%20now&x-other=ignored";`+
		`notify "mailto:a@example.com,b@example.com?cc=c@example.com&subject=Alert%20now&x-other=ignored";`, testMessage(baseMessage))
	if err != nil || len(result.NotifyRequests) != 1 || !result.Kept {
		t.Fatalf("result = %+v, %v", result, err)
	}
	if n := result.NotifyRequests[0]; !slices.Equal(n.To, []string{"a@example.com", "b@example.com", "c@example.com"}) || n.Subject != "Alert now" ||
		n.Message != "New: " || n.From != "Me <me@example.org>" || n.Importance != "1" {
		t.Fatalf("notification = %+v", n)
	}
	result, err = runScript(t, req+`notify "mailto:a@example.com";`, testMessage(baseMessage))
	if err != nil || len(result.NotifyRequests) != 1 || result.NotifyRequests[0].Importance != "2" || !strings.HasPrefix(result.NotifyRequests[0].Subject, `New mail from "Alice Example"`) {
		t.Fatalf("default notification = %+v, %v", result, err)
	}
	result, err = runScript(t, req+`notify "mailto:a@example.com";`, testMessage("Auto-Submitted: auto-notified\n"+baseMessage))
	if err != nil || len(result.NotifyRequests) != 0 {
		t.Fatalf("notification about an automated message = %+v, %v", result, err)
	}
	if _, err := runScript(t, req+`set "m" "mailto:"; notify "${m}";`, testMessage(baseMessage)); err == nil {
		t.Fatal("notify without recipients ran")
	}
	if _, err := runScript(t, req+`notify "mailto:`+strings.Repeat("x@example.com,", maxNotifyRecipients+1)+`";`, testMessage(baseMessage)); err == nil {
		t.Fatal("notification recipient limit not enforced")
	}
	for _, tc := range []struct{ name, test string }{
		{"valid method", `valid_notify_method ["mailto:a@example.com", "MAILTO:b@example.com?subject=x"]`},
		{"invalid method", `not valid_notify_method ["mailto:a@example.com", "xmpp:a@example.com"]`},
		{"capability", `notify_method_capability "mailto:a@example.com" "Online" "maybe"`},
		{"unknown capability", `not notify_method_capability "mailto:a@example.com" "other" "maybe"`},
		{"encodeurl", `allof (string :is "${encoded}" "a%20b%26c%3D%C3%A6", true)`},
	} {
		checkOutcome(t, tc.name, req+`set :encodeurl "encoded" "a b&c=æ"; if `+tc.test+` { fileinto "hit"; }`, testMessage(baseMessage), fileInto("hit"))
	}
}

func TestParseNotify(t *testing.T) {
	for _, script := range []string{
		`require "enotify"; notify :options ["x"] :message "m" "mailto:a@example.com";`,
		`require ["enotify", "variables"]; set :encodeurl :lower "a" "B"; notify "mailto:${a}@example.com";`,
	} {
		if _, err := Parse(script); err != nil {
			t.Errorf("Parse(%q): %v", script, err)
		}
	}
	for _, tc := range []struct{ script, want string }{
		{`notify "mailto:a@example.com";`, `"enotify" extension`},
		{`require "enotify"; notify "xmpp:a@example.com";`, "invalid notification method"},
		{`require "enotify"; notify :importance "4" "mailto:a@example.com";`, "invalid :importance"},
		{`require "enotify"; notify :from "bad" "mailto:a@example.com";`, "invalid :from"},
		{`require "variables"; set :encodeurl "a" "b";`, `"enotify" extension`},
		{`if valid_notify_method "mailto:a@example.com" { keep; }`, `"enotify" extension`},
	} {
		if _, err := Parse(tc.script); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) error = %v, want %q", tc.script, err, tc.want)
		}
	}
}

func TestMailboxExtension(t *testing.T) {
	for _, script := range []string{
		`fileinto :create "A";`,
		`require "fileinto"; fileinto :create "A";`,
		`require "fileinto"; if mailboxexists "A" { keep; }`,
		`require ["fileinto", "mailbox"]; redirect :create "a@example.com";`,
		`require ["fileinto", "mailbox"]; fileinto :create :create "A";`,
	} {
		if _, err := Parse(script); err == nil {
			t.Errorf("Parse(%q) accepted", script)
		}
	}

	existing := map[string]bool{"INBOX": true, "Lists/Acme": true}
	msg := testMessage(baseMessage)
	msg.MailboxExists = func(name string) bool { return existing[name] }
	result, err := runScript(t, `require ["fileinto", "mailbox", "copy"];
if mailboxexists ["INBOX", "Lists/Acme"] { fileinto :create :copy "Lists/Acme"; }
if mailboxexists ["INBOX", "Missing"] { fileinto "Wrong"; }
if not mailboxexists "Missing" { fileinto :create "Projects/2026/Q4"; }
fileinto "Plain";`, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.FileIntoFolders, []string{"Lists/Acme", "Projects/2026/Q4", "Plain"}) || !slices.Equal(result.CreateFolders, []string{"Lists/Acme", "Projects/2026/Q4"}) || result.Kept {
		t.Fatalf("result = %+v", result)
	}

	// Without a lookup every mailbox counts as missing.
	result, err = runScript(t, `require ["fileinto", "mailbox"]; if mailboxexists "INBOX" { discard; }`, testMessage(baseMessage))
	if err != nil || result.Discarded {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
