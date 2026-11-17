package imap

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

const fuzzMessage = "From: \"=?UTF-8?B?SsO4cmdlbg==?=\" <jorgen@example.com>\r\n" +
	"To: a@example.com, B <b@example.org>\r\n" +
	"Subject: =?ISO-8859-1?Q?caf=E9?= report\r\n" +
	"Date: Mon, 01 Jan 2024 10:00:00 +0000\r\n" +
	"Message-Id: <1@example.com>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"outer\"\r\n" +
	"\r\n" +
	"--outer\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n" +
	"\r\n" +
	"hello =C3=A6=\r\n world\r\n" +
	"--outer\r\n" +
	"Content-Type: multipart/alternative; boundary=inner\r\n" +
	"\r\n" +
	"--inner\r\n" +
	"Content-Type: text/html\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"PGI+aGk8L2I+\r\n" +
	"--inner--\r\n" +
	"--outer\r\n" +
	"Content-Type: message/rfc822\r\n" +
	"\r\n" +
	"Subject: inner\r\n\r\nbody\r\n" +
	"--outer--\r\n"

// FuzzIMAPCommand feeds client command lines into the command splitter and
// both argument tokenizers.
func FuzzIMAPCommand(f *testing.F) {
	for _, seed := range []string{
		"A001 SELECT INBOX",
		"A002 LOGIN user@example.com password",
		"A003 SEARCH FROM john SINCE 01-Jan-2024",
		"A003 UID SEARCH (OR FROM \"a b\" TO \"c\\\"d\") NOT SEEN",
		"A004 CAPABILITY",
		"A006 LIST \"\" \"%\"",
		"A007 FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (From To)])",
		"A008 UID SORT (REVERSE DATE) UTF-8 ALL",
		"A009 STORE 1 +FLAGS (\\Seen)",
		"A010 APPEND INBOX (\\Seen) \"01-Jan-2024 10:00:00 +0000\" {25}",
		"A011 NOTIFY SET (SELECTED (MessageNew (UID) MessageExpunge))",
		"A012 ID (\"name\" \"client\")",
		"A013 UID   ",
		"TAG NOOP",
		"X",
		"",
		"\x00\xff\xfe",
		"A \"unterminated",
		"A LIST \"a\\",
		strings.Repeat("A", 10000),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		s := &Session{}
		_, _, args, err := s.parseCommand(input)
		if err == nil {
			for _, arg := range args {
				if strings.ContainsAny(arg, "\r\n\x00") {
					t.Fatalf("argument %q carries a line break or NUL", arg)
				}
			}
		}
		if tokens, err := tokenizeCommandArgs(input); err == nil && len(tokens) > len(input) {
			t.Fatalf("%d tokens from %d bytes", len(tokens), len(input))
		}
		if tokens, err := tokenizeSearchCommandArgs(input); err == nil && len(tokens) > len(input) {
			t.Fatalf("%d search tokens from %d bytes", len(tokens), len(input))
		}
		_ = stripQuotes(input)
		_ = parseFlagsArg(input)
		_, _ = parseIMAPDateTime(input)
		_, _, _ = parseLiteralSize(input)
	})
}

// FuzzSearchCriteria tokenizes a SEARCH argument string the way the session
// does, parses it, and evaluates the result against a fixed message.
func FuzzSearchCriteria(f *testing.F) {
	for _, seed := range []string{
		"ALL",
		"FROM john",
		"SUBJECT hello SEEN",
		"SINCE 01-Jan-2024 BEFORE 31-Dec-2024",
		"UID 1:100,200:*",
		"LARGER 1024 SMALLER 4096",
		"HEADER From user@example.com",
		"TEXT \"search term\" BODY \"body text\"",
		"OR FROM a TO b",
		"AND FROM a SEEN",
		"NOT DELETED",
		"(FLAGGED ANSWERED) (OR UNSEEN DRAFT)",
		"SENTON 15-Mar-2024 SENTSINCE 01-Jan-2024 SENTBEFORE 31-Dec-2024 ON 15-Mar-2024",
		"BODY [HEADER.FIELDS (from to subject)] x",
		"RETURN (MIN MAX COUNT SAVE) CHARSET UTF-8 $",
		"",
		"UNKNOWN",
		"FROM",
		"OR",
		"NOT",
		"(",
		"((ALL)",
		strings.Repeat("NOT ", 200) + "ALL",
		strings.Repeat("(", 200) + "ALL" + strings.Repeat(")", 200),
		"\x00\xff",
	} {
		f.Add(seed)
	}
	item := model.Item{
		UID:          7,
		Size:         int64(len(fuzzMessage)),
		Data:         []byte(fuzzMessage),
		Flags:        []string{model.FlagSeen},
		InternalDate: time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC),
	}

	f.Fuzz(func(t *testing.T, input string) {
		tokens, err := tokenizeSearchCommandArgs(input)
		if err != nil {
			return
		}
		_, _, _, _ = parseSearchCommand(tokens)
		_, _, _ = parseSortCriteria(tokens)
		criteria, err := parseSearchCriteria(tokens)
		if err != nil {
			return
		}
		_ = matchSearchCriteria(item, criteria)
		_ = searchNeedsContent(criteria, false)
		_ = indexedCandidateFilter(criteria)
	})
}

// FuzzMessageSet checks that sequence and UID sets resolve to ascending,
// distinct, existing message numbers without expanding huge ranges.
func FuzzMessageSet(f *testing.F) {
	for _, seed := range []string{
		"1", "1:*", "*", "*:1", "2,4:7,9,12:*", "1:4294967295", "4294967295:1",
		"1,1,1", "3:2,2:3", "", ",", "1:", ":1", "0", "1:2:3", "-1", "a",
	} {
		f.Add(seed, uint16(10), false)
		f.Add(seed, uint16(0), true)
	}

	f.Fuzz(func(t *testing.T, set string, size uint16, sparse bool) {
		maximum := int(size)
		var existing []int
		if sparse {
			// UIDs spread across the whole 32-bit space.
			for index := range int(size % 64) {
				existing = append(existing, 1+index*67108863)
			}
			if len(existing) > 0 {
				maximum = existing[len(existing)-1]
			} else {
				maximum = 0
			}
		}
		result, err := resolveMessageSet(set, maximum, existing)
		if err != nil {
			return
		}
		if !slices.IsSorted(result) || len(slices.Compact(slices.Clone(result))) != len(result) {
			t.Fatalf("set %q resolved to unordered or duplicate members %v", set, result)
		}
		for _, value := range result {
			if sparse && !slices.Contains(existing, value) {
				t.Fatalf("set %q resolved to missing UID %d", set, value)
			}
			if !sparse && (value < 1 || value > maximum) {
				t.Fatalf("set %q resolved to out-of-range sequence %d", set, value)
			}
		}
	})
}

// FuzzFetchItems feeds FETCH attribute strings through the attribute
// tokenizer and the BODY[] and BINARY[] item parsers.
func FuzzFetchItems(f *testing.F) {
	for _, seed := range []string{
		"(FLAGS UID BODY.PEEK[HEADER.FIELDS (From To)] BODY[1.2.MIME]<0.100>)",
		"BINARY.PEEK[1]<10.20> BINARY.SIZE[2]",
		"BODYSTRUCTURE ENVELOPE RFC822.SIZE INTERNALDATE",
		"(CHANGEDSINCE 12345) IFMODSEQ 5",
		"BODY[", "BODY[]<", "BODY[]<1.>", "BODY[]<-1.5>", "BINARY.SIZE[1]<0.1>",
		"))((", "[[]]", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		for _, token := range tokenizeFetchAttrs(input) {
			if request, ok, err := parseBodyFetch(token); ok && err == nil && request.partial {
				if request.partialFrom < 0 || request.partialSize < 1 {
					t.Fatalf("BODY partial %+v accepted from %q", request, token)
				}
			}
			_, _, _ = parseBinaryFetch(token)
			_ = fetchItemNeedsContent(token)
		}
		_, _ = extractIfModSeq(input)
		if _, modifiers := splitFetchModifiers(input); modifiers != "" {
			_, _ = parseFetchModifiers(modifiers)
		}
		_ = fetchSetsSeen(input)
		_ = parseBodyHeaderFields(input)
	})
}

// FuzzMIMEMessage renders FETCH metadata and body sections of an arbitrary
// stored message.
func FuzzMIMEMessage(f *testing.F) {
	for _, seed := range []struct{ message, section string }{
		{fuzzMessage, ""},
		{fuzzMessage, "1"},
		{fuzzMessage, "2.1"},
		{fuzzMessage, "3.HEADER"},
		{fuzzMessage, "1.MIME"},
		{fuzzMessage, "HEADER.FIELDS (SUBJECT FROM)"},
		{fuzzMessage, "HEADER.FIELDS.NOT (SUBJECT)"},
		{fuzzMessage, "TEXT"},
		{"Subject: x\n\nbody", "1"},
		{"Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a--\r\n", "1.1.1"},
		{"", ""},
		{"\r\n\r\n", "HEADER"},
		{"From: =?UTF-8?Q?=FF?= <@>\r\n\r\n", "0"},
	} {
		f.Add(seed.message, seed.section)
	}
	f.Fuzz(func(t *testing.T, message, section string) {
		data := []byte(message)
		item := model.Item{Data: data, Size: int64(len(data))}
		_ = envelope(item)
		_ = bodyStructure(item, true)
		_, _ = bodySection(data, section)
		_, _ = binarySection(data, section)
		_ = decodedMessageHeaders(data)
		_ = extractHeaderFromData(data, section)
		_ = headersStored(item)
	})
}

// FuzzModifiedUTF7 checks that the mailbox name codec only accepts canonical
// input and round-trips everything it encodes.
func FuzzModifiedUTF7(f *testing.F) {
	for _, seed := range []string{"INBOX", "&-", "Entw&APw-rfe", "&ZeVnLIqe-", "~peter/mail/&U,BTFw-/&ZeVnLIqe-", "&", "&AGE-", "&2D3eAA-", "\xff", "a\x00b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if decoded, err := decodeModifiedUTF7(input); err == nil {
			encoded, err := encodeModifiedUTF7(decoded)
			if err != nil || encoded != input {
				t.Fatalf("decoded %q to %q, which encodes to %q (%v)", input, decoded, encoded, err)
			}
		}
		if encoded, err := encodeModifiedUTF7(input); err == nil {
			decoded, err := decodeModifiedUTF7(encoded)
			if err != nil || decoded != input {
				t.Fatalf("encoded %q to %q, which decodes to %q (%v)", input, encoded, decoded, err)
			}
		}
	})
}

// FuzzNotify feeds NOTIFY command text into its s-expression parser.
func FuzzNotify(f *testing.F) {
	for _, seed := range []string{
		"NONE",
		"SET (SELECTED (MessageNew (UID BODY.PEEK[HEADER.FIELDS (From)]) MessageExpunge FlagChange))",
		"SET STATUS (PERSONAL (MailboxName SubscriptionChange)) (MAILBOXES (\"a b\" INBOX) NONE)",
		"SET (SUBTREE \"x\\\"y\" (MessageNew))",
		"SET (", "SET )", "SET \"", strings.Repeat("(", 1000), "",
	} {
		f.Add(seed)
	}
	wire := func(value string) (string, error) { return value, nil }
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = parseNotify(input, wire)
	})
}

// FuzzCommandArguments feeds tokenized arguments into the LIST, APPEND and
// QRESYNC argument parsers.
func FuzzCommandArguments(f *testing.F) {
	for _, seed := range []string{
		"\"\" \"%\"",
		"(SUBSCRIBED RECURSIVEMATCH) \"\" (\"INBOX\" \"Lists/*\") RETURN (CHILDREN STATUS (MESSAGES UNSEEN))",
		"INBOX (\\Seen \\Draft) \"01-Jan-2024 10:00:00 +0000\" {25+}",
		"INBOX {0}",
		"(QRESYNC (77 42 1:100 (1,50,100 1,50,100)))",
		"(CONDSTORE QRESYNC (4294967295 9223372036854775807 1:4294967295))",
		"((((", "))", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		tokens, err := tokenizeCommandArgs(input)
		if err != nil {
			return
		}
		_, _ = parseListRequest(tokens)
		_, _, _, _ = parseAppendDescriptor(tokens)
		_, _ = parseQResyncSelectOptions(tokens)
		_, _ = parseQResyncSelectOptions([]string{input})
	})
}
