package imap

import (
	"fmt"
	"strings"
	"testing"

	imapv2 "github.com/emersion/go-imap/v2"
)

func TestTokenizeSearchCommandArgsPreservesGroupsAndQuotedParentheses(t *testing.T) {
	got, err := tokenizeSearchCommandArgs(`OR (SUBJECT "quarterly report (final)") (NOT FROM "alice@example.com")`)
	if err != nil {
		t.Fatalf("tokenizeSearchCommandArgs: %v", err)
	}
	want := []string{"OR", "(", "SUBJECT", "quarterly report (final)", ")", "(", "NOT", "FROM", "alice@example.com", ")"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
	for _, input := range []string{`SUBJECT "unterminated`, `SUBJECT "bad\q"`, `SUBJECT atom"quote`} {
		if _, err := tokenizeSearchCommandArgs(input); err == nil {
			t.Errorf("tokenizeSearchCommandArgs(%q) succeeded, want error", input)
		}
	}
}

func TestIntegration_SearchGroupedBooleanCriteria(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")
	mustAppend(t, client, "INBOX", "From: alice@example.com\r\nSubject: Quarterly report (final)\r\n\r\nFirst\r\n")
	mustAppend(t, client, "INBOX", "From: bob@example.com\r\nSubject: Routine note\r\n\r\nSecond\r\n")
	mustAppend(t, client, "INBOX", "From: alice@example.com\r\nSubject: Routine note\r\n\r\nThird\r\n")
	mustSelect(t, client, "INBOX")

	criteria := &imapv2.SearchCriteria{Or: [][2]imapv2.SearchCriteria{{
		{Header: []imapv2.SearchCriteriaHeaderField{{Key: "Subject", Value: "Quarterly report (final)"}}},
		{Not: []imapv2.SearchCriteria{{Header: []imapv2.SearchCriteriaHeaderField{{Key: "From", Value: "alice@example.com"}}}}},
	}}}
	result, err := client.Search(criteria, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH grouped criteria: %v", err)
	}
	got := result.AllSeqNums()
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("SEARCH results = %v, want [1 2]", got)
	}
}

func TestIntegration_SearchDecodesMIMEAndNormalizesUnicode(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")
	message := strings.Join([]string{
		"From: =?UTF-8?Q?J=C3=B8rgen?= <sender@example.com>",
		"Subject: =?UTF-8?Q?Cafe=CC=81_status?=",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=iso-8859-1",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"M=F8de i morgen",
		"",
	}, "\r\n")
	headers := decodedMessageHeaders([]byte(message))
	if got := decodedHeaderValue(headers.Get("Subject")); got != "Café status" {
		t.Fatalf("decoded Subject = %q", got)
	}
	if got := canonicalSearchText(decodedHeaderValue(headers.Get("Subject"))); !strings.Contains(got, canonicalSearchText("Café")) {
		t.Fatalf("normalized Subject = %q", got)
	}
	mustAppend(t, client, "INBOX", message)
	mustSelect(t, client, "INBOX")

	checks := []struct {
		name     string
		criteria *imapv2.SearchCriteria
	}{
		{"subject NFC", &imapv2.SearchCriteria{Header: []imapv2.SearchCriteriaHeaderField{{Key: "Subject", Value: "Café"}}}},
		{"decoded from", &imapv2.SearchCriteria{Header: []imapv2.SearchCriteriaHeaderField{{Key: "From", Value: "jørgen"}}}},
		{"decoded body charset", &imapv2.SearchCriteria{Body: []string{"møde"}}},
		{"decoded text", &imapv2.SearchCriteria{Text: []string{"Café status"}}},
	}
	for _, check := range checks {
		result, err := client.Search(check.criteria, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH %s: %v", check.name, err)
		}
		if got := result.AllSeqNums(); len(got) != 1 || got[0] != 1 {
			t.Errorf("SEARCH %s = %v, want [1]", check.name, got)
		}
	}
}

func TestSearchRejectsMalformedGroupsAndMissingArguments(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, code, text := client.send("A002", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	for index, command := range []string{
		"SEARCH (OR ALL ALL",
		"SEARCH ()",
		"SEARCH SUBJECT",
		"SEARCH HEADER Subject",
		"SEARCH OR ALL",
	} {
		_, code, _ := client.send("B00"+string(rune('1'+index)), command)
		if code != "BAD" {
			t.Errorf("%s: code=%s, want BAD", command, code)
		}
	}
	for index, literalTest := range []struct {
		prefix  string
		literal []byte
	}{
		{"SEARCH SUBJECT", []byte{0xff}},
		{"SEARCH CHARSET US-ASCII SUBJECT", []byte("ø")},
	} {
		tag := fmt.Sprintf("C%03d", index+1)
		if _, err := fmt.Fprintf(client.Conn, "%s %s {%d}\r\n", tag, literalTest.prefix, len(literalTest.literal)); err != nil {
			t.Fatal(err)
		}
		continuation, err := client.r.ReadString('\n')
		if err != nil || !strings.HasPrefix(continuation, "+") {
			t.Fatalf("literal continuation = %q err=%v", continuation, err)
		}
		if _, err := client.Write(append(literalTest.literal, '\r', '\n')); err != nil {
			t.Fatal(err)
		}
		_, code, _ := client.readResponse()
		if code != "BAD" {
			t.Errorf("%s literal %x: code=%s, want BAD", literalTest.prefix, literalTest.literal, code)
		}
	}
}
