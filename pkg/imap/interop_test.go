package imap

import (
	"strings"
	"testing"
)

func TestThunderbirdStyleMailboxTranscript(t *testing.T) {
	client := authenticatedTestClient(t)
	message := []byte("Date: Tue, 18 Aug 2026 12:00:00 +0200\r\nFrom: sender@example.com\r\nTo: alice@example.com\r\nSubject: Thunderbird transcript\r\nMessage-ID: <tb@example.com>\r\n\r\nBody\r\n")
	if _, code, text := client.appendMsg("A002", "INBOX", nil, "", message); code != "OK" {
		t.Fatalf("APPEND: code=%s text=%s", code, text)
	}
	commands := []string{
		`ID ("name" "Thunderbird" "version" "128")`,
		"NAMESPACE",
		`LIST "" "%"`,
		`LIST (SPECIAL-USE) "" "*" RETURN (SPECIAL-USE CHILDREN)`,
		"SELECT INBOX",
		"UID FETCH 1:* (UID FLAGS RFC822.SIZE ENVELOPE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID REFERENCES)])",
	}
	for index, command := range commands {
		tag := string(rune('B'+index)) + "001"
		if _, code, text := client.send(tag, command); code != "OK" {
			t.Fatalf("%s: code=%s text=%s", command, code, text)
		}
	}
	client.sendNoTag("Z001 IDLE")
	continuation, err := client.readLine()
	if err != nil || !strings.HasPrefix(continuation, "+") {
		t.Fatalf("IDLE continuation = %q err=%v", continuation, err)
	}
	client.sendNoTag("DONE")
	if _, code, text := client.readResponse(); code != "OK" {
		t.Fatalf("IDLE DONE: code=%s text=%s", code, text)
	}
}

func TestRoundcubeStyleMailboxTranscript(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, code, text := client.appendMsg("A002", "INBOX", nil, "", []byte("From: sender@example.com\r\nSubject: Roundcube transcript\r\n\r\nBody\r\n")); code != "OK" {
		t.Fatalf("APPEND: code=%s text=%s", code, text)
	}
	commands := []string{
		`LIST "" "*"`,
		`LSUB "" "*"`,
		"STATUS INBOX (MESSAGES UNSEEN UIDNEXT UIDVALIDITY SIZE)",
		"SELECT INBOX",
		"UID SEARCH RETURN (ALL) UNDELETED",
		"UID SORT (ARRIVAL) UTF-8 ALL",
		"UID FETCH 1:* (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM TO SUBJECT MESSAGE-ID)])",
	}
	for index, command := range commands {
		tag := string(rune('B'+index)) + "101"
		if _, code, text := client.send(tag, command); code != "OK" {
			t.Fatalf("%s: code=%s text=%s", command, code, text)
		}
	}
}
