package imap

import (
	"fmt"
	"strings"
	"testing"
)

func TestCommandsRejectSurplusAndIncompleteArguments(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, code, text := client.send("A002", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	commands := []string{
		"NOOP extra",
		"LOGOUT extra",
		"LOGIN alice secret extra",
		"CHECK extra",
		"EXPUNGE extra",
		"CLOSE extra",
		"UNSELECT extra",
		"CREATE One extra",
		"DELETE One extra",
		"RENAME One Two extra",
		"SUBSCRIBE One extra",
		"UNSUBSCRIBE One extra",
		"LSUB \"\" * extra",
		"COPY 1 Archive extra",
		"UID COPY 1 Archive extra",
		"UID EXPUNGE 1 extra",
		"MOVE 1",
		"MOVE 1 Archive extra",
		"UID MOVE 1",
		"UID MOVE 1 Archive extra",
		"COMPRESS DEFLATE extra",
	}
	for index, command := range commands {
		tag := fmt.Sprintf("B%03d", index+1)
		if _, code, _ := client.send(tag, command); code != "BAD" {
			t.Errorf("%s: code=%s, want BAD", command, code)
		}
	}
}

func TestStartTLSRejectsArgumentsBeforeAvailabilityCheck(t *testing.T) {
	client := makeTestServer(t, &Config{ServerName: "test.veksel"})
	if _, code, text := client.send("A001", "STARTTLS extra"); code != "BAD" {
		t.Fatalf("STARTTLS extra: code=%s text=%s", code, text)
	}
}

func TestFetchSyntaxUsesBADAndOperationalDecodeFailureUsesNO(t *testing.T) {
	client := authenticatedTestClient(t)
	message := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: x-unknown\r\n\r\nBody\r\n")
	if _, code, text := client.appendMsg("A002", "INBOX", nil, "", message); code != "OK" {
		t.Fatalf("APPEND: code=%s text=%s", code, text)
	}
	if _, code, text := client.send("A003", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	for index, command := range []string{"FETCH 1 ()", "FETCH 1 BOGUS", "FETCH 1 BODY[TEXT", "UID FETCH 1 BINARY.SIZE[]<0.1>"} {
		if _, code, text := client.send(fmt.Sprintf("B%03d", index), command); code != "BAD" {
			t.Errorf("%s: code=%s text=%s, want BAD", command, code, text)
		}
	}
	if _, code, text := client.send("B100", "FETCH 1 BINARY[]"); code != "NO" || !strings.Contains(text, "UNKNOWN-CTE") {
		t.Fatalf("unknown transfer encoding: code=%s text=%s", code, text)
	}
}
