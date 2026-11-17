package imap

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseListRequest(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want listRequest
	}{
		{
			name: "basic",
			args: []string{"", "*"},
			want: listRequest{Reference: "", Patterns: []string{"*"}, Select: map[string]bool{}, Return: map[string]bool{}},
		},
		{
			name: "extended with status",
			args: []string{"(SUBSCRIBED", "RECURSIVEMATCH)", "", "(*)", "RETURN", "(CHILDREN", "SPECIAL-USE", "STATUS", "(MESSAGES", "UIDNEXT", "SIZE))"},
			want: listRequest{
				Reference: "", Patterns: []string{"*"}, ExtendedSyntax: true,
				Select:       map[string]bool{"SUBSCRIBED": true, "RECURSIVEMATCH": true},
				Return:       map[string]bool{"CHILDREN": true, "SPECIAL-USE": true, "STATUS": true},
				ReturnStatus: []string{"MESSAGES", "UIDNEXT", "SIZE"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseListRequest(test.args)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("request = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestExtendedListReturnsSpecialUseChildrenAndStatus(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, err := fmt.Fprint(client.Conn, "A002 LIST (SPECIAL-USE) \"\" \"*\" RETURN (CHILDREN SPECIAL-USE STATUS (MESSAGES UIDNEXT SIZE))\r\n"); err != nil {
		t.Fatal(err)
	}
	lines := client.readUntagged()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `\Archive) "/" "Archive" (STATUS (MESSAGES 0 UIDNEXT 1 SIZE 0))`) {
		t.Fatalf("extended LIST missing Archive status and special use:\n%s", joined)
	}
	if !strings.Contains(joined, `\Inbox) "/" "INBOX" (STATUS (MESSAGES 0 UIDNEXT 1 SIZE 0))`) {
		t.Fatalf("extended LIST missing INBOX status and special use:\n%s", joined)
	}
}

func TestExtendedListAcceptsMultipleMailboxPatterns(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, err := fmt.Fprint(client.Conn, "A002 LIST \"\" (\"INBOX\" \"Archive\")\r\n"); err != nil {
		t.Fatal(err)
	}
	lines := client.readUntagged()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `"INBOX"`) || !strings.Contains(joined, `"Archive"`) {
		t.Fatalf("multiple-pattern LIST response:\n%s", joined)
	}
	if strings.Contains(joined, `"Sent"`) {
		t.Fatalf("multiple-pattern LIST returned unmatched Sent mailbox:\n%s", joined)
	}
}

func TestParseListRequestRejectsInvalidOptions(t *testing.T) {
	for _, args := range [][]string{
		{"(RECURSIVEMATCH)", "", "*"},
		{"(UNKNOWN)", "", "*"},
		{"", "*", "RETURN", "(STATUS", "(NOPE))"},
		{"", "*", "RETURN", "(STATUS)"},
	} {
		if _, err := parseListRequest(args); err == nil {
			t.Fatalf("parse %#v succeeded", args)
		}
	}
}

func TestListWildcardMatchingHonorsHierarchyDelimiter(t *testing.T) {
	for _, test := range []struct {
		name, pattern string
		want          bool
	}{
		{"INBOX", "%", true},
		{"Archive/2026", "%", false},
		{"Archive/2026", "Archive/%", true},
		{"Archive/2026/August", "Archive/%", false},
		{"Archive/2026/August", "Archive/*", true},
		{"Projects/Alpha/Done", "Projects/%/Done", true},
		{"Projects/Alpha/Nested/Done", "Projects/%/Done", false},
		{"A+B[1]", "A+B[1]", true},
		{"日本語/受信", "日本語/%", true},
	} {
		if got := matchPattern(test.name, test.pattern); got != test.want {
			t.Errorf("matchPattern(%q, %q) = %t, want %t", test.name, test.pattern, got, test.want)
		}
	}
}

func TestRecursiveSubscribedListReturnsChildInfo(t *testing.T) {
	client := authenticatedTestClient(t)
	for index, command := range []string{"CREATE Parent", "CREATE Parent/Child", "UNSUBSCRIBE Parent", "SUBSCRIBE Parent/Child"} {
		tag := fmt.Sprintf("A%03d", index+2)
		if _, code, text := client.send(tag, command); code != "OK" {
			t.Fatalf("%s: code=%s text=%s", command, code, text)
		}
	}
	if _, err := fmt.Fprint(client.Conn, "A006 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" \"*\" RETURN (CHILDREN)\r\n"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(client.readUntagged(), "\n")
	if !strings.Contains(joined, `"Parent" ("CHILDINFO" ("SUBSCRIBED"))`) {
		t.Fatalf("recursive parent lacks CHILDINFO:\n%s", joined)
	}
	if !strings.Contains(joined, `\Subscribed) "/" "Parent/Child"`) {
		t.Fatalf("subscribed child missing:\n%s", joined)
	}
}
