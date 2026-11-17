package imap

import (
	"reflect"
	"testing"
)

func TestParseCommandQuotedArguments(t *testing.T) {
	session := &Session{}
	tag, command, args, err := session.parseCommand(`A001 LOGIN "user name" "pa\"ss"`)
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	if tag != "A001" || command != "LOGIN" {
		t.Fatalf("unexpected command: tag=%q command=%q", tag, command)
	}
	want := []string{"user name", `pa"ss`}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("arguments = %#v, want %#v", args, want)
	}
}

func TestParseCommandQuotedFetchFieldList(t *testing.T) {
	session := &Session{}
	_, _, args, err := session.parseCommand(`A001 FETCH 1 BODY.PEEK[HEADER.FIELDS ("From" "Long Subject")]`)
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	want := []string{"1", "BODY.PEEK[HEADER.FIELDS", `("From"`, "Long Subject)]"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("arguments = %#v, want %#v", args, want)
	}
}

func TestParseCommandRejectsMalformedQuotedArguments(t *testing.T) {
	for _, command := range []string{
		`A001 LOGIN "unterminated password`,
		`A001 LOGIN "bad\q" password`,
		`A001 LOGIN "user"suffix password`,
	} {
		t.Run(command, func(t *testing.T) {
			_, _, _, err := (&Session{}).parseCommand(command)
			if err == nil {
				t.Fatal("expected malformed quoted argument to fail")
			}
		})
	}
}
