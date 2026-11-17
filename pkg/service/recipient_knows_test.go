package service

import "testing"

func TestRecipientHistoryKnowsOnlyAddressesTheUserWroteTo(t *testing.T) {
	history, _, _ := testRecipientHistory(t)
	known, err := history.Knows(t.Context(), "alice", "ada@example.test")
	if err != nil || known {
		t.Fatalf("before any submission = %v, %v", known, err)
	}
	if err := history.Record(t.Context(), "alice", []string{"Ada <Ada@Example.test>"}); err != nil {
		t.Fatal(err)
	}
	for address, want := range map[string]bool{
		"ada@example.test": true, " ADA@example.test ": true, "bob@example.test": false, "example.test": false, "": false,
	} {
		if got, err := history.Knows(t.Context(), "alice", address); err != nil || got != want {
			t.Errorf("Knows(%q) = %v, %v; want %v", address, got, err, want)
		}
	}
	if got, err := history.Knows(t.Context(), "bob", "ada@example.test"); err != nil || got {
		t.Fatalf("another account's correspondent = %v, %v", got, err)
	}
}
