package smtp

import (
	"context"
	"errors"
	"testing"
)

func TestPrepareDerivedMessageRoutesLocalAndPreservesIdentity(t *testing.T) {
	derived := DerivedMessage{Kind: "forward", Recipient: "alice@example.test", FullMessage: []byte("From: sender@example.net\r\nSubject: local\r\n\r\nbody"), ParentID: "parent-1", CorrelationID: "transaction-1"}
	resolve := func(context.Context, string) (string, string, bool, error) { return "alice:inbox", "alice", true, nil }
	first, err := PrepareDerivedMessage(t.Context(), derived, resolve)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareDerivedMessage(t.Context(), derived, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.ID != second.ID || first.Outbound || first.TargetFolderID != "alice:inbox" || first.TargetOwnerID != "alice" || string(first.Content) != string(derived.FullMessage) || first.ParentID != "parent-1" || first.CorrelationID != "transaction-1" {
		t.Fatalf("prepared local message = %+v", first)
	}
}

func TestPrepareDerivedMessageRoutesExternalAndFailsClosed(t *testing.T) {
	derived := DerivedMessage{Kind: "notify", Recipient: "outside@example.net", FullMessage: []byte("From: sender@example.test\r\n\r\nbody")}
	external, err := PrepareDerivedMessage(t.Context(), derived, func(context.Context, string) (string, string, bool, error) {
		return "", "", false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !external.Outbound || external.TargetFolderID != "" || string(external.Content) != string(derived.FullMessage) || len(external.Body) != 0 || external.EnvelopeSender != "sender@example.test" {
		t.Fatalf("prepared external message = %+v", external)
	}
	backendErr := errors.New("address index unavailable")
	if _, err := PrepareDerivedMessage(t.Context(), derived, func(context.Context, string) (string, string, bool, error) {
		return "", "", false, backendErr
	}); !errors.Is(err, backendErr) {
		t.Fatalf("resolver error = %v", err)
	}
	if _, err := PrepareDerivedMessage(t.Context(), DerivedMessage{Recipient: "invalid", FullMessage: derived.FullMessage}, nil); err == nil {
		t.Fatal("invalid derived recipient was accepted")
	}
}
