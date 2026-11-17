package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWebhookOutboxStoreRetainsAndOrdersDurableEnvelopes(t *testing.T) {
	ts := testStore(t)
	if err := ts.EnsureNamespace(t.Context(), NSWebhookOutbox); err != nil {
		t.Fatal(err)
	}
	store := NewWebhookOutboxStore(ts)
	now := time.Now().UTC().Round(time.Second)
	for _, entry := range []WebhookOutboxEntry{
		{ID: "later", EventID: "evt-1", WebhookID: "one", Event: "mail", Payload: json.RawMessage(`{"private":"payload"}`), State: WebhookOutboxPending, NextAttemptAt: now.Add(time.Minute)},
		{ID: "first", EventID: "evt-1", WebhookID: "two", Event: "mail", Payload: json.RawMessage(`{"value":1}`), State: WebhookOutboxPending, NextAttemptAt: now},
	} {
		if err := store.Create(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := store.List(t.Context())
	if err != nil || len(entries) != 2 || entries[0].ID != "first" || string(entries[1].Payload) != `{"private":"payload"}` {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
	if entries[0].EventID != entries[1].EventID {
		t.Fatal("destinations did not retain shared event identity")
	}
}

func TestGenerateWebhookEventIDIsUnique(t *testing.T) {
	first, err := GenerateWebhookEventID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateWebhookEventID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 36 || first[:4] != "evt_" {
		t.Fatalf("generated IDs = %q, %q", first, second)
	}
}
