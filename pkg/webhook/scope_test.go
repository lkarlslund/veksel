package webhook

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

// TestQueueForLimitsAccountEventsToMatchingFilters: a message event reaches
// only webhooks filtered to its account or recipient domain, never an
// unfiltered subscription; server-wide events still reach everyone.
func TestQueueForLimitsAccountEventsToMatchingFilters(t *testing.T) {
	whStore, delStore, outbox := newTestStores(t)
	for _, webhook := range []model.Webhook{
		{ID: "alice", URL: "https://a.example/hook", Events: []string{"message.received", "health.alert.opened"}, Accounts: []string{"alice"}, Active: true},
		{ID: "domain", URL: "https://b.example/hook", Events: []string{"message.received"}, Domains: []string{"example.com"}, Active: true},
		{ID: "unfiltered", URL: "https://c.example/hook", Events: []string{"message.received", "health.alert.opened"}, Active: true},
		{ID: "signup", URL: "https://d.example/hook", Events: []string{"message.received"}, Addresses: []string{"signup@example.test"}, Active: true},
	} {
		if err := whStore.Create(t.Context(), webhook); err != nil {
			t.Fatal(err)
		}
	}
	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	targets := func() []string {
		entries, err := outbox.List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, entry := range entries {
			ids = append(ids, entry.WebhookID)
			_ = outbox.Delete(t.Context(), entry.ID)
		}
		slices.Sort(ids)
		return ids
	}
	if err := d.QueueFor("message.received", map[string]string{"item_id": "1"}, model.WebhookScope{Account: "domains", Recipients: []string{"Domains@Example.com"}}); err != nil {
		t.Fatal(err)
	}
	if got := targets(); !slices.Equal(got, []string{"domain"}) {
		t.Fatalf("domains@example.com delivery went to %v", got)
	}
	if err := d.QueueFor("message.received", map[string]string{"item_id": "2"}, model.WebhookScope{Account: "alice", Recipients: []string{"alice@example.test"}}); err != nil {
		t.Fatal(err)
	}
	if got := targets(); !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("alice delivery went to %v", got)
	}
	// An alias delivering into alice's mailbox reaches the address webhook
	// and alice's account webhook, nothing else.
	if err := d.QueueFor("message.received", map[string]string{"item_id": "3"}, model.WebhookScope{Account: "alice", Recipients: []string{"Signup@Example.test"}}); err != nil {
		t.Fatal(err)
	}
	if got := targets(); !slices.Equal(got, []string{"alice", "signup"}) {
		t.Fatalf("signup@ delivery went to %v", got)
	}
	if err := d.Queue("health.alert.opened", map[string]string{"alert": "x"}); err != nil {
		t.Fatal(err)
	}
	if got := targets(); !slices.Equal(got, []string{"alice", "unfiltered"}) {
		t.Fatalf("server-wide alert went to %v", got)
	}
}

// TestQueueForKeepsOnlyIncludedParts: optional content goes only to the
// webhooks that asked for it.
func TestQueueForKeepsOnlyIncludedParts(t *testing.T) {
	whStore, delStore, outbox := newTestStores(t)
	for _, webhook := range []model.Webhook{
		{ID: "summary", URL: "https://a.example/hook", Events: []string{"message.received"}, Accounts: []string{"domains"}, Active: true},
		{ID: "full", URL: "https://b.example/hook", Events: []string{"message.received"}, Accounts: []string{"domains"}, Include: []string{"raw", "text"}, Active: true},
	} {
		if err := whStore.Create(t.Context(), webhook); err != nil {
			t.Fatal(err)
		}
	}
	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	scope := model.WebhookScope{Account: "domains"}
	if got := d.Includes("message.received", scope); !got["raw"] || !got["text"] || got["html"] {
		t.Fatalf("includes = %v", got)
	}
	payload := map[string]any{"subject": "Hi", "text": "body", "html": "<p>body</p>", "raw": "UmF3", "raw_omitted": "x"}
	if err := d.QueueFor("message.received", payload, scope); err != nil {
		t.Fatal(err)
	}
	entries, err := outbox.List(t.Context())
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		body := string(entry.Payload)
		switch entry.WebhookID {
		case "summary":
			if body != `{"subject":"Hi"}` {
				t.Errorf("summary payload %s", body)
			}
		case "full":
			if body != `{"raw":"UmF3","raw_omitted":"x","subject":"Hi","text":"body"}` {
				t.Errorf("full payload %s", body)
			}
		}
	}
}

// TestPersonalWebhooksNeverReachInternalAddresses: even with private
// networks allowed for server webhooks, a personal webhook (created by any
// user) cannot be pointed at an internal service.
func TestPersonalWebhooksNeverReachInternalAddresses(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer internal.Close()
	whStore, delStore, outbox := newTestStores(t)
	for _, webhook := range []model.Webhook{
		{ID: "server", URL: internal.URL, Events: []string{"message.received"}, Accounts: []string{"bob"}, Active: true},
		{ID: "personal", OwnerID: "bob", URL: internal.URL, Events: []string{"message.received"}, Active: true},
	} {
		if err := whStore.Create(t.Context(), webhook); err != nil {
			t.Fatal(err)
		}
	}
	d := newTestDispatcher(whStore, delStore, outbox, DefaultRetryPolicy())
	if _, err := d.Test(t.Context(), "server"); err != nil {
		t.Fatalf("server webhook to an allowed internal address: %v", err)
	}
	if _, err := d.Test(t.Context(), "personal"); err == nil {
		t.Fatal("personal webhook reached an internal address")
	}
	if hits.Load() != 1 {
		t.Fatalf("internal service got %d requests, want 1 (the server webhook)", hits.Load())
	}
}
