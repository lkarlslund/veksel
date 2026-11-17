package model

import (
	"testing"
	"time"
)

func TestWebhookDeliveryPagesUseTimestampsNotRandomIDs(t *testing.T) {
	ts := testStore(t)
	if err := ts.EnsureNamespace(t.Context(), NSWebhookDeliveries); err != nil {
		t.Fatal(err)
	}
	store := NewWebhookDeliveryStore(ts)
	base := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	for _, delivery := range []WebhookDelivery{
		{ID: "z-random", WebhookID: "one", UpdatedAt: base.Add(time.Minute)},
		{ID: "a-random", WebhookID: "one", UpdatedAt: base.Add(3 * time.Minute)},
		{ID: "m-random", WebhookID: "one", UpdatedAt: base.Add(2 * time.Minute)},
		{ID: "other", WebhookID: "two", UpdatedAt: base.Add(4 * time.Minute)},
	} {
		if err := store.Create(t.Context(), delivery); err != nil {
			t.Fatal(err)
		}
	}
	first, total, more, err := store.ListPageByWebhook(t.Context(), "one", time.Time{}, "", 2)
	if err != nil || total != 3 || !more || len(first) != 2 || first[0].ID != "a-random" || first[1].ID != "m-random" {
		t.Fatalf("first page=%+v total=%d more=%t err=%v", first, total, more, err)
	}
	second, total, more, err := store.ListPageByWebhook(t.Context(), "one", first[1].UpdatedAt, first[1].ID, 2)
	if err != nil || total != 3 || more || len(second) != 1 || second[0].ID != "z-random" {
		t.Fatalf("second page=%+v total=%d more=%t err=%v", second, total, more, err)
	}
}
