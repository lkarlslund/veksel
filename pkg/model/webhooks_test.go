package model

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func webhookTestStore(t *testing.T) *WebhookStore {
	t.Helper()
	typed := newTestSetup(t)
	if err := typed.EnsureNamespace(t.Context(), NSWebhooks); err != nil {
		t.Fatal(err)
	}
	return NewWebhookStore(typed)
}

func TestWebhookRotationUsesSupportedStoreAtomicBoundary(t *testing.T) {
	factories := map[string]func(string) (store.Store, error){
		"json":   func(path string) (store.Store, error) { return jsonstore.New(path) },
		"pebble": func(path string) (store.Store, error) { return pebblestore.New(path) },
		"badger": func(path string) (store.Store, error) { return badgerstore.New(path) },
	}
	for name, open := range factories {
		t.Run(name, func(t *testing.T) {
			backend, err := open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			typed := NewTypedStore(backend, store.Backend(name))
			if err := typed.EnsureNamespace(t.Context(), NSWebhooks); err != nil {
				t.Fatal(err)
			}
			webhooks := NewWebhookStore(typed)
			created := Webhook{ID: name, URL: "https://example.test/hook", Events: []string{"event"}, Secret: "old", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
			if err := webhooks.Create(t.Context(), created); err != nil {
				t.Fatal(err)
			}
			rotated, secret, err := webhooks.RotateSecret(t.Context(), created.ID, created.UpdatedAt)
			if err != nil || secret == created.Secret || rotated.SecretRotationCount != 1 {
				t.Fatalf("rotation=%+v secret_changed=%t err=%v", rotated, secret != created.Secret, err)
			}
			stale := created
			stale.URL = "https://example.test/stale"
			if _, err := webhooks.UpdateIfUpdatedAt(t.Context(), stale, created.UpdatedAt); !errors.Is(err, store.ErrPreconditionFailed) {
				t.Fatalf("stale update error=%v", err)
			}
		})
	}
}

func TestWebhookRotateSecretPreservesSubscriptionAndRejectsStaleVersion(t *testing.T) {
	webhooks := webhookTestStore(t)
	created := Webhook{
		ID: "stable", URL: "https://example.test/hook", Events: []string{"message.received"}, Active: true,
		Secret: "old", MaxRetries: 7, BackoffMultiplier: 3, CreatedAt: time.Now().UTC().Add(-time.Hour), UpdatedAt: time.Now().UTC().Add(-time.Minute),
	}
	if err := webhooks.Create(t.Context(), created); err != nil {
		t.Fatal(err)
	}
	rotated, secret, err := webhooks.RotateSecret(t.Context(), created.ID, created.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 40 || secret == created.Secret || rotated.Secret != secret {
		t.Fatalf("replacement secret was not renewed safely")
	}
	if rotated.ID != created.ID || rotated.URL != created.URL || rotated.Active != created.Active || rotated.MaxRetries != created.MaxRetries || rotated.BackoffMultiplier != created.BackoffMultiplier || !rotated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("rotation changed stable subscription: before=%+v after=%+v", created, rotated)
	}
	if len(rotated.Events) != 1 || rotated.Events[0] != created.Events[0] || rotated.SecretRotationCount != 1 || rotated.SecretRotatedAt.IsZero() || !rotated.UpdatedAt.Equal(rotated.SecretRotatedAt) {
		t.Fatalf("rotation evidence/subscription = %+v", rotated)
	}
	if _, _, err := webhooks.RotateSecret(t.Context(), created.ID, created.UpdatedAt); !errors.Is(err, store.ErrPreconditionFailed) {
		t.Fatalf("stale rotation error = %v", err)
	}
	stored, err := webhooks.Get(t.Context(), created.ID)
	if err != nil || stored.Secret != secret || stored.SecretRotationCount != 1 {
		t.Fatalf("stored webhook=%+v err=%v", stored, err)
	}
}

func TestWebhookRotationAndEditHaveOneAtomicWinner(t *testing.T) {
	webhooks := webhookTestStore(t)
	created := Webhook{ID: "race", URL: "https://example.test/old", Events: []string{"event"}, Secret: "old", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := webhooks.Create(t.Context(), created); err != nil {
		t.Fatal(err)
	}
	edited := created
	edited.URL = "https://example.test/edited"
	var editErr, rotateErr error
	var replacement string
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, editErr = webhooks.UpdateIfUpdatedAt(t.Context(), edited, created.UpdatedAt)
	}()
	go func() {
		defer wait.Done()
		_, replacement, rotateErr = webhooks.RotateSecret(t.Context(), created.ID, created.UpdatedAt)
	}()
	wait.Wait()
	successes := 0
	for _, err := range []error{editErr, rotateErr} {
		if err == nil {
			successes++
		} else if !errors.Is(err, store.ErrPreconditionFailed) {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful operations=%d edit=%v rotate=%v", successes, editErr, rotateErr)
	}
	stored, err := webhooks.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotateErr == nil && (stored.Secret != replacement || stored.URL != created.URL || stored.SecretRotationCount != 1) {
		t.Fatalf("rotation winner was overwritten: %+v", stored)
	}
	if editErr == nil && (stored.URL != edited.URL || stored.Secret != created.Secret || stored.SecretRotationCount != 0) {
		t.Fatalf("edit winner was overwritten: %+v", stored)
	}
}

func TestWebhookUpdatePreservesRotationEvidence(t *testing.T) {
	webhooks := webhookTestStore(t)
	created := Webhook{ID: "edit", URL: "https://example.test/old", Events: []string{"event"}, Secret: "old", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := webhooks.Create(t.Context(), created); err != nil {
		t.Fatal(err)
	}
	rotated, _, err := webhooks.RotateSecret(t.Context(), created.ID, created.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	next := *rotated
	next.URL = "https://example.test/new"
	next.SecretRotatedAt = time.Time{}
	next.SecretRotationCount = 0
	updated, err := webhooks.UpdateIfUpdatedAt(t.Context(), next, rotated.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if updated.SecretRotationCount != 1 || !updated.SecretRotatedAt.Equal(rotated.SecretRotatedAt) || updated.URL != next.URL {
		t.Fatalf("updated webhook lost store-owned evidence: %+v", updated)
	}
}
