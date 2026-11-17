package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestSessionStoreUsesGenericBackendsAndOwnerScopedRevocation(t *testing.T) {
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
			typed := model.NewTypedStore(backend, store.Backend(name))
			if err := typed.EnsureNamespace(t.Context(), model.NSSessions); err != nil {
				t.Fatal(err)
			}
			sessions := newSessionStore(typed)
			aliceCurrent, err := sessions.Create(t.Context(), "alice", "csrf-1", "127.0.0.1:5000", "Browser One")
			if err != nil {
				t.Fatal(err)
			}
			aliceOther, err := sessions.Create(t.Context(), "alice", "csrf-2", "[2001:db8::1]:5001", "Browser Two")
			if err != nil {
				t.Fatal(err)
			}
			bob, err := sessions.Create(t.Context(), "bob", "csrf-3", "192.0.2.1:5002", "Browser Three")
			if err != nil {
				t.Fatal(err)
			}

			listed, err := sessions.ListByActor(t.Context(), "ALICE")
			if err != nil || len(listed) != 2 || listed[0].IP != "2001:db8::1" || listed[1].IP != "127.0.0.1" {
				t.Fatalf("alice sessions=%+v err=%v", listed, err)
			}
			if _, err := sessions.DeleteOwned(t.Context(), "alice", tokenHash(bob), tokenHash(aliceCurrent)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("cross-account delete error=%v", err)
			}
			if _, err := sessions.DeleteOwned(t.Context(), "alice", tokenHash(aliceCurrent), tokenHash(aliceCurrent)); !errors.Is(err, errCurrentSession) {
				t.Fatalf("current delete error=%v", err)
			}
			deleted, err := sessions.DeleteOwned(t.Context(), "alice", tokenHash(aliceOther), tokenHash(aliceCurrent))
			if err != nil || deleted.ID != tokenHash(aliceOther) {
				t.Fatalf("delete other=%+v err=%v", deleted, err)
			}
			if _, err := sessions.Get(t.Context(), aliceOther); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("deleted token remains active: %v", err)
			}
			if _, err := sessions.Get(t.Context(), bob); err != nil {
				t.Fatalf("cross-account session was removed: %v", err)
			}
		})
	}
}

func TestSessionStoreAdoptsLegacyRecordsPrunesExpiryAndThrottlesActivity(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	if err := typed.EnsureNamespace(t.Context(), model.NSSessions); err != nil {
		t.Fatal(err)
	}
	sessions := newSessionStore(typed)
	now := time.Now().UTC()
	legacyID, expiredID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := typed.Put(t.Context(), model.NSSessions, legacyID, model.Session{ID: legacyID, User: "alice", CreatedAt: now.Add(-time.Hour), LastActivity: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := typed.Put(t.Context(), model.NSSessions, expiredID, model.Session{ID: expiredID, User: "alice", CreatedAt: now.Add(-8 * 24 * time.Hour), LastActivity: now.Add(-8 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	listed, err := sessions.ListByActor(t.Context(), "alice")
	if err != nil || len(listed) != 1 || listed[0].ActorID != "alice" || listed[0].SubjectID != "alice" || listed[0].ExpiresAt.IsZero() {
		t.Fatalf("adopted sessions=%+v err=%v", listed, err)
	}
	if err := typed.Get(t.Context(), model.NSSessions, expiredID, &model.Session{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session remains: %v", err)
	}

	token, err := sessions.Create(t.Context(), "alice", "csrf", "127.0.0.1:1", strings.Repeat("ü", 800))
	if err != nil {
		t.Fatal(err)
	}
	id := tokenHash(token)
	var before model.Session
	if err := typed.Get(t.Context(), model.NSSessions, id, &before); err != nil {
		t.Fatal(err)
	}
	if len(before.UserAgent) > 1024 || !utf8.ValidString(before.UserAgent) {
		t.Fatalf("unbounded or invalid user agent: bytes=%d", len(before.UserAgent))
	}
	if _, err := sessions.Get(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	var immediate model.Session
	if err := typed.Get(t.Context(), model.NSSessions, id, &immediate); err != nil || !immediate.LastActivity.Equal(before.LastActivity) {
		t.Fatalf("activity was written before throttle interval: before=%v after=%v err=%v", before.LastActivity, immediate.LastActivity, err)
	}
	immediate.LastActivity = now.Add(-2 * sessionActivityInterval)
	if err := typed.Set(t.Context(), model.NSSessions, id, immediate); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Get(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	var touched model.Session
	if err := typed.Get(t.Context(), model.NSSessions, id, &touched); err != nil || !touched.LastActivity.After(immediate.LastActivity) {
		t.Fatalf("stale activity was not refreshed: before=%v after=%v err=%v", immediate.LastActivity, touched.LastActivity, err)
	}
}

func TestSessionStoreCapsConcurrentLogins(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	if err := typed.EnsureNamespace(t.Context(), model.NSSessions); err != nil {
		t.Fatal(err)
	}
	sessions := newSessionStore(typed)
	var wait sync.WaitGroup
	errorsFound := make(chan error, maxBrowserSessions+25)
	for index := 0; index < maxBrowserSessions+25; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := sessions.Create(t.Context(), "alice", "csrf", "127.0.0.1:1", "Browser")
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	listed, err := sessions.ListByActor(t.Context(), "alice")
	if err != nil || len(listed) != maxBrowserSessions {
		t.Fatalf("active sessions=%d err=%v, want %d", len(listed), err, maxBrowserSessions)
	}
}

func TestSessionStoreAccountUpdateAndRevocationRollBackTogether(t *testing.T) {
	base, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	faulty := faultstore.New(base)
	typed := model.NewTypedStore(faulty, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSSessions} {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "alice", "Original", "password123"); err != nil {
		t.Fatal(err)
	}
	sessions := newSessionStore(typed)
	current, err := sessions.Create(t.Context(), "alice", "csrf-1", "127.0.0.1:1", "One")
	if err != nil {
		t.Fatal(err)
	}
	other, err := sessions.Create(t.Context(), "alice", "csrf-2", "127.0.0.1:2", "Two")
	if err != nil {
		t.Fatal(err)
	}
	faulty.Fail("batch_commit", 1)
	_, err = sessions.UpdateActorAndDeleteOthers(t.Context(), "alice", tokenHash(current), func(ctx context.Context) error {
		return typed.UserStore().Update(ctx, "alice", func(user *model.User) { user.DisplayName = "Changed" })
	})
	if !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("update error=%v", err)
	}
	user, err := typed.UserStore().Get(t.Context(), "alice")
	if err != nil || user.DisplayName != "Original" {
		t.Fatalf("account update escaped rollback: user=%+v err=%v", user, err)
	}
	if _, err := sessions.Get(t.Context(), other); err != nil {
		t.Fatalf("session revocation escaped rollback: %v", err)
	}
}
