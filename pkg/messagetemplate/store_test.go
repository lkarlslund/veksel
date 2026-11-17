package messagetemplate

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func newTestStore(t *testing.T, backend store.Store, kind store.Backend) (*Store, service.FolderSpace) {
	t.Helper()
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, kind)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"alice", "bob"} {
		if err := typed.UserStore().Create(t.Context(), userID, userID, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatal(err)
		}
	}
	space := service.NewFolderSpace(typed, authz.New(typed))
	return New(space), space
}

func TestStoreUsesGenericBackendsAndScopesOwners(t *testing.T) {
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
			templates, space := newTestStore(t, backend, store.Backend(name))
			first, err := templates.Create(t.Context(), " Alice ", " Welcome ", " Hello ", "Line one\r\nLine two")
			if err != nil {
				t.Fatal(err)
			}
			if first.OwnerID != "alice" || first.Name != "Welcome" || first.Subject != "Hello" || first.Body != "Line one\nLine two" {
				t.Fatalf("normalized definition=%+v", first)
			}
			folder, err := space.GetFolderByOwnerPath(t.Context(), service.UserAccess("alice", "test"), "alice", FolderPath)
			if err != nil || folder.Type != model.FolderTypeMailTemplate || !folder.System || folder.SpecialUse != model.SpecialUseMailTemplate || folder.Subscribed || folder.ItemCount != 1 {
				t.Fatalf("template folder=%+v err=%v", folder, err)
			}
			second, err := templates.Create(t.Context(), "alice", "Invoice", "Invoice details", "Please see the attached invoice.")
			if err != nil {
				t.Fatal(err)
			}
			bob, err := templates.Create(t.Context(), "bob", "Bob only", "Private", "Bob's content")
			if err != nil {
				t.Fatal(err)
			}
			listed, err := templates.List(t.Context(), "ALICE")
			if err != nil || len(listed) != 2 || listed[0].ID != second.ID || listed[1].ID != first.ID {
				t.Fatalf("Alice list=%+v err=%v", listed, err)
			}
			if _, err := templates.Get(t.Context(), "alice", bob.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("cross-owner get error=%v", err)
			}
			updated, err := templates.Update(t.Context(), "alice", first.ID, "Follow up", "Following up", "Checking in.")
			if err != nil || updated.Name != "Follow up" || updated.Subject != "Following up" || !updated.UpdatedAt.After(updated.CreatedAt) {
				t.Fatalf("updated=%+v err=%v", updated, err)
			}
			if err := templates.Delete(t.Context(), "alice", first.ID); err != nil {
				t.Fatal(err)
			}
			if remaining, err := templates.List(t.Context(), "alice"); err != nil || len(remaining) != 1 || remaining[0].ID != second.ID {
				t.Fatalf("remaining=%+v err=%v", remaining, err)
			}
		})
	}
}

func TestStoreRejectsInvalidDefinitions(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	templates, _ := newTestStore(t, backend, store.BackendJSON)
	tests := []struct{ name, owner, label, subject, body string }{
		{name: "missing owner", label: "Template", subject: "Subject"},
		{name: "missing name", owner: "alice", label: " ", subject: "Subject"},
		{name: "long name", owner: "alice", label: strings.Repeat("ø", MaxNameRunes+1), subject: "Subject"},
		{name: "empty content", owner: "alice", label: "Empty"},
		{name: "multiline subject", owner: "alice", label: "Bad", subject: "one\ntwo"},
		{name: "long subject", owner: "alice", label: "Bad", subject: strings.Repeat("ø", MaxSubjectRunes+1)},
		{name: "large body", owner: "alice", label: "Bad", body: strings.Repeat("x", MaxBodyBytes+1)},
		{name: "nul body", owner: "alice", label: "Bad", body: "one\x00two"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := templates.Create(t.Context(), test.owner, test.label, test.subject, test.body); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestStoreCapsConcurrentOwnerDefinitions(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	templates, _ := newTestStore(t, backend, store.BackendJSON)
	var wait sync.WaitGroup
	errorsByResult := make(chan error, 125)
	for range 125 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := templates.Create(t.Context(), "alice", "Concurrent", "Subject", "Body")
			errorsByResult <- err
		}()
	}
	wait.Wait()
	close(errorsByResult)
	created, limited := 0, 0
	for err := range errorsByResult {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrLimit):
			limited++
		default:
			t.Fatalf("unexpected error=%v", err)
		}
	}
	listed, err := templates.List(t.Context(), "alice")
	if err != nil || created != MaxPerOwner || limited != 25 || len(listed) != MaxPerOwner {
		t.Fatalf("created=%d limited=%d listed=%d err=%v", created, limited, len(listed), err)
	}
}
