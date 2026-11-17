package savedsearch

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
			saved, space := newTestStore(t, backend, store.Backend(name))
			first, err := saved.Create(t.Context(), " Alice ", " Unread mail ", service.SearchQuery{
				Types:  []model.FolderType{model.FolderTypeMail, model.FolderTypeMail},
				Filter: &service.SearchFilter{Operator: service.SearchNot, Children: []service.SearchFilter{{Operator: service.SearchEquals, Field: "flag", Value: model.FlagSeen}}},
				Sort:   "date_desc", Limit: 999, Cursor: "must-not-persist",
			})
			if err != nil {
				t.Fatal(err)
			}
			if first.OwnerID != "alice" || first.Name != "Unread mail" || first.Query.Cursor != "" || first.Query.Limit != 0 || len(first.Query.Types) != 1 {
				t.Fatalf("normalized definition = %+v", first)
			}
			folder, err := space.GetFolderByOwnerPath(t.Context(), service.UserAccess("alice", "test"), "alice", FolderPath)
			if err != nil || folder.Type != model.FolderTypeSavedSearch || folder.ItemCount != 1 {
				t.Fatalf("saved-search folder=%+v err=%v", folder, err)
			}
			second, err := saved.Create(t.Context(), "alice", "Attachments", service.SearchQuery{Expression: "has:attachment"})
			if err != nil {
				t.Fatal(err)
			}
			bob, err := saved.Create(t.Context(), "bob", "Bob only", service.SearchQuery{Text: "bob"})
			if err != nil {
				t.Fatal(err)
			}
			listed, err := saved.List(t.Context(), "ALICE")
			if err != nil || len(listed) != 2 || listed[0].ID != second.ID || listed[1].ID != first.ID {
				t.Fatalf("Alice list=%+v err=%v", listed, err)
			}
			if _, err := saved.Get(t.Context(), "alice", bob.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("cross-owner get error=%v", err)
			}
			if err := saved.Delete(t.Context(), "alice", bob.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("cross-owner delete error=%v", err)
			}
			updated, err := saved.Update(t.Context(), "alice", first.ID, "Flagged", service.SearchQuery{Expression: "is:flagged", Sort: "date_asc"})
			if err != nil || updated.Name != "Flagged" || updated.Query.Expression != "is:flagged" || !updated.UpdatedAt.After(updated.CreatedAt) {
				t.Fatalf("updated=%+v err=%v", updated, err)
			}
			if err := saved.Delete(t.Context(), "alice", first.ID); err != nil {
				t.Fatal(err)
			}
			if remaining, err := saved.List(t.Context(), "alice"); err != nil || len(remaining) != 1 || remaining[0].ID != second.ID {
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
	saved, _ := newTestStore(t, backend, store.BackendJSON)
	tests := []struct {
		name  string
		label string
		query service.SearchQuery
	}{
		{name: "missing owner", label: "Search", query: service.SearchQuery{Text: "mail"}},
		{name: "missing name", label: " ", query: service.SearchQuery{Text: "mail"}},
		{name: "long name", label: strings.Repeat("ø", 121), query: service.SearchQuery{Text: "mail"}},
		{name: "empty query", label: "Everything"},
		{name: "bad sort", label: "Search", query: service.SearchQuery{Text: "mail", Sort: "random"}},
		{name: "bad type", label: "Search", query: service.SearchQuery{Types: []model.FolderType{"unknown"}}},
		{name: "bad expression", label: "Search", query: service.SearchQuery{Expression: "after:not-a-date"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := "alice"
			if test.name == "missing owner" {
				owner = ""
			}
			if _, err := saved.Create(t.Context(), owner, test.label, test.query); !errors.Is(err, ErrInvalid) {
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
	saved, _ := newTestStore(t, backend, store.BackendJSON)
	var wait sync.WaitGroup
	errorsByResult := make(chan error, 125)
	for range 125 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := saved.Create(t.Context(), "alice", "Concurrent", service.SearchQuery{Text: "mail"})
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
	listed, err := saved.List(t.Context(), "alice")
	if err != nil || created != MaxPerOwner || limited != 25 || len(listed) != MaxPerOwner {
		t.Fatalf("created=%d limited=%d listed=%d err=%v", created, limited, len(listed), err)
	}
}
