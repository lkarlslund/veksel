package authz

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// scanCountingStore counts range reads, which are the per-decision cost that
// a request scope removes from catalog-sized authorization loops.
type scanCountingStore struct {
	store.Store
	scans atomic.Int64
}

func (s *scanCountingStore) List(ctx context.Context, namespace string) ([]string, error) {
	s.scans.Add(1)
	return s.Store.List(ctx, namespace)
}

func (s *scanCountingStore) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	s.scans.Add(1)
	return s.Store.Scan(ctx, namespace, prefix)
}

func TestRequestScopeResolvesActorBindingsOnce(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	counting := &scanCountingStore{Store: backend}
	ts := model.NewTypedStore(counting, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	engine := New(ts)
	createUser(t, ts, "alice")
	createUser(t, ts, "bob")
	shared := createFolder(t, ts, "bob", "Shared", "")
	resources := []model.ResourceRef{{Kind: model.ResourceFolder, ID: shared.ID}}
	for index := range 8 {
		child := createFolder(t, ts, "bob", fmt.Sprintf("Shared/Child %d", index), shared.ID)
		resources = append(resources, model.ResourceRef{Kind: model.ResourceFolder, ID: child.ID})
	}
	private := createFolder(t, ts, "bob", "Private", "")
	resources = append(resources, model.ResourceRef{Kind: model.ResourceFolder, ID: private.ID})
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	createBinding(t, ts, model.PolicyBinding{
		Principal: alice, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: shared.ID},
		Effect: model.EffectAllow, RoleID: RoleFolderViewer, Inheritance: model.InheritanceSubtree, GrantedBy: "bob",
	})
	actions := []Action{FolderDiscover, FolderItemsRead, FolderItemsCreate, FolderItemsUpdate, FolderItemsDelete}
	decide := func(ctx context.Context) ([]bool, int64) {
		counting.scans.Store(0)
		allowed := make([]bool, 0, len(resources)*len(actions))
		for _, resource := range resources {
			for _, action := range actions {
				decision, err := engine.Check(ctx, Request{Actor: alice, Action: action, Resource: resource})
				if err != nil {
					t.Fatal(err)
				}
				allowed = append(allowed, decision.Allowed)
			}
		}
		return allowed, counting.scans.Load()
	}

	unscoped, unscopedScans := decide(t.Context())
	scope := WithRequestScope(t.Context())
	scoped, scopedScans := decide(scope)
	if !slices.Equal(unscoped, scoped) {
		t.Fatalf("scoped decisions differ:\nunscoped=%v\nscoped=%v", unscoped, scoped)
	}
	// Viewer may discover and read the shared subtree but not write, and the
	// private sibling stays invisible.
	if !scoped[0] || !scoped[1] || scoped[2] || slices.Contains(scoped[len(scoped)-len(actions):], true) {
		t.Fatalf("unexpected decisions: %v", scoped)
	}
	checks := int64(len(resources) * len(actions))
	t.Logf("range reads for %d decisions: unscoped=%d scoped=%d", checks, unscopedScans, scopedScans)
	if unscopedScans < checks {
		t.Fatalf("unscoped checks performed %d range reads for %d decisions; expected at least one each", unscopedScans, checks)
	}
	if scopedScans > 2 {
		t.Fatalf("request scope performed %d range reads for %d decisions, want at most 2 (principal index + groups)", scopedScans, checks)
	}
	if WithRequestScope(scope) != scope {
		t.Fatal("nested WithRequestScope must reuse the enclosing scope")
	}

	// The scope is a snapshot for one bounded request: a grant revoked while
	// it is alive is honored by fresh requests immediately.
	bindings, err := model.NewPolicyStore(ts).ListForPrincipal(t.Context(), alice)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("list bindings: %v %v", bindings, err)
	}
	if err := model.NewPolicyStore(ts).Delete(t.Context(), bindings[0].ID); err != nil {
		t.Fatal(err)
	}
	if fresh, _ := decide(t.Context()); slices.Contains(fresh, true) {
		t.Fatalf("revoked grant still allowed outside the scope: %v", fresh)
	}
}
