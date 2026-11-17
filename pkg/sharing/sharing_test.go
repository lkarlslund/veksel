package sharing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type sharingFixture struct {
	service *Service
	ts      *model.TypedStore
	space   service.FolderSpace
	inbox   model.Folder
	first   model.Item
	second  model.Item
	actor   model.PrincipalRef
}

func newSharingFixture(t *testing.T) sharingFixture {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	for _, userID := range []string{"alice", "bob"} {
		if err := ts.UserStore().Create(t.Context(), userID, userID, "password123"); err != nil {
			t.Fatalf("create %s: %v", userID, err)
		}
		if err := ts.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatalf("create folders for %s: %v", userID, err)
		}
	}
	inbox, err := ts.FolderStore().Get(t.Context(), model.InboxFolderID("alice"))
	if err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	access := service.UserAccess("alice", "test")
	first, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Name: "first.txt", Data: []byte("first"), Headers: map[string]string{"Content-Type": "text/plain"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{Name: "second.txt", Data: []byte("second")})
	if err != nil {
		t.Fatal(err)
	}
	shares, err := New(t.Context(), ts, space, authz.New(ts))
	if err != nil {
		t.Fatal(err)
	}
	return sharingFixture{service: shares, ts: ts, space: space, inbox: inbox, first: first, second: second, actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}}
}

func TestLinkSecretLifecycleAndBoundedRead(t *testing.T) {
	t.Parallel()
	fixture := newSharingFixture(t)
	issued, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetFolder, FolderID: fixture.inbox.ID, Access: AccessRead, MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fixture.ts.Store().Get(t.Context(), model.NSShareLinks, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(issued.Token)) || bytes.Contains(raw, []byte(stringsAfterLast(issued.Token, "."))) || !bytes.Contains(raw, []byte("secret_hash")) {
		t.Fatalf("stored record leaked bearer material: %s", raw)
	}
	encoded, err := json.Marshal(issued.Link)
	if err != nil || bytes.Contains(encoded, []byte("secret")) {
		t.Fatalf("public link projection leaked a secret: %s, %v", encoded, err)
	}

	resource, err := fixture.service.Open(t.Context(), issued.Token, 0, 1)
	if err != nil || len(resource.Items) != 1 || resource.Total != 2 || resource.Items[0].Data != nil || resource.Remaining == nil || *resource.Remaining != 1 {
		t.Fatalf("open resource = %+v, %v", resource, err)
	}
	item, err := fixture.service.ReadItem(t.Context(), issued.Token, fixture.first.ID)
	if err != nil || string(item.Data) != "first" {
		t.Fatalf("read item = %+v, %v", item, err)
	}
	if _, err := fixture.service.Open(t.Context(), issued.Token, 0, 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("exhausted link error = %v", err)
	}
	link, err := fixture.service.Get(t.Context(), fixture.actor, issued.ID)
	if err != nil || link.UseCount != 2 || link.Active(time.Now().UTC()) {
		t.Fatalf("exhausted link = %+v, %v", link, err)
	}
	if _, err := fixture.service.Open(t.Context(), issued.Token+"x", 0, 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered token error = %v", err)
	}
}

func TestRejectedPageBoundsDoNotConsumeUse(t *testing.T) {
	t.Parallel()
	fixture := newSharingFixture(t)
	issued, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetFolder, FolderID: fixture.inbox.ID, Access: AccessRead, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Open(t.Context(), issued.Token, 0, MaxPageSize+1); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized page error = %v", err)
	}
	link, err := fixture.service.Get(t.Context(), fixture.actor, issued.ID)
	if err != nil || link.UseCount != 0 {
		t.Fatalf("invalid request consumed use: link=%+v err=%v", link, err)
	}
	if _, err := fixture.service.Open(t.Context(), issued.Token, 0, MaxPageSize); err != nil {
		t.Fatalf("valid request after rejection: %v", err)
	}
}

func TestExactItemScopeReadOnlyAndWriteOperations(t *testing.T) {
	t.Parallel()
	fixture := newSharingFixture(t)
	readOnly, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetItem, ItemID: fixture.first.ID, Access: AccessRead})
	if err != nil {
		t.Fatal(err)
	}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	if links, err := fixture.service.List(t.Context(), bob); err != nil || len(links) != 0 {
		t.Fatalf("unrelated user links = %+v, %v", links, err)
	}
	if _, err := fixture.service.Get(t.Context(), bob, readOnly.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("unrelated user inspect error = %v", err)
	}
	if _, err := fixture.service.Revoke(t.Context(), bob, readOnly.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("unrelated user revoke error = %v", err)
	}
	if _, err := fixture.service.ReadItem(t.Context(), readOnly.Token, fixture.second.ID); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("sibling read error = %v", err)
	}
	if _, err := fixture.service.UpdateItem(t.Context(), readOnly.Token, fixture.first.ID, ItemInput{Data: []byte("blocked")}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only update error = %v", err)
	}
	link, err := fixture.service.Get(t.Context(), fixture.actor, readOnly.ID)
	if err != nil || link.UseCount != 0 {
		t.Fatalf("rejected requests consumed uses: %+v, %v", link, err)
	}

	write, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetItem, ItemID: fixture.first.ID, Access: AccessWrite})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CreateItem(t.Context(), write.Token, ItemInput{Name: "sibling", Data: []byte("no")}); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("item link created sibling: %v", err)
	}
	updated, err := fixture.service.UpdateItem(t.Context(), write.Token, fixture.first.ID, ItemInput{Data: []byte("updated"), Headers: map[string]string{"Content-Type": "text/plain"}})
	if err != nil || string(updated.Data) != "updated" {
		t.Fatalf("update target = %+v, %v", updated, err)
	}
	if err := fixture.service.DeleteItem(t.Context(), write.Token, fixture.first.ID); err != nil {
		t.Fatalf("delete target: %v", err)
	}
	if _, err := fixture.space.GetItem(t.Context(), service.UserAccess("alice", "test"), fixture.first.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted target remains: %v", err)
	}
}

func TestPublishedFeedPollingRecordsAUseAtMostEveryInterval(t *testing.T) {
	t.Parallel()
	fixture := newSharingFixture(t)
	now := time.Date(2026, time.August, 18, 10, 0, 0, 0, time.UTC)
	fixture.service.now = func() time.Time { return now }
	calendar, err := fixture.ts.FolderStore().GetByPath(t.Context(), "alice", "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetFolder, FolderID: calendar.ID, Access: AccessRead, Publish: PublishICS})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, _, err := fixture.service.OpenCalendar(t.Context(), issued.Token); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(publishedUseInterval)
	if _, _, err := fixture.service.OpenCalendar(t.Context(), issued.Token); err != nil {
		t.Fatal(err)
	}
	link, err := fixture.service.Get(t.Context(), fixture.actor, issued.ID)
	if err != nil || link.UseCount != 2 {
		t.Fatalf("use count = %d, %v", link.UseCount, err)
	}
}

func TestRevocationExpiryAndCurrentAuthority(t *testing.T) {
	t.Parallel()
	fixture := newSharingFixture(t)
	now := time.Date(2026, time.August, 18, 10, 0, 0, 0, time.UTC)
	fixture.service.now = func() time.Time { return now }
	expiring, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetFolder, FolderID: fixture.inbox.ID, Access: AccessRead, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if _, err := fixture.service.Open(t.Context(), expiring.Token, 0, 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired link error = %v", err)
	}

	now = now.Add(-time.Hour)
	revoked, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetFolder, FolderID: fixture.inbox.ID, Access: AccessRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Revoke(t.Context(), fixture.actor, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Open(t.Context(), revoked.Token, 0, 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked link error = %v", err)
	}
	restarted, err := New(t.Context(), fixture.ts, fixture.space, authz.New(fixture.ts))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Open(t.Context(), revoked.Token, 0, 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revocation did not survive service restart: %v", err)
	}

	binding, err := model.NewPolicyStore(fixture.ts).Create(t.Context(), model.PolicyBinding{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: fixture.inbox.ID}, Effect: model.EffectAllow, RoleID: authz.RoleFolderManager, Inheritance: model.InheritanceSelf, GrantedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	delegated, err := fixture.service.Create(t.Context(), bob, CreateRequest{TargetKind: TargetFolder, FolderID: fixture.inbox.ID, Access: AccessWrite})
	if err != nil {
		t.Fatalf("delegated manager create: %v", err)
	}
	links, err := fixture.service.List(t.Context(), fixture.actor)
	if err != nil || !containsLink(links, delegated.ID) {
		t.Fatalf("owner cannot inspect delegated link: %+v, %v", links, err)
	}
	if err := model.NewPolicyStore(fixture.ts).Delete(t.Context(), binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Open(t.Context(), delegated.Token, 0, 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked creator authority did not disable link: %v", err)
	}
	if _, err := fixture.service.Revoke(t.Context(), fixture.actor, delegated.ID); err != nil {
		t.Fatalf("resource owner revoke: %v", err)
	}
}

func TestUseLimitIsAtomicUnderConcurrency(t *testing.T) {
	fixture := newSharingFixture(t)
	issued, err := fixture.service.Create(t.Context(), fixture.actor, CreateRequest{TargetKind: TargetFolder, FolderID: fixture.inbox.ID, Access: AccessRead, MaxUses: 7})
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int64
	var wait sync.WaitGroup
	for range 40 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := fixture.service.Open(context.Background(), issued.Token, 0, 1); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrUnavailable) {
				t.Errorf("open error = %v", err)
			}
		}()
	}
	wait.Wait()
	link, err := fixture.service.Get(t.Context(), fixture.actor, issued.ID)
	if err != nil || successes.Load() != 7 || link.UseCount != 7 {
		t.Fatalf("successes=%d link=%+v err=%v", successes.Load(), link, err)
	}
}

func stringsAfterLast(value, separator string) string {
	for index := len(value) - 1; index >= 0; index-- {
		if value[index:index+1] == separator {
			return value[index+1:]
		}
	}
	return value
}

func containsLink(links []Link, id string) bool {
	for _, link := range links {
		if link.ID == id {
			return true
		}
	}
	return false
}

// An active link must not serialize zero lifecycle times: the management
// UI read a present revoked_at as "Revoked" for every link.
func TestLinkJSONOmitsUnsetLifecycleTimes(t *testing.T) {
	data, err := json.Marshal(Link{ID: "l1", CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"revoked_at", "expires_at", "last_used_at"} {
		if bytes.Contains(data, []byte(field)) {
			t.Errorf("unset %s serialized: %s", field, data)
		}
	}
	revoked, _ := json.Marshal(Link{ID: "l1", RevokedAt: time.Unix(2, 0)})
	if !bytes.Contains(revoked, []byte(`"revoked_at"`)) {
		t.Fatalf("revocation time missing: %s", revoked)
	}
}
