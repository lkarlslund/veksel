package service

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestCachedFolderSpaceHitsClonesAndInvalidates(t *testing.T) {
	_, typed, _ := testMailService(t)
	next := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "test")
	inbox, err := next.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := next.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: cached\r\n\r\nbody"), Headers: map[string]string{"Subject": "cached"}})
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 8, MaxBytes: 1 << 20})
	first, err := cache.GetItem(t.Context(), access, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	first.Data[0] = 'X'
	first.Headers["Mutated"] = "yes"
	second, err := cache.GetItem(t.Context(), access, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.Data[0] == 'X' || second.Headers["Mutated"] != "" {
		t.Fatalf("caller mutated cached authority: %#v", second)
	}
	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 2 || stats.Entries != 2 {
		t.Fatalf("stats after hit=%+v", stats)
	}
	if _, err := cache.SetFlags(t.Context(), access, created.ID, []string{model.FlagSeen}); err != nil {
		t.Fatal(err)
	}
	if cache.Stats().Entries != 0 {
		t.Fatal("successful mutation did not invalidate reads")
	}
	updated, err := cache.GetItem(t.Context(), access, created.ID)
	if err != nil || len(updated.Flags) != 1 || updated.Flags[0] != model.FlagSeen {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
}

func TestCachedFolderSpaceSkipsLargeItems(t *testing.T) {
	_, typed, _ := testMailService(t)
	next := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "test")
	inbox, err := next.GetFolderByPath(t.Context(), access, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 64, MaxBytes: 64 << 10})
	large, err := next.CreateItem(t.Context(), access, inbox.ID, ItemInput{Data: append([]byte("Subject: large\r\n\r\n"), make([]byte, 4<<10)...)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetItem(t.Context(), access, large.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetItem(t.Context(), access, large.ID); err != nil {
		t.Fatal(err)
	}
	if stats := cache.Stats(); stats.Hits != 0 {
		t.Fatalf("an item over a 64th of the cache was cached: %+v", stats)
	}
}

func TestCachedFolderSpaceExpiresAndEvicts(t *testing.T) {
	_, typed, _ := testMailService(t)
	next := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "test")
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Millisecond, MaxEntries: 1, MaxBytes: 1 << 20})
	if _, err := cache.GetFolderByPath(t.Context(), access, "INBOX"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetFolderByPath(t.Context(), access, "Archive"); err != nil {
		t.Fatal(err)
	}
	if stats := cache.Stats(); stats.Entries != 1 || stats.Evictions != 1 {
		t.Fatalf("eviction stats=%+v", stats)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := cache.GetFolderByPath(t.Context(), access, "Archive"); err != nil {
		t.Fatal(err)
	}
	if cache.Stats().Misses != 3 {
		t.Fatalf("expiration stats=%+v", cache.Stats())
	}
}

func TestCachedFolderSpaceDoesNotCacheDelegatedReads(t *testing.T) {
	_, typed, _ := testMailService(t)
	next := NewFolderSpace(typed, authz.New(typed))
	alice := UserAccess("alice", "test")
	inbox, err := next.GetFolderByPath(t.Context(), alice, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := next.CreateItem(t.Context(), alice, inbox.ID, ItemInput{Data: []byte("Subject: shared\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.NewPolicyStore(typed).Create(t.Context(), model.PolicyBinding{
		Principal:   model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:    model.ResourceRef{Kind: model.ResourceFolder, ID: inbox.ID},
		Effect:      model.EffectAllow,
		RoleID:      authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf,
		GrantedBy:   "alice",
	}); err != nil {
		t.Fatal(err)
	}

	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 8, MaxBytes: 1 << 20})
	bob := UserAccess("bob", "test")
	for range 2 {
		if item, err := cache.GetItem(t.Context(), bob, created.ID); err != nil || item.ID != created.ID {
			t.Fatalf("delegated GetItem = %#v, %v", item, err)
		}
	}
	if stats := cache.Stats(); stats.Entries != 0 || stats.Hits != 0 {
		t.Fatalf("delegated data entered cache: %+v", stats)
	}
}

func BenchmarkCachedFolderSpaceGetItem(b *testing.B) {
	_, typed, _ := testMailService(b)
	next := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "benchmark")
	inbox, err := next.GetFolderByPath(b.Context(), access, "INBOX")
	if err != nil {
		b.Fatal(err)
	}
	created, err := next.CreateItem(b.Context(), access, inbox.ID, ItemInput{Data: []byte("Subject: benchmark\r\n\r\nbody")})
	if err != nil {
		b.Fatal(err)
	}
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 8, MaxBytes: 1 << 20})
	if _, err := cache.GetItem(b.Context(), access, created.ID); err != nil {
		b.Fatal(err)
	}

	b.Run("direct", func(b *testing.B) {
		for range b.N {
			if _, err := next.GetItem(b.Context(), access, created.ID); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		for range b.N {
			if _, err := cache.GetItem(b.Context(), access, created.ID); err != nil {
				b.Fatal(err)
			}
		}
	})
}
