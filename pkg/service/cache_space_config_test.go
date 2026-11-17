package service

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
)

func TestCachedFolderSpaceSetConfigAppliesLive(t *testing.T) {
	_, typed, _ := testMailService(t)
	next := NewFolderSpace(typed, authz.New(typed))
	access := UserAccess("alice", "test")
	cache := NewCachedFolderSpace(next, FolderCacheConfig{TTL: time.Minute, MaxEntries: 8, MaxBytes: 1 << 20})
	read := func(path string) {
		t.Helper()
		if _, err := cache.GetFolderByPath(t.Context(), access, path); err != nil {
			t.Fatal(err)
		}
	}
	read("INBOX")
	read("Archive")
	read("INBOX")
	if stats := cache.Stats(); stats.Entries != 2 || stats.Hits != 1 {
		t.Fatalf("warm stats=%+v", stats)
	}

	cache.SetConfig(FolderCacheConfig{TTL: time.Minute, MaxEntries: 1, MaxBytes: 1 << 20})
	if stats := cache.Stats(); stats.Entries != 1 || stats.Evictions != 1 {
		t.Fatalf("shrunk stats=%+v", stats)
	}

	cache.SetConfig(FolderCacheConfig{Disabled: true})
	if cache.Enabled() || cache.Stats().Entries != 0 {
		t.Fatalf("disabled cache keeps entries: %+v", cache.Stats())
	}
	before := cache.Stats()
	read("INBOX")
	read("INBOX")
	if stats := cache.Stats(); stats.Entries != 0 || stats.Hits != before.Hits {
		t.Fatalf("disabled cache served or kept reads: %+v", stats)
	}

	cache.SetConfig(FolderCacheConfig{TTL: time.Minute, MaxEntries: 8, MaxBytes: 1 << 20})
	read("INBOX")
	read("INBOX")
	if stats := cache.Stats(); !cache.Enabled() || stats.Entries != 1 || stats.Hits != before.Hits+1 {
		t.Fatalf("re-enabled stats=%+v", stats)
	}

	cache.SetConfig(FolderCacheConfig{TTL: time.Nanosecond, MaxEntries: 8, MaxBytes: 1 << 20})
	time.Sleep(time.Millisecond)
	hits := cache.Stats().Hits
	read("INBOX")
	if cache.Stats().Hits != hits {
		t.Fatal("shortened lifetime did not expire an already cached read")
	}
}
