package main

import (
	"path/filepath"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
)

func TestAccountRootsApplyLive(t *testing.T) {
	s := &server{}
	t.Cleanup(func() {
		s.cleanup.run(true)
	})
	if err := s.openRuntime(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := s.openAccounts(); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(t.TempDir(), "extra")
	patchAndApply(t, s, map[string]any{"account_storage_roots": []any{"default=accounts", "extra=" + extra}, "primary_account_root": "extra", "account_idle_close_seconds": 60})
	for _, key := range []string{"account_storage_roots", "primary_account_root", "account_idle_close_seconds"} {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	if len(s.accountManager.Roots()) != 2 || s.accountManager.Root() != extra {
		t.Fatalf("roots=%v primary=%s", s.accountManager.Roots(), s.accountManager.Root())
	}
	if targets := s.capacityTargetList(); len(targets) != 3 {
		t.Fatalf("capacity targets = %+v", targets)
	}
}

func TestStorageEncryptionDefaultAppliesLive(t *testing.T) {
	s := &server{}
	t.Cleanup(func() {
		s.cleanup.run(true)
	})
	if err := s.openRuntime(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := s.openAccounts(); err != nil {
		t.Fatal(err)
	}
	if s.accountManager.EncryptionDefault() || !s.accountManager.EncryptionAvailable() {
		t.Fatalf("initial encryption default=%t available=%t", s.accountManager.EncryptionDefault(), s.accountManager.EncryptionAvailable())
	}
	patchAndApply(t, s, map[string]any{"storage_encryption_default": true})
	if status := applyState(t, s, "storage_encryption_default"); status.State != config.ApplyEffective || status.RestartRequired {
		t.Fatalf("storage_encryption_default state = %+v", status)
	}
	if !s.accountManager.EncryptionDefault() {
		t.Fatal("storage_encryption_default did not reach the account manager")
	}
}
