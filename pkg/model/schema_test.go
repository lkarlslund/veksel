package model

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestSystemSchemaUpgradesCoverEveryVersion(t *testing.T) {
	if len(systemSchemaUpgrades) != SystemSchemaVersion-1 {
		t.Fatalf("%d upgrade steps for schema %d", len(systemSchemaUpgrades), SystemSchemaVersion)
	}
	for version := 1; version < SystemSchemaVersion; version++ {
		if systemSchemaUpgrades[version] == nil {
			t.Fatalf("no upgrade step from schema %d", version)
		}
	}
	for _, namespace := range retiredNamespaces {
		if slices.Contains(Namespaces(), namespace) {
			t.Fatalf("retired namespace %q is still a model namespace", namespace)
		}
	}
}

func TestInitializeSystemStoreRetiresDeletedStoreNamespaces(t *testing.T) {
	for _, recorded := range []int{0, 1} {
		t.Run("from schema "+strconv.Itoa(recorded), func(t *testing.T) {
			ctx := t.Context()
			ts := testStore(t)
			s := ts.Store()
			for _, namespace := range retiredNamespaces {
				if err := s.CreateNamespace(ctx, namespace); err != nil {
					t.Fatal(err)
				}
				if err := s.Set(ctx, namespace, "stale", []byte(`{}`)); err != nil {
					t.Fatal(err)
				}
			}
			if recorded > 0 {
				if err := ts.EnsureNamespace(ctx, NSSchema); err != nil {
					t.Fatal(err)
				}
				if err := s.Set(ctx, NSSchema, systemSchemaKey, []byte(strconv.Itoa(recorded))); err != nil {
					t.Fatal(err)
				}
			}
			// The second run proves the upgrade is idempotent.
			for range 2 {
				if err := InitializeSystemStore(ctx, ts); err != nil {
					t.Fatal(err)
				}
			}
			for _, namespace := range retiredNamespaces {
				if exists, err := s.NamespaceExists(ctx, namespace); err != nil || exists {
					t.Fatalf("retired namespace %q exists = %v, %v", namespace, exists, err)
				}
			}
			if version, err := ReadSystemSchemaVersion(ctx, s); err != nil || version != SystemSchemaVersion {
				t.Fatalf("schema version = %d, %v", version, err)
			}
		})
	}
}

func TestInitializeSystemStoreClearsLegacyUserAPIKeys(t *testing.T) {
	ctx := t.Context()
	ts := testStore(t)
	if err := InitializeSystemStore(ctx, ts); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(ctx, "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := ts.Get(ctx, NSUsers, "alice", &record); err != nil {
		t.Fatal(err)
	}
	record["api_key_hash"] = "$2a$10$stale"
	if err := ts.Set(ctx, NSUsers, "alice", record); err != nil {
		t.Fatal(err)
	}
	if err := ts.Store().Set(ctx, NSSchema, systemSchemaKey, []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := InitializeSystemStore(ctx, ts); err != nil {
		t.Fatal(err)
	}
	raw, err := ts.Store().Get(ctx, NSUsers, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "api_key_hash") {
		t.Fatalf("legacy API key hash survived the upgrade: %s", raw)
	}
	user, err := ts.UserStore().Get(ctx, "alice")
	if err != nil || user.DisplayName != "Alice" || user.PasswordHash == "" {
		t.Fatalf("upgraded user = %+v, %v", user, err)
	}
}

func TestUpgradeSystemStoreUpgradesOlderDataInCurrentStore(t *testing.T) {
	ctx := t.Context()
	ts := testStore(t)
	if err := InitializeSystemStore(ctx, ts); err != nil {
		t.Fatal(err)
	}
	// Data merged from an old archive brings a retired namespace back.
	if err := ts.Store().CreateNamespace(ctx, retiredNamespaces[0]); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeSystemStore(ctx, ts.Store(), 1); err != nil {
		t.Fatal(err)
	}
	if exists, err := ts.Store().NamespaceExists(ctx, retiredNamespaces[0]); err != nil || exists {
		t.Fatalf("retired namespace exists = %v, %v", exists, err)
	}
	if err := UpgradeSystemStore(ctx, ts.Store(), SystemSchemaVersion+1); err == nil {
		t.Fatal("newer data was accepted")
	}
}
