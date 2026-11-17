package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/store"
)

// NSSchema records the on-disk layout version of the system store.
const NSSchema = "schema"

// SystemSchemaVersion is the system-store layout this binary reads and writes.
// Increase it, and add the upgrade step to systemSchemaUpgrades, whenever a
// change makes existing system data unreadable by older binaries or leaves
// data behind that must be rewritten or removed.
const SystemSchemaVersion = 3

const systemSchemaKey = "system"

// systemSchemaUpgrades[v] upgrades a version v store to version v+1. Steps
// must be idempotent: the new version is recorded only after every step has
// succeeded, so an interrupted upgrade runs them again. Unversioned (version
// 0) stores share the version 1 layout.
var systemSchemaUpgrades = map[int]func(context.Context, store.Store) error{
	1: retireNamespaces,
	2: clearLegacyUserAPIKeys,
}

// retiredNamespaces belonged to stores whose handlers were deleted. Nothing
// reads or writes them any more.
var retiredNamespaces = []string{
	"forwarding",               // per-user forwarding rules; forwarding lives on User
	"notification_preferences", // per-user notification preferences
	"rate_limits",              // per-user rate limits
	"templates",                // email templates; message templates are account-folder items
	"dmarc_reports",            // legacy admin DMARC report list; see dmarc_aggregates
	"delegations",              // reserved but never written; delegations are policy bindings
}

func retireNamespaces(ctx context.Context, s store.Store) error {
	for _, namespace := range retiredNamespaces {
		if err := s.DeleteNamespace(ctx, namespace); err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("delete retired namespace %q: %w", namespace, err)
		}
	}
	return nil
}

// clearLegacyUserAPIKeys removes the retired per-user API key hash from user
// records, so a stale credential hash does not linger in the store or in
// backups. Records are rewritten as raw JSON to keep every other field.
func clearLegacyUserAPIKeys(ctx context.Context, s store.Store) error {
	keys, err := s.List(ctx, NSUsers)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	for _, key := range keys {
		value, err := s.Get(ctx, NSUsers, key)
		if err != nil {
			return fmt.Errorf("read user %q: %w", key, err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil {
			continue
		}
		if _, ok := fields["api_key_hash"]; !ok {
			continue
		}
		delete(fields, "api_key_hash")
		if value, err = json.Marshal(fields); err != nil {
			return fmt.Errorf("encode user %q: %w", key, err)
		}
		if err := s.Set(ctx, NSUsers, key, value); err != nil {
			return fmt.Errorf("write user %q: %w", key, err)
		}
	}
	return nil
}

// ErrSystemSchemaTooNew reports a store or backup written by a newer binary.
var ErrSystemSchemaTooNew = errors.New("system store schema is newer than this binary supports")

// ReadSystemSchemaVersion returns the recorded system schema version, or 0
// for a store created before versions were recorded (or not yet initialized).
func ReadSystemSchemaVersion(ctx context.Context, s store.Store) (int, error) {
	value, err := s.Get(ctx, NSSchema, systemSchemaKey)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read system schema version: %w", err)
	}
	version, err := strconv.Atoi(string(value))
	if err != nil || version < 1 {
		return 0, fmt.Errorf("invalid system schema version %q", value)
	}
	return version, nil
}

// CheckSystemSchemaVersion refuses versions this binary cannot interpret.
func CheckSystemSchemaVersion(version int) error {
	if version > SystemSchemaVersion {
		return fmt.Errorf("%w: found version %d, this binary supports up to %d; install a newer Veksel release", ErrSystemSchemaTooNew, version, SystemSchemaVersion)
	}
	return nil
}

// InitializeSystemStore prepares a system store for use: it refuses a store
// written by a newer binary before changing anything, ensures every model
// namespace exists, upgrades older data, and records the current schema
// version.
func InitializeSystemStore(ctx context.Context, ts *TypedStore) error {
	return UpgradeSystemStore(ctx, ts.Store(), SystemSchemaVersion)
}

// UpgradeSystemStore is InitializeSystemStore for a store that has just
// received data of schema version dataVersion, such as a restored backup.
// The upgrade starts from the older of dataVersion and the recorded version,
// so data merged from an old archive is upgraded even into a current store.
func UpgradeSystemStore(ctx context.Context, s store.Store, dataVersion int) error {
	recorded, err := ReadSystemSchemaVersion(ctx, s)
	if err != nil {
		return err
	}
	if err := CheckSystemSchemaVersion(max(recorded, dataVersion)); err != nil {
		return err
	}
	for _, namespace := range Namespaces() {
		if err := ensureNamespace(ctx, s, namespace); err != nil {
			return fmt.Errorf("ensure namespace %q: %w", namespace, err)
		}
	}
	for version := max(min(recorded, dataVersion), 1); version < SystemSchemaVersion; version++ {
		if err := systemSchemaUpgrades[version](ctx, s); err != nil {
			return fmt.Errorf("upgrade system store from schema %d: %w", version, err)
		}
	}
	if recorded == SystemSchemaVersion {
		return nil
	}
	if err := s.Set(ctx, NSSchema, systemSchemaKey, []byte(strconv.Itoa(SystemSchemaVersion))); err != nil {
		return fmt.Errorf("record system schema version: %w", err)
	}
	return nil
}

func ensureNamespace(ctx context.Context, s store.Store, namespace string) error {
	exists, err := s.NamespaceExists(ctx, namespace)
	if err != nil || exists {
		return err
	}
	return s.CreateNamespace(ctx, namespace)
}
