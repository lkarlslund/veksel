package model

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// RFC 5464 limits
const (
	MetadataMaxEntryName  = 255
	MetadataMaxEntryValue = 1024
)

// MetadataEntry represents a single metadata entry per RFC 5464.
// Entry names start with /private/ or /shared/.
type MetadataEntry struct {
	Name  string `json:"name"`  // e.g. "/shared/displayname"
	Value string `json:"value"` // the metadata value
}

// MetadataStore provides CRUD for RFC 5464 metadata entries.
type MetadataStore struct {
	ts *TypedStore
}

// Lazy accessor on TypedStore

// MetadataStore returns the MetadataStore instance.
func (ts *TypedStore) MetadataStore() *MetadataStore {
	return &MetadataStore{ts: ts}
}

// ValidateEntryName checks the entry name per RFC 5464 §5.
// Entry names must start with /private/ or /shared/ and be at most 255 bytes.
func ValidateEntryName(name string) error {
	if len(name) == 0 || len(name) > MetadataMaxEntryName {
		return fmt.Errorf("metadata entry name length must be 1-%d, got %d", MetadataMaxEntryName, len(name))
	}
	if !strings.HasPrefix(name, "/private/") && !strings.HasPrefix(name, "/shared/") {
		return fmt.Errorf("metadata entry name must start with /private/ or /shared/, got %q", name)
	}
	return nil
}

// ValidateEntryValue checks the value length per RFC 5464 §5.
func ValidateEntryValue(value string) error {
	if len(value) > MetadataMaxEntryValue {
		return fmt.Errorf("metadata entry value length must be <= %d, got %d", MetadataMaxEntryValue, len(value))
	}
	return nil
}

// MatchScope checks whether an entry name matches a scope pattern.
// Scope "/" matches all entries.
// Scope "/shared/*" matches entries starting with "/shared/".
// Scope "/private/*" matches entries starting with "/private/".
func MatchScope(entryName, scope string) bool {
	if scope == "/" {
		return true
	}
	if scope == "/shared/*" {
		return strings.HasPrefix(entryName, "/shared/")
	}
	if scope == "/private/*" {
		return strings.HasPrefix(entryName, "/private/")
	}
	return false
}

// Set stores a metadata entry for the given scope (mailbox or server).
// A nil value deletes the entry.
func (ms *MetadataStore) Set(ctx context.Context, scope, entryName, value string) error {
	if err := ValidateEntryName(entryName); err != nil {
		return err
	}
	if value == "" {
		// Empty value means delete
		return ms.ts.Delete(ctx, NSMetadata, MetadataKey(scope, entryName))
	}
	if err := ValidateEntryValue(value); err != nil {
		return err
	}
	e := MetadataEntry{Name: entryName, Value: value}
	return ms.ts.Set(ctx, NSMetadata, MetadataKey(scope, entryName), e)
}

// Get returns a single metadata entry for the given scope.
func (ms *MetadataStore) Get(ctx context.Context, scope, entryName string) (MetadataEntry, error) {
	var e MetadataEntry
	if err := ms.ts.Get(ctx, NSMetadata, MetadataKey(scope, entryName), &e); err != nil {
		return e, err
	}
	return e, nil
}

// List returns all metadata entries for a scope that match the given scope pattern.
// Scope "/" returns all, "/shared/*" returns shared entries, "/private/*" returns private entries.
func (ms *MetadataStore) List(ctx context.Context, scope, scopePattern string) ([]MetadataEntry, error) {
	keys, err := ms.ts.Scan(ctx, NSMetadata, MetadataPrefix(scope))
	if err != nil {
		return nil, err
	}
	var entries []MetadataEntry
	for _, k := range keys {
		var e MetadataEntry
		if err := ms.ts.Get(ctx, NSMetadata, k, &e); err != nil {
			continue
		}
		if MatchScope(e.Name, scopePattern) {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// Delete removes a metadata entry.
func (ms *MetadataStore) Delete(ctx context.Context, scope, entryName string) error {
	return ms.ts.Delete(ctx, NSMetadata, MetadataKey(scope, entryName))
}

// Purge removes all metadata entries for a scope.
func (ms *MetadataStore) Purge(ctx context.Context, scope string) error {
	keys, err := ms.ts.Scan(ctx, NSMetadata, MetadataPrefix(scope))
	if err != nil {
		return err
	}
	var firstErr error
	for _, k := range keys {
		if err := ms.ts.Delete(ctx, NSMetadata, k); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ErrMetadataNotFound is returned when a metadata entry does not exist.
var ErrMetadataNotFound = errors.New("metadata entry not found")
