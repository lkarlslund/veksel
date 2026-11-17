package jsonstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/lkarlslund/veksel/pkg/store"
)

const batchJournalName = ".batch.json"

type batchContextKey struct{}

type batchKey struct {
	Namespace string
	Key       string
}

type batchValue struct {
	Value   []byte
	Deleted bool
}

type batchState struct {
	store      *Store
	changes    map[batchKey]batchValue
	namespaces map[string]batchNamespace
}

type diskBatch struct {
	Namespaces []diskNamespaceChange `json:"namespaces,omitempty"`
	Changes    []diskBatchChange     `json:"changes"`
}

type batchNamespace struct {
	Exists bool
	Reset  bool
}

type diskNamespaceChange struct {
	Namespace string `json:"namespace"`
	Exists    bool   `json:"exists"`
	Reset     bool   `json:"reset,omitempty"`
}

type diskBatchChange struct {
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
	Value     []byte `json:"value,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
}

func (s *Store) activeBatch(ctx context.Context) *batchState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(batchContextKey{}).(*batchState)
	if state == nil || state.store != s {
		return nil
	}
	return state
}

// Batch implements store.Batcher with a read-your-writes overlay and a
// recoverable write-ahead transaction file.
func (s *Store) Batch(ctx context.Context, fn func(context.Context) error) error {
	if active := s.activeBatch(ctx); active != nil {
		return fn(ctx)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	state := &batchState{store: s, changes: make(map[batchKey]batchValue), namespaces: make(map[string]batchNamespace)}
	batchCtx := context.WithValue(ctx, batchContextKey{}, state)
	if err := fn(batchCtx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(state.changes) == 0 && len(state.namespaces) == 0 {
		return nil
	}
	return s.commitBatch(state)
}

func (s *Store) batchGet(state *batchState, namespace, key string) ([]byte, error) {
	if !s.batchNamespaceExists(state, namespace) {
		return nil, store.ErrNotFound
	}
	if value, ok := state.changes[batchKey{Namespace: namespace, Key: key}]; ok {
		if value.Deleted {
			return nil, store.ErrNotFound
		}
		return append([]byte(nil), value.Value...), nil
	}
	if change, changed := state.namespaces[namespace]; changed && change.Reset {
		return nil, store.ErrNotFound
	}
	value, err := s.loadValue(namespace, key)
	if errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrNotFound
	}
	return value, err
}

func (s *Store) batchKeys(state *batchState, namespace string) (map[string]struct{}, error) {
	if !s.batchNamespaceExists(state, namespace) {
		return nil, store.ErrNotFound
	}
	current := s.keys[namespace]
	if change, changed := state.namespaces[namespace]; changed && change.Reset {
		current = nil
	}
	result := make(map[string]struct{}, len(current))
	for key := range current {
		result[key] = struct{}{}
	}
	for key, value := range state.changes {
		if key.Namespace != namespace {
			continue
		}
		if value.Deleted {
			delete(result, key.Key)
		} else {
			result[key.Key] = struct{}{}
		}
	}
	return result, nil
}

func (s *Store) batchNamespaceExists(state *batchState, namespace string) bool {
	if change, changed := state.namespaces[namespace]; changed {
		return change.Exists
	}
	_, exists := s.ns[namespace]
	return exists
}

func (s *Store) batchNamespaces(state *batchState) []string {
	result := make(map[string]struct{}, len(s.ns)+len(state.namespaces))
	for namespace := range s.ns {
		result[namespace] = struct{}{}
	}
	for namespace, change := range state.namespaces {
		if change.Exists {
			result[namespace] = struct{}{}
		} else {
			delete(result, namespace)
		}
	}
	namespaces := make([]string, 0, len(result))
	for namespace := range result {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces
}

func (s *Store) commitBatch(state *batchState) error {
	disk := diskBatch{Namespaces: make([]diskNamespaceChange, 0, len(state.namespaces)), Changes: make([]diskBatchChange, 0, len(state.changes))}
	for namespace, change := range state.namespaces {
		disk.Namespaces = append(disk.Namespaces, diskNamespaceChange{Namespace: namespace, Exists: change.Exists, Reset: change.Reset})
	}
	sort.Slice(disk.Namespaces, func(i, j int) bool { return disk.Namespaces[i].Namespace < disk.Namespaces[j].Namespace })
	touched := make(map[string]struct{})
	for key, value := range state.changes {
		disk.Changes = append(disk.Changes, diskBatchChange{Namespace: key.Namespace, Key: key.Key, Value: value.Value, Deleted: value.Deleted})
		touched[key.Namespace] = struct{}{}
	}
	sort.Slice(disk.Changes, func(i, j int) bool {
		if disk.Changes[i].Namespace == disk.Changes[j].Namespace {
			return disk.Changes[i].Key < disk.Changes[j].Key
		}
		return disk.Changes[i].Namespace < disk.Changes[j].Namespace
	})
	// Make every touched namespace's key snapshot authoritative before the
	// transaction journal appears. Recovery can then replay without ambiguity.
	for namespace := range touched {
		if change, changed := state.namespaces[namespace]; changed && (change.Reset || !change.Exists) {
			continue
		}
		if _, exists := s.ns[namespace]; !exists {
			continue
		}
		if err := s.compactKeys(namespace); err != nil {
			return fmt.Errorf("compact %q before batch: %w", namespace, err)
		}
	}
	encoded, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(s.dir, batchJournalName), encoded, 0o600); err != nil {
		return fmt.Errorf("persist batch journal: %w", err)
	}
	if err := s.applyDiskBatch(disk); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.dir, batchJournalName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove batch journal: %w", err)
	}
	return syncDir(s.dir)
}

func (s *Store) recoverBatch() error {
	path := filepath.Join(s.dir, batchJournalName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk diskBatch
	if err := json.Unmarshal(data, &disk); err != nil {
		return fmt.Errorf("decode batch journal: %w", err)
	}
	if err := s.applyDiskBatch(disk); err != nil {
		return fmt.Errorf("recover batch: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.dir)
}

func (s *Store) applyDiskBatch(batch diskBatch) error {
	for _, change := range batch.Namespaces {
		if !change.Exists {
			continue
		}
		if change.Reset {
			if err := os.RemoveAll(s.nsDir(change.Namespace)); err != nil {
				return err
			}
			delete(s.ns, change.Namespace)
			delete(s.keys, change.Namespace)
			delete(s.keyMutations, change.Namespace)
		}
		if _, exists := s.ns[change.Namespace]; exists {
			continue
		}
		if err := os.MkdirAll(s.nsDir(change.Namespace), 0o755); err != nil {
			return err
		}
		s.ns[change.Namespace] = struct{}{}
		s.keys[change.Namespace] = make(map[string]struct{})
		s.keyMutations[change.Namespace] = 0
		if err := writeFileSync(s.keysFile(change.Namespace), []byte("[]"), 0o644); err != nil {
			return err
		}
		if err := writeFileSync(s.keyJournalFile(change.Namespace), nil, 0o644); err != nil {
			return err
		}
	}
	touched := make(map[string]struct{})
	for _, change := range batch.Changes {
		if _, ok := s.ns[change.Namespace]; !ok {
			return fmt.Errorf("batch namespace %q: %w", change.Namespace, store.ErrNotFound)
		}
		touched[change.Namespace] = struct{}{}
		if change.Deleted {
			if err := os.Remove(s.valueFile(change.Namespace, change.Key)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			delete(s.keys[change.Namespace], change.Key)
			continue
		}
		if err := s.saveValueDurable(change.Namespace, change.Key, change.Value); err != nil {
			return err
		}
		s.keys[change.Namespace][change.Key] = struct{}{}
	}
	for namespace := range touched {
		data, err := json.Marshal(sortedKeys(s.keys[namespace]))
		if err != nil {
			return err
		}
		if err := writeFileSync(s.keysFile(namespace), data, 0o644); err != nil {
			return err
		}
		if err := writeFileSync(s.keyJournalFile(namespace), nil, 0o644); err != nil {
			return err
		}
		s.keyMutations[namespace] = 0
	}
	for _, change := range batch.Namespaces {
		if change.Exists {
			continue
		}
		if err := os.RemoveAll(s.nsDir(change.Namespace)); err != nil {
			return err
		}
		delete(s.ns, change.Namespace)
		delete(s.keys, change.Namespace)
		delete(s.keyMutations, change.Namespace)
	}
	return s.saveNamespacesDurable()
}

func (s *Store) saveNamespacesDurable() error {
	namespaces := make([]string, 0, len(s.ns))
	for namespace := range s.ns {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	data, err := json.Marshal(namespaces)
	if err != nil {
		return err
	}
	return writeFileSync(s.nsFile(), data, 0o644)
}

func sortedKeys(keys map[string]struct{}) []string {
	result := keySlice(keys)
	sort.Strings(result)
	return result
}

func (s *Store) saveValueDurable(namespace, key string, value []byte) error {
	envelope := struct {
		Value string `json:"value"`
	}{Value: base64Value(value)}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return writeFileSync(s.valueFile(namespace, key), data, 0o644)
}

func base64Value(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func writeFileSync(path string, data []byte, mode os.FileMode) (retErr error) {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".jsonstore-tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); retErr == nil && closeErr != nil {
				retErr = closeErr
			}
		}
		_ = os.Remove(temporary)
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDir(directory)
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
