// Package jsonstore implements store.Store using flat JSON files on disk.
//
// Layout:
//
//	data/
//	  namespaces.json  — list of namespace names
//	 <namespace>/
//	    keys.json  — list of keys
//	   <key>.json  — raw value bytes (base64-encoded)
//
// This backend is not optimized for performance. It is intended for
// development, debugging, and small deployments.
package jsonstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleStorage)

// Store implements store.Store using flat JSON files.
type Store struct {
	// mu guards the in-memory indexes and closed; Close takes it exclusively.
	mu           sync.RWMutex
	closed       bool
	dir          string
	ns           map[string]struct{}            // track namespaces in memory
	keys         map[string]map[string]struct{} // namespace keys loaded once at startup
	keyMutations map[string]int
}

const keyJournalCompactThreshold = 10_000

// New returns a new JSON-backed store rooted at dir.
// Creates dir if it does not exist.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{
		dir:          dir,
		ns:           make(map[string]struct{}),
		keys:         make(map[string]map[string]struct{}),
		keyMutations: make(map[string]int),
	}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load store: %w", err)
	}
	if err := s.recoverBatch(); err != nil {
		return nil, fmt.Errorf("recover store batch: %w", err)
	}
	return s, nil
}

// rlock admits a read and returns the function that releases it, or
// store.ErrClosed once the store is closed.
func (s *Store) rlock() (unlock func(), err error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, store.ErrClosed
	}
	return s.mu.RUnlock, nil
}

// lock admits a mutation, like rlock.
func (s *Store) lock() (unlock func(), err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, store.ErrClosed
	}
	return s.mu.Unlock, nil
}

func (s *Store) nsDir(ns string) string {
	return filepath.Join(s.dir, ns)
}

func (s *Store) nsFile() string {
	return filepath.Join(s.dir, "namespaces.json")
}

func (s *Store) keysFile(ns string) string {
	return filepath.Join(s.nsDir(ns), "keys.json")
}

func (s *Store) keyJournalFile(ns string) string {
	return filepath.Join(s.nsDir(ns), "keys.log")
}

func (s *Store) valueFile(ns, key string) string {
	return filepath.Join(s.nsDir(ns), sanitize(key)+".json")
}

func sanitize(key string) string {
	return strings.NewReplacer("/", "_", "\\ ", "_", "..", "_").Replace(key)
}

func (s *Store) load() error {
	// Load namespaces
	nsPath := s.nsFile()
	if _, err := os.Stat(nsPath); err != nil {
		if os.IsNotExist(err) {
			return s.saveNamespaces()
		}
		log.Error("jsonstore: stat namespaces file", "path", nsPath, "error", err)
		return err
	}
	data, err := os.ReadFile(nsPath)
	if err != nil {
		log.Error("jsonstore: read namespaces file", "path", nsPath, "error", err)
		return err
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		log.Error("jsonstore: unmarshal namespaces", "path", nsPath, "error", err)
		return err
	}
	for _, n := range names {
		s.ns[n] = struct{}{}
		keys, err := s.loadKeys(n)
		if err != nil {
			return fmt.Errorf("load keys for namespace %q: %w", n, err)
		}
		s.keys[n] = keySet(keys)
		mutations, err := s.replayKeyJournal(n, s.keys[n])
		if err != nil {
			return fmt.Errorf("replay key journal for namespace %q: %w", n, err)
		}
		s.keyMutations[n] = mutations
	}
	return nil
}

func (s *Store) saveNamespaces() error {
	var names []string
	for n := range s.ns {
		names = append(names, n)
	}
	sort.Strings(names)
	data, err := json.Marshal(names)
	if err != nil {
		return err
	}
	return os.WriteFile(s.nsFile(), data, 0o644)
}

func (s *Store) loadKeys(ns string) ([]string, error) {
	f := s.keysFile(ns)
	if _, err := os.Stat(f); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *Store) saveKeys(ns string, keys []string) error {
	sort.Strings(keys)
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(s.keysFile(ns), data, 0o644)
}

func keySet(keys []string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	return set
}

func keySlice(keys map[string]struct{}) []string {
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	return result
}

func (s *Store) replayKeyJournal(ns string, keys map[string]struct{}) (int, error) {
	file, err := os.Open(s.keyJournalFile(ns))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	mutations := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 1 || (line[0] != '+' && line[0] != '-') {
			return 0, fmt.Errorf("invalid key journal record %q", line)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(line[1:])
		if err != nil {
			return 0, fmt.Errorf("decode key journal record: %w", err)
		}
		key := string(decoded)
		if line[0] == '+' {
			keys[key] = struct{}{}
		} else {
			delete(keys, key)
		}
		mutations++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return mutations, nil
}

func (s *Store) appendKeyMutation(ns string, operation byte, key string) error {
	file, err := os.OpenFile(s.keyJournalFile(ns), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	record := string(operation) + base64.RawURLEncoding.EncodeToString([]byte(key)) + "\n"
	_, writeErr := file.WriteString(record)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	s.keyMutations[ns]++
	if s.keyMutations[ns] >= keyJournalCompactThreshold {
		// The journal record is already durable enough for this backend. A
		// failed compaction can be retried later without failing the mutation.
		_ = s.compactKeys(ns)
	}
	return nil
}

func (s *Store) compactKeys(ns string) error {
	if err := s.saveKeys(ns, keySlice(s.keys[ns])); err != nil {
		return err
	}
	if err := os.WriteFile(s.keyJournalFile(ns), nil, 0o644); err != nil {
		return err
	}
	s.keyMutations[ns] = 0
	return nil
}

func (s *Store) loadValue(ns, key string) ([]byte, error) {
	data, err := os.ReadFile(s.valueFile(ns, key))
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(envelope.Value)
}

func (s *Store) saveValue(ns, key string, value []byte) error {
	envelope := struct {
		Value string `json:"value"`
	}{
		Value: base64.StdEncoding.EncodeToString(value),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		log.Error("jsonstore: marshal value", "namespace", ns, "key", key, "error", err)
		return err
	}
	if err := os.WriteFile(s.valueFile(ns, key), data, 0o644); err != nil {
		log.Error("jsonstore: write value", "namespace", ns, "key", key, "error", err)
		return err
	}
	return nil
}

func (s *Store) deleteValue(ns, key string) error {
	return os.Remove(s.valueFile(ns, key))
}

func (s *Store) keyExists(ns, key string) (bool, error) {
	_, err := os.Stat(s.valueFile(ns, key))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// Get implements store.Store.
func (s *Store) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	if batch := s.activeBatch(ctx); batch != nil {
		return s.batchGet(batch, namespace, key)
	}
	if s.activeView(ctx) {
		return s.getLocked(namespace, key)
	}
	unlock, err := s.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.getLocked(namespace, key)
}

func (s *Store) getLocked(namespace, key string) ([]byte, error) {
	if _, ok := s.ns[namespace]; !ok {
		return nil, store.ErrNotFound
	}
	v, err := s.loadValue(namespace, key)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("load value: %w", err)
	}
	return v, nil
}

// Set implements store.Store.
func (s *Store) Set(ctx context.Context, namespace, key string, value []byte) error {
	if batch := s.activeBatch(ctx); batch != nil {
		if !s.batchNamespaceExists(batch, namespace) {
			return store.ErrNotFound
		}
		batch.changes[batchKey{Namespace: namespace, Key: key}] = batchValue{Value: append([]byte(nil), value...)}
		return nil
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, ok := s.ns[namespace]; !ok {
		return store.ErrNotFound
	}
	if err := s.saveValue(namespace, key, value); err != nil {
		return fmt.Errorf("save value: %w", err)
	}
	if _, found := s.keys[namespace][key]; !found {
		s.keys[namespace][key] = struct{}{}
		if err := s.appendKeyMutation(namespace, '+', key); err != nil {
			delete(s.keys[namespace], key)
			return fmt.Errorf("journal key: %w", err)
		}
	}
	return nil
}

// Put implements store.Store.
func (s *Store) Put(ctx context.Context, namespace, key string, value []byte) error {
	if batch := s.activeBatch(ctx); batch != nil {
		if _, err := s.batchGet(batch, namespace, key); err == nil {
			return store.ErrExists
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		batch.changes[batchKey{Namespace: namespace, Key: key}] = batchValue{Value: append([]byte(nil), value...)}
		return nil
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, ok := s.ns[namespace]; !ok {
		return store.ErrNotFound
	}
	exists, err := s.keyExists(namespace, key)
	if err != nil {
		return fmt.Errorf("check key: %w", err)
	}
	if exists {
		return store.ErrExists
	}
	if err := s.saveValue(namespace, key, value); err != nil {
		return fmt.Errorf("save value: %w", err)
	}
	s.keys[namespace][key] = struct{}{}
	if err := s.appendKeyMutation(namespace, '+', key); err != nil {
		delete(s.keys[namespace], key)
		return err
	}
	return nil
}

// Delete implements store.Store.
func (s *Store) Delete(ctx context.Context, namespace, key string) error {
	if batch := s.activeBatch(ctx); batch != nil {
		if _, err := s.batchGet(batch, namespace, key); err != nil {
			return err
		}
		batch.changes[batchKey{Namespace: namespace, Key: key}] = batchValue{Deleted: true}
		return nil
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, ok := s.ns[namespace]; !ok {
		return store.ErrNotFound
	}
	exists, err := s.keyExists(namespace, key)
	if err != nil {
		return fmt.Errorf("check key: %w", err)
	}
	if !exists {
		return store.ErrNotFound
	}
	if err := s.deleteValue(namespace, key); err != nil {
		return fmt.Errorf("delete value: %w", err)
	}
	delete(s.keys[namespace], key)
	if err := s.appendKeyMutation(namespace, '-', key); err != nil {
		s.keys[namespace][key] = struct{}{}
		return err
	}
	return nil
}

// List implements store.Store.
func (s *Store) List(ctx context.Context, namespace string) ([]string, error) {
	if batch := s.activeBatch(ctx); batch != nil {
		keys, err := s.batchKeys(batch, namespace)
		if err != nil {
			return nil, err
		}
		return sortedKeys(keys), nil
	}
	if s.activeView(ctx) {
		return s.listLocked(namespace)
	}
	unlock, err := s.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.listLocked(namespace)
}

func (s *Store) listLocked(namespace string) ([]string, error) {
	if _, ok := s.ns[namespace]; !ok {
		return nil, store.ErrNotFound
	}
	keys := keySlice(s.keys[namespace])
	sort.Strings(keys)
	return keys, nil
}

// Scan implements store.Store.
func (s *Store) Scan(ctx context.Context, namespace, prefix string) ([]string, error) {
	if batch := s.activeBatch(ctx); batch != nil {
		keys, err := s.batchKeys(batch, namespace)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0)
		for key := range keys {
			if strings.HasPrefix(key, prefix) {
				out = append(out, key)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	if s.activeView(ctx) {
		return s.scanLocked(namespace, prefix)
	}
	unlock, err := s.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.scanLocked(namespace, prefix)
}

func (s *Store) scanLocked(namespace, prefix string) ([]string, error) {
	if _, ok := s.ns[namespace]; !ok {
		return nil, store.ErrNotFound
	}
	var out []string
	for k := range s.keys[namespace] {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// CompareAndSwap implements store.Store.
func (s *Store) CompareAndSwap(ctx context.Context, namespace, key string, oldValue, newValue []byte) error {
	if batch := s.activeBatch(ctx); batch != nil {
		current, err := s.batchGet(batch, namespace, key)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, oldValue) {
			return store.ErrPreconditionFailed
		}
		batch.changes[batchKey{Namespace: namespace, Key: key}] = batchValue{Value: append([]byte(nil), newValue...)}
		return nil
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, ok := s.ns[namespace]; !ok {
		return store.ErrNotFound
	}
	current, err := s.loadValue(namespace, key)
	if err != nil {
		if os.IsNotExist(err) {
			return store.ErrNotFound
		}
		return fmt.Errorf("load value: %w", err)
	}
	if !bytes.Equal(current, oldValue) {
		return store.ErrPreconditionFailed
	}
	return s.saveValue(namespace, key, newValue)
}

// Iterate implements store.Store.
func (s *Store) Iterate(ctx context.Context, namespace, prefix string, fn store.IterCallback) error {
	return s.IterateFrom(ctx, namespace, prefix, "", fn)
}

var _ store.RangeIterator = (*Store)(nil)

// IterateFrom implements store.RangeIterator. The key index is held in
// memory, so only the values from start onward are loaded.
func (s *Store) IterateFrom(ctx context.Context, namespace, prefix, start string, fn store.IterCallback) error {
	if batch := s.activeBatch(ctx); batch != nil {
		keys, err := s.Scan(ctx, namespace, prefix)
		if err != nil {
			return err
		}
		for _, key := range keys[sort.SearchStrings(keys, start):] {
			value, err := s.batchGet(batch, namespace, key)
			if err != nil {
				return err
			}
			proceed, err := fn(key, value)
			if err != nil || !proceed {
				return err
			}
		}
		return nil
	}
	if s.activeView(ctx) {
		return s.iterateLocked(namespace, prefix, start, fn)
	}
	unlock, err := s.rlock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.iterateLocked(namespace, prefix, start, fn)
}

func (s *Store) iterateLocked(namespace, prefix, start string, fn store.IterCallback) error {
	if _, ok := s.ns[namespace]; !ok {
		return store.ErrNotFound
	}
	keys := keySlice(s.keys[namespace])
	sort.Strings(keys)
	for _, k := range keys[sort.SearchStrings(keys, start):] {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		val, err := s.loadValue(namespace, k)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("load value for %s: %w", k, err)
		}
		cont, err := fn(k, val)
		if err != nil || !cont {
			if err == nil && !cont {
				return nil
			}
			return err
		}
	}
	return nil
}

// NamespaceExists implements store.Store.
func (s *Store) NamespaceExists(ctx context.Context, namespace string) (bool, error) {
	if batch := s.activeBatch(ctx); batch != nil {
		return s.batchNamespaceExists(batch, namespace), nil
	}
	if s.activeView(ctx) {
		_, ok := s.ns[namespace]
		return ok, nil
	}
	unlock, err := s.rlock()
	if err != nil {
		return false, err
	}
	defer unlock()

	_, ok := s.ns[namespace]
	return ok, nil
}

// CreateNamespace implements store.Store.
func (s *Store) CreateNamespace(ctx context.Context, namespace string) error {
	if batch := s.activeBatch(ctx); batch != nil {
		if s.batchNamespaceExists(batch, namespace) {
			return store.ErrExists
		}
		_, originallyExists := s.ns[namespace]
		batch.namespaces[namespace] = batchNamespace{Exists: true, Reset: originallyExists}
		return nil
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, ok := s.ns[namespace]; ok {
		return store.ErrExists
	}
	s.ns[namespace] = struct{}{}
	s.keys[namespace] = make(map[string]struct{})
	s.keyMutations[namespace] = 0
	if err := os.MkdirAll(s.nsDir(namespace), 0o755); err != nil {
		delete(s.keys, namespace)
		delete(s.ns, namespace)
		return fmt.Errorf("create ns dir: %w", err)
	}
	if err := s.saveKeys(namespace, nil); err != nil {
		delete(s.keys, namespace)
		delete(s.ns, namespace)
		return fmt.Errorf("init keys: %w", err)
	}
	return s.saveNamespaces()
}

// DeleteNamespace implements store.Store.
func (s *Store) DeleteNamespace(ctx context.Context, namespace string) error {
	if batch := s.activeBatch(ctx); batch != nil {
		if !s.batchNamespaceExists(batch, namespace) {
			return store.ErrNotFound
		}
		if _, originallyExists := s.ns[namespace]; originallyExists {
			batch.namespaces[namespace] = batchNamespace{Exists: false}
		} else {
			delete(batch.namespaces, namespace)
		}
		for key := range batch.changes {
			if key.Namespace == namespace {
				delete(batch.changes, key)
			}
		}
		return nil
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if _, ok := s.ns[namespace]; !ok {
		return store.ErrNotFound
	}
	delete(s.ns, namespace)
	delete(s.keys, namespace)
	delete(s.keyMutations, namespace)
	if err := os.RemoveAll(s.nsDir(namespace)); err != nil {
		return fmt.Errorf("remove ns dir: %w", err)
	}
	return s.saveNamespaces()
}

// ListNamespaces implements store.Store.
func (s *Store) ListNamespaces(ctx context.Context) ([]string, error) {
	if batch := s.activeBatch(ctx); batch != nil {
		return s.batchNamespaces(batch), nil
	}
	if s.activeView(ctx) {
		return s.listNamespacesLocked(), nil
	}
	unlock, err := s.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.listNamespacesLocked(), nil
}

func (s *Store) listNamespacesLocked() []string {
	var out []string
	for n := range s.ns {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Close implements store.Store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for namespace, mutations := range s.keyMutations {
		if mutations == 0 {
			continue
		}
		if err := s.compactKeys(namespace); err != nil {
			return fmt.Errorf("compact namespace %q: %w", namespace, err)
		}
	}
	return nil
}
