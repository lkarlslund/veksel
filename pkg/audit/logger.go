// Package audit provides an append-only audit log for admin actions and
// security events. Entries are stored in the KV store under a dedicated
// "audit" namespace with monotonically increasing sequence keys so that
// queries can scan in chronological order.
package audit

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleAudit)

// Namespace is the KV-store namespace for audit entries.
const Namespace = model.NSAudit

// Entry represents a single audit-log record.
type Entry struct {
	Sequence  int64             `json:"sequence"`
	Timestamp time.Time         `json:"timestamp"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Details   map[string]string `json:"details,omitempty"`
}

// ReversePage is a stable newest-first page of audit entries. NextBefore is
// the exclusive sequence cursor for the next, older page. Total is the number
// of durable entry keys observed while selecting the page.
type ReversePage struct {
	Entries    []Entry
	Total      int
	NextBefore int64
}

// Logger writes and queries audit entries through a TypedStore.
type Logger struct {
	ts       *model.TypedStore
	sequence *auditSequence
}

type auditSequence struct {
	mu    sync.Mutex
	value int64
}

var loggerSequences = struct {
	sync.Mutex
	stores map[*model.TypedStore]*auditSequence
}{stores: make(map[*model.TypedStore]*auditSequence)}

// New creates an audit logger backed by the given TypedStore.
// It loads the current sequence counter so keys remain monotonic.
func New(ts *model.TypedStore) *Logger {
	loggerSequences.Lock()
	defer loggerSequences.Unlock()
	sequence := loggerSequences.stores[ts]
	if sequence == nil {
		sequence = &auditSequence{}
		loggerSequences.stores[ts] = sequence
		var last int64
		if err := ts.Get(context.Background(), Namespace, "_seq", &last); err == nil {
			sequence.value = last
		}
	}
	return &Logger{ts: ts, sequence: sequence}
}

// Log appends a new audit entry. The key is the zero-padded sequence number
// so that lexicographic scans return chronological order.
func (l *Logger) Log(actor, action, target string, details map[string]string) {
	l.sequence.mu.Lock()
	defer l.sequence.mu.Unlock()
	l.sequence.value++
	seq := l.sequence.value
	entry := Entry{
		Sequence:  seq,
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Details:   details,
	}
	ctx := context.Background()
	// Ensure namespace exists
	l.ts.EnsureNamespace(ctx, Namespace)
	key := fmt.Sprintf("%020d", seq)
	// The entry and its sequence counter commit together with one sync.
	err := store.Batch(ctx, l.ts.Store(), func(batchCtx context.Context) error {
		if err := l.ts.Set(batchCtx, Namespace, key, entry); err != nil {
			return fmt.Errorf("write entry: %w", err)
		}
		if err := l.ts.Set(batchCtx, Namespace, "_seq", seq); err != nil {
			return fmt.Errorf("write sequence: %w", err)
		}
		return nil
	})
	if err != nil {
		log.Error("audit: failed to write entry", "key", key, "error", err)
	}
}

// Query returns audit entries filtered by the given criteria.
// Since filters entries on or after [since]. If action is non-empty, only
// entries with that action are returned. If actor is non-empty, only
// entries with that actor are returned. Limit caps the result size.
// Results are returned in chronological order (oldest first).
func (l *Logger) Query(ctx context.Context, since time.Time, action, actor string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}

	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return nil, err
	}

	var matches []Entry
	for _, key := range keys {
		if key == "_seq" {
			continue
		}
		var entry Entry
		if err := l.ts.Get(ctx, Namespace, key, &entry); err != nil {
			continue
		}
		// Apply filters
		if !since.IsZero() && entry.Timestamp.Before(since) {
			continue
		}
		if action != "" && entry.Action != action {
			continue
		}
		if actor != "" && entry.Actor != actor {
			continue
		}
		matches = append(matches, entry)
	}

	// Already in chronological order because keys are sorted lexicographically
	if len(matches) > limit {
		matches = matches[:limit]
	}

	return matches, nil
}

// QueryReverse returns audit entries in reverse chronological order
// (newest first). Useful for the admin UI default view.
// If actor is non-empty, only entries with that actor are returned.
func (l *Logger) QueryReverse(ctx context.Context, since time.Time, action, actor string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}

	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return nil, err
	}

	var matches []Entry
	for _, key := range keys {
		if key == "_seq" {
			continue
		}
		var entry Entry
		if err := l.ts.Get(ctx, Namespace, key, &entry); err != nil {
			continue
		}
		if !since.IsZero() && entry.Timestamp.Before(since) {
			continue
		}
		if action != "" && entry.Action != action {
			continue
		}
		if actor != "" && entry.Actor != actor {
			continue
		}
		matches = append(matches, entry)
	}

	// Reverse to newest-first
	for i, j := 0, len(matches)-1; i < j; i, j = i+1, j-1 {
		matches[i], matches[j] = matches[j], matches[i]
	}

	if len(matches) > limit {
		matches = matches[:limit]
	}

	return matches, nil
}

// QueryReversePage returns a newest-first page without reading record bodies
// outside the requested window. before is an exclusive sequence cursor; zero
// starts at the newest entry. Appends after the first request cannot duplicate
// entries on subsequent pages because every continuation is sequence-bounded.
func (l *Logger) QueryReversePage(ctx context.Context, before int64, limit int) (ReversePage, error) {
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}

	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return ReversePage{}, err
	}

	page := ReversePage{Entries: make([]Entry, 0, limit)}
	for _, key := range keys {
		if key == "_seq" {
			continue
		}
		if _, err := strconv.ParseInt(key, 10, 64); err == nil {
			page.Total++
		}
	}
	for index := len(keys) - 1; index >= 0; index-- {
		key := keys[index]
		if key == "_seq" {
			continue
		}
		sequence, err := strconv.ParseInt(key, 10, 64)
		if err != nil || before > 0 && sequence >= before {
			continue
		}
		var entry Entry
		if err := l.ts.Get(ctx, Namespace, key, &entry); err != nil {
			continue
		}
		page.Entries = append(page.Entries, entry)
		if len(page.Entries) > limit {
			page.NextBefore = page.Entries[limit-1].Sequence
			page.Entries = page.Entries[:limit]
			break
		}
	}
	return page, nil
}

// Count returns the total number of audit entries (excluding metadata keys).
func (l *Logger) Count(ctx context.Context) (int, error) {
	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return 0, err
	}
	n := len(keys)
	if n > 0 {
		n-- // subtract _seq
	}
	return n, nil
}

// GetActionList returns the distinct action strings present in the log.
func (l *Logger) GetActionList(ctx context.Context) ([]string, error) {
	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return nil, err
	}
	actions := make(map[string]struct{})
	for _, key := range keys {
		if key == "_seq" {
			continue
		}
		var entry Entry
		if err := l.ts.Get(ctx, Namespace, key, &entry); err != nil {
			continue
		}
		actions[entry.Action] = struct{}{}
	}
	list := make([]string, 0, len(actions))
	for a := range actions {
		list = append(list, a)
	}
	return list, nil
}

// GetEntry returns a single audit entry by its zero-padded sequence key.
func (l *Logger) GetEntry(ctx context.Context, key string) (Entry, error) {
	var entry Entry
	if err := l.ts.Get(ctx, Namespace, key, &entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// EnsureNamespace ensures the audit namespace exists in the store.
func (l *Logger) EnsureNamespace(ctx context.Context) error {
	return l.ts.EnsureNamespace(ctx, Namespace)
}

// Clear deletes all audit entries from the log.
func (l *Logger) Clear(ctx context.Context) error {
	l.sequence.mu.Lock()
	defer l.sequence.mu.Unlock()
	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := l.ts.Delete(ctx, Namespace, key); err != nil {
			return err
		}
	}
	l.sequence.value = 0
	return nil
}

// GetActorList returns the distinct actor strings present in the log.
func (l *Logger) GetActorList(ctx context.Context) ([]string, error) {
	keys, err := l.ts.List(ctx, Namespace)
	if err != nil {
		return nil, err
	}
	actors := make(map[string]struct{})
	for _, key := range keys {
		if key == "_seq" {
			continue
		}
		var entry Entry
		if err := l.ts.Get(ctx, Namespace, key, &entry); err != nil {
			continue
		}
		actors[entry.Actor] = struct{}{}
	}
	list := make([]string, 0, len(actors))
	for a := range actors {
		list = append(list, a)
	}
	return list, nil
}
