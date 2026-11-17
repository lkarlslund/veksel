// Package messagetrace stores metadata-only delivery histories.
package messagetrace

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type Event struct {
	Time              time.Time  `json:"time"`
	Stage             string     `json:"stage"`
	Status            string     `json:"status"`
	Attempt           int        `json:"attempt,omitempty"`
	Code              string     `json:"code,omitempty"`
	Response          string     `json:"response,omitempty"`
	Destination       string     `json:"destination,omitempty"`
	Route             string     `json:"route,omitempty"`
	OutcomeClass      string     `json:"outcome_class,omitempty"`
	TLSPolicy         string     `json:"tls_policy,omitempty"`
	DurationMillis    int64      `json:"duration_ms,omitempty"`
	RetryAt           *time.Time `json:"retry_at,omitzero"`
	PossibleDuplicate bool       `json:"possible_duplicate,omitempty"`
}

type Record struct {
	QueueID           string            `json:"queue_id"`
	CorrelationID     string            `json:"correlation_id"`
	ParentID          string            `json:"parent_id,omitempty"`
	Kind              string            `json:"kind,omitempty"`
	Direction         string            `json:"direction"`
	EnvelopeSender    string            `json:"envelope_sender"`
	Recipient         string            `json:"recipient"`
	MessageID         string            `json:"message_id,omitempty"`
	Subject           string            `json:"subject,omitempty"`
	ScanSummary       string            `json:"scan_summary,omitempty"`
	TransportSecurity string            `json:"transport_security,omitempty"`
	Status            string            `json:"status"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Events            []Event           `json:"events"`
	EventsDropped     int64             `json:"events_dropped,omitempty"`
	Related           []Related         `json:"related,omitempty"`
	Policy            mailpolicy.Result `json:"policy,omitempty"`
}

type Related struct {
	QueueID       string    `json:"queue_id"`
	CorrelationID string    `json:"correlation_id"`
	ParentID      string    `json:"parent_id,omitempty"`
	Recipient     string    `json:"recipient"`
	Status        string    `json:"status"`
	Relationship  string    `json:"relationship"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// MaxEventsPerRecord bounds a single message's trace metadata while retaining
// representative failure, operator-hold, and uncertain-delivery evidence.
const MaxEventsPerRecord = 256

type Query struct {
	Text, Sender, Recipient, Status, Direction, CorrelationID, Cursor string
	Limit                                                             int
	UpdatedAfter, UpdatedBefore                                       time.Time
	// Visible, when set, hides records the caller may not see; it is
	// applied before the limit so pages stay full and cursors stable.
	Visible func(Record) bool
}

type Page struct {
	Records    []Record `json:"records"`
	NextCursor string   `json:"next_cursor,omitempty"`
	Stats      Stats    `json:"stats"`
}

type Stats struct {
	Records        int       `json:"records"`
	EventsRetained int       `json:"events_retained"`
	EventsDropped  int64     `json:"events_dropped"`
	OldestUpdate   time.Time `json:"oldest_update,omitzero"`
}

type PruneItem struct {
	QueueID   string    `json:"queue_id"`
	UpdatedAt time.Time `json:"updated_at"`
	Removed   bool      `json:"removed"`
}

type PruneResult struct {
	Before   time.Time   `json:"before"`
	DryRun   bool        `json:"dry_run"`
	Examined int         `json:"examined"`
	Removed  int         `json:"removed"`
	Items    []PruneItem `json:"items"`
}

const MaxPruneRecords = 10000

type Store struct {
	backend store.Store
	mu      sync.RWMutex
}

func New(ctx context.Context, backend store.Store) (*Store, error) {
	if backend == nil {
		return nil, errors.New("message trace store is required")
	}
	exists, err := backend.NamespaceExists(ctx, model.NSMessageTrace)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, model.NSMessageTrace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	result := &Store{backend: backend}
	if err := result.ensureIndex(ctx); err != nil {
		return nil, fmt.Errorf("initialize message-trace index: %w", err)
	}
	return result, nil
}

func (s *Store) Record(ctx context.Context, base Record, event Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	event.Stage = boundedEvidence(event.Stage, 128)
	event.Code = boundedEvidence(event.Code, 64)
	event.Response = boundedEvidence(event.Response, 2048)
	event.Destination = boundedEvidence(event.Destination, 512)
	event.Route = boundedEvidence(event.Route, 512)
	event.OutcomeClass = boundedEvidence(event.OutcomeClass, 64)
	event.TLSPolicy = boundedEvidence(event.TLSPolicy, 512)
	return store.Batch(ctx, s.backend, func(batchCtx context.Context) error {
		var current Record
		err := getJSON(batchCtx, s.backend, base.QueueID, &current)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		created := errors.Is(err, store.ErrNotFound)
		if created {
			current = base
			current.Policy = base.Policy.Clone()
			current.CreatedAt = event.Time
		} else if current.TransportSecurity == "" {
			current.TransportSecurity = base.TransportSecurity
		}
		previous := current
		current.Status, current.UpdatedAt = event.Status, event.Time
		current.Events = append(current.Events, event)
		var dropped int
		current.Events, dropped = compactEvents(current.Events)
		current.EventsDropped += int64(dropped)
		data, err := marshal(current)
		if err != nil {
			return err
		}
		metadata, err := s.indexMetadata(batchCtx)
		if err != nil {
			return fmt.Errorf("load message-trace index metadata: %w", err)
		}
		if !created {
			if err := s.removeIndexes(batchCtx, previous); err != nil {
				return err
			}
		}
		if err := s.backend.Set(batchCtx, model.NSMessageTrace, current.QueueID, data); err != nil {
			return err
		}
		if err := s.addIndexes(batchCtx, current); err != nil {
			return err
		}
		if created {
			metadata.Records++
			metadata.Stats.Records++
		}
		metadata.Stats.EventsRetained += len(current.Events) - len(previous.Events)
		metadata.Stats.EventsDropped += current.EventsDropped - previous.EventsDropped
		if metadata.Stats.OldestUpdate.IsZero() || current.UpdatedAt.Before(metadata.Stats.OldestUpdate) {
			metadata.Stats.OldestUpdate = current.UpdatedAt
		} else if !created && previous.UpdatedAt.Equal(metadata.Stats.OldestUpdate) && current.UpdatedAt.After(previous.UpdatedAt) {
			metadata.Stats.OldestUpdate, err = s.oldestIndexedUpdate(batchCtx)
			if err != nil {
				return err
			}
		}
		return s.setIndexMetadata(batchCtx, metadata)
	})
}

func boundedEvidence(value string, limit int) string {
	value = strings.Map(func(character rune) rune {
		switch {
		case character == '\r' || character == '\n' || character == '\t':
			return ' '
		case character < 32 || character == 127:
			return -1
		default:
			return character
		}
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return value
}

func compactEvents(events []Event) ([]Event, int) {
	if len(events) <= MaxEventsPerRecord {
		return events, 0
	}
	selected := make(map[int]struct{}, MaxEventsPerRecord)
	selected[0] = struct{}{}
	selected[len(events)-1] = struct{}{}

	// Preserve the latest example of each operationally significant outcome.
	for _, matches := range []func(Event) bool{
		func(event Event) bool {
			status := strings.ToLower(event.Status)
			return status == "failed" || status == "cancelled" || strings.Contains(status, "error")
		},
		func(event Event) bool {
			stage, status := strings.ToLower(event.Stage), strings.ToLower(event.Status)
			return strings.Contains(stage, "hold") || strings.Contains(stage, "pause") || status == "held" || status == "paused"
		},
		func(event Event) bool {
			return event.PossibleDuplicate || strings.Contains(strings.ToLower(event.Stage), "uncertain") || strings.Contains(strings.ToLower(event.Status), "uncertain")
		},
	} {
		for index := len(events) - 2; index > 0; index-- {
			if matches(events[index]) {
				selected[index] = struct{}{}
				break
			}
		}
	}

	for index := len(events) - 2; index > 0 && len(selected) < MaxEventsPerRecord; index-- {
		selected[index] = struct{}{}
	}
	result := make([]Event, 0, len(selected))
	for index, event := range events {
		if _, keep := selected[index]; keep {
			result = append(result, event)
		}
	}
	return result, len(events) - len(result)
}

func (s *Store) Get(ctx context.Context, id string) (Record, error) {
	var record Record
	err := getJSON(ctx, s.backend, id, &record)
	return record, err
}

func (s *Store) GetWithRelations(ctx context.Context, id string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	candidates := make(map[string]struct{})
	for _, lookup := range []struct{ field, value string }{
		{"correlation", record.CorrelationID},
		{"parent", record.QueueID},
		{"parent", record.ParentID},
	} {
		if normalizeIndexValue(lookup.value) == "" {
			continue
		}
		prefix := exactIndexPrefix(lookup.field, lookup.value)
		keys, scanErr := s.backend.Scan(ctx, model.NSMessageTraceIndexes, prefix)
		if scanErr != nil {
			return Record{}, scanErr
		}
		for _, key := range keys {
			if queueID, ok := queueIDFromIndexKey(prefix, key); ok {
				candidates[queueID] = struct{}{}
			}
		}
	}
	if record.ParentID != "" {
		candidates[record.ParentID] = struct{}{}
	}
	delete(candidates, id)
	for queueID := range candidates {
		candidate, getErr := s.Get(ctx, queueID)
		if getErr != nil || !traceRelated(record, candidate) {
			continue
		}
		relationship := "correlated"
		switch {
		case candidate.QueueID == record.ParentID:
			relationship = "parent"
		case candidate.ParentID == record.QueueID:
			relationship = "child"
		case record.ParentID != "" && candidate.ParentID == record.ParentID:
			relationship = "sibling"
		}
		record.Related = append(record.Related, Related{QueueID: candidate.QueueID, CorrelationID: candidate.CorrelationID, ParentID: candidate.ParentID, Recipient: candidate.Recipient, Status: candidate.Status, Relationship: relationship, UpdatedAt: candidate.UpdatedAt})
	}
	sort.Slice(record.Related, func(i, j int) bool { return record.Related[i].UpdatedAt.Before(record.Related[j].UpdatedAt) })
	return record, nil
}

func traceRelated(left, right Record) bool {
	return left.ParentID == right.QueueID || right.ParentID == left.QueueID ||
		(left.ParentID != "" && left.ParentID == right.ParentID) ||
		(left.CorrelationID != "" && left.CorrelationID == right.CorrelationID)
}

func (s *Store) List(ctx context.Context, query Query) (Page, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := query.Limit
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	page := Page{Records: make([]Record, 0, limit)}
	err := store.View(ctx, s.backend, func(viewCtx context.Context) error {
		metadata, err := s.indexMetadata(viewCtx)
		if err != nil {
			return err
		}
		page.Stats = metadata.Stats
		prefix := queryIndexPrefix(query)
		cursorTime, cursorID, stableCursor := decodeCursor(query.Cursor)
		legacyCursorSeen := query.Cursor == "" || stableCursor
		return s.backend.Iterate(viewCtx, model.NSMessageTraceIndexes, prefix, func(key string, _ []byte) (bool, error) {
			queueID, ok := queueIDFromIndexKey(prefix, key)
			if !ok {
				return true, nil
			}
			if !legacyCursorSeen {
				legacyCursorSeen = queueID == query.Cursor
				return true, nil
			}
			record, getErr := s.Get(viewCtx, queueID)
			if getErr != nil {
				if errors.Is(getErr, store.ErrNotFound) {
					return true, nil
				}
				return false, getErr
			}
			if stableCursor && !(record.UpdatedAt.Before(cursorTime) || (record.UpdatedAt.Equal(cursorTime) && record.QueueID < cursorID)) {
				return true, nil
			}
			if !query.UpdatedAfter.IsZero() && record.UpdatedAt.Before(query.UpdatedAfter) {
				return false, nil
			}
			if !matches(record, query) {
				return true, nil
			}
			page.Records = append(page.Records, record)
			return len(page.Records) <= limit, nil
		})
	})
	if err != nil {
		return Page{}, err
	}
	if len(page.Records) > limit {
		page.Records = page.Records[:limit]
		page.NextCursor = encodeCursor(page.Records[len(page.Records)-1])
	}
	return page, nil
}

func encodeCursor(record Record) string {
	value := record.UpdatedAt.UTC().Format(time.RFC3339Nano) + "\n" + record.QueueID
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeCursor(cursor string) (time.Time, string, bool) {
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", false
	}
	parts := strings.SplitN(string(data), "\n", 2)
	if len(parts) != 2 || parts[1] == "" {
		return time.Time{}, "", false
	}
	parsed, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", false
	}
	return parsed, parts[1], true
}

// Prune removes trace metadata older than before. Message content is never
// stored in this namespace, so retention can be managed independently of mail.
func (s *Store) Prune(ctx context.Context, before time.Time) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result, err := s.prune(ctx, before, 0, false)
	return result.Removed, err
}

// PruneWithOptions previews or removes a bounded, oldest-first set of trace
// records. It is intended for explicit operator maintenance; scheduled
// retention uses Prune without the API limit.
func (s *Store) PruneWithOptions(ctx context.Context, before time.Time, limit int, dryRun bool) (PruneResult, error) {
	if limit < 1 || limit > MaxPruneRecords {
		return PruneResult{}, fmt.Errorf("limit must be between 1 and %d", MaxPruneRecords)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.prune(ctx, before, limit, dryRun)
}

func (s *Store) prune(ctx context.Context, before time.Time, limit int, dryRun bool) (PruneResult, error) {
	result := PruneResult{Before: before.UTC(), DryRun: dryRun, Items: []PruneItem{}}
	keys, err := s.backend.Scan(ctx, model.NSMessageTraceIndexes, updatedPrefix)
	if err != nil {
		return result, err
	}
	for index := len(keys) - 1; index >= 0; index-- {
		key := keys[index]
		updatedAt, ok := timeFromIndexKey(updatedPrefix, key)
		queueID, idOK := queueIDFromIndexKey(updatedPrefix, key)
		if ok && idOK && updatedAt.Before(before) {
			result.Items = append(result.Items, PruneItem{QueueID: queueID, UpdatedAt: updatedAt})
			if limit > 0 && len(result.Items) == limit {
				break
			}
		}
	}
	result.Examined = len(result.Items)
	if dryRun || result.Examined == 0 {
		return result, nil
	}
	err = store.Batch(ctx, s.backend, func(batchCtx context.Context) error {
		metadata, metadataErr := s.indexMetadata(batchCtx)
		if metadataErr != nil {
			return metadataErr
		}
		for _, item := range result.Items {
			record, getErr := s.Get(batchCtx, item.QueueID)
			if errors.Is(getErr, store.ErrNotFound) {
				continue
			}
			if getErr != nil {
				return getErr
			}
			if err := s.removeIndexes(batchCtx, record); err != nil {
				return err
			}
			if err := s.backend.Delete(batchCtx, model.NSMessageTrace, item.QueueID); err != nil {
				return err
			}
			metadata.Records--
			metadata.Stats.Records--
			metadata.Stats.EventsRetained -= len(record.Events)
			metadata.Stats.EventsDropped -= record.EventsDropped
		}
		metadata.Stats.OldestUpdate, err = s.oldestIndexedUpdate(batchCtx)
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		}
		if err != nil {
			return err
		}
		return s.setIndexMetadata(batchCtx, metadata)
	})
	if err == nil {
		result.Removed = result.Examined
		for index := range result.Items {
			result.Items[index].Removed = true
		}
	}
	return result, err
}

func matches(record Record, query Query) bool {
	if query.Visible != nil && !query.Visible(record) {
		return false
	}
	if !query.UpdatedAfter.IsZero() && record.UpdatedAt.Before(query.UpdatedAfter) {
		return false
	}
	if !query.UpdatedBefore.IsZero() && !record.UpdatedAt.Before(query.UpdatedBefore) {
		return false
	}
	if query.Sender != "" && !strings.EqualFold(record.EnvelopeSender, query.Sender) {
		return false
	}
	if query.Recipient != "" && !strings.EqualFold(record.Recipient, query.Recipient) {
		return false
	}
	if query.Status != "" && !strings.EqualFold(record.Status, query.Status) {
		return false
	}
	if query.Direction != "" && !strings.EqualFold(record.Direction, query.Direction) {
		return false
	}
	if query.CorrelationID != "" && !strings.EqualFold(record.CorrelationID, query.CorrelationID) {
		return false
	}
	needle := strings.ToLower(strings.TrimSpace(query.Text))
	return needle == "" || strings.Contains(strings.ToLower(strings.Join([]string{record.QueueID, record.CorrelationID, record.Kind, record.EnvelopeSender, record.Recipient, record.MessageID, record.Subject}, " ")), needle)
}
