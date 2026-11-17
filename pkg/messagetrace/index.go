package messagetrace

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	traceIndexSchema = 1
	indexMetadataKey = "_metadata"
	updatedPrefix    = "updated:"
	// rebuildBatchRecords bounds the canonical records indexed per commit.
	rebuildBatchRecords = 256
)

// IndexStatus describes the disposable projection used to query canonical
// message-trace records. A missing or incompatible projection is rebuilt at
// startup without changing trace truth.
type IndexStatus struct {
	SchemaVersion int       `json:"schema_version"`
	State         string    `json:"state"`
	Records       int       `json:"records"`
	BuiltAt       time.Time `json:"built_at,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
}

type indexMetadata struct {
	IndexStatus
	Stats Stats `json:"stats"`
}

type MaintenanceStatus struct {
	Index IndexStatus `json:"index"`
	Stats Stats       `json:"stats"`
}

func (s *Store) ensureIndex(ctx context.Context) error {
	exists, err := s.backend.NamespaceExists(ctx, model.NSMessageTraceIndexes)
	if err != nil {
		return err
	}
	if exists {
		metadata, getErr := s.indexMetadata(ctx)
		if getErr == nil && metadata.SchemaVersion == traceIndexSchema && metadata.State == "ready" {
			return nil
		}
	}
	return s.rebuildIndex(ctx)
}

func (s *Store) rebuildIndex(ctx context.Context) error {
	if exists, err := s.backend.NamespaceExists(ctx, model.NSMessageTraceIndexes); err != nil {
		return err
	} else if exists {
		if err := s.backend.DeleteNamespace(ctx, model.NSMessageTraceIndexes); err != nil {
			return fmt.Errorf("remove stale message-trace index: %w", err)
		}
	}
	if err := s.backend.CreateNamespace(ctx, model.NSMessageTraceIndexes); err != nil && !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("create message-trace index: %w", err)
	}
	metadata := indexMetadata{IndexStatus: IndexStatus{SchemaVersion: traceIndexSchema, State: "building"}}
	if err := s.setIndexMetadata(ctx, metadata); err != nil {
		return err
	}
	keys, err := s.backend.List(ctx, model.NSMessageTrace)
	if err != nil {
		return fmt.Errorf("list canonical message traces: %w", err)
	}
	// Index records in bounded batches: one commit per chunk instead of one
	// synced write per index key, without holding the whole projection in
	// memory. The "building" state covers a partially written projection.
	for start := 0; start < len(keys) && err == nil; start += rebuildBatchRecords {
		chunk := keys[start:min(start+rebuildBatchRecords, len(keys))]
		err = store.Batch(ctx, s.backend, func(batchCtx context.Context) error {
			for _, key := range chunk {
				if err := s.indexCanonicalRecord(batchCtx, key, &metadata); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if err != nil {
		metadata.State, metadata.LastError = "failed", err.Error()
		_ = s.setIndexMetadata(ctx, metadata)
		return err
	}
	metadata.State, metadata.BuiltAt, metadata.LastError = "ready", time.Now().UTC(), ""
	return s.setIndexMetadata(ctx, metadata)
}

// indexCanonicalRecord writes the projection keys for one canonical record and
// adds it to the rebuild statistics.
func (s *Store) indexCanonicalRecord(ctx context.Context, key string, metadata *indexMetadata) error {
	value, err := s.backend.Get(ctx, model.NSMessageTrace, key)
	if err != nil {
		return err
	}
	var record Record
	if err := unmarshal(value, &record); err != nil {
		return fmt.Errorf("decode canonical message trace: %w", err)
	}
	for _, indexKey := range traceIndexKeys(record) {
		if err := s.backend.Set(ctx, model.NSMessageTraceIndexes, indexKey, nil); err != nil {
			return err
		}
	}
	metadata.Records++
	metadata.Stats.Records++
	metadata.Stats.EventsRetained += len(record.Events)
	metadata.Stats.EventsDropped += record.EventsDropped
	if metadata.Stats.OldestUpdate.IsZero() || record.UpdatedAt.Before(metadata.Stats.OldestUpdate) {
		metadata.Stats.OldestUpdate = record.UpdatedAt
	}
	return nil
}

func (s *Store) IndexStatus(ctx context.Context) (IndexStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metadata, err := s.indexMetadata(ctx)
	return metadata.IndexStatus, err
}

func (s *Store) MaintenanceStatus(ctx context.Context) (MaintenanceStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metadata, err := s.indexMetadata(ctx)
	if err != nil {
		return MaintenanceStatus{}, err
	}
	return MaintenanceStatus{Index: metadata.IndexStatus, Stats: metadata.Stats}, nil
}

// RebuildIndex replaces only the disposable query projection. Trace writers
// and readers wait behind the rebuild lock, so they can never observe a
// partially replaced namespace.
func (s *Store) RebuildIndex(ctx context.Context) (IndexStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rebuildIndex(ctx); err != nil {
		return IndexStatus{}, err
	}
	metadata, err := s.indexMetadata(ctx)
	return metadata.IndexStatus, err
}

func (s *Store) indexMetadata(ctx context.Context) (indexMetadata, error) {
	data, err := s.backend.Get(ctx, model.NSMessageTraceIndexes, indexMetadataKey)
	if err != nil {
		return indexMetadata{}, err
	}
	var metadata indexMetadata
	if err := unmarshal(data, &metadata); err != nil {
		return indexMetadata{}, err
	}
	return metadata, nil
}

func (s *Store) setIndexMetadata(ctx context.Context, metadata indexMetadata) error {
	data, err := marshal(metadata)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, model.NSMessageTraceIndexes, indexMetadataKey, data)
}

func traceIndexKeys(record Record) []string {
	keys := []string{orderedIndexKey(updatedPrefix, record.UpdatedAt, record.QueueID)}
	for field, value := range map[string]string{
		"correlation": record.CorrelationID,
		"direction":   record.Direction,
		"parent":      record.ParentID,
		"recipient":   record.Recipient,
		"sender":      record.EnvelopeSender,
		"status":      record.Status,
	} {
		if value = normalizeIndexValue(value); value != "" {
			keys = append(keys, orderedIndexKey(exactIndexPrefix(field, value), record.UpdatedAt, record.QueueID))
		}
	}
	return keys
}

func exactIndexPrefix(field, value string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(normalizeIndexValue(value)))
	return field + ":" + encoded + ":"
}

func normalizeIndexValue(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func orderedIndexKey(prefix string, updatedAt time.Time, id string) string {
	nanoseconds := updatedAt.UTC().UnixNano()
	if nanoseconds < 0 {
		nanoseconds = 0
	}
	return prefix + fmt.Sprintf("%019d", int64(^uint64(0)>>1)-nanoseconds) + ":" + reverseLexID(id)
}

func queueIDFromIndexKey(prefix, key string) (string, bool) {
	rest := strings.TrimPrefix(key, prefix)
	if rest == key || len(rest) < 21 || rest[19] != ':' {
		return "", false
	}
	id, err := decodeReverseLexID(rest[20:])
	return id, err == nil && id != ""
}

// reverseLexID makes ascending storage iteration produce descending IDs when
// timestamps tie. The complemented terminator also puts a longer ID before an
// otherwise identical prefix, matching Go's descending string comparison.
func reverseLexID(id string) string {
	raw := []byte(id)
	encoded := make([]byte, len(raw)+1)
	for index := range raw {
		encoded[index] = ^raw[index]
	}
	encoded[len(encoded)-1] = 0xff
	return hex.EncodeToString(encoded)
}

func decodeReverseLexID(encoded string) (string, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil || len(data) == 0 || data[len(data)-1] != 0xff {
		return "", errors.New("invalid message-trace identity index")
	}
	data = data[:len(data)-1]
	for index := range data {
		data[index] = ^data[index]
	}
	return string(data), nil
}

func timeFromIndexKey(prefix, key string) (time.Time, bool) {
	rest := strings.TrimPrefix(key, prefix)
	if rest == key || len(rest) < 20 || rest[19] != ':' {
		return time.Time{}, false
	}
	inverted, err := strconv.ParseInt(rest[:19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, int64(^uint64(0)>>1)-inverted).UTC(), true
}

func queryIndexPrefix(query Query) string {
	for _, candidate := range []struct{ field, value string }{
		{"correlation", query.CorrelationID},
		{"sender", query.Sender},
		{"recipient", query.Recipient},
		{"status", query.Status},
		{"direction", query.Direction},
	} {
		if normalizeIndexValue(candidate.value) != "" {
			return exactIndexPrefix(candidate.field, candidate.value)
		}
	}
	return updatedPrefix
}

func (s *Store) removeIndexes(ctx context.Context, record Record) error {
	for _, key := range traceIndexKeys(record) {
		if err := s.backend.Delete(ctx, model.NSMessageTraceIndexes, key); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (s *Store) addIndexes(ctx context.Context, record Record) error {
	for _, key := range traceIndexKeys(record) {
		if err := s.backend.Set(ctx, model.NSMessageTraceIndexes, key, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) oldestIndexedUpdate(ctx context.Context) (time.Time, error) {
	keys, err := s.backend.Scan(ctx, model.NSMessageTraceIndexes, updatedPrefix)
	if err != nil || len(keys) == 0 {
		return time.Time{}, err
	}
	updatedAt, ok := timeFromIndexKey(updatedPrefix, keys[len(keys)-1])
	if !ok {
		return time.Time{}, errors.New("invalid message-trace time index")
	}
	return updatedAt, nil
}
