package dmarc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	dmarcAggregatePrefix       = "aggregate/"
	dmarcSeenPrefix            = "seen/"
	defaultMaxRows             = 100000
	defaultMaxAggregatesPerDay = 10000
	maxAuthResults             = 20
	maxReportingURIs           = 20
)

// AggregateAuthResult is one bounded SPF or DKIM result retained for reports.
type AggregateAuthResult struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector,omitempty"`
	Result   string `json:"result"`
}

// AggregateObservation is the content-free evidence recorded once per DATA
// transaction. It intentionally contains neither recipients nor message data.
type AggregateObservation struct {
	AttemptID    string
	Time         time.Time
	SourceIP     string
	HeaderFrom   string
	EnvelopeFrom string
	Disposition  string
	DKIMAligned  bool
	SPFAligned   bool
	DKIM         []AggregateAuthResult
	SPF          AggregateAuthResult
	Policy       ReportingPolicy
}

// AggregateRow is one RFC 9990 grouping tuple and its message count.
type AggregateRow struct {
	SourceIP     string                `json:"source_ip"`
	Count        int64                 `json:"count"`
	Disposition  string                `json:"disposition"`
	DKIMAligned  bool                  `json:"dkim_aligned"`
	SPFAligned   bool                  `json:"spf_aligned"`
	HeaderFrom   string                `json:"header_from"`
	EnvelopeFrom string                `json:"envelope_from,omitempty"`
	DKIM         []AggregateAuthResult `json:"dkim,omitempty"`
	SPF          AggregateAuthResult   `json:"spf"`
}

// RecordedAggregate is the durable snapshot for one UTC day and one policy
// publication. Rows are bounded so hostile input cannot grow one value without
// limit; OverflowCount makes any loss visible to administration and reporting.
type RecordedAggregate struct {
	ID            string          `json:"id"`
	Day           string          `json:"day"`
	Policy        ReportingPolicy `json:"policy"`
	Rows          []AggregateRow  `json:"rows"`
	OverflowCount int64           `json:"overflow_count,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type aggregateMetadata struct {
	ID            string          `json:"id"`
	Day           string          `json:"day"`
	Policy        ReportingPolicy `json:"policy"`
	RowKinds      int             `json:"row_kinds"`
	OverflowCount int64           `json:"overflow_count,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type AggregateRecorderOptions struct {
	Now                 func() time.Time
	MaxRows             int
	MaxAggregatesPerDay int
}

// AggregateRecorder atomically deduplicates and groups DMARC observations in
// the common embedded system store.
type AggregateRecorder struct {
	store               store.Store
	now                 func() time.Time
	maxRows             int
	maxAggregatesPerDay int
	sequence            atomic.Uint64
}

func NewAggregateRecorder(ctx context.Context, backend store.Store, options AggregateRecorderOptions) (*AggregateRecorder, error) {
	if backend == nil {
		return nil, errors.New("DMARC aggregate store is required")
	}
	if _, ok := backend.(store.Batcher); !ok {
		return nil, errors.New("DMARC aggregate store requires atomic batch support")
	}
	if err := ensureAggregateNamespace(ctx, backend); err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MaxRows <= 0 {
		options.MaxRows = defaultMaxRows
	}
	if options.MaxAggregatesPerDay <= 0 {
		options.MaxAggregatesPerDay = defaultMaxAggregatesPerDay
	}
	return &AggregateRecorder{store: backend, now: options.Now, maxRows: options.MaxRows, maxAggregatesPerDay: options.MaxAggregatesPerDay}, nil
}

func ensureAggregateNamespace(ctx context.Context, backend store.Store) error {
	exists, err := backend.NamespaceExists(ctx, model.NSDMARCAggregates)
	if err != nil {
		return err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, model.NSDMARCAggregates); err != nil && !errors.Is(err, store.ErrExists) {
			return err
		}
	}
	return nil
}

// Record accounts for an observation exactly once. Policies without an rua
// request are intentionally ignored.
func (r *AggregateRecorder) Record(ctx context.Context, observation AggregateObservation) error {
	normalized, err := normalizeAggregateObservation(observation, r.now().UTC())
	if err != nil {
		return err
	}
	if len(normalized.Policy.RUA) == 0 {
		return nil
	}
	if normalized.AttemptID == "" {
		normalized.AttemptID = "smtp-" + strconv.FormatInt(r.now().UnixNano(), 10) + "-" + strconv.FormatUint(r.sequence.Add(1), 10)
	}
	day := normalized.Time.Format(time.DateOnly)
	policyID := digestJSON(normalized.Policy)
	aggregateBase := dmarcAggregatePrefix + day + "/" + normalized.Policy.Domain + "/" + policyID + "/"
	metadataKey := aggregateBase + "metadata"
	seenKey := dmarcSeenPrefix + day + "/" + normalized.Policy.Domain + "/" + digestStrings(normalized.AttemptID, policyID)
	row := observationRow(normalized)
	row.Count = 0
	rowKey := aggregateBase + "row/" + digestJSON(row)

	return store.Batch(ctx, r.store, func(batchCtx context.Context) error {
		if err := r.store.Put(batchCtx, model.NSDMARCAggregates, seenKey, []byte(`{"seen":true}`)); err != nil {
			if errors.Is(err, store.ErrExists) {
				return nil
			}
			return fmt.Errorf("store DMARC deduplication marker: %w", err)
		}
		metadata, err := r.loadMetadata(batchCtx, metadataKey)
		if errors.Is(err, store.ErrNotFound) {
			allowed, limitErr := r.admitAggregate(batchCtx, day, normalized.Policy.Domain, policyID)
			if limitErr != nil {
				return limitErr
			}
			if !allowed {
				return nil
			}
			metadata = aggregateMetadata{ID: policyID, Day: day, Policy: normalized.Policy}
		} else if err != nil {
			return err
		}
		existing, err := r.loadRow(batchCtx, rowKey)
		if err == nil {
			if existing.Count == int64(^uint64(0)>>1) {
				return errors.New("DMARC aggregate count overflow")
			}
			existing.Count++
			if err := r.saveRow(batchCtx, rowKey, existing); err != nil {
				return err
			}
			return r.saveMetadata(batchCtx, metadataKey, metadata)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if metadata.RowKinds >= r.maxRows {
			metadata.OverflowCount++
			return r.saveMetadata(batchCtx, metadataKey, metadata)
		}
		metadata.RowKinds++
		row.Count = 1
		if err := r.saveRow(batchCtx, rowKey, row); err != nil {
			return err
		}
		return r.saveMetadata(batchCtx, metadataKey, metadata)
	})
}

func (r *AggregateRecorder) admitAggregate(ctx context.Context, day, domain, policyID string) (bool, error) {
	marker := "limit/day/" + day + "/aggregate/" + domain + "/" + policyID
	if err := r.store.Put(ctx, model.NSDMARCAggregates, marker, []byte(`{"seen":true}`)); err != nil {
		if errors.Is(err, store.ErrExists) {
			return true, nil
		}
		return false, err
	}
	countKey := "limit/day/" + day + "/count"
	var count int
	data, err := r.store.Get(ctx, model.NSDMARCAggregates, countKey)
	if err == nil {
		if err := json.Unmarshal(data, &count); err != nil {
			return false, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if count >= r.maxAggregatesPerDay {
		if err := r.store.Delete(ctx, model.NSDMARCAggregates, marker); err != nil {
			return false, err
		}
		overflowKey := "limit/day/" + day + "/overflow"
		var overflow int64
		if data, err := r.store.Get(ctx, model.NSDMARCAggregates, overflowKey); err == nil {
			_ = json.Unmarshal(data, &overflow)
		}
		overflow++
		encoded, _ := json.Marshal(overflow)
		if err := r.store.Set(ctx, model.NSDMARCAggregates, overflowKey, encoded); err != nil {
			return false, err
		}
		return false, nil
	}
	count++
	encoded, _ := json.Marshal(count)
	if err := r.store.Set(ctx, model.NSDMARCAggregates, countKey, encoded); err != nil {
		return false, err
	}
	return true, nil
}

func (r *AggregateRecorder) saveMetadata(ctx context.Context, key string, metadata aggregateMetadata) error {
	metadata.UpdatedAt = r.now().UTC()
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return r.store.Set(ctx, model.NSDMARCAggregates, key, data)
}

func (r *AggregateRecorder) loadMetadata(ctx context.Context, key string) (aggregateMetadata, error) {
	data, err := r.store.Get(ctx, model.NSDMARCAggregates, key)
	if err != nil {
		return aggregateMetadata{}, err
	}
	var metadata aggregateMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return aggregateMetadata{}, err
	}
	return metadata, nil
}

func (r *AggregateRecorder) loadRow(ctx context.Context, key string) (AggregateRow, error) {
	data, err := r.store.Get(ctx, model.NSDMARCAggregates, key)
	if err != nil {
		return AggregateRow{}, err
	}
	var row AggregateRow
	if err := json.Unmarshal(data, &row); err != nil {
		return AggregateRow{}, err
	}
	return row, nil
}

func (r *AggregateRecorder) saveRow(ctx context.Context, key string, row AggregateRow) error {
	data, err := json.Marshal(row)
	if err != nil {
		return err
	}
	return r.store.Set(ctx, model.NSDMARCAggregates, key, data)
}

// Aggregates returns stable snapshots for a UTC day and optional policy domain.
func (r *AggregateRecorder) Aggregates(ctx context.Context, day, domain string) ([]RecordedAggregate, error) {
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		return nil, errors.New("DMARC aggregate day must use YYYY-MM-DD")
	}
	prefix := dmarcAggregatePrefix + day + "/"
	if domain != "" {
		normalized, err := normalizeReportDomain(domain)
		if err != nil {
			return nil, err
		}
		prefix += normalized + "/"
	}
	// One pass collects metadata and rows; nesting Iterate calls would hold
	// re-entrant store read locks.
	aggregates := make(map[string]*RecordedAggregate)
	rows := make(map[string][]AggregateRow)
	err := r.store.Iterate(ctx, model.NSDMARCAggregates, prefix, func(key string, value []byte) (bool, error) {
		if base, ok := strings.CutSuffix(key, "/metadata"); ok {
			var metadata aggregateMetadata
			if err := json.Unmarshal(value, &metadata); err != nil {
				return false, err
			}
			aggregates[base] = &RecordedAggregate{ID: metadata.ID, Day: metadata.Day, Policy: metadata.Policy,
				OverflowCount: metadata.OverflowCount, UpdatedAt: metadata.UpdatedAt}
			return true, nil
		}
		if base, _, ok := strings.Cut(key, "/row/"); ok {
			var row AggregateRow
			if err := json.Unmarshal(value, &row); err != nil {
				return false, err
			}
			rows[base] = append(rows[base], row)
		}
		return true, nil
	})
	var result []RecordedAggregate
	for base, aggregate := range aggregates {
		aggregate.Rows = rows[base]
		sort.Slice(aggregate.Rows, func(i, j int) bool { return digestJSON(aggregate.Rows[i]) < digestJSON(aggregate.Rows[j]) })
		result = append(result, *aggregate)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Policy.Domain == result[j].Policy.Domain {
			return result[i].ID < result[j].ID
		}
		return result[i].Policy.Domain < result[j].Policy.Domain
	})
	return result, err
}

// Days returns UTC days that still have aggregate metadata.
func (r *AggregateRecorder) Days(ctx context.Context) ([]string, error) {
	keys, err := r.store.Scan(ctx, model.NSDMARCAggregates, dmarcAggregatePrefix)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, key := range keys {
		if !strings.HasSuffix(key, "/metadata") {
			continue
		}
		remainder := strings.TrimPrefix(key, dmarcAggregatePrefix)
		if day, _, ok := strings.Cut(remainder, "/"); ok {
			seen[day] = struct{}{}
		}
	}
	days := make([]string, 0, len(seen))
	for day := range seen {
		days = append(days, day)
	}
	sort.Strings(days)
	return days, nil
}

// CleanupBefore removes at most limit aggregate, dedupe, and job records whose
// UTC day precedes cutoff. It is safe to resume after interruption.
func (r *AggregateRecorder) CleanupBefore(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, errors.New("DMARC cleanup limit must be positive")
	}
	cutoffDay := cutoff.UTC().Format(time.DateOnly)
	removed := 0
	for _, prefix := range []string{dmarcAggregatePrefix, dmarcSeenPrefix, dmarcJobPrefix, "limit/day/"} {
		keys, err := r.store.Scan(ctx, model.NSDMARCAggregates, prefix)
		if err != nil {
			return removed, err
		}
		for _, key := range keys {
			remainder := strings.TrimPrefix(key, prefix)
			day, _, ok := strings.Cut(remainder, "/")
			if !ok || day >= cutoffDay {
				continue
			}
			if err := r.store.Delete(ctx, model.NSDMARCAggregates, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return removed, err
			}
			removed++
			if removed >= limit {
				return removed, nil
			}
		}
	}
	return removed, nil
}

func normalizeAggregateObservation(value AggregateObservation, fallback time.Time) (AggregateObservation, error) {
	var err error
	if value.Time.IsZero() {
		value.Time = fallback
	}
	value.Time = value.Time.UTC()
	if ip := net.ParseIP(strings.TrimSpace(value.SourceIP)); ip == nil {
		return value, errors.New("DMARC source IP is invalid")
	} else {
		value.SourceIP = ip.String()
	}
	for target, input := range map[*string]string{&value.Policy.Domain: value.Policy.Domain, &value.HeaderFrom: value.HeaderFrom} {
		*target, err = normalizeReportDomain(input)
		if err != nil {
			return value, err
		}
	}
	if value.EnvelopeFrom != "" {
		value.EnvelopeFrom, err = normalizeReportDomain(value.EnvelopeFrom)
		if err != nil {
			return value, err
		}
	}
	if len(value.Policy.RUA) > maxReportingURIs {
		value.Policy.RUA = value.Policy.RUA[:maxReportingURIs]
	}
	for index := range value.Policy.RUA {
		value.Policy.RUA[index] = truncate(strings.TrimSpace(value.Policy.RUA[index]), 2048)
	}
	if len(value.DKIM) > maxAuthResults {
		value.DKIM = value.DKIM[:maxAuthResults]
	}
	for index := range value.DKIM {
		value.DKIM[index] = normalizeAuthResult(value.DKIM[index])
	}
	value.SPF = normalizeAuthResult(value.SPF)
	value.AttemptID = truncate(strings.TrimSpace(value.AttemptID), 256)
	value.Disposition = normalizeResult(value.Disposition, "none")
	return value, nil
}

func normalizeAuthResult(value AggregateAuthResult) AggregateAuthResult {
	value.Domain = truncate(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value.Domain), ".")), 253)
	value.Selector = truncate(strings.TrimSpace(value.Selector), 63)
	value.Result = normalizeResult(value.Result, "none")
	return value
}

func normalizeResult(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return truncate(value, 32)
}

func normalizeReportDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return "", errors.New("DMARC reporting domain is invalid")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DMARC reporting domain is invalid")
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return "", errors.New("DMARC reporting domain is invalid")
			}
		}
	}
	return value, nil
}

func observationRow(value AggregateObservation) AggregateRow {
	return AggregateRow{SourceIP: value.SourceIP, Disposition: value.Disposition, DKIMAligned: value.DKIMAligned,
		SPFAligned: value.SPFAligned, HeaderFrom: value.HeaderFrom, EnvelopeFrom: value.EnvelopeFrom,
		DKIM: append([]AggregateAuthResult(nil), value.DKIM...), SPF: value.SPF}
}

func digestJSON(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func digestStrings(values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		digest.Write([]byte(value))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return value
}
