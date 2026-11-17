package tlsrpt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	aggregatePrefix        = "aggregate/"
	seenPrefix             = "seen/"
	defaultMaxFailureKinds = 256
)

// Recorder atomically deduplicates and aggregates privacy-bounded TLS session
// outcomes in the generic system store.
type Recorder struct {
	store           store.Store
	now             func() time.Time
	maxFailureKinds int
	sequence        atomic.Uint64
}

// RecorderOptions controls bounded aggregation behavior.
type RecorderOptions struct {
	Now             func() time.Time
	MaxFailureKinds int
}

// NewRecorder creates a recorder. Atomic batching is required because a
// deduplication marker and its aggregate count form one durability invariant.
func NewRecorder(ctx context.Context, backend store.Store, options RecorderOptions) (*Recorder, error) {
	if backend == nil {
		return nil, errors.New("TLS report store is required")
	}
	if _, ok := backend.(store.Batcher); !ok {
		return nil, errors.New("TLS report store requires atomic batch support")
	}
	exists, err := backend.NamespaceExists(ctx, model.NSTLSRPT)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, model.NSTLSRPT); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MaxFailureKinds <= 0 {
		options.MaxFailureKinds = defaultMaxFailureKinds
	}
	return &Recorder{store: backend, now: options.Now, maxFailureKinds: options.MaxFailureKinds}, nil
}

// Record durably accounts for event exactly once for a given attempt and
// normalized outcome. Suppressed report-delivery contexts are ignored.
func (r *Recorder) Record(ctx context.Context, event Event) error {
	if IsSuppressed(ctx) {
		return nil
	}
	now := r.now().UTC()
	normalized, err := normalizeEvent(event, now)
	if err != nil {
		return err
	}
	if normalized.AttemptID == "" {
		normalized.AttemptID = "direct-" + strconv.FormatInt(now.UnixNano(), 10) + "-" + strconv.FormatUint(r.sequence.Add(1), 10)
	}
	day := normalized.Time.Format(time.DateOnly)
	policyDigest := policyID(normalized.Policy)
	aggregateKey := aggregatePrefix + day + "/" + normalized.Policy.Domain + "/" + policyDigest
	seenBase := seenPrefix + day + "/" + normalized.Policy.Domain + "/"
	detailKey := seenBase + "detail/" + eventDigest(normalized)
	summaryKey := seenBase + "summary/" + summaryDigest(normalized)

	return store.Batch(ctx, r.store, func(batchCtx context.Context) error {
		if err := r.store.Put(batchCtx, model.NSTLSRPT, detailKey, []byte(`{"seen":true}`)); err != nil {
			if errors.Is(err, store.ErrExists) {
				return nil
			}
			return fmt.Errorf("store TLS report deduplication marker: %w", err)
		}
		aggregate, err := r.loadAggregate(batchCtx, aggregateKey)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if errors.Is(err, store.ErrNotFound) {
			aggregate = Aggregate{ID: policyDigest, Day: day, Policy: normalized.Policy}
		}
		summaryNew := true
		if err := r.store.Put(batchCtx, model.NSTLSRPT, summaryKey, []byte(`{"seen":true}`)); err != nil {
			if !errors.Is(err, store.ErrExists) {
				return fmt.Errorf("store TLS report session marker: %w", err)
			}
			summaryNew = false
		}
		if normalized.Success {
			if summaryNew {
				aggregate.SuccessfulSessions++
			}
		} else {
			if summaryNew {
				aggregate.FailedSessions++
			}
			r.addFailure(&aggregate, normalized)
		}
		aggregate.UpdatedAt = now
		encoded, err := json.Marshal(aggregate)
		if err != nil {
			return err
		}
		if err := r.store.Set(batchCtx, model.NSTLSRPT, aggregateKey, encoded); err != nil {
			return fmt.Errorf("store TLS report aggregate: %w", err)
		}
		return nil
	})
}

// Aggregates returns a stable sorted snapshot for one UTC day and optional
// policy domain.
func (r *Recorder) Aggregates(ctx context.Context, day, domain string) ([]Aggregate, error) {
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		return nil, errors.New("TLS report day must use YYYY-MM-DD")
	}
	prefix := aggregatePrefix + day + "/"
	if domain != "" {
		prefix += strings.ToLower(strings.TrimSuffix(domain, ".")) + "/"
	}
	result := make([]Aggregate, 0)
	err := r.store.Iterate(ctx, model.NSTLSRPT, prefix, func(_ string, value []byte) (bool, error) {
		var aggregate Aggregate
		if err := json.Unmarshal(value, &aggregate); err != nil {
			return false, err
		}
		result = append(result, aggregate)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Policy.Domain == result[j].Policy.Domain {
			return result[i].ID < result[j].ID
		}
		return result[i].Policy.Domain < result[j].Policy.Domain
	})
	return result, nil
}

// Days returns UTC days with retained aggregates.
func (r *Recorder) Days(ctx context.Context) ([]string, error) {
	keys, err := r.store.Scan(ctx, model.NSTLSRPT, aggregatePrefix)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, key := range keys {
		remainder := strings.TrimPrefix(key, aggregatePrefix)
		day, _, ok := strings.Cut(remainder, "/")
		if ok {
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

// DeleteDayDomain removes delivered/expired aggregates and their dedupe keys.
func (r *Recorder) DeleteDayDomain(ctx context.Context, day, domain string) (int, error) {
	prefixes := []string{aggregatePrefix + day + "/" + domain + "/", seenPrefix + day + "/" + domain + "/"}
	removed := 0
	for _, prefix := range prefixes {
		keys, err := r.store.Scan(ctx, model.NSTLSRPT, prefix)
		if err != nil {
			return removed, err
		}
		for _, key := range keys {
			if err := r.store.Delete(ctx, model.NSTLSRPT, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

func (r *Recorder) loadAggregate(ctx context.Context, key string) (Aggregate, error) {
	data, err := r.store.Get(ctx, model.NSTLSRPT, key)
	if err != nil {
		return Aggregate{}, err
	}
	var aggregate Aggregate
	if err := json.Unmarshal(data, &aggregate); err != nil {
		return Aggregate{}, err
	}
	return aggregate, nil
}

func (r *Recorder) addFailure(aggregate *Aggregate, event Event) {
	detail := FailureDetail{ResultType: event.ResultType, SendingMTAIP: event.SendingMTAIP,
		ReceivingMXHostname: event.ReceivingMX, ReceivingMXHELO: event.ReceivingMXHELO,
		ReceivingIP: event.ReceivingIP, FailureReasonCode: event.FailureReasonCode}
	digest := failureDigest(detail)
	for index := range aggregate.Failures {
		if failureDigest(aggregate.Failures[index]) == digest {
			aggregate.Failures[index].FailedSessionCount++
			return
		}
	}
	if len(aggregate.Failures) < r.maxFailureKinds {
		detail.FailedSessionCount = 1
		aggregate.Failures = append(aggregate.Failures, detail)
		return
	}
	aggregate.FailureKindsDropped++
	const overflowReason = "failure-detail-limit-reached"
	for index := range aggregate.Failures {
		if aggregate.Failures[index].ResultType == ResultValidationFailure && aggregate.Failures[index].FailureReasonCode == overflowReason {
			aggregate.Failures[index].FailedSessionCount++
			return
		}
	}
	// Replace the final distinct bucket so the report's failure-detail counts
	// continue to add up to its failure summary without unbounded cardinality.
	last := len(aggregate.Failures) - 1
	aggregate.Failures[last] = FailureDetail{ResultType: ResultValidationFailure, FailureReasonCode: overflowReason,
		FailedSessionCount: aggregate.Failures[last].FailedSessionCount + 1}
}

func eventDigest(event Event) string {
	digest := sha256.New()
	for _, value := range []string{event.AttemptID, policyID(event.Policy), event.ReceivingMX, event.ReceivingMXHELO,
		event.SendingMTAIP, event.ReceivingIP, strconv.FormatBool(event.Success), event.ResultType, event.FailureReasonCode} {
		digest.Write([]byte(value))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func summaryDigest(event Event) string {
	digest := sha256.New()
	for _, value := range []string{event.AttemptID, policyID(event.Policy), event.ReceivingMX, strconv.FormatBool(event.Success)} {
		digest.Write([]byte(value))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func failureDigest(detail FailureDetail) string {
	digest := sha256.New()
	for _, value := range []string{detail.ResultType, detail.SendingMTAIP, detail.ReceivingMXHostname,
		detail.ReceivingMXHELO, detail.ReceivingIP, detail.FailureReasonCode} {
		digest.Write([]byte(value))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}
