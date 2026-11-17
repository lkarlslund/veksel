package messagetrace

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	storepkg "github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type countingStore struct {
	storepkg.Store
	traceGets int
	lists     int
}

type blockingIndexStore struct {
	storepkg.Store
	block   atomic.Bool
	started chan struct{}
	release chan struct{}
}

func (s *blockingIndexStore) DeleteNamespace(ctx context.Context, namespace string) error {
	if namespace == model.NSMessageTraceIndexes && s.block.CompareAndSwap(true, false) {
		close(s.started)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.release:
		}
	}
	return s.Store.DeleteNamespace(ctx, namespace)
}

func (s *countingStore) Get(ctx context.Context, namespace, key string) ([]byte, error) {
	if namespace == model.NSMessageTrace {
		s.traceGets++
	}
	return s.Store.Get(ctx, namespace, key)
}

func (s *countingStore) List(ctx context.Context, namespace string) ([]string, error) {
	s.lists++
	return s.Store.List(ctx, namespace)
}

func testTraceStore(t *testing.T) *Store {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	traces, err := New(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	return traces
}

func TestRecordBuildsDeliveryHistory(t *testing.T) {
	traces := testTraceStore(t)
	base := Record{QueueID: "queue-1", CorrelationID: "transaction-1", Direction: "inbound", EnvelopeSender: "alice@example.test", Recipient: "bob@example.test", Subject: "Hello"}
	first := time.Now().UTC().Add(-time.Minute)
	if err := traces.Record(t.Context(), base, Event{Time: first, Stage: "accepted", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := traces.Record(t.Context(), base, Event{Time: first.Add(time.Second), Stage: "completed", Status: "delivered", Attempt: 1}); err != nil {
		t.Fatal(err)
	}
	record, err := traces.Get(t.Context(), base.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "delivered" || len(record.Events) != 2 || record.CreatedAt != first {
		t.Fatalf("unexpected trace: %+v", record)
	}
}

func TestRecordRetainsTransportSecurityEvidence(t *testing.T) {
	traces := testTraceStore(t)
	base := Record{QueueID: "secure", TransportSecurity: "required"}
	if err := traces.Record(t.Context(), base, Event{Stage: "accepted", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	record, err := traces.Get(t.Context(), base.QueueID)
	if err != nil || record.TransportSecurity != "required" {
		t.Fatalf("record = %+v, error = %v", record, err)
	}
}

func TestRecordRetainsDetachedPolicyExplanation(t *testing.T) {
	traces := testTraceStore(t)
	policy := mailpolicy.Result{Revision: "revision-a", Rules: []mailpolicy.RuleResult{{RuleID: "route", Matched: true}}, Actions: []mailpolicy.Action{{Type: mailpolicy.ActionRoute, Value: "relay.example"}}}
	base := Record{QueueID: "policy-trace", Policy: policy}
	if err := traces.Record(t.Context(), base, Event{Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	policy.Actions[0].Value = "mutated"
	base.Policy.Rules[0].RuleID = "mutated"
	record, err := traces.Get(t.Context(), base.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Policy.Revision != "revision-a" || record.Policy.Rules[0].RuleID != "route" || record.Policy.Actions[0].Value != "relay.example" {
		t.Fatalf("policy evidence = %+v", record.Policy)
	}
}

func TestListFiltersAndPagesNewestFirst(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC()
	for index, record := range []Record{
		{QueueID: "one", Direction: "inbound", EnvelopeSender: "alice@example.test", Recipient: "bob@example.test"},
		{QueueID: "two", Direction: "outbound", EnvelopeSender: "bob@example.test", Recipient: "outside@example.net"},
		{QueueID: "three", Direction: "outbound", EnvelopeSender: "alice@example.test", Recipient: "outside@example.net"},
	} {
		if err := traces.Record(t.Context(), record, Event{Time: now.Add(time.Duration(index) * time.Second), Stage: "accepted", Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := traces.List(t.Context(), Query{Direction: "outbound", Text: "outside", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].QueueID != "three" || page.NextCursor == "" {
		t.Fatalf("unexpected first page: %+v", page)
	}
	next, err := traces.List(t.Context(), Query{Direction: "outbound", Text: "outside", Limit: 1, Cursor: page.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Records) != 1 || next.Records[0].QueueID != "two" || next.NextCursor != "" {
		t.Fatalf("unexpected second page: %+v", next)
	}
}

func TestListFiltersByHalfOpenUpdatedRange(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	for index, id := range []string{"before", "inside", "boundary"} {
		if err := traces.Record(t.Context(), Record{QueueID: id}, Event{Time: now.Add(time.Duration(index) * time.Hour), Status: "delivered"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := traces.List(t.Context(), Query{UpdatedAfter: now.Add(time.Hour), UpdatedBefore: now.Add(2 * time.Hour)})
	if err != nil || len(page.Records) != 1 || page.Records[0].QueueID != "inside" {
		t.Fatalf("range page = %+v, %v", page, err)
	}
}

func TestListCursorIsStableWhenNewerRecordsArrive(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC()
	for _, id := range []string{"c", "b", "a"} {
		if err := traces.Record(t.Context(), Record{QueueID: id}, Event{Time: now, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := traces.List(t.Context(), Query{Limit: 2})
	if err != nil || len(first.Records) != 2 || first.Records[0].QueueID != "c" || first.Records[1].QueueID != "b" {
		t.Fatalf("first page: %+v, %v", first, err)
	}
	if err := traces.Record(t.Context(), Record{QueueID: "new"}, Event{Time: now.Add(time.Minute), Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	second, err := traces.List(t.Context(), Query{Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(second.Records) != 1 || second.Records[0].QueueID != "a" {
		t.Fatalf("stable second page: %+v, %v", second, err)
	}
	if second.Stats.Records != 4 || second.Stats.EventsRetained != 4 {
		t.Fatalf("trace stats: %+v", second.Stats)
	}
}

func TestGetWithRelationsAndCorrelationFilter(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC()
	for index, record := range []Record{
		{QueueID: "original", CorrelationID: "transaction"},
		{QueueID: "dsn", CorrelationID: "transaction", ParentID: "original", Recipient: "sender@example.test"},
		{QueueID: "unrelated", CorrelationID: "elsewhere"},
	} {
		if err := traces.Record(t.Context(), record, Event{Time: now.Add(time.Duration(index) * time.Second), Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	detail, err := traces.GetWithRelations(t.Context(), "original")
	if err != nil || len(detail.Related) != 1 || detail.Related[0].QueueID != "dsn" || detail.Related[0].Relationship != "child" {
		t.Fatalf("related trace: %+v, %v", detail, err)
	}
	page, err := traces.List(t.Context(), Query{CorrelationID: "transaction"})
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("correlation page: %+v, %v", page, err)
	}
}

func TestPruneRemovesOnlyExpiredRecords(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC()
	for _, test := range []struct {
		id string
		at time.Time
	}{{"old", now.Add(-48 * time.Hour)}, {"new", now}} {
		if err := traces.Record(t.Context(), Record{QueueID: test.id}, Event{Time: test.at, Status: "delivered"}); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := traces.Prune(t.Context(), now.Add(-24*time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("prune: removed=%d err=%v", removed, err)
	}
	page, err := traces.List(t.Context(), Query{})
	if err != nil || len(page.Records) != 1 || page.Records[0].QueueID != "new" {
		t.Fatalf("remaining traces: %+v err=%v", page, err)
	}
}

func TestRecordBoundsHistoryAndRetainsOperationalEvidence(t *testing.T) {
	traces := testTraceStore(t)
	base := Record{QueueID: "busy-message"}
	now := time.Now().UTC()
	for index := 0; index < MaxEventsPerRecord+100; index++ {
		event := Event{Time: now.Add(time.Duration(index) * time.Second), Stage: "attempt", Status: "retrying", Attempt: index}
		switch index {
		case 5:
			event.Stage, event.Status = "delivery", "failed"
		case 6:
			event.Stage, event.Status = "operator_hold", "held"
		case 7:
			event.Stage, event.PossibleDuplicate = "uncertain_delivery", true
		}
		if err := traces.Record(t.Context(), base, event); err != nil {
			t.Fatal(err)
		}
	}
	record, err := traces.Get(t.Context(), base.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Events) != MaxEventsPerRecord || record.EventsDropped != 100 {
		t.Fatalf("bounded events = %d, dropped = %d", len(record.Events), record.EventsDropped)
	}
	if record.Events[0].Attempt != 0 || record.Events[len(record.Events)-1].Attempt != MaxEventsPerRecord+99 {
		t.Fatalf("first/latest evidence was not retained: first=%+v latest=%+v", record.Events[0], record.Events[len(record.Events)-1])
	}
	var failure, hold, uncertainty bool
	for _, event := range record.Events {
		failure = failure || event.Status == "failed"
		hold = hold || event.Status == "held"
		uncertainty = uncertainty || event.PossibleDuplicate
	}
	if !failure || !hold || !uncertainty {
		t.Fatalf("operational evidence lost: failure=%t hold=%t uncertainty=%t", failure, hold, uncertainty)
	}
}

func TestRecordBoundsAndFlattensExternalEvidence(t *testing.T) {
	traces := testTraceStore(t)
	long := strings.Repeat("ø", 2200) + "\r\nsecret\x00tail"
	if err := traces.Record(t.Context(), Record{QueueID: "bounded-evidence"}, Event{Stage: "delivery\nresult", Response: long, Route: " relay\t one "}); err != nil {
		t.Fatal(err)
	}
	record, err := traces.Get(t.Context(), "bounded-evidence")
	if err != nil || len(record.Events) != 1 {
		t.Fatalf("record = %+v, %v", record, err)
	}
	event := record.Events[0]
	if len([]rune(event.Response)) != 2048 || strings.ContainsAny(event.Response, "\r\n\x00") || event.Stage != "delivery result" || event.Route != "relay one" {
		t.Fatalf("bounded evidence = %+v", event)
	}
}

func TestIndexBackfillsCanonicalRecordsAndPersistsStats(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err := backend.CreateNamespace(t.Context(), model.NSMessageTrace); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record := Record{QueueID: "legacy", CorrelationID: "transaction", Status: "delivered", UpdatedAt: now, CreatedAt: now, Events: []Event{{Time: now, Status: "delivered"}}}
	data, _ := json.Marshal(record)
	if err := backend.Set(t.Context(), model.NSMessageTrace, record.QueueID, data); err != nil {
		t.Fatal(err)
	}
	traces, err := New(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	status, err := traces.IndexStatus(t.Context())
	if err != nil || status.State != "ready" || status.SchemaVersion != traceIndexSchema || status.Records != 1 {
		t.Fatalf("index status = %+v, %v", status, err)
	}
	page, err := traces.List(t.Context(), Query{CorrelationID: "TRANSACTION"})
	if err != nil || len(page.Records) != 1 || page.Stats.Records != 1 || page.Stats.EventsRetained != 1 || !page.Stats.OldestUpdate.Equal(now) {
		t.Fatalf("backfilled page = %+v, %v", page, err)
	}
}

type batchCountingStore struct {
	storepkg.Store
	batches int
}

func (s *batchCountingStore) Batch(ctx context.Context, fn func(context.Context) error) error {
	s.batches++
	return s.Store.(storepkg.Batcher).Batch(ctx, fn)
}

func TestIndexRebuildCommitsRecordsInBoundedBatches(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err := backend.CreateNamespace(t.Context(), model.NSMessageTrace); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	records := rebuildBatchRecords + 1
	for index := range records {
		record := Record{QueueID: fmt.Sprintf("q%04d", index), Status: "delivered", UpdatedAt: now, CreatedAt: now}
		data, _ := json.Marshal(record)
		if err := backend.Set(t.Context(), model.NSMessageTrace, record.QueueID, data); err != nil {
			t.Fatal(err)
		}
	}
	counting := &batchCountingStore{Store: backend}
	traces, err := New(t.Context(), counting)
	if err != nil {
		t.Fatal(err)
	}
	if counting.batches != 2 {
		t.Fatalf("rebuild batches = %d, want 2 for %d records", counting.batches, records)
	}
	status, err := traces.IndexStatus(t.Context())
	if err != nil || status.State != "ready" || status.Records != records {
		t.Fatalf("index status = %+v, %v", status, err)
	}
}

func TestReverseLexIdentityRoundTripsUnicode(t *testing.T) {
	for _, id := range []string{"trace-1", "kø-id", "配送-1"} {
		decoded, err := decodeReverseLexID(reverseLexID(id))
		if err != nil || decoded != id {
			t.Fatalf("identity %q decoded as %q: %v", id, decoded, err)
		}
	}
}

func TestIndexedListDoesNotEnumerateOrLoadUnmatchedTraceRecords(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	counted := &countingStore{Store: backend}
	traces, err := New(t.Context(), counted)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for index := 0; index < 100; index++ {
		sender := "bulk@example.test"
		if index == 50 {
			sender = "needle@example.test"
		}
		if err := traces.Record(t.Context(), Record{QueueID: fmt.Sprintf("trace-%03d", index), EnvelopeSender: sender}, Event{Time: now.Add(time.Duration(index) * time.Second), Status: "delivered"}); err != nil {
			t.Fatal(err)
		}
	}
	counted.traceGets, counted.lists = 0, 0
	page, err := traces.List(t.Context(), Query{Sender: "NEEDLE@example.test", Limit: 10})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("indexed result = %+v, %v", page, err)
	}
	if counted.lists != 0 || counted.traceGets != 1 {
		t.Fatalf("query used lists=%d trace gets=%d, want 0 and 1", counted.lists, counted.traceGets)
	}
}

func TestRecordUpdateAndPruneKeepIndexAggregatesConsistent(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC()
	base := Record{QueueID: "lifecycle", EnvelopeSender: "sender@example.test", Direction: "outbound"}
	if err := traces.Record(t.Context(), base, Event{Time: now.Add(-48 * time.Hour), Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := traces.Record(t.Context(), base, Event{Time: now, Status: "delivered"}); err != nil {
		t.Fatal(err)
	}
	pending, err := traces.List(t.Context(), Query{Status: "pending"})
	if err != nil || len(pending.Records) != 0 {
		t.Fatalf("stale status index returned %+v, %v", pending, err)
	}
	delivered, err := traces.List(t.Context(), Query{Status: "delivered"})
	if err != nil || len(delivered.Records) != 1 || delivered.Stats.Records != 1 || delivered.Stats.EventsRetained != 2 {
		t.Fatalf("updated trace page = %+v, %v", delivered, err)
	}
	removed, err := traces.Prune(t.Context(), now.Add(time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("prune removed=%d err=%v", removed, err)
	}
	empty, err := traces.List(t.Context(), Query{})
	if err != nil || len(empty.Records) != 0 || empty.Stats.Records != 0 || empty.Stats.EventsRetained != 0 || !empty.Stats.OldestUpdate.IsZero() {
		t.Fatalf("empty indexed page = %+v, %v", empty, err)
	}
}

func TestBoundedPrunePreviewIsOldestFirstAndNonMutating(t *testing.T) {
	traces := testTraceStore(t)
	now := time.Now().UTC()
	for index, id := range []string{"oldest", "middle", "newest"} {
		if err := traces.Record(t.Context(), Record{QueueID: id}, Event{Time: now.Add(time.Duration(index) * time.Hour), Status: "delivered"}); err != nil {
			t.Fatal(err)
		}
	}
	preview, err := traces.PruneWithOptions(t.Context(), now.Add(3*time.Hour), 2, true)
	if err != nil || !preview.DryRun || preview.Examined != 2 || preview.Removed != 0 || preview.Items[0].QueueID != "oldest" || preview.Items[1].QueueID != "middle" {
		t.Fatalf("preview = %+v, %v", preview, err)
	}
	page, _ := traces.List(t.Context(), Query{})
	if page.Stats.Records != 3 {
		t.Fatalf("dry run changed stats: %+v", page.Stats)
	}
	pruned, err := traces.PruneWithOptions(t.Context(), now.Add(3*time.Hour), 2, false)
	if err != nil || pruned.Removed != 2 || !pruned.Items[0].Removed || !pruned.Items[1].Removed {
		t.Fatalf("prune = %+v, %v", pruned, err)
	}
	page, _ = traces.List(t.Context(), Query{})
	if len(page.Records) != 1 || page.Records[0].QueueID != "newest" || page.Stats.Records != 1 {
		t.Fatalf("remaining page = %+v", page)
	}
}

func TestExplicitIndexRebuildPreservesCanonicalTraceResults(t *testing.T) {
	traces := testTraceStore(t)
	if err := traces.Record(t.Context(), Record{QueueID: "rebuild", Recipient: "user@example.test"}, Event{Status: "delivered"}); err != nil {
		t.Fatal(err)
	}
	before, err := traces.MaintenanceStatus(t.Context())
	if err != nil || before.Index.State != "ready" || before.Stats.Records != 1 {
		t.Fatalf("status before = %+v, %v", before, err)
	}
	status, err := traces.RebuildIndex(t.Context())
	if err != nil || status.State != "ready" || status.Records != 1 || status.BuiltAt.Before(before.Index.BuiltAt) {
		t.Fatalf("rebuilt status = %+v, %v", status, err)
	}
	page, err := traces.List(t.Context(), Query{Recipient: "USER@example.test"})
	if err != nil || len(page.Records) != 1 || page.Records[0].QueueID != "rebuild" {
		t.Fatalf("result after rebuild = %+v, %v", page, err)
	}
}

func TestIndexRebuildSerializesConcurrentTraceMutation(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	blocking := &blockingIndexStore{Store: backend, started: make(chan struct{}), release: make(chan struct{})}
	traces, err := New(t.Context(), blocking)
	if err != nil {
		t.Fatal(err)
	}
	if err := traces.Record(t.Context(), Record{QueueID: "before"}, Event{Status: "delivered"}); err != nil {
		t.Fatal(err)
	}
	blocking.block.Store(true)
	rebuildDone := make(chan error, 1)
	go func() {
		_, rebuildErr := traces.RebuildIndex(t.Context())
		rebuildDone <- rebuildErr
	}()
	<-blocking.started
	recordDone := make(chan error, 1)
	go func() {
		recordDone <- traces.Record(t.Context(), Record{QueueID: "during"}, Event{Status: "delivered"})
	}()
	select {
	case err := <-recordDone:
		t.Fatalf("record escaped rebuild lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(blocking.release)
	if err := <-rebuildDone; err != nil {
		t.Fatal(err)
	}
	if err := <-recordDone; err != nil {
		t.Fatal(err)
	}
	page, err := traces.List(t.Context(), Query{})
	if err != nil || len(page.Records) != 2 || page.Stats.Records != 2 {
		t.Fatalf("post-rebuild page = %+v, %v", page, err)
	}
}
