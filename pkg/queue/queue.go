// Package queue provides Veksel' durable system queue for inbound and outbound
// mail. Production queues use the same generic disk-backed store as folders;
// an in-memory mode remains available for focused unit tests.
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
)

var logger = log.For(log.ModuleQueue)

const (
	messageKeyPrefix    = "message/"
	batchKeyPrefix      = "batch/"
	receiptKeyPrefix    = "receipt/"
	acceptanceKeyPrefix = "acceptance/"
	// DeliveryExternalIDNamespace makes a local mailbox append idempotent
	// across a crash between the item commit and queue acknowledgement.
	DeliveryExternalIDNamespace = "veksel.system-queue"
)

var (
	ErrFull                = errors.New("queue is full")
	ErrDuplicate           = errors.New("duplicate queue message")
	ErrRerouteNotFound     = errors.New("queue message not found")
	ErrRerouteDirection    = errors.New("only outbound queue messages can be rerouted")
	ErrRerouteState        = errors.New("queue message cannot be rerouted in its current state")
	ErrRerouteUnchanged    = errors.New("queue message already uses that administrative route")
	ErrIdempotencyConflict = errors.New("queue idempotency key was already used for a different batch")
)

// AttemptRecord preserves the durable outcome of one delivery claim.
type AttemptRecord struct {
	ID        string        `json:"id"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Class     DeliveryClass `json:"class,omitempty"`
	Code      string        `json:"code,omitempty"`
	Response  string        `json:"response,omitempty"`
	// TLSPolicy is the transport-security evidence of the attempt, such as
	// a DANE (RFC 7672) verification outcome.
	TLSPolicy string `json:"tls_policy,omitempty"`
}

// RouteChange records an operator's durable change to outbound routing. An
// empty route means normal automatic/policy routing. History is bounded so an
// administratively noisy item cannot grow without limit.
type RouteChange struct {
	Previous string    `json:"previous,omitempty"`
	Current  string    `json:"current,omitempty"`
	Actor    string    `json:"actor"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

// Direction describes which side of the system accepted a queue item.
type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

// Message represents one durable delivery job.
type Message struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
	ParentID       string            `json:"parent_id,omitempty"`
	Direction      Direction         `json:"direction,omitempty"`
	EnvelopeSender string            `json:"envelope_sender"`
	Recipient      string            `json:"recipient"`
	Headers        map[string]string `json:"headers"`
	Body           []byte            `json:"-"`
	// Content, when set, is the exact RFC 5322 message to deliver or relay;
	// Headers is then only a lookup view of it. Producers set it whenever
	// header order or repeated fields (Received, DKIM-Signature) matter,
	// because a header map keeps one value per name.
	Content             []byte            `json:"-"`
	TargetFolderID      string            `json:"target_folder_id,omitempty"`
	TargetFolderPath    string            `json:"target_folder_path,omitempty"`
	TargetOwnerID       string            `json:"target_owner_id,omitempty"`
	DeliveryRoute       string            `json:"delivery_route,omitempty"`
	AdministrativeRoute string            `json:"administrative_route,omitempty"`
	RouteChanges        []RouteChange     `json:"route_changes,omitempty"`
	RouteChangesDropped int64             `json:"route_changes_dropped,omitempty"`
	Status              Status            `json:"status"`
	RetryCount          int               `json:"retry_count"`
	NextRetry           time.Time         `json:"next_retry"`
	LastError           string            `json:"last_error,omitempty"`
	LastCode            string            `json:"last_code,omitempty"`
	LastResponse        string            `json:"last_response,omitempty"`
	AttemptID           string            `json:"attempt_id,omitempty"`
	ClaimedAt           time.Time         `json:"claimed_at,omitzero"`
	ExpiresAt           time.Time         `json:"expires_at,omitzero"`
	CompletedAt         time.Time         `json:"completed_at,omitzero"`
	FailureMessageID    string            `json:"failure_message_id,omitempty"`
	HoldReason          string            `json:"hold_reason,omitempty"`
	HeldAt              time.Time         `json:"held_at,omitzero"`
	ReleasedAt          time.Time         `json:"released_at,omitzero"`
	PendingHoldReason   string            `json:"pending_hold_reason,omitempty"`
	PendingHoldAt       time.Time         `json:"pending_hold_at,omitzero"`
	PossibleDuplicate   bool              `json:"possible_duplicate,omitempty"`
	Attempts            []AttemptRecord   `json:"attempts,omitempty"`
	AttemptsDropped     int64             `json:"attempts_dropped,omitempty"`
	Policy              mailpolicy.Result `json:"policy,omitempty"`
	PolicyRoute         string            `json:"policy_route,omitempty"`
	AuthenticatedActor  string            `json:"authenticated_actor,omitempty"`
	SourceIP            string            `json:"source_ip,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	// DKIM asks admission to sign a locally originated message; it is
	// consumed before the message is stored.
	DKIM *dkim.Request `json:"-"`
}

type diskMessage struct {
	ID                  string            `json:"id"`
	Kind                string            `json:"kind,omitempty"`
	Attributes          map[string]string `json:"attributes,omitempty"`
	CorrelationID       string            `json:"correlation_id,omitempty"`
	ParentID            string            `json:"parent_id,omitempty"`
	Direction           Direction         `json:"direction,omitempty"`
	EnvelopeSender      string            `json:"envelope_sender"`
	Recipient           string            `json:"recipient"`
	Headers             map[string]string `json:"headers"`
	Body                []byte            `json:"body,omitempty"`
	Content             []byte            `json:"content,omitempty"`
	TargetFolderID      string            `json:"target_folder_id,omitempty"`
	TargetFolderPath    string            `json:"target_folder_path,omitempty"`
	TargetOwnerID       string            `json:"target_owner_id,omitempty"`
	DeliveryRoute       string            `json:"delivery_route,omitempty"`
	AdministrativeRoute string            `json:"administrative_route,omitempty"`
	RouteChanges        []RouteChange     `json:"route_changes,omitempty"`
	RouteChangesDropped int64             `json:"route_changes_dropped,omitempty"`
	Status              Status            `json:"status"`
	RetryCount          int               `json:"retry_count"`
	NextRetry           time.Time         `json:"next_retry"`
	LastError           string            `json:"last_error,omitempty"`
	LastCode            string            `json:"last_code,omitempty"`
	LastResponse        string            `json:"last_response,omitempty"`
	AttemptID           string            `json:"attempt_id,omitempty"`
	ClaimedAt           time.Time         `json:"claimed_at,omitzero"`
	ExpiresAt           time.Time         `json:"expires_at,omitzero"`
	CompletedAt         time.Time         `json:"completed_at,omitzero"`
	FailureMessageID    string            `json:"failure_message_id,omitempty"`
	HoldReason          string            `json:"hold_reason,omitempty"`
	HeldAt              time.Time         `json:"held_at,omitzero"`
	ReleasedAt          time.Time         `json:"released_at,omitzero"`
	PendingHoldReason   string            `json:"pending_hold_reason,omitempty"`
	PendingHoldAt       time.Time         `json:"pending_hold_at,omitzero"`
	PossibleDuplicate   bool              `json:"possible_duplicate,omitempty"`
	Attempts            []AttemptRecord   `json:"attempts,omitempty"`
	AttemptsDropped     int64             `json:"attempts_dropped,omitempty"`
	Policy              mailpolicy.Result `json:"policy,omitempty"`
	PolicyRoute         string            `json:"policy_route,omitempty"`
	AuthenticatedActor  string            `json:"authenticated_actor,omitempty"`
	SourceIP            string            `json:"source_ip,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
}

func toDiskMessage(m *Message) diskMessage {
	return diskMessage{
		ID: m.ID, Kind: m.Kind, Attributes: m.Attributes, CorrelationID: m.CorrelationID, ParentID: m.ParentID, Direction: m.Direction,
		EnvelopeSender: m.EnvelopeSender, Recipient: m.Recipient, Headers: m.Headers,
		Body: m.Body, Content: m.Content, TargetFolderID: m.TargetFolderID, TargetFolderPath: m.TargetFolderPath, TargetOwnerID: m.TargetOwnerID, DeliveryRoute: m.DeliveryRoute,
		AdministrativeRoute: m.AdministrativeRoute, RouteChanges: append([]RouteChange(nil), m.RouteChanges...), RouteChangesDropped: m.RouteChangesDropped,
		Status: m.Status, RetryCount: m.RetryCount, NextRetry: m.NextRetry,
		LastError: m.LastError, LastCode: m.LastCode, LastResponse: m.LastResponse,
		AttemptID: m.AttemptID, ClaimedAt: m.ClaimedAt, ExpiresAt: m.ExpiresAt, CompletedAt: m.CompletedAt,
		FailureMessageID: m.FailureMessageID, HoldReason: m.HoldReason, HeldAt: m.HeldAt, ReleasedAt: m.ReleasedAt,
		PendingHoldReason: m.PendingHoldReason, PendingHoldAt: m.PendingHoldAt,
		PossibleDuplicate: m.PossibleDuplicate, Attempts: append([]AttemptRecord(nil), m.Attempts...),
		AttemptsDropped: m.AttemptsDropped, Policy: m.Policy.Clone(), PolicyRoute: m.PolicyRoute,
		AuthenticatedActor: m.AuthenticatedActor, SourceIP: m.SourceIP, CreatedAt: m.CreatedAt,
	}
}

func fromDiskMessage(m diskMessage) *Message {
	return &Message{ID: m.ID, Kind: m.Kind, Attributes: m.Attributes, CorrelationID: m.CorrelationID, ParentID: m.ParentID, Direction: m.Direction, EnvelopeSender: m.EnvelopeSender,
		Recipient: m.Recipient, Headers: m.Headers, Body: m.Body, Content: m.Content,
		TargetFolderID: m.TargetFolderID, TargetFolderPath: m.TargetFolderPath, TargetOwnerID: m.TargetOwnerID, DeliveryRoute: m.DeliveryRoute,
		AdministrativeRoute: m.AdministrativeRoute, RouteChanges: append([]RouteChange(nil), m.RouteChanges...), RouteChangesDropped: m.RouteChangesDropped,
		Status: m.Status, RetryCount: m.RetryCount,
		NextRetry: m.NextRetry, LastError: m.LastError, LastCode: m.LastCode, LastResponse: m.LastResponse,
		AttemptID: m.AttemptID, ClaimedAt: m.ClaimedAt, ExpiresAt: m.ExpiresAt, CompletedAt: m.CompletedAt,
		FailureMessageID: m.FailureMessageID, HoldReason: m.HoldReason, HeldAt: m.HeldAt, ReleasedAt: m.ReleasedAt,
		PendingHoldReason: m.PendingHoldReason, PendingHoldAt: m.PendingHoldAt,
		PossibleDuplicate: m.PossibleDuplicate, Attempts: append([]AttemptRecord(nil), m.Attempts...),
		AttemptsDropped: m.AttemptsDropped, Policy: m.Policy.Clone(), PolicyRoute: m.PolicyRoute,
		AuthenticatedActor: m.AuthenticatedActor, SourceIP: m.SourceIP, CreatedAt: m.CreatedAt}
}

type batchJournal struct {
	MessageIDs    []string `json:"message_ids"`
	AcceptanceKey string   `json:"acceptance_key,omitempty"`
}

// AcceptanceReceipt permanently records the message IDs atomically admitted
// for a caller-provided idempotency key. It contains no message content.
type AcceptanceReceipt struct {
	Key        string    `json:"key"`
	MessageIDs []string  `json:"message_ids"`
	AcceptedAt time.Time `json:"accepted_at"`
}

type Status string

const (
	StatusPending    Status = "pending"
	StatusProcessing Status = "processing"
	StatusRetrying   Status = "retrying"
	StatusHeld       Status = "held"
	StatusPaused     Status = "paused"
	StatusFailed     Status = "failed"
	StatusDelivered  Status = "delivered"
	StatusCancelled  Status = "cancelled"
)

// Stats is a point-in-time operational view of the durable queue.
type Stats struct {
	Size                    int               `json:"size"`
	ByStatus                map[Status]int    `json:"by_status"`
	ByDirection             map[Direction]int `json:"by_direction"`
	OldestAgeSeconds        float64           `json:"oldest_age_seconds"`
	AttemptsRetained        int               `json:"attempts_retained"`
	AttemptsDropped         int64             `json:"attempts_dropped"`
	CompletionReceipts      int               `json:"completion_receipts"`
	OldestReceiptAgeSeconds float64           `json:"oldest_receipt_age_seconds"`
	NewestReceiptAgeSeconds float64           `json:"newest_receipt_age_seconds"`
	LastReceiptPruneAt      time.Time         `json:"last_receipt_prune_at,omitzero"`
	LastReceiptPruneRemoved int               `json:"last_receipt_prune_removed"`
	LastReceiptPruneError   string            `json:"last_receipt_prune_error,omitempty"`
}

type ReceiptPruneItem struct {
	ID          string    `json:"id"`
	CompletedAt time.Time `json:"completed_at"`
	Removed     bool      `json:"removed"`
	Error       string    `json:"error,omitempty"`
}

type ReceiptPruneResult struct {
	Before   time.Time          `json:"before"`
	DryRun   bool               `json:"dry_run"`
	Examined int                `json:"examined"`
	Removed  int                `json:"removed"`
	Items    []ReceiptPruneItem `json:"items"`
}

const DefaultMaxSize = 10000
const MaxAttemptRecords = 256
const MaxRouteChanges = 32
const MaxReceiptPruneRecords = 10000

type DeliveryFunc func(ctx context.Context, msg *Message) error
type FailureMessageFunc func(failed *Message) *Message

// Event describes a durable queue lifecycle transition.
type Event struct {
	Message           Message
	Stage             string
	Status            Status
	Attempt           int
	Code              string
	Response          string
	Destination       string
	Route             string
	OutcomeClass      string
	TLSPolicy         string
	DurationMillis    int64
	RetryAt           time.Time
	PossibleDuplicate bool
	Time              time.Time
}

// Observer receives queue lifecycle events after their authoritative state is persisted.
type Observer func(context.Context, Event)

type deliveryEvidenceKey struct{}

type deliveryEvidence struct{ route, tlsPolicy string }

// RecordDeliveryRoute attaches bounded, non-secret routing evidence to the
// current queue attempt without allowing a delivery callback to mutate the
// authoritative queue message.
func RecordDeliveryRoute(ctx context.Context, route string) {
	if evidence, _ := ctx.Value(deliveryEvidenceKey{}).(*deliveryEvidence); evidence != nil {
		evidence.route = boundedOperationalText(strings.TrimSpace(route), 256)
	}
}

// RecordTLSPolicy attaches the transport-security outcome (for example a
// DANE verification result) to the current queue attempt. The latest value
// wins, so a multi-MX attempt keeps the outcome of the host it ended on.
func RecordTLSPolicy(ctx context.Context, outcome string) {
	if evidence, _ := ctx.Value(deliveryEvidenceKey{}).(*deliveryEvidence); evidence != nil {
		evidence.tlsPolicy = boundedOperationalText(strings.TrimSpace(outcome), 512)
	}
}

// DeliveryClass controls durable retry behavior.
type DeliveryClass string

const (
	DeliverySuccess   DeliveryClass = "success"
	DeliveryTemporary DeliveryClass = "temporary"
	DeliveryPermanent DeliveryClass = "permanent"
	DeliveryUncertain DeliveryClass = "uncertain"
	DeliveryDeferred  DeliveryClass = "deferred"
)

// DeliveryError carries a machine-readable outcome from a delivery adapter.
type DeliveryError struct {
	Class        DeliveryClass
	EnhancedCode string
	Response     string
	RetryAfter   time.Duration
	Err          error
}

func (e *DeliveryError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.Response != "" {
		return e.Response
	}
	return string(e.Class) + " delivery failure"
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// MaxWorkers bounds the delivery worker pool.
const MaxWorkers = 1024

// Limits are the queue settings that may change while the queue runs.
type Limits struct {
	MaxSize           int
	Workers           int
	MaxPerDestination int
	MaxAge            time.Duration
	RetryInitial      time.Duration
	RetryMax          time.Duration
	ReceiptRetention  time.Duration
}

// Validate reports the first limit that is out of range.
func (l Limits) Validate() error {
	switch {
	case l.MaxSize < 1:
		return errors.New("queue maximum size must be positive")
	case l.Workers < 1 || l.Workers > MaxWorkers:
		return fmt.Errorf("queue workers must be between 1 and %d", MaxWorkers)
	case l.MaxPerDestination < 1:
		return errors.New("queue per-destination limit must be positive")
	case l.MaxAge <= 0:
		return errors.New("queue maximum age must be positive")
	case l.RetryInitial <= 0 || l.RetryMax <= 0:
		return errors.New("queue retry delays must be positive")
	case l.RetryInitial > l.RetryMax:
		return errors.New("queue initial retry delay exceeds the maximum retry delay")
	case l.ReceiptRetention <= 0:
		return errors.New("queue receipt retention must be positive")
	}
	return nil
}

type Config struct {
	MaxSize           int
	Delivery          DeliveryFunc
	ProcessPeriod     time.Duration
	Workers           int
	MaxPerDestination int
	MaxAge            time.Duration
	RetryInitial      time.Duration
	RetryMax          time.Duration
	Observer          Observer
	FailureMessage    FailureMessageFunc
	ReceiptRetention  time.Duration
	Admission         func(context.Context, *Message) error
	// Screen sees each prepared batch after per-message admission and
	// signing, before it is persisted. It may reject the whole batch or hold
	// its messages; undo reverses its accounting when the batch is not
	// committed. It runs under the queue lock and must not call the queue.
	Screen func(ctx context.Context, batch []*Message) (undo func(), err error)
	// DeliveryHold sees each message about to be claimed for a delivery
	// attempt and returns a non-empty reason when it must be paused instead,
	// such as mail of an account held after admission. It must treat the
	// message as read-only; it runs under the queue lock and must not call
	// the queue.
	DeliveryHold func(*Message) string
	// Signer DKIM-signs admitted messages that carry a DKIM request.
	Signer *dkim.Signer
	// Copies returns administrative copies (always-BCC, journal) of an
	// admitted and screened batch. They are committed atomically with it and
	// skip admission, signing, and screening; each needs an explicit ID
	// derived from its original so a replayed batch stays a duplicate. It
	// runs under the queue lock and must not call the queue.
	Copies func(ctx context.Context, batch []*Message) ([]*Message, error)
}

type CompletionReceipt struct {
	ID          string    `json:"id"`
	CompletedAt time.Time `json:"completed_at"`
}

// Queue uses the generic store as its authority when backend is non-nil. msgs
// is only the in-process scheduling index and is reconstructed at startup.
type Queue struct {
	mu                      sync.Mutex
	msgs                    []*Message
	cfg                     Config
	delivery                DeliveryFunc
	backend                 store.Store
	nextID                  uint64
	nextAttempt             uint64
	inFlight                map[string]int
	completed               map[string]time.Time
	accepted                map[string]AcceptanceReceipt
	lastReceiptPrune        time.Time
	lastReceiptPruneRemoved int
	lastReceiptPruneError   string
	stopCh                  chan struct{}
	wakeCh                  chan struct{}
	close                   sync.Once
	// workersMu serializes pool resizing and Close. Each active worker owns
	// one retire channel; closing it lets the worker exit between deliveries.
	workersMu     sync.Mutex
	workerRetire  []chan struct{}
	workerGroup   sync.WaitGroup
	workerCount   atomic.Int32
	runningWorker atomic.Int32
	closed        bool
	ctx           context.Context
	cancel        context.CancelFunc
}

// New creates an in-memory queue. Production callers should use NewPersistent.
func New(cfg *Config) *Queue {
	q, err := newQueue(context.Background(), nil, cfg)
	if err != nil {
		panic(err)
	}
	return q
}

// NewPersistent opens a durable queue backed by the configured generic store.
// It fails closed when persisted state cannot be loaded or recovered.
func NewPersistent(ctx context.Context, backend store.Store, cfg *Config) (*Queue, error) {
	if backend == nil {
		return nil, fmt.Errorf("queue store is required")
	}
	return newQueue(ctx, backend, cfg)
}

func newQueue(ctx context.Context, backend store.Store, cfg *Config) (*Queue, error) {
	var c Config
	if cfg != nil {
		c = *cfg
	}
	if c.MaxSize <= 0 {
		c.MaxSize = DefaultMaxSize
	}
	if c.ProcessPeriod <= 0 {
		c.ProcessPeriod = 10 * time.Second
	}
	if c.Workers <= 0 {
		c.Workers = 4
	}
	c.Workers = min(c.Workers, MaxWorkers)
	if c.MaxPerDestination <= 0 || c.MaxPerDestination > c.Workers {
		c.MaxPerDestination = c.Workers
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 5 * 24 * time.Hour
	}
	if c.RetryInitial <= 0 {
		c.RetryInitial = time.Minute
	}
	if c.RetryMax <= 0 {
		c.RetryMax = 4 * time.Hour
	}
	if c.ReceiptRetention <= 0 {
		c.ReceiptRetention = 7 * 24 * time.Hour
	}
	queueCtx, cancel := context.WithCancel(context.Background())
	q := &Queue{cfg: c, delivery: c.Delivery, backend: backend,
		msgs: make([]*Message, 0, min(c.MaxSize, DefaultMaxSize)), stopCh: make(chan struct{}),
		wakeCh: make(chan struct{}, MaxWorkers), inFlight: make(map[string]int), completed: make(map[string]time.Time), accepted: make(map[string]AcceptanceReceipt), ctx: queueCtx, cancel: cancel}
	if backend != nil {
		if err := q.restore(ctx); err != nil {
			return nil, err
		}
	}
	q.workersMu.Lock()
	q.resizeWorkersLocked(c.Workers)
	q.workersMu.Unlock()
	return q, nil
}

// Limits returns the queue settings currently in effect.
func (q *Queue) Limits() Limits {
	q.mu.Lock()
	defer q.mu.Unlock()
	return Limits{MaxSize: q.cfg.MaxSize, Workers: q.cfg.Workers, MaxPerDestination: q.cfg.MaxPerDestination,
		MaxAge: q.cfg.MaxAge, RetryInitial: q.cfg.RetryInitial, RetryMax: q.cfg.RetryMax, ReceiptRetention: q.cfg.ReceiptRetention}
}

// Reconfigure applies new limits to the running queue, or returns an error
// and keeps the current limits. Added workers start immediately; retired
// workers exit after the delivery they are running, which is never
// interrupted. Retry, age, and retention values apply to subsequent
// scheduling decisions: accepted messages keep the ExpiresAt promised at
// acceptance and their already scheduled NextRetry, so shortening the maximum
// age never bounces queued mail en masse. A per-destination limit above the
// worker count is clamped to it, as at startup.
func (q *Queue) Reconfigure(limits Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	q.workersMu.Lock()
	defer q.workersMu.Unlock()
	if q.closed {
		return errors.New("queue is closed")
	}
	q.mu.Lock()
	if size := len(q.msgs); limits.MaxSize < size {
		q.mu.Unlock()
		return fmt.Errorf("queue holds %d messages, above requested maximum %d", size, limits.MaxSize)
	}
	q.cfg.MaxSize, q.cfg.Workers = limits.MaxSize, limits.Workers
	q.cfg.MaxPerDestination = min(limits.MaxPerDestination, limits.Workers)
	q.cfg.MaxAge, q.cfg.RetryInitial, q.cfg.RetryMax = limits.MaxAge, limits.RetryInitial, limits.RetryMax
	q.cfg.ReceiptRetention = limits.ReceiptRetention
	q.mu.Unlock()
	q.resizeWorkersLocked(limits.Workers)
	q.wakeWorkers()
	return nil
}

// resizeWorkersLocked starts or retires workers until n are active. The
// caller holds workersMu.
func (q *Queue) resizeWorkersLocked(n int) {
	for len(q.workerRetire) < n {
		retire := make(chan struct{})
		q.workerRetire = append(q.workerRetire, retire)
		q.workerGroup.Add(1)
		go func() {
			defer q.workerGroup.Done()
			q.runWorker(retire)
		}()
	}
	for len(q.workerRetire) > n {
		last := len(q.workerRetire) - 1
		close(q.workerRetire[last])
		q.workerRetire = q.workerRetire[:last]
	}
	q.workerCount.Store(int32(n))
}

func (q *Queue) restore(ctx context.Context) error {
	acceptanceKeys, err := q.backend.Scan(ctx, model.NSQueue, acceptanceKeyPrefix)
	if err != nil {
		return fmt.Errorf("scan queue acceptance receipts: %w", err)
	}
	for _, key := range acceptanceKeys {
		data, getErr := q.backend.Get(ctx, model.NSQueue, key)
		if getErr != nil {
			return fmt.Errorf("load queue acceptance receipt %q: %w", key, getErr)
		}
		var receipt AcceptanceReceipt
		if err := json.Unmarshal(data, &receipt); err != nil || receipt.Key == "" || len(receipt.MessageIDs) == 0 {
			return fmt.Errorf("decode queue acceptance receipt %q: %w", key, errors.Join(err, errors.New("invalid acceptance receipt")))
		}
		q.accepted[receipt.Key] = receipt
	}
	receiptKeys, err := q.backend.Scan(ctx, model.NSQueue, receiptKeyPrefix)
	if err != nil {
		return fmt.Errorf("scan queue completion receipts: %w", err)
	}
	cutoff := time.Now().UTC().Add(-q.cfg.ReceiptRetention)
	for _, key := range receiptKeys {
		data, getErr := q.backend.Get(ctx, model.NSQueue, key)
		if getErr != nil {
			return fmt.Errorf("load queue completion receipt %q: %w", key, getErr)
		}
		var receipt CompletionReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return fmt.Errorf("decode queue completion receipt %q: %w", key, err)
		}
		if receipt.ID == "" || receipt.CompletedAt.Before(cutoff) {
			if err := q.deleteKey(ctx, key); err != nil {
				return err
			}
			continue
		}
		q.completed[receipt.ID] = receipt.CompletedAt
	}
	q.lastReceiptPrune = time.Now().UTC()

	// A remaining journal means EnqueueBatch never committed. Remove every
	// member before exposing the queue, giving callers all-or-none acceptance.
	journals, err := q.backend.Scan(ctx, model.NSQueue, batchKeyPrefix)
	if err != nil {
		return fmt.Errorf("scan queue journals: %w", err)
	}
	for _, key := range journals {
		data, err := q.backend.Get(ctx, model.NSQueue, key)
		if err != nil {
			return fmt.Errorf("load queue journal %q: %w", key, err)
		}
		var journal batchJournal
		if err := json.Unmarshal(data, &journal); err != nil {
			return fmt.Errorf("decode queue journal %q: %w", key, err)
		}
		if journal.AcceptanceKey != "" {
			if _, committed := q.accepted[journal.AcceptanceKey]; committed {
				if err := q.deleteKey(ctx, key); err != nil {
					return fmt.Errorf("remove committed queue journal %q: %w", key, err)
				}
				continue
			}
		}
		for _, id := range journal.MessageIDs {
			if err := q.deleteKey(ctx, messageKeyPrefix+id); err != nil {
				return fmt.Errorf("roll back queue batch %q: %w", key, err)
			}
		}
		if err := q.deleteKey(ctx, key); err != nil {
			return fmt.Errorf("remove queue journal %q: %w", key, err)
		}
	}

	keys, err := q.backend.Scan(ctx, model.NSQueue, messageKeyPrefix)
	if err != nil {
		return fmt.Errorf("scan queue messages: %w", err)
	}
	for _, key := range keys {
		data, err := q.backend.Get(ctx, model.NSQueue, key)
		if err != nil {
			return fmt.Errorf("load queue message %q: %w", key, err)
		}
		var persisted diskMessage
		if err := json.Unmarshal(data, &persisted); err != nil {
			return fmt.Errorf("decode queue message %q: %w", key, err)
		}
		msg := fromDiskMessage(persisted)
		if msg.ExpiresAt.IsZero() {
			msg.ExpiresAt = msg.CreatedAt.Add(q.cfg.MaxAge)
		}
		if msg.CorrelationID == "" {
			msg.CorrelationID = msg.ID
		}
		switch msg.Status {
		case StatusDelivered:
			if msg.CompletedAt.IsZero() {
				msg.CompletedAt = time.Now().UTC()
			}
			if err := q.saveReceipt(ctx, CompletionReceipt{ID: msg.ID, CompletedAt: msg.CompletedAt}); err != nil {
				return err
			}
			q.completed[msg.ID] = msg.CompletedAt
			if err := q.deleteKey(ctx, key); err != nil {
				return err
			}
			continue
		case StatusProcessing:
			if msg.PendingHoldReason != "" {
				// The attempt cannot have completed delivery without its
				// completion being persisted, so the requested hold applies.
				pauseMessage(msg, msg.PendingHoldReason, msg.PendingHoldAt)
			} else {
				msg.Status = StatusPending
				msg.AttemptID = ""
				msg.ClaimedAt = time.Time{}
				msg.NextRetry = time.Now().UTC()
			}
			if err := q.save(ctx, msg); err != nil {
				return fmt.Errorf("recover queue message %q: %w", msg.ID, err)
			}
		}
		q.msgs = append(q.msgs, msg)
	}
	if len(q.msgs) > q.cfg.MaxSize {
		return fmt.Errorf("persisted queue contains %d messages, above maximum %d", len(q.msgs), q.cfg.MaxSize)
	}
	logger.Info("queue: restored durable system queue", "messages", len(q.msgs))
	return nil
}

func (q *Queue) Enqueue(msg *Message) error { return q.EnqueueBatch([]*Message{msg}) }

// EnqueueBatch durably accepts all messages or none. The batch journal lets
// startup roll back a process interruption between individual store writes.
func (q *Queue) EnqueueBatch(messages []*Message) error {
	return q.enqueueBatch("", messages)
}

// EnqueueBatchIdempotent atomically admits a stable batch once. Repeating the
// same key and ordered IDs succeeds without creating another delivery batch;
// reusing the key with different IDs fails closed.
func (q *Queue) EnqueueBatchIdempotent(key string, messages []*Message) error {
	if key == "" || len(key) > 256 {
		return errors.New("queue idempotency key must contain 1-256 characters")
	}
	return q.enqueueBatch(key, messages)
}

func (q *Queue) enqueueBatch(idempotencyKey string, messages []*Message) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(messages) == 0 {
		return nil
	}
	if idempotencyKey != "" {
		ids := explicitMessageIDs(messages)
		if len(ids) != len(messages) {
			return errors.New("idempotent queue batches require explicit message IDs")
		}
		if receipt, found := q.accepted[idempotencyKey]; found {
			if equalStrings(receipt.MessageIDs, ids) {
				return nil
			}
			return ErrIdempotencyConflict
		}
	}
	preflightIDs := make(map[string]struct{}, len(messages))
	for _, msg := range messages {
		if msg == nil {
			return fmt.Errorf("nil queue message")
		}
		if msg.ID != "" {
			_, repeated := preflightIDs[msg.ID]
			if repeated || q.findLocked(msg.ID) >= 0 || !q.completed[msg.ID].IsZero() {
				return fmt.Errorf("%w ID %q", ErrDuplicate, msg.ID)
			}
			preflightIDs[msg.ID] = struct{}{}
		}
	}
	if len(q.msgs)+len(messages) > q.cfg.MaxSize {
		return fmt.Errorf("%w (max %d)", ErrFull, q.cfg.MaxSize)
	}
	now := time.Now().UTC()
	ids := make([]string, 0, len(messages))
	seen := make(map[string]struct{}, len(messages))
	for _, msg := range messages {
		if msg == nil {
			return fmt.Errorf("nil queue message")
		}
		if msg.ID == "" {
			q.nextID++
			msg.ID = fmt.Sprintf("msg-%d-%d", now.UnixNano(), q.nextID)
		}
		if _, duplicate := seen[msg.ID]; duplicate || q.findLocked(msg.ID) >= 0 || !q.completed[msg.ID].IsZero() {
			return fmt.Errorf("%w ID %q", ErrDuplicate, msg.ID)
		}
		seen[msg.ID] = struct{}{}
		ids = append(ids, msg.ID)
		q.defaults(msg, now)
	}
	prepared := make([]*Message, len(messages))
	for index, message := range messages {
		prepared[index] = cloneMessage(message)
		if q.cfg.Admission != nil {
			if err := q.cfg.Admission(context.Background(), prepared[index]); err != nil {
				return fmt.Errorf("queue admission for %q: %w", prepared[index].ID, err)
			}
		}
		if err := q.sign(context.Background(), prepared[index]); err != nil {
			return fmt.Errorf("queue admission for %q: %w", prepared[index].ID, err)
		}
	}
	var acceptance AcceptanceReceipt
	if idempotencyKey != "" {
		acceptance = AcceptanceReceipt{Key: idempotencyKey, MessageIDs: append([]string(nil), ids...), AcceptedAt: now}
	}
	var undo func()
	if q.cfg.Screen != nil {
		var err error
		if undo, err = q.cfg.Screen(context.Background(), prepared); err != nil {
			return fmt.Errorf("queue admission: %w", err)
		}
	}
	prepared, committed, err := q.addCopiesLocked(prepared, ids, seen, now)
	if err == nil {
		err = q.commitBatchLocked(prepared, committed, acceptance, now)
	}
	if err != nil && undo != nil {
		undo()
	}
	return err
}

// defaults fills the scheduling fields a producer left unset.
func (q *Queue) defaults(msg *Message, now time.Time) {
	if msg.Status == "" {
		msg.Status = StatusPending
	}
	if msg.Direction == "" {
		msg.Direction = DirectionOutbound
	}
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = now
	}
	if msg.ExpiresAt.IsZero() {
		msg.ExpiresAt = msg.CreatedAt.Add(q.cfg.MaxAge)
	}
	if msg.CorrelationID == "" {
		msg.CorrelationID = msg.ID
	}
	if msg.NextRetry.IsZero() {
		msg.NextRetry = now
	}
}

// addCopiesLocked appends the configured administrative copies of a
// screened batch to it, with their IDs.
func (q *Queue) addCopiesLocked(prepared []*Message, ids []string, seen map[string]struct{}, now time.Time) ([]*Message, []string, error) {
	if q.cfg.Copies == nil {
		return prepared, ids, nil
	}
	copies, err := q.cfg.Copies(context.Background(), prepared)
	if err != nil {
		return nil, nil, fmt.Errorf("queue admission copies: %w", err)
	}
	if len(q.msgs)+len(prepared)+len(copies) > q.cfg.MaxSize {
		return nil, nil, fmt.Errorf("%w (max %d)", ErrFull, q.cfg.MaxSize)
	}
	prepared, ids = slices.Clone(prepared), slices.Clone(ids)
	for _, msg := range copies {
		if msg == nil || msg.ID == "" {
			return nil, nil, errors.New("administrative copies need explicit IDs")
		}
		if _, duplicate := seen[msg.ID]; duplicate || q.findLocked(msg.ID) >= 0 || !q.completed[msg.ID].IsZero() {
			return nil, nil, fmt.Errorf("%w copy ID %q", ErrDuplicate, msg.ID)
		}
		seen[msg.ID] = struct{}{}
		q.defaults(msg, now)
		prepared, ids = append(prepared, msg), append(ids, msg.ID)
	}
	return prepared, ids, nil
}

// commitBatchLocked durably persists admitted messages and their optional
// acceptance receipt, then publishes them to the scheduler.
func (q *Queue) commitBatchLocked(prepared []*Message, ids []string, acceptance AcceptanceReceipt, now time.Time) error {
	if q.backend != nil {
		if _, atomic := q.backend.(store.Batcher); atomic {
			if err := store.Batch(context.Background(), q.backend, func(batchCtx context.Context) error {
				for _, msg := range prepared {
					if err := q.save(batchCtx, msg); err != nil {
						return err
					}
				}
				if acceptance.Key != "" {
					if err := q.saveAcceptance(batchCtx, acceptance); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("commit queue acceptance: %w", err)
			}
			q.acceptLocked(prepared, acceptance)
			return nil
		}
		journalKey := fmt.Sprintf("%s%d", batchKeyPrefix, now.UnixNano())
		journalData, err := json.Marshal(batchJournal{MessageIDs: ids, AcceptanceKey: acceptance.Key})
		if err != nil {
			return fmt.Errorf("encode queue journal: %w", err)
		}
		if err := q.backend.Put(context.Background(), model.NSQueue, journalKey, journalData); err != nil {
			return fmt.Errorf("create queue journal: %w", err)
		}
		for _, msg := range prepared {
			if err := q.save(context.Background(), msg); err != nil {
				q.rollbackBatchLocked(journalKey, ids, acceptance)
				return err
			}
		}
		if acceptance.Key != "" {
			if err := q.saveAcceptance(context.Background(), acceptance); err != nil {
				q.rollbackBatchLocked(journalKey, ids, acceptance)
				return err
			}
		}
		if err := q.backend.Delete(context.Background(), model.NSQueue, journalKey); err != nil {
			if acceptance.Key != "" {
				// The acceptance receipt is the commit marker. Startup removes
				// this leftover journal without rolling back its messages.
				logger.Warn("queue: committed batch journal cleanup deferred", "error", err)
			} else {
				q.rollbackBatchLocked(journalKey, ids, acceptance)
				return fmt.Errorf("commit queue batch: %w", err)
			}
		}
	}
	q.acceptLocked(prepared, acceptance)
	return nil
}

func (q *Queue) acceptLocked(messages []*Message, acceptance AcceptanceReceipt) {
	accepted := make([]*Message, 0, len(messages))
	for _, msg := range messages {
		accepted = append(accepted, cloneMessage(msg))
	}
	q.msgs = append(q.msgs, accepted...)
	if acceptance.Key != "" {
		acceptance.MessageIDs = append([]string(nil), acceptance.MessageIDs...)
		q.accepted[acceptance.Key] = acceptance
	}
	for _, msg := range accepted {
		logger.Debug("queue: message accepted", "id", msg.ID, "direction", msg.Direction, "recipient", msg.Recipient, "durable", q.backend != nil)
	}
	q.wakeWorkers()
	for _, msg := range accepted {
		q.observe(Event{Message: *msg, Stage: "accepted", Status: msg.Status})
	}
}

func (q *Queue) rollbackBatchLocked(journalKey string, ids []string, acceptance AcceptanceReceipt) {
	for _, id := range ids {
		_ = q.deleteKey(context.Background(), messageKeyPrefix+id)
	}
	if acceptance.Key != "" {
		_ = q.deleteKey(context.Background(), acceptanceStoreKey(acceptance.Key))
	}
	_ = q.deleteKey(context.Background(), journalKey)
}

func explicitMessageIDs(messages []*Message) []string {
	ids := make([]string, 0, len(messages))
	for _, message := range messages {
		if message == nil || message.ID == "" {
			return ids
		}
		ids = append(ids, message.ID)
	}
	return ids
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func acceptanceStoreKey(key string) string {
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s%x", acceptanceKeyPrefix, digest)
}

// Dequeue removes and returns a ready item. It is primarily retained for
// explicit/manual consumers; the background worker uses a durable claim.
func (q *Queue) Dequeue() *Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, msg := range q.msgs {
		if ready(msg, time.Now().UTC()) {
			if q.backend != nil && q.deleteKey(context.Background(), messageKeyPrefix+msg.ID) != nil {
				return nil
			}
			q.msgs = append(q.msgs[:i], q.msgs[i+1:]...)
			return msg
		}
	}
	return nil
}

func ready(msg *Message, now time.Time) bool {
	return (msg.Status == StatusPending || msg.Status == StatusRetrying || msg.Status == StatusHeld) && !msg.NextRetry.After(now)
}

func (q *Queue) Size() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.msgs) }

// Stats returns a consistent metadata-only operational snapshot.
func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := Stats{Size: len(q.msgs), ByStatus: make(map[Status]int), ByDirection: make(map[Direction]int), CompletionReceipts: len(q.completed), LastReceiptPruneAt: q.lastReceiptPrune, LastReceiptPruneRemoved: q.lastReceiptPruneRemoved, LastReceiptPruneError: q.lastReceiptPruneError}
	now := time.Now().UTC()
	firstReceipt := true
	for _, completedAt := range q.completed {
		age := now.Sub(completedAt).Seconds()
		if age > stats.OldestReceiptAgeSeconds {
			stats.OldestReceiptAgeSeconds = age
		}
		if firstReceipt || age < stats.NewestReceiptAgeSeconds {
			stats.NewestReceiptAgeSeconds = age
		}
		firstReceipt = false
	}
	for _, msg := range q.msgs {
		stats.ByStatus[msg.Status]++
		stats.ByDirection[msg.Direction]++
		stats.AttemptsRetained += len(msg.Attempts)
		stats.AttemptsDropped += msg.AttemptsDropped
		age := now.Sub(msg.CreatedAt).Seconds()
		if age > stats.OldestAgeSeconds {
			stats.OldestAgeSeconds = age
		}
	}
	return stats
}

func (q *Queue) List(status Status) []*Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	result := make([]*Message, 0, len(q.msgs))
	for _, msg := range q.msgs {
		if status == "" || msg.Status == status {
			result = append(result, cloneMessage(msg))
		}
	}
	return result
}

func (q *Queue) Get(id string) *Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 {
		return nil
	}
	return cloneMessage(q.msgs[i])
}

// RawMessage returns the message bytes to deliver: Content when set,
// otherwise the message rebuilt from Headers and Body.
func (m *Message) RawMessage() []byte {
	if len(m.Content) > 0 {
		return m.Content
	}
	return BuildMessage(m.Headers, m.Body)
}

// cloneMessage returns a fully detached snapshot. Queue callers must never be
// able to mutate authoritative state without taking the queue lock and
// persisting the transition.
func cloneMessage(msg *Message) *Message {
	if msg == nil {
		return nil
	}
	cp := *msg
	if msg.Headers != nil {
		cp.Headers = make(map[string]string, len(msg.Headers))
		for key, value := range msg.Headers {
			cp.Headers[key] = value
		}
	}
	if msg.Attributes != nil {
		cp.Attributes = make(map[string]string, len(msg.Attributes))
		for key, value := range msg.Attributes {
			cp.Attributes[key] = value
		}
	}
	cp.Body = append([]byte(nil), msg.Body...)
	cp.Content = append([]byte(nil), msg.Content...)
	cp.Attempts = append([]AttemptRecord(nil), msg.Attempts...)
	cp.RouteChanges = append([]RouteChange(nil), msg.RouteChanges...)
	cp.Policy = msg.Policy.Clone()
	return &cp
}

// Reroute changes the operator-selected route without overwriting policy or
// attempt evidence. Failed/retrying work is made eligible immediately; an
// explicit administrative pause remains in force until separately released.
func (q *Queue) Reroute(id, route, actor, reason string) (RouteChange, error) {
	route = strings.ToLower(strings.TrimSpace(route))
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if len(route) > 255 || len(actor) > 255 || len(reason) > 512 || actor == "" || reason == "" {
		return RouteChange{}, errors.New("route, actor, or reason is invalid")
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 {
		return RouteChange{}, ErrRerouteNotFound
	}
	msg := q.msgs[i]
	if msg.Direction != DirectionOutbound {
		return RouteChange{}, ErrRerouteDirection
	}
	if msg.Status == StatusProcessing || msg.Status == StatusHeld || msg.Status == StatusDelivered || msg.Status == StatusCancelled {
		return RouteChange{}, ErrRerouteState
	}
	if msg.AdministrativeRoute == route {
		return RouteChange{}, ErrRerouteUnchanged
	}

	old := cloneMessage(msg)
	change := RouteChange{Previous: msg.AdministrativeRoute, Current: route, Actor: actor, Reason: reason, At: time.Now().UTC()}
	msg.AdministrativeRoute = route
	msg.RouteChanges = append(msg.RouteChanges, change)
	if len(msg.RouteChanges) > MaxRouteChanges {
		dropped := len(msg.RouteChanges) - MaxRouteChanges
		msg.RouteChanges = append([]RouteChange(nil), msg.RouteChanges[dropped:]...)
		msg.RouteChangesDropped += int64(dropped)
	}
	if msg.Status != StatusPaused {
		msg.Status, msg.RetryCount, msg.NextRetry = StatusPending, 0, change.At
		msg.LastError, msg.LastCode, msg.LastResponse = "", "", ""
		msg.CompletedAt, msg.AttemptID, msg.ClaimedAt = time.Time{}, "", time.Time{}
	}
	if err := q.save(context.Background(), msg); err != nil {
		*msg = *old
		return RouteChange{}, err
	}
	eventRoute := route
	if eventRoute == "" {
		eventRoute = "automatic"
	}
	q.observe(Event{Message: *msg, Stage: "operator_reroute", Status: msg.Status, Attempt: msg.RetryCount, Route: eventRoute, Response: reason})
	if msg.Status == StatusPending {
		q.wakeWorkers()
	}
	return change, nil
}

// Retry makes a message eligible for an attempt now. A failed message
// starts over with a fresh attempt count; a message waiting for its next
// scheduled attempt keeps its attempt history and backoff and is only moved
// forward. Routes are resolved per attempt, so the attempt uses the current
// routing configuration.
func (q *Queue) Retry(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 {
		return false
	}
	msg := q.msgs[i]
	old := *msg
	switch msg.Status {
	case StatusFailed:
		msg.Status, msg.RetryCount, msg.LastError, msg.NextRetry = StatusPending, 0, "", time.Now().UTC()
		msg.LastCode, msg.LastResponse, msg.AttemptID = "", "", ""
		msg.CompletedAt, msg.ClaimedAt = time.Time{}, time.Time{}
	case StatusPending, StatusRetrying:
		msg.NextRetry = time.Now().UTC()
	default:
		return false
	}
	if err := q.save(context.Background(), msg); err != nil {
		*msg = old
		return false
	}
	q.wakeWorkers()
	return true
}

// Hold pauses a delivery indefinitely without altering its attempt history.
// Release resumes it immediately.
func (q *Queue) Hold(id string) bool {
	return q.HoldWithReason(id, "Held by administrator")
}

// HoldWithReason pauses a queued delivery. An attempt already in progress
// cannot be recalled, so for a processing message the hold is recorded as
// pending and takes effect when the attempt ends, unless it delivered the
// message or failed it permanently. It reports whether a hold was placed
// or recorded.
func (q *Queue) HoldWithReason(id, reason string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 || q.msgs[i].Status == StatusDelivered || q.msgs[i].Status == StatusCancelled || q.msgs[i].Status == StatusPaused || q.msgs[i].Status == StatusHeld {
		return false
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "Held by administrator"
	}
	msg, old := q.msgs[i], *q.msgs[i]
	stage := "operator_hold"
	if msg.Status == StatusProcessing {
		if msg.PendingHoldReason != "" {
			return false
		}
		msg.PendingHoldReason, msg.PendingHoldAt = reason, time.Now().UTC()
		stage = "operator_hold_pending"
	} else {
		pauseMessage(msg, reason, time.Now().UTC())
	}
	if err := q.save(context.Background(), msg); err != nil {
		*msg = old
		return false
	}
	q.observe(Event{Message: *msg, Stage: stage, Status: msg.Status, Attempt: msg.RetryCount, Response: reason})
	return true
}

// pauseMessage moves msg to the paused state with the given hold reason.
func pauseMessage(msg *Message, reason string, at time.Time) {
	msg.Status = StatusPaused
	msg.HoldReason, msg.HeldAt = reason, at
	msg.PendingHoldReason, msg.PendingHoldAt = "", time.Time{}
	msg.ReleasedAt = time.Time{}
	msg.NextRetry = time.Time{}
	msg.AttemptID, msg.ClaimedAt = "", time.Time{}
}

// Release resumes a paused delivery, or withdraws the pending hold of one
// whose attempt is still in progress.
func (q *Queue) Release(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 {
		return false
	}
	msg, old := q.msgs[i], *q.msgs[i]
	switch {
	case msg.Status == StatusPaused:
		msg.Status = StatusPending
		msg.NextRetry = time.Now().UTC()
		msg.ReleasedAt = msg.NextRetry
	case msg.Status == StatusProcessing && msg.PendingHoldReason != "":
		msg.PendingHoldReason, msg.PendingHoldAt = "", time.Time{}
	default:
		return false
	}
	if err := q.save(context.Background(), msg); err != nil {
		*msg = old
		return false
	}
	q.observe(Event{Message: *msg, Stage: "operator_release", Status: msg.Status, Attempt: msg.RetryCount, Response: msg.HoldReason})
	q.wakeWorkers()
	return true
}

// WakeOwner immediately reschedules maintenance-held deliveries for one
// account without resetting ordinary retry history.
func (q *Queue) WakeOwner(ownerID string) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now().UTC()
	woken := 0
	for _, msg := range q.msgs {
		if msg.Status != StatusHeld || !strings.EqualFold(msg.TargetOwnerID, ownerID) {
			continue
		}
		old := *msg
		msg.Status = StatusPending
		msg.NextRetry = now
		if err := q.save(context.Background(), msg); err != nil {
			*msg = old
			return woken, err
		}
		woken++
	}
	if woken > 0 {
		q.wakeWorkers()
	}
	return woken, nil
}

// Cancel durably prevents a queued delivery from being attempted. An active
// SMTP transaction cannot be recalled safely, so processing items are rejected.
func (q *Queue) Cancel(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 || q.msgs[i].Status == StatusProcessing || q.msgs[i].Status == StatusCancelled {
		return false
	}
	msg := q.msgs[i]
	old := *msg
	msg.Status = StatusCancelled
	msg.CompletedAt = time.Now().UTC()
	msg.NextRetry = time.Time{}
	msg.AttemptID, msg.ClaimedAt = "", time.Time{}
	if err := q.save(context.Background(), msg); err != nil {
		*msg = old
		return false
	}
	q.observe(Event{Message: *msg, Stage: "cancelled", Status: StatusCancelled})
	return true
}

func (q *Queue) Remove(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := q.findLocked(id)
	if i < 0 {
		return false
	}
	if q.backend != nil && q.deleteKey(context.Background(), messageKeyPrefix+id) != nil {
		return false
	}
	q.msgs = append(q.msgs[:i], q.msgs[i+1:]...)
	return true
}

func (q *Queue) findLocked(id string) int {
	for i, msg := range q.msgs {
		if msg.ID == id {
			return i
		}
	}
	return -1
}

// Close cancels in-flight deliveries and waits for every worker to exit.
func (q *Queue) Close() {
	q.close.Do(func() {
		q.workersMu.Lock()
		q.closed = true
		q.workersMu.Unlock()
		q.cancel()
		close(q.stopCh)
		q.workerGroup.Wait()
	})
}

// runWorker processes messages until the queue closes or retire is closed.
// Retirement is observed only between deliveries.
func (q *Queue) runWorker(retire <-chan struct{}) {
	q.runningWorker.Add(1)
	defer q.runningWorker.Add(-1)
	ticker := time.NewTicker(q.cfg.ProcessPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-retire:
			return
		default:
		}
		select {
		case <-q.stopCh:
			return
		case <-retire:
			return
		case <-q.wakeCh:
			q.processOne()
		case <-ticker.C:
			q.processOne()
		}
	}
}

func (q *Queue) processOne() {
	if q.finalizeDelivered() {
		return
	}
	msg := q.claimReady()
	if msg == nil {
		return
	}
	q.attemptDelivery(msg)
	q.wakeWorkers()
}

func (q *Queue) finalizeDelivered() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for index, msg := range q.msgs {
		if msg.Status != StatusDelivered {
			continue
		}
		if !q.finalizeDeliveredLocked(index, msg) {
			q.wakeWorkers()
		}
		return true
	}
	return false
}

func (q *Queue) finalizeDeliveredLocked(index int, msg *Message) bool {
	receipt := CompletionReceipt{ID: msg.ID, CompletedAt: msg.CompletedAt}
	var notification *Message
	if msg.FailureMessageID == "" && msg.EnvelopeSender != "" && requestsSuccessNotification(msg) && q.cfg.FailureMessage != nil {
		completed := cloneMessage(msg)
		completed.LastCode, completed.LastResponse = "2.0.0", "delivered"
		if completed.Attributes == nil {
			completed.Attributes = make(map[string]string)
		}
		completed.Attributes["dsn_notification"] = "success"
		notification = q.cfg.FailureMessage(completed)
		if notification != nil {
			q.prepareFailureMessage(msg, notification)
		}
	}
	if err := q.persistDeliveredCompletion(msg, receipt, notification); err != nil {
		logger.Error("queue: delivered but could not persist completion", "id", msg.ID, "error", err)
		return false
	}
	if notification != nil {
		msg.FailureMessageID = notification.ID
		q.msgs = append(q.msgs, notification)
		q.observe(Event{Message: *notification, Stage: "accepted", Status: notification.Status})
		q.wakeWorkers()
	}
	q.completed[msg.ID] = msg.CompletedAt
	q.pruneExpiredReceiptsLocked(context.Background(), time.Now().UTC())
	q.msgs = append(q.msgs[:index], q.msgs[index+1:]...)
	q.observe(Event{Message: *msg, Stage: "completed", Status: StatusDelivered, Attempt: msg.RetryCount})
	logger.Info("queue: message delivered", "id", msg.ID, "recipient", msg.Recipient)
	return true
}

func (q *Queue) wakeWorkers() {
	for range q.workerCount.Load() {
		select {
		case q.wakeCh <- struct{}{}:
		default:
			return
		}
	}
}

func (q *Queue) claimReady() *Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, msg := range q.msgs {
		if !ready(msg, time.Now().UTC()) {
			continue
		}
		if q.cfg.DeliveryHold != nil {
			if reason := q.cfg.DeliveryHold(msg); reason != "" {
				q.pauseClaimLocked(msg, reason)
				continue
			}
		}
		destination := deliveryDestination(msg)
		if q.inFlight[destination] >= q.cfg.MaxPerDestination {
			continue
		}
		old := msg.Status
		msg.Status = StatusProcessing
		msg.DeliveryRoute = ""
		q.nextAttempt++
		msg.AttemptID = fmt.Sprintf("attempt-%d-%d", time.Now().UTC().UnixNano(), q.nextAttempt)
		msg.ClaimedAt = time.Now().UTC()
		if err := q.save(context.Background(), msg); err != nil {
			msg.Status = old
			logger.Error("queue: failed to persist delivery claim", "id", msg.ID, "error", err)
			return nil
		}
		q.inFlight[destination]++
		cp := cloneMessage(msg)
		q.observe(Event{Message: *cp, Stage: "attempt", Status: StatusProcessing, Attempt: cp.RetryCount + 1})
		return cp
	}
	return nil
}

// pauseClaimLocked pauses a ready message that DeliveryHold refused to
// release for delivery.
func (q *Queue) pauseClaimLocked(msg *Message, reason string) {
	old := *msg
	pauseMessage(msg, reason, time.Now().UTC())
	if err := q.save(context.Background(), msg); err != nil {
		*msg = old
		logger.Error("queue: failed to persist delivery hold", "id", msg.ID, "error", err)
		return
	}
	q.observe(Event{Message: *msg, Stage: "delivery_hold", Status: msg.Status, Attempt: msg.RetryCount, Response: reason})
}

func (q *Queue) attemptDelivery(claimed *Message) {
	startedAt := time.Now().UTC()
	evidence := &deliveryEvidence{}
	claimed.RetryCount++
	var err error
	if !claimed.ExpiresAt.IsZero() && !time.Now().UTC().Before(claimed.ExpiresAt) {
		err = &DeliveryError{Class: DeliveryPermanent, EnhancedCode: "5.4.7", Response: "delivery time expired"}
	} else if q.delivery == nil {
		err = errors.New("5.3.0 queue delivery is not configured")
	} else {
		err = q.delivery(context.WithValue(q.ctx, deliveryEvidenceKey{}, evidence), claimed)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	q.releaseDestinationLocked(claimed)
	i := q.findLocked(claimed.ID)
	if i < 0 {
		return
	}
	msg := q.msgs[i]
	msg.RetryCount = claimed.RetryCount
	msg.ClaimedAt = time.Time{}
	msg.DeliveryRoute = evidence.route
	if err == nil {
		appendAttempt(msg, AttemptRecord{ID: claimed.AttemptID, StartedAt: startedAt, EndedAt: time.Now().UTC(), Class: DeliverySuccess, TLSPolicy: evidence.tlsPolicy})
		msg.Status, msg.LastError = StatusDelivered, ""
		msg.CompletedAt = time.Now().UTC()
		msg.PendingHoldReason, msg.PendingHoldAt = "", time.Time{}
		if persistErr := q.save(context.Background(), msg); persistErr != nil {
			logger.Error("queue: delivered but could not persist completion", "id", msg.ID, "error", persistErr)
			return
		}
		q.finalizeDeliveredLocked(i, msg)
		return
	}
	outcome := classifyDeliveryError(err)
	outcome.EnhancedCode = boundedOperationalText(outcome.EnhancedCode, 64)
	outcome.Response = boundedOperationalText(outcome.Response, 2048)
	msg.LastError = boundedOperationalText(err.Error(), 2048)
	appendAttempt(msg, AttemptRecord{ID: claimed.AttemptID, StartedAt: startedAt, EndedAt: time.Now().UTC(), Class: outcome.Class, Code: outcome.EnhancedCode, Response: outcome.Response, TLSPolicy: evidence.tlsPolicy})
	if outcome.Class == DeliveryUncertain {
		msg.PossibleDuplicate = true
	}
	msg.LastCode, msg.LastResponse = outcome.EnhancedCode, outcome.Response
	if msg.PendingHoldReason != "" && outcome.Class != DeliveryPermanent {
		// A hold requested during the attempt takes effect now instead of
		// a retry, so held mail cannot escape on a later attempt.
		if outcome.Class == DeliveryDeferred {
			msg.RetryCount--
		}
		pauseMessage(msg, msg.PendingHoldReason, msg.PendingHoldAt)
		if persistErr := q.persistTerminalFailure(msg, nil); persistErr != nil {
			logger.Error("queue: failed to persist delivery hold", "id", msg.ID, "error", persistErr)
			return
		}
		q.observe(Event{Message: *msg, Stage: "delivery", Status: msg.Status, Attempt: msg.RetryCount, Code: msg.LastCode, Response: msg.LastResponse, PossibleDuplicate: msg.PossibleDuplicate})
		return
	}
	msg.PendingHoldReason, msg.PendingHoldAt = "", time.Time{}
	if outcome.Class == DeliveryDeferred {
		msg.RetryCount--
		msg.Status = StatusHeld
		delay := outcome.RetryAfter
		if delay <= 0 {
			delay = q.cfg.RetryInitial
		}
		msg.NextRetry = time.Now().UTC().Add(delay)
		if persistErr := q.persistTerminalFailure(msg, nil); persistErr != nil {
			logger.Error("queue: failed to persist delivery hold", "id", msg.ID, "error", persistErr)
			return
		}
		logDeliveryFailure(msg)
		q.observe(Event{Message: *msg, Stage: "held", Status: msg.Status, Attempt: msg.RetryCount, Code: msg.LastCode, Response: msg.LastResponse})
		return
	}
	if outcome.Class == DeliveryPermanent {
		msg.Status = StatusFailed
		msg.CompletedAt = time.Now().UTC()
	} else {
		msg.Status = StatusRetrying
		delay := outcome.RetryAfter
		if delay <= 0 {
			delay = q.cfg.RetryInitial * time.Duration(1<<min(msg.RetryCount-1, 20))
		}
		if delay > q.cfg.RetryMax {
			delay = q.cfg.RetryMax
		}
		// Temporary failures retry until the message expires; the final attempt
		// lands on the expiry so the sender learns of failure on time.
		now := time.Now().UTC()
		if !msg.ExpiresAt.IsZero() && now.Add(delay).After(msg.ExpiresAt) {
			delay = max(msg.ExpiresAt.Sub(now), 0)
		}
		msg.NextRetry = now.Add(delay)
	}
	var failureMessage *Message
	if msg.Status == StatusFailed && msg.FailureMessageID == "" && msg.EnvelopeSender != "" && requestsFailureNotification(msg) && q.cfg.FailureMessage != nil {
		failureMessage = q.cfg.FailureMessage(cloneMessage(msg))
		if failureMessage != nil {
			q.prepareFailureMessage(msg, failureMessage)
			msg.FailureMessageID = failureMessage.ID
		}
	}
	if persistErr := q.persistTerminalFailure(msg, failureMessage); persistErr != nil {
		logger.Error("queue: failed to persist delivery failure", "id", msg.ID, "error", persistErr)
		return
	}
	logDeliveryFailure(msg)
	if failureMessage != nil {
		q.msgs = append(q.msgs, failureMessage)
		q.observe(Event{Message: *failureMessage, Stage: "accepted", Status: failureMessage.Status})
		q.wakeWorkers()
	}
	q.observe(Event{Message: *msg, Stage: "delivery", Status: msg.Status, Attempt: msg.RetryCount, Code: msg.LastCode, Response: msg.LastResponse, PossibleDuplicate: msg.PossibleDuplicate})
}

func requestsFailureNotification(message *Message) bool {
	notify := strings.ToLower(strings.TrimSpace(message.Attributes["dsn_notify"]))
	if notify == "" {
		return true
	}
	for _, value := range strings.Split(notify, ",") {
		if strings.TrimSpace(value) == "failure" {
			return true
		}
	}
	return false
}

func requestsSuccessNotification(message *Message) bool {
	for _, value := range strings.Split(strings.ToLower(message.Attributes["dsn_notify"]), ",") {
		if strings.TrimSpace(value) == "success" {
			return true
		}
	}
	return false
}

func (q *Queue) persistDeliveredCompletion(delivered *Message, receipt CompletionReceipt, notification *Message) error {
	if q.backend == nil {
		return nil
	}
	receiptData, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode queue completion receipt: %w", err)
	}
	return store.Batch(context.Background(), q.backend, func(ctx context.Context) error {
		if err := q.backend.Set(ctx, model.NSQueue, receiptKeyPrefix+receipt.ID, receiptData); err != nil {
			return fmt.Errorf("persist queue completion receipt %q: %w", receipt.ID, err)
		}
		if notification != nil {
			if err := q.save(ctx, notification); err != nil {
				return err
			}
		}
		return q.deleteKey(ctx, messageKeyPrefix+delivered.ID)
	})
}

func appendAttempt(msg *Message, attempt AttemptRecord) {
	msg.Attempts = append(msg.Attempts, attempt)
	if len(msg.Attempts) <= MaxAttemptRecords {
		return
	}
	dropped := len(msg.Attempts) - MaxAttemptRecords
	// Retain the original attempt as the beginning of the evidence chain and
	// the newest bounded tail for current operational diagnosis.
	compacted := make([]AttemptRecord, 1, MaxAttemptRecords)
	compacted[0] = msg.Attempts[0]
	compacted = append(compacted, msg.Attempts[len(msg.Attempts)-(MaxAttemptRecords-1):]...)
	msg.Attempts = compacted
	msg.AttemptsDropped += int64(dropped)
}

func boundedOperationalText(value string, limit int) string {
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

func deliveryDestination(msg *Message) string {
	if msg.TargetOwnerID != "" {
		return "local:" + strings.ToLower(msg.TargetOwnerID)
	}
	recipient := strings.ToLower(strings.TrimSpace(msg.Recipient))
	if at := strings.LastIndexByte(recipient, '@'); at >= 0 && at+1 < len(recipient) {
		return "domain:" + recipient[at+1:]
	}
	return "recipient:" + recipient
}

func (q *Queue) releaseDestinationLocked(msg *Message) {
	destination := deliveryDestination(msg)
	if q.inFlight[destination] <= 1 {
		delete(q.inFlight, destination)
		return
	}
	q.inFlight[destination]--
}

func (q *Queue) prepareFailureMessage(failed, notification *Message) {
	now := time.Now().UTC()
	if notification.ID == "" {
		notification.ID = "dsn-" + failed.ID
	}
	notification.ParentID = failed.ID
	notification.CorrelationID = failed.CorrelationID
	notification.Direction = DirectionOutbound
	notification.Status = StatusPending
	notification.RetryCount = 0
	notification.CreatedAt, notification.NextRetry = now, now
	notification.ExpiresAt = now.Add(q.cfg.MaxAge)
	if err := q.sign(context.Background(), notification); err != nil {
		logger.Error("queue: delivery status notification sent unsigned", "id", notification.ID, "error", err)
	}
}

// sign DKIM-signs an admitted message that carries a DKIM request. It is the
// only outbound signing point and runs after mail policy header actions, so
// the signature covers the headers that are sent. The queue ID was fixed
// before signing, so a replayed submission is still detected as a duplicate.
// Quarantined messages keep their bytes. A message held as Content gets the
// signature prepended so its trace fields keep their order. An unsignable
// message is admitted unsigned unless the request requires a signature.
func (q *Queue) sign(ctx context.Context, msg *Message) error {
	request := msg.DKIM
	msg.DKIM = nil
	if request == nil || msg.Kind == smtp.MailTaskQuarantine {
		return nil
	}
	var signed bool
	var err error
	if len(msg.Content) > 0 {
		if msg.Headers == nil {
			msg.Headers = make(map[string]string)
		}
		msg.Content, signed, err = q.cfg.Signer.SignMessage(ctx, msg.Headers, msg.Content, request.Headers...)
	} else {
		signed, err = q.cfg.Signer.SignHeaders(ctx, msg.Headers, msg.Body, request.Headers...)
	}
	if err == nil && !signed && request.Required {
		err = errors.New("the From domain has no active DKIM key")
	}
	if err != nil && request.Required {
		return fmt.Errorf("DKIM-sign: %w", err)
	}
	if err != nil {
		logger.Error("queue: DKIM signing failed; sending unsigned", "id", msg.ID, "error", err)
	}
	return nil
}

func (q *Queue) persistTerminalFailure(failed, notification *Message) error {
	if notification == nil || q.backend == nil {
		return q.save(context.Background(), failed)
	}
	return store.Batch(context.Background(), q.backend, func(ctx context.Context) error {
		if err := q.save(ctx, failed); err != nil {
			return err
		}
		return q.save(ctx, notification)
	})
}

func (q *Queue) observe(event Event) {
	if q.cfg.Observer == nil {
		return
	}
	event.Message = *cloneMessage(&event.Message)
	if event.Destination == "" {
		event.Destination = deliveryDestination(&event.Message)
	}
	if event.Route == "" {
		event.Route = event.Message.DeliveryRoute
	}
	if len(event.Message.Attempts) > 0 && (event.Stage == "completed" || event.Stage == "delivery" || event.Stage == "held") {
		attempt := event.Message.Attempts[len(event.Message.Attempts)-1]
		event.OutcomeClass = string(attempt.Class)
		event.TLSPolicy = attempt.TLSPolicy
		if duration := attempt.EndedAt.Sub(attempt.StartedAt); duration > 0 {
			event.DurationMillis = max(int64(1), duration.Milliseconds())
		}
	}
	if event.Status == StatusRetrying || event.Status == StatusHeld || event.Status == StatusPaused {
		event.RetryAt = event.Message.NextRetry
	}
	event.Time = time.Now().UTC()
	q.cfg.Observer(context.Background(), event)
}

func (q *Queue) save(ctx context.Context, msg *Message) error {
	if q.backend == nil {
		return nil
	}
	data, err := json.Marshal(toDiskMessage(msg))
	if err != nil {
		return fmt.Errorf("encode queue message: %w", err)
	}
	if err := q.backend.Set(ctx, model.NSQueue, messageKeyPrefix+msg.ID, data); err != nil {
		return fmt.Errorf("persist queue message %q: %w", msg.ID, err)
	}
	return nil
}

func (q *Queue) saveAcceptance(ctx context.Context, receipt AcceptanceReceipt) error {
	if q.backend == nil {
		return nil
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode queue acceptance receipt: %w", err)
	}
	if err := q.backend.Set(ctx, model.NSQueue, acceptanceStoreKey(receipt.Key), data); err != nil {
		return fmt.Errorf("persist queue acceptance receipt: %w", err)
	}
	return nil
}

func (q *Queue) saveReceipt(ctx context.Context, receipt CompletionReceipt) error {
	if q.backend == nil {
		return nil
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode queue completion receipt: %w", err)
	}
	if err := q.backend.Set(ctx, model.NSQueue, receiptKeyPrefix+receipt.ID, data); err != nil {
		return fmt.Errorf("persist queue completion receipt %q: %w", receipt.ID, err)
	}
	return nil
}

func (q *Queue) pruneExpiredReceiptsLocked(ctx context.Context, now time.Time) {
	if now.Sub(q.lastReceiptPrune) < time.Hour {
		return
	}
	result := q.pruneReceiptsLocked(ctx, now.Add(-q.cfg.ReceiptRetention), MaxReceiptPruneRecords, false)
	if result.Examined == MaxReceiptPruneRecords {
		q.lastReceiptPrune = time.Time{}
	}
}

// PruneReceipts removes at most limit retained completion identities older
// than before. It is bounded, deterministic, and safe alongside delivery.
func (q *Queue) PruneReceipts(ctx context.Context, before time.Time, limit int, dryRun bool) (ReceiptPruneResult, error) {
	if before.IsZero() {
		return ReceiptPruneResult{}, errors.New("receipt prune cutoff is required")
	}
	if limit < 1 || limit > MaxReceiptPruneRecords {
		return ReceiptPruneResult{}, errors.New("receipt prune limit must be between 1 and 10000")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	result := q.pruneReceiptsLocked(ctx, before.UTC(), limit, dryRun)
	for _, item := range result.Items {
		if item.Error != "" {
			return result, errors.New("one or more completion receipts could not be pruned")
		}
	}
	return result, nil
}

func (q *Queue) pruneReceiptsLocked(ctx context.Context, before time.Time, limit int, dryRun bool) ReceiptPruneResult {
	type candidate struct {
		id string
		at time.Time
	}
	candidates := make([]candidate, 0)
	for id, completedAt := range q.completed {
		if completedAt.Before(before) {
			candidates = append(candidates, candidate{id: id, at: completedAt})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].at.Before(candidates[j].at)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	result := ReceiptPruneResult{Before: before, DryRun: dryRun, Examined: len(candidates), Items: make([]ReceiptPruneItem, 0, len(candidates))}
	for _, candidate := range candidates {
		item := ReceiptPruneItem{ID: candidate.id, CompletedAt: candidate.at}
		if !dryRun {
			if err := q.deleteKey(ctx, receiptKeyPrefix+candidate.id); err != nil {
				item.Error = err.Error()
			} else {
				delete(q.completed, candidate.id)
				item.Removed = true
				result.Removed++
			}
		}
		result.Items = append(result.Items, item)
	}
	q.lastReceiptPrune = time.Now().UTC()
	q.lastReceiptPruneRemoved = result.Removed
	q.lastReceiptPruneError = ""
	for _, item := range result.Items {
		if item.Error != "" {
			q.lastReceiptPruneError = "one or more completion receipts could not be pruned"
			break
		}
	}
	return result
}

// WasCompleted reports whether an ID has a retained durable success receipt.
func (q *Queue) WasCompleted(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, ok := q.completed[id]
	return ok
}

func (q *Queue) deleteKey(ctx context.Context, key string) error {
	if q.backend == nil {
		return nil
	}
	err := q.backend.Delete(ctx, model.NSQueue, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

func isTemporaryFailure(err error) bool {
	if err == nil {
		return false
	}
	return classifyDeliveryError(err).Class != DeliveryPermanent
}

func classifyDeliveryError(err error) DeliveryError {
	if err == nil {
		return DeliveryError{}
	}
	var typed *DeliveryError
	if errors.As(err, &typed) {
		return *typed
	}
	// An SMTP reply code decides (RFC 5321 4.2.1): a 4xx from any target
	// is retried even without an enhanced status code, as greylisting
	// servers often answer "450 try later"; only 5xx from every target
	// that answered is permanent.
	if temporary, permanent := smtpReplyClasses(err); temporary {
		return DeliveryError{Class: DeliveryTemporary, Response: err.Error(), Err: err}
	} else if permanent {
		return DeliveryError{Class: DeliveryPermanent, Response: err.Error(), Err: err}
	}
	msg := strings.ToLower(err.Error())
	for i := 0; i < len(msg)-1; i++ {
		if msg[i] == '4' && msg[i+1] == '.' {
			return DeliveryError{Class: DeliveryTemporary, Response: err.Error(), Err: err}
		}
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "network is unreachable") || msg == "context deadline exceeded" || msg == "context canceled" {
		return DeliveryError{Class: DeliveryUncertain, Response: err.Error(), Err: err}
	}
	return DeliveryError{Class: DeliveryPermanent, Response: err.Error(), Err: err}
}

// MarshalJSON intentionally omits payload bytes from admin/API list views.
func (m *Message) MarshalJSON() ([]byte, error) {
	type view struct {
		ID                  string            `json:"id"`
		Kind                string            `json:"kind,omitempty"`
		Attributes          map[string]string `json:"attributes,omitempty"`
		CorrelationID       string            `json:"correlation_id,omitempty"`
		ParentID            string            `json:"parent_id,omitempty"`
		Direction           Direction         `json:"direction,omitempty"`
		EnvelopeSender      string            `json:"envelope_sender"`
		Recipient           string            `json:"recipient"`
		Headers             map[string]string `json:"headers"`
		TargetFolderID      string            `json:"target_folder_id,omitempty"`
		TargetFolderPath    string            `json:"target_folder_path,omitempty"`
		DeliveryRoute       string            `json:"delivery_route,omitempty"`
		AdministrativeRoute string            `json:"administrative_route,omitempty"`
		RouteChanges        []RouteChange     `json:"route_changes,omitempty"`
		RouteChangesDropped int64             `json:"route_changes_dropped,omitempty"`
		Status              Status            `json:"status"`
		RetryCount          int               `json:"retry_count"`
		NextRetry           time.Time         `json:"next_retry"`
		LastError           string            `json:"last_error,omitempty"`
		LastCode            string            `json:"last_code,omitempty"`
		LastResponse        string            `json:"last_response,omitempty"`
		AttemptID           string            `json:"attempt_id,omitempty"`
		ClaimedAt           time.Time         `json:"claimed_at,omitzero"`
		ExpiresAt           time.Time         `json:"expires_at,omitzero"`
		CompletedAt         time.Time         `json:"completed_at,omitzero"`
		HoldReason          string            `json:"hold_reason,omitempty"`
		HeldAt              time.Time         `json:"held_at,omitzero"`
		ReleasedAt          time.Time         `json:"released_at,omitzero"`
		PendingHoldReason   string            `json:"pending_hold_reason,omitempty"`
		PendingHoldAt       time.Time         `json:"pending_hold_at,omitzero"`
		CreatedAt           time.Time         `json:"created_at"`
		PossibleDuplicate   bool              `json:"possible_duplicate,omitempty"`
		Attempts            []AttemptRecord   `json:"attempts,omitempty"`
		AttemptsDropped     int64             `json:"attempts_dropped,omitempty"`
		PolicyRevision      string            `json:"policy_revision,omitempty"`
		PolicyRuleIDs       []string          `json:"policy_rule_ids,omitempty"`
		PolicyRoute         string            `json:"policy_route,omitempty"`
	}
	return json.Marshal(view{
		ID: m.ID, Kind: m.Kind, Attributes: m.Attributes, CorrelationID: m.CorrelationID, ParentID: m.ParentID, Direction: m.Direction,
		EnvelopeSender: m.EnvelopeSender, Recipient: m.Recipient, Headers: m.Headers, TargetFolderID: m.TargetFolderID, TargetFolderPath: m.TargetFolderPath, DeliveryRoute: m.DeliveryRoute,
		AdministrativeRoute: m.AdministrativeRoute, RouteChanges: append([]RouteChange(nil), m.RouteChanges...), RouteChangesDropped: m.RouteChangesDropped,
		Status: m.Status, RetryCount: m.RetryCount, NextRetry: m.NextRetry,
		LastError: m.LastError, LastCode: m.LastCode, LastResponse: m.LastResponse,
		AttemptID: m.AttemptID, ClaimedAt: m.ClaimedAt, ExpiresAt: m.ExpiresAt, CompletedAt: m.CompletedAt,
		HoldReason: m.HoldReason, HeldAt: m.HeldAt, ReleasedAt: m.ReleasedAt,
		PendingHoldReason: m.PendingHoldReason, PendingHoldAt: m.PendingHoldAt,
		CreatedAt: m.CreatedAt, PossibleDuplicate: m.PossibleDuplicate, Attempts: append([]AttemptRecord(nil), m.Attempts...),
		AttemptsDropped: m.AttemptsDropped, PolicyRevision: m.Policy.Revision,
		PolicyRuleIDs: m.Policy.MatchedRuleIDs(), PolicyRoute: m.PolicyRoute,
	})
}

// logDeliveryFailure records a deferral or bounce with its reason, so
// failures are visible in the log and not only in the queue view.
func logDeliveryFailure(msg *Message) {
	route := msg.DeliveryRoute
	if route == "" {
		route = msg.AdministrativeRoute
	}
	attrs := []any{"id", msg.ID, "sender", msg.EnvelopeSender, "recipient", msg.Recipient, "route", route, "attempt", msg.RetryCount, "code", msg.LastCode, "error", msg.LastError}
	if msg.Status == StatusFailed {
		logger.Warn("queue: delivery failed permanently", attrs...)
		return
	}
	logger.Warn("queue: delivery deferred", append(attrs, "next_attempt", msg.NextRetry.Format(time.RFC3339))...)
}

// smtpReplyClasses walks err (including joined errors from several MX
// targets) for SMTP reply codes and reports whether any is 4xx and
// whether any is 5xx.
func smtpReplyClasses(err error) (temporary, permanent bool) {
	if err == nil {
		return false, false
	}
	if coded, ok := err.(interface{ SMTPReplyCode() int }); ok {
		switch coded.SMTPReplyCode() / 100 {
		case 4:
			temporary = true
		case 5:
			permanent = true
		}
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, inner := range wrapped.Unwrap() {
			t, p := smtpReplyClasses(inner)
			temporary, permanent = temporary || t, permanent || p
		}
	case interface{ Unwrap() error }:
		t, p := smtpReplyClasses(wrapped.Unwrap())
		temporary, permanent = temporary || t, permanent || p
	}
	return temporary, permanent
}
