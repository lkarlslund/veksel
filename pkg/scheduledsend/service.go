// Package scheduledsend owns durable, user-controlled future mail submissions.
// Draft content remains in FolderSpace; jobs retain only operational metadata.
package scheduledsend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

// MaxUndoDelay bounds the undo-send hold, which bypasses the scheduling
// minimum: the message is held only long enough for the sender to recall it.
const MaxUndoDelay = 30 * time.Second

// undoRetention is how long a finished undo-send hold is kept for the
// sender's toast to read its outcome before it is pruned.
const undoRetention = 15 * time.Minute

var (
	ErrNotFound = errors.New("scheduled submission not found")
	ErrConflict = errors.New("scheduled submission state does not allow this action")
)

type Config struct {
	Workers                                int
	MinDelay, MaxDelay, Lease, Retry, Tick time.Duration
}

func (c Config) normalized() (Config, error) {
	if c.Workers == 0 {
		c.Workers = 2
	}
	if c.MinDelay == 0 {
		c.MinDelay = time.Minute
	}
	if c.MaxDelay == 0 {
		c.MaxDelay = 365 * 24 * time.Hour
	}
	if c.Lease == 0 {
		c.Lease = 2 * time.Minute
	}
	if c.Retry == 0 {
		c.Retry = time.Minute
	}
	if c.Tick == 0 {
		c.Tick = time.Second
	}
	if c.Workers < 1 || c.Workers > 16 || c.MinDelay < 0 || c.MaxDelay < c.MinDelay || c.Lease <= 0 || c.Retry <= 0 || c.Tick <= 0 {
		return Config{}, errors.New("invalid scheduled submission configuration")
	}
	return c, nil
}

type Job struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	OwnerID       string    `json:"owner_id"`
	DraftID       string    `json:"draft_id"`
	State         State     `json:"state"`
	DueAt         time.Time `json:"due_at"`
	// Undo marks a short undo-send hold rather than a user-chosen send time.
	Undo          bool                     `json:"undo,omitempty"`
	NextAttemptAt time.Time                `json:"next_attempt_at,omitzero"`
	LeaseUntil    time.Time                `json:"lease_until,omitzero"`
	Attempts      int                      `json:"attempts"`
	LastError     string                   `json:"last_error,omitempty"`
	Submission    service.SubmissionResult `json:"submission,omitempty"`
	CreatedAt     time.Time                `json:"created_at"`
	UpdatedAt     time.Time                `json:"updated_at"`
	CompletedAt   time.Time                `json:"completed_at,omitzero"`
	CancelledAt   time.Time                `json:"cancelled_at,omitzero"`
}

type Submitter interface {
	SubmitIdempotent(context.Context, model.PrincipalRef, service.Submission, string) (service.SubmissionResult, error)
}

type Service struct {
	typed *model.TypedStore
	space service.FolderSpace
	mail  Submitter
	cfg   Config
	now   func() time.Time
	mu    sync.Mutex
	wg    sync.WaitGroup
}

func New(ctx context.Context, typed *model.TypedStore, space service.FolderSpace, mail Submitter, cfg Config) (*Service, error) {
	if typed == nil || space == nil || mail == nil {
		return nil, errors.New("scheduled submissions require system storage, FolderSpace, and Mail")
	}
	var err error
	if cfg, err = cfg.normalized(); err != nil {
		return nil, err
	}
	if err := typed.EnsureNamespace(ctx, model.NSScheduledSubmissions); err != nil {
		return nil, fmt.Errorf("initialize scheduled submissions: %w", err)
	}
	return &Service{typed: typed, space: space, mail: mail, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Schedule(ctx context.Context, ownerID, draftID string, dueAt time.Time) (Job, error) {
	now := s.now()
	dueAt = dueAt.UTC()
	if err := s.validateDue(now, dueAt); err != nil {
		return Job{}, err
	}
	return s.create(ctx, ownerID, draftID, dueAt, false)
}

// HoldForUndo submits a saved draft after delay, the undo-send window. The
// hold is durable like any scheduled send: a restart during the window
// still sends, and Cancel within it recalls the message, which then never
// reaches the queue or the Sent folder.
func (s *Service) HoldForUndo(ctx context.Context, ownerID, draftID string, delay time.Duration) (Job, error) {
	if delay < time.Second || delay > MaxUndoDelay {
		return Job{}, fmt.Errorf("undo delay must be between 1 and %d seconds", int(MaxUndoDelay/time.Second))
	}
	return s.create(ctx, ownerID, draftID, s.now().Add(delay).UTC(), true)
}

func (s *Service) create(ctx context.Context, ownerID, draftID string, dueAt time.Time, undo bool) (Job, error) {
	now := s.now()
	if _, err := s.loadDraft(ctx, ownerID, draftID); err != nil {
		return Job{}, err
	}
	id, err := newID()
	if err != nil {
		return Job{}, err
	}
	job := Job{SchemaVersion: 1, ID: id, OwnerID: ownerID, DraftID: draftID, State: StatePending, DueAt: dueAt, Undo: undo, NextAttemptAt: dueAt, CreatedAt: now, UpdatedAt: now}
	if err := s.typed.Put(ctx, model.NSScheduledSubmissions, id, job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *Service) List(ctx context.Context, ownerID string) ([]Job, error) {
	keys, err := s.typed.List(ctx, model.NSScheduledSubmissions)
	if err != nil {
		return nil, err
	}
	result := make([]Job, 0, len(keys))
	for _, key := range keys {
		job, err := s.get(ctx, key)
		if err != nil {
			return nil, err
		}
		if ownerID == "" || job.OwnerID == ownerID {
			result = append(result, job)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].DueAt.Equal(result[j].DueAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].DueAt.Before(result[j].DueAt)
	})
	return result, nil
}

func (s *Service) Get(ctx context.Context, ownerID, id string) (Job, error) {
	job, err := s.get(ctx, id)
	if err != nil || job.OwnerID != ownerID {
		return Job{}, ErrNotFound
	}
	return job, nil
}

func (s *Service) Reschedule(ctx context.Context, ownerID, id string, dueAt time.Time) (Job, error) {
	return s.mutate(ctx, ownerID, id, func(job *Job, now time.Time) error {
		if job.State != StatePending && job.State != StateFailed {
			return ErrConflict
		}
		dueAt = dueAt.UTC()
		if err := s.validateDue(now, dueAt); err != nil {
			return err
		}
		if _, err := s.loadDraft(ctx, ownerID, job.DraftID); err != nil {
			return err
		}
		job.State, job.DueAt, job.NextAttemptAt, job.LastError = StatePending, dueAt, dueAt, ""
		return nil
	})
}

func (s *Service) Cancel(ctx context.Context, ownerID, id string) (Job, error) {
	return s.mutate(ctx, ownerID, id, func(job *Job, now time.Time) error {
		if job.State != StatePending && job.State != StateFailed {
			return ErrConflict
		}
		job.State, job.CancelledAt, job.NextAttemptAt, job.LastError = StateCancelled, now, time.Time{}, ""
		return nil
	})
}

func (s *Service) SendNow(ctx context.Context, ownerID, id string) (Job, error) {
	return s.mutate(ctx, ownerID, id, func(job *Job, now time.Time) error {
		if job.State != StatePending && job.State != StateFailed {
			return ErrConflict
		}
		job.State, job.DueAt, job.NextAttemptAt, job.LastError = StatePending, now, now, ""
		return nil
	})
}

func (s *Service) mutate(ctx context.Context, ownerID, id string, fn func(*Job, time.Time) error) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.Get(ctx, ownerID, id)
	if err != nil {
		return Job{}, err
	}
	now := s.now()
	if err := fn(&job, now); err != nil {
		return Job{}, err
	}
	job.UpdatedAt = now
	if err := s.typed.Set(ctx, model.NSScheduledSubmissions, id, job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *Service) Start(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(s.cfg.Tick)
		defer ticker.Stop()
		_ = s.RunOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.RunOnce(ctx)
			}
		}
	}()
	return func() { cancel(); <-done; s.wg.Wait() }
}

func (s *Service) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	jobs, err := s.List(ctx, "")
	if err != nil {
		return err
	}
	active := 0
	for i := range jobs {
		job := &jobs[i]
		if job.Undo && (job.State == StateCompleted || job.State == StateCancelled) && now.Sub(job.UpdatedAt) > undoRetention {
			if err := s.typed.Delete(ctx, model.NSScheduledSubmissions, job.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			continue
		}
		if job.State != StateRunning {
			continue
		}
		if job.LeaseUntil.After(now) {
			active++
			continue
		}
		job.State, job.NextAttemptAt, job.LeaseUntil = StatePending, now, time.Time{}
		job.LastError, job.UpdatedAt = "recovered an expired submission lease after restart", now
		if err := s.typed.Set(ctx, model.NSScheduledSubmissions, job.ID, *job); err != nil {
			return err
		}
	}
	for _, job := range jobs {
		if active >= s.cfg.Workers {
			break
		}
		if job.State != StatePending || now.Before(job.DueAt) || now.Before(job.NextAttemptAt) {
			continue
		}
		job.State, job.LeaseUntil, job.UpdatedAt = StateRunning, now.Add(s.cfg.Lease), now
		job.Attempts++
		if err := s.typed.Set(ctx, model.NSScheduledSubmissions, job.ID, job); err != nil {
			return err
		}
		active++
		s.wg.Add(1)
		go func(claimed Job) { defer s.wg.Done(); s.execute(ctx, claimed) }(job)
	}
	return nil
}

func (s *Service) execute(ctx context.Context, claimed Job) {
	request, err := s.loadDraft(ctx, claimed.OwnerID, claimed.DraftID)
	var result service.SubmissionResult
	if err == nil {
		result, err = s.mail.SubmitIdempotent(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: claimed.OwnerID}, request, "scheduled:"+claimed.ID)
	}
	if err == nil {
		err = s.space.DeleteItem(ctx, service.UserAccess(claimed.OwnerID, "scheduled-send"), claimed.DraftID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, getErr := s.get(ctx, claimed.ID)
	if getErr != nil || current.State != StateRunning {
		return
	}
	now := s.now()
	current.LeaseUntil, current.UpdatedAt = time.Time{}, now
	if err == nil {
		current.State, current.Submission, current.CompletedAt, current.LastError = StateCompleted, result, now, ""
		current.NextAttemptAt = time.Time{}
	} else if temporary(err) {
		current.State, current.NextAttemptAt, current.LastError = StatePending, now.Add(s.cfg.Retry), boundedError(err)
	} else {
		current.State, current.LastError, current.NextAttemptAt = StateFailed, boundedError(err), time.Time{}
	}
	_ = s.typed.Set(ctx, model.NSScheduledSubmissions, current.ID, current)
}

func (s *Service) loadDraft(ctx context.Context, ownerID, draftID string) (service.Submission, error) {
	user, err := s.typed.UserStore().Get(ctx, ownerID)
	if err != nil || !user.Enabled {
		return service.Submission{}, errors.New("account is unavailable")
	}
	access := service.UserAccess(ownerID, "scheduled-send")
	drafts, err := s.space.GetFolderByPath(ctx, access, "Drafts")
	if err != nil {
		return service.Submission{}, fmt.Errorf("resolve Drafts folder: %w", err)
	}
	item, err := s.space.GetItem(ctx, access, draftID)
	if err != nil {
		return service.Submission{}, fmt.Errorf("read scheduled draft: %w", err)
	}
	if item.FolderID != drafts.ID {
		return service.Submission{}, errors.New("scheduled item is not in Drafts")
	}
	request, err := service.ParseSubmissionMIME(item.Data)
	if err != nil {
		return service.Submission{}, fmt.Errorf("parse scheduled draft: %w", err)
	}
	return request, nil
}

func (s *Service) get(ctx context.Context, id string) (Job, error) {
	var job Job
	err := s.typed.Get(ctx, model.NSScheduledSubmissions, id, &job)
	if errors.Is(err, store.ErrNotFound) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	if job.SchemaVersion != 1 || job.ID != id || job.OwnerID == "" {
		return Job{}, errors.New("invalid scheduled submission record")
	}
	return job, nil
}

func (s *Service) validateDue(now, due time.Time) error {
	if due.Before(now.Add(s.cfg.MinDelay)) || due.After(now.Add(s.cfg.MaxDelay)) {
		return errors.New("scheduled time is outside the allowed range")
	}
	return nil
}

func temporary(err error) bool {
	return errors.Is(err, queue.ErrFull) || sendguard.IsQuota(err) || errors.Is(err, account.ErrTemporarilyUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
func boundedError(err error) string {
	value := strings.Join(strings.Fields(err.Error()), " ")
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "sched_" + hex.EncodeToString(value[:]), nil
}
