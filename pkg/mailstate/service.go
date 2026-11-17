// Package mailstate keeps per-message triage metadata that does not belong in
// the message itself: snooze wake times and follow-up dates. The visible state
// stays in the mailbox (a snoozed message lives in the "Snoozed" folder, a
// follow-up carries \Flagged) so IMAP clients see it; this package records only
// when to act. A bounded background job returns snoozed messages to the Inbox
// as unread when they wake, and survives restarts because each wake time is a
// durable record.
package mailstate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// SnoozedFolder is the mailbox folder that holds snoozed messages. It is an
// ordinary folder, so IMAP clients see snoozed messages there.
const SnoozedFolder = "Snoozed"

const (
	snoozePrefix   = "s/"
	followUpPrefix = "f/"
	schemaVersion  = 1
)

var (
	// ErrNotOwnMailbox rejects snooze and follow-up dates outside the
	// signed-in mailbox: the wake job acts as the mailbox owner.
	ErrNotOwnMailbox = fmt.Errorf("%w: snooze and follow-up dates apply to your own mailbox", service.ErrForbidden)
	ErrInvalidTime   = errors.New("the chosen time is outside the allowed range")
)

// Config bounds the wake job.
type Config struct {
	// Tick is the wake job interval; Batch caps wakes per run; MaxAhead
	// caps how far ahead a snooze or follow-up date may be.
	Tick     time.Duration
	Batch    int
	MaxAhead time.Duration
}

func (c Config) normalized() Config {
	if c.Tick <= 0 {
		c.Tick = 30 * time.Second
	}
	if c.Batch <= 0 {
		c.Batch = 100
	}
	if c.MaxAhead <= 0 {
		c.MaxAhead = 5 * 365 * 24 * time.Hour
	}
	return c
}

// Snooze records when a message in the owner's Snoozed folder wakes.
type Snooze struct {
	SchemaVersion int       `json:"schema_version"`
	OwnerID       string    `json:"owner_id"`
	ItemID        string    `json:"item_id"`
	FolderID      string    `json:"folder_id"`
	WakeAt        time.Time `json:"wake_at"`
	CreatedAt     time.Time `json:"created_at"`
	// A failed wake backs off so one broken record cannot starve the batch.
	Attempts      int       `json:"attempts,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
}

func (s Snooze) dueAt() time.Time {
	if s.NextAttemptAt.After(s.WakeAt) {
		return s.NextAttemptAt
	}
	return s.WakeAt
}

// FollowUp records the dates of a flagged message. A zero DueAt is a plain
// flag with a reminder only; a zero ReminderAt sets no reminder.
type FollowUp struct {
	SchemaVersion     int       `json:"schema_version"`
	OwnerID           string    `json:"owner_id"`
	ItemID            string    `json:"item_id"`
	DueAt             time.Time `json:"due_at,omitzero"`
	ReminderAt        time.Time `json:"reminder_at,omitzero"`
	ReminderDismissed bool      `json:"reminder_dismissed,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Service stores triage metadata and runs the snooze wake job.
type Service struct {
	typed *model.TypedStore
	space service.FolderSpace
	cfg   Config
	now   func() time.Time
	mu    sync.Mutex
}

func New(ctx context.Context, typed *model.TypedStore, space service.FolderSpace, cfg Config) (*Service, error) {
	if typed == nil || space == nil {
		return nil, errors.New("mail item state requires system storage and FolderSpace")
	}
	if err := typed.EnsureNamespace(ctx, model.NSMailItemState); err != nil {
		return nil, fmt.Errorf("initialize mail item state: %w", err)
	}
	return &Service{typed: typed, space: space, cfg: cfg.normalized(), now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetClock replaces the wake job's clock; tests use it to cross wake times.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

func key(prefix, ownerID, itemID string) string {
	return prefix + strings.ToLower(ownerID) + "/" + itemID
}

// ownItem loads an item the access subject may change in its own mailbox.
func (s *Service) ownItem(ctx context.Context, access service.AccessContext, itemID string) (model.Item, model.Folder, error) {
	item, err := s.space.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, model.Folder{}, err
	}
	folder, err := s.space.GetFolder(ctx, access, item.FolderID)
	if err != nil {
		return model.Item{}, model.Folder{}, err
	}
	if folder.Type != model.FolderTypeMail || !strings.EqualFold(folder.UserID, access.Subject.ID) {
		return model.Item{}, model.Folder{}, ErrNotOwnMailbox
	}
	return item, folder, nil
}

// Snooze moves a message to the owner's Snoozed folder until wakeAt.
func (s *Service) Snooze(ctx context.Context, access service.AccessContext, itemID string, wakeAt time.Time) (model.Item, error) {
	now := s.now()
	wakeAt = wakeAt.UTC()
	if !wakeAt.After(now) || wakeAt.After(now.Add(s.cfg.MaxAhead)) {
		return model.Item{}, ErrInvalidTime
	}
	item, _, err := s.ownItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	snoozed, err := service.EnsureFolderPath(ctx, s.space, access, SnoozedFolder, model.FolderTypeMail)
	if err != nil {
		return model.Item{}, err
	}
	if item.FolderID != snoozed.ID {
		if item, err = s.space.MoveItem(ctx, access, itemID, snoozed.ID, ""); err != nil {
			return model.Item{}, err
		}
	}
	record := Snooze{SchemaVersion: schemaVersion, OwnerID: strings.ToLower(access.Subject.ID), ItemID: item.ID, FolderID: snoozed.ID, WakeAt: wakeAt, CreatedAt: now}
	return item, s.typed.Set(ctx, model.NSMailItemState, key(snoozePrefix, record.OwnerID, item.ID), record)
}

// Unsnooze returns a snoozed message to the Inbox now.
func (s *Service) Unsnooze(ctx context.Context, access service.AccessContext, itemID string) (model.Item, error) {
	item, _, err := s.ownItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	// A message filed into Snoozed by another client has no record; it
	// still returns to the Inbox.
	record := Snooze{OwnerID: strings.ToLower(access.Subject.ID), ItemID: item.ID}
	if err := s.typed.Get(ctx, model.NSMailItemState, key(snoozePrefix, access.Subject.ID, itemID), &record); err != nil && !errors.Is(err, store.ErrNotFound) {
		return model.Item{}, err
	}
	return s.wake(ctx, access, record, item)
}

// Snoozes returns the owner's snooze records keyed by item ID.
func (s *Service) Snoozes(ctx context.Context, ownerID string) (map[string]Snooze, error) {
	return scanOwner[Snooze](ctx, s.typed, snoozePrefix, ownerID)
}

// FollowUps returns the owner's follow-up records keyed by item ID.
func (s *Service) FollowUps(ctx context.Context, ownerID string) (map[string]FollowUp, error) {
	return scanOwner[FollowUp](ctx, s.typed, followUpPrefix, ownerID)
}

func scanOwner[T any](ctx context.Context, typed *model.TypedStore, prefix, ownerID string) (map[string]T, error) {
	keys, err := typed.Scan(ctx, model.NSMailItemState, key(prefix, ownerID, ""))
	if err != nil {
		return nil, err
	}
	records := make(map[string]T, len(keys))
	for _, k := range keys {
		var record T
		if err := typed.Get(ctx, model.NSMailItemState, k, &record); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, err
		}
		records[k[strings.LastIndexByte(k, '/')+1:]] = record
	}
	return records, nil
}

// SetFollowUp flags a message and records its due and reminder times.
func (s *Service) SetFollowUp(ctx context.Context, access service.AccessContext, itemID string, dueAt, reminderAt time.Time) (model.Item, FollowUp, error) {
	now := s.now()
	for _, value := range []time.Time{dueAt, reminderAt} {
		if !value.IsZero() && (value.Before(now.Add(-s.cfg.MaxAhead)) || value.After(now.Add(s.cfg.MaxAhead))) {
			return model.Item{}, FollowUp{}, ErrInvalidTime
		}
	}
	item, _, err := s.ownItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, FollowUp{}, err
	}
	if !slices.Contains(item.Flags, model.FlagFlagged) {
		if item, err = s.space.SetFlags(ctx, access, itemID, append(slices.Clone(item.Flags), model.FlagFlagged)); err != nil {
			return model.Item{}, FollowUp{}, err
		}
	}
	record := FollowUp{SchemaVersion: schemaVersion, OwnerID: strings.ToLower(access.Subject.ID), ItemID: item.ID, DueAt: dueAt.UTC(), ReminderAt: reminderAt.UTC(), UpdatedAt: now}
	if dueAt.IsZero() {
		record.DueAt = time.Time{}
	}
	if reminderAt.IsZero() {
		record.ReminderAt = time.Time{}
	}
	return item, record, s.typed.Set(ctx, model.NSMailItemState, key(followUpPrefix, record.OwnerID, item.ID), record)
}

// ForgetFollowUp drops a message's follow-up dates; its flag is the
// caller's to change. A missing record is not an error.
func (s *Service) ForgetFollowUp(ctx context.Context, ownerID, itemID string) error {
	err := s.typed.Delete(ctx, model.NSMailItemState, key(followUpPrefix, ownerID, itemID))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// DismissReminder records that the owner saw a follow-up reminder.
func (s *Service) DismissReminder(ctx context.Context, ownerID, itemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(followUpPrefix, ownerID, itemID)
	var record FollowUp
	if err := s.typed.Get(ctx, model.NSMailItemState, k, &record); err != nil {
		return err
	}
	record.ReminderDismissed, record.UpdatedAt = true, s.now()
	return s.typed.Set(ctx, model.NSMailItemState, k, record)
}

// DueReminders returns the owner's undismissed reminders due by now,
// earliest first, at most limit.
func (s *Service) DueReminders(ctx context.Context, ownerID string, limit int) ([]FollowUp, error) {
	records, err := s.FollowUps(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var due []FollowUp
	for _, record := range records {
		if !record.ReminderAt.IsZero() && !record.ReminderDismissed && !record.ReminderAt.After(now) {
			due = append(due, record)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ReminderAt.Before(due[j].ReminderAt) })
	if len(due) > limit {
		due = due[:limit]
	}
	return due, nil
}

// Start runs the wake job until the returned stop function is called.
func (s *Service) Start(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(s.cfg.Tick)
		defer ticker.Stop()
		for {
			_, _ = s.RunOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

// RunOnce wakes at most Batch due snoozes, earliest first, and reports how
// many records it settled. A wake that fails stays due for the next run.
func (s *Service) RunOnce(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.typed.Scan(ctx, model.NSMailItemState, snoozePrefix)
	if err != nil {
		return 0, err
	}
	now := s.now()
	var due []Snooze
	for _, k := range keys {
		var record Snooze
		if err := s.typed.Get(ctx, model.NSMailItemState, k, &record); err != nil {
			continue
		}
		if !record.dueAt().After(now) {
			due = append(due, record)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].dueAt().Before(due[j].dueAt()) })
	settled := 0
	var firstErr error
	for _, record := range due[:min(len(due), s.cfg.Batch)] {
		access := service.UserAccess(record.OwnerID, "snooze")
		item, err := s.space.GetItem(ctx, access, record.ItemID)
		if err == nil && item.FolderID == record.FolderID {
			_, err = s.wake(ctx, access, record, item)
		} else if err == nil || errors.Is(err, store.ErrNotFound) {
			// The owner moved or deleted the message: nothing to wake.
			err = s.forget(ctx, record)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			record.Attempts++
			record.NextAttemptAt = now.Add(min(time.Duration(1<<min(record.Attempts, 6))*time.Minute, time.Hour))
			record.LastError = err.Error()
			_ = s.typed.Set(ctx, model.NSMailItemState, key(snoozePrefix, record.OwnerID, record.ItemID), record)
			continue
		}
		settled++
	}
	return settled, firstErr
}

// wake moves a snoozed message to the owner's Inbox, marks it unread, and
// drops its record.
func (s *Service) wake(ctx context.Context, access service.AccessContext, record Snooze, item model.Item) (model.Item, error) {
	folders, err := s.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return model.Item{}, err
	}
	inbox := slices.IndexFunc(folders, func(folder model.Folder) bool {
		return folder.Type == model.FolderTypeMail && folder.SpecialUse == model.SpecialUseInbox && strings.EqualFold(folder.UserID, record.OwnerID)
	})
	if inbox < 0 {
		return model.Item{}, fmt.Errorf("%w: the mailbox has no Inbox", store.ErrNotFound)
	}
	if item.FolderID != folders[inbox].ID {
		if item, err = s.space.MoveItem(ctx, access, item.ID, folders[inbox].ID, ""); err != nil {
			return model.Item{}, err
		}
	}
	if slices.Contains(item.Flags, model.FlagSeen) {
		if item, err = s.space.SetFlags(ctx, access, item.ID, slices.DeleteFunc(slices.Clone(item.Flags), func(flag string) bool { return flag == model.FlagSeen })); err != nil {
			return model.Item{}, err
		}
	}
	return item, s.forget(ctx, record)
}

func (s *Service) forget(ctx context.Context, record Snooze) error {
	err := s.typed.Delete(ctx, model.NSMailItemState, key(snoozePrefix, record.OwnerID, record.ItemID))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}
