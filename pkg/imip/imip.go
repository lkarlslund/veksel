// Package imip carries iTIP scheduling messages (RFC 5546) over email
// (iMIP, RFC 6047) between local organizers and external attendees.
//
// Outgoing: the service observes committed calendar writes made by every
// protocol through the automated FolderSpace. When a local organizer's event
// gains, changes, or loses external attendees, it mails REQUEST or CANCEL
// messages through the normal outbound queue. A per-item scheduling state
// remembers what each attendee was last sent, so ordinary saves that change
// nothing an attendee depends on send nothing.
//
// Incoming: mail delivered to a local account that carries a text/calendar
// part updates attendee status on events the recipient organizes (REPLY),
// answers REFRESH, and places invitations and cancellations from external
// organizers in the recipient's calendar (REQUEST, CANCEL). Every change goes
// through the authorized FolderSpace as the recipient, and a sender can only
// change the parts of an event that belong to them.
package imip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

var logger = log.For(log.ModuleCalDAV)

// Outgoing is one generated iMIP message for the outbound queue.
type Outgoing struct {
	// From is the sending identity's address; it is also the envelope sender.
	From string
	// To lists the envelope recipients, one queue job each.
	To []string
	// Raw is the complete RFC 5322 message.
	Raw []byte
	// UID is the scheduled event's UID, used to correlate queue records.
	UID string
	// Local marks the Inbox copy of a scheduling message for a local
	// attendee whose calendar copy has already been updated.
	Local bool
}

// Config wires the service to its collaborators.
type Config struct {
	// Space is the authorized FolderSpace used for every calendar and mail
	// read or write.
	Space service.FolderSpace
	// Store keeps the per-item scheduling state.
	Store store.Store
	// Identity looks up a local sending identity by exact address.
	Identity func(context.Context, string) (model.EmailAddress, error)
	// Resolve routes an address through the unified recipient resolver;
	// store.ErrNotFound means the address is not local.
	Resolve func(context.Context, string) (model.RecipientRoute, error)
	// Send submits a generated message to the outbound queue.
	Send func(context.Context, Outgoing) error
	// Resource returns the booking profile of a resource account, or nil
	// for an ordinary account. Optional: without it no account books
	// itself automatically.
	Resource func(context.Context, string) *model.ResourceProfile
	// Busy lists the busy periods, with their event UIDs, of an account's
	// calendars over [start, end); resource bookings check conflicts with
	// it. Optional.
	Busy func(ctx context.Context, userID string, start, end time.Time) ([]calendarindex.BusyPeriod, error)
}

// Service implements iMIP scheduling. The zero value is not usable; call New.
type Service struct {
	cfg     Config
	enabled atomic.Bool

	// mu serializes state transitions so concurrent saves of one event
	// cannot both decide they are the first to invite an attendee.
	mu sync.Mutex
	// scheduled caches the IDs of items with scheduling state, so removals
	// of unrelated items never touch the store.
	scheduledOnce sync.Once
	scheduledErr  error
	scheduled     map[string]struct{}
}

// New returns an enabled service.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Space == nil || cfg.Store == nil || cfg.Identity == nil || cfg.Resolve == nil || cfg.Send == nil {
		return nil, errors.New("iMIP scheduling requires a folder space, store, identity lookup, recipient resolver, and sender")
	}
	exists, err := cfg.Store.NamespaceExists(ctx, model.NSIMIPState)
	if err != nil {
		return nil, fmt.Errorf("inspect iMIP state namespace: %w", err)
	}
	if !exists {
		if err := cfg.Store.CreateNamespace(ctx, model.NSIMIPState); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("create iMIP state namespace: %w", err)
		}
	}
	s := &Service{cfg: cfg}
	s.enabled.Store(true)
	return s, nil
}

// SetEnabled switches iMIP sending and incoming processing on or off.
func (s *Service) SetEnabled(enabled bool) { s.enabled.Store(enabled) }

// Enabled reports whether iMIP is active.
func (s *Service) Enabled() bool { return s != nil && s.enabled.Load() }

// eventState is what the external attendees of one organizer event were
// last sent.
type eventState struct {
	Owner     string `json:"owner"`
	UID       string `json:"uid"`
	Organizer string `json:"organizer"`
	// OrganizerName is the organizer's CN, shown as the From display name.
	OrganizerName string   `json:"organizer_name,omitempty"`
	Sequence      int      `json:"sequence"`
	Timing        string   `json:"timing"`
	Recipients    []string `json:"recipients"`
	// Source is the organizer's calendar object as last scheduled; CANCEL
	// messages are built from it after the event is gone.
	Source []byte `json:"source"`
	// Replies holds the DTSTAMP of the newest applied REPLY per attendee so
	// a reordered older reply cannot overwrite a newer answer.
	Replies map[string]string `json:"replies,omitempty"`
	// Content digests the event texts local attendee copies follow.
	Content string `json:"content,omitempty"`
	// Local maps each local attendee address to its account; their copies
	// are delivered to their calendars instead of mailed.
	Local map[string]string `json:"local,omitempty"`
	// Comments holds the newest reply comment per attendee.
	Comments map[string]string `json:"comments,omitempty"`
	// Proposals holds the pending new-time proposal (COUNTER) per attendee.
	Proposals map[string]Proposal `json:"proposals,omitempty"`
}

// Proposal is an attendee's pending COUNTER awaiting the organizer.
type Proposal struct {
	Attendee string    `json:"attendee"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Comment  string    `json:"comment,omitempty"`
	Received time.Time `json:"received"`
	// Counter is the COUNTER message, kept to answer with DECLINECOUNTER.
	Counter []byte `json:"counter,omitempty"`
}

func (s *Service) loadScheduled(ctx context.Context) error {
	s.scheduledOnce.Do(func() {
		keys, err := s.cfg.Store.List(ctx, model.NSIMIPState)
		if err != nil {
			s.scheduledErr = err
			return
		}
		s.scheduled = make(map[string]struct{}, len(keys))
		for _, key := range keys {
			s.scheduled[key] = struct{}{}
		}
	})
	return s.scheduledErr
}

// hasState reports whether an item may have scheduling state. It answers
// true when the cache could not load so state is never silently skipped.
func (s *Service) hasState(ctx context.Context, itemID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadScheduled(ctx); err != nil {
		return true
	}
	_, ok := s.scheduled[itemID]
	return ok
}

// state returns the item's scheduling state; callers hold s.mu.
func (s *Service) state(ctx context.Context, itemID string) (*eventState, error) {
	if err := s.loadScheduled(ctx); err == nil {
		if _, ok := s.scheduled[itemID]; !ok {
			return nil, nil
		}
	}
	raw, err := s.cfg.Store.Get(ctx, model.NSIMIPState, itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state eventState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("decode iMIP state: %w", err)
	}
	return &state, nil
}

// saveState stores (or, with nil, removes) the item's scheduling state;
// callers hold s.mu.
func (s *Service) saveState(ctx context.Context, itemID string, state *eventState) error {
	if state == nil {
		err := s.cfg.Store.Delete(ctx, model.NSIMIPState, itemID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if s.scheduled != nil {
			delete(s.scheduled, itemID)
		}
		return nil
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := s.cfg.Store.Set(ctx, model.NSIMIPState, itemID, raw); err != nil {
		return err
	}
	if s.scheduled != nil {
		s.scheduled[itemID] = struct{}{}
	}
	return nil
}

// ownIdentity returns the enabled identity at address when it belongs to
// userID.
func (s *Service) ownIdentity(ctx context.Context, userID, address string) (model.EmailAddress, bool) {
	if address == "" {
		return model.EmailAddress{}, false
	}
	identity, err := s.cfg.Identity(ctx, address)
	if err != nil || !identity.Enabled || !strings.EqualFold(identity.UserID, userID) {
		return model.EmailAddress{}, false
	}
	return identity, true
}

// silentKey marks a context whose calendar writes schedule nobody.
type silentKey struct{}

// WithoutAttendeeMessages returns a context whose calendar writes and
// removals send no invitations, updates or cancellations, for clients that
// ask explicitly not to notify attendees (EWS SendToNone). A later write
// without it compares the event with what the attendees were last sent and
// catches them up; a silent removal forgets the scheduling state.
func WithoutAttendeeMessages(ctx context.Context) context.Context {
	return context.WithValue(ctx, silentKey{}, true)
}

func silent(ctx context.Context) bool {
	value, _ := ctx.Value(silentKey{}).(bool)
	return value
}

// mayBeEvent is the cheap pre-check every observed write passes through.
func mayBeEvent(data []byte) bool {
	return len(data) <= maxCalendarBytes && bytes.Contains(data, []byte("VEVENT"))
}
