package main

import (
	"context"
	"errors"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// buildCalendarScheduling attaches iMIP to the automated folder space so
// calendar writes from every protocol schedule external attendees, and
// registers calendar_imip_enabled as a live setting.
func (s *server) buildCalendarScheduling(space *rules.FolderSpace) error {
	service, err := imip.New(s.ctx, imip.Config{
		Space: space, Store: s.store, Identity: s.ts.UserStore().GetEmailAddress,
		Resolve: s.resolveRecipient, Send: s.sendIMIP,
		Resource: func(ctx context.Context, userID string) *model.ResourceProfile {
			user, err := s.ts.UserStore().Get(ctx, userID)
			if err != nil {
				return nil
			}
			return user.Resource
		},
		// The web app owns the calendar range index; it is built after
		// scheduling, before any delivery can book a resource.
		Busy: func(ctx context.Context, userID string, start, end time.Time) ([]calendarindex.BusyPeriod, error) {
			if s.appHandler == nil {
				return nil, errors.New("calendar availability is starting")
			}
			return s.appHandler.BusyPeriods(ctx, userID, nil, start, end)
		},
	})
	if err != nil {
		return startupError("initialize calendar email invitations", err)
	}
	service.SetEnabled(s.cfg.CalendarImipEnabled)
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		service.SetEnabled(cfg.CalendarImipEnabled)
		return nil
	}, "calendar_imip_enabled"); err != nil {
		return err
	}
	space.SetItemObserver(service)
	s.imip = service
	return nil
}

// sendIMIP queues one DKIM-signed derived delivery of a scheduling message
// per recipient.
func (s *server) sendIMIP(ctx context.Context, message imip.Outgoing) error {
	if s.smtpQueueAdapter == nil {
		return errors.New("system queue is starting")
	}
	for _, recipient := range message.To {
		if err := s.enqueueDerived(ctx, smtp.DerivedMessage{Kind: "imip", Recipient: recipient, EnvelopeSender: message.From,
			FullMessage: message.Raw, CorrelationID: message.UID, DKIM: &dkim.Request{}}); err != nil {
			return err
		}
	}
	return nil
}
