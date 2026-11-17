package main

import (
	"context"
	"errors"
	"time"

	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// quotaScanInterval bounds the metadata-only quota warning pass. Usage is
// derived from folder totals, so a pass costs one catalog read per limited
// account and never touches item payloads.
const quotaScanInterval = 10 * time.Minute

// buildAlertDelivery creates the alert notifier and the quota warning
// watcher. Their policy follows managed configuration live through the
// application handler's alert appliers.
func (s *server) buildAlertDelivery() error {
	notifier, err := alertnotify.New(s.healthAlerts, s.ts.Store(), alertnotify.Channels{
		Mail: func(ctx context.Context, recipient string, message alertnotify.Message) error {
			return s.sendNotificationMail(ctx, "health-alert", recipient, message)
		},
		Webhook: func(event string, payload any) error {
			if s.webhooks == nil {
				return errors.New("webhook dispatcher is not running")
			}
			return s.webhooks.Queue(event, payload)
		},
		WebhookSubscribed: func(event string) bool { return s.webhooks != nil && s.webhooks.Subscribed(event) },
	}, alertnotify.PolicyFromConfig(s.cfg))
	if err != nil {
		return startupError("initialize alert notifications", err)
	}
	s.alertNotifier = notifier
	users := s.ts.UserStore()
	s.quotaWatcher, err = alertnotify.NewQuotaWatcher(s.ts.Store(), alertnotify.QuotaSource{
		Accounts: func(ctx context.Context) ([]string, error) {
			accounts, err := users.List(ctx)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(accounts))
			for _, account := range accounts {
				if account.Enabled {
					ids = append(ids, account.ID)
				}
			}
			return ids, nil
		},
		Limited: func(ctx context.Context, account string) (bool, error) {
			quota, err := users.GetQuota(ctx, account)
			return quota.MaxStorageBytes > 0 || quota.MaxItems > 0, err
		},
		Usage: func(ctx context.Context, account string) (service.AccountUsage, error) {
			return s.folderSpace.AccountUsage(ctx, service.UserAccess(account, "quota-warning"))
		},
		Recipient: s.digestRecipient,
	}, func(ctx context.Context, recipient string, message alertnotify.Message) error {
		return s.sendNotificationMail(ctx, "quota-warning", recipient, message)
	})
	if err != nil {
		return startupError("initialize quota warnings", err)
	}
	return nil
}

// sendNotificationMail admits generated notification mail into the outbound
// queue from the system mail domain's postmaster, DKIM-signed at admission
// like delivery status notifications and reports.
func (s *server) sendNotificationMail(ctx context.Context, kind, recipient string, message alertnotify.Message) error {
	domain := s.systemMailDomain()
	if domain == "" {
		return errors.New("no enabled hosted domain can send system mail")
	}
	if s.smtpQueueAdapter == nil {
		return errors.New("outbound queue is not running")
	}
	sender := "postmaster@" + domain
	return s.enqueueDerived(ctx, smtp.DerivedMessage{
		Kind: kind, Recipient: recipient, EnvelopeSender: sender,
		FullMessage: alertnotify.ComposeMail("Veksel <"+sender+">", recipient, message),
		ParentID:    message.ID, CorrelationID: message.ID, DKIM: &dkim.Request{},
	})
}

// processAlertNotifications delivers pending alert transitions in the
// background so a slow push receiver never delays health evaluation.
func (s *server) processAlertNotifications() {
	if s.alertNotifier == nil || !s.alertDeliveryBusy.CompareAndSwap(false, true) {
		return
	}
	if !s.background.Go(func(ctx context.Context) {
		defer s.alertDeliveryBusy.Store(false)
		if err := s.alertNotifier.Process(ctx); err != nil && ctx.Err() == nil {
			log.Error("deliver health alert notifications", "error", err)
		}
	}) {
		s.alertDeliveryBusy.Store(false)
	}
}

// scanQuotaWarnings runs one bounded quota warning pass in the background.
func (s *server) scanQuotaWarnings() {
	if s.quotaWatcher == nil || !s.quotaScanBusy.CompareAndSwap(false, true) {
		return
	}
	if !s.background.Go(func(ctx context.Context) {
		defer s.quotaScanBusy.Store(false)
		effective, _ := s.currentConfig()
		policy := service.QuotaPolicy{WarningPercent: effective.QuotaWarningPercent, CriticalPercent: effective.QuotaCriticalPercent}
		scan, err := s.quotaWatcher.Scan(ctx, policy, effective.QuotaWarningEmailsEnabled)
		if err != nil && ctx.Err() == nil {
			log.Error("scan quota warnings", "error", err)
		}
		if scan.Notified > 0 {
			log.Info("sent quota warnings", "count", scan.Notified)
		}
	}) {
		s.quotaScanBusy.Store(false)
	}
}
