package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dmarc"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/jmap"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailstate"
	"github.com/lkarlslund/veksel/pkg/messagetrace"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/scheduledsend"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
	"github.com/lkarlslund/veksel/pkg/virus"
	"github.com/lkarlslund/veksel/pkg/webhook"
)

func tlsReportError(reportErr error) {
	log.Error("record SMTP TLS outcome", "error", reportErr)
}

func dmarcAggregateError(reportErr error) {
	log.Error("record DMARC aggregate observation", "error", reportErr)
}

// buildMailServices opens the mail transport stack in dependency order: trace
// and transport-security reporting, the relay, quarantine, the durable system
// queue, submission, content scanning, digests, and report delivery.
func (s *server) buildMailServices() error {
	for _, step := range []func() error{
		s.openMailTelemetry,
		s.configureRelay,
		s.openAddressing,
		s.openQuarantine,
		s.openQueue,
		s.startSubmission,
		s.buildContentScanning,
		s.startQuarantineDigests,
		s.startReportDelivery,
		s.registerDeliverySettings,
	} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// openMailTelemetry opens message trace, MTA-STS, DANE, SMTP TLS reporting,
// and DMARC aggregate reporting, and schedules their retention cleanup.
func (s *server) openMailTelemetry() error {
	cfg, ctx := s.cfg, s.ctx
	var err error
	s.messageTrace, err = messagetrace.New(ctx, s.ts.Store())
	if err != nil {
		return startupError("open message trace", err)
	}
	s.appHandler.SetMessageTrace(s.messageTrace)
	s.delivery.traceRetentionDays.Store(int64(cfg.MessageTraceRetentionDays))
	s.pruneMessageTrace()
	s.background.Every(24*time.Hour, false, s.pruneMessageTrace)

	s.mtaSTS, err = mtasts.New(ctx, s.ts.Store(), mtasts.Options{})
	if err != nil {
		return startupError("initialize MTA-STS", err)
	}
	pruneMTASTS := func() {
		removed, pruneErr := s.mtaSTS.Prune(ctx, time.Now().UTC().AddDate(0, 0, -30))
		if pruneErr != nil {
			log.Error("prune MTA-STS policy cache", "error", pruneErr)
		} else if removed > 0 {
			log.Info("MTA-STS: pruned stale policy status", "records", removed)
		}
	}
	pruneMTASTS()
	s.background.Every(24*time.Hour, false, pruneMTASTS)
	if err := s.openDANE(cfg); err != nil {
		return err
	}
	s.tlsReporter, err = tlsrpt.NewRecorder(ctx, s.ts.Store(), tlsrpt.RecorderOptions{})
	if err != nil {
		return startupError("initialize SMTP TLS reporting", err)
	}
	s.dmarcAggregates, err = dmarc.NewAggregateRecorder(ctx, s.ts.Store(), dmarc.AggregateRecorderOptions{})
	if err != nil {
		return startupError("initialize DMARC aggregate reporting", err)
	}
	s.delivery.dmarc.recorder = s.dmarcAggregates
	s.delivery.dmarc.enabled.Store(cfg.DmarcAggregateEnabled)
	s.delivery.dmarc.retentionDays.Store(int64(cfg.DmarcAggregateRetentionDays))
	s.dmarcAggregateSink = &s.delivery.dmarc
	s.cleanupDMARCAggregates()
	s.background.Every(24*time.Hour, false, s.cleanupDMARCAggregates)
	return nil
}

// pruneMessageTrace removes trace records older than the current retention.
func (s *server) pruneMessageTrace() {
	before := time.Now().UTC().AddDate(0, 0, -int(s.delivery.traceRetentionDays.Load()))
	if removed, pruneErr := s.messageTrace.Prune(s.ctx, before); pruneErr != nil {
		log.Error("prune message trace", "error", pruneErr)
	} else if removed > 0 {
		log.Info("message trace: pruned expired records", "records", removed)
	}
}

// cleanupDMARCAggregates removes observations older than the current
// retention.
func (s *server) cleanupDMARCAggregates() {
	before := time.Now().UTC().AddDate(0, 0, -int(s.delivery.dmarc.retentionDays.Load()))
	removed, cleanupErr := s.dmarcAggregates.CleanupBefore(s.ctx, before, 100000)
	if cleanupErr != nil {
		log.Error("cleanup DMARC aggregate reporting", "error", cleanupErr)
	} else if removed > 0 {
		log.Info("DMARC aggregate reporting cleanup", "removed", removed)
	}
}

// configureRelay creates the outbound relay client for external domain
// delivery, when one is configured, and the direct-MX fallback.
func (s *server) configureRelay() error {
	cfg := s.cfg
	if cfg.RelayEnabled() {
		log.Info("smtp: outbound relay configured", "host", cfg.RelayHost, "port", cfg.RelayPort)
	}
	s.delivery.outbound.Store(s.buildOutboundRoutes(cfg))
	return nil
}

// openQueue opens the durable system queue. It is the boundary for both
// inbound local appends and outbound relay work; its scheduling index is
// rebuilt from the same generic disk-backed store used by folders and items.
func (s *server) openQueue() error {
	cfg, ts, met := s.cfg, s.ts, s.met
	s.vacationProcessor = service.VacationIntentProcessor{
		Prepare: s.prepareDerived,
		GetQueue: func(id string) *queue.Message {
			if s.mailQueue == nil {
				return nil
			}
			return s.mailQueue.Get(id)
		},
		Completed: func(id string) bool { return s.mailQueue != nil && s.mailQueue.WasCompleted(id) },
		Enqueue: func(message *smtp.MailMessage) error {
			if s.mailQueue == nil {
				return errors.New("system queue is starting")
			}
			return queue.NewSMTPAdapter(s.mailQueue).Enqueue(message)
		},
		Release: func(id string) bool { return s.mailQueue != nil && s.mailQueue.Release(id) },
		Reserve: ts.UserStore().ReserveVacationReplyWithin, Complete: ts.UserStore().CompleteVacationReply,
		Cancel: ts.UserStore().CancelVacationReply, Record: ts.UserStore().RecordVacationReply,
	}
	if err := s.buildSendGuard(); err != nil {
		return err
	}
	limits := queueLimits(cfg)
	mailQueue, err := queue.NewPersistent(context.Background(), ts.Store(), &queue.Config{
		MaxSize:           limits.MaxSize,
		Workers:           limits.Workers,
		MaxPerDestination: limits.MaxPerDestination,
		MaxAge:            limits.MaxAge,
		RetryInitial:      limits.RetryInitial,
		RetryMax:          limits.RetryMax,
		ReceiptRetention:  limits.ReceiptRetention,
		Admission:         s.queueAdmission(),
		Copies:            s.mailFlowCopies,
		Screen:            s.sendGuard.Screen,
		DeliveryHold:      s.sendGuard.DeliveryHold,
		Signer:            dkim.NewSigner(ts.DomainStore()),
		Delivery:          s.deliver,
		FailureMessage:    s.deliveryStatusNotification,
		Observer:          s.observeQueueEvent,
	})
	if err != nil {
		return startupError("open durable system queue", err)
	}
	s.mailQueue = mailQueue
	s.sendGuard.AttachQueue(mailQueue)
	s.cleanup.pushAbort(mailQueue.Close)
	s.accountManager.SetAvailabilityNotifier(func(login string) {
		if woken, wakeErr := mailQueue.WakeOwner(login); wakeErr != nil {
			log.Error("wake account delivery queue", "account", login, "error", wakeErr)
		} else if woken > 0 {
			log.Info("woke maintenance-held deliveries", "account", login, "messages", woken)
		}
	})
	recordQueueStats := func() {
		stats := mailQueue.Stats()
		s.latestQueueStats.Store(&stats)
		met.SetGauge("mail_queue_depth", float64(stats.Size), nil)
		met.SetGauge("mail_queue_oldest_age_seconds", stats.OldestAgeSeconds, nil)
		met.SetGauge("mail_queue_completion_receipts", float64(stats.CompletionReceipts), nil)
		for _, status := range []queue.Status{queue.StatusPending, queue.StatusProcessing, queue.StatusRetrying, queue.StatusHeld, queue.StatusFailed} {
			met.SetGauge("mail_queue_status", float64(stats.ByStatus[status]), map[string]string{"status": string(status)})
		}
	}
	s.background.Every(15*time.Second, true, recordQueueStats)
	s.appHandler.SetMailQueue(mailQueue)
	return nil
}

// startSubmission starts scheduled sending and the submission service used
// by JMAP, EWS, EAS, and SMTP submission authorization.
func (s *server) startSubmission() error {
	cfg, ts, ctx := s.cfg, s.ts, s.ctx
	scheduledMail, err := s.appHandler.ConfigureScheduledSubmissions(ctx, scheduledsend.Config{})
	if err != nil {
		return startupError("initialize scheduled mail", err)
	}
	s.stopScheduledMail = scheduledMail.Start(ctx)
	s.cleanup.push(s.stopScheduledMail)
	mailState, err := s.appHandler.ConfigureMailState(ctx, mailstate.Config{})
	if err != nil {
		return startupError("initialize mail snooze and follow-up state", err)
	}
	s.cleanup.push(mailState.Start(ctx))
	exchangeMail := service.NewMailWithFolderSpace(ts, authz.New(ts), s.mailQueue, s.folderSpace)
	s.exchangeMail = exchangeMail
	s.recipientHistory = service.NewRecipientHistory(s.folderSpace)
	exchangeMail.SetRecipientHistory(s.recipientHistory)
	// JMAP is always mounted; the HTTP service gate follows jmap_enabled.
	jmapHandler, jmapErr := jmap.New(jmap.Config{
		Space: s.folderSpace, Authorizer: authz.New(ts), Search: s.search, MailIndex: s.protocolControl.controllers.mailIndex,
		Directory: jmap.NewModelDirectory(ts), Submitter: exchangeMail,
		Accounts: accountIndexes{accounts: s.accountManager}, State: s.store, Go: s.background.Go,
		MaxSizeUpload: cfg.SmtpMaxMessageSize,
		Authenticate: func(ctx context.Context, username, password string) (model.User, error) {
			result, err := s.protocolAuth.Authenticate(ctx, username, password, model.AppProtocolJMAP)
			if err != nil {
				return model.User{}, fmt.Errorf("invalid credentials")
			}
			return result.User, nil
		},
	})
	if jmapErr != nil {
		return startupError("initialize JMAP", jmapErr)
	}
	jmapHandler.Register(s.mux)
	// Submission history follows change_history_retention_days, live.
	s.appHandler.ObserveChangeRetention(func(days, _ int) {
		jmapHandler.SetSubmissionRetention(time.Duration(days) * 24 * time.Hour)
	})
	// The sweep expires push subscriptions, prunes submission history, and
	// at startup resumes delivery for the verified push subscriptions.
	s.background.Every(15*time.Minute, true, func() {
		if err := jmapHandler.Sweep(s.background.Context()); err != nil {
			log.Warn("sweep JMAP push subscriptions and submissions", "error", err)
		}
	})
	s.appHandler.SetSystemQueue(s.mailQueue)
	s.protocolControl.controllers.mailQueue = s.mailQueue
	s.smtpQueueAdapter = queue.NewSMTPAdapter(s.mailQueue)
	return nil
}

// buildContentScanning assembles the configured malware and spam scanners
// behind the live scanning switch shared by SMTP and the admin UI.
func (s *server) buildContentScanning() error {
	if err := s.applyContentScanning(s.cfg); err != nil {
		return startupError("configure content scanning", err)
	}
	s.delivery.spamDNS = spam.NewDNS(net.DefaultResolver, spam.DNSOptions{Observer: metrics.NewSpamObserver(s.met)})
	s.delivery.spamIdentities = spam.NewIdentityCache(spamDirectory{s}, spam.DefaultIdentityCacheTTL)
	if err := s.applySpamFiltering(s.cfg); err != nil {
		return startupError("configure spam filtering", err)
	}
	s.appHandler.ConfigureSpamFiltering(&s.delivery.spam, s.delivery.spamDNS)
	if s.spamClassifier != nil {
		s.appHandler.ConfigureSpamClassifier(s.spamClassifier)
	}
	s.appHandler.ConfigureSpamReputation(&s.delivery.reputation)
	s.appHandler.ConfigureContentScanning(&s.delivery.scanning)
	s.appHandler.ConfigureContentTrainer(&s.delivery.scanning)
	return nil
}

// systemMailDomain picks the hosted domain that sends system mail (SMTP TLS
// and DMARC aggregate reports, delivery status notifications): the SMTP
// server name's domain when hosted, otherwise the first enabled hosted
// domain, so the mail can carry an aligned DKIM signature.
func (s *server) systemMailDomain() string {
	ctx, ts := s.ctx, s.ts
	if candidate, candidateErr := mtasts.CanonicalDomain(s.smtpServerName()); candidateErr == nil {
		if hosted, hostedErr := ts.DomainStore().Get(ctx, candidate); hostedErr == nil && hosted.Enabled {
			return candidate
		}
	}
	if hostedDomains, listErr := ts.DomainStore().List(ctx); listErr == nil {
		for _, hosted := range hostedDomains {
			if hosted.Enabled {
				return hosted.ID
			}
		}
	}
	return ""
}

// startReportDelivery schedules daily SMTP TLS and DMARC aggregate report
// mail when a hosted submitter domain exists.
func (s *server) startReportDelivery() error {
	submitterDomain := s.systemMailDomain()
	tlsReportSchedulerRunning := false
	if submitterDomain != "" {
		if err := s.startTLSReportDelivery(submitterDomain); err != nil {
			return err
		}
		tlsReportSchedulerRunning = true
	} else {
		log.Warn("SMTP TLS and DMARC reports are retained but cannot be sent until an enabled hosted domain exists")
	}
	if err := s.configureDMARCReporting(s.cfg, submitterDomain); err != nil {
		return startupError("initialize DMARC aggregate delivery", err)
	}
	s.startDMARCReportDelivery()
	s.startUserAliasCleanup()
	s.appHandler.ConfigureOutboundTLS(s.mtaSTS, s.tlsReporter, tlsReportSchedulerRunning)
	s.appHandler.ConfigureDANE(s.daneStatus)
	s.appHandler.ConfigureDMARCAggregates(s.dmarcAggregates, &s.delivery.dmarc, false)
	return nil
}

// reportMail describes one outgoing SMTP TLS or DMARC aggregate report.
type reportMail struct {
	kind, label     string // derived message kind and human-readable name
	submitterDomain string
	sender          string // local part of the envelope sender
	recipient       string
	reportID        string
	build           func() ([]byte, error)
	signedHeaders   []string // DKIM-signed in addition to dkim.DefaultHeaders
	attributes      map[string]string
}

// sendReport builds a report message and enqueues it as derived mail that
// must be DKIM-signed for its enabled submitter domain when sent remotely.
func (s *server) sendReport(ctx context.Context, report reportMail) error {
	message, buildErr := report.build()
	if buildErr != nil {
		return buildErr
	}
	prepared, prepareErr := s.prepareDerived(ctx, smtp.DerivedMessage{Kind: report.kind, Recipient: report.recipient,
		EnvelopeSender: report.sender + "@" + report.submitterDomain, FullMessage: message, ParentID: report.reportID, CorrelationID: report.reportID,
		DKIM: &dkim.Request{Headers: report.signedHeaders, Required: true}})
	if prepareErr != nil {
		return prepareErr
	}
	if prepared.Attributes == nil {
		prepared.Attributes = make(map[string]string)
	}
	prepared.Kind = report.kind
	for name, value := range report.attributes {
		prepared.Attributes[name] = value
	}
	if err := s.enqueuePrepared(prepared); err != nil {
		return fmt.Errorf("enqueue %s: %w", report.label, err)
	}
	return nil
}

func (s *server) startTLSReportDelivery(submitterDomain string) error {
	ctx := s.ctx
	mailer := tlsrpt.MailerFunc(func(mailCtx context.Context, report tlsrpt.MailReport) error {
		return s.sendReport(mailCtx, reportMail{
			kind: "tls-report", label: "TLS report", submitterDomain: report.SubmitterDomain,
			sender: "tlsrpt", recipient: report.Recipient, reportID: report.ReportID,
			build:         func() ([]byte, error) { return tlsrpt.BuildEmailMessage(report, time.Now().UTC()) },
			signedHeaders: []string{"tls-report-domain", "tls-report-submitter"},
			attributes:    map[string]string{"tlsrpt_suppress": "true"},
		})
	})
	sender, err := tlsrpt.NewReporter(s.tlsReporter, tlsrpt.ReporterOptions{
		Metadata: tlsrpt.ReportMetadata{OrganizationName: "Veksel", ContactInfo: "postmaster@" + submitterDomain, SubmitterDomain: submitterDomain},
		Mailer:   mailer,
	})
	if err != nil {
		return startupError("initialize SMTP TLS report delivery", err)
	}
	process := func() {
		now := time.Now().UTC()
		if now.Hour() < 1 {
			return
		}
		days, daysErr := s.tlsReporter.Days(ctx)
		if daysErr != nil {
			log.Error("list SMTP TLS report days", "error", daysErr)
			return
		}
		for _, day := range days {
			if day >= now.Format(time.DateOnly) {
				continue
			}
			jobs, processErr := sender.ProcessDay(ctx, day)
			if processErr != nil {
				log.Error("process SMTP TLS reports", "day", day, "error", processErr)
				continue
			}
			for _, job := range jobs {
				log.Info("SMTP TLS report", "day", job.Day, "domain", job.PolicyDomain, "status", job.Status, "attempts", job.Attempts)
			}
		}
	}
	s.background.Every(time.Hour, true, process)
	return nil
}

// dmarcReportMailer DKIM-signs and enqueues DMARC aggregate reports.
func (s *server) dmarcReportMailer() dmarc.AggregateMailer {
	return dmarc.AggregateMailerFunc(func(mailCtx context.Context, report dmarc.AggregateMailReport) error {
		return s.sendReport(mailCtx, reportMail{
			kind: "dmarc-report", label: "DMARC report", submitterDomain: report.SubmitterDomain,
			sender: "dmarc", recipient: report.Recipient, reportID: report.ReportID,
			build: func() ([]byte, error) { return dmarc.BuildAggregateEmail(report, time.Now().UTC()) },
			// No REQUIRETLS: few receivers support the extension (Postfix
			// does not), so a flagged report could never be delivered;
			// aggregate reports carry counts, not message content, and
			// still use STARTTLS whenever it is offered.
			signedHeaders: []string{"auto-submitted"},
		})
	})
}

// startDMARCReportDelivery schedules hourly delivery of completed days'
// DMARC aggregate reports with whichever sender is current; it idles while
// reporting is disabled.
func (s *server) startDMARCReportDelivery() {
	ctx := s.ctx
	process := func() {
		now := time.Now().UTC()
		if now.Hour() < 1 || !s.delivery.dmarc.Running() {
			return
		}
		days, daysErr := s.dmarcAggregates.Days(ctx)
		if daysErr != nil {
			log.Error("list DMARC aggregate days", "error", daysErr)
			return
		}
		for _, day := range days {
			if day >= now.Format(time.DateOnly) {
				continue
			}
			jobs, processErr := s.delivery.dmarc.ProcessDay(ctx, day)
			if processErr != nil {
				log.Error("process DMARC aggregate reports", "day", day, "error", processErr)
				continue
			}
			for _, job := range jobs {
				log.Info("DMARC aggregate report", "day", job.Day, "domain", job.PolicyDomain, "destination", job.Destination, "status", job.Status, "attempts", job.Attempts)
			}
		}
	}
	s.background.Every(time.Hour, true, process)
}

// prepareDerived resolves local recipients of server-generated mail.
func (s *server) prepareDerived(ctx context.Context, derived smtp.DerivedMessage) (*smtp.MailMessage, error) {
	return smtp.PrepareDerivedMessage(ctx, derived, func(ctx context.Context, recipient string) (string, string, bool, error) {
		identity, err := s.recipientMailbox(ctx, recipient)
		if errors.Is(err, store.ErrNotFound) {
			return "", "", false, nil
		}
		if err != nil {
			return "", "", false, err
		}
		if !identity.Enabled {
			return "", "", false, fmt.Errorf("local recipient %q is disabled", recipient)
		}
		return model.InboxFolderID(identity.UserID), identity.UserID, true, nil
	})
}

// enqueueDerived prepares and enqueues derived mail. Forwards and redirects
// keep the original message bytes; mail the server writes itself carries a
// DKIM request and is signed at queue admission, after its queue ID is
// derived from the unsigned content, so replays stay deduplicated.
func (s *server) enqueueDerived(ctx context.Context, derived smtp.DerivedMessage) error {
	msg, err := s.prepareDerived(ctx, derived)
	if err != nil {
		return err
	}
	return s.enqueuePrepared(msg)
}

// enqueuePrepared enqueues a prepared message, ignoring duplicates of
// messages already queued.
func (s *server) enqueuePrepared(msg *smtp.MailMessage) error {
	if err := s.smtpQueueAdapter.Enqueue(msg); err != nil && !errors.Is(err, queue.ErrDuplicate) {
		return err
	}
	return nil
}

func (s *server) ensureMailFolderPath(ctx context.Context, ownerID, path string) (string, error) {
	folder, err := service.EnsureFolderPath(ctx, s.folderSpace, service.UserAccess(ownerID, "system-queue-fileinto"), path, model.FolderTypeMail)
	return folder.ID, err
}

// appendDelivered appends a queued delivery to a local folder exactly once
// and notifies webhook subscribers. IMAP IDLE and NOTIFY sessions learn of it
// from the folder space's commit notification.
func (s *server) appendDelivered(ctx context.Context, queueID, ownerID, folderID, recipient string, data []byte, headers map[string]string) (string, error) {
	access := service.UserAccess(ownerID, "system-queue")
	item, err := service.CreateItemIdempotent(ctx, s.folderSpace, access, folderID, queue.DeliveryExternalIDNamespace, queueID, service.ItemInput{
		Data: data, Headers: headers,
	})
	if err != nil {
		return "", fmt.Errorf("4.3.0 append message: %w", err)
	}
	id := item.ID
	s.met.IncrementCounter("smtp_messages_delivered_total", nil)
	if s.imip != nil {
		s.imip.ProcessDelivered(ctx, ownerID, data)
	}
	if s.appHandler != nil {
		// Open web sessions refresh their folder unread counts and lists, and
		// the owner's desktop notifications name the new message.
		s.appHandler.EventPublisher().Publish(events.Event{Type: "items.delivered", Resource: folderID, Recipients: []string{ownerID}, Data: map[string]any{
			"folder_id": folderID, "item_id": id, "from": deliveredHeader(headers["From"]), "subject": deliveredHeader(headers["Subject"]),
		}})
	}
	scope := model.WebhookScope{Account: ownerID, Recipients: []string{recipient}}
	if webhookErr := s.webhooks.QueueFor("message.received", messageWebhookPayload(ownerID, recipient, folderID, id, data, headers, s.webhooks.Includes("message.received", scope)), scope); webhookErr != nil {
		log.Error("admit message-received webhook", "error", webhookErr, "item_id", id)
	}
	return id, nil
}

// messageWebhookPayload is the message.received payload: a summary, plus the
// optional parts some matching webhook asked for (the dispatcher strips
// them for webhooks that did not).
func messageWebhookPayload(ownerID, recipient, folderID, itemID string, data []byte, headers map[string]string, wanted map[string]bool) map[string]any {
	payload := map[string]any{
		"account_id": ownerID, "recipient": recipient, "folder_id": folderID, "item_id": itemID,
		"from": model.DecodeHeaderValue(headers["From"]), "to": model.DecodeHeaderValue(headers["To"]),
		"cc": model.DecodeHeaderValue(headers["Cc"]), "subject": model.DecodeHeaderValue(headers["Subject"]),
		"date": headers["Date"], "message_id": headers["Message-Id"], "size": len(data),
	}
	if wanted[model.WebhookIncludeHeaders] {
		payload[model.WebhookIncludeHeaders] = model.ParseHeaderValues(data)
	}
	if wanted[model.WebhookIncludeText] || wanted[model.WebhookIncludeHTML] || wanted[model.WebhookIncludeAttachments] {
		if projection, err := service.ProjectMIME(data); err == nil {
			payload[model.WebhookIncludeText] = projection.Text
			payload[model.WebhookIncludeHTML] = projection.HTML
			attachments := make([]map[string]any, 0, len(projection.Attachments))
			for _, attachment := range projection.Attachments {
				attachments = append(attachments, map[string]any{"name": attachment.Name, "content_type": attachment.ContentType, "size": attachment.Size, "inline": attachment.Inline})
			}
			payload[model.WebhookIncludeAttachments] = attachments
		}
	}
	if wanted[model.WebhookIncludeRaw] {
		if len(data) <= webhook.MaxRawMessageBytes {
			payload[model.WebhookIncludeRaw] = base64.StdEncoding.EncodeToString(data)
		} else {
			payload["raw_omitted"] = fmt.Sprintf("message is %d bytes; raw is sent up to %d bytes", len(data), webhook.MaxRawMessageBytes)
		}
	}
	return payload
}

// deliveredHeader decodes and bounds a header for the delivery event.
func deliveredHeader(value string) string {
	if decoded, err := new(mime.WordDecoder).DecodeHeader(value); err == nil {
		value = decoded
	}
	value = strings.Join(strings.Fields(value), " ")
	if runes := []rune(value); len(runes) > 200 {
		value = string(runes[:200])
	}
	return value
}

func (s *server) deliverConfiguredRoute(ctx context.Context, msg *queue.Message, route *model.OutboundRoute) error {
	if route == nil || !route.Enabled {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "selected route is unavailable"}
	}
	host := route.RelayHost
	if route.Transport == model.OutboundTransportMX {
		host = ""
		queue.RecordDeliveryRoute(ctx, "domain-mx:"+route.Domain)
	} else {
		queue.RecordDeliveryRoute(ctx, "domain-relay:"+net.JoinHostPort(route.RelayHost, fmt.Sprint(route.RelayPort)))
	}
	return s.relay(ctx, s.outboundClient(smtp.RelayConfig{Host: host, Port: route.RelayPort, RequireTLS: route.RequireTLS, TLSSkipVerify: route.TLSSkipVerify}), msg)
}

// accountMaintenance defers deliveries while the target account is
// temporarily unavailable.
func accountMaintenance(err error) error {
	if service.IsTemporarilyUnavailable(err) {
		return &queue.DeliveryError{Class: queue.DeliveryDeferred, EnhancedCode: "4.3.2", Response: "account maintenance", RetryAfter: 30 * time.Second, Err: err}
	}
	return err
}

// deliver is the system queue's delivery function: it quarantines, sends
// vacation replies, appends locally, or relays each queued message.
func (s *server) deliver(ctx context.Context, msg *queue.Message) error {
	ts := s.ts
	if msg.Kind == mailKindJournal {
		// Compliance capture is never refused by a full journal mailbox.
		ctx = model.WithQuotaExempt(ctx)
	}
	if msg.Kind == smtp.MailTaskQuarantine {
		queue.RecordDeliveryRoute(ctx, "quarantine")
		data := msg.RawMessage()
		_, err := s.quarantineStore.Add(ctx, &virus.QuarantineEntry{ID: "queued-" + msg.ID, OwnerID: msg.TargetOwnerID, Sender: msg.EnvelopeSender, Recipient: msg.Recipient,
			Subject: msg.Attributes["subject"], Date: msg.Attributes["date"], VirusName: msg.Attributes["virus_name"], Scanner: msg.Attributes["scanner"],
			MessageSize: int64(len(data)), MessageData: data, Headers: msg.Headers, ReasonType: msg.Attributes["reason_type"], Reason: msg.Attributes["reason"],
			AuthenticationResults: msg.Attributes["authentication_results"], ScanTranscript: msg.Attributes["scan_transcript"]})
		if err != nil {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "quarantine storage unavailable", Err: err}
		}
		return nil
	}
	if msg.Kind == smtp.MailTaskVacation {
		queue.RecordDeliveryRoute(ctx, "vacation-reply")
		return s.vacationProcessor.Process(ctx, msg)
	}
	selectedRoute := selectedOutboundRoute(msg)
	if selectedRoute != "" {
		route, err := ts.OutboundRouteStore().Get(ctx, selectedRoute)
		if err != nil {
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "selected outbound route is unavailable", Err: err}
		}
		return s.deliverConfiguredRoute(ctx, msg, &route)
	}
	targetFolderID := msg.TargetFolderID
	if msg.TargetFolderPath != "" {
		if msg.TargetOwnerID == "" {
			return fmt.Errorf("4.3.0 queued fileinto delivery has no target owner")
		}
		resolved, err := s.ensureMailFolderPath(ctx, msg.TargetOwnerID, msg.TargetFolderPath)
		if err != nil {
			if service.IsTemporarilyUnavailable(err) {
				return accountMaintenance(err)
			}
			return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "fileinto folder unavailable", Err: err}
		}
		targetFolderID = resolved
	}
	if targetFolderID != "" {
		queue.RecordDeliveryRoute(ctx, "local-folder")
		if msg.TargetOwnerID == "" {
			return fmt.Errorf("4.3.0 queued local delivery has no target owner")
		}
		data := msg.RawMessage()
		_, err := s.appendDelivered(ctx, msg.ID, msg.TargetOwnerID, targetFolderID, msg.Recipient, data, msg.Headers)
		return accountMaintenance(err)
	}
	queue.RecordDeliveryRoute(ctx, "routing-policy")
	// Locally generated mail (bounces, reports, forwards) addressed to a
	// recipient alias delivers to each of its targets, as SMTP RCPT does.
	if route, err := s.resolveRecipient(ctx, msg.Recipient); err == nil && len(route.Targets) > 0 {
		return s.deliverToAliasTargets(ctx, msg, route.Targets)
	}
	destination, err := service.ClassifyQueueDestination(ctx, msg.Recipient, s.recipientMailbox, ts.DomainStore().Get, ts.OutboundRouteStore().Get)
	if err != nil {
		if errors.Is(err, service.ErrDisabledLocalRecipient) || errors.Is(err, service.ErrUnknownLocalRecipient) || errors.Is(err, service.ErrInvalidQueueRecipient) {
			return &queue.DeliveryError{Class: queue.DeliveryPermanent, EnhancedCode: "5.1.1", Response: "recipient is not deliverable", Err: err}
		}
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "routing policy unavailable", Err: err}
	}
	if destination.Local != nil {
		queue.RecordDeliveryRoute(ctx, "local-account")
		ea := destination.Local
		_, err = s.appendDelivered(ctx, msg.ID, ea.UserID, model.InboxFolderID(ea.UserID), msg.Recipient, msg.RawMessage(), msg.Headers)
		return accountMaintenance(err)
	}
	// Remote recipients: a sender route (with or without a destination)
	// wins over a destination route, then the global relay or direct MX.
	route, routed, err := s.senderRoute(ctx, msg)
	if err != nil {
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, EnhancedCode: "4.3.0", Response: "sender routing unavailable", Err: err}
	}
	if routed {
		return s.deliverSenderRoute(ctx, msg, route)
	}
	if destination.Route != nil {
		return s.deliverConfiguredRoute(ctx, msg, destination.Route)
	}
	return s.deliverOutbound(ctx, msg)
}

// deliverToAliasTargets appends msg to the inbox of every enabled target of
// a recipient alias. Each append is idempotent per target folder, so a
// retry after a partial failure does not duplicate earlier copies.
func (s *server) deliverToAliasTargets(ctx context.Context, msg *queue.Message, targets []string) error {
	queue.RecordDeliveryRoute(ctx, "local-alias")
	data := msg.RawMessage()
	delivered := 0
	for _, target := range targets {
		identity, err := s.ts.UserStore().GetEmailAddress(ctx, target)
		if err != nil || !identity.Enabled {
			continue
		}
		if _, err := s.appendDelivered(ctx, msg.ID, identity.UserID, model.InboxFolderID(identity.UserID), msg.Recipient, data, msg.Headers); err != nil {
			return accountMaintenance(err)
		}
		delivered++
	}
	if delivered == 0 {
		return &queue.DeliveryError{Class: queue.DeliveryPermanent, EnhancedCode: "5.1.1", Response: "recipient alias has no enabled targets"}
	}
	return nil
}

// deliveryStatusNotification builds the DSN returned to the sender of a
// failed (or success-notified) queued message.
func (s *server) deliveryStatusNotification(failed *queue.Message) *queue.Message {
	code := failed.LastCode
	success := failed.Attributes["dsn_notification"] == "success"
	if success {
		code = "2.0.0"
	} else if code == "" || !strings.HasPrefix(code, "5.") {
		code = "5.0.0"
	}
	diagnostic := failed.LastResponse
	if diagnostic == "" {
		diagnostic = failed.LastError
	}
	returnMode := failed.Attributes["dsn_return"]
	if failed.Attributes[smtp.AttributeRequireTLS] == "true" {
		returnMode = "hdrs"
	}
	from := "" // MAILER-DAEMON at the server name
	if domain := s.systemMailDomain(); domain != "" {
		from = "Mail Delivery System <MAILER-DAEMON@" + domain + ">"
	}
	content := smtp.GenerateDSN(smtp.DSNRequest{
		From:              from,
		EnvelopeSender:    failed.EnvelopeSender,
		Recipient:         failed.Recipient,
		OriginalMessageID: failed.Headers["Message-ID"],
		OriginalHeaders:   failed.Headers,
		Status:            smtp.DSNStatus{Code: code, Success: success, Message: diagnostic},
		DiagnosticCode:    diagnostic,
		ServerName:        s.smtpServerName(),
		EnvelopeID:        failed.Attributes["dsn_envelope_id"],
		OriginalRecipient: failed.Attributes["dsn_original_recipient"],
		ReturnMode:        returnMode,
		OriginalContent:   failed.Content,
		OriginalBody:      failed.Body,
	})
	attributes := make(map[string]string)
	for _, attribute := range []string{smtp.AttributeRequireTLS, smtp.AttributeTLSOptional} {
		if value := failed.Attributes[attribute]; value != "" {
			attributes[attribute] = value
		}
	}
	// The notification is routed like any outbound message, from its headers
	// and body, and is signed for the system mail domain when it is hosted.
	headers, body := model.ParseMessageHeaders(content)
	return &queue.Message{EnvelopeSender: "", Recipient: failed.EnvelopeSender, Headers: headers, Body: body, Attributes: attributes, DKIM: &dkim.Request{}}
}

// observeQueueEvent records queue events in message trace and metrics.
func (s *server) observeQueueEvent(observerCtx context.Context, event queue.Event) {
	messageID, subject := "", ""
	var retryAt *time.Time
	if !event.RetryAt.IsZero() {
		value := event.RetryAt.UTC()
		retryAt = &value
	}
	for name, value := range event.Message.Headers {
		switch {
		case strings.EqualFold(name, "Message-ID"):
			messageID = value
		case strings.EqualFold(name, "Subject"):
			subject = value
		}
	}
	base := messagetrace.Record{
		QueueID: event.Message.ID, CorrelationID: event.Message.CorrelationID,
		ParentID: event.Message.ParentID, Kind: event.Message.Kind,
		Direction: string(event.Message.Direction), EnvelopeSender: event.Message.EnvelopeSender,
		Recipient: event.Message.Recipient, MessageID: messageID, Subject: subject, ScanSummary: event.Message.Attributes["scan_summary"], TransportSecurity: queueTransportSecurity(event.Message.Attributes), Policy: event.Message.Policy.Clone(),
	}
	traceEvent := messagetrace.Event{
		Time: event.Time, Stage: event.Stage, Status: string(event.Status),
		Attempt: event.Attempt, Code: event.Code, Response: event.Response,
		Destination: event.Destination, Route: event.Route, OutcomeClass: event.OutcomeClass, TLSPolicy: event.TLSPolicy,
		DurationMillis: event.DurationMillis, RetryAt: retryAt, PossibleDuplicate: event.PossibleDuplicate,
	}
	if traceErr := s.messageTrace.Record(observerCtx, base, traceEvent); traceErr != nil {
		log.Error("record message trace", "queue_id", event.Message.ID, "error", traceErr)
	}
	if s.sendGuard != nil && (event.Stage == "completed" || event.Stage == "delivery") {
		s.sendGuard.RecordOutcome(observerCtx, event.Message, event.Status)
	}
	s.met.IncrementCounter("mail_queue_events_total", map[string]string{
		"stage": event.Stage, "status": string(event.Status), "direction": string(event.Message.Direction),
	})
}
