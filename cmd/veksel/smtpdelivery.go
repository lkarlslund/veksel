package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/virus"
)

// smtpDelivery wires the SMTP servers to recipient resolution, the durable
// queue, Sieve, spam and content scanning, forwarding, vacation replies, DKIM
// signing, and relay policy.
func (s *server) smtpDelivery() *smtp.Delivery {
	ts := s.ts
	return &smtp.Delivery{
		RecordRecentRecipients: s.recipientHistory.Record,
		AuthorizeSubmission:    s.exchangeMail.AuthorizeSMTPSubmission,
		IsLocalDomain:          s.isHostedDomain,
		ResolveRecipient:       s.resolveLocalAddress,
		RouteUnknownRecipient:  s.routeUnknownRecipient,
		TrustedDomainRelay:     s.trustedDomainRelay,
		ExpandRecipient:        s.expandRecipient,
		IsSpamtrap:             s.isSpamtrap,
		RecordSpamtrap:         s.recordSpamtrap,
		ResolveSender:          s.resolveLocalAddress,
		RewriteForwardSender:   s.rewriteForwardSender,
		ReverseSRS:             s.reverseSRS,
		CheckReturnPath:        s.checkReturnPath,
		RewriteRecipient:       s.rewriteRecipient,
		RecipientDelimiters:    func() string { return s.addressing().delimiters },
		AppendFolderItem: func(ctx context.Context, userID, folderID string, data []byte, headers map[string]string) (string, error) {
			msg := &queue.Message{Direction: queue.DirectionInbound, Headers: headers,
				Content: data, TargetFolderID: folderID, TargetOwnerID: userID, Status: queue.StatusPending}
			if err := s.mailQueue.Enqueue(msg); err != nil {
				return "", fmt.Errorf("persist inbound delivery: %w", err)
			}
			return msg.ID, nil
		},
		// The queue worker notifies IMAP only after the item append commits.
		NotifyIMAPIdle: nil,
		GetSieveScript: func(ctx context.Context, userID string) (string, bool, error) {
			return s.sieveScripts.Active(ctx, userID)
		},
		KnownCorrespondent: s.knownCorrespondent,
		GetSpamConfig:      ts.UserStore().GetSpamConfig,
		GetSpamWhitelist:   ts.UserStore().ReadSpamWhitelist,
		GetSpamBlacklist:   ts.UserStore().ReadSpamBlacklist,
		GetJunkFolderID: func(ctx context.Context, userID string) (string, error) {
			folderID := model.JunkFolderID(userID)
			if _, err := ts.FolderStore().Get(ctx, folderID); err != nil {
				return "", err
			}
			return folderID, nil
		},
		GetVirusScanEnabled: s.delivery.virusScanEnabled.Load,
		GetVirusScanEnabledForDomain: func(ctx context.Context, domainID string) (bool, error) {
			domain, err := ts.DomainStore().Get(ctx, domainID)
			if err != nil {
				return false, err
			}
			return domain.VirusScanEnabled, nil
		},
		ContentScan: s.delivery.scanning.Scan,
		QuarantineMessage: func(ctx context.Context, sender, recipient, subject string, headers map[string]string, body []byte, virusName string) (string, error) {
			return s.quarantineStore.Add(ctx, &virus.QuarantineEntry{Sender: sender, Recipient: recipient, Subject: subject,
				Date: time.Now().UTC().Format(time.RFC3339), VirusName: virusName, Scanner: "smtp", MessageSize: int64(len(body)), MessageData: body, Headers: headers})
		},
		GetFolderIDByPath: func(ctx context.Context, userID, path string) (string, error) {
			f, err := s.folderSpace.GetFolderByPath(ctx, service.UserAccess(userID, "smtp-sieve"), path)
			if err != nil {
				return "", err
			}
			return f.ID, nil
		},
		CreateFolder: func(ctx context.Context, userID, path string, folderType string, parentID string) error {
			_, err := s.ensureMailFolderPath(ctx, userID, path)
			return err
		},
		// Mail forwarding
		ResolveForwardTo: func(ctx context.Context, userID string) (string, error) {
			u, err := ts.UserStore().Get(ctx, userID)
			if err != nil {
				return "", err
			}
			return u.ForwardTo, nil
		},
		SendForward: func(ctx context.Context, toAddr string, fullMsg []byte) error {
			return s.enqueueDerived(ctx, smtp.DerivedMessage{Kind: "legacy", Recipient: toAddr, FullMessage: fullMsg})
		},
		SendDerived:    s.enqueueDerived,
		PrepareDerived: s.prepareDerived,
		// Vacation auto-reply
		VacationActive: func(ctx context.Context, userID string) bool {
			u, err := ts.UserStore().Get(ctx, userID)
			if err != nil {
				return false
			}
			return u.VacationActive()
		},
		VacationReply: func(ctx context.Context, userID string) (string, string) {
			u, err := ts.UserStore().Get(ctx, userID)
			if err != nil {
				return "", ""
			}
			return u.VacationSubject, u.VacationMessage
		},
		ResolveVacation: func(ctx context.Context, userID string) (bool, string, string, error) {
			u, err := ts.UserStore().Get(ctx, userID)
			if err != nil {
				return false, "", "", err
			}
			return u.VacationActive(), u.VacationSubject, u.VacationMessage, nil
		},
		ShouldVacationReply: func(ctx context.Context, userID, sender string) bool {
			return ts.UserStore().ShouldVacationReply(ctx, userID, sender)
		},
		RecordVacationReply: func(ctx context.Context, userID, sender string) error {
			return ts.UserStore().RecordVacationReply(ctx, userID, sender)
		},
		ReserveVacationReply:  ts.UserStore().ReserveVacationReply,
		CompleteVacationReply: ts.UserStore().CompleteVacationReply,
		CancelVacationReply:   ts.UserStore().CancelVacationReply,
		// Mail queue for retrying failed deliveries
		MailQueue: s.smtpQueueAdapter,
		CanRelayRecipient: func(ctx context.Context, recipient string) bool {
			if s.delivery.outbound.Load().relays() {
				return true
			}
			at := strings.LastIndex(recipient, "@")
			if at < 0 {
				return false
			}
			route, err := ts.OutboundRouteStore().Get(ctx, recipient[at+1:])
			return err == nil && route.Enabled || s.senderRouteRelays(ctx, recipient)
		},
	}
}
