package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
)

// maxMDNOriginalHeaderBytes bounds the text/rfc822-headers part.
const maxMDNOriginalHeaderBytes = 16 << 10

// ErrNoReceiptRequested reports a message without a usable
// Disposition-Notification-To request.
var ErrNoReceiptRequested = errors.New("the message does not request a read receipt")

// DispositionNotification is a built RFC 8098 message disposition
// notification ready to queue.
type DispositionNotification struct {
	Recipient string
	Headers   map[string]string
	Body      []byte
}

// BuildDispositionNotification answers original's Disposition-Notification-To
// request with a "displayed" MDN sent manually by finalRecipient. It never
// answers another MDN and addresses only the first requested address.
func BuildDispositionNotification(original []byte, finalRecipient, reportingHost string, now time.Time, messageID string) (DispositionNotification, error) {
	message, err := mail.ReadMessage(bytes.NewReader(original))
	if err != nil {
		return DispositionNotification{}, fmt.Errorf("parse original message: %w", err)
	}
	requested, err := mail.ParseAddressList(message.Header.Get("Disposition-Notification-To"))
	if err != nil || len(requested) == 0 {
		return DispositionNotification{}, ErrNoReceiptRequested
	}
	if mediaType, params, _ := mime.ParseMediaType(message.Header.Get("Content-Type")); mediaType == "multipart/report" && strings.EqualFold(params["report-type"], "disposition-notification") {
		return DispositionNotification{}, errors.New("read receipts are never sent for read receipts")
	}
	subject := sanitizeHeader(model.DecodeHeaderValue(message.Header.Get("Subject")))
	recipient := strings.ToLower(requested[0].Address)
	originalID := strings.TrimSpace(message.Header.Get("Message-ID"))
	reportingHost = sanitizeHeader(reportingHost)
	if reportingHost == "" {
		reportingHost = "localhost"
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	human := make(textproto.MIMEHeader)
	human.Set("Content-Type", "text/plain; charset=utf-8")
	human.Set("Content-Transfer-Encoding", "8bit")
	part, err := writer.CreatePart(human)
	if err != nil {
		return DispositionNotification{}, err
	}
	fmt.Fprintf(part, "This is a read receipt for the message sent to %s with the subject \"%s\".\r\n\r\nIt confirms only that the message was displayed; there is no guarantee that it was read or understood.\r\n", finalRecipient, subject)
	machine := make(textproto.MIMEHeader)
	machine.Set("Content-Type", "message/disposition-notification")
	machine.Set("Content-Transfer-Encoding", "7bit")
	part, err = writer.CreatePart(machine)
	if err != nil {
		return DispositionNotification{}, err
	}
	fmt.Fprintf(part, "Reporting-UA: %s; Veksel\r\n", reportingHost)
	if originalRecipient := sanitizeHeader(message.Header.Get("Original-Recipient")); originalRecipient != "" {
		fmt.Fprintf(part, "Original-Recipient: %s\r\n", originalRecipient)
	}
	fmt.Fprintf(part, "Final-Recipient: rfc822;%s\r\n", finalRecipient)
	if originalID != "" {
		fmt.Fprintf(part, "Original-Message-ID: %s\r\n", sanitizeHeader(originalID))
	}
	fmt.Fprint(part, "Disposition: manual-action/MDN-sent-manually; displayed\r\n")
	headerBlock, _, _ := bytes.Cut(original, []byte("\r\n\r\n"))
	if len(headerBlock) == len(original) {
		headerBlock, _, _ = bytes.Cut(original, []byte("\n\n"))
	}
	if len(headerBlock) <= maxMDNOriginalHeaderBytes {
		headers := make(textproto.MIMEHeader)
		headers.Set("Content-Type", "text/rfc822-headers")
		part, err = writer.CreatePart(headers)
		if err != nil {
			return DispositionNotification{}, err
		}
		_, _ = part.Write(headerBlock)
		_, _ = io.WriteString(part, "\r\n")
	}
	if err := writer.Close(); err != nil {
		return DispositionNotification{}, err
	}
	headers := map[string]string{
		"From":           (&mail.Address{Address: finalRecipient}).String(),
		"To":             (&mail.Address{Address: recipient}).String(),
		"Subject":        mime.QEncoding.Encode("utf-8", "Read: "+subject),
		"Message-ID":     messageID,
		"Date":           now.UTC().Format(time.RFC1123Z),
		"MIME-Version":   "1.0",
		"Auto-Submitted": "auto-replied",
		"Content-Type":   mime.FormatMediaType("multipart/report", map[string]string{"report-type": "disposition-notification", "boundary": writer.Boundary()}),
	}
	if originalID != "" {
		headers["In-Reply-To"], headers["References"] = sanitizeHeader(originalID), sanitizeHeader(originalID)
	}
	return DispositionNotification{Recipient: recipient, Headers: headers, Body: body.Bytes()}, nil
}

// SendDispositionNotification queues a manually confirmed read receipt for
// original, sent from the actor's identity that received it (else their
// primary identity). It returns the receipt recipient.
func (s *Mail) SendDispositionNotification(ctx context.Context, actor model.PrincipalRef, original []byte) (string, error) {
	if s.queue == nil {
		return "", fmt.Errorf("mail queue is unavailable")
	}
	identity, err := s.receivingIdentity(ctx, actor.ID, original)
	if err != nil {
		return "", err
	}
	id, err := submissionID()
	if err != nil {
		return "", err
	}
	domain := identity[strings.LastIndexByte(identity, '@')+1:]
	notification, err := BuildDispositionNotification(original, identity, domain, time.Now(), fmt.Sprintf("<mdn-%s@%s>", id, mailidentity.MessageIDDomain(identity, "")))
	if err != nil {
		return "", err
	}
	message := &queue.Message{ID: "mdn-" + id, Direction: queue.DirectionOutbound, EnvelopeSender: identity, Recipient: notification.Recipient,
		Headers: notification.Headers, Body: notification.Body, Status: queue.StatusPending, CreatedAt: time.Now().UTC(),
		CorrelationID: id, AuthenticatedActor: actor.ID, DKIM: &dkim.Request{}}
	if err := s.queue.EnqueueBatch([]*queue.Message{message}); err != nil {
		return "", fmt.Errorf("enqueue read receipt: %w", err)
	}
	s.audit.Log(actor.ID, "mail.mdn.send", identity, map[string]string{"recipient": notification.Recipient, "submission_id": id})
	return notification.Recipient, nil
}

// receivingIdentity picks the actor's enabled identity addressed by original,
// falling back to the primary identity.
func (s *Mail) receivingIdentity(ctx context.Context, userID string, original []byte) (string, error) {
	identities, err := s.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if message, parseErr := mail.ReadMessage(bytes.NewReader(original)); parseErr == nil {
		for _, field := range []string{"To", "Cc"} {
			addresses, _ := mail.ParseAddressList(message.Header.Get(field))
			for _, address := range addresses {
				for _, identity := range identities {
					if identity.Enabled && strings.EqualFold(identity.ID, address.Address) {
						return identity.ID, nil
					}
				}
			}
		}
	}
	return s.primaryIdentity(ctx, userID)
}
