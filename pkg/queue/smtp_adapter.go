// Package queue provides an adapter for the SMTP delivery queue.
package queue

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// SMTPAdapter implements smtp.MailQueue using the internal Queue.
type SMTPAdapter struct {
	q  *Queue
	id atomic.Uint64
}

// NewSMTPAdapter creates an smtp.MailQueue adapter from a Queue.
func NewSMTPAdapter(q *Queue) *SMTPAdapter {
	return &SMTPAdapter{q: q}
}

// Enqueue implements smtp.MailQueue.
func (a *SMTPAdapter) Enqueue(msg *smtp.MailMessage) error {
	return a.EnqueueBatch([]*smtp.MailMessage{msg})
}

// EnqueueBatch converts an SMTP transaction into one atomic queue batch.
func (a *SMTPAdapter) EnqueueBatch(messages []*smtp.MailMessage) error {
	queued := make([]*Message, 0, len(messages))
	for _, msg := range messages {
		if msg == nil {
			return fmt.Errorf("nil SMTP queue message")
		}
		id := msg.ID
		if id == "" {
			id = fmt.Sprintf("smtp-%d-%d", time.Now().UnixNano(), a.id.Add(1))
		}
		direction := DirectionInbound
		if msg.Outbound {
			direction = DirectionOutbound
		}
		status := StatusPending
		if msg.Held {
			status = StatusPaused
		}
		qMsg := &Message{
			ID:                 id,
			Kind:               msg.Kind,
			Attributes:         cloneHeaders(msg.Attributes),
			CorrelationID:      msg.CorrelationID,
			ParentID:           msg.ParentID,
			Direction:          direction,
			EnvelopeSender:     msg.EnvelopeSender,
			Recipient:          msg.Recipient,
			Headers:            cloneHeaders(msg.Headers),
			Body:               append([]byte(nil), msg.Body...),
			Content:            append([]byte(nil), msg.Content...),
			TargetFolderID:     msg.TargetFolderID,
			TargetFolderPath:   msg.TargetFolderPath,
			TargetOwnerID:      msg.TargetOwnerID,
			Status:             status,
			CreatedAt:          time.Now().UTC(),
			NextRetry:          time.Now().UTC(),
			Policy:             msg.Policy.Clone(),
			PolicyRoute:        msg.PolicyRoute,
			AuthenticatedActor: msg.AuthenticatedActor,
			SourceIP:           msg.SourceIP,
			DKIM:               msg.DKIM,
		}
		// The RFC 8689 header is also meaningful for web, JMAP, EWS, and
		// other submission paths that enter through this shared adapter rather
		// than an SMTP MAIL command. An explicit REQUIRETLS envelope tag wins.
		if qMsg.Attributes[smtp.AttributeRequireTLS] != "true" && tlsRequiredNo(qMsg.Headers) {
			qMsg.Attributes[smtp.AttributeTLSOptional] = "true"
		}
		queued = append(queued, qMsg)
	}
	return a.q.EnqueueBatch(queued)
}

func tlsRequiredNo(headers map[string]string) bool {
	for name, value := range headers {
		if strings.EqualFold(name, "TLS-Required") {
			return strings.EqualFold(strings.TrimSpace(value), "No")
		}
	}
	return false
}

func cloneHeaders(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

// NewWithDelivery creates a Queue with a delivery function that uses
// the provided delivery callbacks.
func NewWithDelivery(deliver func(ctx context.Context, msg *Message) error, maxSize int) *Queue {
	return New(&Config{
		MaxSize:  maxSize,
		Delivery: deliver,
	})
}

// BuildDeliveryFunc creates a DeliveryFunc from the SMTP Delivery callbacks.
func BuildDeliveryFunc(resolveRecipient func(ctx context.Context, addr string) (folderID string, userID string, err error),
	appendMessage func(ctx context.Context, folderID string, data []byte, headers map[string]string) (itemID string, err error),
	notifyIMAPIdle func(folderID string)) DeliveryFunc {

	return func(ctx context.Context, msg *Message) error {
		// Reconstruct full message
		fullMsg := msg.RawMessage()

		folderID, _, err := resolveRecipient(ctx, msg.Recipient)
		if err != nil {
			return fmt.Errorf("4.7.1 resolve recipient: %w", err)
		}

		_, err = appendMessage(ctx, folderID, fullMsg, msg.Headers)
		if err != nil {
			return fmt.Errorf("4.7.2 append message: %w", err)
		}

		if notifyIMAPIdle != nil {
			notifyIMAPIdle(folderID)
		}

		logger.Info("queue: message delivered on retry", "id", msg.ID, "recipient", msg.Recipient)
		return nil
	}
}

// BuildMessage reconstructs an RFC 5322 message from headers and body.
func BuildMessage(headers map[string]string, body []byte) []byte {
	return model.BuildMessage(headers, body)
}
