package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
)

var mailLogger = log.For(log.ModuleSMTP)

// MailQueue accepts one delivery job per envelope recipient.
type MailQueue interface {
	EnqueueBatch([]*queue.Message) error
}

// IdempotentMailQueue atomically remembers a stable delivery batch after its
// message payloads are accepted.
type IdempotentMailQueue interface {
	MailQueue
	EnqueueBatchIdempotent(string, []*queue.Message) error
}

// SendMode controls delegated identity header semantics.
type SendMode string

const (
	SendNormal   SendMode = "normal"
	SendAs       SendMode = "send_as"
	SendOnBehalf SendMode = "send_on_behalf"
)

// Submission is a validated outbound message request.
type Submission struct {
	From       string         `json:"from"`
	Mode       SendMode       `json:"mode"`
	Importance MailImportance `json:"importance,omitempty"`
	RequireTLS bool           `json:"require_tls,omitempty"`
	To         []string       `json:"to"`
	CC         []string       `json:"cc,omitempty"`
	BCC        []string       `json:"bcc,omitempty"`
	Subject    string         `json:"subject"`
	Body       string         `json:"body"`
	// HTML, when set, makes the message multipart/alternative; Body is then
	// regenerated from the sanitized HTML.
	HTML string `json:"html,omitempty"`
	// ReadReceipt requests a message disposition notification (RFC 8098).
	ReadReceipt bool                   `json:"read_receipt,omitempty"`
	Attachments []SubmissionAttachment `json:"attachments,omitempty"`
}

// SubmissionAttachment is one MIME attachment supplied by an API client.
type SubmissionAttachment struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size,omitempty"`
	// ContentID marks an inline image referenced as cid:<ContentID> by HTML.
	ContentID string `json:"content_id,omitempty"`
	Data      []byte `json:"data"`
}

// SubmissionResult identifies an accepted submission and its Sent copy.
type SubmissionResult struct {
	ID         string    `json:"id"`
	SentItemID string    `json:"sent_item_id"`
	Recipients []string  `json:"recipients"`
	AcceptedAt time.Time `json:"accepted_at"`
}

// Mail submits authorized outbound messages and records Sent copies.
type Mail struct {
	users        *model.UserStore
	aliases      *model.UserAliasStore
	space        FolderSpace
	authorizer   *authz.Engine
	queue        MailQueue
	audit        *audit.Logger
	events       events.Publisher
	history      *RecipientHistory
	idempotentMu sync.Mutex
}

func (s *Mail) SetEventPublisher(publisher events.Publisher) { s.events = publisher }

func NewMail(ts *model.TypedStore, authorizer *authz.Engine, mailQueue MailQueue) *Mail {
	return NewMailWithFolderSpace(ts, authorizer, mailQueue, NewFolderSpace(ts, authorizer))
}

func NewMailWithFolderSpace(ts *model.TypedStore, authorizer *authz.Engine, mailQueue MailQueue, space FolderSpace) *Mail {
	return &Mail{users: ts.UserStore(), aliases: ts.UserAliasStore(), space: space, authorizer: authorizer, queue: mailQueue, audit: audit.New(ts), history: NewRecipientHistory(space)}
}

func (s *Mail) SetRecipientHistory(history *RecipientHistory) { s.history = history }

// Submit validates identity delegation, enqueues every recipient, and appends
// the accepted message to the identity owner's Sent folder.
func (s *Mail) Submit(ctx context.Context, actor model.PrincipalRef, request Submission) (SubmissionResult, error) {
	return s.submit(ctx, actor, request, "")
}

// SubmitIdempotent submits one stable logical message once. It is used by
// durable schedulers that may replay work after losing an acknowledgement.
func (s *Mail) SubmitIdempotent(ctx context.Context, actor model.PrincipalRef, request Submission, idempotencyKey string) (SubmissionResult, error) {
	if strings.TrimSpace(idempotencyKey) == "" || len(idempotencyKey) > 256 {
		return SubmissionResult{}, errors.New("mail idempotency key must contain 1-256 characters")
	}
	if _, ok := s.queue.(IdempotentMailQueue); !ok {
		return SubmissionResult{}, errors.New("mail queue does not support idempotent submissions")
	}
	s.idempotentMu.Lock()
	defer s.idempotentMu.Unlock()
	return s.submit(ctx, actor, request, idempotencyKey)
}

func (s *Mail) submit(ctx context.Context, actor model.PrincipalRef, request Submission, idempotencyKey string) (SubmissionResult, error) {
	if s.queue == nil {
		return SubmissionResult{}, fmt.Errorf("mail queue is unavailable")
	}
	importance, err := NormalizeMailImportance(request.Importance)
	if err != nil {
		return SubmissionResult{}, err
	}
	request.Importance = importance
	identity, err := s.sendingIdentity(ctx, strings.ToLower(strings.TrimSpace(request.From)))
	if err != nil || !identity.Enabled {
		return SubmissionResult{}, fmt.Errorf("sending identity is unavailable")
	}
	if err := s.authorizeIdentity(ctx, actor, identity, request.Mode); err != nil {
		return SubmissionResult{}, err
	}
	recipients, toHeader, ccHeader, err := parseRecipients(request.To, request.CC, request.BCC)
	if err != nil {
		return SubmissionResult{}, err
	}
	if len(recipients) == 0 {
		return SubmissionResult{}, fmt.Errorf("at least one recipient is required")
	}
	subject := sanitizeHeader(request.Subject)
	if strings.TrimSpace(request.Body) == "" && strings.TrimSpace(request.HTML) == "" && len(request.Attachments) == 0 {
		return SubmissionResult{}, fmt.Errorf("body or an attachment is required")
	}
	now := time.Now().UTC()
	var existingSent *model.Item
	if idempotencyKey != "" {
		sent, folderErr := s.space.GetFolderByPath(ctx, UserAccess(actor.ID, "mail-submission"), "Sent")
		if folderErr != nil {
			return SubmissionResult{}, fmt.Errorf("resolve Sent folder: %w", folderErr)
		}
		existing, findErr := s.space.GetItemByExternalID(ctx, UserAccess(actor.ID, "mail-submission"), sent.ID, "veksel.mail-submission", idempotencyKey)
		if findErr == nil {
			existingSent = &existing
			if !existing.InternalDate.IsZero() {
				now = existing.InternalDate.UTC()
			}
		} else if !errors.Is(findErr, store.ErrNotFound) {
			return SubmissionResult{}, fmt.Errorf("resolve prior Sent copy: %w", findErr)
		}
	}
	var submissionIDValue string
	if idempotencyKey == "" {
		submissionIDValue, err = submissionID()
		if err != nil {
			return SubmissionResult{}, err
		}
	} else {
		digest := sha256.Sum256([]byte(idempotencyKey))
		submissionIDValue = "stable-" + hex.EncodeToString(digest[:16])
	}
	contentType, messageBody, err := BuildSubmissionMIME(request.Body, request.HTML, request.Attachments)
	if err != nil {
		return SubmissionResult{}, err
	}
	headers := map[string]string{
		"From":         s.namedAddress(ctx, identity.UserID, identity.ID),
		"To":           toHeader,
		"Subject":      subject,
		"Message-ID":   fmt.Sprintf("<%s@%s>", submissionIDValue, mailidentity.MessageIDDomain(identity.ID, "")),
		"Date":         now.Format(time.RFC1123Z),
		"MIME-Version": "1.0",
		"Content-Type": contentType,
	}
	if ccHeader != "" {
		headers["Cc"] = ccHeader
	}
	if request.ReadReceipt {
		headers["Disposition-Notification-To"] = headers["From"]
	}
	SetMailImportanceHeaders(headers, request.Importance)
	if request.Mode == SendOnBehalf {
		delegateAddress, err := s.primaryIdentity(ctx, actor.ID)
		if err != nil {
			return SubmissionResult{}, fmt.Errorf("resolve delegate identity: %w", err)
		}
		headers["Sender"] = s.namedAddress(ctx, actor.ID, delegateAddress)
	}
	messages := make([]*queue.Message, 0, len(recipients))
	for index, recipient := range recipients {
		messageHeaders := cloneHeaders(headers)
		var attributes map[string]string
		if request.RequireTLS {
			attributes = map[string]string{smtp.AttributeRequireTLS: "true"}
		}
		messages = append(messages, &queue.Message{
			ID:             fmt.Sprintf("web-%s-%d", submissionIDValue, index+1),
			Direction:      queue.DirectionOutbound,
			EnvelopeSender: identity.ID, Recipient: recipient,
			Headers: messageHeaders, Body: messageBody, Attributes: attributes, Status: queue.StatusPending,
			CreatedAt: now, CorrelationID: submissionIDValue, AuthenticatedActor: actor.ID, DKIM: &dkim.Request{},
		})
	}
	raw := buildMessageBytes(headers, messageBody)
	sentItemID, sentCreated := "", false
	if existingSent != nil {
		sentItemID = existingSent.ID
	} else {
		externalIDs := map[string]string(nil)
		if idempotencyKey != "" {
			externalIDs = map[string]string{"veksel.mail-submission": idempotencyKey}
		}
		sentItemID, err = s.storeSent(ctx, actor, raw, headers, externalIDs)
		if err != nil {
			return SubmissionResult{}, fmt.Errorf("append Sent copy: %w", err)
		}
		sentCreated = true
	}
	if idempotencyKey == "" {
		err = s.queue.EnqueueBatch(messages)
	} else {
		err = s.queue.(IdempotentMailQueue).EnqueueBatchIdempotent(idempotencyKey, messages)
	}
	if err != nil {
		if !sentCreated {
			return SubmissionResult{}, fmt.Errorf("enqueue submission: %w", err)
		}
		if rollbackErr := s.space.DeleteItem(ctx, UserAccess(actor.ID, "submission-rollback"), sentItemID); rollbackErr != nil {
			return SubmissionResult{}, fmt.Errorf("enqueue submission: %v (Sent rollback failed: %w)", err, rollbackErr)
		}
		return SubmissionResult{}, fmt.Errorf("enqueue submission: %w", err)
	}
	s.audit.Log(actor.ID, "mail.submit", identity.ID, map[string]string{
		"mode": string(request.Mode), "submission_id": submissionIDValue,
		"recipient_count": fmt.Sprintf("%d", len(recipients)), "sent_item_id": sentItemID,
		"require_tls": strconv.FormatBool(request.RequireTLS),
	})
	if s.events != nil {
		s.events.Publish(events.Event{ID: submissionIDValue, Type: "mail.submitted", Resource: identity.ID,
			Data:       map[string]any{"sent_item_id": sentItemID, "recipient_count": len(recipients)},
			Recipients: []string{actor.ID, identity.UserID}})
	}
	s.recordRecipients(ctx, actor.ID, append(append(append([]string{}, request.To...), request.CC...), request.BCC...))
	return SubmissionResult{ID: submissionIDValue, SentItemID: sentItemID, Recipients: recipients, AcceptedAt: now}, nil
}

// RawSubmissionOptions adjusts SubmitRawWithOptions.
type RawSubmissionOptions struct {
	// Recipients, when set, replaces the envelope recipients otherwise taken
	// from To, Cc and Bcc (a JMAP EmailSubmission envelope).
	Recipients []string
	// SkipSentCopy leaves filing the sent message to the caller, as JMAP
	// clients do with onSuccessUpdateEmail.
	SkipSentCopy bool
}

// SubmitRaw accepts an RFC 5322 MIME message without flattening attachments or
// alternative bodies. It is used by EWS and EAS submission adapters.
func (s *Mail) SubmitRaw(ctx context.Context, actor model.PrincipalRef, raw []byte) (SubmissionResult, error) {
	return s.SubmitRawWithOptions(ctx, actor, raw, RawSubmissionOptions{})
}

// SubmitRawWithOptions is SubmitRaw with an explicit envelope and Sent copy
// policy.
func (s *Mail) SubmitRawWithOptions(ctx context.Context, actor model.PrincipalRef, raw []byte, options RawSubmissionOptions) (SubmissionResult, error) {
	if s.queue == nil {
		return SubmissionResult{}, fmt.Errorf("mail queue is unavailable")
	}
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return SubmissionResult{}, fmt.Errorf("parse MIME message: %w", err)
	}
	// RFC 5322 3.6: exactly one From and at most one Sender, so the identity
	// authorized here is the one every recipient's client shows.
	if len(message.Header["From"]) != 1 || len(message.Header["Sender"]) > 1 {
		return SubmissionResult{}, fmt.Errorf("message must have exactly one From and at most one Sender header field")
	}
	from, err := mail.ParseAddress(message.Header.Get("From"))
	if err != nil {
		return SubmissionResult{}, fmt.Errorf("invalid From address: %w", err)
	}
	identity, err := s.sendingIdentity(ctx, strings.ToLower(from.Address))
	if err != nil || !identity.Enabled {
		return SubmissionResult{}, fmt.Errorf("sending identity is unavailable")
	}
	if err := s.authorizeIdentity(ctx, actor, identity, SendNormal); err != nil {
		return SubmissionResult{}, err
	}
	values := func(name string) []string {
		if value := message.Header.Get(name); value != "" {
			return []string{value}
		}
		return nil
	}
	recipientValues := append(append(values("To"), values("Cc")...), values("Bcc")...)
	recipients, _, _, err := parseRecipients(values("To"), values("Cc"), values("Bcc"))
	if len(options.Recipients) > 0 {
		recipients, _, _, err = parseRecipients(options.Recipients, nil, nil)
	}
	if err != nil || len(recipients) == 0 {
		return SubmissionResult{}, fmt.Errorf("at least one valid recipient is required")
	}
	body, err := io.ReadAll(message.Body)
	if err != nil {
		return SubmissionResult{}, err
	}
	headers := make(map[string]string, len(message.Header))
	for key := range message.Header {
		if !strings.EqualFold(key, "Bcc") {
			headers[key] = message.Header.Get(key)
		}
	}
	now := time.Now().UTC()
	id, err := submissionID()
	if err != nil {
		return SubmissionResult{}, err
	}
	queued := make([]*queue.Message, 0, len(recipients))
	for index, recipient := range recipients {
		queued = append(queued, &queue.Message{ID: fmt.Sprintf("exchange-%s-%d", id, index+1), Direction: queue.DirectionOutbound,
			EnvelopeSender: identity.ID, Recipient: recipient, Headers: cloneHeaders(headers), Body: body, AuthenticatedActor: actor.ID,
			Status: queue.StatusPending, CreatedAt: now, DKIM: &dkim.Request{}})
	}
	sentItemID := ""
	if !options.SkipSentCopy {
		sentItemID, err = s.storeSent(ctx, actor, raw, headers, nil)
		if err != nil {
			return SubmissionResult{}, err
		}
	}
	if err := s.queue.EnqueueBatch(queued); err != nil {
		if sentItemID != "" {
			_ = s.space.DeleteItem(ctx, UserAccess(actor.ID, "submission-rollback"), sentItemID)
		}
		return SubmissionResult{}, fmt.Errorf("enqueue submission: %w", err)
	}
	s.recordRecipients(ctx, actor.ID, recipientValues)
	return SubmissionResult{ID: id, SentItemID: sentItemID, Recipients: recipients, AcceptedAt: now}, nil
}

func (s *Mail) recordRecipients(ctx context.Context, userID string, values []string) {
	if s.history == nil {
		return
	}
	if err := s.history.Record(ctx, userID, values); err != nil {
		mailLogger.Warn("record recent recipients", "user", userID, "error", err)
	}
}

func (s *Mail) storeSent(ctx context.Context, actor model.PrincipalRef, raw []byte, headers map[string]string, externalIDs map[string]string) (string, error) {
	access := UserAccess(actor.ID, "mail-submission")
	sent, err := s.space.GetFolderByPath(ctx, access, "Sent")
	if err != nil {
		return "", fmt.Errorf("resolve Sent folder: %w", err)
	}
	item, err := s.space.CreateItem(ctx, access, sent.ID, ItemInput{Data: raw, Headers: headers, ExternalIDs: externalIDs})
	if err != nil {
		return "", fmt.Errorf("append Sent copy: %w", err)
	}
	return item.ID, nil
}

// sendingIdentity resolves a From, Sender, or envelope address to the
// identity that may send as it: an email identity, or an active temporary
// alias acting as its owner's identity. Delegation never applies to aliases.
func (s *Mail) sendingIdentity(ctx context.Context, address string) (model.EmailAddress, error) {
	identity, err := s.users.GetEmailAddress(ctx, address)
	if !errors.Is(err, store.ErrNotFound) || s.aliases == nil {
		return identity, err
	}
	return s.aliases.SendingIdentity(ctx, address, time.Now())
}

func (s *Mail) authorizeIdentity(ctx context.Context, actor model.PrincipalRef, identity model.EmailAddress, mode SendMode) error {
	if actor.ID == identity.UserID {
		if mode == "" || mode == SendNormal || mode == SendAs {
			return nil
		}
		return fmt.Errorf("send-on-behalf requires a different identity owner")
	}
	var action authz.Action
	switch mode {
	case SendAs:
		action = authz.IdentitySendAs
	case SendOnBehalf:
		action = authz.IdentitySendOnBehalf
	default:
		return fmt.Errorf("delegated sending requires send_as or send_on_behalf mode")
	}
	decision, err := s.authorizer.Check(ctx, authz.Request{
		Actor: actor, Subject: actor, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: identity.ID},
	})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: identity permission %s", ErrForbidden, decision.Reason)
	}
	return nil
}

// AuthorizeSMTPSubmission applies the same identity RBAC as API submission to
// authenticated SMTP, including RFC 5322 Sender semantics for on-behalf mail.
// Every identity carried by the envelope or headers must be enabled and either
// owned by the actor or explicitly delegated.
func (s *Mail) AuthorizeSMTPSubmission(ctx context.Context, actorID, envelopeSender, fromHeader, senderHeader string) error {
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}
	fromAddress, err := parseSingleAddress(fromHeader, "From")
	if err != nil {
		return err
	}
	fromIdentity, err := s.sendingIdentity(ctx, fromAddress)
	if err != nil || !fromIdentity.Enabled {
		return fmt.Errorf("sending identity is unavailable")
	}

	mode := SendNormal
	if !strings.EqualFold(fromIdentity.UserID, actorID) {
		if strings.TrimSpace(senderHeader) == "" {
			mode = SendAs
		} else {
			mode = SendOnBehalf
		}
	}
	if err := s.authorizeIdentity(ctx, actor, fromIdentity, mode); err != nil {
		return err
	}

	if strings.TrimSpace(senderHeader) != "" {
		senderAddress, err := parseSingleAddress(senderHeader, "Sender")
		if err != nil {
			return err
		}
		senderIdentity, err := s.sendingIdentity(ctx, senderAddress)
		if err != nil || !senderIdentity.Enabled || !strings.EqualFold(senderIdentity.UserID, actorID) {
			return fmt.Errorf("sender must be an enabled identity owned by the authenticated user")
		}
	}

	if strings.TrimSpace(envelopeSender) == "" {
		return fmt.Errorf("authenticated submission requires a non-empty envelope sender")
	}
	envelopeIdentity, err := s.sendingIdentity(ctx, strings.ToLower(strings.TrimSpace(envelopeSender)))
	if err != nil || !envelopeIdentity.Enabled || (!strings.EqualFold(envelopeIdentity.ID, fromIdentity.ID) && !strings.EqualFold(envelopeIdentity.UserID, actorID)) {
		return fmt.Errorf("envelope sender is not authorized for this submission")
	}
	return nil
}

func parseSingleAddress(value, field string) (string, error) {
	address, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil || address.Address == "" {
		return "", fmt.Errorf("invalid %s address", field)
	}
	return strings.ToLower(address.Address), nil
}

// namedAddress formats an identity for a From or Sender header with its
// owner's display name, as every mail client shows the sender by name.
func (s *Mail) namedAddress(ctx context.Context, userID, address string) string {
	formatted := &mail.Address{Address: address}
	if user, err := s.users.Get(ctx, userID); err == nil {
		formatted.Name = sanitizeHeader(user.DisplayName)
	}
	return formatted.String()
}

func (s *Mail) primaryIdentity(ctx context.Context, userID string) (string, error) {
	identities, err := s.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil {
		return "", err
	}
	for _, identity := range identities {
		if identity.Enabled && identity.Primary {
			return identity.ID, nil
		}
	}
	for _, identity := range identities {
		if identity.Enabled {
			return identity.ID, nil
		}
	}
	return "", fmt.Errorf("user has no enabled email identity")
}

func parseRecipients(to, cc, bcc []string) ([]string, string, string, error) {
	toAddresses, err := parseAddressValues(to)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid To address: %w", err)
	}
	ccAddresses, err := parseAddressValues(cc)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid Cc address: %w", err)
	}
	bccAddresses, err := parseAddressValues(bcc)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid Bcc address: %w", err)
	}
	all := append(append(append([]*mail.Address{}, toAddresses...), ccAddresses...), bccAddresses...)
	recipients := make([]string, 0, len(all))
	seen := make(map[string]struct{}, len(all))
	for _, address := range all {
		value := strings.ToLower(address.Address)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		recipients = append(recipients, value)
	}
	return recipients, formatAddresses(toAddresses), formatAddresses(ccAddresses), nil
}

func parseAddressValues(values []string) ([]*mail.Address, error) {
	var result []*mail.Address
	for _, value := range values {
		addresses, err := mail.ParseAddressList(value)
		if err != nil {
			return nil, err
		}
		result = append(result, addresses...)
	}
	return result, nil
}

func formatAddresses(addresses []*mail.Address) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return strings.Join(values, ", ")
}

func sanitizeHeader(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}

func submissionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate submission id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}

func buildMessageBytes(headers map[string]string, body []byte) []byte {
	order := []string{"From", "Sender", "To", "Cc", "Subject", "Importance", "X-Priority", "Priority", "Disposition-Notification-To", "Message-ID", "Date", "MIME-Version", "Content-Type"}
	var message strings.Builder
	for _, key := range order {
		if value := headers[key]; value != "" {
			fmt.Fprintf(&message, "%s: %s\r\n", key, value)
		}
	}
	message.WriteString("\r\n")
	_, _ = message.Write(body)
	return []byte(message.String())
}
