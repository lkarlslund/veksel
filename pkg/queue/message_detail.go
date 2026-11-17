package queue

import (
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

// QueueMessageDetail is the payload-free administrative projection of one
// live delivery. Attempt and policy evidence is already bounded when written
// to the durable queue; Detail clones both so API callers cannot mutate queue
// state through a returned view.
type QueueMessageDetail struct {
	ID                  string            `json:"id"`
	CorrelationID       string            `json:"correlation_id,omitempty"`
	ParentID            string            `json:"parent_id,omitempty"`
	Direction           Direction         `json:"direction"`
	EnvelopeSender      string            `json:"envelope_sender"`
	Recipient           string            `json:"recipient"`
	Subject             string            `json:"subject,omitempty"`
	MessageID           string            `json:"message_id,omitempty"`
	Status              Status            `json:"status"`
	RetryCount          int               `json:"retry_count"`
	NextRetry           string            `json:"next_retry,omitempty"`
	ExpiresAt           string            `json:"expires_at,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	LastCode            string            `json:"last_code,omitempty"`
	LastResponse        string            `json:"last_response,omitempty"`
	DeliveryRoute       string            `json:"delivery_route,omitempty"`
	AdministrativeRoute string            `json:"administrative_route,omitempty"`
	RouteChanges        []RouteChange     `json:"route_changes"`
	RouteChangesDropped int64             `json:"route_changes_dropped,omitempty"`
	PolicyRoute         string            `json:"policy_route,omitempty"`
	TargetFolderPath    string            `json:"target_folder_path,omitempty"`
	TransportSecurity   string            `json:"transport_security"`
	AuthenticatedActor  string            `json:"authenticated_actor,omitempty"`
	SourceIP            string            `json:"source_ip,omitempty"`
	HoldReason          string            `json:"hold_reason,omitempty"`
	HeldAt              string            `json:"held_at,omitempty"`
	ReleasedAt          string            `json:"released_at,omitempty"`
	PendingHoldReason   string            `json:"pending_hold_reason,omitempty"`
	PendingHoldAt       string            `json:"pending_hold_at,omitempty"`
	PossibleDuplicate   bool              `json:"possible_duplicate,omitempty"`
	Attempts            []AttemptRecord   `json:"attempts"`
	AttemptsDropped     int64             `json:"attempts_dropped,omitempty"`
	Policy              mailpolicy.Result `json:"policy"`
	CreatedAt           string            `json:"created_at"`
	CompletedAt         string            `json:"completed_at,omitempty"`
}

// ProjectMessageDetail converts a detached queue snapshot into its bounded
// administrative form. It accepts nil so queue interfaces can expose detail
// as an optional read capability without widening their mutation contract.
func ProjectMessageDetail(m *Message) *QueueMessageDetail {
	if m == nil {
		return nil
	}
	return &QueueMessageDetail{
		ID: m.ID, CorrelationID: m.CorrelationID, ParentID: m.ParentID,
		Direction: m.Direction, EnvelopeSender: m.EnvelopeSender, Recipient: m.Recipient,
		Subject: headerValue(m.Headers, "Subject"), MessageID: headerValue(m.Headers, "Message-ID"),
		Status: m.Status, RetryCount: m.RetryCount, NextRetry: formatOptionalTime(m.NextRetry), ExpiresAt: formatOptionalTime(m.ExpiresAt),
		LastError: m.LastError, LastCode: m.LastCode, LastResponse: m.LastResponse,
		DeliveryRoute: m.DeliveryRoute, AdministrativeRoute: m.AdministrativeRoute,
		RouteChanges: append([]RouteChange(nil), m.RouteChanges...), RouteChangesDropped: m.RouteChangesDropped,
		PolicyRoute: m.PolicyRoute, TargetFolderPath: m.TargetFolderPath,
		TransportSecurity: transportSecurity(m), AuthenticatedActor: m.AuthenticatedActor, SourceIP: m.SourceIP,
		HoldReason: m.HoldReason, HeldAt: formatOptionalTime(m.HeldAt), ReleasedAt: formatOptionalTime(m.ReleasedAt),
		PendingHoldReason: m.PendingHoldReason, PendingHoldAt: formatOptionalTime(m.PendingHoldAt),
		PossibleDuplicate: m.PossibleDuplicate, Attempts: append([]AttemptRecord(nil), m.Attempts...),
		AttemptsDropped: m.AttemptsDropped, Policy: m.Policy.Evidence(), CreatedAt: formatOptionalTime(m.CreatedAt), CompletedAt: formatOptionalTime(m.CompletedAt),
	}
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func transportSecurity(message *Message) string {
	if message.Attributes[smtp.AttributeRequireTLS] == "true" {
		return "required"
	}
	if message.Attributes[smtp.AttributeTLSOptional] == "true" {
		return "optional"
	}
	return "default"
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

// FormatBackoff returns a human-readable backoff duration for the given retry count.
func FormatBackoff(retryCount int) string {
	if retryCount <= 0 {
		return "now"
	}
	d := time.Duration(1<<uint(retryCount-1)) * time.Minute
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%.1fh", float64(d)/float64(time.Hour))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
