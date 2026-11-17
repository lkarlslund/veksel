package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
)

func queueTransportSecurity(attributes map[string]string) string {
	if attributes[smtp.AttributeRequireTLS] == "true" {
		return "required"
	}
	if attributes[smtp.AttributeTLSOptional] == "true" {
		return "optional"
	}
	return "default"
}

func mailPolicyAdmission(policy *mailpolicy.Service) func(context.Context, *queue.Message) error {
	return func(_ context.Context, message *queue.Message) error {
		if policy == nil || message == nil {
			return nil
		}
		direction := mailpolicy.DirectionOutbound
		if message.Direction == queue.DirectionInbound {
			direction = mailpolicy.DirectionInbound
		} else if message.AuthenticatedActor != "" {
			direction = mailpolicy.DirectionSubmission
		}
		contentType := queueHeader(message.Headers, "Content-Type")
		size := len(message.Content)
		if size == 0 {
			size = len(message.Body)
		}
		result := policy.Evaluate(mailpolicy.Message{
			Direction: direction, EnvelopeFrom: message.EnvelopeSender, EnvelopeTo: []string{message.Recipient},
			AuthenticatedActor: message.AuthenticatedActor, SourceIP: message.SourceIP, SizeBytes: int64(size),
			HeaderFrom: queueHeader(message.Headers, "From"), HeaderSubject: queueHeader(message.Headers, "Subject"),
			HasAttachment: messageHasAttachment(contentType, message.Body, message.Content), ContentType: contentType,
			Domain: recipientDomain(message.Recipient),
		})
		decision := result.Decision()
		message.Policy = result.Evidence()
		if message.Headers == nil {
			message.Headers = make(map[string]string)
		}
		var added strings.Builder
		for _, action := range decision.Headers {
			setQueueHeader(message.Headers, action.Header, action.Value)
			fmt.Fprintf(&added, "%s: %s\r\n", action.Header, action.Value)
		}
		if added.Len() > 0 && len(message.Content) > 0 {
			message.Content = append([]byte(added.String()), message.Content...)
		}
		if decision.Route != nil {
			message.PolicyRoute = strings.ToLower(strings.TrimSpace(decision.Route.Value))
		}
		if decision.Reject != nil {
			return &mailpolicy.RejectionError{Reason: decision.Reject.Value, EnhancedStatusCode: decision.Reject.EnhancedStatusCode}
		}
		if decision.Quarantine != nil {
			if message.Attributes == nil {
				message.Attributes = make(map[string]string)
			}
			message.Kind = smtp.MailTaskQuarantine
			message.Attributes["subject"] = queueHeader(message.Headers, "Subject")
			message.Attributes["virus_name"] = "Policy: " + decision.Quarantine.Value
			message.Attributes["scanner"] = "mail-policy"
			message.Attributes["date"] = time.Now().UTC().Format(time.RFC3339)
			message.Content = message.RawMessage()
			message.TargetFolderID, message.TargetFolderPath, message.TargetOwnerID, message.PolicyRoute = "", "", "", ""
		}
		return nil
	}
}

func queueHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func setQueueHeader(headers map[string]string, name, value string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
	headers[name] = value
}

func recipientDomain(recipient string) string {
	index := strings.LastIndex(recipient, "@")
	if index < 0 || index == len(recipient)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(recipient[index+1:]))
}

func selectedOutboundRoute(message *queue.Message) string {
	if message.AdministrativeRoute != "" {
		return message.AdministrativeRoute
	}
	return message.PolicyRoute
}

func messageHasAttachment(contentType string, body, content []byte) bool {
	if !strings.Contains(strings.ToLower(contentType), "multipart/") {
		return false
	}
	data := body
	if len(data) == 0 {
		data = content
	}
	return strings.Contains(strings.ToLower(string(data)), "content-disposition: attachment")
}
