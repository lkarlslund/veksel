package queue

import (
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/smtp"
)

func TestSMTPAdapterTagsTLSOptionalAcrossSubmissionProtocols(t *testing.T) {
	q := New(&Config{ProcessPeriod: time.Hour})
	defer q.Close()
	adapter := NewSMTPAdapter(q)
	if err := adapter.EnqueueBatch([]*smtp.MailMessage{
		{ID: "optional", Recipient: "one@example.test", Headers: map[string]string{"tls-required": " No "}},
		{ID: "required", Recipient: "two@example.test", Headers: map[string]string{"TLS-Required": "No"}, Attributes: map[string]string{smtp.AttributeRequireTLS: "true"}},
	}); err != nil {
		t.Fatal(err)
	}
	optional, required := q.Get("optional"), q.Get("required")
	if optional == nil || optional.Attributes[smtp.AttributeTLSOptional] != "true" {
		t.Fatalf("optional message = %#v", optional)
	}
	if required == nil || required.Attributes[smtp.AttributeRequireTLS] != "true" || required.Attributes[smtp.AttributeTLSOptional] != "" {
		t.Fatalf("required message = %#v", required)
	}
}
