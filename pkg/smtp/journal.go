package smtp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// JournalHeader marks every journal copy with the ID of the message it
// records.
const JournalHeader = "X-Veksel-Journal"

// JournalRequest describes one journal copy of an accepted message.
type JournalRequest struct {
	Format     model.JournalFormat
	From       string // RFC 5322 From of an envelope report
	To         string // the journal address
	ServerName string // for the report's Message-ID
	ID         string // the original queue ID, carried in JournalHeader
	Direction  string // inbound or outbound
	Sender     string // envelope sender
	// Recipients are every envelope recipient, including Bcc recipients,
	// which appear in neither To nor Cc.
	Recipients []string
	Original   []byte
}

// JournalRecipient is one envelope recipient and how the original header
// addressed it: to, cc, or bcc when it is in neither To nor Cc.
type JournalRecipient struct{ Address, Type string }

// ClassifyJournalRecipients types each envelope recipient by the original
// To and Cc fields.
func ClassifyJournalRecipients(original []byte, recipients []string) []JournalRecipient {
	headers := model.ParseHeaderValues(original)
	addressed := make(map[string]string)
	for _, field := range []string{"cc", "to"} {
		for _, value := range headers[field] {
			list, _ := mail.ParseAddressList(value)
			for _, address := range list {
				addressed[strings.ToLower(address.Address)] = field
			}
		}
	}
	classified := make([]JournalRecipient, 0, len(recipients))
	for _, recipient := range recipients {
		kind := addressed[strings.ToLower(recipient)]
		if kind == "" {
			kind = "bcc"
		}
		classified = append(classified, JournalRecipient{Address: recipient, Type: kind})
	}
	return classified
}

// headerSafe removes line breaks from a value placed in a header field.
func headerSafe(value string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(value)
}

// BuildJournalMessage returns the journal copy for request: an envelope
// report wrapping the original as message/rfc822, or the original with
// X-Veksel-Journal-* fields listing the envelope.
func BuildJournalMessage(request JournalRequest, now time.Time) []byte {
	recipients := ClassifyJournalRecipients(request.Original, request.Recipients)
	sender := headerSafe(request.Sender)
	if sender == "" {
		sender = "<>"
	}
	var sb strings.Builder
	if request.Format == model.JournalRaw {
		fmt.Fprintf(&sb, "%s: %s\r\n%s-Direction: %s\r\n%s-Sender: %s\r\n", JournalHeader, headerSafe(request.ID), JournalHeader, headerSafe(request.Direction), JournalHeader, sender)
		for _, recipient := range recipients {
			fmt.Fprintf(&sb, "%s-Recipient: %s; type=%s\r\n", JournalHeader, headerSafe(recipient.Address), recipient.Type)
		}
		return append([]byte(sb.String()), request.Original...)
	}
	headers := model.ParseItemHeaders(request.Original)
	token := make([]byte, 12)
	_, _ = rand.Read(token)
	boundary := "veksel-journal-" + hex.EncodeToString(token)
	fmt.Fprintf(&sb, "From: %s\r\nTo: %s\r\n", headerSafe(request.From), headerSafe(request.To))
	fmt.Fprintf(&sb, "Subject: Journal report: %s\r\n", headerSafe(headers["Subject"]))
	fmt.Fprintf(&sb, "Date: %s\r\nMessage-ID: %s\r\n", now.UTC().Format(time.RFC1123Z), generateMessageID("", request.ServerName))
	fmt.Fprintf(&sb, "Auto-Submitted: auto-generated\r\n%s: %s\r\nMIME-Version: 1.0\r\n", JournalHeader, headerSafe(request.ID))
	fmt.Fprintf(&sb, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)
	fmt.Fprintf(&sb, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", boundary)
	fmt.Fprintf(&sb, "Sender: %s\r\nSubject: %s\r\nMessage-Id: %s\r\nDirection: %s\r\n", sender, headerSafe(headers["Subject"]), headerSafe(headers["Message-Id"]), headerSafe(request.Direction))
	for _, recipient := range recipients {
		fmt.Fprintf(&sb, "%s: %s\r\n", strings.ToUpper(recipient.Type[:1])+recipient.Type[1:], headerSafe(recipient.Address))
	}
	fmt.Fprintf(&sb, "\r\n--%s\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n", boundary)
	sb.Write(request.Original)
	if !strings.HasSuffix(sb.String(), "\r\n") {
		sb.WriteString("\r\n")
	}
	fmt.Fprintf(&sb, "--%s--\r\n", boundary)
	return []byte(sb.String())
}
