package alertnotify

import (
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailidentity"
)

// ComposeMail renders a notification as an auto-generated plain-text RFC 5322
// message. Date and Message-ID derive from the message identity, so a
// re-admission after a crash produces identical bytes and the queue drops it
// as a duplicate.
func ComposeMail(from, to string, message Message) []byte {
	domain := mailidentity.MessageIDDomain(from, "")
	at := message.At
	if at.IsZero() {
		at = time.Now()
	}
	body := strings.ReplaceAll(strings.ReplaceAll(message.Text, "\r\n", "\n"), "\n", "\r\n")
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n",
		headerValue(from), headerValue(to), mime.QEncoding.Encode("utf-8", headerValue(message.Subject)),
		at.UTC().Format(time.RFC1123Z), messageIDPart(message.ID), domain)
	builder.WriteString("MIME-Version: 1.0\r\nAuto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\n")
	builder.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	builder.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		builder.WriteString("\r\n")
	}
	return []byte(builder.String())
}

// messageIDPart maps an identity onto Message-ID dot-atom characters.
func messageIDPart(id string) string {
	return strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".-_+=", r)) {
			return r
		}
		return '-'
	}, id)
}

func headerValue(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}
