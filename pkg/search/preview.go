package search

import (
	"bytes"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// previewBodyBudget bounds the decoded body bytes read for a list preview.
const previewBodyBudget = 64 << 10

// MailPreview returns the first limit runes of a message's whitespace-
// collapsed body text and whether it carries attachments. It shares the
// index extractor's bounded MIME walk so list previews and search agree.
func MailPreview(raw []byte, limit int) (preview string, hasAttachment bool) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", false
	}
	extractor := entityExtractor{budget: extractionBudget{remaining: previewBodyBudget, limited: true}}
	result := extractor.extract(message.Body, message.Header.Get("Content-Type"), message.Header.Get("Content-Transfer-Encoding"), message.Header.Get("Content-Disposition"), 0)
	for _, body := range result.body {
		if text := strings.TrimSpace(whitespace.ReplaceAllString(body, " ")); text != "" {
			preview = text
			break
		}
	}
	if utf8.RuneCountInString(preview) > limit {
		preview = strings.TrimSpace(string([]rune(preview)[:limit])) + "…"
	}
	return preview, result.hasAttachment
}
