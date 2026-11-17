package imap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/threading"
)

// OBJECTID (RFC 8474), PREVIEW (RFC 8970), and SAVEDATE (RFC 8514) data items.

// objectID renders a storage identifier as an RFC 8474 objectid: 1 to 255
// ASCII letters, digits, "_" and "-". Veksel resource IDs already qualify;
// anything else maps to a stable digest so the value stays opaque and valid.
func objectID(value string) string {
	valid := value != "" && len(value) <= 255
	for index := 0; valid && index < len(value); index++ {
		c := value[index]
		valid = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
	}
	if valid {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "x" + hex.EncodeToString(sum[:16])
}

// emailID is the immutable item ID, so it survives MOVE and flag changes.
func emailID(item model.Item) string { return objectID(item.ID) }

// mailboxID is the immutable folder ID, so it survives RENAME.
func mailboxID(folder model.Folder) string { return objectID(folder.ID) }

// threadID is the conversation ID JMAP and the webmail share.
func threadID(item model.Item) string {
	return threading.ID(threading.Message{
		ID:      threading.CanonicalID(getMessageID(item)),
		Parents: threading.Parents(getReferences(item), getInReplyTo(item)),
		Subject: model.DecodeHeaderValue(getSubject(item)),
	})
}

// savedAt is when the item entered its current mailbox: the move time for
// moved items, otherwise its creation time. Items stored before the save
// time was recorded fall back to creation.
func savedAt(item model.Item) time.Time {
	if !item.SavedAt.IsZero() {
		return item.SavedAt
	}
	return item.CreatedAt
}

func formatSaveDate(item model.Item) string {
	saved := savedAt(item)
	if saved.IsZero() {
		return "SAVEDATE NIL"
	}
	return "SAVEDATE " + formatInternalDate(saved)
}

// loadStoredPreviews prepares the selected mailbox's projected previews for
// one FETCH that asks for PREVIEW. It leaves none loaded when the mail list
// index is unavailable, which sends PREVIEW back to computing.
func (s *Session) loadStoredPreviews(attrs string) {
	s.storedPreviews = nil
	if s.cfg.MailIndex == nil || !strings.Contains(attrs, "PREVIEW") {
		return
	}
	folder, err := s.cfg.FolderSpace.GetFolder(*s.ctx, s.access(), s.selectedFolderID)
	if err != nil {
		return
	}
	if previews, err := s.cfg.MailIndex.Previews(*s.ctx, s.cfg.FolderSpace, s.access(), folder); err == nil {
		s.storedPreviews = previews
	}
}

// messagePreview returns the item's preview. The stored projection answers
// when it describes this version of the message; otherwise the preview is
// computed, except for the LAZY modifier, which declines to do that work.
func (s *Session) messagePreview(item model.Item, lazy bool) (string, bool) {
	if s.hasStoredPreview(item) {
		return s.storedPreviews[item.ID].Text, true
	}
	if lazy {
		return "", false
	}
	return mailindex.ComputePreview(item.Data), true
}

// hasStoredPreview reports whether the stored projection describes this
// version of item, so its preview needs no message content.
func (s *Session) hasStoredPreview(item model.Item) bool {
	stored, ok := s.storedPreviews[item.ID]
	return ok && stored.ModSeq == item.ModSeq
}

// previewFetchItem formats the PREVIEW response item. Non-ASCII previews
// travel as a literal, as RFC 8970 requires.
func (s *Session) previewFetchItem(item model.Item, lazy bool) (string, *fetchLiteral) {
	text, ok := s.messagePreview(item, lazy)
	if !ok {
		return "PREVIEW NIL", nil
	}
	if strings.IndexFunc(text, func(r rune) bool { return r > 127 }) >= 0 {
		return fmt.Sprintf("PREVIEW {%d}", len(text)), &fetchLiteral{label: "PREVIEW", data: []byte(text)}
	}
	quoted, err := quoteIMAPString(text)
	if err != nil {
		return "PREVIEW NIL", nil
	}
	return "PREVIEW " + quoted, nil
}

// mergePreviewModifiers joins "PREVIEW" with a following "(LAZY)" token.
func mergePreviewModifiers(tokens []string) []string {
	merged := tokens[:0:0]
	for index := 0; index < len(tokens); index++ {
		token := strings.ToUpper(tokens[index])
		if token == "PREVIEW" && index+1 < len(tokens) && strings.EqualFold(tokens[index+1], "(LAZY)") {
			merged = append(merged, "PREVIEW(LAZY)")
			index++
			continue
		}
		merged = append(merged, tokens[index])
	}
	return merged
}
