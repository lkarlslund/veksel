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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"golang.org/x/net/html/charset"
)

const (
	MaxMIMEParts      = 512
	MaxMIMEDepth      = 24
	MaxMIMEBodyBytes  = 4 << 20
	MaxMIMEHeaderKeys = 256
	// MaxMIMECalendarBytes bounds the decoded text/calendar part captured for
	// scheduling (iMIP); larger calendars are ignored.
	MaxMIMECalendarBytes = 256 << 10
)

// MessageAttachment is safe metadata for one downloadable MIME leaf.
type MessageAttachment struct {
	PartID      string `json:"part_id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Inline      bool   `json:"inline"`
	ContentID   string `json:"content_id,omitempty"`
	Previewable bool   `json:"previewable"`
}

// MessageProjection is a bounded, presentation-safe view of a canonical mail
// item. HTML has already passed through the conservative email sanitizer.
type MessageProjection struct {
	ItemID               string              `json:"item_id"`
	FolderID             string              `json:"folder_id"`
	Headers              map[string]string   `json:"headers"`
	Text                 string              `json:"text,omitempty"`
	HTML                 string              `json:"html,omitempty"`
	Attachments          []MessageAttachment `json:"attachments"`
	BodyTruncated        bool                `json:"body_truncated"`
	UnsafeContentRemoved bool                `json:"unsafe_content_removed"`
	RemoteContentBlocked bool                `json:"remote_content_blocked"`
	// Calendar is the first text/calendar part (iMIP, RFC 6047) when it fits
	// MaxMIMECalendarBytes. Consumers parse it; it is never sent as is.
	Calendar []byte `json:"-"`
}

// MessageAttachmentStream keeps decoded attachment bytes out of JSON and lets
// consumers copy them directly to their response or protocol stream.
type MessageAttachmentStream struct {
	MessageAttachment
	Reader io.ReadCloser
}

// MIMEReader projects opaque mail items exclusively through FolderSpace.
type MIMEReader struct{ space FolderSpace }

func NewMIMEReader(space FolderSpace) *MIMEReader { return &MIMEReader{space: space} }

func (r *MIMEReader) Project(ctx context.Context, access AccessContext, itemID string) (MessageProjection, error) {
	item, err := r.mailItem(ctx, access, itemID)
	if err != nil {
		return MessageProjection{}, err
	}
	projection, err := ProjectMIME(item.Data)
	if err != nil {
		return MessageProjection{}, err
	}
	projection.ItemID, projection.FolderID = item.ID, item.FolderID
	return projection, nil
}

// ProjectMIME projects a raw RFC 5322 message within the same bounds as a
// stored mail item.
func ProjectMIME(data []byte) (MessageProjection, error) {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return MessageProjection{}, fmt.Errorf("parse MIME message: %w", err)
	}
	projection := MessageProjection{Headers: projectMIMEHeaders(message.Header), Attachments: []MessageAttachment{}}
	state := mimeProjectionState{projection: &projection}
	if err := state.walk(message.Header, message.Body, "1", 0); err != nil {
		return MessageProjection{}, err
	}
	return projection, nil
}

func (r *MIMEReader) OpenAttachment(ctx context.Context, access AccessContext, itemID, partID string) (MessageAttachmentStream, error) {
	if !validMIMEPartID(partID) {
		return MessageAttachmentStream{}, fmt.Errorf("invalid MIME part ID")
	}
	item, err := r.mailItem(ctx, access, itemID)
	if err != nil {
		return MessageAttachmentStream{}, err
	}
	message, err := mail.ReadMessage(bytes.NewReader(item.Data))
	if err != nil {
		return MessageAttachmentStream{}, fmt.Errorf("parse MIME message: %w", err)
	}
	attachment, reader, err := findMIMEAttachment(message.Header, message.Body, "1", partID, 0, new(int))
	if err != nil {
		return MessageAttachmentStream{}, err
	}
	return MessageAttachmentStream{MessageAttachment: attachment, Reader: io.NopCloser(reader)}, nil
}

func (r *MIMEReader) mailItem(ctx context.Context, access AccessContext, itemID string) (model.Item, error) {
	if r == nil || r.space == nil {
		return model.Item{}, errors.New("MIME reader is unavailable")
	}
	item, err := r.space.GetItem(ctx, access, itemID)
	if err != nil {
		return model.Item{}, err
	}
	folder, err := r.space.GetFolder(ctx, access, item.FolderID)
	if err != nil {
		return model.Item{}, err
	}
	if folder.Type != model.FolderTypeMail {
		return model.Item{}, fmt.Errorf("item is not a mail message")
	}
	return item, nil
}

type mimeProjectionState struct {
	projection *MessageProjection
	parts      int
	bodyBytes  int64
}

func (s *mimeProjectionState) walk(header mail.Header, body io.Reader, partID string, depth int) error {
	if depth > MaxMIMEDepth {
		return errors.New("MIME nesting exceeds supported depth")
	}
	s.parts++
	if s.parts > MaxMIMEParts {
		return errors.New("MIME message has too many parts")
	}
	mediaType, params := parseMIMEType(header.Get("Content-Type"))
	if strings.HasPrefix(mediaType, "multipart/") {
		if params["boundary"] == "" {
			return errors.New("multipart MIME part has no boundary")
		}
		reader := multipart.NewReader(body, params["boundary"])
		for index := 1; ; index++ {
			part, err := reader.NextRawPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read MIME part: %w", err)
			}
			childID := partID + "." + strconv.Itoa(index)
			err = s.walk(mail.Header(part.Header), part, childID, depth+1)
			_ = part.Close()
			if err != nil {
				return err
			}
		}
	}
	attachment, isAttachment := describeMIMEAttachment(header, mediaType, partID)
	decoded := model.TransferDecoder(body, header.Get("Content-Transfer-Encoding"))
	if mediaType == "text/calendar" && s.projection.Calendar == nil {
		data, err := io.ReadAll(io.LimitReader(decoded, MaxMIMECalendarBytes+1))
		if err != nil {
			return fmt.Errorf("read MIME calendar: %w", err)
		}
		if len(data) <= MaxMIMECalendarBytes {
			s.projection.Calendar = data
		}
		decoded = io.MultiReader(bytes.NewReader(data), decoded)
	}
	if isAttachment {
		size, err := io.Copy(io.Discard, decoded)
		if err != nil {
			return fmt.Errorf("decode MIME attachment: %w", err)
		}
		attachment.Size = size
		attachment.Previewable = ContentPreviewable(attachment.ContentType, size)
		s.projection.Attachments = append(s.projection.Attachments, attachment)
		return nil
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		return nil
	}
	remaining := int64(MaxMIMEBodyBytes) - s.bodyBytes
	if remaining <= 0 {
		s.projection.BodyTruncated = true
		return nil
	}
	decoded, err := decodeMIMECharset(decoded, params["charset"])
	if err != nil {
		return fmt.Errorf("decode MIME charset: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(decoded, remaining+1))
	if err != nil {
		return fmt.Errorf("read MIME body: %w", err)
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
		s.projection.BodyTruncated = true
	}
	s.bodyBytes += int64(len(data))
	if mediaType == "text/plain" {
		s.projection.Text = appendBody(s.projection.Text, string(data))
		return nil
	}
	safe, removed, remote := sanitizeEmailHTML(string(data))
	s.projection.HTML = appendBody(s.projection.HTML, safe)
	s.projection.UnsafeContentRemoved = s.projection.UnsafeContentRemoved || removed
	s.projection.RemoteContentBlocked = s.projection.RemoteContentBlocked || remote
	return nil
}

func findMIMEAttachment(header mail.Header, body io.Reader, partID, target string, depth int, parts *int) (MessageAttachment, io.Reader, error) {
	if depth > MaxMIMEDepth {
		return MessageAttachment{}, nil, errors.New("MIME nesting exceeds supported depth")
	}
	(*parts)++
	if *parts > MaxMIMEParts {
		return MessageAttachment{}, nil, errors.New("MIME message has too many parts")
	}
	mediaType, params := parseMIMEType(header.Get("Content-Type"))
	if strings.HasPrefix(mediaType, "multipart/") {
		if params["boundary"] == "" {
			return MessageAttachment{}, nil, errors.New("multipart MIME part has no boundary")
		}
		reader := multipart.NewReader(body, params["boundary"])
		for index := 1; ; index++ {
			part, err := reader.NextRawPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return MessageAttachment{}, nil, err
			}
			attachment, content, findErr := findMIMEAttachment(mail.Header(part.Header), part, partID+"."+strconv.Itoa(index), target, depth+1, parts)
			if findErr == nil {
				return attachment, content, nil
			}
			if !errors.Is(findErr, store.ErrNotFound) {
				return MessageAttachment{}, nil, findErr
			}
			_ = part.Close()
		}
		return MessageAttachment{}, nil, store.ErrNotFound
	}
	attachment, ok := describeMIMEAttachment(header, mediaType, partID)
	if partID != target || !ok {
		return MessageAttachment{}, nil, store.ErrNotFound
	}
	return attachment, model.TransferDecoder(body, header.Get("Content-Transfer-Encoding")), nil
}

func describeMIMEAttachment(header mail.Header, mediaType, partID string) (MessageAttachment, bool) {
	disposition, dispositionParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	_, contentParams := parseMIMEType(header.Get("Content-Type"))
	name := firstNonEmptyString(dispositionParams["filename"], contentParams["name"])
	isAttachment := strings.EqualFold(disposition, "attachment") || name != "" || (!strings.HasPrefix(mediaType, "text/") && mediaType != "")
	if !isAttachment {
		return MessageAttachment{}, false
	}
	name = safeAttachmentName(name, mediaType, partID)
	return MessageAttachment{
		PartID: partID, Name: name, ContentType: mediaType,
		Inline: strings.EqualFold(disposition, "inline"), ContentID: strings.Trim(strings.TrimSpace(header.Get("Content-ID")), "<>"),
	}, true
}

func projectMIMEHeaders(header mail.Header) map[string]string {
	result := make(map[string]string)
	keys := []string{"From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "In-Reply-To", "References", "Importance", "X-Priority", "Priority", "Disposition-Notification-To", "Return-Path"}
	for _, key := range keys {
		if len(result) >= MaxMIMEHeaderKeys {
			break
		}
		value := model.DecodeHeaderValue(header.Get(key))
		if value != "" {
			result[key] = value
		}
	}
	return result
}

func parseMIMEType(value string) (string, map[string]string) {
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || mediaType == "" {
		return "text/plain", map[string]string{}
	}
	return strings.ToLower(mediaType), params
}

func decodeMIMECharset(reader io.Reader, name string) (io.Reader, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "utf-8") || strings.EqualFold(name, "us-ascii") {
		return reader, nil
	}
	return charset.NewReader(reader, name)
}

func safeAttachmentName(name, mediaType, partID string) string {
	name = filepath.Base(strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(name)))
	if name != "" && name != "." {
		return name
	}
	extension := ""
	if extensions, _ := mime.ExtensionsByType(mediaType); len(extensions) > 0 {
		extension = extensions[0]
	}
	return "attachment-" + strings.ReplaceAll(partID, ".", "-") + extension
}

func validMIMEPartID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		value, err := strconv.Atoi(part)
		if err != nil || value < 1 || value > MaxMIMEParts {
			return false
		}
	}
	return true
}

func appendBody(current, value string) string {
	if strings.TrimSpace(value) == "" {
		return current
	}
	if current == "" {
		return value
	}
	return current + "\n" + value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
