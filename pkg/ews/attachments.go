package ews

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// maxAttachmentBytes bounds one attachment read or written over EWS.
const maxAttachmentBytes = 25 << 20

var errAttachmentNotFound = errors.New("the attachment could not be found")

// attachmentsXML lists a message's attachments as FileAttachment elements.
// The AttachmentId names the item and the MIME part.
func attachmentsXML(itemID string, attachments []service.MessageAttachment, info requestInfo) string {
	var out strings.Builder
	for _, attachment := range attachments {
		out.WriteString(`<t:FileAttachment><t:AttachmentId Id="` + encodeID("a:", itemID+"\x00"+attachment.PartID) + `"/><t:Name>` + escape(attachment.Name) + `</t:Name><t:ContentType>` + escape(attachment.ContentType) + `</t:ContentType>`)
		if attachment.ContentID != "" {
			out.WriteString(`<t:ContentId>` + escape(attachment.ContentID) + `</t:ContentId>`)
		}
		if !info.exchange2007() {
			out.WriteString(`<t:Size>` + strconv.FormatInt(attachment.Size, 10) + `</t:Size><t:IsInline>` + strconv.FormatBool(attachment.Inline) + `</t:IsInline>`)
		}
		out.WriteString(`</t:FileAttachment>`)
	}
	return out.String()
}

func decodeAttachmentID(encoded string) (itemID, part string, ok bool) {
	raw, err := decodeID(encoded, "a:")
	if err != nil {
		return "", "", false
	}
	itemID, part, ok = strings.Cut(raw, "\x00")
	return itemID, part, ok && itemID != "" && part != ""
}

func (h *Handler) getAttachment(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	var ids []string
	op.descendant("AttachmentIds").walk(func(n *node) {
		if n.Name.Local == "AttachmentId" && n.attr("Id") != "" {
			ids = append(ids, n.attr("Id"))
		}
	})
	if len(ids) == 0 {
		return "", errors.New("attachment ID is required")
	}
	reader := service.NewMIMEReader(h.space)
	messages := make([]responseMessage, 0, len(ids))
	for _, encoded := range ids {
		itemID, part, ok := decodeAttachmentID(encoded)
		if !ok {
			messages = append(messages, responseMessage{err: errAttachmentNotFound})
			continue
		}
		var name, contentType string
		var content []byte
		if part == contactPhotoPart {
			item, err := h.space.GetItem(ctx, access, itemID)
			if err != nil {
				messages = append(messages, responseMessage{err: err})
				continue
			}
			content = model.ParseVCard(item.Data).PhotoData
			if len(content) == 0 {
				messages = append(messages, responseMessage{err: errAttachmentNotFound})
				continue
			}
			name, contentType = "ContactPicture.jpg", "image/jpeg"
		} else {
			stream, err := reader.OpenAttachment(ctx, access, itemID, part)
			if err != nil {
				if errors.Is(err, service.ErrForbidden) || service.IsTemporarilyUnavailable(err) {
					messages = append(messages, responseMessage{err: err})
				} else {
					messages = append(messages, responseMessage{err: errAttachmentNotFound})
				}
				continue
			}
			content, err = io.ReadAll(io.LimitReader(stream.Reader, maxAttachmentBytes+1))
			_ = stream.Reader.Close()
			if err != nil || len(content) > maxAttachmentBytes {
				messages = append(messages, responseMessage{err: fmt.Errorf("%w: attachment is too large", errEWSInvalidProperty)})
				continue
			}
			name, contentType = stream.Name, stream.ContentType
		}
		messages = append(messages, responseMessage{body: `<m:Attachments><t:FileAttachment><t:AttachmentId Id="` + escape(encoded) + `"/><t:Name>` + escape(name) + `</t:Name><t:ContentType>` + escape(contentType) + `</t:ContentType><t:Content>` + base64.StdEncoding.EncodeToString(content) + `</t:Content></t:FileAttachment></m:Attachments>`})
	}
	return responses("GetAttachment", messages), nil
}

// createAttachment adds file attachments to a message (as MIME parts) or a
// photo to a contact.
func (h *Handler) createAttachment(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	parent := op.child("ParentItemId")
	if parent == nil {
		return "", errors.New("parent item is required")
	}
	attachments := op.child("Attachments")
	if attachments == nil || len(attachments.Children) == 0 {
		return "", errors.New("attachment payload is required")
	}
	parentID, err := decodeID(parent.attr("Id"), "i:")
	messages := make([]responseMessage, 0, len(attachments.Children))
	for _, attachment := range attachments.Children {
		if err != nil {
			messages = append(messages, responseMessage{err: errItemNotFound})
			continue
		}
		body, createErr := h.addAttachment(ctx, access, parentID, attachment)
		messages = append(messages, responseMessage{body: body, err: createErr})
	}
	return responses("CreateAttachment", messages), nil
}

func (h *Handler) addAttachment(ctx context.Context, access service.AccessContext, itemID string, attachment *node) (string, error) {
	if attachment.Name.Local != "FileAttachment" {
		return "", fmt.Errorf("%w: only file attachments are supported", errEWSInvalidProperty)
	}
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(attachment.descendantText("Content")))
	if err != nil || len(content) > maxAttachmentBytes {
		return "", fmt.Errorf("%w: attachment content must be base64 of at most %d bytes", errEWSInvalidProperty, maxAttachmentBytes)
	}
	name := strings.TrimSpace(attachment.descendantText("Name"))
	contentType := strings.TrimSpace(attachment.descendantText("ContentType"))
	if contentType == "" {
		contentType = mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
	}
	if _, _, parseErr := mime.ParseMediaType(contentType); contentType == "" || parseErr != nil {
		contentType = "application/octet-stream"
	}
	item, err := h.space.GetItem(ctx, access, itemID)
	if err != nil {
		return "", err
	}
	part := ""
	var data []byte
	var headers map[string]string
	switch kindOf(item.Data) {
	case kindContact:
		card := decodeCard(item.Data)
		if card == nil {
			return "", fmt.Errorf("%w: the contact cannot be read", errEWSInvalidProperty)
		}
		setContactPhoto(card, content, contentType)
		if data, headers, err = encodeCard(card); err != nil {
			return "", err
		}
		part = contactPhotoPart
	case kindMessage:
		data, err = appendMIMEAttachment(item.Data, name, contentType, strings.TrimSpace(attachment.descendantText("ContentId")), parseBool(attachment.descendantText("IsInline")), content)
		if err != nil {
			return "", fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
		}
		headers = model.ParseItemHeaders(data)
	default:
		return "", fmt.Errorf("%w: attachments on calendar items and tasks are not supported", errEWSInvalidProperty)
	}
	updated, err := h.conditionalUpdate(ctx, access, item, data, headers)
	if err != nil {
		return "", err
	}
	if part == "" {
		projection, projectErr := service.ProjectMIME(updated.Data)
		if projectErr != nil || len(projection.Attachments) == 0 {
			return "", errors.New("the attachment was stored but cannot be located")
		}
		part = projection.Attachments[len(projection.Attachments)-1].PartID
	}
	return `<m:Attachments><t:FileAttachment><t:AttachmentId Id="` + encodeID("a:", updated.ID+"\x00"+part) + `" RootItemId="` + encodeID("i:", updated.ID) + `" RootItemChangeKey="` + strconv.FormatUint(updated.ModSeq, 10) + `"/></t:FileAttachment></m:Attachments>`, nil
}

func (h *Handler) deleteAttachment(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	var ids []string
	op.descendant("AttachmentIds").walk(func(n *node) {
		if n.Name.Local == "AttachmentId" && n.attr("Id") != "" {
			ids = append(ids, n.attr("Id"))
		}
	})
	messages := make([]responseMessage, 0, len(ids))
	for _, encoded := range ids {
		itemID, part, ok := decodeAttachmentID(encoded)
		if !ok {
			messages = append(messages, responseMessage{err: errAttachmentNotFound})
			continue
		}
		item, err := h.space.GetItem(ctx, access, itemID)
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		var data []byte
		var headers map[string]string
		if part == contactPhotoPart {
			card := decodeCard(item.Data)
			if card == nil {
				messages = append(messages, responseMessage{err: errAttachmentNotFound})
				continue
			}
			setContactPhoto(card, nil, "")
			data, headers, err = encodeCard(card)
		} else {
			data, err = removeMIMEPart(item.Data, part)
			headers = model.ParseItemHeaders(data)
		}
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		updated, err := h.conditionalUpdate(ctx, access, item, data, headers)
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:RootItemId RootItemId="` + encodeID("i:", updated.ID) + `" RootItemChangeKey="` + strconv.FormatUint(updated.ModSeq, 10) + `"/>`})
	}
	return responses("DeleteAttachment", messages), nil
}

// conditionalUpdate replaces an item's content unless it changed since it
// was read.
func (h *Handler) conditionalUpdate(ctx context.Context, access service.AccessContext, item model.Item, data []byte, headers map[string]string) (model.Item, error) {
	if updater, ok := h.space.(service.ConditionalItemUpdater); ok {
		return updater.UpdateItemIfModSeq(ctx, access, item.ID, item.ModSeq, data, headers)
	}
	return h.space.UpdateItem(ctx, access, item.ID, data, headers)
}

// appendMIMEAttachment adds a base64 part to a message: inside an existing
// multipart/mixed body, or by wrapping a single-part body in a new one.
func appendMIMEAttachment(data []byte, name, contentType, contentID string, inline bool, content []byte) ([]byte, error) {
	headers, err := parseMIMEHeaders(data)
	if err != nil {
		return nil, err
	}
	header, body, lineBreak, separator, err := splitMIMEMessage(data)
	if err != nil {
		return nil, err
	}
	disposition := "attachment"
	if inline {
		disposition = "inline"
	}
	typeParams := map[string]string{}
	dispositionParams := map[string]string{}
	if name != "" {
		typeParams["name"], dispositionParams["filename"] = name, name
	}
	var part strings.Builder
	part.WriteString("Content-Type: " + mime.FormatMediaType(contentType, typeParams) + lineBreak)
	part.WriteString("Content-Disposition: " + mime.FormatMediaType(disposition, dispositionParams) + lineBreak)
	if contentID != "" {
		part.WriteString("Content-ID: <" + strings.Trim(contentID, "<>") + ">" + lineBreak)
	}
	part.WriteString("Content-Transfer-Encoding: base64" + lineBreak + lineBreak)
	encoded := base64.StdEncoding.EncodeToString(content)
	for len(encoded) > 76 {
		part.WriteString(encoded[:76] + lineBreak)
		encoded = encoded[76:]
	}
	part.WriteString(encoded + lineBreak)

	mediaType, params, _ := mime.ParseMediaType(headers["Content-Type"])
	if strings.EqualFold(mediaType, "multipart/mixed") && params["boundary"] != "" {
		closing := []byte("--" + params["boundary"] + "--")
		index := bytes.LastIndex(body, closing)
		if index < 0 {
			return nil, errors.New("multipart message has no closing boundary")
		}
		result := make([]byte, 0, len(data)+part.Len()+len(params["boundary"])+8)
		result = append(result, header...)
		result = append(result, separator...)
		result = append(result, body[:index]...)
		result = append(result, "--"+params["boundary"]+lineBreak...)
		result = append(result, part.String()...)
		result = append(result, body[index:]...)
		return result, nil
	}
	boundary := newBoundary()
	innerType := headers["Content-Type"]
	if innerType == "" {
		innerType = "text/plain; charset=us-ascii"
	}
	mimeVersion, outerType := "1.0", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": boundary})
	rewritten, err := rewriteMIMEHeaders(data, map[string]*string{"MIME-Version": &mimeVersion, "Content-Type": &outerType, "Content-Transfer-Encoding": nil})
	if err != nil {
		return nil, err
	}
	outerHeader, _, _, _, err := splitMIMEMessage(rewritten)
	if err != nil {
		return nil, err
	}
	var result bytes.Buffer
	result.Write(outerHeader)
	result.Write(separator)
	result.WriteString("--" + boundary + lineBreak + "Content-Type: " + innerType + lineBreak)
	if encoding := headers["Content-Transfer-Encoding"]; encoding != "" {
		result.WriteString("Content-Transfer-Encoding: " + encoding + lineBreak)
	}
	result.WriteString(lineBreak)
	result.Write(body)
	result.WriteString(lineBreak + "--" + boundary + lineBreak + part.String() + "--" + boundary + "--" + lineBreak)
	return result.Bytes(), nil
}

func newBoundary() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return "veksel-" + hex.EncodeToString(value)
}

// removeMIMEPart removes a direct child part ("1.N") of a top-level
// multipart body, keeping every other byte of the message.
func removeMIMEPart(data []byte, partID string) ([]byte, error) {
	index, err := strconv.Atoi(strings.TrimPrefix(partID, "1."))
	if !strings.HasPrefix(partID, "1.") || err != nil || index < 1 {
		return nil, fmt.Errorf("%w: only top-level attachments can be deleted", errEWSInvalidProperty)
	}
	headers, err := parseMIMEHeaders(data)
	if err != nil {
		return nil, err
	}
	mediaType, params, _ := mime.ParseMediaType(headers["Content-Type"])
	if !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") || params["boundary"] == "" {
		return nil, errAttachmentNotFound
	}
	header, body, _, separator, err := splitMIMEMessage(data)
	if err != nil {
		return nil, err
	}
	delimiter := []byte("--" + params["boundary"])
	// Delimiters start a line: at the start of the body or after a line break.
	var starts []int
	for offset := 0; offset < len(body); {
		position := bytes.Index(body[offset:], delimiter)
		if position < 0 {
			break
		}
		position += offset
		if position == 0 || body[position-1] == '\n' {
			starts = append(starts, position)
		}
		offset = position + len(delimiter)
	}
	if index >= len(starts) {
		return nil, errAttachmentNotFound
	}
	from, to := starts[index-1], starts[index]
	result := make([]byte, 0, len(data))
	result = append(result, header...)
	result = append(result, separator...)
	result = append(result, body[:from]...)
	result = append(result, body[to:]...)
	return result, nil
}
