package service

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	MaxSubmissionAttachments     = 20
	MaxSubmissionInlineImages    = 40
	MaxSubmissionAttachmentBytes = 25 << 20
	MaxSubmissionAttachmentTotal = 50 << 20
)

var submissionContentID = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)

// BuildSubmissionMIME validates attachments and returns a top-level content
// type plus the body bytes that follow the RFC 5322 header block.
//
// A plain message is text/plain (or multipart/mixed with attachments). An
// HTML message is sanitized with the composer allowlist and sent as
// multipart/alternative with a generated text/plain part; inline images
// (attachments with a ContentID referenced as cid: by the HTML) join the HTML
// in multipart/related. Inline images the HTML no longer references are
// dropped, so removing an image from the editor removes its part.
func BuildSubmissionMIME(body, htmlBody string, attachments []SubmissionAttachment) (string, []byte, error) {
	if strings.TrimSpace(htmlBody) != "" {
		htmlBody = SanitizeComposeHTML(htmlBody)
		body = HTMLToText(htmlBody)
	} else {
		htmlBody = ""
	}
	files, inline, err := splitSubmissionAttachments(htmlBody, attachments)
	if err != nil {
		return "", nil, err
	}
	if htmlBody == "" && len(files) == 0 {
		return "text/plain; charset=utf-8", []byte(body), nil
	}
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)
	if htmlBody == "" {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", "text/plain; charset=utf-8")
		header.Set("Content-Transfer-Encoding", "8bit")
		part, err := writer.CreatePart(header)
		if err != nil {
			return "", nil, err
		}
		_, _ = io.WriteString(part, body)
	} else {
		alternativeType, alternative, err := buildAlternativeMIME(body, htmlBody, inline)
		if err != nil {
			return "", nil, err
		}
		if len(files) == 0 {
			return alternativeType, alternative, nil
		}
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", alternativeType)
		part, err := writer.CreatePart(header)
		if err != nil {
			return "", nil, err
		}
		_, _ = part.Write(alternative)
	}
	for _, attachment := range files {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", mime.FormatMediaType(attachment.ContentType, map[string]string{"name": attachment.Name}))
		header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": attachment.Name}))
		if err := writeBase64Part(writer, header, attachment.Data); err != nil {
			return "", nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return "", nil, err
	}
	return mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": writer.Boundary()}), output.Bytes(), nil
}

// splitSubmissionAttachments validates names, sizes, and counts and returns
// regular attachments plus the inline images the HTML references.
func splitSubmissionAttachments(htmlBody string, attachments []SubmissionAttachment) ([]SubmissionAttachment, []SubmissionAttachment, error) {
	var files, inline []SubmissionAttachment
	total := 0
	for _, attachment := range attachments {
		name := filepath.Base(strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(attachment.Name)))
		if name == "" || name == "." {
			return nil, nil, errors.New("attachment name is required")
		}
		if len(attachment.Data) > MaxSubmissionAttachmentBytes {
			return nil, nil, fmt.Errorf("attachment %q exceeds %d bytes", name, MaxSubmissionAttachmentBytes)
		}
		mediaType := strings.TrimSpace(attachment.ContentType)
		if parsed, _, parseErr := mime.ParseMediaType(mediaType); parseErr != nil || parsed == "" {
			mediaType = "application/octet-stream"
		} else {
			mediaType = parsed
		}
		contentID := strings.Trim(strings.TrimSpace(attachment.ContentID), "<>")
		if contentID != "" {
			if !submissionContentID.MatchString(contentID) || !strings.HasPrefix(mediaType, "image/") {
				return nil, nil, fmt.Errorf("inline image %q needs an image type and a simple Content-ID", name)
			}
			if htmlBody == "" || !strings.Contains(htmlBody, `"cid:`+contentID+`"`) {
				continue
			}
		}
		total += len(attachment.Data)
		if total > MaxSubmissionAttachmentTotal {
			return nil, nil, fmt.Errorf("attachments exceed %d bytes in total", MaxSubmissionAttachmentTotal)
		}
		clean := SubmissionAttachment{Name: name, ContentType: mediaType, ContentID: contentID, Size: int64(len(attachment.Data)), Data: attachment.Data}
		if contentID != "" {
			inline = append(inline, clean)
		} else {
			files = append(files, clean)
		}
	}
	if len(files) > MaxSubmissionAttachments {
		return nil, nil, fmt.Errorf("at most %d attachments are allowed", MaxSubmissionAttachments)
	}
	if len(inline) > MaxSubmissionInlineImages {
		return nil, nil, fmt.Errorf("at most %d inline images are allowed", MaxSubmissionInlineImages)
	}
	return files, inline, nil
}

func buildAlternativeMIME(text, htmlBody string, inline []SubmissionAttachment) (string, []byte, error) {
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)
	if err := writeQuotedPrintablePart(writer, "text/plain; charset=utf-8", text); err != nil {
		return "", nil, err
	}
	if len(inline) == 0 {
		if err := writeQuotedPrintablePart(writer, "text/html; charset=utf-8", htmlBody); err != nil {
			return "", nil, err
		}
	} else {
		var related bytes.Buffer
		relatedWriter := multipart.NewWriter(&related)
		if err := writeQuotedPrintablePart(relatedWriter, "text/html; charset=utf-8", htmlBody); err != nil {
			return "", nil, err
		}
		for _, image := range inline {
			header := make(textproto.MIMEHeader)
			header.Set("Content-Type", mime.FormatMediaType(image.ContentType, map[string]string{"name": image.Name}))
			header.Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": image.Name}))
			header.Set("Content-ID", "<"+image.ContentID+">")
			if err := writeBase64Part(relatedWriter, header, image.Data); err != nil {
				return "", nil, err
			}
		}
		if err := relatedWriter.Close(); err != nil {
			return "", nil, err
		}
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", mime.FormatMediaType("multipart/related", map[string]string{"type": "text/html", "boundary": relatedWriter.Boundary()}))
		part, err := writer.CreatePart(header)
		if err != nil {
			return "", nil, err
		}
		_, _ = part.Write(related.Bytes())
	}
	if err := writer.Close(); err != nil {
		return "", nil, err
	}
	return mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": writer.Boundary()}), output.Bytes(), nil
}

func writeQuotedPrintablePart(writer *multipart.Writer, contentType, value string) error {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	encoder := quotedprintable.NewWriter(part)
	if _, err := io.WriteString(encoder, value); err != nil {
		return err
	}
	return encoder.Close()
}

func writeBase64Part(writer *multipart.Writer, header textproto.MIMEHeader, data []byte) error {
	header.Set("Content-Transfer-Encoding", "base64")
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	for len(encoded) > 76 {
		_, _ = part.Write(encoded[:76])
		_, _ = part.Write([]byte("\r\n"))
		encoded = encoded[76:]
	}
	_, _ = part.Write(encoded)
	_, err = part.Write([]byte("\r\n"))
	return err
}

// ParseSubmissionMIME projects a saved draft back to the composer model,
// including its HTML body and inline images.
func ParseSubmissionMIME(raw []byte) (Submission, error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Submission{}, err
	}
	result := Submission{From: message.Header.Get("From"), Subject: message.Header.Get("Subject"), Mode: SendMode(message.Header.Get("X-Veksel-Send-Mode")), RequireTLS: strings.EqualFold(strings.TrimSpace(message.Header.Get("X-Veksel-Require-TLS")), "true"), Importance: MessageImportance(map[string]string{
		"Importance": message.Header.Get("Importance"), "X-Priority": message.Header.Get("X-Priority"), "Priority": message.Header.Get("Priority"),
	}), ReadReceipt: strings.TrimSpace(message.Header.Get("Disposition-Notification-To")) != ""}
	if result.Mode != SendAs && result.Mode != SendOnBehalf {
		result.Mode = SendNormal
	}
	parseList := func(name string) []string {
		if value := message.Header.Get(name); value != "" {
			return []string{value}
		}
		return nil
	}
	result.To, result.CC, result.BCC = parseList("To"), parseList("Cc"), parseList("Bcc")
	parser := submissionParser{result: &result}
	if err := parser.walk(textproto.MIMEHeader(message.Header), message.Body, 0); err != nil {
		return Submission{}, err
	}
	return result, nil
}

type submissionParser struct {
	result      *Submission
	parts       int
	seenText    bool
	seenHTML    bool
	totalBytes  int
	unnamedPart int
}

func (p *submissionParser) walk(header textproto.MIMEHeader, body io.Reader, depth int) error {
	if depth > MaxMIMEDepth {
		return errors.New("MIME nesting exceeds supported depth")
	}
	if p.parts++; p.parts > MaxMIMEParts {
		return errors.New("MIME message has too many parts")
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		parts := multipart.NewReader(body, params["boundary"])
		for {
			part, nextErr := parts.NextRawPart()
			if errors.Is(nextErr, io.EOF) {
				return nil
			}
			if nextErr != nil {
				return nextErr
			}
			err := p.walk(part.Header, part, depth+1)
			_ = part.Close()
			if err != nil {
				return err
			}
		}
	}
	const limit = MaxSubmissionAttachmentTotal + MaxMIMEBodyBytes
	data, err := io.ReadAll(io.LimitReader(model.TransferDecoder(body, header.Get("Content-Transfer-Encoding")), int64(limit+1-p.totalBytes)))
	if err != nil {
		return err
	}
	if p.totalBytes += len(data); p.totalBytes > limit {
		return errors.New("draft content is too large")
	}
	disposition, dispositionParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := firstNonEmptyString(dispositionParams["filename"], params["name"])
	contentID := strings.Trim(strings.TrimSpace(header.Get("Content-ID")), "<>")
	isBody := filename == "" && contentID == "" && !strings.EqualFold(disposition, "attachment")
	switch {
	case isBody && mediaType == "text/plain" && !p.seenText:
		p.seenText = true
		p.result.Body = strings.ReplaceAll(string(data), "\r\n", "\n")
	case isBody && mediaType == "text/html" && !p.seenHTML:
		p.seenHTML = true
		p.result.HTML = strings.ReplaceAll(string(data), "\r\n", "\n")
	default:
		if filename == "" {
			p.unnamedPart++
			extension := ""
			if extensions, _ := mime.ExtensionsByType(mediaType); len(extensions) > 0 {
				extension = extensions[0]
			}
			filename = "part-" + strconv.Itoa(p.unnamedPart) + extension
		}
		p.result.Attachments = append(p.result.Attachments, SubmissionAttachment{Name: filename, ContentType: mediaType, ContentID: contentID, Size: int64(len(data)), Data: data})
	}
	return nil
}
