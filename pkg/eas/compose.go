package eas

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// maxSentClientIDs bounds the remembered SendMail ClientIds that let a
// retried submission be recognized instead of sent twice.
const maxSentClientIDs = 64

// statusMessagePreviouslySent is MS-ASCMD 2.2.2 status 118.
const statusMessagePreviouslySent = "118"

// outgoing is one message submission parsed from SendMail, SmartReply or
// SmartForward in either the WBXML (14.0+) or plain MIME (12.1) form.
type outgoing struct {
	clientID    string
	mime        []byte
	replaceMIME bool
	sourceItem  string
	sourceLong  string
}

func parseOutgoing(command *commandContext, root string) (outgoing, string) {
	if command.raw != nil {
		return outgoing{mime: command.raw, sourceItem: command.line.ItemID, sourceLong: command.line.LongID}, ""
	}
	request := command.request
	if request == nil || request.Tag != root {
		return outgoing{}, statusInvalidContent
	}
	message := outgoing{clientID: childText(request, "ClientId"), replaceMIME: request.Child("ReplaceMime") != nil}
	if node := request.Child("MIME"); node != nil {
		message.mime = node.Opaque
		if message.mime == nil {
			message.mime = []byte(node.Text)
		}
	}
	if source := request.Child("Source"); source != nil {
		message.sourceItem = childText(source, "ItemId")
		message.sourceLong = childText(source, "LongId")
	}
	if len(message.mime) == 0 {
		return outgoing{}, statusInvalidMIME
	}
	return message, ""
}

func (h *Handler) sendMail(command *commandContext) (*Node, error) {
	message, status := parseOutgoing(command, "SendMail")
	if status != "" {
		return statusResponse("SendMail", status), nil
	}
	return h.submitOutgoing(command, "SendMail", message, message.mime)
}

func (h *Handler) submitOutgoing(command *commandContext, root string, message outgoing, raw []byte) (*Node, error) {
	if h.submit == nil {
		return statusResponse(root, statusMailSubmissionFailed), nil
	}
	if message.clientID != "" && slices.Contains(command.state.SentClientIDs, message.clientID) {
		return statusResponse(root, statusMessagePreviouslySent), nil
	}
	prepared, err := h.prepareOutgoing(command, raw)
	if err != nil {
		return statusResponse(root, statusInvalidMIME), nil
	}
	if err := h.submit(command.ctx, command.userID, prepared); err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return statusResponse(root, statusServerErrorRetry), nil
		}
		return statusResponse(root, statusMailSubmissionFailed), nil
	}
	if message.clientID != "" {
		command.state.SentClientIDs = append(command.state.SentClientIDs, message.clientID)
		if excess := len(command.state.SentClientIDs) - maxSentClientIDs; excess > 0 {
			command.state.SentClientIDs = command.state.SentClientIDs[excess:]
		}
	}
	return nil, nil
}

// prepareOutgoing completes a client message: a From address when the
// client left it to the server, and Date and Message-ID when absent.
func (h *Handler) prepareOutgoing(command *commandContext, raw []byte) ([]byte, error) {
	header, body, err := splitMessage(raw)
	if err != nil {
		return nil, err
	}
	profile := h.profile(command)
	var additions []string
	if header.Get("From") == "" {
		if profile.primary() == "" {
			return nil, fmt.Errorf("message has no From address")
		}
		additions = append(additions, "From: "+(&mail.Address{Name: profile.DisplayName, Address: profile.primary()}).String())
	}
	if header.Get("Date") == "" {
		additions = append(additions, "Date: "+time.Now().Format(time.RFC1123Z))
	}
	if header.Get("Message-Id") == "" {
		domain := "veksel.invalid"
		if from, parseErr := mail.ParseAddress(firstNonEmpty(header.Get("From"), profile.primary())); parseErr == nil {
			if _, host, ok := strings.Cut(from.Address, "@"); ok {
				domain = host
			}
		}
		additions = append(additions, "Message-ID: <"+randomToken()+"@"+domain+">")
	}
	if len(additions) == 0 {
		return raw, nil
	}
	var output bytes.Buffer
	for _, line := range additions {
		output.WriteString(line + "\r\n")
	}
	output.Write(header.raw)
	output.Write(body)
	return output.Bytes(), nil
}

func randomToken() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}

// rawHeader is a parsed header block that keeps its original bytes.
type rawHeader struct {
	textproto.MIMEHeader
	raw []byte
}

// splitMessage separates the header block (including the blank line) from
// the body without re-encoding either.
func splitMessage(raw []byte) (rawHeader, []byte, error) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	header, err := reader.ReadMIMEHeader()
	if err != nil && len(header) == 0 {
		return rawHeader{}, nil, err
	}
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	separator := 4
	if lf := bytes.Index(raw, []byte("\n\n")); lf >= 0 && (end < 0 || lf < end) {
		end, separator = lf, 2
	}
	if end < 0 {
		return rawHeader{MIMEHeader: header, raw: raw}, nil, nil
	}
	return rawHeader{MIMEHeader: header, raw: raw[:end+separator]}, raw[end+separator:], nil
}

func (h *Handler) smartSend(command *commandContext) (*Node, error) {
	root := command.line.Command
	message, status := parseOutgoing(command, root)
	if status != "" {
		return statusResponse(root, status), nil
	}
	sourceID := firstNonEmpty(message.sourceItem, message.sourceLong)
	itemID, err := decodeServerID(sourceID, "i:")
	if err != nil {
		return statusResponse(root, statusItemNotFound), nil
	}
	source, err := h.space.GetItem(command.ctx, command.access, itemID)
	if err != nil {
		return statusResponse(root, statusItemNotFound), nil
	}
	reply := root == "SmartReply"
	raw := message.mime
	if reply {
		raw = addThreadingHeaders(raw, source.Data)
	}
	if !message.replaceMIME {
		if composed, composeErr := appendOriginal(raw, source, !reply); composeErr == nil {
			raw = composed
		}
	}
	response, err := h.submitOutgoing(command, root, message, raw)
	if err != nil || response != nil {
		return response, err
	}
	flag := model.FlagAnswered
	if !reply {
		flag = "$Forwarded"
	}
	if !hasFlag(source.Flags, flag) {
		if _, flagErr := h.space.SetFlags(command.ctx, command.access, source.ID, setFlag(source.Flags, flag, true)); flagErr == nil {
			// The flag change reaches the device through the journal.
			_ = flagErr
		}
	}
	return nil, nil
}

// addThreadingHeaders sets In-Reply-To and References from the original
// when the client did not.
func addThreadingHeaders(raw, original []byte) []byte {
	header, body, err := splitMessage(raw)
	if err != nil || header.Get("In-Reply-To") != "" {
		return raw
	}
	originalHeader, _, err := splitMessage(original)
	if err != nil {
		return raw
	}
	messageID := strings.TrimSpace(originalHeader.Get("Message-Id"))
	if messageID == "" {
		return raw
	}
	references := strings.TrimSpace(strings.Join(strings.Fields(originalHeader.Get("References")+" "+messageID), " "))
	var output bytes.Buffer
	output.WriteString("In-Reply-To: " + messageID + "\r\n")
	if header.Get("References") == "" {
		output.WriteString("References: " + references + "\r\n")
	}
	output.Write(header.raw)
	output.Write(body)
	return output.Bytes()
}

// appendOriginal implements SmartReply and SmartForward without
// ReplaceMime: the original message's text is appended to the client's
// text and HTML bodies, and a forward also carries the original
// attachments.
func appendOriginal(raw []byte, source model.Item, forward bool) ([]byte, error) {
	original, err := service.ProjectMIME(source.Data)
	if err != nil {
		return nil, err
	}
	text := original.Text
	if text == "" && original.HTML != "" {
		text = service.HTMLToText(original.HTML)
	}
	block := []string{"-----Original Message-----"}
	for _, name := range []string{"From", "Date", "To", "Cc", "Subject"} {
		if value := original.Headers[name]; value != "" {
			label := name
			if name == "Date" {
				label = "Sent"
			}
			block = append(block, label+": "+value)
		}
	}
	plain := "\r\n\r\n" + strings.Join(block, "\r\n") + "\r\n\r\n" + strings.ReplaceAll(text, "\n", "\r\n")
	htmlQuote := "<br><br><div>" + strings.ReplaceAll(html.EscapeString(strings.Join(block, "\n")), "\n", "<br>") + "</div><br>"
	if original.HTML != "" {
		htmlQuote += "<blockquote>" + original.HTML + "</blockquote>"
	} else {
		htmlQuote += "<blockquote>" + strings.ReplaceAll(html.EscapeString(text), "\n", "<br>") + "</blockquote>"
	}
	header, body, err := splitMessage(raw)
	if err != nil {
		return nil, err
	}
	rewritten, err := appendToBodies(textproto.MIMEHeader(header.MIMEHeader), body, plain, htmlQuote, new(bool), new(bool), 0)
	if err != nil {
		return nil, err
	}
	var attachments []rawPart
	if !forward {
		attachments = nil
	} else {
		attachments, _ = attachmentParts(source.Data)
	}
	outputHeader := filterHeader(header.raw, rewritten.header)
	if len(attachments) == 0 {
		return append(outputHeader, rewritten.body...), nil
	}
	// Wrap the rewritten entity and the original attachments.
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)
	inner := textproto.MIMEHeader{}
	for _, name := range []string{"Content-Type", "Content-Transfer-Encoding"} {
		if value := rewritten.header.Get(name); value != "" {
			inner.Set(name, value)
		}
	}
	if inner.Get("Content-Type") == "" {
		inner.Set("Content-Type", "text/plain; charset=utf-8")
	}
	part, _ := writer.CreatePart(inner)
	_, _ = part.Write(rewritten.body)
	for _, attachment := range attachments {
		part, _ := writer.CreatePart(attachment.header)
		_, _ = part.Write(attachment.body)
	}
	_ = writer.Close()
	mixed := textproto.MIMEHeader{}
	mixed.Set("Content-Type", "multipart/mixed; boundary=\""+writer.Boundary()+"\"")
	mixed.Del("Content-Transfer-Encoding")
	return append(filterHeader(header.raw, mixed), output.Bytes()...), nil
}

// filterHeader rewrites the entity headers of a message header block while
// keeping every other header line verbatim.
func filterHeader(raw []byte, entity textproto.MIMEHeader) []byte {
	var output bytes.Buffer
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	skip := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !skip {
				output.WriteString(line + "\r\n")
			}
			continue
		}
		name, _, _ := strings.Cut(line, ":")
		canonical := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
		skip = canonical == "Content-Type" || canonical == "Content-Transfer-Encoding"
		if !skip {
			output.WriteString(line + "\r\n")
		}
	}
	if output.Len() == 0 || !strings.Contains(strings.ToLower(output.String()), "mime-version:") {
		output.WriteString("MIME-Version: 1.0\r\n")
	}
	for _, name := range []string{"Content-Type", "Content-Transfer-Encoding"} {
		if value := entity.Get(name); value != "" {
			output.WriteString(name + ": " + value + "\r\n")
		}
	}
	output.WriteString("\r\n")
	return output.Bytes()
}

type rawPart struct {
	header textproto.MIMEHeader
	body   []byte
}

type rewrittenEntity struct {
	header textproto.MIMEHeader
	body   []byte
}

// appendToBodies appends text to the first text/plain and html to the first
// text/html body part, recursing through multipart containers and leaving
// attachments untouched.
func appendToBodies(header textproto.MIMEHeader, body []byte, text, htmlText string, doneText, doneHTML *bool, depth int) (rewrittenEntity, error) {
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || header.Get("Content-Type") == "" {
		mediaType, params = "text/plain", map[string]string{"charset": "us-ascii"}
	}
	disposition, _, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	if strings.EqualFold(disposition, "attachment") || depth > service.MaxMIMEDepth {
		return rewrittenEntity{header: header, body: body}, nil
	}
	switch {
	case strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "":
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		var output bytes.Buffer
		writer := multipart.NewWriter(&output)
		if err := writer.SetBoundary(params["boundary"]); err != nil {
			return rewrittenEntity{}, err
		}
		for {
			part, err := reader.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return rewrittenEntity{}, err
			}
			content, err := io.ReadAll(part)
			if err != nil {
				return rewrittenEntity{}, err
			}
			child, err := appendToBodies(part.Header, content, text, htmlText, doneText, doneHTML, depth+1)
			if err != nil {
				return rewrittenEntity{}, err
			}
			destination, err := writer.CreatePart(child.header)
			if err != nil {
				return rewrittenEntity{}, err
			}
			_, _ = destination.Write(child.body)
		}
		_ = writer.Close()
		return rewrittenEntity{header: header, body: output.Bytes()}, nil
	case mediaType == "text/plain" && !*doneText, mediaType == "text/html" && !*doneHTML:
		charset := strings.ToLower(params["charset"])
		if charset != "" && charset != "utf-8" && charset != "us-ascii" {
			return rewrittenEntity{header: header, body: body}, nil
		}
		decoded, err := io.ReadAll(model.TransferDecoder(bytes.NewReader(body), header.Get("Content-Transfer-Encoding")))
		if err != nil {
			return rewrittenEntity{header: header, body: body}, nil
		}
		content := string(decoded)
		if mediaType == "text/plain" {
			content += text
			*doneText = true
		} else {
			if index := strings.LastIndex(strings.ToLower(content), "</body>"); index >= 0 {
				content = content[:index] + htmlText + content[index:]
			} else {
				content += htmlText
			}
			*doneHTML = true
		}
		var encoded bytes.Buffer
		writer := quotedprintable.NewWriter(&encoded)
		_, _ = writer.Write([]byte(content))
		_ = writer.Close()
		updated := textproto.MIMEHeader{}
		for key, values := range header {
			updated[key] = slices.Clone(values)
		}
		params["charset"] = "utf-8"
		updated.Set("Content-Type", mime.FormatMediaType(mediaType, params))
		updated.Set("Content-Transfer-Encoding", "quoted-printable")
		return rewrittenEntity{header: updated, body: encoded.Bytes()}, nil
	}
	return rewrittenEntity{header: header, body: body}, nil
}

// attachmentParts returns the raw attachment leaves of a message.
func attachmentParts(data []byte) ([]rawPart, error) {
	header, body, err := splitMessage(data)
	if err != nil {
		return nil, err
	}
	var parts []rawPart
	var walk func(textproto.MIMEHeader, []byte, int)
	walk = func(header textproto.MIMEHeader, body []byte, depth int) {
		mediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
		if depth > service.MaxMIMEDepth || len(parts) >= service.MaxMIMEParts {
			return
		}
		if strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
			reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			for {
				part, err := reader.NextRawPart()
				if err != nil {
					return
				}
				content, err := io.ReadAll(part)
				if err != nil {
					return
				}
				walk(part.Header, content, depth+1)
			}
		}
		disposition, dispositionParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
		named := dispositionParams["filename"] != "" || params["name"] != ""
		if depth > 0 && (strings.EqualFold(disposition, "attachment") || named || !strings.HasPrefix(mediaType, "text/") && !strings.HasPrefix(mediaType, "multipart/")) {
			parts = append(parts, rawPart{header: header, body: body})
		}
	}
	walk(header.MIMEHeader, body, 0)
	return parts, nil
}

// draftFromEAS renders 16.0 draft ApplicationData as a MIME message,
// keeping the attachments of the draft it replaces.
func (h *Handler) draftFromEAS(command *commandContext, existing []byte, data *Node) ([]byte, map[string]string, error) {
	profile := h.profile(command)
	headers := map[string]string{}
	var output bytes.Buffer
	write := func(name, value string) {
		if value = strings.TrimSpace(value); value != "" {
			output.WriteString(name + ": " + mime.QEncoding.Encode("utf-8", value) + "\r\n")
			headers[name] = value
		}
	}
	if profile.primary() != "" {
		output.WriteString("From: " + (&mail.Address{Name: profile.DisplayName, Address: profile.primary()}).String() + "\r\n")
	}
	output.WriteString("To: " + childText(data, "To") + "\r\n")
	if cc := childText(data, "Cc"); cc != "" {
		output.WriteString("Cc: " + cc + "\r\n")
	}
	if bcc := childText(data, "Bcc"); bcc != "" {
		output.WriteString("Bcc: " + bcc + "\r\n")
	}
	write("Subject", childText(data, "Subject"))
	switch childText(data, "Importance") {
	case "0":
		write("Importance", "low")
	case "2":
		write("Importance", "high")
	}
	output.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\n")
	mediaType, content := "text/plain", ""
	if body := data.Child("Body"); body != nil {
		content = nodeValue(body.Child("Data"))
		if childText(body, "Type") == "2" {
			mediaType = "text/html"
		}
	}
	var encoded bytes.Buffer
	writer := quotedprintable.NewWriter(&encoded)
	_, _ = writer.Write([]byte(content))
	_ = writer.Close()
	var attachments []rawPart
	if existing != nil {
		attachments, _ = attachmentParts(existing)
	}
	if len(attachments) == 0 {
		output.WriteString("Content-Type: " + mediaType + "; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
		output.Write(encoded.Bytes())
		return output.Bytes(), headers, nil
	}
	var mixed bytes.Buffer
	multi := multipart.NewWriter(&mixed)
	part, _ := multi.CreatePart(textproto.MIMEHeader{"Content-Type": {mediaType + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
	_, _ = part.Write(encoded.Bytes())
	for _, attachment := range attachments {
		part, _ := multi.CreatePart(attachment.header)
		_, _ = part.Write(attachment.body)
	}
	_ = multi.Close()
	output.WriteString("Content-Type: multipart/mixed; boundary=\"" + multi.Boundary() + "\"\r\n\r\n")
	output.Write(mixed.Bytes())
	return output.Bytes(), headers, nil
}
