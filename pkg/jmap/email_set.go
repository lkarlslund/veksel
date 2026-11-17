package jmap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Email/set (RFC 8621 §4.6): creation builds a MIME message from the
// Email's header and body properties; updates take keywords and mailboxIds
// as whole values or as patch paths.

// emailServerSet are Email properties a client may not set.
var emailServerSet = map[string]bool{"id": true, "blobId": true, "threadId": true, "size": true, "hasAttachment": true, "preview": true}

func (h *Handler) emailSet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string) (any, *MethodError) {
	var a setArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if len(a.Create)+len(a.Update)+len(a.Destroy) > maxObjectsInSet {
		return nil, &MethodError{Type: "requestTooLarge", Description: fmt.Sprintf("at most %d objects per call", maxObjectsInSet)}
	}
	access, e := h.validateAccount(ctx, actor, a.AccountID)
	if e != nil {
		return nil, e
	}
	oldState, stateErr := h.journalState(ctx, access, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	if a.IfInState != "" && a.IfInState != oldState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	result := newSetResult(a.AccountID, oldState)
	for _, cid := range sortedKeys(a.Create) {
		item, e := h.createEmail(ctx, access, a.Create[cid], created)
		if e != nil {
			result.notCreated[cid] = *e
			continue
		}
		created[cid] = item.ID
		result.created[cid] = map[string]any{"id": item.ID, "blobId": item.ID, "threadId": threadForData(item.Data), "size": item.Size}
	}
	for _, key := range sortedKeys(a.Update) {
		if e := h.updateEmail(ctx, access, resolveCreated(key, created), a.Update[key], created); e != nil {
			result.notUpdated[key] = *e
			continue
		}
		result.updated[key] = nil
	}
	for _, key := range a.Destroy {
		if err := h.destroyMailItem(ctx, access, resolveCreated(key, created)); err != nil {
			result.notDestroyed[key] = *serverError(err)
			continue
		}
		result.destroyed = append(result.destroyed, key)
	}
	newState, stateErr := h.journalState(ctx, access, service.ChangeObjectItem)
	if stateErr != nil {
		return nil, serverError(stateErr)
	}
	return result.response(newState), nil
}

// destroyMailItem deletes an email of the account; ids of other objects
// (for example uploaded blobs) are notFound.
func (h *Handler) destroyMailItem(ctx context.Context, access service.AccessContext, id string) error {
	if items, err := h.mailItemsByID(ctx, access, []string{id}); err != nil {
		return err
	} else if len(items) == 0 {
		return store.ErrNotFound
	}
	return h.cfg.Space.DeleteItem(ctx, access, id)
}

type setResult struct {
	accountID    string
	oldState     string
	created      map[string]any
	notCreated   map[string]any
	updated      map[string]any
	notUpdated   map[string]any
	destroyed    []string
	notDestroyed map[string]any
}

func newSetResult(accountID, oldState string) *setResult {
	return &setResult{accountID: accountID, oldState: oldState, created: map[string]any{}, notCreated: map[string]any{},
		updated: map[string]any{}, notUpdated: map[string]any{}, destroyed: []string{}, notDestroyed: map[string]any{}}
}

func (r *setResult) response(newState string) map[string]any {
	return map[string]any{"accountId": r.accountID, "oldState": r.oldState, "newState": newState, "created": r.created,
		"notCreated": r.notCreated, "updated": r.updated, "notUpdated": r.notUpdated, "destroyed": r.destroyed, "notDestroyed": r.notDestroyed}
}

func invalidProperties(description string, properties ...string) *MethodError {
	return &MethodError{Type: "invalidProperties", Description: description, Properties: properties}
}

// singleMailbox returns the one mailbox of a mailboxIds value; this server
// stores each email in exactly one mailbox.
func singleMailbox(ids map[string]bool, created map[string]string) (string, *MethodError) {
	var chosen []string
	for id, on := range ids {
		if on {
			chosen = append(chosen, resolveCreated(id, created))
		}
	}
	if len(chosen) != 1 {
		return "", invalidProperties("an email must be in exactly one mailbox (maxMailboxesPerEmail is 1)", "mailboxIds")
	}
	return chosen[0], nil
}

func (h *Handler) createEmail(ctx context.Context, access service.AccessContext, raw json.RawMessage, created map[string]string) (model.Item, *MethodError) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return model.Item{}, invalidProperties("an Email must be a JSON object")
	}
	for name := range object {
		if emailServerSet[name] {
			return model.Item{}, invalidProperties(name+" is set by the server", name)
		}
	}
	var mailboxIDs map[string]bool
	if err := json.Unmarshal(object["mailboxIds"], &mailboxIDs); err != nil {
		return model.Item{}, invalidProperties("mailboxIds is required", "mailboxIds")
	}
	folderID, e := singleMailbox(mailboxIDs, created)
	if e != nil {
		return model.Item{}, e
	}
	var words map[string]bool
	if rawWords, ok := object["keywords"]; ok && json.Unmarshal(rawWords, &words) != nil {
		return model.Item{}, invalidProperties("keywords must map keywords to true", "keywords")
	}
	var received time.Time
	if rawDate, ok := object["receivedAt"]; ok {
		var value string
		var err error
		if json.Unmarshal(rawDate, &value) == nil {
			received, err = parseUTCDate(value)
		}
		if err != nil || value == "" {
			return model.Item{}, invalidProperties("receivedAt must be a UTCDate", "receivedAt")
		}
	}
	data, e := h.buildMessage(ctx, access, object)
	if e != nil {
		return model.Item{}, e
	}
	item, err := h.cfg.Space.CreateItem(ctx, access, folderID, service.ItemInput{Data: data, Headers: messageHeaders(data), Flags: keywordFlags(nil, words), InternalDate: received})
	if err != nil {
		return model.Item{}, serverError(err)
	}
	return item, nil
}

// creationPart is an EmailBodyPart in an Email/set create.
type creationPart struct {
	PartID      string          `json:"partId"`
	BlobID      string          `json:"blobId"`
	Type        string          `json:"type"`
	Charset     string          `json:"charset"`
	Disposition string          `json:"disposition"`
	CID         string          `json:"cid"`
	Language    []string        `json:"language"`
	Location    string          `json:"location"`
	Name        string          `json:"name"`
	Headers     []headerField   `json:"headers"`
	SubParts    []*creationPart `json:"subParts"`
	extra       map[string]json.RawMessage
}

func (p *creationPart) UnmarshalJSON(data []byte) error {
	type plain creationPart
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = creationPart(value)
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for key, raw := range all {
		if strings.HasPrefix(key, "header:") {
			if p.extra == nil {
				p.extra = map[string]json.RawMessage{}
			}
			p.extra[key] = raw
		}
	}
	return nil
}

// outPart is one entity of the message being built.
type outPart struct {
	header   []headerField // fields other than Content-Type/-Transfer-Encoding
	media    string
	params   map[string]string
	children []*outPart
	data     []byte
}

// buildMessage renders an Email creation object as RFC 5322 octets.
func (h *Handler) buildMessage(ctx context.Context, access service.AccessContext, object map[string]json.RawMessage) ([]byte, *MethodError) {
	var headers []headerField
	if raw, ok := object["headers"]; ok {
		if err := json.Unmarshal(raw, &headers); err != nil {
			return nil, invalidProperties("headers must be an array of EmailHeader", "headers")
		}
	}
	set := func(name, value string) {
		filtered := headers[:0]
		for _, field := range headers {
			if !strings.EqualFold(field.Name, name) {
				filtered = append(filtered, field)
			}
		}
		headers = append(filtered, headerField{Name: name, Value: value})
	}
	for _, property := range sortedKeys(object) {
		rawValue := object[property]
		if header, ok := convenienceHeaders[property]; ok {
			if string(rawValue) == "null" {
				continue
			}
			value, err := composeHeader(header.form, rawValue)
			if err != nil {
				return nil, invalidProperties(err.Error(), property)
			}
			set(header.name, value)
			continue
		}
		if !strings.HasPrefix(property, "header:") {
			continue
		}
		header, ok := parseHeaderProperty(property)
		if !ok || strings.HasPrefix(strings.ToLower(header.name), "content-") {
			return nil, invalidProperties("invalid header property", property)
		}
		values := []json.RawMessage{rawValue}
		if header.all {
			if err := json.Unmarshal(rawValue, &values); err != nil {
				return nil, invalidProperties("an :all header takes an array", property)
			}
		}
		filtered := headers[:0]
		for _, field := range headers {
			if !strings.EqualFold(field.Name, header.name) {
				filtered = append(filtered, field)
			}
		}
		headers = filtered
		for _, value := range values {
			composed, err := composeHeader(header.form, value)
			if err != nil {
				return nil, invalidProperties(err.Error(), property)
			}
			headers = append(headers, headerField{Name: header.name, Value: composed})
		}
	}
	if _, ok := lastHeader(headers, "Date"); !ok {
		headers = append(headers, headerField{Name: "Date", Value: time.Now().Format(time.RFC1123Z)})
	}
	if _, ok := lastHeader(headers, "Message-ID"); !ok {
		headers = append(headers, headerField{Name: "Message-ID", Value: "<" + newMessageID(headers) + ">"})
	}
	root, e := h.buildBody(ctx, access, object)
	if e != nil {
		return nil, e
	}
	var b bytes.Buffer
	for _, field := range headers {
		if strings.HasPrefix(strings.ToLower(field.Name), "content-") || strings.EqualFold(field.Name, "MIME-Version") {
			continue
		}
		writeField(&b, field.Name, field.Value)
	}
	writeField(&b, "MIME-Version", "1.0")
	renderPart(&b, root)
	return b.Bytes(), nil
}

func writeField(b *bytes.Buffer, name, value string) {
	value = strings.NewReplacer("\r\n", "\r\n", "\n", "\r\n").Replace(strings.TrimLeft(value, " "))
	b.WriteString(name + ": " + value + "\r\n")
}

// composeHeader renders a header property value in the given form.
func composeHeader(form string, raw json.RawMessage) (string, error) {
	switch form {
	case "asRaw":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || strings.ContainsAny(value, "\r\n") && !validFolding(value) {
			return "", fmt.Errorf("raw header value must be a string")
		}
		return value, nil
	case "asText":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("text header value must be a string")
		}
		return encodeWord(value), nil
	case "asAddresses":
		var list []address
		if err := json.Unmarshal(raw, &list); err != nil {
			return "", fmt.Errorf("address header value must be an array of EmailAddress")
		}
		return formatAddresses(list), nil
	case "asGroupedAddresses":
		var groups []emailAddressGroup
		if err := json.Unmarshal(raw, &groups); err != nil {
			return "", fmt.Errorf("grouped address header value must be an array of EmailAddressGroup")
		}
		parts := make([]string, 0, len(groups))
		for _, group := range groups {
			if group.Name == nil {
				parts = append(parts, formatAddresses(group.Addresses))
				continue
			}
			parts = append(parts, encodePhrase(*group.Name)+": "+formatAddresses(group.Addresses)+";")
		}
		return strings.Join(parts, ", "), nil
	case "asMessageIds":
		var ids []string
		if err := json.Unmarshal(raw, &ids); err != nil {
			return "", fmt.Errorf("message id header value must be an array of strings")
		}
		for i, id := range ids {
			if id == "" || strings.ContainsAny(id, "<> \t\r\n") {
				return "", fmt.Errorf("invalid message id %q", id)
			}
			ids[i] = "<" + id + ">"
		}
		return strings.Join(ids, " "), nil
	case "asDate":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("date header value must be a Date")
		}
		t, err := parseUTCDate(value)
		if err != nil {
			return "", fmt.Errorf("date header value must be a Date")
		}
		return t.Format(time.RFC1123Z), nil
	case "asURLs":
		var urls []string
		if err := json.Unmarshal(raw, &urls); err != nil {
			return "", fmt.Errorf("URL header value must be an array of strings")
		}
		for i, u := range urls {
			urls[i] = "<" + u + ">"
		}
		return strings.Join(urls, ", "), nil
	}
	return "", fmt.Errorf("unknown header form %s", form)
}

// validFolding reports whether every line break in a raw value is a fold.
func validFolding(value string) bool {
	for _, line := range strings.Split(value, "\r\n")[1:] {
		if line == "" || (line[0] != ' ' && line[0] != '\t') {
			return false
		}
	}
	return !strings.Contains(strings.ReplaceAll(value, "\r\n", ""), "\n")
}

func formatAddresses(list []address) string {
	parts := make([]string, 0, len(list))
	for _, a := range list {
		name := ""
		if a.Name != nil {
			name = *a.Name
		}
		parts = append(parts, (&mail.Address{Name: name, Address: a.Email}).String())
	}
	return strings.Join(parts, ", ")
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func encodeWord(value string) string {
	if isASCII(value) {
		return value
	}
	return mime.QEncoding.Encode("utf-8", value)
}

func encodePhrase(value string) string {
	if !isASCII(value) {
		return mime.QEncoding.Encode("utf-8", value)
	}
	if strings.ContainsAny(value, "()<>[]:;@\\,.\"") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	}
	return value
}

func newMessageID(headers []headerField) string {
	domain := "localhost"
	if from, ok := lastHeader(headers, "From"); ok {
		if list := parseAddressList(unfold(from)); len(list) > 0 {
			if _, host, found := strings.Cut(list[0].Email, "@"); found && host != "" {
				domain = host
			}
		}
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "@" + domain
}

// buildBody turns bodyStructure, or textBody/htmlBody/attachments, into
// the message's MIME tree.
func (h *Handler) buildBody(ctx context.Context, access service.AccessContext, object map[string]json.RawMessage) (*outPart, *MethodError) {
	var values map[string]bodyValue
	if raw, ok := object["bodyValues"]; ok {
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, invalidProperties("bodyValues must map part ids to EmailBodyValue", "bodyValues")
		}
		for partID, value := range values {
			if value.IsTruncated || value.IsEncodingProblem {
				return nil, invalidProperties("bodyValues "+partID+" may not be truncated or have an encoding problem", "bodyValues")
			}
		}
	}
	decodeParts := func(property string) ([]*creationPart, *MethodError) {
		raw, ok := object[property]
		if !ok || string(raw) == "null" {
			return nil, nil
		}
		var parts []*creationPart
		if err := json.Unmarshal(raw, &parts); err != nil {
			return nil, invalidProperties(property+" must be an array of EmailBodyPart", property)
		}
		return parts, nil
	}
	builder := partBuilder{h: h, ctx: ctx, access: access, values: values, used: map[string]bool{}}
	if raw, ok := object["bodyStructure"]; ok && string(raw) != "null" {
		for _, property := range []string{"textBody", "htmlBody", "attachments"} {
			if _, both := object[property]; both {
				return nil, invalidProperties("bodyStructure cannot be combined with "+property, "bodyStructure", property)
			}
		}
		var structure creationPart
		if err := json.Unmarshal(raw, &structure); err != nil {
			return nil, invalidProperties("bodyStructure must be an EmailBodyPart", "bodyStructure")
		}
		root, e := builder.build(&structure, "bodyStructure")
		if e != nil {
			return nil, e
		}
		return root, builder.unused()
	}
	textParts, e := decodeParts("textBody")
	if e != nil {
		return nil, e
	}
	htmlParts, e := decodeParts("htmlBody")
	if e != nil {
		return nil, e
	}
	attachments, e := decodeParts("attachments")
	if e != nil {
		return nil, e
	}
	if len(textParts) > 1 || len(textParts) == 1 && textParts[0].Type != "" && textParts[0].Type != "text/plain" {
		return nil, invalidProperties("textBody takes at most one text/plain part", "textBody")
	}
	if len(htmlParts) > 1 || len(htmlParts) == 1 && htmlParts[0].Type != "" && htmlParts[0].Type != "text/html" {
		return nil, invalidProperties("htmlBody takes at most one text/html part", "htmlBody")
	}
	var text, htmlPart *outPart
	if len(textParts) == 1 {
		textParts[0].Type = "text/plain"
		if text, e = builder.build(textParts[0], "textBody"); e != nil {
			return nil, e
		}
	}
	if len(htmlParts) == 1 {
		htmlParts[0].Type = "text/html"
		if htmlPart, e = builder.build(htmlParts[0], "htmlBody"); e != nil {
			return nil, e
		}
	}
	var inline, mixed []*outPart
	for _, attachment := range attachments {
		part, e := builder.build(attachment, "attachments")
		if e != nil {
			return nil, e
		}
		if htmlPart != nil && attachment.CID != "" && attachment.Disposition != "attachment" {
			inline = append(inline, part)
		} else {
			mixed = append(mixed, part)
		}
	}
	if len(inline) > 0 {
		htmlPart = &outPart{media: "multipart/related", children: append([]*outPart{htmlPart}, inline...)}
	}
	var body *outPart
	switch {
	case text != nil && htmlPart != nil:
		body = &outPart{media: "multipart/alternative", children: []*outPart{text, htmlPart}}
	case text != nil:
		body = text
	case htmlPart != nil:
		body = htmlPart
	default:
		body = &outPart{media: "text/plain", params: map[string]string{"charset": "utf-8"}}
	}
	if len(mixed) > 0 {
		body = &outPart{media: "multipart/mixed", children: append([]*outPart{body}, mixed...)}
	}
	return body, builder.unused()
}

type partBuilder struct {
	h      *Handler
	ctx    context.Context
	access service.AccessContext
	values map[string]bodyValue
	used   map[string]bool
}

func (b *partBuilder) unused() *MethodError {
	for partID := range b.values {
		if !b.used[partID] {
			return invalidProperties("bodyValues "+partID+" is not referenced by any part", "bodyValues")
		}
	}
	return nil
}

func (b *partBuilder) build(p *creationPart, property string) (*outPart, *MethodError) {
	media := strings.ToLower(p.Type)
	out := &outPart{media: media, params: map[string]string{}}
	for _, field := range p.Headers {
		lower := strings.ToLower(field.Name)
		if lower == "content-type" || lower == "content-transfer-encoding" {
			return nil, invalidProperties(field.Name+" is set by the server", property)
		}
		out.header = append(out.header, field)
	}
	for key, raw := range p.extra {
		header, ok := parseHeaderProperty(key)
		lower := strings.ToLower(header.name)
		if !ok || lower == "content-type" || lower == "content-transfer-encoding" || header.all {
			return nil, invalidProperties("invalid part header "+key, property)
		}
		value, err := composeHeader(header.form, raw)
		if err != nil {
			return nil, invalidProperties(err.Error(), property)
		}
		out.header = append(out.header, headerField{Name: header.name, Value: value})
	}
	if strings.HasPrefix(media, "multipart/") {
		if p.PartID != "" || p.BlobID != "" {
			return nil, invalidProperties("a multipart part has neither partId nor blobId", property)
		}
		for _, child := range p.SubParts {
			built, e := b.build(child, property)
			if e != nil {
				return nil, e
			}
			out.children = append(out.children, built)
		}
		return out, nil
	}
	switch {
	case p.PartID != "" && p.BlobID != "":
		return nil, invalidProperties("a part has either partId or blobId", property)
	case p.PartID != "":
		value, ok := b.values[p.PartID]
		if !ok {
			return nil, invalidProperties("no bodyValues entry for part "+p.PartID, property, "bodyValues")
		}
		b.used[p.PartID] = true
		if media == "" {
			media = "text/plain"
		}
		if !strings.HasPrefix(media, "text/") {
			return nil, invalidProperties("a bodyValues part must be text/*", property)
		}
		out.media = media
		out.params["charset"] = "utf-8"
		out.data = []byte(value.Value)
	case p.BlobID != "":
		data, contentType, err := b.h.blobData(b.ctx, b.access, p.BlobID)
		if err != nil {
			return nil, &MethodError{Type: "blobNotFound", Description: "blob " + p.BlobID + " not found", NotFound: []string{p.BlobID}}
		}
		if media == "" {
			media, _, _ = mime.ParseMediaType(contentType)
		}
		if media == "" {
			media = "application/octet-stream"
		}
		out.media = media
		if p.Charset != "" {
			out.params["charset"] = p.Charset
		}
		out.data = data
	default:
		return nil, invalidProperties("a part needs a partId or blobId", property)
	}
	if p.Name != "" && p.Disposition == "" {
		p.Disposition = "attachment"
	}
	if p.Disposition != "" {
		params := map[string]string{}
		if p.Name != "" {
			params["filename"] = p.Name
		}
		out.header = append(out.header, headerField{Name: "Content-Disposition", Value: mime.FormatMediaType(strings.ToLower(p.Disposition), params)})
	}
	if p.Name != "" {
		out.params["name"] = p.Name
	}
	if p.CID != "" {
		out.header = append(out.header, headerField{Name: "Content-ID", Value: "<" + strings.Trim(p.CID, "<>") + ">"})
	}
	if len(p.Language) > 0 {
		out.header = append(out.header, headerField{Name: "Content-Language", Value: strings.Join(p.Language, ", ")})
	}
	if p.Location != "" {
		out.header = append(out.header, headerField{Name: "Content-Location", Value: p.Location})
	}
	return out, nil
}

// renderPart writes an entity's MIME header fields, a blank line and its
// body. Text is quoted-printable unless it is short-lined ASCII; other
// content is base64.
func renderPart(b *bytes.Buffer, p *outPart) {
	params := p.params
	var boundary string
	if len(p.children) > 0 || strings.HasPrefix(p.media, "multipart/") {
		random := make([]byte, 12)
		_, _ = rand.Read(random)
		boundary = "=_" + hex.EncodeToString(random)
		params = map[string]string{"boundary": boundary}
	}
	contentType := mime.FormatMediaType(p.media, params)
	if contentType == "" {
		contentType = p.media
	}
	writeField(b, "Content-Type", contentType)
	for _, field := range p.header {
		writeField(b, field.Name, field.Value)
	}
	if boundary != "" {
		b.WriteString("\r\n")
		for _, child := range p.children {
			b.WriteString("--" + boundary + "\r\n")
			renderPart(b, child)
			b.WriteString("\r\n")
		}
		b.WriteString("--" + boundary + "--\r\n")
		return
	}
	switch {
	case strings.HasPrefix(p.media, "text/") && sevenBitText(p.data):
		writeField(b, "Content-Transfer-Encoding", "7bit")
		b.WriteString("\r\n")
		b.Write(crlf(p.data))
	case strings.HasPrefix(p.media, "text/") && utf8.Valid(p.data):
		writeField(b, "Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		writer := quotedprintable.NewWriter(b)
		_, _ = writer.Write(crlf(p.data))
		_ = writer.Close()
	default:
		writeField(b, "Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		encoded := base64.StdEncoding.EncodeToString(p.data)
		for len(encoded) > 76 {
			b.WriteString(encoded[:76] + "\r\n")
			encoded = encoded[76:]
		}
		b.WriteString(encoded)
	}
}

func crlf(data []byte) []byte {
	return []byte(strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n", "\r\n"))
}

func sevenBitText(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) > 900 {
			return false
		}
		for _, c := range line {
			if c >= 0x80 || c == 0 {
				return false
			}
		}
	}
	return true
}

// keywordFlags maps a keyword set to stored flags, keeping the item's
// non-keyword system flags (such as \Deleted) and the stored spelling of
// keywords that remain set.
func keywordFlags(current []string, words map[string]bool) []string {
	var out []string
	kept := map[string]bool{}
	for _, flag := range current {
		switch {
		case strings.HasPrefix(flag, "\\") && keywordForFlag(flag) == "":
			out = append(out, flag)
		case words[keywordOf(flag)]:
			out = append(out, flag)
			kept[keywordOf(flag)] = true
		}
	}
	for word, on := range words {
		word = strings.ToLower(word)
		if on && !kept[word] {
			out = append(out, keywordFlag(word))
			kept[word] = true
		}
	}
	sort.Strings(out)
	return out
}

// keywordOf is the JMAP keyword for a stored flag.
func keywordOf(flag string) string {
	if word := keywordForFlag(flag); word != "" {
		return word
	}
	return strings.ToLower(flag)
}

func keywordForFlag(flag string) string {
	switch strings.ToLower(flag) {
	case strings.ToLower(model.FlagSeen):
		return "$seen"
	case strings.ToLower(model.FlagAnswered):
		return "$answered"
	case strings.ToLower(model.FlagFlagged):
		return "$flagged"
	case strings.ToLower(model.FlagDraft):
		return "$draft"
	}
	return ""
}

// validKeyword checks the RFC 8621 §4.1.1 keyword syntax.
func validKeyword(word string) bool {
	if word == "" || len(word) > 255 {
		return false
	}
	for i := 0; i < len(word); i++ {
		c := word[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(`()]{%*"\`, c) >= 0 {
			return false
		}
	}
	return true
}

// updateEmail applies an Email/set update. Only keywords and mailboxIds
// are mutable, as whole values or through patch paths.
func (h *Handler) updateEmail(ctx context.Context, access service.AccessContext, id string, raw json.RawMessage, created map[string]string) *MethodError {
	var patch map[string]json.RawMessage
	if err := json.Unmarshal(raw, &patch); err != nil {
		return invalidProperties("patch must be a JSON object")
	}
	items, err := h.mailItemsByID(ctx, access, []string{id})
	if err != nil {
		return serverError(err)
	}
	if len(items) == 0 {
		return &MethodError{Type: "notFound"}
	}
	item := items[0]
	words := map[string]bool{}
	for _, flag := range item.Flags {
		if !strings.HasPrefix(flag, "\\") || keywordForFlag(flag) != "" {
			words[keywordOf(flag)] = true
		}
	}
	mailboxes := map[string]bool{item.FolderID: true}
	wordsChanged, mailboxesChanged := false, false
	var wholeWords, wholeMailboxes bool
	for _, key := range sortedKeys(patch) {
		value := patch[key]
		switch {
		case key == "keywords":
			var next map[string]bool
			if err := json.Unmarshal(value, &next); err != nil {
				return invalidProperties("keywords must map keywords to true", key)
			}
			words = map[string]bool{}
			for word, on := range next {
				if !on || !validKeyword(word) {
					return invalidProperties("invalid keyword "+word, key)
				}
				words[strings.ToLower(word)] = true
			}
			wordsChanged, wholeWords = true, true
		case strings.HasPrefix(key, "keywords/"):
			word := strings.ToLower(unescapePointer(strings.TrimPrefix(key, "keywords/")))
			if wholeWords || !validKeyword(word) {
				return invalidProperties("invalid keyword patch", key)
			}
			on, e := patchFlag(value, key)
			if e != nil {
				return e
			}
			if on {
				words[word] = true
			} else {
				delete(words, word)
			}
			wordsChanged = true
		case key == "mailboxIds":
			var next map[string]bool
			if err := json.Unmarshal(value, &next); err != nil {
				return invalidProperties("mailboxIds must map mailbox ids to true", key)
			}
			mailboxes = map[string]bool{}
			for mailbox, on := range next {
				if !on {
					return invalidProperties("mailboxIds values must be true", key)
				}
				mailboxes[resolveCreated(mailbox, created)] = true
			}
			mailboxesChanged, wholeMailboxes = true, true
		case strings.HasPrefix(key, "mailboxIds/"):
			if wholeMailboxes {
				return invalidProperties("mailboxIds patch overlaps mailboxIds", key)
			}
			mailbox := resolveCreated(unescapePointer(strings.TrimPrefix(key, "mailboxIds/")), created)
			on, e := patchFlag(value, key)
			if e != nil {
				return e
			}
			if on {
				mailboxes[mailbox] = true
			} else {
				delete(mailboxes, mailbox)
			}
			mailboxesChanged = true
		default:
			property, _, _ := strings.Cut(key, "/")
			return invalidProperties(property+" cannot be changed", property)
		}
	}
	if mailboxesChanged {
		destination, e := singleMailbox(mailboxes, nil)
		if e != nil {
			return e
		}
		if destination != item.FolderID {
			moved, err := h.cfg.Space.MoveItem(ctx, access, item.ID, destination, "")
			if err != nil {
				return serverError(err)
			}
			item = moved
		}
	}
	if wordsChanged {
		next := keywordFlags(item.Flags, words)
		if !sameFlags(next, item.Flags) {
			if _, err := h.cfg.Space.SetFlags(ctx, access, item.ID, next); err != nil {
				return serverError(err)
			}
		}
	}
	return nil
}

func patchFlag(value json.RawMessage, key string) (bool, *MethodError) {
	switch strings.TrimSpace(string(value)) {
	case "true":
		return true, nil
	case "null", "false":
		return false, nil
	}
	return false, invalidProperties("patch value must be true or null", key)
}

func unescapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~1", "/"), "~0", "~")
}

func sameFlags(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
