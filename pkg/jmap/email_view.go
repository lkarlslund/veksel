package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

type address struct {
	Name  *string `json:"name"`
	Email string  `json:"email"`
}
type bodyValue struct {
	Value             string `json:"value"`
	IsEncodingProblem bool   `json:"isEncodingProblem"`
	IsTruncated       bool   `json:"isTruncated"`
}
type headerField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

var (
	defaultEmailProperties = []string{"id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt", "messageId",
		"inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "hasAttachment",
		"preview", "bodyValues", "textBody", "htmlBody", "attachments"}
	// defaultParseProperties are Email/parse's defaults (RFC 8621 §4.9).
	defaultParseProperties = []string{"messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo",
		"subject", "sentAt", "hasAttachment", "preview", "bodyValues", "textBody", "htmlBody", "attachments"}
	defaultBodyProperties = []string{"partId", "blobId", "size", "name", "type", "charset", "disposition", "cid", "language", "location"}
	extraEmailProperties  = []string{"headers", "bodyStructure"}
	extraBodyProperties   = []string{"headers", "subParts"}
	// convenienceHeaders maps Email properties to the header field and form
	// they are defined as (RFC 8621 §4.1.2 - §4.1.3).
	convenienceHeaders = map[string]headerProperty{
		"messageId": {name: "Message-ID", form: "asMessageIds"}, "inReplyTo": {name: "In-Reply-To", form: "asMessageIds"},
		"references": {name: "References", form: "asMessageIds"}, "sender": {name: "Sender", form: "asAddresses"},
		"from": {name: "From", form: "asAddresses"}, "to": {name: "To", form: "asAddresses"}, "cc": {name: "Cc", form: "asAddresses"},
		"bcc": {name: "Bcc", form: "asAddresses"}, "replyTo": {name: "Reply-To", form: "asAddresses"},
		"subject": {name: "Subject", form: "asText"}, "sentAt": {name: "Date", form: "asDate"},
	}
)

// emailOptions are the validated Email/get and Email/parse output options.
type emailOptions struct {
	properties     []string
	bodyProperties []string
	fetchText      bool
	fetchHTML      bool
	fetchAll       bool
	maxBytes       int
}

type emailFetchArgs struct {
	BodyProperties      []string `json:"bodyProperties"`
	FetchTextBodyValues bool     `json:"fetchTextBodyValues"`
	FetchHTMLBodyValues bool     `json:"fetchHTMLBodyValues"`
	FetchAllBodyValues  bool     `json:"fetchAllBodyValues"`
	MaxBodyValueBytes   int      `json:"maxBodyValueBytes"`
}

func (a emailFetchArgs) options(properties, defaults []string) (emailOptions, *MethodError) {
	opts := emailOptions{properties: properties, bodyProperties: a.BodyProperties, fetchText: a.FetchTextBodyValues,
		fetchHTML: a.FetchHTMLBodyValues, fetchAll: a.FetchAllBodyValues, maxBytes: a.MaxBodyValueBytes}
	if opts.properties == nil {
		opts.properties = defaults
	}
	if opts.bodyProperties == nil {
		opts.bodyProperties = defaultBodyProperties
	}
	if opts.maxBytes < 0 {
		return opts, &MethodError{Type: "invalidArguments", Description: "maxBodyValueBytes must be a positive integer", Properties: []string{"maxBodyValueBytes"}}
	}
	if bad := unknownProperties(opts.properties, defaultEmailProperties, extraEmailProperties); len(bad) > 0 {
		return opts, &MethodError{Type: "invalidArguments", Description: "unknown or invalid Email properties: " + strings.Join(bad, ", "), Properties: bad}
	}
	if bad := unknownProperties(opts.bodyProperties, defaultBodyProperties, extraBodyProperties); len(bad) > 0 {
		return opts, &MethodError{Type: "invalidArguments", Description: "unknown or invalid body properties: " + strings.Join(bad, ", "), Properties: bad}
	}
	return opts, nil
}

func unknownProperties(properties []string, known ...[]string) []string {
	var bad []string
	for _, property := range properties {
		if strings.HasPrefix(property, "header:") {
			if _, ok := parseHeaderProperty(property); !ok {
				bad = append(bad, property)
			}
			continue
		}
		found := false
		for _, list := range known {
			for _, name := range list {
				found = found || name == property
			}
		}
		if !found {
			bad = append(bad, property)
		}
	}
	return bad
}

// emailView derives Email properties from a stored item, or from a parsed
// blob when the item has no id (Email/parse).
type emailView struct {
	item        model.Item
	blobID      string
	size        int64
	root        *mimeEntity
	text        []*mimeEntity
	html        []*mimeEntity
	attachments []*mimeEntity
}

func newEmailView(item model.Item, blobID string, raw []byte) *emailView {
	v := &emailView{item: item, blobID: blobID, size: item.Size, root: parseMessage(raw)}
	if v.size == 0 {
		v.size = int64(len(raw))
	}
	v.text, v.html, v.attachments = bodyLists(v.root)
	return v
}

func (v *emailView) object(opts emailOptions) map[string]any {
	out := make(map[string]any, len(opts.properties)+1)
	if v.item.ID != "" {
		out["id"] = v.item.ID
	}
	for _, property := range opts.properties {
		out[property] = v.property(property, opts)
	}
	return out
}

func (v *emailView) property(name string, opts emailOptions) any {
	parsed := v.item.ID == ""
	switch name {
	case "id":
		return nullable(v.item.ID)
	case "blobId":
		return v.blobID
	case "size":
		return v.size
	case "threadId", "mailboxIds", "keywords", "receivedAt":
		if parsed {
			return nil
		}
		switch name {
		case "threadId":
			return threadID(mailHeader(v.root.header))
		case "mailboxIds":
			return map[string]bool{v.item.FolderID: true}
		case "keywords":
			return keywords(v.item.Flags)
		default:
			return formatUTCDate(v.item.InternalDate)
		}
	case "headers":
		return headerList(v.root.header)
	case "bodyStructure":
		return v.part(v.root, opts.bodyProperties, true)
	case "textBody":
		return v.parts(v.text, opts.bodyProperties)
	case "htmlBody":
		return v.parts(v.html, opts.bodyProperties)
	case "attachments":
		return v.parts(v.attachments, opts.bodyProperties)
	case "hasAttachment":
		return v.hasAttachment()
	case "preview":
		return v.preview()
	case "bodyValues":
		return v.bodyValues(opts)
	}
	if header, ok := convenienceHeaders[name]; ok {
		return header.value(v.root.header)
	}
	if header, ok := parseHeaderProperty(name); ok {
		return header.value(v.root.header)
	}
	return nil
}

func headerList(fields []headerField) []headerField {
	if fields == nil {
		return []headerField{}
	}
	return fields
}

func (v *emailView) parts(parts []*mimeEntity, properties []string) []map[string]any {
	out := make([]map[string]any, 0, len(parts))
	for _, part := range parts {
		out = append(out, v.part(part, properties, false))
	}
	return out
}

// part renders an EmailBodyPart. In bodyStructure, multipart parts always
// carry their subParts so the tree stays navigable.
func (v *emailView) part(e *mimeEntity, properties []string, structure bool) map[string]any {
	out := make(map[string]any, len(properties)+1)
	for _, property := range properties {
		switch property {
		case "partId":
			if e.multipart() {
				out[property] = nil
			} else {
				out[property] = e.partID
			}
		case "blobId":
			if e.multipart() || v.blobID == "" {
				out[property] = nil
			} else {
				out[property] = v.blobID + "-" + e.partID
			}
		case "size":
			out[property] = entitySize(e)
		case "headers":
			out[property] = headerList(e.header)
		case "name":
			out[property] = nullable(e.name())
		case "type":
			out[property] = e.mediaType
		case "charset":
			switch {
			case e.params["charset"] != "":
				out[property] = e.params["charset"]
			case strings.HasPrefix(e.mediaType, "text/"):
				out[property] = "us-ascii"
			default:
				out[property] = nil
			}
		case "disposition":
			out[property] = nullable(e.disposition)
		case "cid":
			value, _ := lastHeader(e.header, "Content-ID")
			out[property] = nullable(strings.Trim(unfold(value), "<>"))
		case "language":
			value, ok := lastHeader(e.header, "Content-Language")
			if languages := splitHeaderList(unfold(value)); ok && len(languages) > 0 {
				out[property] = languages
			} else {
				out[property] = nil
			}
		case "location":
			value, _ := lastHeader(e.header, "Content-Location")
			out[property] = nullable(unfold(value))
		case "subParts":
			out[property] = v.subParts(e, properties)
		default:
			if header, ok := parseHeaderProperty(property); ok {
				out[property] = header.value(e.header)
			}
		}
	}
	if structure && e.multipart() {
		out["subParts"] = v.subParts(e, properties)
	}
	return out
}

func (v *emailView) subParts(e *mimeEntity, properties []string) any {
	if !e.multipart() {
		return nil
	}
	out := make([]map[string]any, 0, len(e.children))
	for _, child := range e.children {
		out = append(out, v.part(child, properties, true))
	}
	return out
}

func entitySize(e *mimeEntity) int64 {
	if e.multipart() {
		var total int64
		for _, child := range e.children {
			total += entitySize(child)
		}
		return total
	}
	data, _ := e.decodedBody()
	return int64(len(data))
}

// hasAttachment counts attachments a client should offer for download;
// images embedded in an HTML body by Content-ID are not among them.
func (v *emailView) hasAttachment() bool {
	for _, part := range v.attachments {
		cid, _ := lastHeader(part.header, "Content-ID")
		if part.disposition == "inline" && cid != "" && isInlineMediaType(part.mediaType) {
			continue
		}
		return true
	}
	return false
}

func (v *emailView) preview() string {
	for _, part := range v.text {
		if !strings.HasPrefix(part.mediaType, "text/") {
			continue
		}
		text, _ := part.text()
		if part.mediaType == "text/html" {
			text = htmlToText(text)
		}
		if text = trimPreview(text); text != "" {
			return text
		}
	}
	return ""
}

func (v *emailView) bodyValues(opts emailOptions) map[string]bodyValue {
	values := map[string]bodyValue{}
	add := func(part *mimeEntity) {
		if !strings.HasPrefix(part.mediaType, "text/") {
			return
		}
		if _, done := values[part.partID]; done {
			return
		}
		text, problem := part.text()
		text, truncated := truncateUTF8(text, opts.maxBytes)
		values[part.partID] = bodyValue{Value: text, IsEncodingProblem: problem, IsTruncated: truncated}
	}
	if opts.fetchText || opts.fetchAll {
		for _, part := range v.text {
			add(part)
		}
	}
	if opts.fetchHTML || opts.fetchAll {
		for _, part := range v.html {
			add(part)
		}
	}
	if opts.fetchAll {
		var walk func(*mimeEntity)
		walk = func(e *mimeEntity) {
			if e.multipart() {
				for _, child := range e.children {
					walk(child)
				}
				return
			}
			add(e)
		}
		walk(v.root)
	}
	return values
}

// blobData resolves a blob id to its octets and media type. Ids are item
// ids, optionally suffixed with "-<partId>" for a decoded MIME part or
// "-media.<key>" for contact media.
func (h *Handler) blobData(ctx context.Context, access service.AccessContext, blobID string) ([]byte, string, error) {
	baseID, partID := splitBlobID(blobID)
	item, err := h.cfg.Space.GetItem(ctx, access, baseID)
	if err != nil {
		return nil, "", err
	}
	if partID == "" {
		return item.Data, item.Headers["Content-Type"], nil
	}
	if key, media := strings.CutPrefix(partID, "media."); media {
		data, contentType, ok := contactMedia(item.Data, item.ID, key)
		if !ok {
			return nil, "", errBlobNotFound
		}
		return data, contentType, nil
	}
	part := parseMessage(item.Data).find(partID)
	if part == nil {
		return nil, "", errBlobNotFound
	}
	data, _ := part.decodedBody()
	return data, part.mediaType, nil
}

var errBlobNotFound = fmt.Errorf("blob not found")

// decodeGetArgs decodes /get arguments and enforces maxObjectsInGet.
func decodeGetArgs(raw json.RawMessage, into any, ids func() []string) *MethodError {
	if err := json.Unmarshal(raw, into); err != nil {
		return invalidArguments(err)
	}
	if len(ids()) > maxObjectsInGet {
		return &MethodError{Type: "requestTooLarge", Description: fmt.Sprintf("at most %d ids per call", maxObjectsInGet)}
	}
	return nil
}
