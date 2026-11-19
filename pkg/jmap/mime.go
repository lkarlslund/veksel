package jmap

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"

	"github.com/lkarlslund/veksel/pkg/model"
)

// The MIME model behind Email/get, Email/parse and blob downloads (RFC 8621
// §4.1). Header fields keep their raw octets and order so every header:
// parsed form can be derived from them; leaf bodies keep their transfer
// encoding until a body value or blob asks for the decoded content.

const maxMIMEDepth = 32

// mimeEntity is one node of a message's MIME tree.
type mimeEntity struct {
	partID      string // dotted path; containers keep theirs for numbering
	header      []headerField
	mediaType   string
	params      map[string]string
	disposition string
	dispParams  map[string]string
	body        []byte // transfer-encoded content of a leaf
	children    []*mimeEntity
	decoded     []byte
	decodeErr   bool
	decodedOnce bool
}

func (e *mimeEntity) multipart() bool { return strings.HasPrefix(e.mediaType, "multipart/") }

// parseMessage parses raw message octets into a MIME tree. It never fails:
// malformed structure degrades to text/plain leaves, as RFC 2045 asks.
func parseMessage(raw []byte) *mimeEntity {
	return parseEntity(raw, "1", "text/plain", 0)
}

func parseEntity(raw []byte, partID, defaultType string, depth int) *mimeEntity {
	fields, body := parseHeaderBlock(raw)
	e := &mimeEntity{partID: partID, header: fields, body: body}
	e.mediaType, e.params = defaultType, map[string]string{}
	if value, ok := lastHeader(fields, "Content-Type"); ok {
		if mediaType, params, err := mime.ParseMediaType(unfold(value)); mediaType != "" && (err == nil || err == mime.ErrInvalidMediaParameter) && strings.Contains(mediaType, "/") {
			e.mediaType, e.params = strings.ToLower(mediaType), params
		}
	}
	if value, ok := lastHeader(fields, "Content-Disposition"); ok {
		if disposition, params, err := mime.ParseMediaType(unfold(value)); disposition != "" && (err == nil || err == mime.ErrInvalidMediaParameter) {
			e.disposition, e.dispParams = strings.ToLower(disposition), params
		}
	}
	if !e.multipart() {
		return e
	}
	boundary := e.params["boundary"]
	if boundary == "" || depth >= maxMIMEDepth {
		e.mediaType, e.params = "text/plain", map[string]string{}
		return e
	}
	childType := "text/plain"
	if e.mediaType == "multipart/digest" {
		childType = "message/rfc822"
	}
	for index, part := range splitMultipart(body, boundary) {
		e.children = append(e.children, parseEntity(part, partID+"."+strconv.Itoa(index+1), childType, depth+1))
	}
	e.body = nil
	return e
}

// parseHeaderBlock splits a header block into raw fields and returns the
// body after the blank line. A field value keeps its folding (normalised to
// CRLF) and starts after the colon, as the Raw form requires.
func parseHeaderBlock(data []byte) ([]headerField, []byte) {
	var fields []headerField
	pos := 0
	for pos < len(data) {
		if data[pos] == '\n' {
			return fields, data[pos+1:]
		}
		if data[pos] == '\r' && pos+1 < len(data) && data[pos+1] == '\n' {
			return fields, data[pos+2:]
		}
		end := bytes.IndexByte(data[pos:], '\n')
		next := len(data)
		if end >= 0 {
			next = pos + end + 1
			end = pos + end
		} else {
			end = len(data)
		}
		line := strings.TrimSuffix(string(data[pos:end]), "\r")
		pos = next
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) > 0 {
				fields[len(fields)-1].Value += "\r\n" + line
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		fields = append(fields, headerField{Name: strings.TrimRight(name, " \t"), Value: value})
	}
	return fields, nil
}

// splitMultipart returns the body parts between boundary delimiter lines.
func splitMultipart(body []byte, boundary string) [][]byte {
	delimiter := []byte("--" + boundary)
	var parts [][]byte
	start := -1
	pos := 0
	for pos <= len(body) {
		end := bytes.IndexByte(body[pos:], '\n')
		next := len(body) + 1
		lineEnd := len(body)
		if end >= 0 {
			lineEnd = pos + end
			next = lineEnd + 1
		}
		line := bytes.TrimRight(body[pos:lineEnd], " \t\r")
		if rest, ok := bytes.CutPrefix(line, delimiter); ok && (len(rest) == 0 || bytes.Equal(rest, []byte("--"))) {
			if start >= 0 {
				// The CRLF before a delimiter belongs to the delimiter.
				partEnd := pos
				if partEnd > start && body[partEnd-1] == '\n' {
					partEnd--
					if partEnd > start && body[partEnd-1] == '\r' {
						partEnd--
					}
				}
				parts = append(parts, body[start:partEnd])
			}
			if len(rest) == 2 {
				return parts
			}
			start = min(next, len(body))
		}
		pos = next
	}
	if start >= 0 && start < len(body) {
		parts = append(parts, body[start:])
	}
	return parts
}

func unfold(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r\n", "", "\n", "").Replace(value))
}

func lastHeader(fields []headerField, name string) (string, bool) {
	for i := len(fields) - 1; i >= 0; i-- {
		if strings.EqualFold(fields[i].Name, name) {
			return fields[i].Value, true
		}
	}
	return "", false
}

func allHeaderValues(fields []headerField, name string) []string {
	var out []string
	for _, field := range fields {
		if strings.EqualFold(field.Name, name) {
			out = append(out, field.Value)
		}
	}
	return out
}

// mailHeader adapts raw fields to net/mail lookups.
func mailHeader(fields []headerField) mail.Header {
	h := make(mail.Header, len(fields))
	for _, field := range fields {
		key := textproto.CanonicalMIMEHeaderKey(field.Name)
		h[key] = append(h[key], unfold(field.Value))
	}
	return h
}

// decodedBody returns the leaf body without its transfer encoding.
func (e *mimeEntity) decodedBody() ([]byte, bool) {
	if !e.decodedOnce {
		e.decodedOnce = true
		encoding, _ := lastHeader(e.header, "Content-Transfer-Encoding")
		data, err := io.ReadAll(model.TransferDecoder(bytes.NewReader(e.body), unfold(encoding)))
		if err != nil {
			e.decodeErr = true
		}
		e.decoded = data
	}
	return e.decoded, e.decodeErr
}

// text returns a text part's content decoded to UTF-8 and whether decoding
// met a problem (bad transfer encoding, unknown charset, invalid octets).
func (e *mimeEntity) text() (string, bool) {
	data, problem := e.decodedBody()
	name := strings.ToLower(strings.TrimSpace(e.params["charset"]))
	switch name {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
	default:
		reader, err := charset.NewReaderLabel(name, bytes.NewReader(data))
		if err != nil {
			problem = true
			break
		}
		converted, err := io.ReadAll(reader)
		if err != nil {
			problem = true
			break
		}
		data = converted
	}
	if !utf8.Valid(data) {
		problem = true
	}
	return strings.ToValidUTF8(string(data), "�"), problem
}

// find returns the entity with partID.
func (e *mimeEntity) find(partID string) *mimeEntity {
	if e.partID == partID && !e.multipart() {
		return e
	}
	for _, child := range e.children {
		if found := child.find(partID); found != nil {
			return found
		}
	}
	return nil
}

func (e *mimeEntity) name() string {
	name := e.dispParams["filename"]
	if name == "" {
		name = e.params["name"]
	}
	return model.DecodeHeaderValue(name)
}

// isInlineMediaType reports the media types RFC 8621 §4.1.4 lets a client
// display inline alongside text.
func isInlineMediaType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/")
}

// bodyLists runs the RFC 8621 §4.1.4 parseStructure algorithm, which
// chooses the textBody, htmlBody and attachments lists.
func bodyLists(root *mimeEntity) (text, htmlParts, attachments []*mimeEntity) {
	text, htmlParts = []*mimeEntity{}, []*mimeEntity{}
	attachments = []*mimeEntity{}
	parseStructure([]*mimeEntity{root}, "mixed", false, &htmlParts, &text, &attachments)
	return text, htmlParts, attachments
}

func parseStructure(parts []*mimeEntity, multipartType string, inAlternative bool, htmlBody, textBody, attachments *[]*mimeEntity) {
	textLength, htmlLength := -1, -1
	if textBody != nil {
		textLength = len(*textBody)
	}
	if htmlBody != nil {
		htmlLength = len(*htmlBody)
	}
	for i, part := range parts {
		isInline := part.disposition != "attachment" &&
			(part.mediaType == "text/plain" || part.mediaType == "text/html" || isInlineMediaType(part.mediaType)) &&
			(i == 0 || (multipartType != "related" && (isInlineMediaType(part.mediaType) || part.name() == "")))
		switch {
		case part.multipart():
			sub := strings.TrimPrefix(part.mediaType, "multipart/")
			parseStructure(part.children, sub, inAlternative || sub == "alternative", htmlBody, textBody, attachments)
		case isInline:
			if multipartType == "alternative" {
				switch part.mediaType {
				case "text/plain":
					if textBody != nil {
						*textBody = append(*textBody, part)
					}
				case "text/html":
					if htmlBody != nil {
						*htmlBody = append(*htmlBody, part)
					}
				default:
					*attachments = append(*attachments, part)
				}
				continue
			} else if inAlternative {
				if part.mediaType == "text/plain" {
					htmlBody = nil
				}
				if part.mediaType == "text/html" {
					textBody = nil
				}
			}
			if textBody != nil {
				*textBody = append(*textBody, part)
			}
			if htmlBody != nil {
				*htmlBody = append(*htmlBody, part)
			}
			if (textBody == nil || htmlBody == nil) && isInlineMediaType(part.mediaType) {
				*attachments = append(*attachments, part)
			}
		default:
			*attachments = append(*attachments, part)
		}
	}
	if multipartType == "alternative" && textBody != nil && htmlBody != nil {
		if textLength == len(*textBody) && htmlLength != len(*htmlBody) {
			*textBody = append(*textBody, (*htmlBody)[htmlLength:]...)
		}
		if htmlLength == len(*htmlBody) && textLength != len(*textBody) {
			*htmlBody = append(*htmlBody, (*textBody)[textLength:]...)
		}
	}
}

// Header parsed forms (RFC 8621 §4.1.2).

var (
	// rfc5322Headers are the fields RFC 5322 and RFC 2369 define; each form
	// other than Raw is only valid for some of them.
	rfc5322Headers = map[string]bool{"date": true, "from": true, "sender": true, "reply-to": true, "to": true, "cc": true, "bcc": true,
		"message-id": true, "in-reply-to": true, "references": true, "subject": true, "comments": true, "keywords": true,
		"resent-date": true, "resent-from": true, "resent-sender": true, "resent-to": true, "resent-cc": true, "resent-bcc": true,
		"resent-message-id": true, "return-path": true, "received": true, "list-help": true, "list-unsubscribe": true,
		"list-subscribe": true, "list-post": true, "list-owner": true, "list-archive": true}
	headerFormFields = map[string]map[string]bool{
		"asText": {"subject": true, "comments": true, "keywords": true, "list-id": true},
		"asAddresses": {"from": true, "sender": true, "reply-to": true, "to": true, "cc": true, "bcc": true, "resent-from": true,
			"resent-sender": true, "resent-reply-to": true, "resent-to": true, "resent-cc": true, "resent-bcc": true},
		"asMessageIds": {"message-id": true, "in-reply-to": true, "references": true, "resent-message-id": true},
		"asDate":       {"date": true, "resent-date": true},
		"asURLs": {"list-help": true, "list-unsubscribe": true, "list-subscribe": true, "list-post": true, "list-owner": true,
			"list-archive": true},
	}
)

func init() { headerFormFields["asGroupedAddresses"] = headerFormFields["asAddresses"] }

// headerProperty is a parsed "header:{name}[:as{Form}][:all]" property.
type headerProperty struct {
	name string
	form string
	all  bool
}

// parseHeaderProperty parses a header: property and checks that its form
// may be used with the field.
func parseHeaderProperty(property string) (headerProperty, bool) {
	rest, ok := strings.CutPrefix(property, "header:")
	if !ok || rest == "" {
		return headerProperty{}, false
	}
	parts := strings.Split(rest, ":")
	p := headerProperty{name: parts[0], form: "asRaw"}
	parts = parts[1:]
	if len(parts) > 0 && parts[len(parts)-1] == "all" {
		p.all = true
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 1 || p.name == "" || strings.ContainsAny(p.name, " \t") {
		return headerProperty{}, false
	}
	if len(parts) == 1 {
		p.form = parts[0]
	}
	if p.form == "asRaw" {
		return p, true
	}
	allowed, known := headerFormFields[p.form]
	if !known {
		return headerProperty{}, false
	}
	lower := strings.ToLower(p.name)
	return p, allowed[lower] || !rfc5322Headers[lower]
}

// value returns the property's value over fields: the last instance, or
// every instance in order with :all.
func (p headerProperty) value(fields []headerField) any {
	values := allHeaderValues(fields, p.name)
	if p.all {
		out := make([]any, 0, len(values))
		for _, raw := range values {
			out = append(out, headerFormValue(p.form, raw))
		}
		return out
	}
	if len(values) == 0 {
		return nil
	}
	return headerFormValue(p.form, values[len(values)-1])
}

func headerFormValue(form, raw string) any {
	switch form {
	case "asText":
		return headerText(raw)
	case "asAddresses":
		return flattenGroups(parseAddressGroups(raw))
	case "asGroupedAddresses":
		return parseAddressGroups(raw)
	case "asMessageIds":
		if ids := parseMessageIDs(raw); len(ids) > 0 {
			return ids
		}
		return nil
	case "asDate":
		if t, err := mail.ParseDate(unfold(raw)); err == nil {
			return formatDate(t)
		}
		return nil
	case "asURLs":
		if urls := parseURLs(raw); len(urls) > 0 {
			return urls
		}
		return nil
	}
	return raw
}

var wordDecoder = model.HeaderWordDecoder

// headerText is the Text form: unfolded, encoded-words decoded, trimmed.
func headerText(raw string) string {
	value := strings.NewReplacer("\r\n", "", "\n", "").Replace(raw)
	if decoded, err := wordDecoder.DecodeHeader(value); err == nil {
		value = decoded
	}
	return strings.TrimSpace(value)
}

// formatDate renders a Date (RFC 3339 with the original offset).
func formatDate(t time.Time) string { return t.Format("2006-01-02T15:04:05Z07:00") }

// formatUTCDate renders a UTCDate.
func formatUTCDate(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

type emailAddressGroup struct {
	Name      *string   `json:"name"`
	Addresses []address `json:"addresses"`
}

func flattenGroups(groups []emailAddressGroup) []address {
	out := []address{}
	for _, group := range groups {
		out = append(out, group.Addresses...)
	}
	return out
}

// parseAddressGroups parses an address-list header into groups; addresses
// outside a group form groups with a null name.
func parseAddressGroups(raw string) []emailAddressGroup {
	value := unfold(raw)
	groups := []emailAddressGroup{}
	addUngrouped := func(segment string) {
		list := parseAddressList(segment)
		if len(list) == 0 {
			return
		}
		if n := len(groups); n > 0 && groups[n-1].Name == nil {
			groups[n-1].Addresses = append(groups[n-1].Addresses, list...)
			return
		}
		groups = append(groups, emailAddressGroup{Addresses: list})
	}
	inQuote, inAngle, comment := false, false, 0
	segmentStart, groupStart := 0, -1
	groupName := ""
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case inQuote:
			if c == '\\' {
				i++
			} else if c == '"' {
				inQuote = false
			}
		case comment > 0:
			if c == '\\' {
				i++
			} else if c == '(' {
				comment++
			} else if c == ')' {
				comment--
			}
		case c == '"':
			inQuote = true
		case c == '(':
			comment++
		case c == '<':
			inAngle = true
		case c == '>':
			inAngle = false
		case inAngle:
		case c == ':' && groupStart < 0:
			groupName = headerText(value[segmentStart:i])
			groupStart = i + 1
		case c == ';' && groupStart >= 0:
			name := groupName
			groups = append(groups, emailAddressGroup{Name: &name, Addresses: parseAddressList(value[groupStart:i])})
			groupStart = -1
			segmentStart = i + 1
			if j := strings.IndexFunc(value[i+1:], func(r rune) bool { return r != ' ' && r != '\t' }); j >= 0 && value[i+1+j] == ',' {
				i += j + 1
				segmentStart = i + 1
			}
		case c == ',' && groupStart < 0:
			addUngrouped(value[segmentStart:i])
			segmentStart = i + 1
		}
	}
	if groupStart >= 0 {
		name := groupName
		groups = append(groups, emailAddressGroup{Name: &name, Addresses: parseAddressList(value[groupStart:])})
	} else {
		addUngrouped(value[segmentStart:])
	}
	return groups
}

// parseAddressList parses mailboxes leniently: a list net/mail rejects is
// retried one mailbox at a time, and bare addr-specs are kept.
func parseAddressList(value string) []address {
	value = strings.TrimSpace(value)
	out := []address{}
	if value == "" {
		return out
	}
	parser := mail.AddressParser{WordDecoder: wordDecoder}
	if list, err := parser.ParseList(value); err == nil {
		for _, a := range list {
			out = append(out, address{Name: nullableName(a.Name), Email: a.Address})
		}
		return out
	}
	for _, piece := range strings.Split(value, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		if a, err := parser.Parse(piece); err == nil {
			out = append(out, address{Name: nullableName(a.Name), Email: a.Address})
		} else if strings.Contains(piece, "@") {
			out = append(out, address{Email: strings.Trim(piece, "<> ")})
		}
	}
	return out
}

func nullableName(name string) *string {
	if name = strings.TrimSpace(name); name == "" {
		return nil
	}
	return &name
}

// parseMessageIDs returns the msg-ids of a header without angle brackets.
func parseMessageIDs(raw string) []string {
	value := stripComments(unfold(raw))
	var out []string
	for {
		start := strings.IndexByte(value, '<')
		if start < 0 {
			break
		}
		end := strings.IndexByte(value[start:], '>')
		if end < 0 {
			break
		}
		if id := strings.TrimSpace(value[start+1 : start+end]); id != "" && !strings.ContainsAny(id, " \t") {
			out = append(out, id)
		}
		value = value[start+end+1:]
	}
	if len(out) == 0 {
		// Tolerate ids sent without brackets.
		for _, field := range strings.Fields(value) {
			if field = strings.Trim(field, ","); strings.Contains(field, "@") {
				out = append(out, field)
			}
		}
	}
	return out
}

func stripComments(value string) string {
	var b strings.Builder
	depth, inQuote := 0, false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case inQuote:
			if c == '"' {
				inQuote = false
			}
		case c == '"' && depth == 0:
			inQuote = true
		case c == '(':
			depth++
			continue
		case c == ')' && depth > 0:
			depth--
			continue
		}
		if depth == 0 {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// parseURLs returns the URLs of an RFC 2369 List-* header.
func parseURLs(raw string) []string {
	value := stripComments(unfold(raw))
	var out []string
	for {
		start := strings.IndexByte(value, '<')
		if start < 0 {
			return out
		}
		end := strings.IndexByte(value[start:], '>')
		if end < 0 {
			return out
		}
		out = append(out, strings.Join(strings.Fields(value[start+1:start+end]), ""))
		value = value[start+end+1:]
	}
}

// htmlToText renders HTML as plain text for previews.
func htmlToText(source string) string {
	root, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return source
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "script" || node.Data == "style" || node.Data == "head") {
			return
		}
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
			b.WriteByte(' ')
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return b.String()
}

// truncateUTF8 cuts value to at most limit octets without splitting a
// character.
func truncateUTF8(value string, limit int) (string, bool) {
	if limit <= 0 || len(value) <= limit {
		return value, false
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut], true
}
