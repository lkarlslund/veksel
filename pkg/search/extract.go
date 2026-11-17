// Package search implements Veksel' derived, account-local full-text index.
package search

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

const maxMIMEParts = 256

// maxAttachmentTextBytes caps the text indexed from one attachment within the
// per-message MaxExtractedBytes budget.
const maxAttachmentTextBytes = 256 << 10

type document struct {
	ItemID         string   `json:"item_id"`
	FolderID       string   `json:"folder_id"`
	FolderName     string   `json:"folder_name"`
	Type           string   `json:"type"`
	Name           string   `json:"name"`
	Title          string   `json:"title"`
	Sender         string   `json:"sender"`
	Recipients     string   `json:"recipients"`
	Subject        string   `json:"subject"`
	Headers        string   `json:"headers"`
	Content        string   `json:"content"`
	Attachment     string   `json:"attachment"`
	AttachmentText string   `json:"attachment_content"`
	HasAttachment  bool     `json:"has_attachment"`
	Flags          []string `json:"flags"`
	// Categories are the lower-cased CATEGORIES of an event, task, or card.
	Categories       []string  `json:"categories,omitempty"`
	Date             time.Time `json:"date"`
	Updated          time.Time `json:"updated"`
	Size             float64   `json:"size"`
	Trashed          bool      `json:"trashed"`
	Truncated        bool      `json:"truncated"`
	ContactName      string    `json:"contact_name"`
	ContactOrg       string    `json:"contact_org"`
	ContactEmail     string    `json:"contact_email"`
	ContactPhone     string    `json:"contact_phone"`
	ContactEmails    []string  `json:"contact_emails"`
	ContactSuggest   string    `json:"contact_suggest"`
	ContactOrgView   string    `json:"-"`
	ContactPhoneView string    `json:"-"`
	ContactKind      string    `json:"-"`
	ContactMembers   int       `json:"-"`
	ContactHasPhoto  bool      `json:"-"`
	ContactGroups    []string  `json:"-"`
	// Summary is the stored-only JSON projection from which a hit is served
	// without reading and re-parsing the item; see indexSummary.
	Summary string `json:"summary,omitempty"`
}

// indexSummary is everything a search hit presents for an item. Documents
// store it in the index so list and search pages avoid an item read and a
// full MIME or vCard parse per hit; for mail that read includes every
// attachment. Times are kept here at full precision
// because Bleve returns stored dates truncated to seconds, and contact photo
// URLs are versioned by the exact update time.
type indexSummary struct {
	Name            string    `json:"n,omitempty"`
	Title           string    `json:"t,omitempty"`
	Sender          string    `json:"s,omitempty"`
	Date            time.Time `json:"d"`
	Updated         time.Time `json:"u"`
	Flags           []string  `json:"f,omitempty"`
	Trashed         bool      `json:"tr,omitempty"`
	Truncated       bool      `json:"tc,omitempty"`
	ContactEmails   []string  `json:"ce,omitempty"`
	ContactOrg      string    `json:"co,omitempty"`
	ContactPhone    string    `json:"cp,omitempty"`
	ContactKind     string    `json:"ck,omitempty"`
	ContactMembers  int       `json:"cm,omitempty"`
	ContactHasPhoto bool      `json:"cph,omitempty"`
	ContactGroups   []string  `json:"cg,omitempty"`
}

func (doc document) summary() indexSummary {
	return indexSummary{
		Name: doc.Name, Title: doc.Title, Sender: doc.Sender, Date: doc.Date, Updated: doc.Updated,
		Flags: doc.Flags, Trashed: doc.Trashed, Truncated: doc.Truncated,
		ContactEmails: doc.ContactEmails, ContactOrg: doc.ContactOrgView, ContactPhone: doc.ContactPhoneView,
		ContactKind: doc.ContactKind, ContactMembers: doc.ContactMembers, ContactHasPhoto: doc.ContactHasPhoto,
		ContactGroups: doc.ContactGroups,
	}
}

func extract(folder model.Folder, item model.Item, maxBytes int64) document {
	doc := document{
		ItemID: item.ID, FolderID: folder.ID, FolderName: folder.Name, Type: string(folder.Type),
		Name: item.Name, Flags: append([]string(nil), item.Flags...), Date: item.InternalDate,
		Updated: item.UpdatedAt, Size: float64(item.Size), Trashed: !item.TrashedAt.IsZero(),
	}
	if doc.Date.IsZero() {
		doc.Date = item.CreatedAt
	}
	var messageHeaders mail.Header
	switch folder.Type {
	case model.FolderTypeMail:
		messageHeaders = extractMail(&doc, item.Data, maxBytes)
	case model.FolderTypeContacts:
		extractContact(&doc, item.Data)
		doc.ContactGroups = model.ParseVCard(item.Data).Categories
		doc.Categories = lowerAll(doc.ContactGroups)
	default:
		doc.Content = textualPayload(item.Data)
		if folder.Type == model.FolderTypeCalendar || folder.Type == model.FolderTypeTasks {
			doc.Content = icalendarText(item.Data)
			doc.Categories = lowerAll(calendarcore.ItemCategories(item.Data))
		}
		doc.Title = firstNonEmpty(item.Headers["SUMMARY"], item.Headers["Name"], item.Name)
	}
	// Item metadata headers come after the message's own; a mail item's copy
	// of a message header is not indexed twice.
	var itemHeaders strings.Builder
	for name, value := range item.Headers {
		if messageHeaders != nil && len(messageHeaders[textproto.CanonicalMIMEHeaderKey(name)]) > 0 {
			continue
		}
		if value, ok := indexedHeaderValue(name, value); ok {
			itemHeaders.WriteString(name + ": " + value + "\n")
		}
	}
	doc.Headers += itemHeaders.String()
	if maxBytes > 0 && int64(len(doc.Content)) > maxBytes {
		doc.Content = doc.Content[:maxBytes]
		doc.Truncated = true
	}
	if encoded, err := json.Marshal(doc.summary()); err == nil {
		doc.Summary = string(encoded)
	}
	return doc
}

func extractContact(doc *document, data []byte) {
	contact := model.ParseVCard(data)
	doc.ContactName = sortableContactValue(contact.FN)
	doc.ContactOrg = sortableContactValue(contact.Org)
	doc.ContactOrgView = contact.Org
	doc.ContactKind = contact.Kind
	doc.ContactMembers = len(contact.Members)
	if len(contact.Emails) > 0 {
		doc.ContactEmail = sortableContactValue(contact.Emails[0])
		doc.ContactEmails = append([]string(nil), contact.Emails...)
	}
	if len(contact.Phones) > 0 {
		doc.ContactPhone = sortableContactValue(contact.Phones[0])
		doc.ContactPhoneView = contact.Phones[0]
	}
	doc.ContactHasPhoto = len(contact.PhotoData) > 0
	doc.Name = contact.FN
	doc.Title = firstNonEmpty(contact.FN, doc.Name)
	doc.ContactSuggest = strings.Join([]string{
		contact.FN, contact.Nickname, contact.Org, strings.Join(contact.Emails, " "),
	}, " ")
	doc.Content = contactText(contact)
}

// contactText is the searchable text of a contact: its decoded property
// values, one per line, so that "navy" matches ORG:Navy. The raw vCard lines
// would index as single tokens such as "org:navy"; PHOTO payloads are left out.
func contactText(contact model.Contact) string {
	values := []string{
		contact.FN, contact.N, contact.Prefix, contact.GivenName, contact.MiddleName, contact.FamilyName,
		contact.Suffix, contact.Nickname, contact.Org, contact.Department, contact.Title, contact.Role,
		contact.Note, contact.URL, contact.Birthday, contact.PhotoURI,
	}
	for _, email := range contact.Emails {
		// The standard tokenizer keeps "ada@analytical.example" as one or two
		// dotted tokens; the parts make the domain and local part searchable.
		values = append(values, email, strings.Join(strings.FieldsFunc(email, func(r rune) bool { return r == '@' || r == '.' }), " "))
	}
	values = append(values, contact.Phones...)
	values = append(values, contact.Categories...)
	values = append(values, contact.Members...)
	for _, address := range contact.Addresses {
		values = append(values, address.Street, address.Locality, address.Region, address.PostalCode, address.Country)
	}
	return strings.Join(uniqueStrings(values), "\n")
}

// icalendarText returns the decoded property values of an iCalendar object
// (SUMMARY, LOCATION, DESCRIPTION, ...) one per line, without the property
// names and parameters that would glue to the value as a single token.
func icalendarText(data []byte) string {
	text := strings.NewReplacer("\r\n ", "", "\r\n\t", "", "\n ", "", "\n\t", "").Replace(string(data))
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(strings.ToUpper(name), ";")
		switch name {
		case "BEGIN", "END", "VERSION", "PRODID", "CALSCALE", "METHOD", "ATTACH":
			continue
		}
		value = strings.NewReplacer("\\n", "\n", "\\N", "\n", "\\,", ",", "\\;", ";", "\\\\", "\\").Replace(value)
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return strings.Join(out, "\n")
}

func lowerAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.ToLower(strings.TrimSpace(value))
	}
	return result
}

func sortableContactValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// extractMail fills doc from a MIME message and returns its header, or nil
// when raw does not parse as one.
func extractMail(doc *document, raw []byte, maxBytes int64) mail.Header {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		doc.Content = textualPayload(raw)
		doc.Title = doc.Name
		return nil
	}
	doc.Subject = model.DecodeHeaderValue(message.Header.Get("Subject"))
	doc.Title = firstNonEmpty(doc.Subject, doc.Name)
	doc.Sender = model.DecodeHeaderValue(message.Header.Get("From"))
	doc.Recipients = strings.Join([]string{
		model.DecodeHeaderValue(message.Header.Get("To")), model.DecodeHeaderValue(message.Header.Get("Cc")),
		model.DecodeHeaderValue(message.Header.Get("Bcc")), model.DecodeHeaderValue(message.Header.Get("Reply-To")),
	}, " ")
	var headers strings.Builder
	for name, values := range message.Header {
		if value, ok := indexedHeaderValue(name, strings.Join(values, " ")); ok {
			headers.WriteString(name + ": " + value + "\n")
		}
	}
	doc.Headers = headers.String()
	contentType := message.Header.Get("Content-Type")
	extractor := entityExtractor{budget: extractionBudget{remaining: maxBytes, limited: maxBytes > 0}}
	result := extractor.extract(message.Body, contentType, message.Header.Get("Content-Transfer-Encoding"), message.Header.Get("Content-Disposition"), 0)
	doc.Content = strings.Join(result.body, "\n")
	doc.Attachment = strings.Join(uniqueStrings(result.attachmentNames), " ")
	doc.AttachmentText = strings.Join(result.attachmentText, "\n")
	doc.HasAttachment = result.hasAttachment
	doc.Truncated = doc.Truncated || extractor.budget.truncated
	return message.Header
}

// signatureHeaders carry base64 signatures and hashes: every message adds
// unique, unsearchable terms to the index. Only their identifying tags are
// kept, so header:example.net still finds mail signed by example.net.
var signatureHeaders = map[string]bool{
	"Dkim-Signature": true, "X-Google-Dkim-Signature": true, "Arc-Seal": true, "Arc-Message-Signature": true,
}

var signatureTag = regexp.MustCompile(`(?:^|;)\s*([dis])=([^;]*)`)

// indexedHeaderValue returns the searchable text of a header, or false when
// the header is not indexed: X-Veksel-Command-ID is a random internal
// idempotency token.
func indexedHeaderValue(name, value string) (string, bool) {
	name = textproto.CanonicalMIMEHeaderKey(name)
	if name == "X-Veksel-Command-Id" {
		return "", false
	}
	if !signatureHeaders[name] {
		return value, true
	}
	var tags []string
	for _, match := range signatureTag.FindAllStringSubmatch(value, -1) {
		tags = append(tags, match[1]+"="+strings.Join(strings.Fields(match[2]), ""))
	}
	return strings.Join(tags, "; "), true
}

type entityExtraction struct {
	body            []string
	attachmentNames []string
	attachmentText  []string
	hasAttachment   bool
}

func (result *entityExtraction) append(other entityExtraction) {
	result.body = append(result.body, other.body...)
	result.attachmentNames = append(result.attachmentNames, other.attachmentNames...)
	result.attachmentText = append(result.attachmentText, other.attachmentText...)
	result.hasAttachment = result.hasAttachment || other.hasAttachment
}

type extractionBudget struct {
	remaining int64
	limited   bool
	truncated bool
}

func (budget *extractionBudget) read(reader io.Reader) []byte {
	if !budget.limited {
		data, _ := io.ReadAll(reader)
		return data
	}
	if budget.remaining <= 0 {
		budget.truncated = true
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(reader, budget.remaining+1))
	if int64(len(data)) > budget.remaining {
		data = trimPartialRune(data[:budget.remaining])
		budget.truncated = true
	}
	budget.remaining -= int64(len(data))
	return data
}

// readAtMost reads like read but never more than limit bytes, so one large
// attachment cannot take the whole message budget.
func (budget *extractionBudget) readAtMost(reader io.Reader, limit int64) []byte {
	if budget.limited && budget.remaining <= limit {
		return budget.read(reader)
	}
	capped := extractionBudget{remaining: limit, limited: true}
	data := capped.read(reader)
	budget.truncated = budget.truncated || capped.truncated
	if budget.limited {
		budget.remaining -= int64(len(data))
	}
	return data
}

// trimPartialRune drops a UTF-8 sequence cut short by a byte limit, which
// would otherwise make a truncated text attachment fail the UTF-8 check.
func trimPartialRune(data []byte) []byte {
	for range utf8.UTFMax - 1 {
		if len(data) == 0 {
			break
		}
		if r, size := utf8.DecodeLastRune(data); r != utf8.RuneError || size != 1 {
			break
		}
		data = data[:len(data)-1]
	}
	return data
}

type entityExtractor struct {
	budget extractionBudget
	parts  int
}

func (extractor *entityExtractor) extract(reader io.Reader, contentType, transferEncoding, contentDisposition string, depth int) entityExtraction {
	if depth > 20 || extractor.parts >= maxMIMEParts {
		extractor.budget.truncated = true
		return entityExtraction{}
	}
	extractor.parts++
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return entityExtraction{}
		}
		parts := multipart.NewReader(reader, boundary)
		alternative := mediaType == "multipart/alternative"
		var result entityExtraction
		var preferred []string
		for {
			part, err := parts.NextPart()
			if err != nil {
				break
			}
			extracted := extractor.extract(part, part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-Disposition"), depth+1)
			_ = part.Close()
			partType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if alternative && partType != "text/calendar" && strings.TrimSpace(strings.Join(extracted.body, "")) != "" {
				// Alternatives render the same content; RFC 2046 orders them
				// by increasing preference, so the last textual one is
				// indexed instead of the same words once per rendering. An
				// invitation's text/calendar part carries its own fields and
				// stays indexed beside it.
				preferred, extracted.body = extracted.body, nil
			}
			result.append(extracted)
		}
		if alternative {
			result.body = append(result.body, preferred...)
		}
		return result
	}
	filename, attachment := attachmentIdentity(contentDisposition, params)
	if attachment {
		result := entityExtraction{hasAttachment: true}
		if filename != "" {
			result.attachmentNames = []string{filename}
		}
		if !attachmentTextMediaType(mediaType) {
			return result
		}
		data := extractor.budget.readAtMost(model.TransferDecoder(reader, transferEncoding), maxAttachmentTextBytes)
		if text, ok := safeAttachmentText(mediaType, params["charset"], data); ok {
			result.attachmentText = []string{text}
		}
		return result
	}
	switch mediaType {
	case "text/html":
		data := extractor.budget.read(model.TransferDecoder(reader, transferEncoding))
		return entityExtraction{body: []string{htmlText(data)}}
	case "text/calendar":
		// An invitation's body is its readable event, not raw iCalendar lines.
		data := extractor.budget.read(model.TransferDecoder(reader, transferEncoding))
		return entityExtraction{body: []string{readableICalendarText([]byte(decodeCharset(data, params["charset"])))}}
	case "text/plain", "text/vcard", "text/x-vcard":
		data := extractor.budget.read(model.TransferDecoder(reader, transferEncoding))
		return entityExtraction{body: []string{decodeCharset(data, params["charset"])}}
	default:
		return entityExtraction{}
	}
}

func attachmentIdentity(disposition string, contentTypeParams map[string]string) (string, bool) {
	mediaType, params, _ := mime.ParseMediaType(disposition)
	filename := firstNonEmpty(params["filename"], contentTypeParams["name"])
	return model.DecodeHeaderValue(filename), strings.EqualFold(mediaType, "attachment") || filename != ""
}

func safeAttachmentText(mediaType, charsetName string, data []byte) (string, bool) {
	if !attachmentTextMediaType(mediaType) {
		return "", false
	}
	if (charsetName == "" || strings.EqualFold(charsetName, "utf-8") || strings.EqualFold(charsetName, "us-ascii")) && !utf8.Valid(data) {
		return "", false
	}
	text := decodeCharset(data, charsetName)
	if !likelyText([]byte(text)) {
		return "", false
	}
	if mediaType == "text/html" {
		text = htmlText([]byte(text))
	}
	text = strings.TrimSpace(text)
	return text, text != ""
}

func attachmentTextMediaType(mediaType string) bool {
	return mediaType == "text/plain" || mediaType == "text/html" || mediaType == "text/csv" ||
		mediaType == "text/markdown" || mediaType == "text/x-markdown" || mediaType == "text/calendar" ||
		mediaType == "text/vcard" || mediaType == "text/x-vcard" || mediaType == "application/json" ||
		mediaType == "application/xml" || mediaType == "text/xml" ||
		(strings.HasPrefix(mediaType, "application/") && (strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")))
}

func decodeCharset(data []byte, charsetName string) string {
	if charsetName != "" && !strings.EqualFold(charsetName, "utf-8") && !strings.EqualFold(charsetName, "us-ascii") {
		reader, err := charset.NewReaderLabel(charsetName, bytes.NewReader(data))
		if err == nil {
			decoded, readErr := io.ReadAll(reader)
			if readErr == nil {
				data = decoded
			}
		}
	}
	return strings.ToValidUTF8(string(data), "�")
}

func likelyText(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	controls := 0
	for _, value := range data {
		if value == 0 {
			return false
		}
		if value < 0x20 && value != '\n' && value != '\r' && value != '\t' && value != '\f' {
			controls++
		}
	}
	return controls*100 <= len(data)
}

func textualPayload(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return htmlText(trimmed)
	}
	return string(data)
}

var whitespace = regexp.MustCompile(`\s+`)

func htmlText(data []byte) string {
	root, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return string(data)
	}
	var result strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			result.WriteString(node.Data)
			result.WriteByte(' ')
		}
		if node.Type == html.ElementNode && (node.Data == "script" || node.Data == "style") {
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return strings.TrimSpace(whitespace.ReplaceAllString(result.String(), " "))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := values[:0]
	for _, value := range values {
		if value = strings.TrimSpace(value); value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// snippetText is what a result snippet may quote: the fields a person
// recognizes. Storage names, item headers, raw iCalendar values (UIDs,
// stamps), and structured names stay searchable but are never shown.
func snippetText(doc document, data []byte) string {
	body := doc.Content
	switch model.FolderType(doc.Type) {
	case model.FolderTypeContacts:
		body = strings.Join(append([]string{doc.ContactOrgView, doc.ContactPhoneView}, doc.ContactEmails...), "\n")
	case model.FolderTypeCalendar, model.FolderTypeTasks:
		body = readableICalendarText(data)
	}
	return strings.Join(uniqueStrings([]string{doc.Subject, doc.Title, body, doc.Sender, doc.Recipients, doc.AttachmentText, doc.Attachment}), "\n")
}

// readableICalendarText keeps the iCalendar properties people write.
func readableICalendarText(data []byte) string {
	text := strings.NewReplacer("\r\n ", "", "\r\n\t", "", "\n ", "", "\n\t", "").Replace(string(data))
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(strings.ToUpper(name), ";")
		switch name {
		case "SUMMARY", "DESCRIPTION", "LOCATION", "COMMENT", "CATEGORIES", "RESOURCES", "CONTACT":
			value = strings.NewReplacer("\\n", "\n", "\\N", "\n", "\\,", ",", "\\;", ";", "\\\\", "\\").Replace(value)
			out = append(out, value)
		}
	}
	return strings.Join(uniqueStrings(out), "\n")
}

func validateDocument(doc document) error {
	if doc.ItemID == "" || doc.FolderID == "" || doc.Type == "" {
		return fmt.Errorf("search document lacks identity")
	}
	return nil
}
