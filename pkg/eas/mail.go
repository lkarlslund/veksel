package eas

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"html"
	"mime"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// AirSyncBase body types (MS-ASAIRS 2.2.2.22.1).
const (
	bodyText = 1
	bodyHTML = 2
	bodyRTF  = 3
	bodyMIME = 4
)

const easDateFormat = "2006-01-02T15:04:05.000Z"

// BodyPreference is one client body request (MS-ASAIRS 2.2.2.7).
type BodyPreference struct {
	Type           int   `json:"type"`
	TruncationSize int64 `json:"truncation_size,omitempty"`
	AllOrNone      bool  `json:"all_or_none,omitempty"`
	Preview        int   `json:"preview,omitempty"`
}

func parseBodyPreferences(parent *Node) []BodyPreference {
	var preferences []BodyPreference
	for _, node := range parent.ChildrenNamed("BodyPreference") {
		kind, _ := strconv.Atoi(childText(node, "Type"))
		if kind < bodyText || kind > bodyMIME {
			continue
		}
		size, _ := strconv.ParseInt(childText(node, "TruncationSize"), 10, 64)
		preview, _ := strconv.Atoi(childText(node, "Preview"))
		preferences = append(preferences, BodyPreference{
			Type: kind, TruncationSize: max(size, 0), AllOrNone: childText(node, "AllOrNone") == "1", Preview: min(max(preview, 0), 255),
		})
	}
	return preferences
}

// chooseBody picks the representation for one message. MIME is returned
// only when the client asked for it, for every message (MIMESupport 2) or
// for S/MIME (1), or when it is the only type requested. Otherwise HTML
// beats plain text, and RTF, which Veksel does not author, falls back to text.
func chooseBody(preferences []BodyPreference, mimeSupport int, smime bool) BodyPreference {
	byType := map[int]BodyPreference{}
	for _, preference := range preferences {
		if _, seen := byType[preference.Type]; !seen {
			byType[preference.Type] = preference
		}
	}
	if preference, ok := byType[bodyMIME]; ok && (mimeSupport == 2 || mimeSupport == 1 && smime || len(byType) == 1) {
		return preference
	}
	if preference, ok := byType[bodyHTML]; ok {
		return preference
	}
	if preference, ok := byType[bodyText]; ok {
		return preference
	}
	if preference, ok := byType[bodyRTF]; ok {
		preference.Type = bodyText
		return preference
	}
	if smime && mimeSupport > 0 {
		return BodyPreference{Type: bodyMIME}
	}
	return BodyPreference{Type: bodyText}
}

// bodyNode renders an AirSyncBase Body: Type, EstimatedDataSize, Truncated,
// Data, Preview, in schema order.
func bodyNode(kind int, content []byte, preference BodyPreference, previewSource string) *Node {
	body := E(17, "Body", T(17, "Type", strconv.Itoa(kind)), T(17, "EstimatedDataSize", strconv.Itoa(len(content))))
	data, truncated := content, false
	if preference.TruncationSize > 0 && int64(len(content)) > preference.TruncationSize {
		truncated = true
		if preference.AllOrNone {
			data = nil
		} else {
			data = truncateUTF8(content, int(preference.TruncationSize), kind != bodyMIME)
		}
	}
	if truncated {
		body.Children = append(body.Children, T(17, "Truncated", "1"))
	}
	if data != nil || !truncated {
		body.Children = append(body.Children, dataNode(17, "Data", data))
	}
	if preference.Preview > 0 && previewSource != "" {
		body.Children = append(body.Children, T(17, "Preview", string(truncateUTF8([]byte(collapseWhitespace(previewSource)), preference.Preview, true))))
	}
	return body
}

// dataNode carries text as an inline string and falls back to opaque data
// for content that contains NUL, which inline strings cannot encode.
func dataNode(page byte, tag string, data []byte) *Node {
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return O(page, tag, append([]byte{}, data...))
	}
	if len(data) == 0 {
		return O(page, tag, []byte{})
	}
	return T(page, tag, string(data))
}

func truncateUTF8(data []byte, limit int, runeSafe bool) []byte {
	if limit >= len(data) {
		return data
	}
	if runeSafe {
		for limit > 0 && !utf8.RuneStart(data[limit]) {
			limit--
		}
	}
	return data[:limit]
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func textToHTML(text string) string {
	return "<html><body><div>" + strings.ReplaceAll(html.EscapeString(text), "\n", "<br>\n") + "</div></body></html>"
}

func messageClass(item model.Item, projection service.MessageProjection, method string) string {
	contentType, params, _ := mime.ParseMediaType(headerValue(item.Data, "Content-Type"))
	switch {
	case contentType == "multipart/signed":
		return "IPM.Note.SMIME.MultipartSigned"
	case contentType == "application/pkcs7-mime" || contentType == "application/x-pkcs7-mime":
		if strings.EqualFold(params["smime-type"], "signed-data") {
			return "IPM.Note.SMIME.MultipartSigned"
		}
		return "IPM.Note.SMIME"
	}
	switch method {
	case "REQUEST":
		return "IPM.Schedule.Meeting.Request"
	case "CANCEL":
		return "IPM.Schedule.Meeting.Canceled"
	case "REPLY":
		return "IPM.Schedule.Meeting.Resp.Pos"
	}
	return "IPM.Note"
}

func headerValue(data []byte, name string) string {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	return message.Header.Get(name)
}

// emailData renders a mail item as MS-ASEMAIL ApplicationData.
func (h *Handler) emailData(command *commandContext, folder model.Folder, item model.Item, options SyncOptions) *Node {
	projection, err := service.ProjectMIME(item.Data)
	if err != nil {
		projection = service.MessageProjection{Headers: item.Headers}
	}
	header := func(name string) string {
		if value := projection.Headers[name]; value != "" {
			return value
		}
		return item.Headers[name]
	}
	method := ""
	var invitation *calendarEvent
	if len(projection.Calendar) > 0 {
		if message, parseErr := calendar.ParseITIP(projection.Calendar); parseErr == nil {
			method = strings.ToUpper(message.Method)
		}
		invitation = parseCalendarEvent(projection.Calendar)
	}
	class := messageClass(item, projection, method)
	data := E(0, "ApplicationData")
	add := func(nodes ...*Node) { data.Children = append(data.Children, nodes...) }
	if to := header("To"); to != "" {
		add(T(2, "To", to))
	}
	if cc := header("Cc"); cc != "" {
		add(T(2, "Cc", cc))
	}
	if from := header("From"); from != "" {
		add(T(2, "From", from))
	}
	subject := header("Subject")
	if subject == "" {
		subject = itemSubject(item)
	}
	add(T(2, "Subject", subject))
	if replyTo := header("Reply-To"); replyTo != "" {
		add(T(2, "ReplyTo", replyTo))
	}
	received := item.InternalDate
	if received.IsZero() {
		received = item.CreatedAt
	}
	add(T(2, "DateReceived", received.UTC().Format(easDateFormat)))
	if displayTo := displayNames(header("To")); displayTo != "" {
		add(T(2, "DisplayTo", displayTo))
	}
	add(T(2, "ThreadTopic", threadTopic(subject)), T(2, "Importance", easImportance(item.Headers)), T(2, "Read", boolNumber(hasFlag(item.Flags, model.FlagSeen))))
	smime := strings.HasPrefix(class, "IPM.Note.SMIME")
	preference := chooseBody(options.BodyPreferences, options.MIMESupport, smime)
	if preference.Type != bodyMIME && len(projection.Attachments) > 0 {
		attachments := E(17, "Attachments")
		for _, attachment := range projection.Attachments {
			node := E(17, "Attachment",
				T(17, "DisplayName", attachment.Name),
				T(17, "FileReference", encodeServerID("a:", item.ID+"/"+attachment.PartID)),
				T(17, "Method", "1"),
				T(17, "EstimatedDataSize", strconv.FormatInt(attachment.Size, 10)))
			if attachment.ContentID != "" {
				node.Children = append(node.Children, T(17, "ContentId", attachment.ContentID))
			}
			if attachment.Inline || attachment.ContentID != "" {
				node.Children = append(node.Children, T(17, "IsInline", "1"))
			}
			attachments.Children = append(attachments.Children, node)
		}
		add(attachments)
	}
	text := projection.Text
	if text == "" && projection.HTML != "" {
		text = service.HTMLToText(projection.HTML)
	}
	switch preference.Type {
	case bodyMIME:
		add(bodyNode(bodyMIME, item.Data, preference, text))
	case bodyHTML:
		content := projection.HTML
		if content == "" {
			content = textToHTML(text)
		}
		add(bodyNode(bodyHTML, []byte(content), preference, text))
	default:
		add(bodyNode(bodyText, []byte(text), preference, text))
	}
	add(T(2, "MessageClass", class), T(2, "InternetCPID", "65001"))
	if hasFlag(item.Flags, model.FlagFlagged) {
		add(E(2, "Flag", T(2, "Status", "2"), T(2, "FlagType", "Follow up")))
	} else {
		add(E(2, "Flag"))
	}
	add(T(2, "ContentClass", "urn:content-classes:message"))
	if invitation != nil && method == "REQUEST" {
		add(meetingRequestNode(invitation, h.userLocation(command)))
	}
	native := bodyText
	if projection.HTML != "" {
		native = bodyHTML
	}
	add(T(17, "NativeBodyType", strconv.Itoa(native)))
	if command.version(14, 0) {
		add(O(22, "ConversationId", conversationID(subject)), O(22, "ConversationIndex", conversationIndex(received)))
	}
	if command.version(16, 0) && folderIsDrafts(folder) {
		add(T(22, "IsDraft", "1"))
		if bcc := header("Bcc"); bcc != "" {
			add(T(22, "Bcc", bcc))
		}
	}
	return data
}

func folderIsDrafts(folder model.Folder) bool {
	return strings.EqualFold(strings.TrimPrefix(folder.SpecialUse, "\\"), model.SpecialUseDrafts)
}

func displayNames(list string) string {
	addresses, err := mail.ParseAddressList(list)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address.Name != "" {
			names = append(names, address.Name)
		} else {
			names = append(names, address.Address)
		}
	}
	return strings.Join(names, "; ")
}

// threadTopic strips reply and forward prefixes.
func threadTopic(subject string) string {
	for {
		trimmed := strings.TrimSpace(subject)
		lower := strings.ToLower(trimmed)
		stripped := false
		for _, prefix := range []string{"re:", "fw:", "fwd:", "aw:", "sv:", "vs:", "wg:", "tr:"} {
			if strings.HasPrefix(lower, prefix) {
				trimmed = trimmed[len(prefix):]
				stripped = true
				break
			}
		}
		if !stripped {
			return trimmed
		}
		subject = trimmed
	}
}

// conversationID derives a stable 16-byte identifier from the thread topic,
// which is how Exchange groups messages for clients without threading data.
func conversationID(subject string) []byte {
	sum := sha256.Sum256([]byte(strings.ToLower(threadTopic(subject))))
	return sum[:16]
}

// conversationIndex is the 22-byte header block of MS-OXOMSG 2.2.1.3.
func conversationIndex(at time.Time) []byte {
	index := make([]byte, 22)
	filetime := uint64(at.UTC().UnixNano()/100) + 116444736000000000
	index[0] = 0x01
	binary.BigEndian.PutUint32(index[1:5], uint32(filetime>>32))
	index[5] = byte(filetime >> 24)
	return index
}

func easImportance(headers map[string]string) string {
	switch service.MessageImportance(headers) {
	case service.MailImportanceLow:
		return "0"
	case service.MailImportanceHigh:
		return "2"
	default:
		return "1"
	}
}

// globalObjectID encodes a calendar UID as PidLidGlobalObjectId
// (MS-OXOCAL 2.2.1.27), the form EAS uses to correlate a meeting request
// with its calendar item.
func globalObjectID(uid string) string {
	header := []byte{0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xE0, 0x00, 0x74, 0xC5, 0xB7, 0x10, 0x1A, 0x82, 0xE0, 0x08}
	if decoded, ok := outlookUID(uid); ok {
		return base64.StdEncoding.EncodeToString(decoded)
	}
	payload := append([]byte("vCal-Uid\x01\x00\x00\x00"), uid...)
	payload = append(payload, 0)
	buffer := make([]byte, 0, len(header)+20+len(payload))
	buffer = append(buffer, header...)
	buffer = append(buffer, make([]byte, 4+8+8)...)
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(payload)))
	buffer = append(buffer, size...)
	buffer = append(buffer, payload...)
	return base64.StdEncoding.EncodeToString(buffer)
}

// outlookUID recognizes a UID that is itself a hex-encoded global object
// ID, as Outlook and Exchange generate them.
func outlookUID(uid string) ([]byte, bool) {
	if len(uid) < 80 || len(uid)%2 != 0 || !strings.HasPrefix(strings.ToUpper(uid), "040000008200E00074C5B7101A82E008") {
		return nil, false
	}
	decoded := make([]byte, len(uid)/2)
	for index := range decoded {
		value, err := strconv.ParseUint(uid[index*2:index*2+2], 16, 8)
		if err != nil {
			return nil, false
		}
		decoded[index] = byte(value)
	}
	return decoded, true
}

// uidFromGlobalObjectID reverses globalObjectID.
func uidFromGlobalObjectID(value string) string {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) < 40 {
		return ""
	}
	size := int(binary.LittleEndian.Uint32(data[36:40]))
	payload := data[40:]
	if size > len(payload) {
		return ""
	}
	payload = payload[:size]
	if bytes.HasPrefix(payload, []byte("vCal-Uid\x01\x00\x00\x00")) {
		return strings.TrimRight(string(payload[12:]), "\x00")
	}
	return strings.ToUpper(hexString(data))
}

func hexString(data []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for index, value := range data {
		result[index*2], result[index*2+1] = digits[value>>4], digits[value&0x0F]
	}
	return string(result)
}
