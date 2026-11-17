package spam

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/mail"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Header and MIME anomaly thresholds.
const (
	dateFutureLimit    = 24 * time.Hour
	datePastLimit      = 7 * 24 * time.Hour
	receivedSkewLimit  = 24 * time.Hour
	maxRecipientFields = 50
	maxMIMENesting     = 5
	minHiddenLetters   = 200
	minZeroWidthInWord = 3
	minSubjectNoise    = 5
)

// anomalySymbols are the header and MIME structure symbols. They join
// builtinSymbols so score overrides and descriptions work like any other.
var anomalySymbols = map[string]symbolInfo{
	"HDR_DATE_INVALID":       {1.0, "Date header cannot be parsed"},
	"HDR_DATE_FUTURE":        {1.5, "Date header is more than 24 hours in the future"},
	"HDR_DATE_PAST":          {0.3, "Date header is more than 7 days before receipt"},
	"HDR_DATE_TZ":            {0.5, "Date header has an impossible or unusual time zone"},
	"HDR_MSGID_INVALID":      {1.0, "Message-ID is not a single <local@domain> identifier"},
	"HDR_MSGID_IP":           {0.3, "Message-ID domain is a bare IP address or localhost"},
	"HDR_MSGID_FORGED_LOCAL": {1.5, "Message-ID uses a hosted domain but the sender is external and unauthenticated"},
	"HDR_RCVD_FORGED_LOCAL":  {2.0, "A Received header added before this server claims delivery by a hosted host name"},
	"HDR_RCVD_ORDER":         {0.8, "Received header dates run out of order by more than a day"},
	"HDR_FROM_MULTI":         {1.5, "Message has more than one From address or From header"},
	"HDR_DUPLICATE":          {1.5, "A mandatory header appears more than once"},
	"HDR_TO_UNDISCLOSED":     {0.3, "To header is empty or undisclosed-recipients"},
	"HDR_TO_FROM_SAME":       {0.5, "The only recipient in To is the From address"},
	"HDR_RCPT_MANY":          {0.8, "More than 50 addresses in To and Cc"},
	"HDR_SUBJ_ENCODED_ASCII": {1.0, "Subject is encoded although it is plain ASCII"},
	"HDR_SUBJ_MIXED_CHARSET": {0.8, "Subject mixes several character sets in encoded words"},
	"HDR_SUBJ_NOISE":         {0.8, "Subject has excessive punctuation or emoji"},
	"HDR_FAKE_REPLY":         {1.0, "Subject claims to be a reply but there is no In-Reply-To or References"},
	"HDR_MAILER_SPAMWARE":    {2.5, "X-Mailer or User-Agent names known bulk-mailing software"},
	"MIME_NO_BOUNDARY":       {2.0, "Multipart message declares no boundary"},
	"MIME_UNTERMINATED":      {1.0, "Multipart message lacks its closing boundary"},
	"MIME_NESTING_DEPTH":     {1.5, "Multipart parts are nested unusually deep"},
	"MIME_BAD_ENCODING":      {1.5, "Content-Transfer-Encoding is not a defined encoding"},
	"MIME_HTML_ONLY":         {0.3, "HTML body without a plain-text alternative"},
	"MIME_BAD_CHARSET":       {0.8, "Text part is not valid in its declared character set"},
	"MIME_BASE64_TEXT":       {0.3, "Plain ASCII text is base64 encoded"},
	"HTML_HIDDEN_TEXT":       {2.0, "HTML hides a large block of text with display:none, zero font size, or matching colors"},
	"TEXT_ZERO_WIDTH":        {2.0, "Invisible zero-width characters are hidden inside words"},
}

func init() { maps.Copy(builtinSymbols, anomalySymbols) }

// spamwareMailers are lower-case fragments of X-Mailer and User-Agent
// values naming mass-mailing and spam tools. Legitimate newsletter
// software is deliberately absent.
var spamwareMailers = []string{
	"mass mailer", "massmailer", "advanced mass sender", "atomic mail sender", "send-safe", "sendsafe",
	"dark mailer", "mail bomber", "bulk mailer", "email blaster", "emailblaster", "turbo mailer",
	"ghostmailer", "evil mailer", "e-mail spider",
}

var (
	messageIDPattern   = regexp.MustCompile(`^<[^<>\s]+@[^<>@\s]+>$`)
	receivedByPattern  = regexp.MustCompile(`(?i)\bby\s+([a-z0-9][a-z0-9._-]*)`)
	fakeReplyPattern   = regexp.MustCompile(`(?i)^\s*re(\[\d+\])?\s*:`)
	encodedWordPattern = regexp.MustCompile(`=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=`)
)

// scoreAnomalies adds the header and MIME structure symbols.
func (e *Engine) scoreAnomalies(ctx context.Context, symbols *symbolSet, headers map[string]string, body content, m Message) {
	ident := e.config.Identities.get(ctx)
	var raw mail.Header
	if message, err := mail.ReadMessage(bytes.NewReader(m.Content)); err == nil {
		raw = message.Header
	}
	fromDomain := extractDomain(headers["from"])
	external := fromDomain != "" && !ident.hosts(fromDomain)
	e.scoreDate(symbols, headers["date"])
	e.scoreMessageID(symbols, ident, headers["message-id"], external, m)
	e.scoreReceived(symbols, ident, raw["Received"], external, m)
	scoreAddressing(symbols, headers, raw, m)
	scoreSubject(symbols, headers)
	scoreMailer(symbols, headers)
	body.structure.score(symbols)
	scoreHiddenContent(symbols, body)
}

func (e *Engine) scoreDate(symbols *symbolSet, value string) {
	if value == "" {
		return
	}
	date, err := mail.ParseDate(value)
	if err != nil {
		symbols.builtin("HDR_DATE_INVALID", boundOption(value))
		return
	}
	switch skew := date.Sub(e.now()); {
	case skew > dateFutureLimit:
		symbols.builtin("HDR_DATE_FUTURE", date.UTC().Format(time.DateOnly))
	case -skew > datePastLimit:
		symbols.builtin("HDR_DATE_PAST", date.UTC().Format(time.DateOnly))
	}
	if _, offset := date.Zone(); offset < -12*3600 || offset > 14*3600 || offset%(15*60) != 0 {
		symbols.builtin("HDR_DATE_TZ", fmt.Sprintf("%+d s", offset))
	}
}

func (e *Engine) scoreMessageID(symbols *symbolSet, ident *identities, value string, external bool, m Message) {
	if value == "" {
		return
	}
	id := strings.TrimSpace(value)
	if !messageIDPattern.MatchString(id) {
		symbols.builtin("HDR_MSGID_INVALID", boundOption(id))
		return
	}
	domain := strings.ToLower(id[strings.LastIndex(id, "@")+1 : len(id)-1])
	domain = strings.Trim(domain, "[]")
	if _, err := netip.ParseAddr(domain); err == nil || domain == "localhost" || strings.HasPrefix(domain, "localhost.") {
		symbols.builtin("HDR_MSGID_IP", domain)
	}
	if external && ident.hosts(domain) && !strings.EqualFold(m.DKIM, "pass") && !strings.EqualFold(m.DMARC, "pass") {
		symbols.builtin("HDR_MSGID_FORGED_LOCAL", domain)
	}
}

// scoreReceived checks the Received chain, newest first. The newest field
// is skipped: it is this server's own, or the last peer's, and either may
// legitimately name a hosted host.
func (e *Engine) scoreReceived(symbols *symbolSet, ident *identities, received []string, external bool, m Message) {
	if addr, err := netip.ParseAddr(m.RemoteIP); err == nil && e.trusted(addr.Unmap()) {
		return
	}
	var newer time.Time
	for index, field := range received {
		if index > 0 && external {
			if match := receivedByPattern.FindStringSubmatch(field); match != nil && ident.hosts(strings.ToLower(match[1])) {
				symbols.builtin("HDR_RCVD_FORGED_LOCAL", strings.ToLower(match[1]))
			}
		}
		_, stamp, found := cutLast(field, ";")
		date, err := mail.ParseDate(strings.TrimSpace(stamp))
		if !found || err != nil {
			continue
		}
		if !newer.IsZero() && date.Sub(newer) > receivedSkewLimit {
			symbols.builtin("HDR_RCVD_ORDER", date.UTC().Format(time.DateOnly))
		}
		newer = date
	}
}

func cutLast(s, sep string) (before, after string, found bool) {
	index := strings.LastIndex(s, sep)
	if index < 0 {
		return s, "", false
	}
	return s[:index], s[index+len(sep):], true
}

func scoreAddressing(symbols *symbolSet, headers map[string]string, raw mail.Header, m Message) {
	for _, name := range []string{"From", "Subject", "Date", "Message-Id", "To"} {
		if len(raw[name]) > 1 {
			symbols.builtin("HDR_DUPLICATE", name)
		}
	}
	from, hasFrom := headers["from"]
	if hasFrom {
		if list, err := mail.ParseAddressList(from); (err == nil && len(list) > 1) || len(raw["From"]) > 1 {
			symbols.builtin("HDR_FROM_MULTI")
		}
	}
	to, hasTo := headers["to"]
	if hasTo {
		compact := strings.ToLower(strings.ReplaceAll(to, " ", ""))
		if compact == "" || strings.Contains(compact, "undisclosed-recipients") || strings.Contains(compact, "undisclosedrecipients") {
			symbols.builtin("HDR_TO_UNDISCLOSED")
		} else if list, err := mail.ParseAddressList(to); err == nil && len(list) == 1 && headers["cc"] == "" &&
			hasFrom && strings.EqualFold(list[0].Address, senderAddress(from)) && !strings.EqualFold(m.DMARC, "pass") {
			symbols.builtin("HDR_TO_FROM_SAME", list[0].Address)
		}
	}
	if count := strings.Count(to, "@") + strings.Count(headers["cc"], "@"); count > maxRecipientFields {
		symbols.builtin("HDR_RCPT_MANY", strconv.Itoa(count))
	}
}

func scoreSubject(symbols *symbolSet, headers map[string]string) {
	subject, ok := headers["subject"]
	if !ok {
		return
	}
	words := encodedWordPattern.FindAllStringSubmatch(subject, -1)
	charsets := make(map[string]bool)
	allASCII := len(words) > 0
	for _, word := range words {
		if charset := strings.ToLower(word[1]); charset != "us-ascii" {
			charsets[charset] = true
		}
		decoded, ok := decodeEncodedWord(word[2], word[3])
		if !ok || !isPrintableASCII(decoded) {
			allASCII = false
		}
	}
	if allASCII {
		symbols.builtin("HDR_SUBJ_ENCODED_ASCII", boundOption(decodeHeader(subject)))
	}
	if len(charsets) > 1 {
		symbols.builtin("HDR_SUBJ_MIXED_CHARSET", strings.Join(slices.Sorted(maps.Keys(charsets)), ","))
	}
	decoded := decodeHeader(subject)
	if subjectNoise(decoded) >= minSubjectNoise {
		symbols.builtin("HDR_SUBJ_NOISE", boundOption(decoded))
	}
	_, replies := headers["in-reply-to"]
	_, references := headers["references"]
	if fakeReplyPattern.MatchString(decoded) && !replies && !references {
		symbols.builtin("HDR_FAKE_REPLY", boundOption(decoded))
	}
}

// decodeEncodedWord decodes the payload of one RFC 2047 encoded word.
func decodeEncodedWord(encoding, payload string) (string, bool) {
	if strings.EqualFold(encoding, "b") {
		data, err := base64.StdEncoding.DecodeString(payload)
		return string(data), err == nil
	}
	var out []byte
	for index := 0; index < len(payload); index++ {
		switch character := payload[index]; {
		case character == '_':
			out = append(out, ' ')
		case character == '=' && index+2 < len(payload):
			value, err := strconv.ParseUint(payload[index+1:index+3], 16, 8)
			if err != nil {
				return "", false
			}
			out = append(out, byte(value))
			index += 2
		default:
			out = append(out, character)
		}
	}
	return string(out), true
}

func isPrintableASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r > '~' })
}

// subjectNoise counts the longest run of !, ?, or $ and the number of
// emoji and pictographic symbols, whichever is larger.
func subjectNoise(subject string) int {
	longest, run, symbolsSeen := 0, 0, 0
	for _, r := range subject {
		if r == '!' || r == '?' || r == '$' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
		if r >= 0x1F000 || unicode.Is(unicode.So, r) {
			symbolsSeen++
		}
	}
	return max(longest, symbolsSeen)
}

func scoreMailer(symbols *symbolSet, headers map[string]string) {
	for _, name := range []string{"x-mailer", "user-agent"} {
		lower := strings.ToLower(headers[name])
		if index := slices.IndexFunc(spamwareMailers, func(fragment string) bool { return strings.Contains(lower, fragment) }); index >= 0 {
			symbols.builtin("HDR_MAILER_SPAMWARE", spamwareMailers[index])
		}
	}
}

// mimeStructure records anomalies the content walker noticed.
type mimeStructure struct {
	noBoundary, unterminated bool
	nesting                  int
	badEncoding              string
	badCharset               string
	base64Text               bool
}

var validEncodings = map[string]bool{"": true, "7bit": true, "8bit": true, "binary": true, "quoted-printable": true, "base64": true}

func (s *mimeStructure) noteEncoding(encoding string) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if !validEncodings[encoding] && s.badEncoding == "" {
		s.badEncoding = encoding
	}
}

// noteText checks one decoded text part against its declared charset and
// encoding.
func (s *mimeStructure) noteText(mediaType, charset, encoding string, data []byte) {
	charset = strings.ToLower(charset)
	switch {
	case charset == "utf-8" && !utf8.Valid(data), charset == "us-ascii" && !isASCII(data):
		if s.badCharset == "" {
			s.badCharset = charset
		}
	}
	if mediaType == "text/plain" && strings.EqualFold(strings.TrimSpace(encoding), "base64") && len(data) > 0 && isASCII(data) {
		s.base64Text = true
	}
}

func isASCII(data []byte) bool {
	return !slices.ContainsFunc(data, func(b byte) bool { return b >= utf8.RuneSelf })
}

func (s mimeStructure) score(symbols *symbolSet) {
	if s.noBoundary {
		symbols.builtin("MIME_NO_BOUNDARY")
	}
	if s.unterminated {
		symbols.builtin("MIME_UNTERMINATED")
	}
	if s.nesting > maxMIMENesting {
		symbols.builtin("MIME_NESTING_DEPTH", strconv.Itoa(s.nesting))
	}
	if s.badEncoding != "" {
		symbols.builtin("MIME_BAD_ENCODING", boundOption(s.badEncoding))
	}
	if s.badCharset != "" {
		symbols.builtin("MIME_BAD_CHARSET", s.badCharset)
	}
	if s.base64Text {
		symbols.builtin("MIME_BASE64_TEXT")
	}
}

func scoreHiddenContent(symbols *symbolSet, body content) {
	if len(body.html) > 0 && len(body.text) == 0 && strings.TrimSpace(strings.Join(body.htmlText, "")) != "" {
		symbols.builtin("MIME_HTML_ONLY")
	}
	hidden := 0
	for _, document := range body.html {
		hidden += hiddenLetters(document)
	}
	if hidden >= minHiddenLetters {
		symbols.builtin("HTML_HIDDEN_TEXT", strconv.Itoa(hidden)+" hidden characters")
	}
	if count := zeroWidthInWords(body.visibleText()); count >= minZeroWidthInWord {
		symbols.builtin("TEXT_ZERO_WIDTH", strconv.Itoa(count)+" characters")
	}
}

// zeroWidthInWords counts invisible characters between two ASCII letters,
// where they can only defeat word matching. Padding next to spaces, as
// preheaders use, and joiners in non-Latin scripts do not count.
func zeroWidthInWords(text string) int {
	runes := []rune(text)
	count := 0
	for index := 1; index+1 < len(runes); index++ {
		switch runes[index] {
		case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			if isASCIILetter(runes[index-1]) && isASCIILetter(runes[index+1]) {
				count++
			}
		}
	}
	return count
}

func isASCIILetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true,
}

// skippedElements never show their text.
var skippedElements = map[string]bool{"head": true, "script": true, "style": true, "title": true}

const maxHTMLStack = 256

// hiddenLetters counts the letters and digits an HTML document hides from
// the reader with inline styles or the hidden attribute.
func hiddenLetters(document string) int {
	type element struct {
		name           string
		hidden, ignore bool
	}
	var stack []element
	hidden, ignore, count := 0, 0, 0
	tokenizer := html.NewTokenizer(strings.NewReader(document))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return count
		case html.TextToken:
			if hidden > 0 && ignore == 0 {
				for _, r := range string(tokenizer.Text()) {
					if unicode.IsLetter(r) || unicode.IsDigit(r) {
						count++
					}
				}
			}
		case html.StartTagToken:
			nameBytes, hasAttributes := tokenizer.TagName()
			name := string(nameBytes)
			var style string
			attribute := false
			for hasAttributes {
				var key, value []byte
				key, value, hasAttributes = tokenizer.TagAttr()
				switch string(key) {
				case "style":
					style = string(value)
				case "hidden":
					attribute = true
				}
			}
			if voidElements[name] || len(stack) >= maxHTMLStack {
				continue
			}
			entry := element{name: name, hidden: attribute || hiddenStyle(style), ignore: skippedElements[name]}
			stack = append(stack, entry)
			if entry.hidden {
				hidden++
			}
			if entry.ignore {
				ignore++
			}
		case html.EndTagToken:
			nameBytes, _ := tokenizer.TagName()
			index := slices.IndexFunc(stack, func(e element) bool { return e.name == string(nameBytes) })
			for index >= 0 && len(stack) > index {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if top.hidden {
					hidden--
				}
				if top.ignore {
					ignore--
				}
			}
		}
	}
}

// hiddenStyle reports whether an inline style hides its element: display
// none, hidden visibility, zero opacity or font size, or text in the
// background color.
func hiddenStyle(style string) bool {
	if style == "" {
		return false
	}
	declarations := make(map[string]string)
	for _, declaration := range strings.Split(style, ";") {
		if name, value, ok := strings.Cut(declaration, ":"); ok {
			declarations[strings.ToLower(strings.TrimSpace(name))] = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "!important")))
		}
	}
	if declarations["display"] == "none" || declarations["visibility"] == "hidden" {
		return true
	}
	if opacity, err := strconv.ParseFloat(declarations["opacity"], 64); err == nil && opacity == 0 {
		return true
	}
	if number, err := strconv.ParseFloat(strings.TrimRight(declarations["font-size"], "pxtemr%"), 64); err == nil && number == 0 {
		return true
	}
	color := normalizeColor(declarations["color"])
	background := normalizeColor(firstNonEmpty(declarations["background-color"], declarations["background"]))
	return color != "" && color == background
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var rgbPattern = regexp.MustCompile(`^rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)$`)

// normalizeColor reduces white and black spellings to #rrggbb; other
// values are compared as written.
func normalizeColor(value string) string {
	value = strings.ReplaceAll(value, " ", "")
	switch {
	case value == "white":
		return "#ffffff"
	case value == "black":
		return "#000000"
	case len(value) == 4 && value[0] == '#':
		return "#" + string([]byte{value[1], value[1], value[2], value[2], value[3], value[3]})
	}
	if match := rgbPattern.FindStringSubmatch(value); match != nil {
		var channels [3]int
		for index := range channels {
			channels[index], _ = strconv.Atoi(match[index+1])
		}
		return fmt.Sprintf("#%02x%02x%02x", channels[0], channels[1], channels[2])
	}
	return value
}
