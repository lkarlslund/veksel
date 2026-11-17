package spam

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	// MaxSampleTokens caps the distinct tokens taken from one message.
	MaxSampleTokens = 1000
	minTokenRunes   = 3
	maxTokenRunes   = 24
	maxURLTokens    = 50
)

// Sample is the statistical classifier's view of one message: its distinct
// tokens and a stable key that identifies the message across moves,
// copies, and the headers delivery adds.
type Sample struct {
	Key    string
	Tokens []string
}

// NewSample tokenizes raw and derives its key from the Message-ID and the
// body, which delivery and moves leave untouched.
func NewSample(raw []byte) Sample {
	return Sample{Key: sampleKey(raw), Tokens: Tokenize(raw)}
}

func sampleKey(raw []byte) string {
	head, body := model.SplitHeaderBody(raw)
	messageID := ""
	// head aliases raw, so it is capped before appending: a plain append
	// would overwrite the first body bytes of the caller's message.
	if message, err := mail.ReadMessage(bytes.NewReader(append(head[:len(head):len(head)], "\r\n\r\n"...))); err == nil {
		messageID = strings.TrimSpace(message.Header.Get("Message-Id"))
	}
	digest := sha256.New()
	digest.Write([]byte(messageID))
	digest.Write([]byte{0})
	digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil)[:16])
}

// Tokenize returns the distinct classifier tokens of raw, in order of first
// appearance and at most MaxSampleTokens: lower-cased words of the subject
// (prefixed "s:") and of the decoded text and HTML bodies, the From domain,
// the mailer, the class of the relaying host, the top-level content type,
// and linked registrable domains. Words shorter than three or longer than
// 24 characters, and long digit runs, are summarized or skipped.
func Tokenize(raw []byte) []string {
	t := tokenizer{seen: make(map[string]bool)}
	var header mail.Header
	if message, err := mail.ReadMessage(bytes.NewReader(raw)); err == nil {
		header = message.Header
	}
	t.words("s:", decodeHeader(header.Get("Subject")))
	t.headers(header)
	body := parseContent(raw)
	for _, text := range body.text {
		t.words("", text)
	}
	for _, text := range body.htmlText {
		t.words("", text)
	}
	for _, domain := range extractURIDomains(body, maxURLTokens) {
		t.add("url:" + domain)
	}
	return t.tokens
}

type tokenizer struct {
	tokens []string
	seen   map[string]bool
}

func (t *tokenizer) add(token string) {
	if len(t.tokens) < MaxSampleTokens && !t.seen[token] {
		t.seen[token] = true
		t.tokens = append(t.tokens, token)
	}
}

func (t *tokenizer) words(prefix, text string) {
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '\'' && r != '$'
	}) {
		if len(t.tokens) >= MaxSampleTokens {
			return
		}
		word = strings.ToLower(strings.Trim(word, "'"))
		runes := utf8.RuneCountInString(word)
		switch {
		case runes < minTokenRunes:
		case runes > maxTokenRunes:
			first, _ := utf8.DecodeRuneInString(word)
			t.add(prefix + "skip:" + string(first) + ":" + strconv.Itoa(runes/10*10))
		case runes > 4 && strings.IndexFunc(word, func(r rune) bool { return !unicode.IsDigit(r) }) < 0:
		default:
			t.add(prefix + word)
		}
	}
}

var (
	dynamicHost    = regexp.MustCompile(`(?i)\d{1,3}[-.]\d{1,3}[-.]\d{1,3}|dyn|dsl|pool|dhcp|cable|ppp|client|broadband`)
	addressLiteral = regexp.MustCompile(`\[[^\]]*\]`)
)

// headers adds the From domain, mailer, relaying-host class, and content
// type tokens.
func (t *tokenizer) headers(header mail.Header) {
	if header == nil {
		return
	}
	if domain := extractDomain(header.Get("From")); domain != "" {
		t.add("from:" + domain)
	}
	mailer := header.Get("X-Mailer")
	if mailer == "" {
		mailer = header.Get("User-Agent")
	}
	name := strings.ToLower(strings.TrimLeftFunc(mailer, unicode.IsSpace))
	if end := strings.IndexFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && r != '-' }); end >= 0 {
		name = name[:end]
	}
	if name == "" {
		name = "none"
	}
	t.add("mailer:" + name)
	for _, received := range header["Received"] {
		if class := relayClass(received); class != "" {
			t.add("rcvd:" + class)
			break
		}
	}
	if mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type")); err == nil {
		t.add("ct:" + mediaType)
	}
}

// relayClass classifies the "from" host of a Received header: unknown
// reverse DNS, an address literal, a dynamic-looking name, or a named host.
func relayClass(received string) string {
	lower := strings.ToLower(received)
	start := strings.Index(lower, "from ")
	if start < 0 {
		return ""
	}
	clause := lower[start+5:]
	if end := strings.Index(clause, " by "); end >= 0 {
		clause = clause[:end]
	}
	fields := strings.Fields(clause)
	if len(fields) == 0 {
		return ""
	}
	switch {
	case strings.Contains(clause, "unknown"):
		return "unknown"
	case strings.HasPrefix(fields[0], "["):
		return "literal"
	case dynamicHost.MatchString(addressLiteral.ReplaceAllString(clause, "")):
		return "dynamic"
	default:
		return "named"
	}
}
