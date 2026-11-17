package spam

import (
	"net/mail"
	"regexp"
	"strings"
)

// scoreHeuristics adds the header and content symbols.
func scoreHeuristics(symbols *symbolSet, headers map[string]string, body content, m Message) {
	if _, ok := headers["from"]; !ok {
		symbols.builtin("MISSING_FROM")
	}
	subject, hasSubject := headers["subject"]
	if !hasSubject {
		symbols.builtin("MISSING_SUBJECT")
	}
	if hasSubject && isAllCaps(subject) {
		symbols.builtin("CAPS_SUBJECT")
	}
	if phrase := matchSpamPhrase(subject); phrase != "" {
		symbols.builtin("SPAM_PHRASE", phrase)
	}
	if _, ok := headers["message-id"]; !ok {
		symbols.builtin("MISSING_MESSAGE_ID")
	}
	if _, ok := headers["date"]; !ok {
		symbols.builtin("MISSING_DATE")
	}
	if calculateHTMLRatio([]byte(strings.Join(body.html, "\n"))) > 10 {
		symbols.builtin("HTML_HEAVY")
	}
	if excessiveSalesWords(body.visibleText()) {
		symbols.builtin("SALES_LANGUAGE")
	}
	if from := headers["from"]; from != "" && m.EnvelopeFrom != "" && fromDomainMismatch(from, m.EnvelopeFrom) {
		symbols.builtin("FROM_DOMAIN_MISMATCH", extractDomain(from), extractDomain(m.EnvelopeFrom))
	}
}

// scoreAuthentication adds symbols for the results the SMTP boundary
// already evaluated.
func scoreAuthentication(symbols *symbolSet, headers map[string]string, m Message) {
	switch strings.ToLower(m.SPF) {
	case "fail":
		symbols.builtin("SPF_FAIL", extractDomain(m.EnvelopeFrom))
	case "softfail":
		symbols.builtin("SPF_SOFTFAIL", extractDomain(m.EnvelopeFrom))
	}
	if _, signed := headers["dkim-signature"]; !signed {
		symbols.builtin("DKIM_MISSING")
	} else if result := strings.ToLower(m.DKIM); result == "fail" || result == "permerror" {
		symbols.builtin("DKIM_INVALID")
	}
	if strings.EqualFold(m.DMARC, "fail") {
		symbols.builtin("DMARC_FAIL", extractDomain(headers["from"]))
	}
}

// isAllCaps checks if the visible text of a subject is mostly uppercase letters.
func isAllCaps(subject string) bool {
	if len(subject) < 10 {
		return false
	}
	var upperCount, alphaCount int
	for _, r := range subject {
		if r >= 'A' && r <= 'Z' {
			upperCount++
			alphaCount++
		} else if r >= 'a' && r <= 'z' {
			alphaCount++
		}
	}
	if alphaCount < 8 {
		return false
	}
	return float64(upperCount)/float64(alphaCount) > 0.8
}

// spamPhrases are common words/phrases found in spam subjects.
var spamPhrases = []string{
	"viagra", "lottery", "winner", "free money", "earn money", "make money",
	"nigerian", "inheritance", "prize claim", "urgent action", "act now",
	"limited offer", "click here", "buy now", "order now", "cialis",
	"pharmacy", "debt relief", "weight loss", "enlargement",
}

// matchSpamPhrase returns the first common spam phrase in subject, or empty.
func matchSpamPhrase(subject string) string {
	lower := strings.ToLower(subject)
	for _, phrase := range spamPhrases {
		if strings.Contains(lower, phrase) {
			return phrase
		}
	}
	return ""
}

var htmlTagPattern = regexp.MustCompile(`<[^>]+>`)

// calculateHTMLRatio estimates the ratio of HTML markup to visible text.
// Returns the ratio (markup bytes / text bytes), or 0 without HTML.
func calculateHTMLRatio(data []byte) float64 {
	text := string(data)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "<html") && !strings.Contains(lower, "<body") {
		return 0
	}
	htmlContent := 0
	for _, tag := range htmlTagPattern.FindAllString(text, -1) {
		htmlContent += len(tag)
	}
	textContent := len(strings.Join(strings.Fields(htmlTagPattern.ReplaceAllString(text, " ")), ""))
	if textContent == 0 {
		return float64(htmlContent)
	}
	return float64(htmlContent) / float64(textContent)
}

// salesWords are words commonly found in spam body text.
var salesWords = []string{
	"buy now", "order today", "limited time", "act now", "free trial",
	"no obligation", "risk free", "guaranteed", "congratulations",
	"you've won", "click here", "unsubscribe", "special offer",
	"discount price", "cheap",
}

// salesWordThreshold is the minimum number of sales words to trigger the rule.
const salesWordThreshold = 3

// excessiveSalesWords checks if the body text contains too many sales-oriented words.
func excessiveSalesWords(body string) bool {
	lower := strings.ToLower(body)
	count := 0
	for _, word := range salesWords {
		if strings.Contains(lower, word) {
			count++
		}
		if count >= salesWordThreshold {
			return true
		}
	}
	return false
}

// senderAddress returns the addr-spec of a mailbox or bare address.
func senderAddress(value string) string {
	if address, err := mail.ParseAddress(value); err == nil {
		return address.Address
	}
	if start := strings.LastIndex(value, "<"); start >= 0 {
		value = value[start+1:]
		if end := strings.Index(value, ">"); end >= 0 {
			value = value[:end]
		}
	}
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(value), "<>"))
}

// extractDomain extracts the lower-case domain from an email address or
// mailbox; a value without @ is returned as a domain.
func extractDomain(addr string) string {
	address := senderAddress(addr)
	if index := strings.LastIndex(address, "@"); index >= 0 {
		return strings.ToLower(strings.TrimSuffix(address[index+1:], "."))
	}
	return strings.ToLower(strings.TrimSuffix(address, "."))
}

// fromDomainMismatch reports whether the From header domain
// differs from the envelope sender domain.
func fromDomainMismatch(fromHeader, envelopeSender string) bool {
	fromDomain, envelopeDomain := extractDomain(fromHeader), extractDomain(envelopeSender)
	return fromDomain != "" && envelopeDomain != "" && fromDomain != envelopeDomain
}
