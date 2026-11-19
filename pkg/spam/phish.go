package spam

import (
	"context"
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"golang.org/x/net/html"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// Phishing and impersonation symbols. Each names one deception technique;
// options carry the offending value, bounded to maxOptionBytes.
const (
	symbolPhishDisplayAddr   = "PHISH_DISPLAY_ADDR"
	symbolPhishInternalName  = "PHISH_INTERNAL_NAME"
	symbolPhishLookalike     = "PHISH_LOOKALIKE_DOMAIN"
	symbolPhishMixedScript   = "PHISH_MIXED_SCRIPT"
	symbolPhishReplyTo       = "PHISH_REPLYTO_MISMATCH"
	symbolPhishHrefMismatch  = "PHISH_HREF_MISMATCH"
	symbolPhishURLIP         = "PHISH_URL_IP"
	symbolPhishURLShortener  = "PHISH_URL_SHORTENER"
	symbolPhishURLScript     = "PHISH_URL_SCRIPT"
	symbolPhishHTMLForm      = "PHISH_HTML_FORM"
	symbolPhishBrand         = "PHISH_BRAND"
	maxOptionBytes           = 96
	maxProtectedBrands       = 256
	maxURLShorteners         = 512
	maxBrandLength           = 64
	maxAnchorTextBytes       = 256
	identityRetryInterval    = 10 * time.Second
	DefaultIdentityCacheTTL  = time.Minute
	minLookalikeLabelRunes   = 4
	minDistanceOneLabelRunes = 5
	minDistanceTwoLabelRunes = 9
)

var defaultURLShorteners = []string{
	"bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
	"shorturl.at", "tiny.cc", "rb.gy", "t.ly", "v.gd", "s.id", "lnkd.in", "bl.ink", "clck.ru", "shorte.st", "adf.ly", "qrco.de",
}

// DefaultURLShorteners returns the built-in URL shortener domains.
func DefaultURLShorteners() []string { return slices.Clone(defaultURLShorteners) }

// freemailDomains are consumer mailbox providers anyone can register at.
var freemailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "yahoo.com": true, "yahoo.co.uk": true, "yahoo.fr": true, "yahoo.de": true,
	"ymail.com": true, "outlook.com": true, "hotmail.com": true, "hotmail.co.uk": true, "hotmail.fr": true, "live.com": true,
	"msn.com": true, "aol.com": true, "icloud.com": true, "me.com": true, "mac.com": true, "gmx.com": true, "gmx.net": true,
	"gmx.de": true, "web.de": true, "mail.com": true, "mail.ru": true, "yandex.com": true, "yandex.ru": true, "proton.me": true,
	"protonmail.com": true, "zoho.com": true, "qq.com": true, "163.com": true, "126.com": true, "tutanota.com": true,
	"fastmail.com": true, "hey.com": true,
}

// LocalIdentities are the names impersonation checks protect: hosted
// domains and the display names of local users.
type LocalIdentities struct {
	Domains      []string
	DisplayNames []string
}

// Directory lists the local identities. It is consulted through an
// IdentityCache, never once per message.
type Directory interface {
	LocalIdentities(context.Context) (LocalIdentities, error)
}

// IdentityCache serves a Directory's identities, reloading them at most
// once per TTL. A failed reload keeps the previous identities and retries
// shortly. It outlives engine replacement and is safe for concurrent use.
type IdentityCache struct {
	directory Directory
	ttl       time.Duration
	now       func() time.Time

	mu      sync.Mutex
	value   *identities
	expires time.Time
}

// NewIdentityCache caches directory for ttl, defaulting to
// DefaultIdentityCacheTTL.
func NewIdentityCache(directory Directory, ttl time.Duration) *IdentityCache {
	if ttl <= 0 {
		ttl = DefaultIdentityCacheTTL
	}
	return &IdentityCache{directory: directory, ttl: ttl, now: time.Now}
}

// get returns the prepared identities, or nil when none could be loaded.
func (c *IdentityCache) get(ctx context.Context) *identities {
	if c == nil || c.directory == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Before(c.expires) {
		return c.value
	}
	loaded, err := c.directory.LocalIdentities(ctx)
	if err != nil {
		c.expires = now.Add(min(c.ttl, identityRetryInterval))
		return c.value
	}
	c.value, c.expires = prepareIdentities(loaded), now.Add(c.ttl)
	return c.value
}

// identities are LocalIdentities normalized for comparison.
type identities struct {
	domains map[string]bool // hosted domains and their registrable domains
	names   map[string]bool // skeletons of multi-word display names
	hosted  []protected
}

func prepareIdentities(loaded LocalIdentities) *identities {
	prepared := &identities{domains: make(map[string]bool), names: make(map[string]bool)}
	seen := make(map[string]bool)
	for _, domain := range loaded.Domains {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain == "" {
			continue
		}
		prepared.domains[domain] = true
		org := orgDomain(domain)
		prepared.domains[org] = true
		if entry, ok := newProtected(org, org); ok && !seen[entry.domain] {
			seen[entry.domain] = true
			prepared.hosted = append(prepared.hosted, entry)
		}
	}
	for _, name := range loaded.DisplayNames {
		if normalized := normalizeName(name); len(strings.Fields(normalized)) >= 2 {
			prepared.names[skeleton(normalized)] = true
		}
	}
	return prepared
}

// hosts reports whether domain or its registrable domain is hosted. It is
// safe on nil identities.
func (i *identities) hosts(domain string) bool {
	return i != nil && (i.domains[domain] || i.domains[orgDomain(domain)])
}

// protected is a hosted domain or configured brand that lookalikes imitate.
type protected struct {
	display string // as configured, for options
	domain  string // registrable domain; empty for a name-only brand
	label   string // lower-case label or compacted name
	skel    string // skeleton of label
	phrase  string // skeleton of the name as words, for text matching
}

// newProtected parses a brand entry: a domain such as paypal.com, or a
// name such as "Bank of America".
func newProtected(display, entry string) (protected, bool) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if strings.Contains(entry, ".") && !strings.ContainsAny(entry, " \t") {
		domain, ok := registrableDomain(entry)
		if !ok {
			return protected{}, false
		}
		label := domainLabel(domain)
		return protected{display: display, domain: domain, label: label, skel: skeleton(label), phrase: skeleton(label)}, true
	}
	words := strings.Fields(entry)
	compact := strings.Join(words, "")
	if utf8.RuneCountInString(compact) < 3 {
		return protected{}, false
	}
	return protected{display: display, label: compact, skel: skeleton(compact), phrase: skeleton(strings.Join(words, " "))}, true
}

// phishConfig is the prepared phishing configuration of one engine.
type phishConfig struct {
	brands     []protected
	shorteners map[string]bool
}

func newPhishConfig(config Config) phishConfig {
	prepared := phishConfig{shorteners: make(map[string]bool, len(config.URLShorteners))}
	for _, entry := range config.ProtectedBrands {
		if brand, ok := newProtected(strings.TrimSpace(entry), entry); ok {
			prepared.brands = append(prepared.brands, brand)
		}
	}
	for _, host := range config.URLShorteners {
		prepared.shorteners[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")] = true
	}
	return prepared
}

var shortenerPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// parsePhishSettings validates the protected brands and URL shorteners.
func parsePhishSettings(brands, shorteners []string) ([]string, []string, error) {
	if len(brands) > maxProtectedBrands {
		return nil, nil, fmt.Errorf("at most %d protected brands are allowed", maxProtectedBrands)
	}
	parsedBrands := make([]string, 0, len(brands))
	for _, entry := range brands {
		entry = strings.TrimSpace(entry)
		if len(entry) > maxBrandLength {
			return nil, nil, fmt.Errorf("protected brand %q exceeds %d bytes", entry, maxBrandLength)
		}
		if _, ok := newProtected(entry, entry); !ok {
			return nil, nil, fmt.Errorf("protected brand %q must be a name of at least three letters or a registrable domain", entry)
		}
		parsedBrands = append(parsedBrands, entry)
	}
	if len(shorteners) > maxURLShorteners {
		return nil, nil, fmt.Errorf("at most %d URL shorteners are allowed", maxURLShorteners)
	}
	parsedShorteners := make([]string, 0, len(shorteners))
	for _, entry := range shorteners {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if len(host) > 253 || !shortenerPattern.MatchString(host) {
			return nil, nil, fmt.Errorf("URL shortener %q must be a host name", entry)
		}
		parsedShorteners = append(parsedShorteners, host)
	}
	return parsedBrands, parsedShorteners, nil
}

// scorePhishing adds the phishing and impersonation symbols.
func (e *Engine) scorePhishing(ctx context.Context, symbols *symbolSet, headers map[string]string, body content, m Message) {
	ident := e.config.Identities.get(ctx)
	if ident == nil {
		ident = &identities{}
	}
	from := headers["from"]
	fromDomain := extractDomain(from)
	fromOrg := orgDomain(fromDomain)
	external := fromDomain != "" && !ident.hosts(fromDomain)
	name := displayName(from)

	if name != "" && fromOrg != "" {
		for _, shown := range namedDomains(name) {
			if shown != fromOrg && domainLabel(shown) != domainLabel(fromOrg) {
				phishSymbol(symbols, symbolPhishDisplayAddr, name)
			}
		}
	}
	nameSkeleton := skeleton(normalizeName(name))
	if external && name != "" {
		if ident.names[nameSkeleton] {
			phishSymbol(symbols, symbolPhishInternalName, name)
		}
		for _, hosted := range ident.hosted {
			if utf8.RuneCountInString(hosted.label) >= minLookalikeLabelRunes && containsWord(nameSkeleton, hosted.phrase) {
				phishSymbol(symbols, symbolPhishInternalName, name+" ~ "+hosted.domain)
			}
		}
	}
	subject := decodeHeader(headers["subject"])
	subjectSkeleton := skeleton(normalizeName(subject))
	for _, brand := range e.phish.brands {
		mentioned := containsWord(nameSkeleton, brand.phrase) || containsWord(subjectSkeleton, brand.phrase)
		if mentioned && !brandAuthenticated(brand, fromOrg, m.DMARC) {
			phishSymbol(symbols, symbolPhishBrand, brand.display)
		}
	}

	protectedSet := slices.Concat(ident.hosted, e.phish.brands)
	checkDomain := func(domain string) {
		if domain == "" || ident.domains[domain] {
			return
		}
		candidate := newCandidate(domain)
		if candidate.label == "" {
			return
		}
		if mixedScript(candidate.unicodeLabel) {
			phishSymbol(symbols, symbolPhishMixedScript, candidate.unicodeDomain)
		}
		for _, target := range protectedSet {
			if imitates(candidate, target) {
				phishSymbol(symbols, symbolPhishLookalike, candidate.unicodeDomain+" ~ "+target.display)
			}
		}
	}
	checkDomain(fromOrg)
	replyOrgs := replyToDomains(headers["reply-to"])
	for _, org := range replyOrgs {
		checkDomain(org)
		if fromOrg != "" && org != fromOrg && (freemailDomains[fromOrg] || !external) {
			phishSymbol(symbols, symbolPhishReplyTo, fromOrg+" -> "+org)
		}
	}
	for _, domain := range extractURIDomains(body, e.config.MaxURIDomains) {
		checkDomain(domain)
	}

	e.scoreLinks(symbols, body, fromOrg)
}

// scoreLinks adds the link and HTML form symbols.
func (e *Engine) scoreLinks(symbols *symbolSet, body content, fromOrg string) {
	links := slices.Clone(body.links)
	for _, text := range append(append([]string(nil), body.text...), body.htmlText...) {
		links = append(links, urlPattern.FindAllString(deobfuscate(text), maxLinks)...)
	}
	for _, link := range links {
		host := strings.Trim(strings.ToLower(hostFromLink(link)), "[]")
		if host == "" {
			continue
		}
		if ipHost(host) {
			phishSymbol(symbols, symbolPhishURLIP, host)
			continue
		}
		bare := strings.TrimPrefix(host, "www.")
		if org, ok := registrableDomain(bare); e.phish.shorteners[bare] || (ok && e.phish.shorteners[org]) {
			phishSymbol(symbols, symbolPhishURLShortener, bare)
		}
	}
	for _, document := range body.html {
		evidence := scanHTML(document)
		for _, target := range evidence.targets {
			if scriptURI(target) {
				phishSymbol(symbols, symbolPhishURLScript, target)
			}
		}
		for _, anchor := range evidence.anchors {
			if shown, target, ok := hrefMismatch(anchor); ok {
				phishSymbol(symbols, symbolPhishHrefMismatch, shown+" -> "+target)
			}
		}
		if evidence.password {
			phishSymbol(symbols, symbolPhishHTMLForm, "password field")
		}
		for _, action := range evidence.forms {
			host := hostFromLink(action)
			if host == "" {
				continue
			}
			if org := orgDomain(host); org != fromOrg {
				phishSymbol(symbols, symbolPhishHTMLForm, "form posts to "+org)
			}
		}
	}
}

// phishSymbol records a phishing symbol with its bounded offending value.
func phishSymbol(symbols *symbolSet, name, option string) {
	symbols.builtin(name, boundOption(option))
}

// brandAuthenticated reports whether a DMARC pass authenticates the From
// domain as brand.
func brandAuthenticated(brand protected, fromOrg, dmarc string) bool {
	if !strings.EqualFold(dmarc, "pass") || fromOrg == "" {
		return false
	}
	if brand.domain != "" && fromOrg == brand.domain {
		return true
	}
	return skeleton(strings.ReplaceAll(domainLabel(fromOrg), "-", "")) == brand.skel
}

// candidate is a domain compared against protected identities.
type candidate struct {
	domain        string // registrable, ASCII
	label         string // first label of domain, ASCII
	unicodeDomain string
	unicodeLabel  string
	skel          string
}

func newCandidate(domain string) candidate {
	unicodeDomain, err := idna.ToUnicode(domain)
	if err != nil {
		unicodeDomain = domain
	}
	unicodeLabel := domainLabel(unicodeDomain)
	return candidate{domain: domain, label: domainLabel(domain), unicodeDomain: unicodeDomain, unicodeLabel: unicodeLabel, skel: skeleton(unicodeLabel)}
}

// imitates reports whether c looks like target without being it: a
// confusable skeleton, a small edit distance, or target's name as one
// hyphenated part (acme-login.com).
func imitates(c candidate, target protected) bool {
	if c.domain == target.domain || c.label == target.label || c.unicodeLabel == target.label {
		return false
	}
	length := utf8.RuneCountInString(target.label)
	if length < minLookalikeLabelRunes {
		return c.skel == target.skel
	}
	if c.skel == target.skel {
		return true
	}
	distance := editDistance(c.skel, target.skel)
	if (length >= minDistanceOneLabelRunes && distance <= 1) || (length >= minDistanceTwoLabelRunes && distance <= 2) {
		return true
	}
	if length >= minDistanceOneLabelRunes && strings.Contains(c.unicodeLabel, "-") {
		for _, part := range strings.Split(c.unicodeLabel, "-") {
			if skeleton(part) == target.skel {
				return true
			}
		}
	}
	return false
}

// editDistance is the optimal string alignment distance between a and b:
// insertions, deletions, substitutions, and adjacent transpositions.
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	if len(x) > 64 || len(y) > 64 {
		return max(len(x), len(y))
	}
	rows := make([][]int, len(x)+1)
	for i := range rows {
		rows[i] = make([]int, len(y)+1)
		rows[i][0] = i
	}
	for j := range rows[0] {
		rows[0][j] = j
	}
	for i := 1; i <= len(x); i++ {
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			rows[i][j] = min(rows[i-1][j]+1, rows[i][j-1]+1, rows[i-1][j-1]+cost)
			if i > 1 && j > 1 && x[i-1] == y[j-2] && x[i-2] == y[j-1] {
				rows[i][j] = min(rows[i][j], rows[i-2][j-2]+1)
			}
		}
	}
	return rows[len(x)][len(y)]
}

// confusables maps characters to the Latin letters they render like: a
// compact subset of Unicode TR39 for Cyrillic, Greek, and Latin, plus digit
// and case confusions. i, I, l, 1, and | are folded together, as are m/rn
// and w/vv.
var confusables = map[rune]string{
	// Cyrillic
	'а': "a", 'в': "b", 'ь': "b", 'с': "c", 'ԁ': "d", 'е': "e", 'ё': "e", 'һ': "h", 'і': "l", 'ї': "l", 'ј': "j",
	'к': "k", 'ӏ': "l", 'м': "rn", 'н': "h", 'о': "o", 'р': "p", 'ԛ': "q", 'г': "r", 'ѕ': "s", 'т': "t", 'у': "y",
	'ү': "y", 'х': "x", 'ԝ': "vv", 'ѡ': "vv", 'п': "n", 'ц': "u", 'ꙇ': "l",
	// Greek
	'α': "a", 'β': "b", 'ϲ': "c", 'δ': "d", 'ε': "e", 'η': "n", 'ι': "l", 'κ': "k", 'μ': "u", 'ν': "v", 'ο': "o",
	'ρ': "p", 'τ': "t", 'υ': "u", 'χ': "x", 'ω': "vv", 'γ': "y", 'ϳ': "j",
	// Latin and symbols
	'ı': "l", 'ɩ': "l", 'ℓ': "l", 'ǀ': "l", '|': "l", 'i': "l", '1': "l", 'ɡ': "g", 'ɑ': "a",
	'0': "o", 'm': "rn", 'w': "vv", 'ß': "ss", 'ø': "o", 'đ': "d", 'ħ': "h", 'ł': "l",
}

// skeleton maps s to a form in which confusable strings are equal: case
// folded, compatibility-decomposed with combining marks removed, and
// confusable characters replaced by their Latin look-alikes.
func skeleton(s string) string {
	var builder strings.Builder
	for _, r := range norm.NFKD.String(s) {
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		r = unicode.ToLower(r)
		if replacement, ok := confusables[r]; ok {
			builder.WriteString(replacement)
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

// allowedScriptSets are the TR39 "highly restrictive" combinations.
var allowedScriptSets = [][]string{
	{"Latin", "Han", "Hiragana", "Katakana"},
	{"Latin", "Han", "Bopomofo"},
	{"Latin", "Han", "Hangul"},
}

// mixedScript reports whether label mixes letters from scripts that TR39
// does not allow together, such as Latin with Cyrillic.
func mixedScript(label string) bool {
	scripts := make(map[string]bool)
	for _, r := range label {
		if r < utf8.RuneSelf {
			if unicode.IsLetter(r) {
				scripts["Latin"] = true
			}
			continue
		}
		if !unicode.IsLetter(r) {
			continue
		}
		for name, table := range unicode.Scripts {
			if name != "Common" && name != "Inherited" && unicode.Is(table, r) {
				scripts[name] = true
				break
			}
		}
	}
	if len(scripts) <= 1 {
		return false
	}
	for _, allowed := range allowedScriptSets {
		subset := true
		for name := range scripts {
			if !slices.Contains(allowed, name) {
				subset = false
				break
			}
		}
		if subset {
			return false
		}
	}
	return true
}

// containsWord reports whether phrase occurs in text bounded by
// non-alphanumeric characters.
func containsWord(text, phrase string) bool {
	if phrase == "" {
		return false
	}
	for offset := 0; offset < len(text); {
		index := strings.Index(text[offset:], phrase)
		if index < 0 {
			return false
		}
		start, end := offset+index, offset+index+len(phrase)
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		after, _ := utf8.DecodeRuneInString(text[end:])
		if (start == 0 || !isWordRune(before)) && (end == len(text) || !isWordRune(after)) {
			return true
		}
		offset = start + 1
	}
	return false
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// displayName returns the decoded display name of a From mailbox.
func displayName(value string) string {
	if address, err := mail.ParseAddress(value); err == nil {
		return strings.TrimSpace(address.Name)
	}
	if index := strings.LastIndex(value, "<"); index > 0 {
		return strings.Trim(strings.TrimSpace(decodeHeader(value[:index])), `"`)
	}
	return ""
}

func decodeHeader(value string) string {
	return model.DecodeHeaderValue(value)
}

func normalizeName(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.Trim(name, `"' `))), " ")
}

// namedDomains returns the registrable domains of addresses and host names
// written in a display name.
func namedDomains(name string) []string {
	var domains []string
	for _, match := range emailPattern.FindAllStringSubmatch(name, 4) {
		if domain, ok := registrableDomain(match[1]); ok && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	for _, host := range bareDomainPattern.FindAllString(name, 4) {
		if domain, ok := registrableDomain(host); ok && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return domains
}

// replyToDomains returns the distinct organizational domains of Reply-To.
func replyToDomains(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var domains []string
	addresses, err := mail.ParseAddressList(value)
	if err != nil {
		addresses = []*mail.Address{{Address: senderAddress(value)}}
	}
	for _, address := range addresses {
		if org := orgDomain(extractDomain(address.Address)); org != "" && !slices.Contains(domains, org) && len(domains) < 4 {
			domains = append(domains, org)
		}
	}
	return domains
}

// orgDomain returns the registrable domain of host, or the normalized host
// when it has none (reserved or single-label names).
func orgDomain(host string) string {
	if domain, ok := registrableDomain(host); ok {
		return domain
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// domainLabel returns the first label of a domain.
func domainLabel(domain string) string {
	label, _, _ := strings.Cut(domain, ".")
	return label
}

// ipHost reports whether host is an address literal, including the
// decimal, hexadecimal, and octal integer forms browsers accept.
func ipHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		digits := strings.TrimPrefix(part, "0x")
		if digits == "" {
			return false
		}
		hex := digits != part
		for _, r := range digits {
			if !(r >= '0' && r <= '9' || hex && (r >= 'a' && r <= 'f')) {
				return false
			}
		}
	}
	return true
}

// scriptURI reports whether target runs script or embeds content when
// followed. Browsers ignore whitespace and control characters in a scheme.
func scriptURI(target string) bool {
	compact := strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return -1
		}
		return unicode.ToLower(r)
	}, target)
	return strings.HasPrefix(compact, "javascript:") || strings.HasPrefix(compact, "vbscript:") || strings.HasPrefix(compact, "data:")
}

// anchor is one HTML link with its visible text.
type anchor struct {
	href string
	text string
}

// htmlEvidence is what one HTML part reveals about deceptive links and
// credential harvesting.
type htmlEvidence struct {
	anchors  []anchor
	targets  []string // href, action, and formaction values
	forms    []string // form actions
	password bool
}

// scanHTML collects anchors with their text, followed link targets, form
// actions, and password inputs, bounded to maxLinks of each.
func scanHTML(document string) htmlEvidence {
	var evidence htmlEvidence
	tokenizer := html.NewTokenizer(strings.NewReader(document))
	var current *anchor
	skip := 0
	for {
		token := tokenizer.Next()
		switch token {
		case html.ErrorToken:
			return evidence
		case html.TextToken:
			if current != nil && skip == 0 && len(current.text) < maxAnchorTextBytes {
				current.text += string(tokenizer.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			nameBytes, hasAttributes := tokenizer.TagName()
			name := string(nameBytes)
			if name == "script" || name == "style" {
				skip++
			}
			attributes := make(map[string]string)
			for hasAttributes {
				var key, value []byte
				key, value, hasAttributes = tokenizer.TagAttr()
				attributes[strings.ToLower(string(key))] = string(value)
			}
			for _, key := range []string{"href", "action", "formaction"} {
				if value, ok := attributes[key]; ok && len(evidence.targets) < maxLinks {
					evidence.targets = append(evidence.targets, value)
				}
			}
			switch name {
			case "a":
				if href, ok := attributes["href"]; ok && token == html.StartTagToken && len(evidence.anchors) < maxLinks {
					evidence.anchors = append(evidence.anchors, anchor{href: href})
					current = &evidence.anchors[len(evidence.anchors)-1]
				}
			case "form":
				if action := attributes["action"]; action != "" && len(evidence.forms) < maxLinks {
					evidence.forms = append(evidence.forms, action)
				}
			case "input":
				if strings.EqualFold(strings.TrimSpace(attributes["type"]), "password") {
					evidence.password = true
				}
			}
		case html.EndTagToken:
			nameBytes, _ := tokenizer.TagName()
			switch string(nameBytes) {
			case "script", "style":
				if skip > 0 {
					skip--
				}
			case "a":
				current = nil
			}
		}
	}
}

// hrefMismatch reports an anchor whose text is itself a URL or host name
// on a different organizational domain than its href.
func hrefMismatch(link anchor) (string, string, bool) {
	text := strings.TrimSpace(link.text)
	if text == "" || strings.ContainsAny(text, " \t\r\n@") {
		return "", "", false
	}
	text = strings.TrimRight(text, ".,;:!?)>")
	lowerHref := strings.ToLower(strings.TrimSpace(link.href))
	if !strings.HasPrefix(lowerHref, "http://") && !strings.HasPrefix(lowerHref, "https://") && !strings.HasPrefix(lowerHref, "//") {
		return "", "", false
	}
	shownLink := text
	if !strings.Contains(shownLink, "://") {
		shownLink = "http://" + shownLink
	}
	shown, ok := registrableDomain(hostFromLink(shownLink))
	if !ok {
		return "", "", false
	}
	targetHost := strings.Trim(strings.ToLower(hostFromLink(link.href)), "[]")
	if ipHost(targetHost) {
		return shown, targetHost, true
	}
	target, ok := registrableDomain(targetHost)
	if !ok || target == shown || domainLabel(target) == domainLabel(shown) {
		return "", "", false
	}
	return shown, target, true
}

// boundOption truncates an option to maxOptionBytes on a rune boundary.
func boundOption(option string) string {
	option = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, option)
	if len(option) <= maxOptionBytes {
		return option
	}
	cut := maxOptionBytes
	for cut > 0 && !utf8.RuneStart(option[cut]) {
		cut--
	}
	return option[:cut] + "…"
}
