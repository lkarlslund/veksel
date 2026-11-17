package spam

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type symbolInfo struct {
	score       float64
	description string
}

// builtinSymbols are the heuristic and authentication symbols with their
// default scores. Blocklist symbols are defined by their zones.
var builtinSymbols = map[string]symbolInfo{
	"MISSING_FROM":             {2.0, "Message has no From header"},
	"MISSING_SUBJECT":          {1.0, "Message has no Subject header"},
	"MISSING_MESSAGE_ID":       {0.5, "Message has no Message-ID header"},
	"MISSING_DATE":             {0.5, "Message has no Date header"},
	"CAPS_SUBJECT":             {1.5, "Subject is mostly upper case"},
	"SPAM_PHRASE":              {3.0, "Subject contains a common spam phrase"},
	"HTML_HEAVY":               {1.0, "HTML markup outweighs visible text more than ten to one"},
	"SALES_LANGUAGE":           {1.0, "Body uses several sales phrases"},
	"FROM_DOMAIN_MISMATCH":     {1.0, "From domain differs from the envelope sender domain"},
	"SPF_FAIL":                 {3.0, "SPF fail for the envelope sender"},
	"SPF_SOFTFAIL":             {1.5, "SPF softfail for the envelope sender"},
	"DKIM_INVALID":             {2.0, "DKIM signature did not verify"},
	"DKIM_MISSING":             {0.5, "Message carries no DKIM signature"},
	"DMARC_FAIL":               {2.0, "DMARC evaluation failed for the From domain"},
	"DNS_LOOKUP_ERROR":         {0, "A blocklist lookup failed; the zone did not contribute"},
	"ATTACH_DANGEROUS_EXT":     {6.0, "Attachment has a dangerous executable or script extension"},
	"ATTACH_DOUBLE_EXT":        {4.0, "Attachment hides a dangerous extension behind a document extension"},
	"ATTACH_TYPE_MISMATCH":     {4.0, "Attachment content does not match its file name"},
	"ATTACH_MACRO":             {3.0, "Attachment is an Office document with macros"},
	"ATTACH_ENCRYPTED_ARCHIVE": {3.0, "Attachment is a password-protected archive"},
	"ATTACH_ARCHIVE_BOMB":      {3.0, "Attachment archive declares an implausible expanded size"},
	"ATTACH_RTLO":              {6.0, "Attachment file name contains text-direction or zero-width spoofing characters"},
	"ATTACH_HTML_FORM":         {3.0, "HTML attachment contains a form, password field, or script"},
	symbolPhishDisplayAddr:     {3.0, "From display name shows an address or domain other than the sender's"},
	symbolPhishInternalName:    {2.5, "External sender uses a local user's display name or a hosted domain's name"},
	symbolPhishLookalike:       {4.0, "Sender, Reply-To, or link domain imitates a hosted domain or protected brand"},
	symbolPhishMixedScript:     {3.0, "Domain mixes letters from different scripts"},
	symbolPhishReplyTo:         {1.5, "Reply-To diverts answers away from a freemail or hosted From domain"},
	symbolPhishHrefMismatch:    {2.5, "Link text shows a different domain than the link opens"},
	symbolPhishURLIP:           {2.0, "Link points at a raw IP address"},
	symbolPhishURLShortener:    {0.5, "Link uses a URL shortener that hides its destination"},
	symbolPhishURLScript:       {3.0, "Link or form uses a javascript:, vbscript:, or data: URI"},
	symbolPhishHTMLForm:        {3.0, "HTML body contains a password field or a form posting to another domain"},
	symbolPhishBrand:           {3.0, "Display name or subject names a protected brand the sender is not DMARC-authenticated for"},
	"USER_ALLOWLIST":           {0, "Sender is on the recipient's allow list"},
	"USER_BLOCKLIST":           {0, "Sender is on the recipient's block list"},
}

const maxSymbolScoreEntries = 256

// validSymbolName accepts 1-64 upper-case letters, digits, and underscores.
func validSymbolName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validSymbolScore(score float64) bool {
	return !math.IsNaN(score) && !math.IsInf(score, 0) && score >= -100 && score <= 100
}

// Settings is the textual managed-configuration form of an engine
// configuration. Trusted networks and the resolver are parsed by their
// owners.
type Settings struct {
	Thresholds   Thresholds
	SymbolScores []string
	DNSBL        []string
	RHSBL        []string
	URIBL        []string
	// ProtectedBrands and URLShorteners feed the phishing checks.
	ProtectedBrands []string
	URLShorteners   []string
}

// ParseSettings validates settings and returns the engine configuration
// they describe. Symbol overrides must name a built-in symbol or one
// defined by a known or configured zone, so a typo cannot silently do
// nothing.
func ParseSettings(settings Settings) (Config, error) {
	if err := settings.Thresholds.Validate(); err != nil {
		return Config{}, err
	}
	config := Config{Thresholds: settings.Thresholds}
	var err error
	if config.DNSBL, err = ParseZones(ZoneDNSBL, settings.DNSBL); err != nil {
		return Config{}, err
	}
	if config.RHSBL, err = ParseZones(ZoneRHSBL, settings.RHSBL); err != nil {
		return Config{}, err
	}
	if config.URIBL, err = ParseZones(ZoneURIBL, settings.URIBL); err != nil {
		return Config{}, err
	}
	if config.ProtectedBrands, config.URLShorteners, err = parsePhishSettings(settings.ProtectedBrands, settings.URLShorteners); err != nil {
		return Config{}, err
	}
	known := knownZoneSymbols()
	for _, zones := range [][]Zone{config.DNSBL, config.RHSBL, config.URIBL} {
		for _, zone := range zones {
			for _, rule := range zone.Rules {
				if !rule.Refused {
					known[rule.Symbol] = true
				}
			}
		}
	}
	if config.SymbolScores, err = parseSymbolScores(settings.SymbolScores, known); err != nil {
		return Config{}, err
	}
	return config, nil
}

// parseSymbolScores parses NAME=score override entries.
func parseSymbolScores(entries []string, known map[string]bool) (map[string]float64, error) {
	if len(entries) > maxSymbolScoreEntries {
		return nil, fmt.Errorf("at most %d symbol score overrides are allowed", maxSymbolScoreEntries)
	}
	scores := make(map[string]float64, len(entries))
	for _, entry := range entries {
		name, value, found := strings.Cut(strings.TrimSpace(entry), "=")
		name, value = strings.ToUpper(strings.TrimSpace(name)), strings.TrimSpace(value)
		if !found || !validSymbolName(name) {
			return nil, fmt.Errorf("symbol score %q must have the form SYMBOL=score", entry)
		}
		if _, builtin := builtinSymbols[name]; !builtin && !known[name] {
			return nil, fmt.Errorf("symbol score %q names an unknown symbol", entry)
		}
		score, err := strconv.ParseFloat(value, 64)
		if err != nil || !validSymbolScore(score) {
			return nil, fmt.Errorf("symbol score %q must be a number between -100 and 100", entry)
		}
		if _, duplicate := scores[name]; duplicate {
			return nil, fmt.Errorf("symbol %s has more than one score override", name)
		}
		scores[name] = score
	}
	return scores, nil
}
