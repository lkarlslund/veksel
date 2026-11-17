package model

import (
	"encoding/base64"
	"strings"
)

// Contact is a simplified JSON representation of a vCard contact.
type Contact struct {
	ID          string `json:"id"`
	ItemID      string `json:"item_id"`
	ModSeq      uint64 `json:"mod_seq,omitempty"`
	FolderID    string `json:"folder_id"`
	Addressbook string `json:"addressbook"` // folder path, e.g. "Contacts"
	UserID      string `json:"user_id"`
	UID         string `json:"uid,omitempty"` // vCard UID
	FN          string `json:"fn"`            // formatted name
	// Kind is the RFC 6350 object kind when explicitly present. An empty value
	// has the standard meaning "individual". Veksel currently authors and edits
	// ordinary contacts and groups while preserving other imported kinds.
	Kind string `json:"kind,omitempty"`
	// Members contains the absolute URI values from repeated RFC 6350 MEMBER
	// properties. MEMBER is valid only for a vCard 4 group.
	Members    []string         `json:"members,omitempty"`
	N          string           `json:"n,omitempty"` // structured name (family;given;...)
	Prefix     string           `json:"prefix,omitempty"`
	GivenName  string           `json:"given_name,omitempty"`
	MiddleName string           `json:"middle_name,omitempty"`
	FamilyName string           `json:"family_name,omitempty"`
	Suffix     string           `json:"suffix,omitempty"`
	Nickname   string           `json:"nickname,omitempty"`
	Emails     []string         `json:"emails,omitempty"`
	Phones     []string         `json:"phones,omitempty"`
	Org        string           `json:"org,omitempty"`
	Department string           `json:"department,omitempty"`
	Title      string           `json:"title,omitempty"`
	Role       string           `json:"role,omitempty"`
	Addresses  []ContactAddress `json:"addresses,omitempty"`
	Note       string           `json:"note,omitempty"`
	URL        string           `json:"url,omitempty"`
	Birthday   string           `json:"birthday,omitempty"`
	// Categories is the list of group names from the CATEGORIES property (RFC 6350 §6.3.3).
	// e.g. CATEGORIES=work,friends → ["work", "friends"]
	Categories []string `json:"categories,omitempty"`
	// PhotoData is the raw photo data from the PHOTO property (RFC 6350 §6.3.7).
	// Stored as base64-encoded image bytes extracted from the vCard.
	PhotoData []byte `json:"photo_data,omitempty"`
	// PhotoURI retains a remotely hosted PHOTO value without treating it as
	// binary image data. The web editor leaves it untouched unless the user
	// explicitly replaces or removes the photo.
	PhotoURI string `json:"photo_uri,omitempty"`
	// PhotoType is the media type of the photo, e.g. "JPEG", "PNG", "GIF".
	PhotoType string `json:"photo_type,omitempty"`
	// CustomFields carries interoperable X- properties for fields not covered
	// by the standard contact schema.
	CustomFields map[string]string `json:"custom_fields,omitempty"`
	Raw          string            `json:"raw,omitempty"` // raw vCard data
}

// ContactAddress is the structured postal-address portion of a contact.
type ContactAddress struct {
	Type       string `json:"type,omitempty"`
	Street     string `json:"street,omitempty"`
	Locality   string `json:"locality,omitempty"`
	Region     string `json:"region,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}

// searchProperties are the vCard properties searched when looking for contacts.
var searchProperties = map[string]bool{
	"FN":     true,
	"N":      true,
	"EMAIL":  true,
	"TEL":    true,
	"UID":    true,
	"ORG":    true,
	"NOTE":   true,
	"MEMBER": true,
}

// ParseVCard parses a vCard (3.0 or 4.0) into a Contact struct.
// It extracts common properties: FN, N, EMAIL, TEL, UID, ORG, NOTE, URL, BDAY.
func ParseVCard(data []byte) Contact {
	c := Contact{}
	normalized := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")
	var accumulated strings.Builder

	flush := func() {
		raw := strings.TrimSpace(accumulated.String())
		accumulated.Reset()
		if strings.TrimSpace(raw) == "" {
			return
		}

		colonIdx := strings.Index(raw, ":")
		if colonIdx < 1 {
			return
		}

		propPart := raw[:colonIdx]
		value := strings.TrimSpace(raw[colonIdx+1:])

		baseProp := propPart
		if semiIdx := strings.Index(propPart, ";"); semiIdx >= 0 {
			baseProp = propPart[:semiIdx]
		}
		if dot := strings.LastIndex(baseProp, "."); dot >= 0 {
			baseProp = baseProp[dot+1:]
		}

		switch strings.ToUpper(baseProp) {
		case "KIND":
			c.Kind = strings.ToLower(strings.TrimSpace(unescapeVCardText(value)))
		case "MEMBER":
			if value = strings.TrimSpace(value); value != "" {
				c.Members = append(c.Members, value)
			}
		case "FN":
			c.FN = unescapeVCardText(value)
		case "N":
			c.N = value
			parts := splitEscapedVCard(value, ';')
			for len(parts) < 5 {
				parts = append(parts, "")
			}
			c.FamilyName, c.GivenName, c.MiddleName, c.Prefix, c.Suffix = unescapeVCardText(parts[0]), unescapeVCardText(parts[1]), unescapeVCardText(parts[2]), unescapeVCardText(parts[3]), unescapeVCardText(parts[4])
		case "NICKNAME":
			c.Nickname = unescapeVCardText(value)
		case "EMAIL":
			c.Emails = append(c.Emails, unescapeVCardText(value))
		case "TEL":
			c.Phones = append(c.Phones, unescapeVCardText(value))
		case "UID":
			c.UID = unescapeVCardText(value)
		case "ORG":
			parts := splitEscapedVCard(value, ';')
			c.Org = unescapeVCardText(parts[0])
			if len(parts) > 1 {
				for index := 1; index < len(parts); index++ {
					parts[index] = unescapeVCardText(parts[index])
				}
				c.Department = strings.Join(parts[1:], " / ")
			}
		case "TITLE":
			c.Title = unescapeVCardText(value)
		case "ROLE":
			c.Role = unescapeVCardText(value)
		case "ADR":
			parts := splitEscapedVCard(value, ';')
			for len(parts) < 7 {
				parts = append(parts, "")
			}
			addressType := ""
			if typeValue := extractParameter(propPart, "TYPE"); typeValue != "" {
				addressType = strings.ToLower(typeValue)
			}
			c.Addresses = append(c.Addresses, ContactAddress{Type: addressType, Street: unescapeVCardText(parts[2]), Locality: unescapeVCardText(parts[3]), Region: unescapeVCardText(parts[4]), PostalCode: unescapeVCardText(parts[5]), Country: unescapeVCardText(parts[6])})
		case "NOTE":
			c.Note = unescapeVCardText(value)
		case "URL":
			c.URL = unescapeVCardText(value)
		case "BDAY":
			c.Birthday = unescapeVCardText(value)
		case "CATEGORIES":
			c.Categories = parseCategories(value)
		case "PHOTO":
			parsePhoto(&c, propPart, value)
		default:
			if strings.HasPrefix(strings.ToUpper(baseProp), "X-VEKSEL-") {
				if c.CustomFields == nil {
					c.CustomFields = make(map[string]string)
				}
				c.CustomFields[strings.TrimPrefix(strings.ToUpper(baseProp), "X-VEKSEL-")] = unescapeVCardText(value)
			}
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && accumulated.Len() > 0 && !isVCardPropertyLine(trimmed) {
			accumulated.WriteString(trimmed)
			continue
		}
		if accumulated.Len() > 0 {
			flush()
		}
		accumulated.WriteString(line)
	}
	if accumulated.Len() > 0 {
		flush()
	}

	return c
}

func extractParameter(propPart, name string) string {
	for _, parameter := range strings.Split(propPart, ";")[1:] {
		parts := strings.SplitN(parameter, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], name) {
			return parts[1]
		}
	}
	return ""
}

func isVCardPropertyLine(line string) bool {
	colon := strings.Index(line, ":")
	if colon < 1 {
		return false
	}
	property := strings.ToUpper(strings.SplitN(line[:colon], ";", 2)[0])
	if dot := strings.LastIndex(property, "."); dot >= 0 {
		property = property[dot+1:]
	}
	switch property {
	case "BEGIN", "END", "VERSION", "KIND", "MEMBER", "UID", "FN", "N", "NICKNAME", "EMAIL", "TEL", "ORG", "TITLE", "ROLE", "ADR", "NOTE", "URL", "BDAY", "CATEGORIES", "PHOTO":
		return true
	default:
		return strings.HasPrefix(property, "X-")
	}
}

// VCardMatchesSearch checks if a vCard matches the search query
// against FN, N, EMAIL, TEL, UID, ORG, and NOTE properties.
func VCardMatchesSearch(data []byte, query string) bool {
	if query == "" {
		return true
	}

	queryLower := strings.ToLower(query)
	lines := strings.Split(string(data), "\n")
	var accumulated strings.Builder
	matched := false

	flush := func() {
		raw := strings.TrimSpace(accumulated.String())
		accumulated.Reset()
		if raw == "" {
			return
		}
		colonIdx := strings.Index(raw, ":")
		if colonIdx < 1 {
			return
		}
		propPart := raw[:colonIdx]
		value := strings.TrimSpace(raw[colonIdx+1:])

		baseProp := propPart
		if semiIdx := strings.Index(propPart, ";"); semiIdx >= 0 {
			baseProp = propPart[:semiIdx]
		}
		if dot := strings.LastIndex(baseProp, "."); dot >= 0 {
			baseProp = baseProp[dot+1:]
		}

		if searchProperties[strings.ToUpper(baseProp)] {
			if strings.Contains(strings.ToLower(value), queryLower) {
				matched = true
			}
		}
	}

	for _, line := range lines {
		if matched {
			return true
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && accumulated.Len() > 0 && !isVCardPropertyLine(trimmed) {
			accumulated.WriteString(trimmed)
			continue
		}
		if accumulated.Len() > 0 {
			flush()
		}
		accumulated.WriteString(line)
	}
	if accumulated.Len() > 0 {
		flush()
	}
	return matched
}

// parseCategories parses the CATEGORIES property value (RFC 6350 §6.3.3).
// CATEGORIES is a comma-separated list: "work,friends,family"
// Returns a slice of trimmed, non-empty category names.
func parseCategories(value string) []string {
	if value == "" {
		return nil
	}
	parts := splitEscapedVCard(value, ',')
	cats := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(unescapeVCardText(p))
		if trimmed != "" {
			cats = append(cats, trimmed)
		}
	}
	return cats
}

// extractPhotoType extracts the TYPE parameter from a PHOTO property part.
// e.g. "PHOTO;TYPE=JPEG;VALUE=binary" → "JPEG"
func extractPhotoType(propPart string) string {
	idx, _ := IndexFold(propPart, "TYPE=")
	if idx < 0 {
		return ""
	}
	start := idx + 5
	end := len(propPart)
	if semi := strings.Index(propPart[start:], ";"); semi >= 0 {
		end = start + semi
	}
	return strings.TrimSpace(propPart[start:end])
}

// parsePhoto parses the PHOTO property (RFC 6350 §6.3.7).
// Handles VALUE=binary with base64 data and VALUE=uri.
// For binary photos, extracts the base64-decoded data.
// For URI photos, stores the URI reference.
func parsePhoto(c *Contact, propPart, value string) {
	upperProp := strings.ToUpper(propPart)
	if len(value) >= 5 && strings.EqualFold(value[:5], "data:") {
		comma := strings.IndexByte(value, ',')
		if comma > 5 && strings.Contains(strings.ToLower(value[:comma]), ";base64") {
			metadata := value[5:comma]
			if semi := strings.IndexByte(metadata, ';'); semi >= 0 {
				metadata = metadata[:semi]
			}
			if slash := strings.IndexByte(metadata, '/'); slash >= 0 {
				c.PhotoType = strings.ToUpper(metadata[slash+1:])
			}
			if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[comma+1:])); err == nil {
				c.PhotoData = decoded
			}
		}
		return
	}

	// Extract TYPE parameter (e.g. JPEG, PNG, GIF)
	c.PhotoType = extractPhotoType(propPart)

	// Check VALUE parameter
	if strings.Contains(upperProp, "VALUE=BINARY") || strings.Contains(upperProp, "VALUE==BINARY") {
		// Binary data — may have "binary:" prefix
		data := value
		if strings.HasPrefix(strings.ToLower(data), "binary:") {
			data = value[len("binary:"):]
		}
		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
		if err == nil {
			c.PhotoData = decoded
		}
	} else if strings.Contains(upperProp, "VALUE=URI") {
		c.PhotoURI = unescapeVCardText(value)
	} else {
		// Default: try to decode as base64
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err == nil {
			c.PhotoData = decoded
		}
	}
}

// ContactHasCategory checks if a parsed contact belongs to the given category.
// Comparison is case-insensitive.
func ContactHasCategory(c Contact, category string) bool {
	target := strings.ToLower(strings.TrimSpace(category))
	if target == "" {
		return false
	}
	for _, cat := range c.Categories {
		if strings.ToLower(cat) == target {
			return true
		}
	}
	return false
}

// ContactToVCard converts a Contact into vCard 3.0 data.
// It builds properties for FN, N, EMAIL, TEL, UID, ORG, NOTE, URL, BDAY,
// CATEGORIES, and PHOTO.
func ContactToVCard(c Contact) []byte {
	return NewContactVCard(c)
}

func sanitizeCustomProperty(value string) string {
	var out strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(value)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		} else if r == ' ' || r == '_' {
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

// VCardHasCategory checks if raw vCard data contains a CATEGORIES property
// that includes the given category name (case-insensitive).
func VCardHasCategory(data []byte, category string) bool {
	if category == "" {
		return false
	}
	target := strings.ToLower(strings.TrimSpace(category))
	lines := strings.Split(string(data), "\n")
	var accumulated strings.Builder

	flush := func() bool {
		raw := strings.TrimSpace(accumulated.String())
		accumulated.Reset()
		if raw == "" {
			return false
		}
		colonIdx := strings.Index(raw, ":")
		if colonIdx < 1 {
			return false
		}
		propPart := raw[:colonIdx]
		value := strings.TrimSpace(raw[colonIdx+1:])

		baseProp := propPart
		if semiIdx := strings.Index(propPart, ";"); semiIdx >= 0 {
			baseProp = propPart[:semiIdx]
		}

		if strings.ToUpper(baseProp) == "CATEGORIES" {
			cats := parseCategories(value)
			for _, cat := range cats {
				if strings.ToLower(cat) == target {
					return true
				}
			}
		}
		return false
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && accumulated.Len() > 0 && !isVCardPropertyLine(trimmed) {
			accumulated.WriteString(trimmed)
			continue
		}
		if accumulated.Len() > 0 {
			if flush() {
				return true
			}
		}
		accumulated.WriteString(line)
	}
	if accumulated.Len() > 0 {
		if flush() {
			return true
		}
	}
	return false
}
