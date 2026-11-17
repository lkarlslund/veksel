package model

import (
	"encoding/base64"
	"errors"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// ValidateContactVCard verifies the structural subset accepted by Veksel
// without normalizing or otherwise changing the supplied document. Imported
// cards can therefore retain opaque standard/vendor properties verbatim.
func ValidateContactVCard(data []byte) error {
	_, err := parseVCardDocument(data)
	return err
}

// PatchContactVCard applies the fields owned by the Veksel contact editor to an
// existing card. Every other content line is retained semantically, including
// unknown standard fields, vendor extensions, groups, parameters and version.
func PatchContactVCard(original []byte, update Contact, photoChanged bool) ([]byte, error) {
	document, err := parseVCardDocument(original)
	if err != nil {
		return nil, err
	}
	if update.FN = strings.TrimSpace(update.FN); update.FN == "" {
		return nil, errors.New("contact name is required")
	}
	kind := strings.ToLower(strings.TrimSpace(update.Kind))
	if kind != "" {
		if document.version != "4.0" {
			if kind == "group" || len(update.Members) > 0 {
				originalContact := ParseVCard(original)
				if originalContact.Kind != "group" || kind != "group" || !slices.Equal(originalContact.Members, update.Members) {
					return nil, errors.New("contact groups require vCard 4.0")
				}
			}
		} else {
			document.patchScalar("KIND", escapeVCardText(kind))
		}
	}
	if kind == "group" && document.version == "4.0" {
		document.patchURIRepeated("MEMBER", update.Members)
	} else if kind != "group" && len(update.Members) > 0 {
		return nil, errors.New("MEMBER properties require KIND:group")
	}

	document.patchScalar("FN", escapeVCardText(update.FN))
	structuredName := []string{update.FamilyName, update.GivenName, update.MiddleName, update.Prefix, update.Suffix}
	if update.FamilyName == "" && update.GivenName == "" && update.MiddleName == "" && update.Prefix == "" && update.Suffix == "" && update.N != "" {
		structuredName = splitEscapedVCard(update.N, ';')
		for index := range structuredName {
			structuredName[index] = unescapeVCardText(structuredName[index])
		}
		for len(structuredName) < 5 {
			structuredName = append(structuredName, "")
		}
	}
	document.patchScalar("N", encodeVCardComponents(structuredName))
	document.patchScalar("NICKNAME", escapeVCardText(update.Nickname))
	document.patchRepeated("EMAIL", update.Emails, "EMAIL;TYPE=INTERNET")
	document.patchRepeated("TEL", update.Phones, "TEL;TYPE=WORK")
	document.patchScalar("ORG", encodeVCardComponents([]string{update.Org, update.Department}))
	document.patchScalar("TITLE", escapeVCardText(update.Title))
	document.patchScalar("ROLE", escapeVCardText(update.Role))
	document.patchAddresses(update.Addresses)
	document.patchScalar("NOTE", escapeVCardText(update.Note))
	document.patchScalar("URL", escapeVCardText(update.URL))
	document.patchScalar("BDAY", escapeVCardText(update.Birthday))
	document.patchScalar("CATEGORIES", encodeVCardList(update.Categories))
	document.patchCustomFields(update.CustomFields)
	if photoChanged {
		document.removeAll("PHOTO")
		if len(update.PhotoData) > 0 {
			photoType := strings.ToUpper(strings.TrimSpace(update.PhotoType))
			encoded := base64.StdEncoding.EncodeToString(update.PhotoData)
			if document.version == "4.0" {
				mediaType := "image/" + strings.ToLower(photoType)
				if photoType == "JPG" {
					mediaType = "image/jpeg"
				}
				if photoType == "" {
					mediaType = "application/octet-stream"
				}
				document.lines = append(document.lines, vCardLine{prefix: "PHOTO;MEDIATYPE=" + mediaType, name: "PHOTO", value: "data:" + mediaType + ";base64," + encoded})
			} else {
				prefix := "PHOTO;VALUE=BINARY"
				if photoType != "" {
					prefix = "PHOTO;TYPE=" + photoType + ";VALUE=BINARY"
				}
				document.lines = append(document.lines, vCardLine{prefix: prefix, name: "PHOTO", value: encoded})
			}
		} else if update.PhotoURI != "" {
			document.lines = append(document.lines, vCardLine{prefix: "PHOTO;VALUE=URI", name: "PHOTO", value: escapeVCardText(update.PhotoURI)})
		}
	}
	return document.encode(), nil
}

// PatchContactCategories replaces only the CATEGORIES of a card, keeping
// every other content line as stored.
func PatchContactCategories(original []byte, categories []string) ([]byte, error) {
	document, err := parseVCardDocument(original)
	if err != nil {
		return nil, err
	}
	document.patchScalar("CATEGORIES", encodeVCardList(categories))
	return document.encode(), nil
}

// NewContactVCard creates a standards-valid vCard 3.0 document for a contact
// authored by Veksel. Imported cards retain their original version through
// PatchContactVCard instead.
func NewContactVCard(contact Contact) []byte {
	uid := contact.UID
	if uid == "" {
		uid = contact.ID
	}
	version, uidPrefix := "3.0", "UID:"
	if strings.EqualFold(strings.TrimSpace(contact.Kind), "group") {
		version, uidPrefix = "4.0", "UID;VALUE=text:"
	}
	base := []byte("BEGIN:VCARD\r\nVERSION:" + version + "\r\n" + uidPrefix + escapeVCardText(uid) + "\r\nFN:Unnamed contact\r\nEND:VCARD\r\n")
	patched, err := PatchContactVCard(base, contact, true)
	if err != nil {
		return nil
	}
	return patched
}

type vCardLine struct {
	prefix string
	name   string
	value  string
}

type vCardDocument struct {
	version string
	lines   []vCardLine
}

func parseVCardDocument(data []byte) (*vCardDocument, error) {
	raw := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	logical := UnfoldContentLines(strings.Split(raw, "\n"), func(line string) bool { return line != "" })
	if len(logical) < 3 || !strings.EqualFold(logical[0], "BEGIN:VCARD") || !strings.EqualFold(logical[len(logical)-1], "END:VCARD") {
		return nil, errors.New("invalid vCard envelope")
	}
	document := &vCardDocument{lines: make([]vCardLine, 0, len(logical)-2)}
	for _, rawLine := range logical[1 : len(logical)-1] {
		line, err := parseVCardLine(rawLine)
		if err != nil {
			return nil, err
		}
		if line.name == "VERSION" {
			if document.version != "" {
				return nil, errors.New("vCard has multiple VERSION properties")
			}
			document.version = strings.TrimSpace(line.value)
		}
		document.lines = append(document.lines, line)
	}
	if document.version != "3.0" && document.version != "4.0" {
		return nil, errors.New("vCard VERSION must be 3.0 or 4.0")
	}
	if !document.has("FN") {
		return nil, errors.New("vCard requires an FN property")
	}
	return document, nil
}

func parseVCardLine(raw string) (vCardLine, error) {
	colon, quoted, escaped := -1, false, false
	for index, r := range raw {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			continue
		}
		if r == ':' && !quoted {
			colon = index
			break
		}
	}
	if colon < 1 {
		return vCardLine{}, errors.New("invalid vCard content line")
	}
	prefix := raw[:colon]
	property := strings.SplitN(prefix, ";", 2)[0]
	if dot := strings.LastIndex(property, "."); dot >= 0 {
		property = property[dot+1:]
	}
	name := strings.ToUpper(property)
	if name == "" || strings.IndexFunc(name, func(r rune) bool { return !(r == '-' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') }) >= 0 {
		return vCardLine{}, errors.New("invalid vCard property name")
	}
	return vCardLine{prefix: prefix, name: name, value: raw[colon+1:]}, nil
}

func (d *vCardDocument) has(name string) bool {
	for _, line := range d.lines {
		if line.name == name {
			return true
		}
	}
	return false
}

func (d *vCardDocument) patchScalar(name, encoded string) {
	for index := range d.lines {
		if d.lines[index].name != name {
			continue
		}
		if encoded == "" {
			d.lines = append(d.lines[:index], d.lines[index+1:]...)
		} else {
			d.lines[index].value = encoded
		}
		return
	}
	if encoded != "" {
		d.lines = append(d.lines, vCardLine{prefix: name, name: name, value: encoded})
	}
}

func (d *vCardDocument) patchRepeated(name string, values []string, defaultPrefix string) {
	values = cleanContactValues(values)
	indices := make([]int, 0)
	for index, line := range d.lines {
		if line.name == name {
			indices = append(indices, index)
		}
	}
	used := make(map[int]bool)
	replacements := make([]vCardLine, 0, len(values))
	for _, value := range values {
		matched := -1
		for _, index := range indices {
			if !used[index] && strings.EqualFold(unescapeVCardText(d.lines[index].value), value) {
				matched = index
				break
			}
		}
		if matched >= 0 {
			used[matched] = true
			line := d.lines[matched]
			line.value = escapeVCardText(value)
			replacements = append(replacements, line)
		} else {
			replacements = append(replacements, vCardLine{prefix: defaultPrefix, name: name, value: escapeVCardText(value)})
		}
	}
	d.replaceAll(name, replacements)
}

func (d *vCardDocument) patchURIRepeated(name string, values []string) {
	values = cleanContactValues(values)
	indices := make([]int, 0)
	for index, line := range d.lines {
		if line.name == name {
			indices = append(indices, index)
		}
	}
	used := make(map[int]bool)
	replacements := make([]vCardLine, 0, len(values))
	for _, value := range values {
		matched := -1
		for _, index := range indices {
			if !used[index] && d.lines[index].value == value {
				matched = index
				break
			}
		}
		if matched >= 0 {
			used[matched] = true
			line := d.lines[matched]
			line.value = value
			replacements = append(replacements, line)
		} else {
			replacements = append(replacements, vCardLine{prefix: name, name: name, value: value})
		}
	}
	d.replaceAll(name, replacements)
}

func (d *vCardDocument) patchAddresses(addresses []ContactAddress) {
	// The current editor exposes one HOME and one WORK address. Patch only
	// those first occurrences; retain additional or differently typed ADRs.
	for _, kind := range []string{"HOME", "WORK"} {
		var desired *ContactAddress
		for index := range addresses {
			if strings.EqualFold(strings.TrimSpace(addresses[index].Type), kind) {
				desired = &addresses[index]
				break
			}
		}
		lineIndex := -1
		for index, line := range d.lines {
			if line.name == "ADR" && parameterHasToken(vCardParameter(line.prefix, "TYPE"), kind) {
				lineIndex = index
				break
			}
		}
		empty := desired == nil || desired.Street == "" && desired.Locality == "" && desired.Region == "" && desired.PostalCode == "" && desired.Country == ""
		if empty {
			if lineIndex >= 0 {
				d.lines = append(d.lines[:lineIndex], d.lines[lineIndex+1:]...)
			}
			continue
		}
		value := encodeVCardComponents([]string{"", "", desired.Street, desired.Locality, desired.Region, desired.PostalCode, desired.Country})
		if lineIndex >= 0 {
			d.lines[lineIndex].value = value
		} else {
			d.lines = append(d.lines, vCardLine{prefix: "ADR;TYPE=" + kind, name: "ADR", value: value})
		}
	}
}

func parameterHasToken(value, wanted string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), wanted) {
			return true
		}
	}
	return false
}

func (d *vCardDocument) patchCustomFields(fields map[string]string) {
	kept := d.lines[:0]
	for _, line := range d.lines {
		if !strings.HasPrefix(line.name, "X-VEKSEL-") {
			kept = append(kept, line)
		}
	}
	d.lines = kept
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		name := sanitizeCustomProperty(key)
		value := strings.TrimSpace(fields[key])
		if name != "" && value != "" {
			d.lines = append(d.lines, vCardLine{prefix: "X-VEKSEL-" + name, name: "X-VEKSEL-" + name, value: escapeVCardText(value)})
		}
	}
}

func (d *vCardDocument) removeAll(name string) { d.replaceAll(name, nil) }

func (d *vCardDocument) replaceAll(name string, replacements []vCardLine) {
	result := make([]vCardLine, 0, len(d.lines)-1+len(replacements))
	inserted := false
	for _, line := range d.lines {
		if line.name != name {
			result = append(result, line)
			continue
		}
		if !inserted {
			result = append(result, replacements...)
			inserted = true
		}
	}
	if !inserted {
		result = append(result, replacements...)
	}
	d.lines = result
}

func (d *vCardDocument) encode() []byte {
	var output strings.Builder
	output.WriteString("BEGIN:VCARD\r\n")
	for _, line := range d.lines {
		writeFoldedVCardLine(&output, line.prefix+":"+line.value)
	}
	output.WriteString("END:VCARD\r\n")
	return []byte(output.String())
}

func writeFoldedVCardLine(output *strings.Builder, line string) {
	remaining, limit := line, 75
	for len(remaining) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(remaining[cut]) {
			cut--
		}
		if cut == 0 {
			cut = limit
		}
		output.WriteString(remaining[:cut])
		output.WriteString("\r\n ")
		remaining, limit = remaining[cut:], 74
	}
	output.WriteString(remaining)
	output.WriteString("\r\n")
}

// UnfoldContentLines joins RFC 6350 / RFC 5545 folded physical lines: a line
// starting with a space or tab continues the previous logical line, minus
// that one character. Other lines start a new logical line when keep accepts
// them. Each logical line is built once, so the work stays linear however
// many continuation lines a value is folded over.
func UnfoldContentLines(physical []string, keep func(string) bool) []string {
	var logical []string
	var current strings.Builder
	started := false
	for _, line := range physical {
		if started && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			current.WriteString(line[1:])
			continue
		}
		if !keep(line) {
			continue
		}
		if started {
			logical = append(logical, current.String())
			current.Reset()
		}
		current.WriteString(line)
		started = true
	}
	if started {
		logical = append(logical, current.String())
	}
	return logical
}

func cleanContactValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func encodeVCardComponents(values []string) string {
	encoded := make([]string, len(values))
	for index, value := range values {
		encoded[index] = escapeVCardText(value)
	}
	return strings.Join(encoded, ";")
}

func encodeVCardList(values []string) string {
	encoded := make([]string, 0, len(values))
	for _, value := range cleanContactValues(values) {
		encoded = append(encoded, escapeVCardText(value))
	}
	return strings.Join(encoded, ",")
}

func escapeVCardText(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\r\n", "\\n", "\r", "\\n", "\n", "\\n", ";", "\\;", ",", "\\,")
	return replacer.Replace(value)
}

func unescapeVCardText(value string) string {
	var output strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 >= len(value) {
			output.WriteByte(value[index])
			continue
		}
		index++
		switch value[index] {
		case 'n', 'N':
			output.WriteByte('\n')
		default:
			output.WriteByte(value[index])
		}
	}
	return output.String()
}

func splitEscapedVCard(value string, separator byte) []string {
	parts, start, escaped := make([]string, 0), 0, false
	for index := 0; index < len(value); index++ {
		if escaped {
			escaped = false
			continue
		}
		if value[index] == '\\' {
			escaped = true
			continue
		}
		if value[index] == separator {
			parts = append(parts, value[start:index])
			start = index + 1
		}
	}
	return append(parts, value[start:])
}

func vCardParameter(prefix, name string) string {
	for _, parameter := range strings.Split(prefix, ";")[1:] {
		parts := strings.SplitN(parameter, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], name) {
			return strings.Trim(parts[1], "\"")
		}
	}
	return ""
}
