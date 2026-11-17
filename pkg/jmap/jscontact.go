package jmap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// JSContact (RFC 9553) ↔ vCard (RFC 6350, RFC 9554) conversion following
// the RFC 9555 mapping for the commonly used properties. Lines the converter
// does not represent stay in the stored card verbatim; JSContact properties
// without a vCard mapping are stored as RFC 9555 JSPROP lines.

// contactField maps one map-valued JSContact property to the vCard
// properties that feed it and the prefix of its positional keys.
type contactField struct {
	property string
	prefix   string
	names    []string
}

var contactFields = []contactField{
	{"nicknames", "k", []string{"NICKNAME"}},
	{"emails", "e", []string{"EMAIL"}},
	{"phones", "p", []string{"TEL"}},
	{"addresses", "a", []string{"ADR"}},
	{"organizations", "o", []string{"ORG"}},
	{"titles", "t", []string{"TITLE", "ROLE"}},
	{"notes", "n", []string{"NOTE"}},
	{"anniversaries", "d", []string{"BDAY", "ANNIVERSARY", "DEATHDATE"}},
	{"media", "m", []string{"PHOTO", "LOGO", "SOUND"}},
	{"links", "l", []string{"URL"}},
	{"onlineServices", "s", []string{"IMPP"}},
}

var knownContactProperties = map[string]bool{
	"@type": true, "version": true, "uid": true, "kind": true, "name": true, "keywords": true, "members": true,
	"updated": true, "created": true, "prodId": true, "id": true, "addressBookIds": true,
}

func init() {
	for _, field := range contactFields {
		knownContactProperties[field.property] = true
	}
}

var nameComponentKinds = []string{"surname", "given", "given2", "title", "credential", "surname2", "generation"}

var phoneFeatures = map[string]string{"cell": "mobile", "voice": "voice", "fax": "fax", "pager": "pager", "text": "text", "video": "video", "textphone": "textphone", "main-number": "main-number"}

const contactProductID = "-//Veksel//JMAP Contacts//EN"

// contactMediaBlobID names the blob of an inline media value of a card.
func contactMediaBlobID(itemID, key string) string { return itemID + "-media." + key }

// decodeContact projects a vCard into a JSContact Card. represented maps
// every line the Card represents to its JSContact location ("uid",
// "emails/e1", ...); all other lines are opaque to JSContact.
func decodeContact(doc *vcardDoc, itemID string) (map[string]any, map[*vcardProp]string) {
	card := map[string]any{"@type": "Card", "version": "1.0"}
	represented := map[*vcardProp]string{}
	name := map[string]any{}
	var components []any
	keywords, members := map[string]any{}, map[string]any{}
	counts := map[string]int{}
	used := map[string]bool{}
	for _, prop := range doc.props {
		switch prop.name {
		case "UID":
			if _, ok := card["uid"]; !ok {
				card["uid"], represented[prop] = prop.text(), "uid"
			}
			continue
		case "KIND", "X-ADDRESSBOOKSERVER-KIND":
			if _, ok := card["kind"]; !ok {
				card["kind"], represented[prop] = strings.ToLower(prop.text()), "kind"
			}
			continue
		case "FN":
			if _, ok := name["full"]; !ok {
				name["full"], represented[prop] = prop.text(), "name/full"
			}
			continue
		case "N":
			if components == nil {
				represented[prop] = "name/components"
				components = []any{}
				for index, values := range prop.components() {
					if index >= len(nameComponentKinds) {
						break
					}
					for _, value := range values {
						if value != "" {
							components = append(components, map[string]any{"kind": nameComponentKinds[index], "value": value})
						}
					}
				}
			}
			continue
		case "CATEGORIES":
			for _, values := range prop.components() {
				for _, value := range values {
					if value != "" {
						keywords[value] = true
					}
				}
			}
			represented[prop] = "keywords"
			continue
		case "MEMBER", "X-ADDRESSBOOKSERVER-MEMBER":
			members[prop.text()], represented[prop] = true, "members"
			continue
		case "PRODID":
			if _, ok := card["prodId"]; !ok {
				card["prodId"], represented[prop] = prop.text(), "prodId"
			}
			continue
		case "REV", "CREATED":
			property := map[string]string{"REV": "updated", "CREATED": "created"}[prop.name]
			if when, ok := parseVCardTimestamp(prop.text()); ok {
				if _, exists := card[property]; !exists {
					card[property], represented[prop] = when.UTC().Format(time.RFC3339), property
				}
			}
			continue
		case "JSPROP":
			pointer := strings.TrimPrefix(prop.param("JSPTR"), "/")
			var value any
			if pointer != "" && !strings.Contains(pointer, "/") && !knownContactProperties[pointer] && json.Unmarshal([]byte(prop.text()), &value) == nil {
				card[pointer], represented[prop] = value, pointer
			}
			continue
		}
		for _, field := range contactFields {
			if !containsString(field.names, prop.name) {
				continue
			}
			key := prop.param("PROP-ID")
			if key == "" || used[field.property+"/"+key] {
				key = field.prefix + strconv.Itoa(counts[field.property]+1)
			}
			entry, ok := contactEntry(prop, doc.version(), itemID, key)
			if !ok {
				break
			}
			counts[field.property]++
			used[field.property+"/"+key] = true
			entries, _ := card[field.property].(map[string]any)
			if entries == nil {
				entries = map[string]any{}
				card[field.property] = entries
			}
			entries[key] = entry
			represented[prop] = field.property + "/" + key
			break
		}
	}
	if len(components) > 0 {
		name["components"] = components
	}
	if len(name) > 0 {
		card["name"] = name
	}
	if len(keywords) > 0 {
		card["keywords"] = keywords
	}
	if len(members) > 0 {
		card["members"] = members
	}
	return card, represented
}

// contactEntry converts one line of a map-valued field. ok is false for
// values the JSContact model cannot carry; such lines stay verbatim.
func contactEntry(prop *vcardProp, version, itemID, key string) (map[string]any, bool) {
	entry := map[string]any{}
	setContexts(entry, prop)
	if pref, err := strconv.Atoi(prop.param("PREF")); err == nil && pref > 0 {
		entry["pref"] = pref
	} else if prop.hasType("pref") {
		entry["pref"] = 1
	}
	switch prop.name {
	case "NICKNAME":
		entry = map[string]any{"name": prop.text()}
	case "EMAIL":
		entry["address"] = prop.text()
	case "TEL":
		entry["number"] = prop.text()
		features := map[string]any{}
		for _, t := range prop.paramValues("TYPE") {
			if feature, ok := phoneFeatures[strings.ToLower(t)]; ok {
				features[feature] = true
			}
		}
		if len(features) > 0 {
			entry["features"] = features
		}
	case "ADR":
		parts := prop.components()
		kinds := []string{"postOfficeBox", "apartment", "name", "locality", "region", "postcode", "country"}
		var components []any
		for index, values := range parts {
			if index >= len(kinds) {
				break
			}
			for _, value := range values {
				if value != "" {
					components = append(components, map[string]any{"kind": kinds[index], "value": value})
				}
			}
		}
		if len(components) > 0 {
			entry["components"] = components
		}
		if label := prop.param("LABEL"); label != "" {
			entry["full"] = unescapeVCard(label)
		}
		if cc := prop.param("CC"); cc != "" {
			entry["countryCode"] = cc
		}
	case "ORG":
		parts := prop.components()
		entry = map[string]any{}
		if len(parts) > 0 && strings.Join(parts[0], ",") != "" {
			entry["name"] = strings.Join(parts[0], ",")
		}
		var units []any
		for _, unit := range parts[min(1, len(parts)):] {
			if value := strings.Join(unit, ","); value != "" {
				units = append(units, map[string]any{"name": value})
			}
		}
		if len(units) > 0 {
			entry["units"] = units
		}
	case "TITLE", "ROLE":
		entry = map[string]any{"name": prop.text(), "kind": strings.ToLower(prop.name)}
	case "NOTE":
		entry = map[string]any{"note": prop.text()}
	case "BDAY", "ANNIVERSARY", "DEATHDATE":
		if strings.EqualFold(prop.param("VALUE"), "text") {
			return nil, false
		}
		date, ok := parseVCardDate(prop.text())
		if !ok {
			return nil, false
		}
		entry = map[string]any{"kind": map[string]string{"BDAY": "birth", "ANNIVERSARY": "wedding", "DEATHDATE": "death"}[prop.name], "date": date}
	case "PHOTO", "LOGO", "SOUND":
		media := map[string]any{"kind": strings.ToLower(prop.name)}
		for k, v := range entry {
			media[k] = v
		}
		entry = media
		_, mediaType, inline, ok := decodeMediaValue(prop, version)
		if !ok {
			return nil, false
		}
		if mediaType != "" {
			entry["mediaType"] = mediaType
		}
		if inline {
			entry["blobId"] = contactMediaBlobID(itemID, key)
		} else {
			entry["uri"] = prop.value
		}
	case "URL":
		entry["uri"] = prop.text()
	case "IMPP":
		entry["uri"] = prop.text()
	}
	return entry, true
}

func setContexts(entry map[string]any, prop *vcardProp) {
	contexts := map[string]any{}
	for _, t := range prop.paramValues("TYPE") {
		switch strings.ToLower(t) {
		case "work":
			contexts["work"] = true
		case "home":
			contexts["private"] = true
		}
	}
	if len(contexts) > 0 {
		entry["contexts"] = contexts
	}
}

// decodeMediaValue returns the payload of an inline media value or reports a
// URI reference.
func decodeMediaValue(prop *vcardProp, version string) (data []byte, mediaType string, inline bool, ok bool) {
	value := strings.TrimSpace(prop.value)
	mediaType = prop.param("MEDIATYPE")
	if strings.HasPrefix(strings.ToLower(value), "data:") {
		header, payload, found := strings.Cut(value[5:], ",")
		if !found {
			return nil, "", false, false
		}
		params := strings.Split(header, ";")
		if params[0] != "" {
			mediaType = params[0]
		}
		if !containsString(params[1:], "base64") {
			return []byte(payload), mediaType, true, true
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		return decoded, mediaType, true, err == nil
	}
	encoding := strings.ToLower(prop.param("ENCODING"))
	if encoding == "b" || encoding == "base64" || (version != "4.0" && strings.EqualFold(prop.param("VALUE"), "binary")) {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(value, " ", ""))
		if t := prop.param("TYPE"); t != "" && mediaType == "" {
			mediaType = legacyMediaType(prop.name, t)
		}
		return decoded, mediaType, true, err == nil
	}
	if !strings.Contains(value, ":") {
		return nil, "", false, false
	}
	return nil, mediaType, false, true
}

func legacyMediaType(property, value string) string {
	if strings.Contains(value, "/") {
		return strings.ToLower(value)
	}
	major := "image"
	if property == "SOUND" {
		major = "audio"
	}
	value = strings.ToLower(value)
	if value == "jpg" {
		value = "jpeg"
	}
	return major + "/" + value
}

// contactMedia extracts the payload of the inline media value key.
func contactMedia(data []byte, itemID, key string) ([]byte, string, bool) {
	doc, err := parseVCard(data)
	if err != nil {
		return nil, "", false
	}
	_, represented := decodeContact(doc, itemID)
	for prop, location := range represented {
		if location == "media/"+key {
			payload, mediaType, inline, ok := decodeMediaValue(prop, doc.version())
			return payload, mediaType, ok && inline
		}
	}
	return nil, "", false
}

// blobFetcher reads an uploaded blob for embedding into a card.
type blobFetcher func(blobID string) ([]byte, string, error)

// encodeContact writes a JSContact Card into a vCard. With an original card,
// every line the original Card did not represent is retained, and lines that
// keep their JSContact key keep their group and unknown parameters.
func encodeContact(card map[string]any, original *vcardDoc, itemID string, fetch blobFetcher) (*vcardDoc, error) {
	if t, ok := card["@type"]; ok && t != "Card" {
		return nil, errors.New("@type must be Card")
	}
	doc := &vcardDoc{}
	byLocation := map[string]*vcardProp{}
	version := "4.0"
	if original != nil {
		_, represented := decodeContact(original, itemID)
		for _, prop := range original.props {
			if location, ok := represented[prop]; ok {
				if _, seen := byLocation[location]; !seen {
					byLocation[location] = prop
				}
				continue
			}
			doc.props = append(doc.props, prop)
		}
		version = original.version()
	} else {
		doc.props = append(doc.props, &vcardProp{name: "VERSION", value: version})
	}
	line := func(location, name, value string) *vcardProp {
		if base, ok := byLocation[location]; ok && base.name == name {
			prop := base.clone()
			prop.value = value
			return prop
		}
		return &vcardProp{name: name, value: value}
	}
	add := func(prop *vcardProp) { doc.props = append(doc.props, prop) }

	uid, _ := card["uid"].(string)
	if uid == "" {
		return nil, errors.New("uid is required")
	}
	add(line("uid", "UID", escapeVCard(uid)))
	prodID, _ := card["prodId"].(string)
	if prodID == "" && original == nil {
		prodID = contactProductID
	}
	if prodID != "" {
		add(line("prodId", "PRODID", escapeVCard(prodID)))
	}
	kind, _ := card["kind"].(string)
	if kind = strings.ToLower(kind); kind != "" {
		if !containsString([]string{"individual", "group", "org", "location", "device", "application"}, kind) {
			return nil, fmt.Errorf("unsupported kind %q", kind)
		}
		if version == "4.0" || kind != "group" {
			add(line("kind", "KIND", kind))
		} else {
			add(line("kind", "X-ADDRESSBOOKSERVER-KIND", kind))
		}
	}
	name, _ := card["name"].(map[string]any)
	components := [][]string{{}, {}, {}, {}, {}}
	hasComponents := false
	if list, ok := name["components"].([]any); ok {
		for _, raw := range list {
			component, _ := raw.(map[string]any)
			kind, _ := component["kind"].(string)
			value, _ := component["value"].(string)
			index := indexOf(nameComponentKinds, kind)
			if index < 0 || value == "" {
				continue
			}
			if index >= 5 && version != "4.0" {
				index = map[int]int{5: 0, 6: 4}[index]
			}
			for len(components) <= index {
				components = append(components, []string{})
			}
			components[index] = append(components[index], value)
			hasComponents = true
		}
	}
	full, _ := name["full"].(string)
	if full == "" {
		full = derivedFullName(card, components)
	}
	add(line("name/full", "FN", escapeVCard(full)))
	if hasComponents || version != "4.0" {
		add(line("name/components", "N", structuredValue(components)))
	}
	for _, field := range contactFields {
		entries, _ := card[field.property].(map[string]any)
		for position, key := range sortedKeys(entries) {
			entry, ok := entries[key].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s/%s must be an object", field.property, key)
			}
			prop, err := encodeContactEntry(field, key, entry, version, itemID, byLocation, fetch)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", field.property, key, err)
			}
			if key == field.prefix+strconv.Itoa(position+1) {
				prop.setParam("PROP-ID")
			} else {
				prop.setParam("PROP-ID", key)
			}
			add(prop)
		}
	}
	if keywords := trueKeys(card["keywords"]); len(keywords) > 0 {
		values := make([]string, len(keywords))
		for i, keyword := range keywords {
			values[i] = escapeVCard(keyword)
		}
		add(line("keywords", "CATEGORIES", strings.Join(values, ",")))
	}
	members := trueKeys(card["members"])
	if len(members) > 0 && kind != "group" {
		return nil, errors.New("members require kind group")
	}
	memberProperty := "MEMBER"
	if version != "4.0" {
		memberProperty = "X-ADDRESSBOOKSERVER-MEMBER"
	}
	for _, member := range members {
		add(&vcardProp{name: memberProperty, value: member})
	}
	if created, ok := card["created"].(string); ok {
		if when, err := time.Parse(time.RFC3339, created); err == nil {
			add(line("created", "CREATED", when.UTC().Format("20060102T150405Z")))
		}
	}
	add(&vcardProp{name: "REV", value: time.Now().UTC().Format("20060102T150405Z")})
	for _, key := range sortedKeys(card) {
		if knownContactProperties[key] {
			continue
		}
		data, err := json.Marshal(card[key])
		if err != nil {
			return nil, err
		}
		prop := line(key, "JSPROP", escapeVCard(string(data)))
		prop.setParam("JSPTR", key)
		add(prop)
	}
	return doc, nil
}

func encodeContactEntry(field contactField, key string, entry map[string]any, version, itemID string, byLocation map[string]*vcardProp, fetch blobFetcher) (*vcardProp, error) {
	location := field.property + "/" + key
	propertyName := field.names[0]
	switch field.property {
	case "titles":
		if kind, _ := entry["kind"].(string); kind == "role" {
			propertyName = "ROLE"
		}
	case "anniversaries":
		kind, _ := entry["kind"].(string)
		switch kind {
		case "birth":
		case "wedding":
			propertyName = "ANNIVERSARY"
		case "death":
			propertyName = "DEATHDATE"
		default:
			return nil, fmt.Errorf("unsupported anniversary kind %q", kind)
		}
	case "media":
		kind, _ := entry["kind"].(string)
		switch kind {
		case "photo":
		case "logo":
			propertyName = "LOGO"
		case "sound":
			propertyName = "SOUND"
		default:
			return nil, fmt.Errorf("unsupported media kind %q", kind)
		}
	}
	prop := &vcardProp{name: propertyName}
	if base, ok := byLocation[location]; ok && base.name == propertyName {
		prop = base.clone()
	}
	str := func(name string) string { value, _ := entry[name].(string); return value }
	switch field.property {
	case "nicknames":
		prop.value = escapeVCard(str("name"))
	case "emails":
		if str("address") == "" {
			return nil, errors.New("address is required")
		}
		prop.value = escapeVCard(str("address"))
	case "phones":
		number := str("number")
		if number == "" {
			return nil, errors.New("number is required")
		}
		prop.value = escapeVCard(number)
		if strings.HasPrefix(number, "tel:") {
			prop.value = number
			if version == "4.0" {
				prop.setParam("VALUE", "uri")
			}
		}
	case "addresses":
		slots := map[string]int{"postOfficeBox": 0, "apartment": 1, "locality": 3, "region": 4, "postcode": 5, "country": 6}
		parts := make([][]string, 7)
		var street []string
		separated := false
		components, _ := entry["components"].([]any)
		for _, raw := range components {
			component, _ := raw.(map[string]any)
			kind, _ := component["kind"].(string)
			value, _ := component["value"].(string)
			if slot, ok := slots[kind]; ok {
				parts[slot] = append(parts[slot], value)
				continue
			}
			if kind == "separator" {
				separated = true
			}
			street = append(street, value)
		}
		joiner := " "
		if separated {
			joiner = ""
		}
		if len(street) > 0 {
			parts[2] = []string{strings.Join(street, joiner)}
		}
		for i := range parts {
			parts[i] = []string{strings.Join(parts[i], " ")}
		}
		prop.value = structuredValue(parts)
		setOptionalParam(prop, "LABEL", str("full"), version == "4.0")
		setOptionalParam(prop, "CC", str("countryCode"), version == "4.0")
	case "organizations":
		parts := [][]string{{str("name")}}
		units, _ := entry["units"].([]any)
		for _, raw := range units {
			unit, _ := raw.(map[string]any)
			value, _ := unit["name"].(string)
			parts = append(parts, []string{value})
		}
		prop.value = structuredValue(parts)
	case "titles":
		prop.value = escapeVCard(str("name"))
	case "notes":
		prop.value = escapeVCard(str("note"))
	case "anniversaries":
		value, err := encodeVCardDate(entry["date"], version)
		if err != nil {
			return nil, err
		}
		prop.value = value
		prop.setParam("VALUE")
	case "media":
		if err := encodeMedia(prop, entry, version, itemID, byLocation, fetch); err != nil {
			return nil, err
		}
	case "links", "onlineServices":
		if str("uri") == "" {
			return nil, errors.New("uri is required")
		}
		prop.value = str("uri")
	}
	if field.property == "emails" || field.property == "phones" || field.property == "addresses" || field.property == "links" || field.property == "onlineServices" {
		writeTypes(prop, entry, field.property == "phones", version)
	}
	return prop, nil
}

func setOptionalParam(prop *vcardProp, name, value string, allowed bool) {
	if value == "" || !allowed {
		prop.setParam(name)
		return
	}
	prop.setParam(name, value)
}

// writeTypes replaces the context, feature and preference TYPE values and
// keeps every other TYPE value the line already had.
func writeTypes(prop *vcardProp, entry map[string]any, phone bool, version string) {
	var types []string
	for _, t := range prop.paramValues("TYPE") {
		lower := strings.ToLower(t)
		if lower == "work" || lower == "home" || lower == "pref" || (phone && phoneFeatures[lower] != "") {
			continue
		}
		types = append(types, t)
	}
	for _, context := range trueKeys(entry["contexts"]) {
		switch context {
		case "work":
			types = append(types, "work")
		case "private":
			types = append(types, "home")
		}
	}
	if phone {
		for _, feature := range trueKeys(entry["features"]) {
			for vcard, js := range phoneFeatures {
				if js == feature {
					types = append(types, vcard)
				}
			}
		}
	}
	pref, _ := entry["pref"].(float64)
	if p, ok := entry["pref"].(int); ok {
		pref = float64(p)
	}
	prop.setParam("PREF")
	if pref > 0 {
		if version == "4.0" {
			prop.setParam("PREF", strconv.Itoa(int(pref)))
		} else if pref == 1 {
			types = append(types, "pref")
		}
	}
	prop.setParam("TYPE", types...)
}

func encodeMedia(prop *vcardProp, entry map[string]any, version, itemID string, byLocation map[string]*vcardProp, fetch blobFetcher) error {
	mediaType, _ := entry["mediaType"].(string)
	if uri, _ := entry["uri"].(string); uri != "" {
		prop.params = nil
		prop.value = uri
		if version == "4.0" {
			setOptionalParam(prop, "MEDIATYPE", mediaType, true)
		} else {
			prop.setParam("VALUE", "uri")
		}
		return nil
	}
	blobID, _ := entry["blobId"].(string)
	if blobID == "" {
		return errors.New("uri or blobId is required")
	}
	if key, ok := strings.CutPrefix(blobID, itemID+"-media."); ok && itemID != "" {
		original, exists := byLocation["media/"+key]
		if !exists {
			return errors.New("blobId does not exist")
		}
		*prop = *original.clone()
		return nil
	}
	if fetch == nil {
		return errors.New("blobId cannot be resolved")
	}
	data, uploadedType, err := fetch(blobID)
	if err != nil {
		return errors.New("blobId does not exist")
	}
	if mediaType == "" {
		mediaType, _, _ = mime.ParseMediaType(uploadedType)
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	prop.params = nil
	if version == "4.0" {
		prop.value = "data:" + mediaType + ";base64," + encoded
		return nil
	}
	prop.value = encoded
	prop.setParam("ENCODING", "b")
	if _, subtype, ok := strings.Cut(mediaType, "/"); ok {
		prop.setParam("TYPE", strings.ToUpper(subtype))
	}
	return nil
}

// parseVCardDate converts vCard date and date-time values into a JSContact
// PartialDate or Timestamp.
func parseVCardDate(value string) (map[string]any, bool) {
	value = strings.TrimSpace(value)
	if when, ok := parseVCardTimestamp(value); ok && strings.Contains(value, "T") {
		return map[string]any{"@type": "Timestamp", "utc": when.UTC().Format(time.RFC3339)}, true
	}
	compact := strings.ReplaceAll(value, "-", "")
	date := map[string]any{"@type": "PartialDate"}
	digits := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil
	}
	switch {
	case strings.HasPrefix(value, "--") && len(compact) == 4:
		month, ok1 := digits(compact[:2])
		day, ok2 := digits(compact[2:])
		if !ok1 || !ok2 {
			return nil, false
		}
		date["month"], date["day"] = month, day
	case strings.HasPrefix(value, "---") && len(compact) == 2:
		day, ok := digits(compact)
		if !ok {
			return nil, false
		}
		date["day"] = day
	case len(compact) == 8:
		year, ok1 := digits(compact[:4])
		month, ok2 := digits(compact[4:6])
		day, ok3 := digits(compact[6:])
		if !ok1 || !ok2 || !ok3 {
			return nil, false
		}
		date["year"], date["month"], date["day"] = year, month, day
	case len(compact) == 6 && strings.Contains(value, "-"):
		year, ok1 := digits(compact[:4])
		month, ok2 := digits(compact[4:])
		if !ok1 || !ok2 {
			return nil, false
		}
		date["year"], date["month"] = year, month
	case len(compact) == 4 && !strings.HasPrefix(value, "-"):
		year, ok := digits(compact)
		if !ok {
			return nil, false
		}
		date["year"] = year
	default:
		return nil, false
	}
	if month, ok := date["month"].(int); ok && (month < 1 || month > 12) {
		return nil, false
	}
	if day, ok := date["day"].(int); ok && (day < 1 || day > 31) {
		return nil, false
	}
	return date, true
}

func parseVCardTimestamp(value string) (time.Time, bool) {
	for _, layout := range []string{"20060102T150405Z", "2006-01-02T15:04:05Z", time.RFC3339, "20060102T150405Z0700", "20060102T150405"} {
		if when, err := time.Parse(layout, value); err == nil {
			return when, true
		}
	}
	return time.Time{}, false
}

func encodeVCardDate(raw any, version string) (string, error) {
	date, _ := raw.(map[string]any)
	if date == nil {
		return "", errors.New("date is required")
	}
	if utc, ok := date["utc"].(string); ok {
		when, err := time.Parse(time.RFC3339, utc)
		if err != nil {
			return "", errors.New("invalid timestamp")
		}
		return when.UTC().Format("20060102T150405Z"), nil
	}
	number := func(name string) int {
		switch v := date[name].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
		return 0
	}
	year, month, day := number("year"), number("month"), number("day")
	switch {
	case year > 0 && month > 0 && day > 0:
		if version == "4.0" {
			return fmt.Sprintf("%04d%02d%02d", year, month, day), nil
		}
		return fmt.Sprintf("%04d-%02d-%02d", year, month, day), nil
	case year == 0 && month > 0 && day > 0:
		return fmt.Sprintf("--%02d%02d", month, day), nil
	case year > 0 && month > 0:
		return fmt.Sprintf("%04d-%02d", year, month), nil
	case year > 0:
		return fmt.Sprintf("%04d", year), nil
	}
	return "", errors.New("date needs a year or a month and day")
}

func derivedFullName(card map[string]any, components [][]string) string {
	var parts []string
	for _, index := range []int{3, 1, 2, 0, 4} {
		if index < len(components) {
			parts = append(parts, components[index]...)
		}
	}
	if full := strings.TrimSpace(strings.Join(parts, " ")); full != "" {
		return full
	}
	for _, property := range []string{"organizations", "emails"} {
		entries, _ := card[property].(map[string]any)
		for _, key := range sortedKeys(entries) {
			entry, _ := entries[key].(map[string]any)
			for _, name := range []string{"name", "address"} {
				if value, _ := entry[name].(string); value != "" {
					return value
				}
			}
		}
	}
	return "Unnamed contact"
}

// sortedKeys orders map keys naturally, so "e2" sorts before "e10".
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return naturalLess(keys[i], keys[j]) })
	return keys
}

func naturalLess(a, b string) bool {
	split := func(s string) (string, int, bool) {
		i := len(s)
		for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
			i--
		}
		n, err := strconv.Atoi(s[i:])
		return s[:i], n, err == nil && i < len(s)
	}
	pa, na, oka := split(a)
	pb, nb, okb := split(b)
	if oka && okb && pa == pb && na != nb {
		return na < nb
	}
	return a < b
}

// trueKeys returns the sorted keys of a JSON boolean set.
func trueKeys(raw any) []string {
	set, _ := raw.(map[string]any)
	var keys []string
	for key, value := range set {
		if value == true {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func indexOf(values []string, value string) int {
	for i, v := range values {
		if v == value {
			return i
		}
	}
	return -1
}
