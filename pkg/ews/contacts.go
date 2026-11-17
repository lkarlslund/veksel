package ews

import (
	"bytes"
	"encoding/base64"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-vcard"

	"github.com/lkarlslund/veksel/pkg/model"
)

// phoneKey maps one EWS PhoneNumbers key to the vCard TEL types written for
// it and recognised when reading.
type phoneKey struct {
	key   string
	types []string
}

var phoneKeys = []phoneKey{
	{"MobilePhone", []string{"cell"}},
	{"HomePhone", []string{"home", "voice"}},
	{"HomePhone2", []string{"home", "voice"}},
	{"BusinessPhone", []string{"work", "voice"}},
	{"BusinessPhone2", []string{"work", "voice"}},
	{"BusinessFax", []string{"work", "fax"}},
	{"HomeFax", []string{"home", "fax"}},
	{"OtherFax", []string{"fax"}},
	{"CarPhone", []string{"car"}},
	{"Pager", []string{"pager"}},
	{"RadioPhone", []string{"x-radio"}},
	{"AssistantPhone", []string{"x-assistant"}},
	{"CompanyMainPhone", []string{"x-main", "work"}},
	{"PrimaryPhone", []string{"pref", "voice"}},
	{"Isdn", []string{"isdn"}},
	{"Telex", []string{"x-telex"}},
	{"TtyTddPhone", []string{"textphone"}},
	{"Callback", []string{"x-callback"}},
	{"OtherTelephone", []string{"voice"}},
}

// phoneKeyFor picks the PhoneNumbers key for a TEL field that is still free.
func phoneKeyFor(field *vcard.Field, used map[string]bool) string {
	has := field.Params.HasType
	var candidates []string
	switch {
	case has("cell") || has("iphone"):
		candidates = []string{"MobilePhone"}
	case has("fax") && has("work"):
		candidates = []string{"BusinessFax"}
	case has("fax") && has("home"):
		candidates = []string{"HomeFax"}
	case has("fax"):
		candidates = []string{"OtherFax", "HomeFax", "BusinessFax"}
	case has("pager"):
		candidates = []string{"Pager"}
	case has("car"):
		candidates = []string{"CarPhone"}
	case has("x-assistant"):
		candidates = []string{"AssistantPhone"}
	case has("x-radio"):
		candidates = []string{"RadioPhone"}
	case has("isdn"):
		candidates = []string{"Isdn"}
	case has("x-telex"):
		candidates = []string{"Telex"}
	case has("textphone"):
		candidates = []string{"TtyTddPhone"}
	case has("x-callback"):
		candidates = []string{"Callback"}
	case has("main") || has("x-main"):
		candidates = []string{"CompanyMainPhone", "BusinessPhone"}
	case has("work"):
		candidates = []string{"BusinessPhone", "BusinessPhone2"}
	case has("home"):
		candidates = []string{"HomePhone", "HomePhone2"}
	case has("pref"):
		candidates = []string{"PrimaryPhone", "OtherTelephone"}
	default:
		candidates = []string{"OtherTelephone", "HomePhone", "MobilePhone", "BusinessPhone", "HomePhone2", "BusinessPhone2"}
	}
	for _, candidate := range candidates {
		if !used[candidate] {
			used[candidate] = true
			return candidate
		}
	}
	return ""
}

func decodeCard(data []byte) vcard.Card {
	card, err := vcard.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil || card == nil {
		return nil
	}
	return card
}

// contactSlots is the indexed view of a vCard's emails, phones, addresses
// and IM addresses; fields that fit no slot are kept as they are.
type contactSlots struct {
	emails      map[string]*vcard.Field
	phones      map[string]*vcard.Field
	addresses   map[string]*vcard.Address
	ims         map[string]*vcard.Field
	extraEmails []*vcard.Field
	extraPhones []*vcard.Field
	extraAddr   []*vcard.Address
	extraIMs    []*vcard.Field
}

func slotsOf(card vcard.Card) contactSlots {
	slots := contactSlots{emails: map[string]*vcard.Field{}, phones: map[string]*vcard.Field{}, addresses: map[string]*vcard.Address{}, ims: map[string]*vcard.Field{}}
	for index, field := range card[vcard.FieldEmail] {
		if index < 3 {
			slots.emails["EmailAddress"+string(rune('1'+index))] = field
		} else {
			slots.extraEmails = append(slots.extraEmails, field)
		}
	}
	used := map[string]bool{}
	for _, field := range card[vcard.FieldTelephone] {
		if key := phoneKeyFor(field, used); key != "" {
			slots.phones[key] = field
		} else {
			slots.extraPhones = append(slots.extraPhones, field)
		}
	}
	for _, address := range card.Addresses() {
		key := "Other"
		if address.Params.HasType("home") {
			key = "Home"
		} else if address.Params.HasType("work") {
			key = "Business"
		}
		if slots.addresses[key] != nil {
			slots.extraAddr = append(slots.extraAddr, address)
			continue
		}
		slots.addresses[key] = address
	}
	for index, field := range card[vcard.FieldIMPP] {
		if index < 3 {
			slots.ims["ImAddress"+string(rune('1'+index))] = field
		} else {
			slots.extraIMs = append(slots.extraIMs, field)
		}
	}
	return slots
}

// renderContact renders a vCard in ItemType/ContactItemType schema order.
func renderContact(item model.Item, shape itemShape) string {
	card := decodeCard(item.Data)
	if card == nil {
		card = vcard.Card{}
	}
	name := card.Name()
	if name == nil {
		name = &vcard.Name{}
	}
	displayName := card.PreferredValue(vcard.FieldFormattedName)
	if displayName == "" {
		displayName = strings.Join(nonEmpty(name.GivenName, name.FamilyName), " ")
	}
	common := itemCommon{item: item, id: encodeID("i:", item.ID), class: "IPM.Contact", subject: displayName, sensitivity: "Normal", body: card.Value(vcard.FieldNote), categories: card.Categories(), importance: "Normal"}
	photo := model.ParseVCard(item.Data).PhotoData
	if len(photo) > 0 {
		common.attachments = `<t:FileAttachment><t:AttachmentId Id="` + encodeID("a:", item.ID+"\x00"+contactPhotoPart) + `"/><t:Name>ContactPicture.jpg</t:Name><t:ContentType>image/jpeg</t:ContentType>`
		if !shape.info.exchange2007() {
			common.attachments += `<t:Size>` + strconv.Itoa(len(photo)) + `</t:Size><t:IsInline>false</t:IsInline>`
		}
		common.attachments += `<t:IsContactPhoto>true</t:IsContactPhoto></t:FileAttachment>`
	}
	var out strings.Builder
	out.WriteString(`<t:Contact>`)
	if shape.mime {
		out.WriteString(`<t:MimeContent CharacterSet="UTF-8">` + base64.StdEncoding.EncodeToString(item.Data) + `</t:MimeContent>`)
	}
	out.WriteString(common.render(shape))
	text := func(tag, value string) {
		if value = strings.TrimSpace(value); value != "" {
			out.WriteString(`<t:` + tag + `>` + escape(value) + `</t:` + tag + `>`)
		}
	}
	fileAs := displayName
	if name.FamilyName != "" && name.GivenName != "" {
		fileAs = name.FamilyName + ", " + name.GivenName
	}
	text("FileAs", fileAs)
	text("DisplayName", displayName)
	text("GivenName", name.GivenName)
	text("MiddleName", name.AdditionalName)
	text("Nickname", card.Value(vcard.FieldNickname))
	out.WriteString(`<t:CompleteName>`)
	text("Title", name.HonorificPrefix)
	text("FirstName", name.GivenName)
	text("MiddleName", name.AdditionalName)
	text("LastName", name.FamilyName)
	text("Suffix", name.HonorificSuffix)
	text("FullName", displayName)
	text("Nickname", card.Value(vcard.FieldNickname))
	out.WriteString(`</t:CompleteName>`)
	company, department := "", ""
	if org := card.Get(vcard.FieldOrganization); org != nil {
		parts := strings.SplitN(org.Value, ";", 2)
		company = parts[0]
		if len(parts) > 1 {
			department = strings.ReplaceAll(parts[1], ";", ", ")
		}
	}
	text("CompanyName", company)
	slots := slotsOf(card)
	entries := func(tag, prefix string, count int, values map[string]*vcard.Field, value func(*vcard.Field) string) {
		var list strings.Builder
		for index := 1; index <= count; index++ {
			key := prefix + string(rune('0'+index))
			if field := values[key]; field != nil {
				if text := strings.TrimSpace(value(field)); text != "" {
					list.WriteString(`<t:Entry Key="` + key + `">` + escape(text) + `</t:Entry>`)
				}
			}
		}
		if list.Len() > 0 {
			out.WriteString(`<t:` + tag + `>` + list.String() + `</t:` + tag + `>`)
		}
	}
	entries("EmailAddresses", "EmailAddress", 3, slots.emails, func(field *vcard.Field) string { return emailAddress(field.Value) })
	var addresses strings.Builder
	for _, key := range []string{"Home", "Business", "Other"} {
		address := slots.addresses[key]
		if address == nil {
			continue
		}
		street := strings.Join(nonEmpty(address.StreetAddress, address.ExtendedAddress), "\n")
		addresses.WriteString(`<t:Entry Key="` + key + `">`)
		for _, part := range [][2]string{{"Street", street}, {"City", address.Locality}, {"State", address.Region}, {"CountryOrRegion", address.Country}, {"PostalCode", address.PostalCode}} {
			if value := strings.TrimSpace(part[1]); value != "" {
				addresses.WriteString(`<t:` + part[0] + `>` + escape(value) + `</t:` + part[0] + `>`)
			}
		}
		addresses.WriteString(`</t:Entry>`)
	}
	if addresses.Len() > 0 {
		out.WriteString(`<t:PhysicalAddresses>` + addresses.String() + `</t:PhysicalAddresses>`)
	}
	var phones strings.Builder
	for _, key := range phoneKeys {
		if field := slots.phones[key.key]; field != nil {
			if value := strings.TrimSpace(strings.TrimPrefix(field.Value, "tel:")); value != "" {
				phones.WriteString(`<t:Entry Key="` + key.key + `">` + escape(value) + `</t:Entry>`)
			}
		}
	}
	if phones.Len() > 0 {
		out.WriteString(`<t:PhoneNumbers>` + phones.String() + `</t:PhoneNumbers>`)
	}
	text("AssistantName", card.Value("X-ASSISTANT"))
	if birthday, ok := contactDate(card.Value(vcard.FieldBirthday)); ok {
		out.WriteString(`<t:Birthday>` + formatDateTime(birthday) + `</t:Birthday>`)
	}
	text("BusinessHomePage", card.Value(vcard.FieldURL))
	text("Department", department)
	text("Generation", name.HonorificSuffix)
	entries("ImAddresses", "ImAddress", 3, slots.ims, func(field *vcard.Field) string {
		if _, rest, ok := strings.Cut(field.Value, ":"); ok {
			return rest
		}
		return field.Value
	})
	text("JobTitle", card.Value(vcard.FieldTitle))
	text("Manager", card.Value("X-MANAGER"))
	text("OfficeLocation", card.Value("X-OFFICE-LOCATION"))
	text("Profession", card.Value(vcard.FieldRole))
	text("SpouseName", card.Value("X-SPOUSE"))
	text("Surname", name.FamilyName)
	if anniversary, ok := contactDate(firstNonEmpty(card.Value(vcard.FieldAnniversary), card.Value("X-ANNIVERSARY"))); ok {
		out.WriteString(`<t:WeddingAnniversary>` + formatDateTime(anniversary) + `</t:WeddingAnniversary>`)
	}
	if !shape.info.exchange2007() {
		out.WriteString(`<t:HasPicture>` + strconv.FormatBool(len(photo) > 0) + `</t:HasPicture>`)
	}
	out.WriteString(`</t:Contact>`)
	return out.String()
}

const contactPhotoPart = "photo"

// contactDate parses a vCard date (YYYY-MM-DD, YYYYMMDD or a timestamp) as
// noon UTC, so that no client time zone moves it to an adjacent day.
func contactDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{"2006-01-02", "20060102", time.RFC3339, "2006-01-02T15:04:05Z", "20060102T150405Z"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 12, 0, 0, 0, time.UTC), true
		}
	}
	return time.Time{}, false
}

// contactDay converts a client date-time to the vCard date it names:
// clients send local midnight, so the nearest day is taken.
func contactDay(value string) (string, bool) {
	parsed, ok := parseDateTime(value, localZone{location: time.UTC})
	if !ok {
		return "", false
	}
	return parsed.Add(12 * time.Hour).Format("2006-01-02"), true
}

func nonEmpty(values ...string) []string {
	var result []string
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	return result
}

func emailAddress(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "SMTP:"), "smtp:"))
	if value == "" {
		return ""
	}
	if parsed, err := mail.ParseAddress(value); err == nil {
		return parsed.Address
	}
	return strings.Trim(value, "<> \"")
}

// newContact starts an empty vCard 3.0.
func newContact() vcard.Card {
	card := vcard.Card{}
	card.SetValue(vcard.FieldVersion, "3.0")
	card.SetValue(vcard.FieldUID, strings.TrimSuffix(newUID(), "@veksel"))
	return card
}

// applyContactFields writes the Contact properties in fields to card;
// everything EWS does not model is preserved.
func applyContactFields(card vcard.Card, fields fieldChanges) {
	value := func(name string) (string, bool) {
		if element := fields.set[name]; element != nil {
			return strings.TrimSpace(element.Text), true
		}
		if fields.deleted[name] {
			return "", true
		}
		return "", false
	}
	setValue := func(field, text string) {
		if text == "" {
			delete(card, field)
			return
		}
		card.SetValue(field, text)
	}
	name := card.Name()
	if name == nil {
		name = &vcard.Name{}
	}
	nameChanged := false
	for element, target := range map[string]*string{"GivenName": &name.GivenName, "Surname": &name.FamilyName, "MiddleName": &name.AdditionalName, "Generation": &name.HonorificSuffix} {
		if text, ok := value(element); ok {
			*target, nameChanged = text, true
		}
	}
	if nameChanged || card.Name() == nil {
		card.SetName(name)
	}
	for element, field := range map[string]string{
		"Nickname": vcard.FieldNickname, "JobTitle": vcard.FieldTitle, "Profession": vcard.FieldRole, "Manager": "X-MANAGER",
		"AssistantName": "X-ASSISTANT", "SpouseName": "X-SPOUSE", "BusinessHomePage": vcard.FieldURL, "OfficeLocation": "X-OFFICE-LOCATION",
	} {
		if text, ok := value(element); ok {
			setValue(field, text)
		}
	}
	company, companyOK := value("CompanyName")
	department, departmentOK := value("Department")
	if companyOK || departmentOK {
		current := strings.SplitN(card.Value(vcard.FieldOrganization), ";", 2)
		if !companyOK {
			company = current[0]
		}
		if !departmentOK && len(current) > 1 {
			department = current[1]
		}
		switch {
		case company == "" && department == "":
			delete(card, vcard.FieldOrganization)
		case department == "":
			card.Set(vcard.FieldOrganization, &vcard.Field{Value: company})
		default:
			card.Set(vcard.FieldOrganization, &vcard.Field{Value: company + ";" + department})
		}
	}
	for element, field := range map[string]string{"Birthday": vcard.FieldBirthday, "WeddingAnniversary": vcard.FieldAnniversary} {
		text, ok := value(element)
		if !ok {
			continue
		}
		if field == vcard.FieldAnniversary && card.Value(vcard.FieldVersion) != "4.0" {
			field = "X-ANNIVERSARY"
		}
		day, valid := contactDay(text)
		if !valid {
			delete(card, field)
			continue
		}
		card.SetValue(field, day)
	}
	if element := fields.set["Body"]; element != nil {
		setValue(vcard.FieldNote, strings.TrimSpace(bodyText(element)))
	} else if fields.deleted["Body"] {
		delete(card, vcard.FieldNote)
	}
	if element := fields.set["Categories"]; element != nil {
		if values := stringList(element); len(values) > 0 {
			card.SetCategories(values)
		} else {
			delete(card, vcard.FieldCategories)
		}
	} else if fields.deleted["Categories"] {
		delete(card, vcard.FieldCategories)
	}
	applyContactDictionaries(card, fields)
	if text, ok := value("DisplayName"); ok && text != "" {
		card.SetValue(vcard.FieldFormattedName, text)
	} else if card.PreferredValue(vcard.FieldFormattedName) == "" || nameChanged && !fields.has("DisplayName") && fields.set["FileAs"] == nil {
		formatted := strings.Join(nonEmpty(name.HonorificPrefix, name.GivenName, name.AdditionalName, name.FamilyName, name.HonorificSuffix), " ")
		if formatted == "" {
			formatted = firstNonEmpty(strings.SplitN(card.Value(vcard.FieldOrganization), ";", 2)[0], emailAddress(card.Value(vcard.FieldEmail)), card.PreferredValue(vcard.FieldFormattedName))
		}
		card.SetValue(vcard.FieldFormattedName, formatted)
	}
}

// applyContactDictionaries writes the indexed EmailAddresses, PhoneNumbers,
// PhysicalAddresses and ImAddresses entries.
func applyContactDictionaries(card vcard.Card, fields fieldChanges) {
	if !fields.has("EmailAddresses") && !fields.has("PhoneNumbers") && !fields.has("PhysicalAddresses") && !fields.has("ImAddresses") && !hasPrefixKey(fields.deleted, "EmailAddresses/", "PhoneNumbers/", "PhysicalAddresses/", "ImAddresses/") {
		return
	}
	slots := slotsOf(card)
	entries := func(dictionary string) []*node {
		if element := fields.set[dictionary]; element != nil {
			return element.ChildrenNamed("Entry")
		}
		return nil
	}
	for _, entry := range entries("EmailAddresses") {
		key := entry.attr("Key")
		if address := emailAddress(entry.Text); address != "" {
			slots.emails[key] = &vcard.Field{Value: address, Params: vcard.Params{vcard.ParamType: []string{"internet"}}}
		} else {
			delete(slots.emails, key)
		}
	}
	for _, entry := range entries("PhoneNumbers") {
		key := entry.attr("Key")
		number := strings.TrimSpace(entry.Text)
		if number == "" {
			delete(slots.phones, key)
			continue
		}
		for _, candidate := range phoneKeys {
			if candidate.key == key {
				slots.phones[key] = &vcard.Field{Value: number, Params: vcard.Params{vcard.ParamType: candidate.types}}
			}
		}
	}
	for _, entry := range entries("ImAddresses") {
		key := entry.attr("Key")
		address := strings.TrimSpace(entry.Text)
		if address == "" {
			delete(slots.ims, key)
			continue
		}
		if !strings.Contains(address, ":") {
			address = "xmpp:" + address
		}
		slots.ims[key] = &vcard.Field{Value: address}
	}
	for _, entry := range entries("PhysicalAddresses") {
		key := entry.attr("Key")
		address := slots.addresses[key]
		if address == nil {
			vtype := map[string]string{"Home": "home", "Business": "work"}[key]
			if vtype == "" {
				vtype = "other"
			}
			address = &vcard.Address{Field: &vcard.Field{Params: vcard.Params{vcard.ParamType: []string{vtype}}}}
		}
		for _, part := range entry.Children {
			text := strings.TrimSpace(part.Text)
			switch part.Name.Local {
			case "Street":
				address.StreetAddress, address.ExtendedAddress = text, ""
			case "City":
				address.Locality = text
			case "State":
				address.Region = text
			case "CountryOrRegion":
				address.Country = text
			case "PostalCode":
				address.PostalCode = text
			}
		}
		slots.addresses[key] = address
	}
	for key := range fields.deleted {
		dictionary, rest, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		switch dictionary {
		case "EmailAddresses":
			delete(slots.emails, rest)
		case "PhoneNumbers":
			delete(slots.phones, rest)
		case "ImAddresses":
			delete(slots.ims, rest)
		case "PhysicalAddresses":
			entry, field, _ := strings.Cut(rest, "/")
			if address := slots.addresses[entry]; address != nil {
				switch field {
				case "Street":
					address.StreetAddress, address.ExtendedAddress = "", ""
				case "City":
					address.Locality = ""
				case "State":
					address.Region = ""
				case "CountryOrRegion":
					address.Country = ""
				case "PostalCode":
					address.PostalCode = ""
				case "":
					delete(slots.addresses, entry)
				}
			}
		}
	}
	delete(card, vcard.FieldEmail)
	for _, key := range []string{"EmailAddress1", "EmailAddress2", "EmailAddress3"} {
		if field := slots.emails[key]; field != nil {
			card.Add(vcard.FieldEmail, field)
		}
	}
	for _, field := range slots.extraEmails {
		card.Add(vcard.FieldEmail, field)
	}
	delete(card, vcard.FieldTelephone)
	for _, key := range phoneKeys {
		if field := slots.phones[key.key]; field != nil {
			card.Add(vcard.FieldTelephone, field)
		}
	}
	for _, field := range slots.extraPhones {
		card.Add(vcard.FieldTelephone, field)
	}
	delete(card, vcard.FieldIMPP)
	for _, key := range []string{"ImAddress1", "ImAddress2", "ImAddress3"} {
		if field := slots.ims[key]; field != nil {
			card.Add(vcard.FieldIMPP, field)
		}
	}
	for _, field := range slots.extraIMs {
		card.Add(vcard.FieldIMPP, field)
	}
	delete(card, vcard.FieldAddress)
	for _, key := range []string{"Home", "Business", "Other"} {
		address := slots.addresses[key]
		if address == nil || address.StreetAddress+address.ExtendedAddress+address.Locality+address.Region+address.PostalCode+address.Country+address.PostOfficeBox == "" {
			continue
		}
		card.AddAddress(address)
	}
	for _, address := range slots.extraAddr {
		card.AddAddress(address)
	}
}

func hasPrefixKey(values map[string]bool, prefixes ...string) bool {
	for key := range values {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				return true
			}
		}
	}
	return false
}

// setContactPhoto replaces (or, with nil, removes) the vCard PHOTO.
func setContactPhoto(card vcard.Card, photo []byte, contentType string) {
	delete(card, vcard.FieldPhoto)
	if len(photo) == 0 {
		return
	}
	if contentType == "" {
		contentType = "image/jpeg"
	}
	encoded := base64.StdEncoding.EncodeToString(photo)
	if card.Value(vcard.FieldVersion) == "4.0" {
		card.SetValue(vcard.FieldPhoto, "data:"+contentType+";base64,"+encoded)
		return
	}
	format := strings.ToUpper(strings.TrimPrefix(contentType, "image/"))
	card.Set(vcard.FieldPhoto, &vcard.Field{Value: encoded, Params: vcard.Params{"ENCODING": []string{"b"}, vcard.ParamType: []string{format}}})
}

func encodeCard(card vcard.Card) ([]byte, map[string]string, error) {
	var buffer bytes.Buffer
	if err := vcard.NewEncoder(&buffer).Encode(card); err != nil {
		return nil, nil, err
	}
	return buffer.Bytes(), map[string]string{"Name": card.PreferredValue(vcard.FieldFormattedName)}, nil
}
