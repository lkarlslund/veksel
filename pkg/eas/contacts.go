package eas

import (
	"bytes"
	"encoding/base64"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-vcard"

	"github.com/lkarlslund/veksel/pkg/model"
)

// maxContactPicture is the largest photo sent to devices; MS-ASCNTC limits
// Picture to 48 KB of image data.
const maxContactPicture = 48 << 10

// phoneSlot maps one EAS phone element to the vCard TEL types it renders.
type phoneSlot struct {
	page  byte
	tag   string
	types []string
}

var phoneSlots = []phoneSlot{
	{1, "MobilePhoneNumber", []string{"cell"}},
	{1, "HomePhoneNumber", []string{"home", "voice"}},
	{1, "Home2PhoneNumber", []string{"home", "voice"}},
	{1, "BusinessPhoneNumber", []string{"work", "voice"}},
	{1, "Business2PhoneNumber", []string{"work", "voice"}},
	{1, "BusinessFaxNumber", []string{"work", "fax"}},
	{1, "HomeFaxNumber", []string{"home", "fax"}},
	{1, "CarPhoneNumber", []string{"car"}},
	{1, "PagerNumber", []string{"pager"}},
	{1, "RadioPhoneNumber", []string{"x-radio"}},
	{1, "AssistantPhoneNumber", []string{"x-assistant"}},
	{12, "CompanyMainPhone", []string{"x-main", "work"}},
}

// phoneSlotFor picks the EAS element for a TEL field that is still free.
func phoneSlotFor(field *vcard.Field, used map[string]bool) string {
	has := field.Params.HasType
	candidates := []string{}
	switch {
	case has("cell") || has("iphone"):
		candidates = []string{"MobilePhoneNumber"}
	case has("fax") && has("work"):
		candidates = []string{"BusinessFaxNumber"}
	case has("fax"):
		candidates = []string{"HomeFaxNumber", "BusinessFaxNumber"}
	case has("pager"):
		candidates = []string{"PagerNumber"}
	case has("car"):
		candidates = []string{"CarPhoneNumber"}
	case has("x-assistant"):
		candidates = []string{"AssistantPhoneNumber"}
	case has("x-radio"):
		candidates = []string{"RadioPhoneNumber"}
	case has("main") || has("x-main"):
		candidates = []string{"CompanyMainPhone", "BusinessPhoneNumber"}
	case has("work"):
		candidates = []string{"BusinessPhoneNumber", "Business2PhoneNumber"}
	case has("home"):
		candidates = []string{"HomePhoneNumber", "Home2PhoneNumber"}
	default:
		candidates = []string{"HomePhoneNumber", "MobilePhoneNumber", "Home2PhoneNumber", "BusinessPhoneNumber", "Business2PhoneNumber"}
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

func (h *Handler) contactData(command *commandContext, item model.Item, options SyncOptions) *Node {
	data := E(0, "ApplicationData")
	card := decodeCard(item.Data)
	if card == nil {
		return data
	}
	add := func(page byte, tag, value string) {
		if value = strings.TrimSpace(value); value != "" {
			data.Children = append(data.Children, T(page, tag, value))
		}
	}
	if name := card.Name(); name != nil {
		add(1, "LastName", name.FamilyName)
		add(1, "FirstName", name.GivenName)
		add(1, "MiddleName", name.AdditionalName)
		add(1, "Title", name.HonorificPrefix)
		add(1, "Suffix", name.HonorificSuffix)
	}
	add(1, "FileAs", card.PreferredValue(vcard.FieldFormattedName))
	if org := card.Get(vcard.FieldOrganization); org != nil {
		parts := strings.SplitN(org.Value, ";", 2)
		add(1, "CompanyName", parts[0])
		if len(parts) > 1 {
			add(1, "Department", parts[1])
		}
	}
	add(1, "JobTitle", card.Value(vcard.FieldTitle))
	for index, field := range card[vcard.FieldEmail] {
		if index >= 3 {
			break
		}
		add(1, []string{"Email1Address", "Email2Address", "Email3Address"}[index], field.Value)
	}
	used := map[string]bool{}
	phones := map[string]string{}
	for _, field := range card[vcard.FieldTelephone] {
		if slot := phoneSlotFor(field, used); slot != "" {
			phones[slot] = strings.TrimPrefix(field.Value, "tel:")
		}
	}
	for _, slot := range phoneSlots {
		if value := phones[slot.tag]; value != "" {
			add(slot.page, slot.tag, value)
		}
	}
	seenAddress := map[string]bool{}
	for _, address := range card.Addresses() {
		prefix := "Other"
		if address.Params.HasType("home") {
			prefix = "Home"
		} else if address.Params.HasType("work") {
			prefix = "Business"
		}
		if seenAddress[prefix] {
			continue
		}
		seenAddress[prefix] = true
		street := strings.TrimSpace(strings.Join(nonEmpty(address.StreetAddress, address.ExtendedAddress), "\n"))
		add(1, prefix+"AddressStreet", street)
		add(1, prefix+"AddressCity", address.Locality)
		add(1, prefix+"AddressState", address.Region)
		add(1, prefix+"AddressPostalCode", address.PostalCode)
		add(1, prefix+"AddressCountry", address.Country)
	}
	if birthday := contactDate(card.Value(vcard.FieldBirthday)); birthday != "" {
		add(1, "Birthday", birthday)
	}
	if anniversary := contactDate(firstNonEmpty(card.Value(vcard.FieldAnniversary), card.Value("X-ANNIVERSARY"))); anniversary != "" {
		add(1, "Anniversary", anniversary)
	}
	add(1, "WebPage", card.Value(vcard.FieldURL))
	add(1, "Spouse", card.Value("X-SPOUSE"))
	add(1, "AssistantName", card.Value("X-ASSISTANT"))
	add(12, "ManagerName", card.Value("X-MANAGER"))
	add(12, "NickName", card.Value(vcard.FieldNickname))
	for index, value := range imAddresses(card) {
		if index >= 3 {
			break
		}
		add(12, []string{"IMAddress", "IMAddress2", "IMAddress3"}[index], value)
	}
	if categories := card.Categories(); len(categories) > 0 {
		node := E(1, "Categories")
		for _, category := range categories {
			if category = strings.TrimSpace(category); category != "" {
				node.Children = append(node.Children, T(1, "Category", category))
			}
		}
		if len(node.Children) > 0 {
			data.Children = append(data.Children, node)
		}
	}
	if photo := model.ParseVCard(item.Data).PhotoData; len(photo) > 0 && len(photo) <= maxContactPicture {
		add(1, "Picture", base64.StdEncoding.EncodeToString(photo))
	}
	data.Children = append(data.Children, textBody(card.Value(vcard.FieldNote), options))
	return data
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

func imAddresses(card vcard.Card) []string {
	var result []string
	for _, field := range card[vcard.FieldIMPP] {
		value := field.Value
		if _, rest, ok := strings.Cut(value, ":"); ok {
			value = rest
		}
		result = append(result, value)
	}
	return result
}

// contactDate renders a vCard date (YYYY-MM-DD, YYYYMMDD or a timestamp)
// as the EAS date-time clients expect, at noon UTC so that no time zone
// moves it to an adjacent day.
func contactDate(value string) string {
	value = strings.TrimSpace(value)
	for _, layout := range []string{"2006-01-02", "20060102", time.RFC3339, "2006-01-02T15:04:05Z", "20060102T150405Z"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 12, 0, 0, 0, time.UTC).Format(easDateFormat)
		}
	}
	return ""
}

// managedContactFields are the vCard properties EAS replaces wholesale on
// every client write. Everything else (UID, REV, custom properties) is kept.
var managedContactFields = []string{
	vcard.FieldName, vcard.FieldFormattedName, vcard.FieldOrganization, vcard.FieldTitle, vcard.FieldEmail,
	vcard.FieldTelephone, vcard.FieldAddress, vcard.FieldBirthday, vcard.FieldAnniversary, "X-ANNIVERSARY",
	vcard.FieldURL, vcard.FieldNote, vcard.FieldCategories, vcard.FieldNickname, vcard.FieldIMPP,
	"X-SPOUSE", "X-ASSISTANT", "X-MANAGER",
}

// contactFromEAS builds or updates a vCard from contact ApplicationData.
func contactFromEAS(existing []byte, data *Node) ([]byte, map[string]string, error) {
	card := decodeCard(existing)
	if card == nil {
		card = vcard.Card{}
		card.SetValue(vcard.FieldVersion, "3.0")
		card.SetValue(vcard.FieldUID, strings.TrimSuffix(newUID(), "@veksel"))
	}
	version := card.Value(vcard.FieldVersion)
	photoPresent := data.Child("Picture") != nil
	for _, field := range managedContactFields {
		delete(card, field)
	}
	value := func(tag string) string { return strings.TrimSpace(childText(data, tag)) }
	name := &vcard.Name{
		FamilyName: value("LastName"), GivenName: value("FirstName"), AdditionalName: value("MiddleName"),
		HonorificPrefix: value("Title"), HonorificSuffix: value("Suffix"),
	}
	card.SetName(name)
	formatted := value("FileAs")
	if formatted == "" {
		formatted = strings.Join(nonEmpty(name.HonorificPrefix, name.GivenName, name.AdditionalName, name.FamilyName, name.HonorificSuffix), " ")
	}
	if formatted == "" {
		formatted = firstNonEmpty(value("CompanyName"), emailAddress(value("Email1Address")))
	}
	if strings.Contains(formatted, ", ") && value("FileAs") != "" && (name.GivenName != "" || name.FamilyName != "") {
		// FileAs is a sort key ("Last, First"); FN is the display name.
		formatted = strings.Join(nonEmpty(name.HonorificPrefix, name.GivenName, name.AdditionalName, name.FamilyName, name.HonorificSuffix), " ")
	}
	card.SetValue(vcard.FieldFormattedName, formatted)
	if company, department := value("CompanyName"), value("Department"); company != "" || department != "" {
		org := company
		if department != "" {
			org += ";" + department
		}
		card.Set(vcard.FieldOrganization, &vcard.Field{Value: org})
	}
	if title := value("JobTitle"); title != "" {
		card.SetValue(vcard.FieldTitle, title)
	}
	for _, tag := range []string{"Email1Address", "Email2Address", "Email3Address"} {
		if address := emailAddress(value(tag)); address != "" {
			card.Add(vcard.FieldEmail, &vcard.Field{Value: address, Params: vcard.Params{vcard.ParamType: []string{"internet"}}})
		}
	}
	for _, slot := range phoneSlots {
		if number := value(slot.tag); number != "" {
			card.Add(vcard.FieldTelephone, &vcard.Field{Value: number, Params: vcard.Params{vcard.ParamType: slot.types}})
		}
	}
	for _, kind := range []struct{ prefix, vtype string }{{"Home", "home"}, {"Business", "work"}, {"Other", "other"}} {
		address := &vcard.Address{
			StreetAddress: value(kind.prefix + "AddressStreet"), Locality: value(kind.prefix + "AddressCity"),
			Region: value(kind.prefix + "AddressState"), PostalCode: value(kind.prefix + "AddressPostalCode"),
			Country: value(kind.prefix + "AddressCountry"),
		}
		if address.StreetAddress+address.Locality+address.Region+address.PostalCode+address.Country == "" {
			continue
		}
		address.Field = &vcard.Field{Params: vcard.Params{vcard.ParamType: []string{kind.vtype}}}
		card.AddAddress(address)
	}
	if birthday, ok := parseEASTime(value("Birthday")); ok {
		card.SetValue(vcard.FieldBirthday, contactDay(birthday))
	}
	if anniversary, ok := parseEASTime(value("Anniversary")); ok {
		field := vcard.FieldAnniversary
		if version != "4.0" {
			field = "X-ANNIVERSARY"
		}
		card.SetValue(field, contactDay(anniversary))
	}
	for tag, field := range map[string]string{"WebPage": vcard.FieldURL, "Spouse": "X-SPOUSE", "AssistantName": "X-ASSISTANT", "ManagerName": "X-MANAGER", "NickName": vcard.FieldNickname} {
		if text := value(tag); text != "" {
			card.SetValue(field, text)
		}
	}
	for _, tag := range []string{"IMAddress", "IMAddress2", "IMAddress3"} {
		if text := value(tag); text != "" {
			if !strings.Contains(text, ":") {
				text = "xmpp:" + text
			}
			card.Add(vcard.FieldIMPP, &vcard.Field{Value: text})
		}
	}
	if categories := data.Child("Categories"); categories != nil {
		var values []string
		for _, category := range categories.Children {
			if text := strings.TrimSpace(nodeValue(category)); text != "" {
				values = append(values, text)
			}
		}
		if len(values) > 0 {
			card.SetCategories(values)
		}
	}
	if body := data.Child("Body"); body != nil {
		if note := strings.TrimSpace(clientBodyText(body)); note != "" {
			card.SetValue(vcard.FieldNote, note)
		}
	}
	if photoPresent {
		delete(card, vcard.FieldPhoto)
		if picture, err := base64.StdEncoding.DecodeString(value("Picture")); err == nil && len(picture) > 0 {
			if version == "4.0" {
				card.SetValue(vcard.FieldPhoto, "data:image/jpeg;base64,"+base64.StdEncoding.EncodeToString(picture))
			} else {
				card.Set(vcard.FieldPhoto, &vcard.Field{Value: base64.StdEncoding.EncodeToString(picture), Params: vcard.Params{"ENCODING": []string{"b"}, vcard.ParamType: []string{"JPEG"}}})
			}
		}
	}
	var buffer bytes.Buffer
	if err := vcard.NewEncoder(&buffer).Encode(card); err != nil {
		return nil, nil, err
	}
	return buffer.Bytes(), map[string]string{"Name": formatted}, nil
}

func contactDay(value time.Time) string {
	// Clients send local midnight in UTC; round to the nearest day.
	return value.Add(12 * time.Hour).Format("2006-01-02")
}

func emailAddress(value string) string {
	if value == "" {
		return ""
	}
	if parsed, err := mail.ParseAddress(value); err == nil {
		return parsed.Address
	}
	return strings.Trim(value, "<> \"")
}
