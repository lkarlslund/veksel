package ews

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// Profile is the account identity EWS needs to tell the user's own
// meetings from invitations and to name the organizer of new ones.
type Profile struct {
	DisplayName string
	Addresses   []string
	// TimeZone is the account's IANA zone, used for all-day events when
	// the request carries no TimeZoneContext.
	TimeZone string
}

func (p Profile) owns(address string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	for _, candidate := range p.Addresses {
		if address != "" && strings.EqualFold(candidate, address) {
			return true
		}
	}
	return false
}

func (p Profile) primary() string {
	if len(p.Addresses) == 0 {
		return ""
	}
	return strings.ToLower(p.Addresses[0])
}

func (h *Handler) loadProfile(ctx context.Context, userID string) Profile {
	if h.profile == nil {
		return Profile{}
	}
	profile, err := h.profile(ctx, userID)
	if err != nil {
		return Profile{}
	}
	return profile
}

// displayZone is the zone all-day events and wall times are read in: the
// request's TimeZoneContext, else the account's zone, else UTC.
func displayZone(info requestInfo, profile Profile) *time.Location {
	if info.zone != nil {
		return info.zone
	}
	if location := zoneLocation(profile.TimeZone); location != nil {
		return location
	}
	return time.UTC
}

// shapeFor parses an ItemShape and binds the request and account context
// typed items are rendered with.
func (h *Handler) shapeFor(ctx context.Context, access service.AccessContext, shapeNode *node) itemShape {
	shape := parseItemShape(shapeNode)
	shape.info = requestInfoFrom(ctx)
	shape.profile = h.loadProfile(ctx, access.Actor.ID)
	shape.zone = displayZone(shape.info, shape.profile)
	return shape
}

// itemKind is the EWS item type a stored item is presented as.
type itemKind int

const (
	kindMessage itemKind = iota
	kindCalendar
	kindTask
	kindContact
)

// kindOf classifies stored data: vCards are contacts, iCalendar objects
// are calendar items or tasks, and everything else is a message.
func kindOf(data []byte) itemKind {
	head := bytes.TrimLeft(bytes.TrimPrefix(data[:min(len(data), 64)], []byte("\xef\xbb\xbf")), " \t\r\n")
	switch {
	case len(head) >= 11 && strings.EqualFold(string(head[:11]), "BEGIN:VCARD"):
		return kindContact
	case len(head) >= 15 && strings.EqualFold(string(head[:15]), "BEGIN:VCALENDAR"):
		if calendar.IsTask(data) && !bytes.Contains(bytes.ToUpper(data), []byte("BEGIN:VEVENT")) {
			return kindTask
		}
		return kindCalendar
	}
	return kindMessage
}

func (k itemKind) tag() string {
	switch k {
	case kindCalendar:
		return "CalendarItem"
	case kindTask:
		return "Task"
	case kindContact:
		return "Contact"
	}
	return "Message"
}

func kindOfTag(tag string) itemKind {
	switch tag {
	case "CalendarItem":
		return kindCalendar
	case "Task":
		return kindTask
	case "Contact":
		return kindContact
	}
	return kindMessage
}

// itemCommon is the ItemType part every typed item shares.
type itemCommon struct {
	item            model.Item
	id              string
	class           string
	subject         string
	sensitivity     string
	body            string
	attachments     string
	categories      []string
	importance      string
	created         time.Time
	modified        time.Time
	responseObjects string
	reminderSet     bool
	reminderMinutes int
	reminderDue     time.Time
	displayTo       string
}

// render writes the ItemType elements in schema order, after MimeContent.
func (c itemCommon) render(shape itemShape) string {
	var out strings.Builder
	out.WriteString(`<t:ItemId Id="` + c.id + `" ChangeKey="` + strconv.FormatUint(c.item.ModSeq, 10) + `"/>`)
	out.WriteString(`<t:ParentFolderId Id="` + encodeID("f:", c.item.FolderID) + `"/><t:ItemClass>` + c.class + `</t:ItemClass>`)
	out.WriteString(`<t:Subject>` + escape(c.subject) + `</t:Subject><t:Sensitivity>` + c.sensitivity + `</t:Sensitivity>`)
	if shape.body {
		out.WriteString(`<t:Body BodyType="Text">` + escape(c.body) + `</t:Body>`)
	}
	if c.attachments != "" {
		out.WriteString(`<t:Attachments>` + c.attachments + `</t:Attachments>`)
	}
	created := c.created
	if created.IsZero() {
		created = c.item.CreatedAt
	}
	out.WriteString(`<t:DateTimeReceived>` + formatDateTime(created) + `</t:DateTimeReceived><t:Size>` + strconv.FormatInt(c.item.Size, 10) + `</t:Size>`)
	if len(c.categories) > 0 {
		out.WriteString(`<t:Categories>`)
		for _, category := range c.categories {
			out.WriteString(`<t:String>` + escape(category) + `</t:String>`)
		}
		out.WriteString(`</t:Categories>`)
	}
	out.WriteString(`<t:Importance>` + c.importance + `</t:Importance>`)
	out.WriteString(`<t:DateTimeCreated>` + formatDateTime(created) + `</t:DateTimeCreated>`)
	if c.responseObjects != "" {
		out.WriteString(`<t:ResponseObjects>` + c.responseObjects + `</t:ResponseObjects>`)
	}
	if c.reminderSet && !c.reminderDue.IsZero() {
		out.WriteString(`<t:ReminderDueBy>` + formatDateTime(c.reminderDue) + `</t:ReminderDueBy>`)
	}
	out.WriteString(`<t:ReminderIsSet>` + strconv.FormatBool(c.reminderSet) + `</t:ReminderIsSet><t:ReminderMinutesBeforeStart>` + strconv.Itoa(c.reminderMinutes) + `</t:ReminderMinutesBeforeStart>`)
	if c.displayTo != "" {
		out.WriteString(`<t:DisplayTo>` + escape(c.displayTo) + `</t:DisplayTo>`)
	}
	out.WriteString(`<t:HasAttachments>` + strconv.FormatBool(c.attachments != "") + `</t:HasAttachments>`)
	out.WriteString(`<t:EffectiveRights><t:CreateAssociated>false</t:CreateAssociated><t:CreateContents>false</t:CreateContents><t:CreateHierarchy>false</t:CreateHierarchy><t:Delete>true</t:Delete><t:Modify>true</t:Modify><t:Read>true</t:Read></t:EffectiveRights>`)
	modified := c.modified
	if modified.IsZero() {
		modified = c.item.UpdatedAt
	}
	if !modified.IsZero() {
		out.WriteString(`<t:LastModifiedTime>` + formatDateTime(modified) + `</t:LastModifiedTime>`)
	}
	return out.String()
}

// fieldChanges are the properties a CreateItem element or an UpdateItem
// change set writes or deletes, keyed by element name. Indexed contact
// properties collect their entries under the dictionary element and
// delete "Dictionary/Key" or "Dictionary/Key/Field".
type fieldChanges struct {
	set     map[string]*node
	deleted map[string]bool
}

func (f fieldChanges) has(name string) bool { return f.set[name] != nil || f.deleted[name] }

func newFieldChanges() fieldChanges {
	return fieldChanges{set: map[string]*node{}, deleted: map[string]bool{}}
}

// merge records a property element; dictionary entries accumulate.
func (f fieldChanges) merge(property *node) {
	switch property.Name.Local {
	case "EmailAddresses", "PhoneNumbers", "PhysicalAddresses", "ImAddresses":
		existing := f.set[property.Name.Local]
		if existing == nil {
			existing = &node{Name: property.Name}
			f.set[property.Name.Local] = existing
		}
		existing.Children = append(existing.Children, property.Children...)
	default:
		f.set[property.Name.Local] = property
	}
}

// fieldsOfItem collects the properties of a CreateItem element.
func fieldsOfItem(item *node) fieldChanges {
	fields := newFieldChanges()
	for _, child := range item.Children {
		fields.merge(child)
	}
	return fields
}

// indexedDictionaries maps indexed FieldURIs to their dictionary element
// and, for physical addresses, the entry field.
var indexedDictionaries = map[string][2]string{
	"contacts:emailaddress": {"EmailAddresses", ""}, "contacts:phonenumber": {"PhoneNumbers", ""}, "contacts:imaddress": {"ImAddresses", ""},
	"contacts:physicaladdress:street": {"PhysicalAddresses", "Street"}, "contacts:physicaladdress:city": {"PhysicalAddresses", "City"},
	"contacts:physicaladdress:state": {"PhysicalAddresses", "State"}, "contacts:physicaladdress:countryorregion": {"PhysicalAddresses", "CountryOrRegion"},
	"contacts:physicaladdress:postalcode": {"PhysicalAddresses", "PostalCode"},
}

// fieldsOfUpdates collects an ItemChange's SetItemField, AppendToItemField
// and DeleteItemField operations. Extended MAPI properties, which clients
// write alongside, are ignored.
func fieldsOfUpdates(updates *node) fieldChanges {
	fields := newFieldChanges()
	if updates == nil {
		return fields
	}
	for _, operation := range updates.Children {
		var uri *node
		var value *node
		for _, child := range operation.Children {
			switch child.Name.Local {
			case "FieldURI", "IndexedFieldURI", "ExtendedFieldURI":
				uri = child
			default:
				value = child
			}
		}
		if uri == nil || uri.Name.Local == "ExtendedFieldURI" {
			continue
		}
		switch operation.Name.Local {
		case "SetItemField", "AppendToItemField":
			if value == nil {
				continue
			}
			for _, property := range value.Children {
				fields.merge(property)
			}
		case "DeleteItemField":
			fieldURI := strings.TrimSpace(uri.attr("FieldURI"))
			if uri.Name.Local == "IndexedFieldURI" {
				dictionary, ok := indexedDictionaries[strings.ToLower(fieldURI)]
				if !ok {
					continue
				}
				key := dictionary[0] + "/" + uri.attr("FieldIndex")
				if dictionary[1] != "" {
					key += "/" + dictionary[1]
				}
				fields.deleted[key] = true
				continue
			}
			if _, name, ok := strings.Cut(fieldURI, ":"); ok {
				fields.deleted[name] = true
			}
		}
	}
	return fields
}

// itemRef is a decoded item identifier: an item, or one occurrence of a
// recurring calendar item.
type itemRef struct {
	itemID string
	// key is the occurrence key; index is a 1-based InstanceIndex still
	// to be resolved to a key.
	key   string
	index int
}

// parseItemRef decodes an encoded ItemId, occurrence ID, or the synthetic
// IDs itemIDs builds for OccurrenceItemId.
func parseItemRef(encoded string) (itemRef, bool) {
	if id, err := decodeID(encoded, "i:"); err == nil {
		return itemRef{itemID: id}, true
	}
	if raw, err := decodeID(encoded, "o:"); err == nil {
		if id, key, ok := strings.Cut(raw, "\x00"); ok && id != "" && key != "" {
			return itemRef{itemID: id, key: key}, true
		}
	}
	if raw, err := decodeID(encoded, "n:"); err == nil {
		if id, index, ok := strings.Cut(raw, "\x00"); ok {
			if value, err := strconv.Atoi(index); err == nil && value > 0 {
				return itemRef{itemID: id, index: value}, true
			}
		}
	}
	return itemRef{}, false
}

// lookupItem resolves an encoded identifier to the stored item and, for an
// occurrence, its key.
func (h *Handler) lookupItem(ctx context.Context, access service.AccessContext, encoded string, zone *time.Location) (model.Item, string, error) {
	ref, ok := parseItemRef(encoded)
	if !ok {
		return model.Item{}, "", errItemNotFound
	}
	item, err := h.space.GetItem(ctx, access, ref.itemID)
	if err != nil {
		return model.Item{}, "", err
	}
	if ref.key == "" && ref.index == 0 {
		return item, "", nil
	}
	event := parseEvent(item.Data)
	if event == nil {
		return model.Item{}, "", errItemNotFound
	}
	var found occurrence
	if ref.index > 0 {
		found, ok = event.nthOccurrence(ref.index, zone)
	} else {
		found, ok = event.occurrenceAt(ref.key, zone)
	}
	if !ok {
		return model.Item{}, "", errItemNotFound
	}
	return item, found.key, nil
}

// refID returns the encoded identifier of an ItemId, OccurrenceItemId or
// RecurringMasterItemId element.
func refID(element *node) string {
	if element == nil {
		return ""
	}
	switch element.Name.Local {
	case "ItemId":
		return element.attr("Id")
	case "OccurrenceItemId":
		master, err := decodeID(element.attr("RecurringMasterId"), "i:")
		if err != nil {
			return element.attr("RecurringMasterId")
		}
		return encodeID("n:", master+"\x00"+strings.TrimSpace(element.attr("InstanceIndex")))
	case "RecurringMasterItemId":
		occurrenceID := element.attr("OccurrenceId")
		if ref, ok := parseItemRef(occurrenceID); ok {
			return encodeID("i:", ref.itemID)
		}
		return occurrenceID
	}
	return ""
}

// itemRefElement finds the identifier element of an ItemChange.
func itemRefElement(change *node) *node {
	for _, name := range []string{"ItemId", "OccurrenceItemId", "RecurringMasterItemId"} {
		if element := change.child(name); element != nil {
			return element
		}
	}
	return nil
}
