package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// JMAP for Contacts (RFC 9610): AddressBook and ContactCard over the same
// FolderSpace contact collections and vCards CardDAV serves.

func (h *Handler) contactCodec() itemCodec {
	return itemCodec{
		kind:      contactsKind,
		extension: "vcf",
		headers:   map[string]string{"Content-Type": "text/vcard; charset=utf-8"},
		decode: func(item model.Item) (map[string]any, error) {
			doc, err := parseVCard(item.Data)
			if err != nil {
				return nil, err
			}
			card, _ := decodeContact(doc, item.ID)
			return card, nil
		},
		encode: func(ctx context.Context, access service.AccessContext, object map[string]any, original *model.Item) ([]byte, error) {
			var doc *vcardDoc
			itemID := ""
			if original != nil {
				var err error
				if doc, err = parseVCard(original.Data); err != nil {
					return nil, err
				}
				itemID = original.ID
			}
			fetch := func(blobID string) ([]byte, string, error) {
				blob, err := h.cfg.Space.GetItem(ctx, access, blobID)
				if err != nil {
					return nil, "", err
				}
				return blob.Data, blob.Headers["Content-Type"], nil
			}
			encoded, err := encodeContact(object, doc, itemID, fetch)
			if err != nil {
				return nil, err
			}
			return encoded.encode(), nil
		},
		newUID:    func() string { return "urn:uuid:" + newUUID() },
		match:     matchContact,
		sortValue: contactSortValue,
	}
}

func matchContact(card map[string]any, item model.Item, condition map[string]any) (bool, error) {
	for property, value := range condition {
		text, _ := value.(string)
		var ok bool
		switch property {
		case "inAddressBook":
			ok = item.FolderID == text
		case "uid":
			ok = card["uid"] == text
		case "hasMember":
			members, _ := card["members"].(map[string]any)
			ok = members[text] == true
		case "kind":
			kind, _ := card["kind"].(string)
			if kind == "" {
				kind = "individual"
			}
			ok = kind == text
		case "createdBefore", "createdAfter", "updatedBefore", "updatedAfter":
			field := "created"
			if strings.HasPrefix(property, "updated") {
				field = "updated"
			}
			stamp, has := utcDate(card[field])
			limit, valid := utcDate(value)
			if !valid {
				return false, fmt.Errorf("%s must be a UTCDate", property)
			}
			ok = has && ((strings.HasSuffix(property, "Before") && stamp.Before(limit)) || (strings.HasSuffix(property, "After") && !stamp.Before(limit)))
		case "text":
			ok = anyContains(textValues(card), text)
		case "name":
			ok = anyContains(textValues(card["name"]), text)
		case "name/given", "name/surname", "name/surname2":
			ok = anyContains(nameComponents(card, strings.TrimPrefix(property, "name/")), text)
		case "nickname":
			ok = anyContains(textValues(card["nicknames"]), text)
		case "organization":
			ok = anyContains(textValues(card["organizations"]), text)
		case "email":
			ok = anyContains(textValues(card["emails"]), text)
		case "phone":
			ok = anyContains(textValues(card["phones"]), text)
		case "onlineService":
			ok = anyContains(textValues(card["onlineServices"]), text)
		case "address":
			ok = anyContains(textValues(card["addresses"]), text)
		case "note":
			ok = anyContains(textValues(card["notes"]), text)
		default:
			return false, fmt.Errorf("%w %s", errUnsupportedFilter, property)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func nameComponents(card map[string]any, kind string) []string {
	name, _ := card["name"].(map[string]any)
	components, _ := name["components"].([]any)
	var values []string
	for _, raw := range components {
		component, _ := raw.(map[string]any)
		if component["kind"] == kind {
			value, _ := component["value"].(string)
			values = append(values, value)
		}
	}
	return values
}

func contactSortValue(card map[string]any, property string) (string, bool) {
	switch property {
	case "created", "updated":
		value, _ := card[property].(string)
		return value, true
	case "name/given", "name/surname", "name/surname2":
		return strings.ToLower(strings.Join(nameComponents(card, strings.TrimPrefix(property, "name/")), " ")), true
	}
	return "", false
}

func projectAddressBook(folder model.Folder, rights collectionRights, owner bool) map[string]any {
	return map[string]any{"id": folder.ID, "name": folder.Name, "description": nullable(folder.Description), "sortOrder": 0,
		"isDefault": folder.SpecialUse == model.SpecialUseContacts, "isSubscribed": owner || folder.Subscribed, "shareWith": nil,
		"myRights": map[string]bool{"mayRead": rights.read, "mayWrite": rights.create && rights.update && rights.remove, "mayShare": rights.share, "mayDelete": rights.delete}}
}

func (h *Handler) dispatchContacts(ctx context.Context, actor model.User, name string, raw json.RawMessage, created map[string]string) (any, *MethodError, bool) {
	codec := h.contactCodec()
	switch name {
	case "AddressBook/get":
		result, err := h.collectionGet(ctx, actor, raw, created, contactsKind, projectAddressBook)
		return result, err, true
	case "AddressBook/changes":
		result, err := h.typedChanges(ctx, actor, contactsKind, service.ChangeObjectFolder, raw)
		return result, err, true
	case "AddressBook/set":
		result, err := h.collectionSet(ctx, actor, raw, created, contactsKind, projectAddressBook)
		return result, err, true
	case "ContactCard/get":
		result, err := h.itemGet(ctx, actor, raw, created, codec)
		return result, err, true
	case "ContactCard/changes":
		result, err := h.typedChanges(ctx, actor, contactsKind, service.ChangeObjectItem, raw)
		return result, err, true
	case "ContactCard/query":
		result, err := h.itemQuery(ctx, actor, raw, codec)
		return result, err, true
	case "ContactCard/queryChanges":
		result, err := h.itemQueryChanges(ctx, actor, raw, codec)
		return result, err, true
	case "ContactCard/set":
		result, err := h.itemSet(ctx, actor, raw, created, codec)
		return result, err, true
	case "ContactCard/copy":
		result, err := h.itemCopy(ctx, actor, raw, created, codec)
		return result, err, true
	}
	return nil, nil, false
}
