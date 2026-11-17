package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// collectionKind binds a JMAP collection/item type pair to the typed
// FolderSpace collections that back it. Contacts and calendars share every
// generic method below; only the item codec differs.
type collectionKind struct {
	folderType model.FolderType
	capability string
	collection string // AddressBook, Calendar
	item       string // ContactCard, CalendarEvent
	containers string // addressBookIds, calendarIds
	hasContent string // SetError type when destroying a non-empty collection
	removeArg  string // destroy argument that removes contents
}

var (
	contactsKind = collectionKind{folderType: model.FolderTypeContacts, capability: ContactsCapability, collection: "AddressBook", item: "ContactCard",
		containers: "addressBookIds", hasContent: "addressBookHasContents", removeArg: "onDestroyRemoveContents"}
	calendarsKind = collectionKind{folderType: model.FolderTypeCalendar, capability: CalendarsCapability, collection: "Calendar", item: "CalendarEvent",
		containers: "calendarIds", hasContent: "calendarHasEvent", removeArg: "onDestroyRemoveEvents"}
)

// jmapFolderTypes are the folder types that make an account visible through
// JMAP; any one of them shared with the actor exposes the owner's account.
var jmapFolderTypes = []model.FolderType{model.FolderTypeMail, model.FolderTypeContacts, model.FolderTypeCalendar}

// typedFolders lists the folders of one type that belong to the account the
// access context was validated for.
func (h *Handler) typedFolders(ctx context.Context, access service.AccessContext, folderType model.FolderType) ([]model.Folder, error) {
	folders, err := h.cfg.Space.ListFolders(ctx, access, service.FolderQuery{Type: folderType})
	if err != nil {
		return nil, err
	}
	accountID := strings.TrimPrefix(access.Correlation, "account:")
	filtered := folders[:0]
	for _, folder := range folders {
		if accountID == "" || folder.UserID == accountID {
			filtered = append(filtered, folder)
		}
	}
	return filtered, nil
}

// accountFolderTypes reports which JMAP-visible folder types the actor can
// reach in the account. Owners and delegates always reach every type.
func (h *Handler) accountFolderTypes(ctx context.Context, access service.AccessContext, accountID string) map[model.FolderType]bool {
	types := map[model.FolderType]bool{}
	if access.Subject.ID == accountID {
		for _, folderType := range jmapFolderTypes {
			types[folderType] = true
		}
		return types
	}
	folders, err := h.cfg.Space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return types
	}
	for _, folder := range folders {
		if folder.UserID == accountID {
			types[folder.Type] = true
		}
	}
	return types
}

// collectionState is the change state of the account journal that holds the
// folders. Owners and delegates read the subject journal; a sharee reads the
// owner's journal through one of the shared folders.
func (h *Handler) collectionState(ctx context.Context, access service.AccessContext, folders []model.Folder) (string, error) {
	reader, ok := h.cfg.Space.(service.FolderChangeReader)
	if !ok {
		return "", errors.New("incremental change history is unavailable")
	}
	scope := service.ChangeScope{}
	if accountID := strings.TrimPrefix(access.Correlation, "account:"); access.Subject.ID != accountID && len(folders) > 0 {
		scope.FolderID = folders[0].ID
	}
	return reader.CurrentChangeState(ctx, access, scope)
}

// collectionChanges returns the journal records since state that touch the
// folders (object folder) or the items in them (object item). Moves into or
// out of the folder set are rewritten as creates and destroys.
func (h *Handler) collectionChanges(ctx context.Context, access service.AccessContext, folders []model.Folder, object service.ChangeObject, since string, limit int) (service.ChangePage, error) {
	reader, ok := h.cfg.Space.(service.FolderChangeReader)
	if !ok {
		return service.ChangePage{}, errors.New("incremental change history is unavailable")
	}
	member := make(map[string]bool, len(folders))
	for _, folder := range folders {
		member[folder.ID] = true
	}
	var pages []service.ChangePage
	if accountID := strings.TrimPrefix(access.Correlation, "account:"); access.Subject.ID == accountID || len(folders) == 0 {
		page, err := reader.ListChanges(ctx, access, service.ChangeScope{Object: object}, since, limit)
		if err != nil {
			return service.ChangePage{}, err
		}
		pages = append(pages, page)
	} else {
		// Every folder of one owner shares that owner's journal, so the
		// per-folder pages use one sequence space and merge directly.
		for _, folder := range folders {
			page, err := reader.ListChanges(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: object}, since, limit)
			if err != nil {
				return service.ChangePage{}, err
			}
			pages = append(pages, page)
		}
	}
	return mergeChangePages(pages, member, object), nil
}

func mergeChangePages(pages []service.ChangePage, member map[string]bool, object service.ChangeObject) service.ChangePage {
	merged := service.ChangePage{OldState: pages[0].OldState, NewState: pages[0].NewState, CurrentState: pages[0].CurrentState}
	cutoff := ^uint64(0)
	for _, page := range pages {
		if page.HasMoreChanges && len(page.Records) > 0 {
			if last := page.Records[len(page.Records)-1].Sequence; last < cutoff {
				cutoff, merged.NewState, merged.HasMoreChanges = last, page.NewState, true
			}
		}
	}
	if !merged.HasMoreChanges {
		merged.NewState = merged.CurrentState
	}
	seen := map[uint64]bool{}
	for _, page := range pages {
		for _, record := range page.Records {
			if record.Sequence > cutoff || seen[record.Sequence] {
				continue
			}
			seen[record.Sequence] = true
			changes := make([]service.Change, 0, len(record.Changes))
			for _, change := range record.Changes {
				if change.Object == service.ChangeObjectFolder {
					changes = append(changes, change)
					continue
				}
				in, was := member[change.FolderID], member[change.PreviousFolderID]
				switch {
				case in && change.PreviousFolderID != "" && !was:
					change.Operation = service.ChangeCreate
				case !in && was:
					change.Operation = service.ChangeDestroy
				case !in:
					continue
				}
				changes = append(changes, change)
			}
			if len(changes) > 0 {
				record.Changes = changes
				merged.Records = append(merged.Records, record)
			}
		}
	}
	sort.Slice(merged.Records, func(i, j int) bool { return merged.Records[i].Sequence < merged.Records[j].Sequence })
	return merged
}

// typedChanges implements Foo/changes for the collection and item types of
// a kind.
func (h *Handler) typedChanges(ctx context.Context, actor model.User, kind collectionKind, object service.ChangeObject, raw json.RawMessage) (any, *MethodError) {
	var a changesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, kind)
	if e != nil {
		return nil, e
	}
	limit := 500
	if a.MaxChanges != nil && *a.MaxChanges > 0 {
		limit = *a.MaxChanges
	}
	page, err := h.kindChanges(ctx, access, folders, kind, object, a.SinceState, limit)
	if err != nil {
		return nil, changesError(err)
	}
	created, updated, destroyed := projectJMAPChanges(page.Records, true)
	result := map[string]any{"accountId": a.AccountID, "oldState": page.OldState, "newState": page.NewState, "hasMoreChanges": page.HasMoreChanges, "created": created, "updated": updated, "destroyed": destroyed}
	if object == service.ChangeObjectFolder {
		result["updatedProperties"] = nil
	}
	return result, nil
}

func (h *Handler) kindChanges(ctx context.Context, access service.AccessContext, folders []model.Folder, kind collectionKind, object service.ChangeObject, since string, limit int) (service.ChangePage, error) {
	page, err := h.collectionChanges(ctx, access, folders, object, since, limit)
	if err != nil || object != service.ChangeObjectFolder {
		return page, err
	}
	// Folder records carry their type, which also identifies collections
	// destroyed since the client's state.
	filtered := page.Records[:0]
	for _, record := range page.Records {
		changes := record.Changes[:0]
		for _, change := range record.Changes {
			if change.FolderType == kind.folderType {
				changes = append(changes, change)
			}
		}
		if len(changes) > 0 {
			record.Changes = changes
			filtered = append(filtered, record)
		}
	}
	page.Records = filtered
	return page, nil
}

func changesError(err error) *MethodError {
	if errors.Is(err, service.ErrChangeStateExpired) || strings.Contains(err.Error(), "change state") {
		return &MethodError{Type: "cannotCalculateChanges", Description: err.Error()}
	}
	return serverError(err)
}

// kindAccess validates the account and lists the kind's collections in it.
func (h *Handler) kindAccess(ctx context.Context, actor model.User, accountID string, kind collectionKind) (service.AccessContext, []model.Folder, *MethodError) {
	access, e := h.validateAccount(ctx, actor, accountID)
	if e != nil {
		return access, nil, e
	}
	folders, err := h.typedFolders(ctx, access, kind.folderType)
	if err != nil {
		return access, nil, serverError(err)
	}
	return access, folders, nil
}

// collectionRights is the authorization projection behind JMAP myRights.
type collectionRights struct {
	read, create, update, remove, share, delete bool
}

func (h *Handler) folderRights(ctx context.Context, access service.AccessContext, folder model.Folder) collectionRights {
	if strings.EqualFold(folder.UserID, access.Subject.ID) {
		return collectionRights{read: true, create: true, update: true, remove: true, share: access.Subject == access.Actor, delete: !folder.System}
	}
	if h.cfg.Authorizer == nil {
		return collectionRights{read: true}
	}
	request := authz.Request{Actor: access.Actor, Subject: access.Subject, Mode: access.Mode, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID}}
	allowed := func(action authz.Action) bool {
		request.Action = action
		decision, err := h.cfg.Authorizer.Check(ctx, request)
		return err == nil && decision.Allowed
	}
	return collectionRights{read: allowed(authz.FolderItemsRead), create: allowed(authz.FolderItemsCreate), update: allowed(authz.FolderItemsUpdate),
		remove: allowed(authz.FolderItemsDelete), share: allowed(authz.FolderSharesManage)}
}

func (h *Handler) collectionItems(ctx context.Context, access service.AccessContext, folders []model.Folder) []model.Item {
	var out []model.Item
	for _, folder := range folders {
		items, err := h.cfg.Space.ListItems(ctx, access, folder.ID, service.ItemQuery{})
		if err == nil {
			out = append(out, items...)
		}
	}
	return out
}

// selectProperties limits a JMAP object to the requested properties; the id
// is always returned.
func selectProperties(object map[string]any, properties []string) map[string]any {
	if properties == nil {
		return object
	}
	selected := map[string]any{"id": object["id"]}
	for _, property := range properties {
		if value, ok := object[property]; ok {
			selected[property] = value
		}
	}
	return selected
}

// applyPatch applies a JMAP PatchObject (RFC 8620 §5.3) to a JSON object.
// Keys are JSON pointers without the leading slash; a null value removes.
func applyPatch(object map[string]any, patch map[string]any) error {
	keys := make([]string, 0, len(patch))
	for key := range patch {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for index, key := range keys {
		if index > 0 && strings.HasPrefix(key, keys[index-1]+"/") {
			return fmt.Errorf("patch %q overlaps %q", key, keys[index-1])
		}
		parts := strings.Split(key, "/")
		for i := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
		}
		node := object
		for _, part := range parts[:len(parts)-1] {
			next, ok := node[part].(map[string]any)
			if !ok {
				return fmt.Errorf("patch path %q does not exist", key)
			}
			node = next
		}
		last := parts[len(parts)-1]
		if patch[key] == nil {
			delete(node, last)
		} else {
			node[last] = cloneJSON(patch[key])
		}
	}
	return nil
}

// cloneJSON deep-copies a decoded JSON value.
func cloneJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = cloneJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = cloneJSON(item)
		}
		return out
	default:
		return v
	}
}

// normalizeJSON round-trips a Go value through JSON so typed values compare
// equal to decoded request values.
func normalizeJSON(value any) any {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(data, &out)
	return out
}

// evalFilter evaluates a JMAP FilterOperator/FilterCondition tree.
func evalFilter(filter map[string]any, match func(map[string]any) bool) bool {
	if filter == nil {
		return true
	}
	operator, ok := filter["operator"].(string)
	if !ok {
		return match(filter)
	}
	conditions, _ := filter["conditions"].([]any)
	switch operator {
	case "AND":
		for _, condition := range conditions {
			if c, ok := condition.(map[string]any); ok && !evalFilter(c, match) {
				return false
			}
		}
		return true
	case "OR":
		for _, condition := range conditions {
			if c, ok := condition.(map[string]any); ok && evalFilter(c, match) {
				return true
			}
		}
		return false
	case "NOT":
		for _, condition := range conditions {
			if c, ok := condition.(map[string]any); ok && evalFilter(c, match) {
				return false
			}
		}
		return true
	}
	return false
}

func decodeFilter(raw json.RawMessage) (map[string]any, *MethodError) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var filter map[string]any
	if err := json.Unmarshal(raw, &filter); err != nil {
		return nil, &MethodError{Type: "invalidArguments", Description: "filter must be an object"}
	}
	return filter, nil
}

// containsFold reports whether value contains needle case-insensitively.
func containsFold(value, needle string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(needle))
}

// uniqueItemName derives a collection-unique protocol name from a UID,
// falling back to an opaque name when the UID is unsuitable as a path segment.
func uniqueItemName(uid, extension string) string {
	safe := uid != "" && len(uid) <= 200
	for _, r := range uid {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.@", r)) {
			safe = false
			break
		}
	}
	if !safe {
		sum := sha256Bytes(uid)
		return fmt.Sprintf("%x.%s", sum[:16], extension)
	}
	return uid + "." + extension
}

// newUUID returns a random RFC 9562 version 4 UUID.
func newUUID() string {
	id := randomID("")
	b := []byte(id[:32])
	b[12] = '4'
	variant, _ := strconv.ParseUint(string(b[16]), 16, 8)
	b[16] = "89ab"[variant&3]
	return string(b[0:8]) + "-" + string(b[8:12]) + "-" + string(b[12:16]) + "-" + string(b[16:20]) + "-" + string(b[20:32])
}
