package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// itemCodec adapts one payload format (vCard, iCalendar) to the generic
// collection-backed JMAP item methods shared by ContactCard and
// CalendarEvent.
type itemCodec struct {
	kind      collectionKind
	extension string
	headers   map[string]string
	// decode projects a stored item into its JMAP object without id and
	// containers.
	decode func(item model.Item) (map[string]any, error)
	// encode writes a complete JMAP object into item data; original is nil
	// for a create.
	encode func(ctx context.Context, access service.AccessContext, object map[string]any, original *model.Item) ([]byte, error)
	// newUID generates a uid for objects created without one.
	newUID func() string
	// match evaluates one filter condition; unknown properties are errors.
	match func(object map[string]any, item model.Item, condition map[string]any) (bool, error)
	// sortValue returns the comparable value of a sort property.
	sortValue func(object map[string]any, property string) (string, bool)
}

var errUnsupportedFilter = errors.New("unsupported filter")

// itemObject is the complete JMAP object of a stored item.
func (c itemCodec) itemObject(item model.Item) (map[string]any, error) {
	object, err := c.decode(item)
	if err != nil {
		return nil, err
	}
	object["id"] = item.ID
	object[c.kind.containers] = map[string]any{item.FolderID: true}
	return object, nil
}

func folderIndex(folders []model.Folder) map[string]model.Folder {
	index := make(map[string]model.Folder, len(folders))
	for _, folder := range folders {
		index[folder.ID] = folder
	}
	return index
}

// resolveIDs replaces creation references (RFC 8620 §5.3) in an id list.
func resolveIDs(ids []string, created map[string]string) []string {
	if ids == nil {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = resolveCreated(id, created)
	}
	return out
}

func (h *Handler) itemGet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string, codec itemCodec) (any, *MethodError) {
	var a getArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	a.IDs = resolveIDs(a.IDs, created)
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, codec.kind)
	if e != nil {
		return nil, e
	}
	state, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	list := []any{}
	found := map[string]bool{}
	if a.IDs != nil {
		visible := folderIndex(folders)
		for _, id := range a.IDs {
			item, err := h.cfg.Space.GetItem(ctx, access, id)
			if err != nil || found[id] {
				continue
			}
			if _, ok := visible[item.FolderID]; !ok {
				continue
			}
			if object, err := codec.itemObject(item); err == nil {
				found[id] = true
				list = append(list, selectProperties(object, a.Properties))
			}
		}
	} else {
		for _, item := range h.collectionItems(ctx, access, folders) {
			if object, err := codec.itemObject(item); err == nil {
				list = append(list, selectProperties(object, a.Properties))
			}
		}
	}
	return map[string]any{"accountId": a.AccountID, "state": state, "list": list, "notFound": nonNil(missing(a.IDs, found))}, nil
}

func nonNil(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// containerOf returns the single collection named by an object's container
// set, resolving creation references.
func containerOf(object map[string]any, kind collectionKind, folders map[string]model.Folder, created map[string]string) (model.Folder, bool) {
	set, _ := object[kind.containers].(map[string]any)
	var chosen []string
	for id, on := range set {
		if on == true {
			chosen = append(chosen, resolveCreated(id, created))
		}
	}
	if len(chosen) != 1 {
		return model.Folder{}, false
	}
	folder, ok := folders[chosen[0]]
	return folder, ok
}

func setError(kind string, description string, properties ...string) MethodError {
	return MethodError{Type: kind, Description: description, Properties: properties}
}

func (h *Handler) itemSet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string, codec itemCodec) (any, *MethodError) {
	var a setArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, codec.kind)
	if e != nil {
		return nil, e
	}
	oldState, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	if a.IfInState != "" && a.IfInState != oldState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	visible := folderIndex(folders)
	made, notMade := map[string]any{}, map[string]any{}
	updated, notUpdated := map[string]any{}, map[string]any{}
	destroyed, notDestroyed := []string{}, map[string]any{}
	for _, cid := range sortedKeys(a.Create) {
		var object map[string]any
		if err := json.Unmarshal(a.Create[cid], &object); err != nil {
			notMade[cid] = setError("invalidProperties", "object must be a JSON object")
			continue
		}
		result, setErr := h.createTypedItem(ctx, access, object, visible, created, codec)
		if setErr != nil {
			notMade[cid] = *setErr
			continue
		}
		created[cid] = result["id"].(string)
		made[cid] = result
	}
	for _, rawID := range sortedKeys(a.Update) {
		id := resolveCreated(rawID, created)
		var patch map[string]any
		if err := json.Unmarshal(a.Update[rawID], &patch); err != nil {
			notUpdated[id] = setError("invalidPatch", "patch must be a JSON object")
			continue
		}
		if setErr := h.updateTypedItem(ctx, access, id, patch, visible, created, codec); setErr != nil {
			notUpdated[id] = *setErr
			continue
		}
		updated[id] = nil
	}
	for _, rawID := range a.Destroy {
		id := resolveCreated(rawID, created)
		item, err := h.cfg.Space.GetItem(ctx, access, id)
		if _, ok := visible[item.FolderID]; err != nil || !ok {
			notDestroyed[id] = setError("notFound", "")
			continue
		}
		if err := h.cfg.Space.DeleteItem(ctx, access, id); err != nil {
			notDestroyed[id] = *serverError(err)
			continue
		}
		destroyed = append(destroyed, id)
	}
	newState, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"accountId": a.AccountID, "oldState": oldState, "newState": newState, "created": made, "notCreated": notMade,
		"updated": updated, "notUpdated": notUpdated, "destroyed": destroyed, "notDestroyed": notDestroyed}, nil
}

func (h *Handler) createTypedItem(ctx context.Context, access service.AccessContext, object map[string]any, visible map[string]model.Folder, created map[string]string, codec itemCodec) (map[string]any, *MethodError) {
	if _, ok := object["id"]; ok {
		e := setError("invalidProperties", "id is server-set", "id")
		return nil, &e
	}
	folder, ok := containerOf(object, codec.kind, visible, created)
	if !ok {
		e := setError("invalidProperties", "exactly one visible collection is required", codec.kind.containers)
		return nil, &e
	}
	result := map[string]any{}
	uid, _ := object["uid"].(string)
	if uid == "" {
		uid = codec.newUID()
		object["uid"] = uid
		result["uid"] = uid
	}
	name := uniqueItemName(uid, codec.extension)
	if _, err := h.cfg.Space.GetItemByName(ctx, access, folder.ID, name); err == nil {
		e := setError("invalidProperties", "an object with this uid already exists", "uid")
		return nil, &e
	}
	data, err := codec.encode(ctx, access, object, nil)
	if err != nil {
		e := setError("invalidProperties", err.Error())
		return nil, &e
	}
	item, err := h.cfg.Space.CreateItem(ctx, access, folder.ID, service.ItemInput{Name: name, Data: data, Headers: codec.headers})
	if err != nil {
		return nil, serverError(err)
	}
	result["id"] = item.ID
	return result, nil
}

func (h *Handler) updateTypedItem(ctx context.Context, access service.AccessContext, id string, patch map[string]any, visible map[string]model.Folder, created map[string]string, codec itemCodec) *MethodError {
	item, err := h.cfg.Space.GetItem(ctx, access, id)
	if _, ok := visible[item.FolderID]; err != nil || !ok {
		e := setError("notFound", "")
		return &e
	}
	object, err := codec.itemObject(item)
	if err != nil {
		e := setError("invalidProperties", "stored object cannot be converted: "+err.Error())
		return &e
	}
	uid := object["uid"]
	if err := applyPatch(object, patch); err != nil {
		e := setError("invalidPatch", err.Error())
		return &e
	}
	if object["id"] != id || object["uid"] != uid {
		e := setError("invalidProperties", "id and uid are immutable", "id", "uid")
		return &e
	}
	folder, ok := containerOf(object, codec.kind, visible, created)
	if !ok {
		e := setError("invalidProperties", "exactly one visible collection is required", codec.kind.containers)
		return &e
	}
	data, err := codec.encode(ctx, access, object, &item)
	if err != nil {
		e := setError("invalidProperties", err.Error())
		return &e
	}
	if folder.ID != item.FolderID {
		if item, err = h.cfg.Space.MoveItem(ctx, access, item.ID, folder.ID, item.Name); err != nil {
			return serverError(err)
		}
	}
	if _, err := h.cfg.Space.UpdateItem(ctx, access, item.ID, data, codec.headers); err != nil {
		return serverError(err)
	}
	return nil
}

// itemQueryResult evaluates a query and returns the sorted matching ids.
func (h *Handler) itemQueryResult(ctx context.Context, access service.AccessContext, folders []model.Folder, a queryArgs, codec itemCodec) ([]string, *MethodError) {
	filter, e := decodeFilter(a.Filter)
	if e != nil {
		return nil, e
	}
	type row struct {
		id     string
		object map[string]any
	}
	var rows []row
	var filterErr error
	for _, item := range h.collectionItems(ctx, access, folders) {
		object, err := codec.itemObject(item)
		if err != nil {
			continue
		}
		matched := evalFilter(filter, func(condition map[string]any) bool {
			ok, err := codec.match(object, item, condition)
			if err != nil && filterErr == nil {
				filterErr = err
			}
			return ok
		})
		if matched {
			rows = append(rows, row{id: item.ID, object: object})
		}
	}
	if filterErr != nil {
		return nil, &MethodError{Type: "unsupportedFilter", Description: filterErr.Error()}
	}
	for _, comparator := range a.Sort {
		if _, ok := codec.sortValue(map[string]any{}, comparator.Property); !ok {
			return nil, &MethodError{Type: "unsupportedSort", Description: comparator.Property}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		for _, comparator := range a.Sort {
			left, _ := codec.sortValue(rows[i].object, comparator.Property)
			right, _ := codec.sortValue(rows[j].object, comparator.Property)
			if left == right {
				continue
			}
			return (left < right) == comparator.IsAscending
		}
		return rows[i].id < rows[j].id
	})
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.id
	}
	return ids, nil
}

func (h *Handler) itemQuery(ctx context.Context, actor model.User, raw json.RawMessage, codec itemCodec) (any, *MethodError) {
	var a queryArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, codec.kind)
	if e != nil {
		return nil, e
	}
	state, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	ids, e := h.itemQueryResult(ctx, access, folders, a, codec)
	if e != nil {
		return nil, e
	}
	position := a.Position
	if position < 0 {
		position = max(0, len(ids)+position)
	}
	if a.Anchor != "" {
		anchor := indexOf(ids, a.Anchor)
		if anchor < 0 {
			return nil, &MethodError{Type: "anchorNotFound"}
		}
		position = max(0, anchor+a.AnchorOffset)
	}
	page := window(ids, position, a.Limit)
	result := map[string]any{"accountId": a.AccountID, "queryState": state, "canCalculateChanges": true, "position": min(position, len(ids)), "ids": page}
	if a.CalculateTotal {
		result["total"] = len(ids)
	}
	return result, nil
}

// itemQueryChanges derives query changes from the item journal: every item
// changed since the old query state is removed and, when it still matches,
// added at its current index (RFC 8620 §5.6 permits this conservative form).
func (h *Handler) itemQueryChanges(ctx context.Context, actor model.User, raw json.RawMessage, codec itemCodec) (any, *MethodError) {
	var a queryChangesArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, codec.kind)
	if e != nil {
		return nil, e
	}
	page, err := h.collectionChanges(ctx, access, folders, service.ChangeObjectItem, a.SinceQueryState, 10_000)
	if err != nil {
		return nil, changesError(err)
	}
	if page.HasMoreChanges {
		return nil, &MethodError{Type: "tooManyChanges"}
	}
	created, updated, destroyed := projectJMAPChanges(page.Records, true)
	if a.MaxChanges != nil && *a.MaxChanges > 0 && len(created)+len(updated)+len(destroyed) > *a.MaxChanges {
		return nil, &MethodError{Type: "tooManyChanges"}
	}
	ids, e := h.itemQueryResult(ctx, access, folders, a.queryArgs, codec)
	if e != nil {
		return nil, e
	}
	removed := append(append([]string{}, updated...), destroyed...)
	added := []any{}
	touched := idSet(append(append([]string{}, created...), updated...))
	for index, id := range ids {
		if touched[id] {
			added = append(added, map[string]any{"id": id, "index": index})
		}
	}
	result := map[string]any{"accountId": a.AccountID, "oldQueryState": a.SinceQueryState, "newQueryState": page.NewState, "removed": removed, "added": added}
	if a.CalculateTotal {
		result["total"] = len(ids)
	}
	return result, nil
}

// itemCopy implements Foo/copy between accounts by re-creating the source
// objects with the client's overrides in the destination account.
func (h *Handler) itemCopy(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string, codec itemCodec) (any, *MethodError) {
	var a struct {
		FromAccountID            string                    `json:"fromAccountId"`
		IfFromInState            string                    `json:"ifFromInState"`
		AccountID                string                    `json:"accountId"`
		IfInState                string                    `json:"ifInState"`
		Create                   map[string]map[string]any `json:"create"`
		OnSuccessDestroyOriginal bool                      `json:"onSuccessDestroyOriginal"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	if a.FromAccountID == a.AccountID {
		return nil, &MethodError{Type: "invalidArguments", Description: "fromAccountId and accountId must differ"}
	}
	source, sourceFolders, e := h.kindAccess(ctx, actor, a.FromAccountID, codec.kind)
	if e != nil {
		return nil, e
	}
	destination, folders, e := h.kindAccess(ctx, actor, a.AccountID, codec.kind)
	if e != nil {
		return nil, e
	}
	sourceState, err := h.collectionState(ctx, source, sourceFolders)
	if err != nil {
		return nil, serverError(err)
	}
	oldState, err := h.collectionState(ctx, destination, folders)
	if err != nil {
		return nil, serverError(err)
	}
	if (a.IfFromInState != "" && a.IfFromInState != sourceState) || (a.IfInState != "" && a.IfInState != oldState) {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	sourceVisible, visible := folderIndex(sourceFolders), folderIndex(folders)
	made, notMade := map[string]any{}, map[string]any{}
	for _, cid := range sortedKeys(a.Create) {
		overrides := a.Create[cid]
		sourceID, _ := overrides["id"].(string)
		item, err := h.cfg.Space.GetItem(ctx, source, sourceID)
		if _, ok := sourceVisible[item.FolderID]; err != nil || !ok {
			notMade[cid] = setError("notFound", "")
			continue
		}
		object, err := codec.itemObject(item)
		if err != nil {
			notMade[cid] = setError("invalidProperties", err.Error())
			continue
		}
		delete(object, "id")
		for key, value := range overrides {
			if key != "id" {
				object[key] = value
			}
		}
		result, setErr := h.createTypedItem(ctx, destination, object, visible, created, codec)
		if setErr != nil {
			notMade[cid] = *setErr
			continue
		}
		created[cid] = result["id"].(string)
		made[cid] = result
		if a.OnSuccessDestroyOriginal {
			_ = h.cfg.Space.DeleteItem(ctx, source, item.ID)
		}
	}
	newState, err := h.collectionState(ctx, destination, folders)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"fromAccountId": a.FromAccountID, "accountId": a.AccountID, "oldState": oldState, "newState": newState, "created": made, "notCreated": notMade}, nil
}

// collectionProjector renders a collection-specific JMAP object.
type collectionProjector func(folder model.Folder, rights collectionRights, owner bool) map[string]any

func (h *Handler) collectionGet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string, kind collectionKind, project collectionProjector) (any, *MethodError) {
	var a getArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	a.IDs = resolveIDs(a.IDs, created)
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, kind)
	if e != nil {
		return nil, e
	}
	state, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	wanted := idSet(a.IDs)
	found := map[string]bool{}
	list := []any{}
	for _, folder := range folders {
		if wanted != nil && !wanted[folder.ID] {
			continue
		}
		found[folder.ID] = true
		object := project(folder, h.folderRights(ctx, access, folder), access.Subject.ID == a.AccountID)
		list = append(list, selectProperties(object, a.Properties))
	}
	return map[string]any{"accountId": a.AccountID, "state": state, "list": list, "notFound": nonNil(missing(a.IDs, found))}, nil
}

func (h *Handler) collectionSet(ctx context.Context, actor model.User, raw json.RawMessage, created map[string]string, kind collectionKind, project collectionProjector) (any, *MethodError) {
	var a setArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, invalidArguments(err)
	}
	var extra map[string]json.RawMessage
	_ = json.Unmarshal(raw, &extra)
	var removeContents bool
	_ = json.Unmarshal(extra[kind.removeArg], &removeContents)
	var setDefault string
	_ = json.Unmarshal(extra["onSuccessSetIsDefault"], &setDefault)
	access, folders, e := h.kindAccess(ctx, actor, a.AccountID, kind)
	if e != nil {
		return nil, e
	}
	oldState, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	if a.IfInState != "" && a.IfInState != oldState {
		return nil, &MethodError{Type: "stateMismatch"}
	}
	owner := access.Subject.ID == a.AccountID
	visible := folderIndex(folders)
	made, notMade := map[string]any{}, map[string]any{}
	updated, notUpdated := map[string]any{}, map[string]any{}
	destroyed, notDestroyed := []string{}, map[string]any{}
	for _, cid := range sortedKeys(a.Create) {
		var v struct {
			Name         string `json:"name"`
			IsSubscribed *bool  `json:"isSubscribed"`
		}
		if json.Unmarshal(a.Create[cid], &v) != nil || strings.TrimSpace(v.Name) == "" {
			notMade[cid] = setError("invalidProperties", "name is required", "name")
			continue
		}
		folder, err := h.cfg.Space.CreateFolder(ctx, access, strings.TrimSpace(v.Name), kind.folderType, "")
		if err != nil {
			notMade[cid] = *serverError(err)
			continue
		}
		if v.IsSubscribed != nil {
			if changed, err := h.cfg.Space.UpdateFolder(ctx, access, folder.ID, service.FolderUpdate{Subscribed: v.IsSubscribed}); err == nil {
				folder = changed
			}
		}
		created[cid] = folder.ID
		visible[folder.ID] = folder
		made[cid] = project(folder, h.folderRights(ctx, access, folder), owner)
	}
	for _, rawID := range sortedKeys(a.Update) {
		id := resolveCreated(rawID, created)
		folder, ok := visible[id]
		var patch map[string]any
		if !ok {
			notUpdated[id] = setError("notFound", "")
			continue
		}
		if json.Unmarshal(a.Update[rawID], &patch) != nil {
			notUpdated[id] = setError("invalidPatch", "patch must be a JSON object")
			continue
		}
		if err := h.updateCollection(ctx, access, folder, patch); err != nil {
			notUpdated[id] = *err
			continue
		}
		// Report properties Veksel keeps fixed so the client learns the
		// server value instead of silently diverging.
		current := project(folder, h.folderRights(ctx, access, folder), owner)
		ignored := map[string]any{}
		for key, value := range patch {
			if key != "name" && key != "isSubscribed" && key != "isDefault" {
				if normalized, exists := current[key]; exists && fmt.Sprint(normalizeJSON(normalized)) != fmt.Sprint(value) {
					ignored[key] = normalized
				}
			}
		}
		if len(ignored) > 0 {
			updated[id] = ignored
		} else {
			updated[id] = nil
		}
	}
	for _, rawID := range a.Destroy {
		id := resolveCreated(rawID, created)
		if _, ok := visible[id]; !ok {
			notDestroyed[id] = setError("notFound", "")
			continue
		}
		if !removeContents {
			if items, err := h.cfg.Space.ListItems(ctx, access, id, service.ItemQuery{Limit: 1, MetadataOnly: true}); err == nil && len(items) > 0 {
				notDestroyed[id] = setError(kind.hasContent, "")
				continue
			}
		}
		if err := h.cfg.Space.DeleteFolder(ctx, access, id); err != nil {
			notDestroyed[id] = *serverError(err)
			continue
		}
		destroyed = append(destroyed, id)
	}
	if setDefault != "" && kind.folderType == model.FolderTypeCalendar {
		yes := true
		if _, err := h.cfg.Space.UpdateFolder(ctx, access, resolveCreated(setDefault, created), service.FolderUpdate{Default: &yes}); err != nil {
			return nil, serverError(err)
		}
	}
	newState, err := h.collectionState(ctx, access, folders)
	if err != nil {
		return nil, serverError(err)
	}
	return map[string]any{"accountId": a.AccountID, "oldState": oldState, "newState": newState, "created": made, "notCreated": notMade,
		"updated": updated, "notUpdated": notUpdated, "destroyed": destroyed, "notDestroyed": notDestroyed}, nil
}

func (h *Handler) updateCollection(ctx context.Context, access service.AccessContext, folder model.Folder, patch map[string]any) *MethodError {
	if raw, ok := patch["name"]; ok {
		name, _ := raw.(string)
		if strings.TrimSpace(name) == "" {
			e := setError("invalidProperties", "name is required", "name")
			return &e
		}
		if _, err := h.cfg.Space.MoveFolder(ctx, access, folder.ID, folder.ParentID, strings.TrimSpace(name)); err != nil {
			return serverError(err)
		}
	}
	update := service.FolderUpdate{}
	if raw, ok := patch["isSubscribed"]; ok {
		subscribed, valid := raw.(bool)
		if !valid {
			e := setError("invalidProperties", "isSubscribed must be a boolean", "isSubscribed")
			return &e
		}
		update.Subscribed = &subscribed
	}
	if raw, ok := patch["isDefault"]; ok {
		if raw != true || folder.Type != model.FolderTypeCalendar {
			e := setError("invalidProperties", "isDefault can only be set to true on a calendar", "isDefault")
			return &e
		}
		yes := true
		update.Default = &yes
	}
	if update.Subscribed != nil || update.Default != nil {
		if _, err := h.cfg.Space.UpdateFolder(ctx, access, folder.ID, update); err != nil {
			return serverError(err)
		}
	}
	return nil
}

// textValues collects every string in a JSON subtree.
func textValues(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case map[string]any:
		var out []string
		for key, item := range v {
			if key == "blobId" || key == "@type" {
				continue
			}
			out = append(out, textValues(item)...)
		}
		return out
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, textValues(item)...)
		}
		return out
	}
	return nil
}

func anyContains(values []string, needle string) bool {
	for _, value := range values {
		if containsFold(value, needle) {
			return true
		}
	}
	return false
}

// utcDate parses a JMAP UTCDate filter value.
func utcDate(value any) (time.Time, bool) {
	text, _ := value.(string)
	when, err := time.Parse(time.RFC3339, text)
	return when, err == nil
}
