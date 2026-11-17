package eas

import (
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// EAS folder types (MS-ASCMD 2.2.3.186.3).
const (
	folderTypeUserGeneric   = "1"
	folderTypeInbox         = "2"
	folderTypeDrafts        = "3"
	folderTypeDeleted       = "4"
	folderTypeSent          = "5"
	folderTypeTasks         = "7"
	folderTypeCalendar      = "8"
	folderTypeContacts      = "9"
	folderTypeUserMail      = "12"
	folderTypeUserCalendar  = "13"
	folderTypeUserContacts  = "14"
	folderTypeUserTasks     = "15"
	folderTypeRecipientInfo = "19"
)

// easSyncable reports whether a folder carries an item class ActiveSync
// can represent. Files, Sieve scripts, scheduling mailboxes, saved
// searches, templates and notes would otherwise appear as mail folders.
func easSyncable(folderType model.FolderType) bool {
	switch folderType {
	case model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeTasks:
		return true
	}
	return false
}

// folderView assigns EAS folder types to one account's hierarchy. Default
// types (Inbox, Calendar, ...) may appear once and only for the user's own
// folders: a shared folder with the same special use is a user folder.
type folderView struct {
	types   map[string]string
	visible map[string]model.Folder
}

func newFolderView(userID string, folders []model.Folder) folderView {
	view := folderView{types: map[string]string{}, visible: map[string]model.Folder{}}
	sorted := slices.Clone(folders)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].UserID == userID != (sorted[j].UserID == userID) {
			return sorted[i].UserID == userID
		}
		return sorted[i].Path < sorted[j].Path
	})
	used := map[string]bool{}
	for _, folder := range sorted {
		if !easSyncable(folder.Type) || strings.HasPrefix(folder.SpecialUse, model.SpecialUseHeldDeletedPrefix) {
			continue
		}
		view.visible[folder.ID] = folder
		folderType := userFolderType(folder.Type)
		if folder.UserID == userID || folder.UserID == "" {
			if candidate := defaultFolderType(folder); candidate != "" && !used[candidate] {
				folderType = candidate
				used[candidate] = true
			}
		}
		view.types[folder.ID] = folderType
	}
	return view
}

func defaultFolderType(folder model.Folder) string {
	switch strings.TrimPrefix(strings.ToLower(folder.SpecialUse), "\\") {
	case model.SpecialUseInbox:
		return folderTypeInbox
	case model.SpecialUseDrafts:
		return folderTypeDrafts
	case model.SpecialUseTrash:
		return folderTypeDeleted
	case model.SpecialUseSent:
		return folderTypeSent
	case model.SpecialUseCalendar:
		return folderTypeCalendar
	case model.SpecialUseContacts:
		return folderTypeContacts
	case model.SpecialUseRecentRecipients:
		return folderTypeRecipientInfo
	}
	if folder.Type == model.FolderTypeTasks {
		return folderTypeTasks
	}
	return ""
}

func userFolderType(folderType model.FolderType) string {
	switch folderType {
	case model.FolderTypeCalendar:
		return folderTypeUserCalendar
	case model.FolderTypeContacts:
		return folderTypeUserContacts
	case model.FolderTypeTasks:
		return folderTypeUserTasks
	default:
		return folderTypeUserMail
	}
}

// easFolderType is the stateless type of one folder, used when a whole
// hierarchy is not at hand.
func easFolderType(folder model.Folder) string {
	if candidate := defaultFolderType(folder); candidate != "" && candidate != folderTypeTasks {
		return candidate
	}
	if folder.Type == model.FolderTypeNotes {
		return "17"
	}
	return userFolderType(folder.Type)
}

func folderTypeFromEAS(value string) model.FolderType {
	switch value {
	case "8", "13":
		return model.FolderTypeCalendar
	case "9", "14", "19":
		return model.FolderTypeContacts
	case "7", "15":
		return model.FolderTypeTasks
	case "10", "17":
		return model.FolderTypeNotes
	default:
		return model.FolderTypeMail
	}
}

func (v folderView) change(tag string, folder model.Folder) *Node {
	parentID := "0"
	if _, ok := v.visible[folder.ParentID]; ok && folder.ParentID != "" {
		parentID = encodeServerID("f:", folder.ParentID)
	}
	return E(7, tag,
		T(7, "ServerId", encodeServerID("f:", folder.ID)),
		T(7, "ParentId", parentID),
		T(7, "DisplayName", folder.Name),
		T(7, "Type", v.types[folder.ID]),
	)
}

func (h *Handler) folderView(command *commandContext) (folderView, error) {
	folders, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{})
	if err != nil {
		return folderView{}, err
	}
	return newFolderView(command.userID, folders), nil
}

func (h *Handler) folderSync(command *commandContext) (*Node, error) {
	state := command.state
	requestKey := childText(command.request, "SyncKey")
	if requestKey == "" {
		return E(7, "FolderSync", T(7, "Status", "10")), nil
	}
	switch {
	case requestKey == "0":
	case requestKey == state.FolderKey:
	case requestKey == state.PreviousFolderKey && state.PreviousFolderKey != "":
		// The client never received the response that issued FolderKey.
		state.FolderState = state.PreviousFolderState
		state.FolderEchoes = slices.Clone(state.PreviousFolderEchoes)
	default:
		return E(7, "FolderSync", T(7, "Status", "9")), nil
	}
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return nil, errors.New("folder space does not provide incremental changes")
	}
	view, err := h.folderView(command)
	if err != nil {
		return nil, err
	}
	key, err := nextKey()
	if err != nil {
		return nil, err
	}
	changes := E(7, "Changes")
	if requestKey == "0" || state.FolderState == "" {
		folders := make([]model.Folder, 0, len(view.visible))
		for _, folder := range view.visible {
			folders = append(folders, folder)
		}
		// Parents precede children, so a client can file each Add.
		sort.Slice(folders, func(i, j int) bool {
			if depthI, depthJ := strings.Count(folders[i].Path, "/"), strings.Count(folders[j].Path, "/"); depthI != depthJ {
				return depthI < depthJ
			}
			return folders[i].Path < folders[j].Path
		})
		for _, folder := range folders {
			changes.Children = append(changes.Children, view.change("Add", folder))
		}
		current, stateErr := reader.CurrentChangeState(command.ctx, command.access, service.ChangeScope{Object: service.ChangeObjectFolder})
		if stateErr != nil {
			return nil, stateErr
		}
		if requestKey == "0" {
			// A full resynchronization invalidates every collection key.
			state.CollectionKeys = map[string]string{}
			state.CollectionStates = map[string]string{}
			state.CollectionInitialStates = map[string]string{}
			state.CollectionOffsets = map[string]int{}
			state.PreviousCollections = map[string]CollectionSnapshot{}
			state.CollectionEchoes = map[string][]Echo{}
			state.CollectionClientIDs = map[string]map[string]string{}
		}
		state.PreviousFolderKey, state.PreviousFolderState = "", ""
		state.FolderState, state.FolderEchoes = current, nil
	} else {
		page, listErr := reader.ListChanges(command.ctx, command.access, service.ChangeScope{Object: service.ChangeObjectFolder}, state.FolderState, 10_000)
		if listErr != nil {
			return E(7, "FolderSync", T(7, "Status", "9")), nil
		}
		seen := map[string]bool{}
		echoed := map[string]bool{}
		for _, id := range state.FolderEchoes {
			echoed[id] = true
		}
		previousEchoes := slices.Clone(state.FolderEchoes)
		var adds, updates, deletes []*Node
		for _, record := range page.Records {
			for _, change := range record.Changes {
				if seen[change.ID] || echoed[change.ID] {
					continue
				}
				seen[change.ID] = true
				folder, visible := view.visible[change.ID]
				if !visible {
					if change.FolderType != "" && !easSyncable(change.FolderType) {
						continue
					}
					if existing, getErr := h.space.GetFolder(command.ctx, command.access, change.ID); getErr == nil && existing.TrashedAt.IsZero() && !easSyncable(existing.Type) {
						continue
					}
					deletes = append(deletes, E(7, "Delete", T(7, "ServerId", encodeServerID("f:", change.ID))))
					continue
				}
				if folderCreatedIn(page, change.ID) {
					adds = append(adds, view.change("Add", folder))
				} else {
					updates = append(updates, view.change("Update", folder))
				}
			}
		}
		// Parents were created first, and journal order preserves that.
		changes.Children = append(append(append(changes.Children, adds...), updates...), deletes...)
		state.FolderEchoes = slices.DeleteFunc(state.FolderEchoes, func(id string) bool { return pageMentions(page, id) })
		state.PreviousFolderKey, state.PreviousFolderState, state.PreviousFolderEchoes = requestKey, state.FolderState, previousEchoes
		state.FolderState = page.NewState
	}
	state.FolderKey = key
	changes.Children = append([]*Node{T(7, "Count", strconv.Itoa(len(changes.Children)))}, changes.Children...)
	return E(7, "FolderSync", T(7, "Status", "1"), T(7, "SyncKey", key), changes), nil
}

func folderCreatedIn(page service.ChangePage, id string) bool {
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.ID == id && (change.Operation == service.ChangeCreate || change.Operation == service.ChangeRestore) {
				return true
			}
		}
	}
	return false
}

func pageMentions(page service.ChangePage, id string) bool {
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.ID == id {
				return true
			}
		}
	}
	return false
}

// folderKeyStatus validates the SyncKey of FolderCreate, FolderDelete and
// FolderUpdate, which must match the current hierarchy key.
func folderKeyStatus(command *commandContext) string {
	key := childText(command.request, "SyncKey")
	if key == "" || key == "0" || key != command.state.FolderKey {
		return "9"
	}
	return ""
}

func (h *Handler) rotateFolderKey(state *DeviceState, folderID string) string {
	key, _ := nextKey()
	state.FolderKey = key
	state.PreviousFolderKey, state.PreviousFolderState = "", ""
	if !slices.Contains(state.FolderEchoes, folderID) {
		state.FolderEchoes = append(state.FolderEchoes, folderID)
		if excess := len(state.FolderEchoes) - maxEchoes; excess > 0 {
			state.FolderEchoes = state.FolderEchoes[excess:]
		}
	}
	return key
}

func folderErrorStatus(err error, notFound string) string {
	switch {
	case errors.Is(err, store.ErrExists):
		return "2"
	case errors.Is(err, store.ErrNotFound):
		return notFound
	case errors.Is(err, service.ErrForbidden):
		return "3"
	case errors.Is(err, service.ErrInvalidRequest):
		return "10"
	}
	return "6"
}

func (h *Handler) resolveParent(command *commandContext, value string) (string, bool) {
	if value == "" || value == "0" {
		return "", true
	}
	id, err := decodeServerID(value, "f:")
	if err != nil {
		return "", false
	}
	if _, err := h.space.GetFolder(command.ctx, command.access, id); err != nil {
		return "", false
	}
	return id, true
}

func (h *Handler) folderCreate(command *commandContext) (*Node, error) {
	if status := folderKeyStatus(command); status != "" {
		return E(7, "FolderCreate", T(7, "Status", status)), nil
	}
	name := strings.TrimSpace(childText(command.request, "DisplayName"))
	if name == "" {
		return E(7, "FolderCreate", T(7, "Status", "10")), nil
	}
	parentID, ok := h.resolveParent(command, childText(command.request, "ParentId"))
	if !ok {
		return E(7, "FolderCreate", T(7, "Status", "5")), nil
	}
	folderType := folderTypeFromEAS(childText(command.request, "Type"))
	if !easSyncable(folderType) {
		return E(7, "FolderCreate", T(7, "Status", "10")), nil
	}
	folder, err := h.space.CreateFolder(command.ctx, command.access, name, folderType, parentID)
	if err != nil {
		if errors.Is(err, model.ErrQuotaExceeded) || service.IsTemporarilyUnavailable(err) {
			return nil, err
		}
		return E(7, "FolderCreate", T(7, "Status", folderErrorStatus(err, "5"))), nil
	}
	key := h.rotateFolderKey(command.state, folder.ID)
	return E(7, "FolderCreate", T(7, "Status", "1"), T(7, "SyncKey", key), T(7, "ServerId", encodeServerID("f:", folder.ID))), nil
}

func (h *Handler) folderDelete(command *commandContext) (*Node, error) {
	if status := folderKeyStatus(command); status != "" {
		return E(7, "FolderDelete", T(7, "Status", status)), nil
	}
	id, err := decodeServerID(childText(command.request, "ServerId"), "f:")
	if err != nil {
		return E(7, "FolderDelete", T(7, "Status", "4")), nil
	}
	folder, err := h.space.GetFolder(command.ctx, command.access, id)
	if err != nil {
		return E(7, "FolderDelete", T(7, "Status", "4")), nil
	}
	if folder.System || folder.SpecialUse != "" {
		return E(7, "FolderDelete", T(7, "Status", "3")), nil
	}
	if err := h.space.DeleteFolder(command.ctx, command.access, id); err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return nil, err
		}
		return E(7, "FolderDelete", T(7, "Status", folderErrorStatus(err, "4"))), nil
	}
	command.state.resetCollection(id)
	key := h.rotateFolderKey(command.state, id)
	return E(7, "FolderDelete", T(7, "Status", "1"), T(7, "SyncKey", key)), nil
}

func (h *Handler) folderUpdate(command *commandContext) (*Node, error) {
	if status := folderKeyStatus(command); status != "" {
		return E(7, "FolderUpdate", T(7, "Status", status)), nil
	}
	id, err := decodeServerID(childText(command.request, "ServerId"), "f:")
	if err != nil {
		return E(7, "FolderUpdate", T(7, "Status", "4")), nil
	}
	folder, err := h.space.GetFolder(command.ctx, command.access, id)
	if err != nil {
		return E(7, "FolderUpdate", T(7, "Status", "4")), nil
	}
	if folder.System || folder.SpecialUse != "" {
		return E(7, "FolderUpdate", T(7, "Status", "3")), nil
	}
	parentID, ok := h.resolveParent(command, childText(command.request, "ParentId"))
	if !ok {
		return E(7, "FolderUpdate", T(7, "Status", "5")), nil
	}
	name := strings.TrimSpace(childText(command.request, "DisplayName"))
	if name == "" {
		name = folder.Name
	}
	if _, err := h.space.MoveFolder(command.ctx, command.access, id, parentID, name); err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return nil, err
		}
		return E(7, "FolderUpdate", T(7, "Status", folderErrorStatus(err, "4"))), nil
	}
	key := h.rotateFolderKey(command.state, id)
	return E(7, "FolderUpdate", T(7, "Status", "1"), T(7, "SyncKey", key)), nil
}
