package eas

import (
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Sync collection status codes (MS-ASCMD 2.2.3.177.17).
const (
	syncStatusOK             = "1"
	syncStatusInvalidKey     = "3"
	syncStatusProtocolError  = "4"
	syncStatusServerError    = "5"
	syncStatusConversion     = "6"
	syncStatusConflict       = "7"
	syncStatusNotFound       = "8"
	syncStatusHierarchy      = "12"
	syncStatusIncomplete     = "13"
	syncStatusInvalidWait    = "14"
	syncStatusTooManyFolders = "15"
	// syncStatusSent is internal: a 16.0 draft was sent and removed, so the
	// journal's deletion must reach the device rather than be suppressed.
	syncStatusSent = "sent"
	// sentClientID marks a ClientId whose Add was a draft sent at once.
	sentClientID              = "\x00sent"
	defaultWindowSize         = 100
	maxWindowSize             = 512
	maxCachedSyncRequestBytes = 64 << 10
	// maxInitialPages bounds the item pages one initial window reads.
	maxInitialPages = 20
)

// SyncOptions are one collection's persistent Sync options.
type SyncOptions struct {
	FilterType      int              `json:"filter_type,omitempty"`
	BodyPreferences []BodyPreference `json:"body_preferences,omitempty"`
	MIMESupport     int              `json:"mime_support,omitempty"`
	// ClientWins records Conflict 0; the default (1) lets the server win.
	ClientWins bool `json:"client_wins,omitempty"`
}

// parseSyncOptions reads the Options element for the collection's own
// class; a mail folder may also carry SMS options, which are ignored.
func parseSyncOptions(collection *Node, folderType model.FolderType) (SyncOptions, bool) {
	var chosen *Node
	for _, options := range collection.ChildrenNamed("Options") {
		class := childText(options, "Class")
		if class == "" || class == easClass(folderType) {
			chosen = options
			break
		}
	}
	if chosen == nil {
		return SyncOptions{}, false
	}
	filter, _ := strconv.Atoi(childText(chosen, "FilterType"))
	mimeSupport, _ := strconv.Atoi(childText(chosen, "MIMESupport"))
	options := SyncOptions{FilterType: filter, BodyPreferences: parseBodyPreferences(chosen), MIMESupport: mimeSupport}
	if conflict := chosen.Child("Conflict"); conflict != nil {
		options.ClientWins = conflict.Text == "0"
	}
	return options, true
}

func easClass(folderType model.FolderType) string {
	switch folderType {
	case model.FolderTypeCalendar:
		return "Calendar"
	case model.FolderTypeContacts:
		return "Contacts"
	case model.FolderTypeTasks:
		return "Tasks"
	}
	return "Email"
}

// filterCutoff converts an EAS FilterType into the oldest item to send.
func filterCutoff(filter int, now time.Time) time.Time {
	days := map[int]int{1: 1, 2: 3, 3: 7, 4: 14, 5: 31, 6: 92, 7: 183}[filter]
	if days == 0 {
		return time.Time{}
	}
	return now.AddDate(0, 0, -days)
}

// syncWithWait runs Sync, first holding a request that asks to wait for
// changes (Wait or HeartbeatInterval) until one arrives or the interval ends.
func (h *Handler) syncWithWait(command *commandContext, r *http.Request) (*Node, error) {
	if command.request != nil {
		wait, waitStatus := syncWaitInterval(command.request)
		if waitStatus != nil {
			return h.withState(command, r, func(*commandContext) (*Node, error) { return waitStatus, nil })
		}
		if wait > 0 && command.request.Descendant("Commands") == nil {
			var waiter *pingWaiter
			idle := false
			_, err := h.withState(command, r, func(command *commandContext) (*Node, error) {
				var folders []string
				for _, collection := range command.request.Descendant("Collections").ChildrenNamed("Collection") {
					folderID, decodeErr := decodeServerID(childText(collection, "CollectionId"), "f:")
					key := childText(collection, "SyncKey")
					if decodeErr != nil || key == "0" || key != command.state.CollectionKeys[folderID] {
						return nil, nil
					}
					folders = append(folders, folderID)
				}
				if len(folders) == 0 {
					return nil, nil
				}
				waiter = h.waits.register(h.waitKey(command), folders, h.folderAccounts(command, folders))
				changed, changeErr := h.changedFolders(command, command.state, folders, nil)
				if changeErr != nil {
					return nil, changeErr
				}
				idle = len(changed) == 0
				return nil, nil
			})
			switch {
			case idle && err == nil:
				h.waitForChanges(command, waiter, wait, nil)
			case waiter != nil:
				h.waits.unregister(waiter)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return h.withState(command, r, h.sync)
}

func syncWaitInterval(request *Node) (time.Duration, *Node) {
	if text := childText(request, "Wait"); text != "" {
		minutes, err := strconv.Atoi(text)
		if err != nil || minutes < 1 || minutes > 59 {
			return 0, E(0, "Sync", T(0, "Status", syncStatusInvalidWait), T(0, "Limit", "59"))
		}
		return time.Duration(minutes) * time.Minute, nil
	}
	if text := childText(request, "HeartbeatInterval"); text != "" {
		seconds, err := strconv.Atoi(text)
		if err != nil || seconds < minHeartbeatSeconds || seconds > maxHeartbeatSeconds {
			limit := strconv.Itoa(maxHeartbeatSeconds)
			if err == nil && seconds < minHeartbeatSeconds {
				limit = strconv.Itoa(minHeartbeatSeconds)
			}
			return 0, E(0, "Sync", T(0, "Status", syncStatusInvalidWait), T(0, "Limit", limit))
		}
		return time.Duration(seconds) * time.Second, nil
	}
	return 0, nil
}

// syncContext carries per-request lookups shared by every collection.
type syncContext struct {
	trashID string
	trashOK bool
}

func (h *Handler) sync(command *commandContext) (*Node, error) {
	state := command.state
	request := command.request
	if request == nil || request.Child("Collections") == nil {
		// An empty Sync repeats the previous one (MS-ASCMD 2.2.3.176).
		cached, err := Decode(state.SyncRequest)
		if len(state.SyncRequest) == 0 || err != nil {
			return E(0, "Sync", T(0, "Status", syncStatusIncomplete)), nil
		}
		for _, collection := range cached.Descendant("Collections").ChildrenNamed("Collection") {
			if folderID, decodeErr := decodeServerID(childText(collection, "CollectionId"), "f:"); decodeErr == nil {
				if key := collection.Child("SyncKey"); key != nil {
					key.Text = state.CollectionKeys[folderID]
				}
			}
		}
		request = cached
	} else if len(request.Descendant("Collections").ChildrenNamed("Collection")) > 0 {
		h.cacheSyncRequest(state, request)
	}
	globalWindow, _ := strconv.Atoi(childText(request, "WindowSize"))
	response := E(0, "Sync", E(0, "Collections"))
	shared := &syncContext{}
	remaining := maxWindowSize
	if globalWindow > 0 {
		remaining = min(globalWindow, maxWindowSize)
	}
	applied := false
	for _, collection := range request.Child("Collections").ChildrenNamed("Collection") {
		result, used, err := h.syncCollection(command, shared, collection, remaining)
		if err != nil {
			if !applied {
				return nil, err
			}
			// Earlier collections already changed storage: failing the whole
			// request would discard their state and make the retry apply
			// their commands twice. This collection reports a server error
			// and keeps its key.
			folderID, _ := decodeServerID(childText(collection, "CollectionId"), "f:")
			result = collectionResult(command, model.Folder{}, childText(collection, "CollectionId"), state.CollectionKeys[folderID], syncStatusServerError)
		}
		if collection.Child("Commands") != nil {
			applied = true
		}
		remaining = max(remaining-used, 1)
		response.Children[0].Children = append(response.Children[0].Children, result)
	}
	return response, nil
}

// cacheSyncRequest keeps the collection list and options of the request,
// without client commands, for a later empty Sync.
func (h *Handler) cacheSyncRequest(state *DeviceState, request *Node) {
	clone := cloneNode(request)
	for _, collection := range clone.Descendant("Collections").ChildrenNamed("Collection") {
		collection.Children = slices.DeleteFunc(collection.Children, func(child *Node) bool { return child.Tag == "Commands" })
	}
	if encoded, err := Encode(clone); err == nil && len(encoded) <= maxCachedSyncRequestBytes {
		state.SyncRequest = encoded
	}
}

func cloneNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	clone := &Node{Page: node.Page, Tag: node.Tag, Text: node.Text, Opaque: slices.Clone(node.Opaque)}
	for _, child := range node.Children {
		clone.Children = append(clone.Children, cloneNode(child))
	}
	return clone
}

func collectionResult(command *commandContext, folder model.Folder, collectionID, key, status string) *Node {
	result := E(0, "Collection")
	if !command.version(14, 0) && folder.ID != "" {
		result.Children = append(result.Children, T(0, "Class", easClass(folder.Type)))
	}
	result.Children = append(result.Children, T(0, "SyncKey", key), T(0, "CollectionId", collectionID), T(0, "Status", status))
	return result
}

func (h *Handler) syncCollection(command *commandContext, shared *syncContext, collection *Node, budget int) (*Node, int, error) {
	state := command.state
	collectionID := childText(collection, "CollectionId")
	requestKey := childText(collection, "SyncKey")
	folderID, err := decodeServerID(collectionID, "f:")
	if err != nil {
		return collectionResult(command, model.Folder{}, collectionID, "0", syncStatusHierarchy), 0, nil
	}
	folder, err := h.space.GetFolder(command.ctx, command.access, folderID)
	if err != nil || !easSyncable(folder.Type) {
		if err != nil && (service.IsTemporarilyUnavailable(err) || errors.Is(err, model.ErrQuotaExceeded)) {
			return nil, 0, err
		}
		return collectionResult(command, model.Folder{}, collectionID, "0", syncStatusHierarchy), 0, nil
	}
	if options, present := parseSyncOptions(collection, folder.Type); present {
		state.CollectionOptions[folderID] = options
	}
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return nil, 0, errors.New("folder space does not provide incremental changes")
	}
	replay := false
	switch {
	case requestKey == "0":
		options := state.CollectionOptions[folderID]
		state.resetCollection(folderID)
		state.CollectionOptions[folderID] = options
		// A paging enumeration takes its watermark with the first window.
		watermark := ""
		if _, paging := h.space.(service.FolderItemPager); !paging {
			var stateErr error
			if watermark, stateErr = reader.CurrentChangeState(command.ctx, command.access, service.ChangeScope{FolderID: folderID, Object: service.ChangeObjectItem}); stateErr != nil {
				return nil, 0, stateErr
			}
		}
		key, keyErr := nextKey()
		if keyErr != nil {
			return nil, 0, keyErr
		}
		state.CollectionKeys[folderID] = key
		state.CollectionInitialStates[folderID] = watermark
		state.CollectionOffsets[folderID] = 0
		state.setCursor(folderID, "", time.Now().UTC())
		return collectionResult(command, folder, collectionID, key, syncStatusOK), 0, nil
	case requestKey != "" && requestKey == state.CollectionKeys[folderID]:
		state.PreviousCollections[folderID] = state.snapshot(folderID)
	case requestKey != "" && requestKey == state.PreviousCollections[folderID].Key:
		// The client lost the last response: replay from the state its key
		// names, and recognize the Adds it already sent.
		state.restore(folderID, state.PreviousCollections[folderID])
		replay = true
	default:
		return collectionResult(command, folder, collectionID, "0", syncStatusInvalidKey), 0, nil
	}
	options := state.CollectionOptions[folderID]
	window := budget
	if size, sizeErr := strconv.Atoi(childText(collection, "WindowSize")); sizeErr == nil && size > 0 {
		window = min(size, budget)
	} else if childText(collection, "WindowSize") == "" && budget == maxWindowSize {
		window = defaultWindowSize
	}
	window = max(min(window, maxWindowSize), 1)
	getChanges := true
	if node := collection.Child("GetChanges"); node != nil && node.Text == "0" {
		getChanges = false
	}

	// Server changes are read before the client's commands are applied, so
	// a conflicting client edit is recognized and the client's own effects
	// are not reported back to it.
	var changes []pendingChange
	more := false
	var nextState string
	initial := false
	if getChanges {
		changes, more, nextState, initial, err = h.pendingCollectionChanges(command, folder, options, window)
		if errors.Is(err, service.ErrChangeStateExpired) {
			state.resetCollection(folderID)
			return collectionResult(command, folder, collectionID, "0", syncStatusInvalidKey), 0, nil
		}
		if err != nil {
			return nil, 0, err
		}
	}
	serverChanged := map[string]bool{}
	for _, change := range changes {
		serverChanged[change.id] = true
	}
	responses, clientTouched, err := h.applyClientCommands(command, shared, folder, collection, options, serverChanged, replay)
	if err != nil {
		return nil, 0, err
	}
	if getChanges {
		if initial {
			state.advanceInitial(folderID, nextState, more)
		} else {
			state.CollectionStates[folderID] = nextState
		}
	}
	commands := E(0, "Commands")
	for _, change := range changes {
		if clientTouched[change.id] {
			continue
		}
		switch change.operation {
		case "Delete":
			commands.Children = append(commands.Children, E(0, "Delete", T(0, "ServerId", encodeServerID("i:", change.id))))
		default:
			commands.Children = append(commands.Children, E(0, change.operation, T(0, "ServerId", encodeServerID("i:", change.item.ID)), h.applicationData(command, folder, change.item, options)))
		}
	}
	key, err := nextKey()
	if err != nil {
		return nil, 0, err
	}
	state.CollectionKeys[folderID] = key
	result := collectionResult(command, folder, collectionID, key, syncStatusOK)
	if len(responses.Children) > 0 {
		result.Children = append(result.Children, responses)
	}
	if more {
		result.Children = append(result.Children, E(0, "MoreAvailable"))
	}
	if len(commands.Children) > 0 {
		result.Children = append(result.Children, commands)
	}
	return result, len(commands.Children), nil
}

// pendingChange is one server-side change to report.
type pendingChange struct {
	operation string // Add, Change or Delete
	id        string
	item      model.Item
}

// pendingCollectionChanges returns the next window of server changes: the
// initial enumeration while it is in progress, then the change journal.
func (h *Handler) pendingCollectionChanges(command *commandContext, folder model.Folder, options SyncOptions, window int) ([]pendingChange, bool, string, bool, error) {
	state := command.state
	if initialState, initial := state.CollectionInitialStates[folder.ID]; initial {
		changes, more, err := h.initialWindow(command, folder, options, window)
		// The first window may have moved the watermark up to its snapshot.
		if current, ok := state.CollectionInitialStates[folder.ID]; ok {
			initialState = current
		}
		return changes, more, initialState, true, err
	}
	reader := h.space.(service.FolderChangeReader)
	scope := service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem}
	journalState := state.CollectionStates[folder.ID]
	if journalState == "" {
		current, err := reader.CurrentChangeState(command.ctx, command.access, scope)
		return nil, false, current, false, err
	}
	page, err := reader.ListChanges(command.ctx, command.access, scope, journalState, window)
	if err != nil {
		return nil, false, "", false, err
	}
	echoes := newEchoSet(state.CollectionEchoes[folder.ID])
	order := echoes.pendingIDs(page, folder.ID)
	created := map[string]bool{}
	uids := map[string]uint32{}
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.Object != "" && change.Object != service.ChangeObjectItem || echoes.suppresses(change, folder.ID) {
				continue
			}
			if change.FolderID == folder.ID && change.UID != 0 {
				uids[change.ID] = change.UID
			}
			if change.Operation == service.ChangeCreate || change.Operation == service.ChangeRestore || change.Operation == service.ChangeMove && change.PreviousFolderID != folder.ID {
				created[change.ID] = true
			}
		}
	}
	state.CollectionEchoes[folder.ID] = forgetEchoes(state.CollectionEchoes[folder.ID], page, folder.ID)
	if len(state.CollectionEchoes[folder.ID]) == 0 {
		delete(state.CollectionEchoes, folder.ID)
	}
	changes := make([]pendingChange, 0, len(order))
	for _, id := range order {
		item, getErr := h.changedItem(command, folder.ID, id, uids[id])
		present := getErr == nil && item.FolderID == folder.ID && item.TrashedAt.IsZero() && representable(folder, item)
		switch {
		case present && created[id]:
			changes = append(changes, pendingChange{operation: "Add", id: id, item: item})
		case present:
			changes = append(changes, pendingChange{operation: "Change", id: id, item: item})
		case !created[id]:
			changes = append(changes, pendingChange{operation: "Delete", id: id})
		}
	}
	return changes, page.HasMoreChanges, page.NewState, false, nil
}

// changedItem reads an item named by a journal record of folderID.
//
// GetItem alone cannot establish that the item is gone. The routed account
// space resolves an item ID through a system-wide location index written
// only after the account commit, and that commit already made the journal
// record visible and woke waiting Ping and Sync requests. A brand-new item
// read in that window is reported as missing; skipping it would advance the
// sync key past its creation. The record's folder and UID address the item
// in the account store that holds the journal, so that lookup is never
// behind the record.
func (h *Handler) changedItem(command *commandContext, folderID, id string, uid uint32) (model.Item, error) {
	item, err := h.space.GetItem(command.ctx, command.access, id)
	if !errors.Is(err, store.ErrNotFound) || uid == 0 {
		return item, err
	}
	item, err = h.space.GetItemByUID(command.ctx, command.access, folderID, uid)
	if err == nil && item.ID != id {
		return model.Item{}, store.ErrNotFound
	}
	return item, err
}

// initialWindow pages through the folder. With a paging FolderSpace it walks
// UIDs downwards from the newest item, as Exchange sends newest mail first;
// items that arrive meanwhile get higher UIDs and reach the device through
// the change journal. Otherwise it pages in item-ID order. Either way a
// cursor, not an offset, survives deletions between windows.
func (h *Handler) initialWindow(command *commandContext, folder model.Folder, options SyncOptions, window int) ([]pendingChange, bool, error) {
	state := command.state
	cursor, startedAt := state.cursor(folder.ID)
	cutoff := time.Time{}
	if folder.Type == model.FolderTypeMail {
		cutoff = filterCutoff(options.FilterType, time.Now().UTC())
	}
	if pager, ok := h.space.(service.FolderItemPager); ok && (cursor == "" || strings.HasPrefix(cursor, "uid:")) {
		before, _ := strconv.ParseUint(strings.TrimPrefix(cursor, "uid:"), 10, 32)
		if cursor == "" {
			// Take the journal watermark with the first page: items that
			// arrived since SyncKey 0 are then enumerated, not also replayed
			// from the journal as duplicate Adds.
			watermark, err := h.space.(service.FolderChangeReader).CurrentChangeState(command.ctx, command.access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem})
			if err != nil {
				return nil, false, err
			}
			state.CollectionInitialStates[folder.ID] = watermark
		}
		var changes []pendingChange
		for pages := 0; len(changes) < window && pages < maxInitialPages; pages++ {
			page, err := pager.ListItemPage(command.ctx, command.access, folder.ID, service.ItemPageQuery{BeforeUID: uint32(before), Limit: window - len(changes), IncludeData: true})
			if err != nil {
				return nil, false, err
			}
			older := !cutoff.IsZero() && len(page.Items) > 0
			for _, item := range page.Items {
				if older && !item.InternalDate.Before(cutoff) {
					older = false
				}
				if item.TrashedAt.IsZero() && (cutoff.IsZero() || !item.InternalDate.Before(cutoff)) && representable(folder, item) && withinFilter(folder, item, options) {
					changes = append(changes, pendingChange{operation: "Add", id: item.ID, item: item})
				}
			}
			before = uint64(page.NextBeforeUID)
			// UIDs follow arrival, so once a whole page predates the
			// FilterType window the rest of the folder does too.
			if page.NextBeforeUID == 0 || len(page.Items) == 0 || older {
				before = 0
				break
			}
		}
		state.pendingCursor = "uid:" + strconv.FormatUint(before, 10)
		return changes, before != 0, nil
	}
	query := service.ItemQuery{MetadataOnly: true, RequireRead: true, Since: cutoff}
	items, err := h.space.ListItems(command.ctx, command.access, folder.ID, query)
	if err != nil {
		return nil, false, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	start := sort.Search(len(items), func(i int) bool { return items[i].ID > cursor })
	var changes []pendingChange
	index := start
	for ; index < len(items) && len(changes) < window; index++ {
		summary := items[index]
		if !startedAt.IsZero() && summary.CreatedAt.After(startedAt) {
			continue
		}
		item, getErr := h.space.GetItem(command.ctx, command.access, summary.ID)
		if getErr != nil || !representable(folder, item) || !withinFilter(folder, item, options) {
			continue
		}
		changes = append(changes, pendingChange{operation: "Add", id: item.ID, item: item})
	}
	more := index < len(items)
	if index > start {
		state.pendingCursor = items[index-1].ID
	} else {
		state.pendingCursor = cursor
	}
	return changes, more, nil
}

// representable reports whether an item converts to its folder's class.
func representable(folder model.Folder, item model.Item) bool {
	switch folder.Type {
	case model.FolderTypeCalendar:
		return parseCalendarEvent(item.Data) != nil
	case model.FolderTypeTasks:
		return calendar.IsTask(item.Data)
	case model.FolderTypeContacts:
		return decodeCard(item.Data) != nil
	}
	return true
}

// withinFilter applies the calendar FilterType to recurring-aware end times.
func withinFilter(folder model.Folder, item model.Item, options SyncOptions) bool {
	cutoff := filterCutoff(options.FilterType, time.Now().UTC())
	if cutoff.IsZero() {
		return true
	}
	switch folder.Type {
	case model.FolderTypeCalendar:
		event := parseCalendarEvent(item.Data)
		if event == nil || event.master.Props.Get("RRULE") != nil {
			return true
		}
		_, end, _, _ := eventTimes(event.master, time.UTC)
		return end.IsZero() || end.After(cutoff)
	case model.FolderTypeTasks:
		if options.FilterType == 8 {
			task, err := calendar.ProjectTask(item.Data)
			return err != nil || !task.Completed
		}
	}
	return true
}

func (h *Handler) applicationData(command *commandContext, folder model.Folder, item model.Item, options SyncOptions) *Node {
	switch folder.Type {
	case model.FolderTypeCalendar:
		return h.calendarData(command, item, options)
	case model.FolderTypeContacts:
		return h.contactData(command, item, options)
	case model.FolderTypeTasks:
		return h.taskData(command, item, options)
	}
	return h.emailData(command, folder, item, options)
}

func (h *Handler) trashFolder(command *commandContext, shared *syncContext) (string, bool) {
	if shared.trashOK || shared.trashID != "" {
		return shared.trashID, shared.trashID != ""
	}
	shared.trashOK = true
	folders, err := h.space.ListFolders(command.ctx, command.access, service.FolderQuery{Type: model.FolderTypeMail})
	if err != nil {
		return "", false
	}
	for _, folder := range folders {
		if folder.UserID == command.userID && strings.EqualFold(strings.TrimPrefix(folder.SpecialUse, "\\"), model.SpecialUseTrash) {
			shared.trashID = folder.ID
			return folder.ID, true
		}
	}
	return "", false
}

// applyClientCommands applies Add, Change, Delete and Fetch and returns the
// Responses element and the items the client itself touched.
func (h *Handler) applyClientCommands(command *commandContext, shared *syncContext, folder model.Folder, collection *Node, options SyncOptions, serverChanged map[string]bool, replay bool) (*Node, map[string]bool, error) {
	state := command.state
	responses := E(0, "Responses")
	touched := map[string]bool{}
	commands := collection.Child("Commands")
	if commands == nil {
		return responses, touched, nil
	}
	deletesAsMoves := true
	if node := collection.Child("DeletesAsMoves"); node != nil && node.Text == "0" {
		deletesAsMoves = false
	}
	previousClientIDs := state.CollectionClientIDs[folder.ID]
	clientIDs := map[string]string{}
	// echo records the device's own change. The mod-sequence the device's
	// mutation returned bounds which journal entries are its own; reading
	// the item again could pick up another client's later edit and hide it.
	echo := func(id string, modSeq uint64, removed bool) {
		touched[id] = true
		if beforeEchoHook != nil {
			beforeEchoHook(id)
		}
		state.addEcho(folder.ID, Echo{ID: id, ModSeq: modSeq, Removed: removed})
	}
	for _, entry := range commands.Children {
		serverID := childText(entry, "ServerId")
		switch entry.Tag {
		case "Add":
			clientID := childText(entry, "ClientId")
			if existing := previousClientIDs[clientID]; replay && clientID != "" && existing != "" {
				clientIDs[clientID] = existing
				add := E(0, "Add", T(0, "ClientId", clientID))
				if existing != sentClientID {
					add.Children = append(add.Children, T(0, "ServerId", existing))
					// The item is the device's own, although the restored
					// echoes of the replayed key predate its creation.
					if id, err := decodeServerID(existing, "i:"); err == nil {
						var modSeq uint64
						if item, err := h.space.GetItem(command.ctx, command.access, id); err == nil {
							modSeq = item.ModSeq
						}
						echo(id, modSeq, false)
					}
				}
				add.Children = append(add.Children, T(0, "Status", syncStatusOK))
				responses.Children = append(responses.Children, add)
				continue
			}
			item, status, err := h.createFromClient(command, folder, entry.Child("ApplicationData"))
			if err != nil {
				// Earlier commands are already applied; report this one as a
				// server error and keep the request's state.
				status = syncStatusServerError
			}
			add := E(0, "Add", T(0, "ClientId", clientID))
			if status == syncStatusSent {
				// A draft sent on creation never exists on the server; the
				// marker keeps a replayed request from sending it again.
				status = syncStatusOK
				if clientID != "" {
					clientIDs[clientID] = sentClientID
				}
			} else if status == syncStatusOK {
				serverID := encodeServerID("i:", item.ID)
				clientIDs[clientID] = serverID
				add.Children = append(add.Children, T(0, "ServerId", serverID))
				echo(item.ID, item.ModSeq, false)
			}
			add.Children = append(add.Children, T(0, "Status", status))
			responses.Children = append(responses.Children, add)
		case "Change":
			id, item, status := h.clientItem(command, folder, serverID)
			if status == syncStatusOK {
				if serverChanged[id] && !options.ClientWins {
					// Server wins: the pending server version is sent instead.
					continue
				}
				changed, changeStatus, err := h.changeFromClient(command, folder, item, entry.Child("ApplicationData"))
				status = changeStatus
				if err != nil {
					status = syncStatusServerError
				}
				if status == syncStatusOK {
					echo(id, changed.ModSeq, false)
				}
				if status == syncStatusSent {
					status = syncStatusOK
				}
			}
			if status != syncStatusOK {
				responses.Children = append(responses.Children, E(0, "Change", T(0, "ServerId", serverID), T(0, "Status", status)))
			}
		case "Delete", "SoftDelete":
			id, _, status := h.clientItem(command, folder, serverID)
			if status == syncStatusOK {
				if serverChanged[id] && !options.ClientWins && entry.Tag == "Delete" && folder.Type != model.FolderTypeMail {
					continue
				}
				if entry.Tag == "SoftDelete" {
					// Outside the client's filter window; nothing to delete.
					touched[id] = true
					continue
				}
				var err error
				trashID, hasTrash := h.trashFolder(command, shared)
				if deletesAsMoves && folder.Type == model.FolderTypeMail && hasTrash && trashID != folder.ID {
					_, err = h.space.MoveItem(command.ctx, command.access, id, trashID, "")
				} else {
					err = h.space.DeleteItem(command.ctx, command.access, id)
				}
				switch {
				case err == nil:
					echo(id, 0, true)
				case errors.Is(err, store.ErrNotFound):
					status = syncStatusNotFound
				default:
					status = syncStatusServerError
				}
			}
			if status != syncStatusOK {
				responses.Children = append(responses.Children, E(0, "Delete", T(0, "ServerId", serverID), T(0, "Status", status)))
			}
		case "Fetch":
			_, item, status := h.clientItem(command, folder, serverID)
			fetch := E(0, "Fetch", T(0, "ServerId", serverID), T(0, "Status", status))
			if status == syncStatusOK {
				full := options
				full.BodyPreferences = untruncated(options.BodyPreferences)
				fetch.Children = append(fetch.Children, h.applicationData(command, folder, item, full))
			}
			responses.Children = append(responses.Children, fetch)
		}
	}
	state.CollectionClientIDs[folder.ID] = clientIDs
	if len(clientIDs) == 0 {
		delete(state.CollectionClientIDs, folder.ID)
	}
	return responses, touched, nil
}

func untruncated(preferences []BodyPreference) []BodyPreference {
	result := slices.Clone(preferences)
	for index := range result {
		result[index].TruncationSize = 0
		result[index].AllOrNone = false
	}
	return result
}

// clientItem resolves a client ServerId to an item of this collection.
func (h *Handler) clientItem(command *commandContext, folder model.Folder, serverID string) (string, model.Item, string) {
	id, err := decodeServerID(serverID, "i:")
	if err != nil {
		return "", model.Item{}, syncStatusNotFound
	}
	item, err := h.space.GetItem(command.ctx, command.access, id)
	if err != nil || item.FolderID != folder.ID || !item.TrashedAt.IsZero() {
		return id, model.Item{}, syncStatusNotFound
	}
	return id, item, syncStatusOK
}

func (h *Handler) createFromClient(command *commandContext, folder model.Folder, data *Node) (model.Item, string, error) {
	if data == nil {
		return model.Item{}, syncStatusProtocolError, nil
	}
	var payload []byte
	var headers map[string]string
	var err error
	switch folder.Type {
	case model.FolderTypeCalendar:
		payload, headers, err = h.calendarFromEAS(command, nil, data)
	case model.FolderTypeContacts:
		payload, headers, err = contactFromEAS(nil, data)
	case model.FolderTypeTasks:
		payload, headers, err = h.taskFromEAS(command, nil, data)
	default:
		if !command.version(16, 0) || !folderIsDrafts(folder) {
			return model.Item{}, syncStatusConversion, nil
		}
		payload, headers, err = h.draftFromEAS(command, nil, data)
		if err == nil && data.Child("Send") != nil {
			status, sendErr := h.sendDraft(command, payload)
			return model.Item{}, status, sendErr
		}
	}
	if err != nil {
		return model.Item{}, syncStatusConversion, nil
	}
	input := service.ItemInput{Data: payload, Headers: headers}
	if folder.Type == model.FolderTypeMail {
		input.Flags = []string{model.FlagSeen, model.FlagDraft}
		input.InternalDate = time.Now().UTC()
	}
	item, err := h.space.CreateItem(command.ctx, command.access, folder.ID, input)
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return model.Item{}, "", err
		}
		if errors.Is(err, model.ErrQuotaExceeded) {
			return model.Item{}, syncStatusServerError, nil
		}
		return model.Item{}, syncStatusServerError, nil
	}
	return item, syncStatusOK, nil
}

func (h *Handler) changeFromClient(command *commandContext, folder model.Folder, item model.Item, data *Node) (model.Item, string, error) {
	if data == nil {
		return item, syncStatusOK, nil
	}
	var payload []byte
	var headers map[string]string
	var err error
	switch folder.Type {
	case model.FolderTypeCalendar:
		payload, headers, err = h.calendarFromEAS(command, item.Data, data)
	case model.FolderTypeContacts:
		payload, headers, err = contactFromEAS(item.Data, data)
	case model.FolderTypeTasks:
		payload, headers, err = h.taskFromEAS(command, item.Data, data)
	default:
		return h.changeMail(command, folder, item, data)
	}
	if err != nil {
		return model.Item{}, syncStatusConversion, nil
	}
	updated, err := h.space.UpdateItem(command.ctx, command.access, item.ID, payload, headers)
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return model.Item{}, "", err
		}
		return model.Item{}, syncStatusServerError, nil
	}
	return updated, syncStatusOK, nil
}

// changeMail applies the mail properties a client may change: Read, Flag,
// and, for 16.0 drafts, the whole message.
func (h *Handler) changeMail(command *commandContext, folder model.Folder, item model.Item, data *Node) (model.Item, string, error) {
	if command.version(16, 0) && folderIsDrafts(folder) && (data.Child("Subject") != nil || data.Child("Body") != nil || data.Child("To") != nil) {
		payload, headers, err := h.draftFromEAS(command, item.Data, data)
		if err != nil {
			return model.Item{}, syncStatusConversion, nil
		}
		updated, err := h.space.UpdateItem(command.ctx, command.access, item.ID, payload, headers)
		if err != nil {
			if service.IsTemporarilyUnavailable(err) {
				return model.Item{}, "", err
			}
			return model.Item{}, syncStatusServerError, nil
		}
		item = updated
		item.Data = payload
	}
	if command.version(16, 0) && folderIsDrafts(folder) && data.Child("Send") != nil {
		status, err := h.sendDraft(command, item.Data)
		if err != nil || status != syncStatusSent {
			return model.Item{}, status, err
		}
		// The message is on its way: a failure to remove the draft must not
		// fail the request, or the device would send it again.
		_ = h.space.DeleteItem(command.ctx, command.access, item.ID)
		return model.Item{}, syncStatusSent, nil
	}
	if data.Child("Subject") != nil && data.Child("Read") == nil && data.Child("Flag") == nil {
		return item, syncStatusOK, nil
	}
	flags := item.Flags
	if read := data.Child("Read"); read != nil {
		flags = setFlag(flags, model.FlagSeen, read.Text == "1")
	}
	if flag := data.Child("Flag"); flag != nil {
		flags = setFlag(flags, model.FlagFlagged, childText(flag, "Status") == "2")
	}
	if slices.Equal(flags, item.Flags) {
		return item, syncStatusOK, nil
	}
	updated, err := h.space.SetFlags(command.ctx, command.access, item.ID, flags)
	if err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return model.Item{}, "", err
		}
		return model.Item{}, syncStatusServerError, nil
	}
	return updated, syncStatusOK, nil
}

// sendDraft submits a 16.0 draft the client marked with Send.
func (h *Handler) sendDraft(command *commandContext, payload []byte) (string, error) {
	if h.submit == nil {
		return syncStatusServerError, nil
	}
	prepared, err := h.prepareOutgoing(command, payload)
	if err != nil {
		return syncStatusConversion, nil
	}
	if err := h.submit(command.ctx, command.userID, prepared); err != nil {
		if service.IsTemporarilyUnavailable(err) {
			return "", err
		}
		return syncStatusServerError, nil
	}
	return syncStatusSent, nil
}

// cursor returns the initial-enumeration position of a collection.
func (s *DeviceState) cursor(folderID string) (string, time.Time) {
	position := s.CollectionCursors[folderID]
	return position.After, position.StartedAt
}

func (s *DeviceState) setCursor(folderID, after string, startedAt time.Time) {
	if s.CollectionCursors == nil {
		s.CollectionCursors = map[string]EnumerationCursor{}
	}
	s.CollectionCursors[folderID] = EnumerationCursor{After: after, StartedAt: startedAt}
}

// advanceInitial moves the enumeration on, or ends it and hands over to
// the change journal from the watermark taken when it began.
func (s *DeviceState) advanceInitial(folderID, watermark string, more bool) {
	if more {
		_, startedAt := s.cursor(folderID)
		s.setCursor(folderID, s.pendingCursor, startedAt)
		return
	}
	s.CollectionStates[folderID] = watermark
	delete(s.CollectionInitialStates, folderID)
	delete(s.CollectionOffsets, folderID)
	delete(s.CollectionCursors, folderID)
}
