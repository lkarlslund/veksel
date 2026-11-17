// Package ews implements the Exchange Web Services SOAP protocol over Veksel'
// generic typed-folder abstraction.
package ews

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	soapNS = "http://schemas.xmlsoap.org/soap/envelope/"
	msgNS  = "http://schemas.microsoft.com/exchange/services/2006/messages"
	typeNS = "http://schemas.microsoft.com/exchange/services/2006/types"
)

var errEWSInvalidProperty = errors.New("invalid EWS property request")

type Submit func(context.Context, string, []byte) error

type Handler struct {
	space          service.FolderSpace
	authenticate   protocolauth.AuthenticateFunc
	maxRequest     int64
	submit         Submit
	freeBusy       func(context.Context, service.AccessContext, string, time.Time, time.Time) ([]BusyPeriod, bool, error)
	directory      func(context.Context, string, string, int) ([]DirectoryEntry, error)
	profile        func(context.Context, string) (Profile, error)
	respond        func(context.Context, service.AccessContext, string, string) error
	outOfOffice    func(context.Context, string) (OutOfOffice, error)
	setOutOfOffice func(context.Context, string, OutOfOffice) error
	// ctx ends at shutdown, closing streaming notification connections.
	ctx                context.Context
	subscriptions      *subscriptions
	streamingKeepalive time.Duration
	// streamingMinute is the unit of ConnectionTimeout; tests shorten it.
	streamingMinute time.Duration
}

type Config struct {
	Space           service.FolderSpace
	Authenticate    protocolauth.AuthenticateFunc
	MaxRequestBytes int64
	Submit          Submit
	// FreeBusy reports an address's busy periods for GetUserAvailability,
	// with known=false when the requester may not see them.
	FreeBusy func(ctx context.Context, access service.AccessContext, address string, start, end time.Time) ([]BusyPeriod, bool, error)
	// Directory searches the global address list for ResolveNames.
	Directory func(ctx context.Context, userID, query string, limit int) ([]DirectoryEntry, error)
	// Profile names the account's addresses, display name and time zone,
	// which tell its own meetings from invitations.
	Profile func(ctx context.Context, userID string) (Profile, error)
	// Respond answers a meeting invitation (an item ID with ACCEPTED,
	// TENTATIVE or DECLINED) through the scheduling service.
	Respond func(ctx context.Context, access service.AccessContext, itemID, partStat string) error
	// OutOfOffice and SetOutOfOffice read and write the vacation responder.
	OutOfOffice    func(ctx context.Context, userID string) (OutOfOffice, error)
	SetOutOfOffice func(ctx context.Context, userID string, oof OutOfOffice) error
	// Context ends when shutdown begins: streaming notification
	// connections close and the in-memory subscriptions are dropped. Nil
	// means context.Background.
	Context context.Context
}

func New(cfg Config) (*Handler, error) {
	if cfg.Space == nil || cfg.Authenticate == nil {
		return nil, errors.New("EWS requires folder space and authenticator")
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 10 << 20
	}
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	h := &Handler{
		space: cfg.Space, authenticate: cfg.Authenticate, maxRequest: cfg.MaxRequestBytes, submit: cfg.Submit, freeBusy: cfg.FreeBusy, directory: cfg.Directory,
		profile: cfg.Profile, respond: cfg.Respond, outOfOffice: cfg.OutOfOffice, setOutOfOffice: cfg.SetOutOfOffice,
		ctx: ctx, subscriptions: newSubscriptions(), streamingKeepalive: defaultStreamingKeepalive, streamingMinute: time.Minute,
	}
	remove := func() {}
	if notifier, ok := cfg.Space.(service.FolderChangeNotifier); ok {
		remove = notifier.OnChangesCommitted(h.subscriptions.changesCommitted)
	}
	context.AfterFunc(ctx, func() {
		remove()
		h.subscriptions.clear()
	})
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		h.unauthorized(w)
		return
	}
	userID, err := h.authenticate(r.Context(), username, password)
	if err != nil {
		h.unauthorized(w)
		return
	}
	root, err := decodeXML(http.MaxBytesReader(w, r.Body, h.maxRequest))
	if err != nil {
		h.writeFault(w, http.StatusBadRequest, "ErrorInvalidRequest", "Malformed SOAP request")
		return
	}
	body := root.child("Body")
	if body == nil || len(body.Children) != 1 {
		h.writeFault(w, http.StatusBadRequest, "ErrorInvalidRequest", "SOAP Body must contain one operation")
		return
	}
	access := service.UserAccess(userID, "ews")
	if body.Children[0].Name.Local == "GetStreamingEvents" {
		h.getStreamingEvents(w, r, access, body.Children[0])
		return
	}
	ctx := withRequestInfo(r.Context(), parseRequestInfo(root.child("Header")))
	response, err := h.dispatch(ctx, access, body.Children[0])
	if err != nil {
		code, message := ewsError(err)
		h.writeFault(w, http.StatusOK, code, message)
		return
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-EWS-Server-Version", "Exchange2016")
	_, _ = io.WriteString(w, envelope(response))
}

func (h *Handler) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Veksel EWS"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func (h *Handler) dispatch(ctx context.Context, access service.AccessContext, operation *node) (string, error) {
	switch operation.Name.Local {
	case "GetFolder":
		return h.getFolder(ctx, access, operation)
	case "FindFolder":
		return h.findFolder(ctx, access, operation)
	case "CreateFolder":
		return h.createFolder(ctx, access, operation)
	case "MoveFolder":
		return h.moveFolder(ctx, access, operation)
	case "DeleteFolder":
		return h.deleteFolder(ctx, access, operation)
	case "EmptyFolder":
		return h.emptyFolder(ctx, access, operation)
	case "FindItem":
		return h.findItem(ctx, access, operation)
	case "GetItem":
		return h.getItem(ctx, access, operation)
	case "CreateItem":
		return h.createItem(ctx, access, operation)
	case "UpdateItem":
		return h.updateItem(ctx, access, operation)
	case "SendItem":
		return h.sendItem(ctx, access, operation)
	case "MoveItem", "CopyItem":
		return h.moveItem(ctx, access, operation)
	case "DeleteItem":
		return h.deleteItem(ctx, access, operation)
	case "SyncFolderHierarchy":
		return h.syncFolderHierarchy(ctx, access, operation)
	case "SyncFolderItems":
		return h.syncFolderItems(ctx, access, operation)
	case "GetUserAvailabilityRequest":
		return h.getUserAvailability(ctx, access, operation)
	case "ResolveNames":
		return h.resolveNames(ctx, access, operation)
	case "GetUserOofSettingsRequest":
		return h.getUserOofSettings(ctx, access, operation)
	case "SetUserOofSettingsRequest":
		return h.setUserOofSettings(ctx, access, operation)
	case "Subscribe":
		return h.subscribe(ctx, access, operation)
	case "GetEvents":
		return h.getEvents(ctx, access, operation)
	case "Unsubscribe":
		return h.unsubscribe(ctx, access, operation)
	case "GetAttachment":
		return h.getAttachment(ctx, access, operation)
	case "CreateAttachment":
		return h.createAttachment(ctx, access, operation)
	case "DeleteAttachment":
		return h.deleteAttachment(ctx, access, operation)
	default:
		return "", fmt.Errorf("unsupported EWS operation %s", operation.Name.Local)
	}
}

func (h *Handler) getFolder(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := folderIDs(op)
	if len(ids) == 0 {
		return "", errors.New("folder ID is required")
	}
	all, err := h.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return "", err
	}
	messages := make([]responseMessage, 0, len(ids))
	for _, id := range ids {
		folder, err := h.resolveFolder(ctx, access, id)
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:Folders>` + h.folderXMLCounted(ctx, access, folder, all) + `</m:Folders>`})
	}
	return responses("GetFolder", messages), nil
}

func (h *Handler) findFolder(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	all, err := h.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return "", err
	}
	parentIDs := folderIDs(op)
	parent := ""
	if len(parentIDs) > 0 {
		resolved, err := h.resolveFolder(ctx, access, parentIDs[0])
		if err != nil {
			return responses("FindFolder", []responseMessage{{err: err}}), nil
		}
		if resolved.ID != rootFolderID {
			parent = resolved.ID
		}
	}
	deep := strings.EqualFold(op.attr("Traversal"), "Deep")
	visible := visibleFolders(all)
	byID := make(map[string]model.Folder, len(visible))
	for _, folder := range visible {
		byID[folder.ID] = folder
	}
	var folders strings.Builder
	count := 0
	for _, folder := range visible {
		if folder.ParentID != parent && !(deep && isDescendant(folder, parent, byID)) {
			continue
		}
		folders.WriteString(h.folderXMLCounted(ctx, access, folder, all))
		count++
	}
	root := fmt.Sprintf(`<m:RootFolder TotalItemsInView="%d" IncludesLastItemInRange="true"><t:Folders>%s</t:Folders></m:RootFolder>`, count, folders.String())
	return response("FindFolder", root), nil
}

func (h *Handler) createFolder(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	parentIDs := folderIDs(op.descendant("ParentFolderId"))
	parentID := ""
	if len(parentIDs) > 0 {
		parent, err := h.resolveFolder(ctx, access, parentIDs[0])
		if err != nil {
			return responses("CreateFolder", []responseMessage{{err: err}}), nil
		}
		if parent.ID != rootFolderID {
			parentID = parent.ID
		}
	}
	foldersNode := op.descendant("Folders")
	if foldersNode == nil || len(foldersNode.Children) == 0 {
		return "", errors.New("folder payload is required")
	}
	messages := make([]responseMessage, 0, len(foldersNode.Children))
	for _, input := range foldersNode.Children {
		name := input.descendantText("DisplayName")
		folderType := ewsFolderType(input.Name.Local, input.descendantText("FolderClass"))
		folder, err := h.space.CreateFolder(ctx, access, name, folderType, parentID)
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:Folders>` + folderIdentityXML(folder) + `</m:Folders>`})
	}
	return responses("CreateFolder", messages), nil
}

func (h *Handler) moveFolder(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	destIDs := folderIDs(op.descendant("ToFolderId"))
	if len(destIDs) == 0 {
		return "", errors.New("destination folder is required")
	}
	dest, err := h.resolveFolder(ctx, access, destIDs[0])
	if err != nil {
		return responses("MoveFolder", []responseMessage{{err: err}}), nil
	}
	destinationID := dest.ID
	if destinationID == rootFolderID {
		destinationID = ""
	}
	ids := folderIDs(op.descendant("FolderIds"))
	messages := make([]responseMessage, 0, len(ids))
	for _, id := range ids {
		folder, err := h.resolveFolder(ctx, access, id)
		if err == nil {
			folder, err = h.space.MoveFolder(ctx, access, folder.ID, destinationID, folder.Name)
		}
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:Folders>` + folderIdentityXML(folder) + `</m:Folders>`})
	}
	return responses("MoveFolder", messages), nil
}

func (h *Handler) deleteFolder(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := folderIDs(op)
	messages := make([]responseMessage, 0, len(ids))
	for _, id := range ids {
		folder, err := h.resolveFolder(ctx, access, id)
		if err == nil {
			err = h.space.DeleteFolder(ctx, access, folder.ID)
		}
		messages = append(messages, responseMessage{err: err})
	}
	return responses("DeleteFolder", messages), nil
}

func (h *Handler) emptyFolder(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	for _, id := range folderIDs(op) {
		folder, err := h.resolveFolder(ctx, access, id)
		if err != nil {
			return "", err
		}
		items, err := h.space.ListItems(ctx, access, folder.ID, service.ItemQuery{})
		if err != nil {
			return "", err
		}
		for _, item := range items {
			if err := h.space.DeleteItem(ctx, access, item.ID); err != nil {
				return "", err
			}
		}
	}
	return response("EmptyFolder", ""), nil
}

func (h *Handler) findItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := folderIDs(op.descendant("ParentFolderIds"))
	if len(ids) == 0 {
		ids = folderIDs(op)
	}
	if len(ids) == 0 {
		return "", errors.New("parent folder is required")
	}
	folder, err := h.resolveFolder(ctx, access, ids[len(ids)-1])
	if err != nil {
		return responses("FindItem", []responseMessage{{err: err}}), nil
	}
	if folder.ID == rootFolderID {
		return response("FindItem", `<m:RootFolder TotalItemsInView="0" IncludesLastItemInRange="true"><t:Items/></m:RootFolder>`), nil
	}
	shape := h.shapeFor(ctx, access, op.descendant("ItemShape"))
	if view := op.descendant("CalendarView"); view != nil {
		return h.calendarView(ctx, access, folder, view, shape)
	}
	items, err := h.space.ListItems(ctx, access, folder.ID, service.ItemQuery{})
	if err != nil {
		return "", err
	}
	total := len(items)
	offset, limit := 0, total
	if view := op.descendant("IndexedPageItemView"); view != nil {
		if parsed, parseErr := strconv.Atoi(view.attr("Offset")); parseErr == nil && parsed > 0 {
			offset = parsed
		}
		if parsed, parseErr := strconv.Atoi(view.attr("MaxEntriesReturned")); parseErr == nil && parsed > 0 {
			limit = parsed
		}
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	var out strings.Builder
	for _, item := range items[offset:end] {
		out.WriteString(renderItem(item, shape))
	}
	root := fmt.Sprintf(`<m:RootFolder TotalItemsInView="%d" IndexedPagingOffset="%d" IncludesLastItemInRange="%t"><t:Items>%s</t:Items></m:RootFolder>`, total, end, end >= total, out.String())
	return response("FindItem", root), nil
}

func (h *Handler) getItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := itemIDs(op)
	if len(ids) == 0 {
		return "", errors.New("item ID is required")
	}
	shape := h.shapeFor(ctx, access, op.descendant("ItemShape"))
	shape.body = true
	messages := make([]responseMessage, 0, len(ids))
	for _, encoded := range ids {
		item, key, err := h.lookupItem(ctx, access, encoded, shape.zone)
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		rendered := ""
		if key != "" {
			rendered = renderCalendarItem(item, shape, key)
		} else {
			rendered = renderItem(item, shape)
		}
		messages = append(messages, responseMessage{body: `<m:Items>` + rendered + `</m:Items>`})
	}
	return responses("GetItem", messages), nil
}

func (h *Handler) createItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	disposition := strings.ToLower(op.attr("MessageDisposition"))
	folderIDs := folderIDs(op.descendant("SavedItemFolderId"))
	if len(folderIDs) == 0 {
		folderIDs = []string{"drafts"}
	}
	itemsNode := op.descendant("Items")
	if itemsNode == nil || len(itemsNode.Children) == 0 {
		return "", errors.New("item payload is required")
	}
	folder, folderErr := h.resolveFolder(ctx, access, folderIDs[0])
	messages := make([]responseMessage, 0, len(itemsNode.Children))
	for _, input := range itemsNode.Children {
		switch input.Name.Local {
		case "CalendarItem", "Contact", "Task":
			item, err := h.createTypedItem(ctx, access, op, input)
			if err != nil {
				messages = append(messages, responseMessage{err: err})
				continue
			}
			messages = append(messages, responseMessage{body: `<m:Items>` + itemIdentityXML(item) + `</m:Items>`})
			continue
		case "AcceptItem", "TentativelyAcceptItem", "DeclineItem", "CancelCalendarItem", "RemoveItem":
			messages = append(messages, responseMessage{body: `<m:Items/>`, err: h.respondToMeeting(ctx, access, op, input)})
			continue
		}
		data, headers, err := encodeEWSItem(input)
		if err != nil {
			messages = append(messages, responseMessage{err: fmt.Errorf("%w: %v", errEWSInvalidProperty, err)})
			continue
		}
		if disposition == "sendonly" || disposition == "sendandsavecopy" {
			if h.submit == nil {
				messages = append(messages, responseMessage{err: errSubmissionUnavailable})
				continue
			}
			// Submission files the Sent copy itself.
			if err := h.submit(ctx, access.Actor.ID, data); err != nil {
				messages = append(messages, responseMessage{err: fmt.Errorf("%w: %v", errSubmissionFailed, err)})
				continue
			}
			messages = append(messages, responseMessage{body: `<m:Items/>`})
			continue
		}
		if folderErr != nil {
			messages = append(messages, responseMessage{err: folderErr})
			continue
		}
		item, err := h.space.CreateItem(ctx, access, folder.ID, service.ItemInput{Data: data, Headers: headers})
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:Items>` + itemIdentityXML(item) + `</m:Items>`})
	}
	return responses("CreateItem", messages), nil
}

func (h *Handler) updateItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	disposition := strings.ToLower(strings.TrimSpace(op.attr("MessageDisposition")))
	switch disposition {
	case "", "saveonly", "sendonly", "sendandsavecopy":
	default:
		return "", errors.New("MessageDisposition must be SaveOnly, SendOnly or SendAndSaveCopy")
	}
	changes := op.descendant("ItemChanges")
	if changes == nil || len(changes.ChildrenNamed("ItemChange")) == 0 {
		return "", errors.New("at least one item change is required")
	}
	var messages []responseMessage
	for _, change := range changes.ChildrenNamed("ItemChange") {
		item, err := h.applyItemChange(ctx, access, op, change)
		if err == nil && (disposition == "sendonly" || disposition == "sendandsavecopy") {
			err = h.sendDraft(ctx, access, item)
			if err == nil {
				messages = append(messages, responseMessage{body: `<m:Items/>`})
				continue
			}
		}
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:Items>` + itemIdentityXML(item) + `</m:Items>`})
	}
	return responses("UpdateItem", messages), nil
}

func (h *Handler) sendItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := itemIDs(op.descendant("ItemIds"))
	messages := make([]responseMessage, 0, len(ids))
	for _, encoded := range ids {
		id, err := decodeID(encoded, "i:")
		if err != nil {
			messages = append(messages, responseMessage{err: errItemNotFound})
			continue
		}
		item, err := h.space.GetItem(ctx, access, id)
		if err == nil {
			err = h.sendDraft(ctx, access, item)
		}
		messages = append(messages, responseMessage{err: err})
	}
	return responses("SendItem", messages), nil
}

func (h *Handler) moveItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	destIDs := folderIDs(op.descendant("ToFolderId"))
	if len(destIDs) == 0 {
		return "", errors.New("destination folder is required")
	}
	ids := itemIDs(op.descendant("ItemIds"))
	dest, destErr := h.resolveFolder(ctx, access, destIDs[0])
	messages := make([]responseMessage, 0, len(ids))
	for _, encoded := range ids {
		if destErr != nil {
			messages = append(messages, responseMessage{err: destErr})
			continue
		}
		id, err := decodeID(encoded, "i:")
		if err != nil {
			messages = append(messages, responseMessage{err: errItemNotFound})
			continue
		}
		var item model.Item
		if op.Name.Local == "CopyItem" {
			item, err = h.space.CopyItem(ctx, access, id, dest.ID, "")
		} else {
			item, err = h.space.MoveItem(ctx, access, id, dest.ID, "")
		}
		if err != nil {
			messages = append(messages, responseMessage{err: err})
			continue
		}
		messages = append(messages, responseMessage{body: `<m:Items>` + itemIdentityXML(item) + `</m:Items>`})
	}
	return responses(op.Name.Local, messages), nil
}

func (h *Handler) deleteItem(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := itemIDs(op)
	writeContext := quietScheduling(ctx, op.attr("SendMeetingCancellations"))
	zone := h.calendarContext(ctx, access, false).zone
	messages := make([]responseMessage, 0, len(ids))
	for _, encoded := range ids {
		item, key, err := h.lookupItem(ctx, access, encoded, zone)
		switch {
		case err != nil:
		case key != "":
			err = h.deleteOccurrence(writeContext, access, item, key)
		default:
			err = h.space.DeleteItem(writeContext, access, item.ID)
		}
		messages = append(messages, responseMessage{err: err})
	}
	return responses("DeleteItem", messages), nil
}

func (h *Handler) syncFolderHierarchy(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return "", errors.New("folder change history is unavailable")
	}
	requestState := strings.TrimSpace(op.descendantText("SyncState"))
	folders, err := h.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return "", err
	}
	var changes strings.Builder
	state := requestState
	done := true
	if requestState == "" {
		for _, folder := range parentsFirst(visibleFolders(folders)) {
			changes.WriteString(`<t:Create>` + folderXML(folder) + `</t:Create>`)
		}
		state, err = reader.CurrentChangeState(ctx, access, service.ChangeScope{Object: service.ChangeObjectFolder})
		if err != nil {
			return "", err
		}
	} else {
		page, listErr := reader.ListChanges(ctx, access, service.ChangeScope{Object: service.ChangeObjectFolder}, requestState, 1000)
		if listErr != nil {
			return "", listErr
		}
		for _, record := range page.Records {
			for _, change := range record.Changes {
				if change.Operation == service.ChangeDestroy || change.Operation == service.ChangeTrash {
					changes.WriteString(`<t:Delete><t:FolderId Id="` + escape(encodeID("f:", change.ID)) + `"/></t:Delete>`)
					continue
				}
				folder, getErr := h.space.GetFolder(ctx, access, change.ID)
				if getErr != nil || !ewsVisible(folder) {
					continue
				}
				typeName := "Update"
				if change.Operation == service.ChangeCreate || change.Operation == service.ChangeRestore {
					typeName = "Create"
				}
				changes.WriteString(`<t:` + typeName + `>` + folderXML(folder) + `</t:` + typeName + `>`)
			}
		}
		state = page.NewState
		done = !page.HasMoreChanges
	}
	body := `<m:SyncState>` + escape(state) + `</m:SyncState><m:IncludesLastFolderInRange>` + strconv.FormatBool(done) + `</m:IncludesLastFolderInRange><m:Changes>` + changes.String() + `</m:Changes>`
	return response("SyncFolderHierarchy", body), nil
}

func (h *Handler) syncFolderItems(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	ids := folderIDs(op)
	if len(ids) == 0 {
		return "", errors.New("sync folder is required")
	}
	folder, err := h.resolveFolder(ctx, access, ids[0])
	if err != nil {
		return "", err
	}
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return "", errors.New("folder change history is unavailable")
	}
	state := ewsItemSyncState{FolderID: folder.ID}
	if encoded := strings.TrimSpace(op.descendantText("SyncState")); encoded != "" {
		if err := decodeEWSItemSyncState(encoded, &state); err != nil || state.FolderID != folder.ID {
			return "", errors.New("invalid EWS item sync state")
		}
	}
	limit := 100
	if parsed, parseErr := strconv.Atoi(op.descendantText("MaxChangesReturned")); parseErr == nil && parsed > 0 && parsed <= 512 {
		limit = parsed
	}
	shape := h.shapeFor(ctx, access, op.descendant("ItemShape"))
	var changes strings.Builder
	done := true
	if state.JournalState == "" {
		items, err := h.space.ListItems(ctx, access, folder.ID, service.ItemQuery{})
		if err != nil {
			return "", err
		}
		if state.InitialState == "" {
			state.InitialState, err = reader.CurrentChangeState(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem})
			if err != nil {
				return "", err
			}
		}
		end := min(state.InitialOffset+limit, len(items))
		for _, item := range items[state.InitialOffset:end] {
			changes.WriteString(`<t:Create>` + renderItem(item, shape) + `</t:Create>`)
		}
		state.InitialOffset = end
		done = end >= len(items)
		if done {
			state.JournalState, state.InitialState, state.InitialOffset = state.InitialState, "", 0
		}
	} else {
		page, err := reader.ListChanges(ctx, access, service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem}, state.JournalState, limit)
		if err != nil {
			return "", err
		}
		for _, record := range page.Records {
			for _, change := range record.Changes {
				typeName := "Update"
				if change.Operation == service.ChangeCreate || (change.Operation == service.ChangeMove && change.PreviousFolderID != folder.ID) {
					typeName = "Create"
				}
				if change.Operation == service.ChangeDestroy || change.Operation == service.ChangeTrash || (change.Operation == service.ChangeMove && change.FolderID != folder.ID) {
					changes.WriteString(`<t:Delete><t:ItemId Id="` + escape(encodeID("i:", change.ID)) + `"/></t:Delete>`)
					continue
				}
				if change.Operation == service.ChangeRestore {
					typeName = "Create"
				}
				item, getErr := h.space.GetItem(ctx, access, change.ID)
				if getErr == nil {
					changes.WriteString(`<t:` + typeName + `>` + renderItem(item, shape) + `</t:` + typeName + `>`)
				}
			}
		}
		state.JournalState = page.NewState
		done = !page.HasMoreChanges
	}
	encodedState, err := encodeEWSItemSyncState(state)
	if err != nil {
		return "", err
	}
	body := `<m:SyncState>` + encodedState + `</m:SyncState><m:IncludesLastItemInRange>` + strconv.FormatBool(done) + `</m:IncludesLastItemInRange><m:Changes>` + changes.String() + `</m:Changes>`
	return response("SyncFolderItems", body), nil
}

type ewsItemSyncState struct {
	FolderID      string `json:"folder_id"`
	JournalState  string `json:"journal_state,omitempty"`
	InitialState  string `json:"initial_state,omitempty"`
	InitialOffset int    `json:"initial_offset,omitempty"`
}

func encodeEWSItemSyncState(state ewsItemSyncState) (string, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func decodeEWSItemSyncState(encoded string, state *ewsItemSyncState) error {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, state)
}

func (h *Handler) resolveFolder(ctx context.Context, access service.AccessContext, id string) (model.Folder, error) {
	if isDistinguishedRoot(id) {
		return rootFolder(), nil
	}
	if distinguishedPath, ok := distinguishedFolderPath(id); ok {
		return h.distinguishedFolder(ctx, access, strings.ToLower(id), distinguishedPath)
	}
	decoded, err := decodeID(id, "f:")
	if err != nil {
		return model.Folder{}, errFolderNotFound
	}
	if decoded == rootFolderID {
		return rootFolder(), nil
	}
	folder, err := h.space.GetFolder(ctx, access, decoded)
	if errors.Is(err, store.ErrNotFound) {
		return model.Folder{}, errFolderNotFound
	}
	return folder, err
}

func response(operation, body string) string {
	return `<m:` + operation + `Response><m:ResponseMessages><m:` + operation + `ResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode>` + body + `</m:` + operation + `ResponseMessage></m:ResponseMessages></m:` + operation + `Response>`
}

func envelope(body string) string {
	return xml.Header + `<s:Envelope xmlns:s="` + soapNS + `" xmlns:m="` + msgNS + `" xmlns:t="` + typeNS + `"><s:Header><t:ServerVersionInfo MajorVersion="15" MinorVersion="2" MajorBuildNumber="0" MinorBuildNumber="0" Version="V2016"/></s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
}

func folderXML(folder model.Folder) string {
	return renderFolder(folder, nil)
}

func ewsImportance(headers map[string]string) string {
	switch service.MessageImportance(headers) {
	case service.MailImportanceLow:
		return "Low"
	case service.MailImportanceHigh:
		return "High"
	default:
		return "Normal"
	}
}

func encodeEWSItem(input *node) ([]byte, map[string]string, error) {
	if encoded := input.descendantText("MimeContent"); encoded != "" {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid MIME content: %w", err)
		}
		return data, model.ParseItemHeaders(data), nil
	}
	headers := map[string]string{"Subject": input.descendantText("Subject")}
	if from := input.descendantText("EmailAddress"); from != "" {
		headers["From"] = from
	}
	importance, err := service.NormalizeMailImportance(service.MailImportance(input.descendantText("Importance")))
	if err != nil {
		return nil, nil, err
	}
	service.SetMailImportanceHeaders(headers, importance)
	body := input.descendantText("Body")
	var raw strings.Builder
	for key, value := range headers {
		if value != "" {
			raw.WriteString(key + ": " + strings.ReplaceAll(value, "\r", "") + "\r\n")
		}
	}
	raw.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body)
	return []byte(raw.String()), headers, nil
}

type ewsItemFieldUpdate struct {
	field    string
	value    string
	bodyType string
	delete   bool
}

func ewsExpectedModSeq(resolution, changeKey string, current uint64) (uint64, error) {
	switch strings.ToLower(strings.TrimSpace(resolution)) {
	case "alwaysoverwrite":
		return current, nil
	case "", "autoresolve", "neveroverwrite":
		if strings.TrimSpace(changeKey) == "" {
			return 0, errors.New("ChangeKey is required for conflict-aware updates")
		}
	default:
		return 0, errors.New("ConflictResolution must be AutoResolve, NeverOverwrite, or AlwaysOverwrite")
	}
	expected, err := strconv.ParseUint(strings.TrimSpace(changeKey), 10, 64)
	if err != nil || expected == 0 {
		return 0, errors.New("invalid item ChangeKey")
	}
	return expected, nil
}

func applyEWSItemUpdates(item model.Item, updatesNode *node) ([]byte, map[string]string, error) {
	updates, err := parseEWSItemUpdates(updatesNode)
	if err != nil {
		return nil, nil, err
	}
	data := bytes.Clone(item.Data)
	for _, update := range updates {
		switch update.field {
		case "item:mimecontent":
			data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(update.value))
			if err != nil || len(data) == 0 {
				return nil, nil, fmt.Errorf("%w: invalid MIME content", errEWSInvalidProperty)
			}
			if _, err = parseMIMEHeaders(data); err != nil {
				return nil, nil, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
			}
		case "item:subject":
			var value *string
			if !update.delete {
				value = &update.value
			}
			data, err = rewriteMIMEHeaders(data, map[string]*string{"Subject": value})
		case "item:importance":
			importance := service.MailImportanceNormal
			if !update.delete {
				importance, err = service.NormalizeMailImportance(service.MailImportance(update.value))
			}
			if err == nil {
				replacements := map[string]*string{"Importance": nil, "X-Priority": nil, "Priority": nil}
				switch importance {
				case service.MailImportanceHigh:
					importanceValue, xPriority, priority := "high", "1", "urgent"
					replacements["Importance"], replacements["X-Priority"], replacements["Priority"] = &importanceValue, &xPriority, &priority
				case service.MailImportanceLow:
					importanceValue, xPriority, priority := "low", "5", "non-urgent"
					replacements["Importance"], replacements["X-Priority"], replacements["Priority"] = &importanceValue, &xPriority, &priority
				}
				data, err = rewriteMIMEHeaders(data, replacements)
			}
		case "item:body":
			body := update.value
			if update.delete {
				body = ""
				update.bodyType = "preserve"
			}
			data, err = replaceSimpleMIMEBody(data, update.bodyType, body)
		}
		if err != nil {
			if errors.Is(err, errEWSInvalidProperty) {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
		}
	}
	headers, err := parseMIMEHeaders(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
	}
	return data, headers, nil
}

func parseEWSItemUpdates(updatesNode *node) ([]ewsItemFieldUpdate, error) {
	if updatesNode == nil || len(updatesNode.Children) == 0 {
		return nil, errors.New("item updates are required")
	}
	updates := make([]ewsItemFieldUpdate, 0, len(updatesNode.Children))
	seen := make(map[string]bool)
	for _, operation := range updatesNode.Children {
		if operation.Name.Local != "SetItemField" && operation.Name.Local != "DeleteItemField" {
			return nil, fmt.Errorf("%w: unsupported update operation %s", errEWSInvalidProperty, operation.Name.Local)
		}
		fieldNode := operation.child("FieldURI")
		if fieldNode == nil {
			return nil, fmt.Errorf("%w: FieldURI is required", errEWSInvalidProperty)
		}
		field := strings.ToLower(strings.TrimSpace(fieldNode.attr("FieldURI")))
		switch field {
		case "item:mimecontent", "item:subject", "item:importance", "item:body":
		default:
			return nil, fmt.Errorf("%w: unsupported field %s", errEWSInvalidProperty, field)
		}
		if seen[field] {
			return nil, fmt.Errorf("%w: field %s is updated more than once", errEWSInvalidProperty, field)
		}
		seen[field] = true
		update := ewsItemFieldUpdate{field: field, delete: operation.Name.Local == "DeleteItemField"}
		if update.delete && field == "item:mimecontent" {
			return nil, fmt.Errorf("%w: MIME content cannot be deleted", errEWSInvalidProperty)
		}
		if !update.delete {
			switch field {
			case "item:mimecontent":
				value := operation.descendant("MimeContent")
				if value == nil {
					return nil, fmt.Errorf("%w: MimeContent value is required", errEWSInvalidProperty)
				}
				update.value = strings.TrimSpace(value.Text)
			case "item:subject":
				value := operation.descendant("Subject")
				if value == nil {
					return nil, fmt.Errorf("%w: Subject value is required", errEWSInvalidProperty)
				}
				update.value = strings.TrimSpace(value.Text)
			case "item:importance":
				value := operation.descendant("Importance")
				if value == nil {
					return nil, fmt.Errorf("%w: Importance value is required", errEWSInvalidProperty)
				}
				update.value = strings.TrimSpace(value.Text)
			case "item:body":
				body := operation.descendant("Body")
				if body == nil {
					return nil, fmt.Errorf("%w: Body value is required", errEWSInvalidProperty)
				}
				update.value, update.bodyType = body.Text, body.attr("BodyType")
			}
		}
		updates = append(updates, update)
	}
	if seen["item:mimecontent"] && len(updates) != 1 {
		return nil, fmt.Errorf("%w: MIME content replacement cannot be combined with property updates", errEWSInvalidProperty)
	}
	return updates, nil
}

func rewriteMIMEHeaders(data []byte, replacements map[string]*string) ([]byte, error) {
	header, body, lineBreak, separator, err := splitMIMEMessage(data)
	if err != nil {
		return nil, err
	}
	targets := make(map[string]string, len(replacements))
	for name, value := range replacements {
		if strings.ContainsAny(name, ":\r\n") || value != nil && strings.ContainsAny(*value, "\r\n") {
			return nil, errors.New("invalid MIME header replacement")
		}
		targets[strings.ToLower(name)] = name
	}
	lines := strings.Split(string(header), lineBreak)
	retained := make([]string, 0, len(lines)+len(replacements))
	skip := false
	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if !skip {
				retained = append(retained, line)
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, errors.New("malformed MIME header")
		}
		_, skip = targets[strings.ToLower(strings.TrimSpace(line[:colon]))]
		if !skip {
			retained = append(retained, line)
		}
	}
	order := []string{"Subject", "Importance", "X-Priority", "Priority", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"}
	emitted := make(map[string]bool, len(order))
	for _, name := range order {
		value, found := replacements[name]
		if found && value != nil {
			retained = append(retained, name+": "+*value)
		}
		if found {
			emitted[name] = true
		}
	}
	for name, value := range replacements {
		if !emitted[name] && value != nil {
			retained = append(retained, name+": "+*value)
		}
	}
	result := make([]byte, 0, len(data)+128)
	result = append(result, strings.Join(retained, lineBreak)...)
	result = append(result, separator...)
	result = append(result, body...)
	return result, nil
}

func replaceSimpleMIMEBody(data []byte, bodyType, body string) ([]byte, error) {
	headers, err := parseMIMEHeaders(data)
	if err != nil {
		return nil, err
	}
	mediaType, _, parseErr := mime.ParseMediaType(headers["Content-Type"])
	if parseErr != nil && headers["Content-Type"] != "" {
		return nil, errors.New("invalid MIME content type")
	}
	if mediaType == "" {
		mediaType = "text/plain"
	}
	if !strings.HasPrefix(strings.ToLower(mediaType), "text/") {
		return nil, fmt.Errorf("%w: structured body replacement requires a simple text message", errEWSInvalidProperty)
	}
	switch strings.ToLower(strings.TrimSpace(bodyType)) {
	case "preserve":
	case "", "text":
		mediaType = "text/plain"
	case "html":
		mediaType = "text/html"
	default:
		return nil, fmt.Errorf("%w: BodyType must be Text or HTML", errEWSInvalidProperty)
	}
	mimeVersion, contentType, transferEncoding := "1.0", mediaType+`; charset="utf-8"`, "8bit"
	updated, err := rewriteMIMEHeaders(data, map[string]*string{
		"MIME-Version": &mimeVersion, "Content-Type": &contentType, "Content-Transfer-Encoding": &transferEncoding,
	})
	if err != nil {
		return nil, err
	}
	header, _, _, separator, err := splitMIMEMessage(updated)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(header)+len(separator)+len(body))
	result = append(result, header...)
	result = append(result, separator...)
	result = append(result, body...)
	return result, nil
}

func splitMIMEMessage(data []byte) (header, body []byte, lineBreak string, separator []byte, err error) {
	if index := bytes.Index(data, []byte("\r\n\r\n")); index >= 0 {
		return data[:index], data[index+4:], "\r\n", []byte("\r\n\r\n"), nil
	}
	if index := bytes.Index(data, []byte("\n\n")); index >= 0 {
		return data[:index], data[index+2:], "\n", []byte("\n\n"), nil
	}
	return nil, nil, "", nil, errors.New("MIME message is missing the header separator")
}

// parseMIMEHeaders validates that data is a parseable RFC 5322 message and
// returns its headers keyed by canonical name.
func parseMIMEHeaders(data []byte) (map[string]string, error) {
	if _, err := mail.ReadMessage(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return model.ParseItemHeaders(data), nil
}

func folderClass(folderType model.FolderType) string {
	switch folderType {
	case model.FolderTypeCalendar:
		return "IPF.Appointment"
	case model.FolderTypeContacts:
		return "IPF.Contact"
	case model.FolderTypeTasks:
		return "IPF.Task"
	case model.FolderTypeNotes:
		return "IPF.StickyNote"
	default:
		return "IPF.Note"
	}
}

func ewsFolderType(tag, class string) model.FolderType {
	switch {
	case tag == "CalendarFolder" || strings.HasPrefix(class, "IPF.Appointment"):
		return model.FolderTypeCalendar
	case tag == "ContactsFolder" || strings.HasPrefix(class, "IPF.Contact"):
		return model.FolderTypeContacts
	case tag == "TasksFolder" || strings.HasPrefix(class, "IPF.Task"):
		return model.FolderTypeTasks
	case strings.HasPrefix(class, "IPF.StickyNote"):
		return model.FolderTypeNotes
	default:
		return model.FolderTypeMail
	}
}

func distinguishedFolderPath(id string) (string, bool) {
	paths := map[string]string{
		"inbox": "INBOX", "drafts": "Drafts", "sentitems": "Sent", "deleteditems": "Trash",
		"junkemail": "Junk", "calendar": "Calendar", "contacts": "Contacts", "notes": "",
		"tasks": "", "archive": "Archive", "outbox": "", "recipientcache": "",
		"searchfolders": "", "conflicts": "", "syncissues": "", "localfailures": "", "serverfailures": "",
	}
	path, ok := paths[strings.ToLower(id)]
	return path, ok
}

func isDistinguishedRoot(id string) bool {
	switch strings.ToLower(id) {
	case "msgfolderroot", "root", "mailboxroot":
		return true
	default:
		return false
	}
}

func encodeID(prefix, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(prefix + id))
}

func decodeID(encoded, prefix string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || !strings.HasPrefix(string(decoded), prefix) {
		return "", errors.New("invalid EWS identifier")
	}
	return strings.TrimPrefix(string(decoded), prefix), nil
}

func folderIDs(root *node) []string {
	if root == nil {
		return nil
	}
	var ids []string
	root.walk(func(n *node) {
		if n.Name.Local == "DistinguishedFolderId" {
			if id := n.attr("Id"); id != "" {
				ids = append(ids, id)
			}
		} else if n.Name.Local == "FolderId" {
			if id := n.attr("Id"); id != "" {
				ids = append(ids, id)
			}
		}
	})
	return ids
}

func itemIDs(root *node) []string {
	if root == nil {
		return nil
	}
	var ids []string
	root.walk(func(n *node) {
		switch n.Name.Local {
		case "ItemId", "OccurrenceItemId", "RecurringMasterItemId":
			if id := refID(n); id != "" {
				ids = append(ids, id)
			}
		}
	})
	return ids
}

func ewsError(err error) (string, string) {
	switch {
	case errors.Is(err, errFolderNotFound):
		return "ErrorFolderNotFound", "The specified folder could not be found in the store."
	case errors.Is(err, errItemNotFound):
		return "ErrorItemNotFound", "The specified object was not found in the store."
	case errors.Is(err, errSubmissionUnavailable), errors.Is(err, errSubmissionFailed):
		return "ErrorMessageSubmissionBlocked", err.Error()
	case errors.Is(err, service.ErrChangeStateExpired):
		return "ErrorInvalidSyncStateData", "The synchronization state is no longer retained; perform a full synchronization"
	case errors.Is(err, model.ErrQuotaExceeded):
		return "ErrorQuotaExceeded", "The account quota has been exceeded"
	case service.IsTemporarilyUnavailable(err):
		return "ErrorServerBusy", "The account is temporarily unavailable; retry the request"
	case errors.Is(err, store.ErrNotFound):
		return "ErrorItemNotFound", "The requested item was not found"
	case errors.Is(err, store.ErrExists):
		return "ErrorFolderExists", "A folder with the specified name already exists"
	case errors.Is(err, service.ErrForbidden):
		return "ErrorAccessDenied", "Access is denied"
	case errors.Is(err, service.ErrItemUpdateConflict):
		return "ErrorIrresolvableConflict", "The item changed since it was read"
	case errors.Is(err, errEWSInvalidProperty):
		return "ErrorInvalidPropertyRequest", err.Error()
	case errors.Is(err, errEndBeforeStart):
		return "ErrorCalendarEndDateIsEarlierThanStartDate", "The end date is earlier than the start date"
	case errors.Is(err, errAttachmentNotFound):
		return "ErrorAttachmentNotFound", "The attachment could not be found"
	case errors.Is(err, errSubscriptionNotFound):
		return "ErrorSubscriptionNotFound", "The specified subscription was not found"
	case errors.Is(err, errInvalidSubscription):
		return "ErrorInvalidSubscription", "The subscription is invalid; subscribe again"
	case errors.Is(err, errSubscriptionAccessDenied):
		return "ErrorSubscriptionAccessDenied", "The subscription belongs to another user"
	case errors.Is(err, errInvalidWatermark):
		return "ErrorInvalidWatermark", "The watermark is invalid"
	case errors.Is(err, errInvalidSubscriptionReq):
		return "ErrorInvalidSubscriptionRequest", "The subscription request is invalid"
	case errors.Is(err, errSubscriptionCount):
		return "ErrorExceededSubscriptionCount", "The user has too many subscriptions"
	case errors.Is(err, errOOFUnavailable):
		return "ErrorInvalidRequest", err.Error()
	case strings.Contains(err.Error(), "unsupported EWS operation"):
		return "ErrorInvalidRequest", err.Error()
	default:
		return "ErrorInvalidRequest", err.Error()
	}
}

func (h *Handler) writeFault(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	body := `<s:Fault><faultcode>s:Client</faultcode><faultstring>` + escape(message) + `</faultstring><detail><e:ResponseCode xmlns:e="` + msgNS + `">` + escape(code) + `</e:ResponseCode></detail></s:Fault>`
	_, _ = io.WriteString(w, envelope(body))
}

func escape(value string) string {
	var out strings.Builder
	_ = xml.EscapeText(&out, []byte(value))
	return out.String()
}

type node struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Text     string
	Children []*node
}

func decodeXML(reader io.Reader) (*node, error) {
	decoder := xml.NewDecoder(reader)
	var root *node
	stack := make([]*node, 0, 16)
	// Character data arrives in runs split by comments, CDATA sections and
	// entities; each element's text is collected in a builder so that many
	// runs cost linear rather than quadratic time.
	texts := make([]*strings.Builder, 0, 16)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) >= 64 {
				return nil, errors.New("XML nesting limit exceeded")
			}
			current := &node{Name: value.Name, Attrs: value.Attr}
			if len(stack) == 0 {
				root = current
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, current)
			}
			stack = append(stack, current)
			texts = append(texts, &strings.Builder{})
		case xml.CharData:
			if len(stack) > 0 {
				texts[len(texts)-1].Write(value)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unexpected XML end element")
			}
			stack[len(stack)-1].Text = texts[len(texts)-1].String()
			stack, texts = stack[:len(stack)-1], texts[:len(texts)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errors.New("incomplete XML document")
	}
	return root, nil
}

func (n *node) child(local string) *node {
	if n == nil {
		return nil
	}
	for _, child := range n.Children {
		if child.Name.Local == local {
			return child
		}
	}
	return nil
}

func (n *node) descendant(local string) *node {
	if n == nil {
		return nil
	}
	if n.Name.Local == local {
		return n
	}
	for _, child := range n.Children {
		if match := child.descendant(local); match != nil {
			return match
		}
	}
	return nil
}

func (n *node) descendantText(local string) string {
	if found := n.descendant(local); found != nil {
		return strings.TrimSpace(found.Text)
	}
	return ""
}

func (n *node) attr(local string) string {
	for _, attribute := range n.Attrs {
		if attribute.Name.Local == local {
			return attribute.Value
		}
	}
	return ""
}

func (n *node) walk(visit func(*node)) {
	if n == nil {
		return
	}
	visit(n)
	for _, child := range n.Children {
		child.walk(visit)
	}
}

// applyItemChange applies one ItemChange: MIME, subject, importance and
// body edits rewrite the message under the ChangeKey, and message:IsRead
// (how Mac Mail and Outlook mark mail read) sets the \Seen flag.
func (h *Handler) applyItemChange(ctx context.Context, access service.AccessContext, op *node, change *node) (model.Item, error) {
	resolution := op.attr("ConflictResolution")
	identifier := itemRefElement(change)
	encoded := refID(identifier)
	if encoded == "" {
		return model.Item{}, fmt.Errorf("%w: item ID is required", errEWSInvalidProperty)
	}
	current, key, err := h.lookupItem(ctx, access, encoded, h.calendarContext(ctx, access, false).zone)
	if err != nil {
		return model.Item{}, err
	}
	id := current.ID
	if kindOf(current.Data) != kindMessage {
		return h.applyTypedChange(ctx, access, op, identifier, current, key, change.child("Updates"))
	}
	content, read, err := splitEWSItemUpdates(change.child("Updates"))
	if err != nil {
		return model.Item{}, err
	}
	updated := current
	if content != nil {
		expected, err := ewsExpectedModSeq(resolution, identifier.attr("ChangeKey"), current.ModSeq)
		if err != nil {
			return model.Item{}, fmt.Errorf("%w: %v", errEWSInvalidProperty, err)
		}
		data, headers, err := applyEWSItemUpdates(current, content)
		if err != nil {
			return model.Item{}, err
		}
		updater, ok := h.space.(service.ConditionalItemUpdater)
		if !ok {
			return model.Item{}, errors.New("conditional item update is unavailable")
		}
		if updated, err = updater.UpdateItemIfModSeq(ctx, access, id, expected, data, headers); err != nil {
			return model.Item{}, err
		}
	}
	if read != nil {
		if updated, err = h.space.SetFlags(ctx, access, id, setFlag(updated.Flags, model.FlagSeen, *read)); err != nil {
			return model.Item{}, err
		}
	}
	return updated, nil
}

func (h *Handler) sendDraft(ctx context.Context, access service.AccessContext, item model.Item) error {
	if h.submit == nil {
		return errSubmissionUnavailable
	}
	if err := h.submit(ctx, access.Actor.ID, item.Data); err != nil {
		return fmt.Errorf("%w: %v", errSubmissionFailed, err)
	}
	// The message is on its way: a failure to remove the draft must not be
	// reported as a send failure, or the client would send it again.
	_ = h.space.DeleteItem(ctx, access, item.ID)
	return nil
}
