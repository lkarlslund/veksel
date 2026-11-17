package caldav

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- WebDAV Base Methods (RFC 4918) ---

// handlePropfind handles PROPFIND requests.
// Depth: 0 = this resource only, 1 = this + immediate children, infinity = all descendants.
func (h *Handler) handlePropfind(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "0"
	}

	// Parse PROPFIND body
	pf, err := parsePropfind(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid PROPFIND body: %v", err))
		return
	}
	request := requestFor(pf)
	var responses []response

	if len(parts) == 0 || parts[0] == "" {
		// PROPFIND on user root: list all collections
		responses, err = h.propfindUserRoot(r.Context(), username, pf, depth)
	} else if len(parts) == 1 {
		// PROPFIND on a collection — check folder type
		if folder, lookupErr := h.store.FolderStore().GetByPath(r.Context(), username, parts[0]); lookupErr == nil {
			switch folder.Type {
			case model.FolderTypeContacts:
				responses, err = h.propfindAddressbook(r.Context(), username, parts[0], pf, depth)
			case model.FolderTypeFiles:
				responses, err = h.handleFilesPropfind(r.Context(), username, parts[0], pf, depth)
			default:
				responses, err = h.propfindCollection(r.Context(), username, parts[0], pf, depth)
			}
		} else {
			responses, err = h.propfindCollection(r.Context(), username, parts[0], pf, depth)
		}
	} else {
		// PROPFIND on a specific item — check if it's a file item
		if folder, lookupErr := h.store.FolderStore().GetByPath(r.Context(), username, parts[0]); lookupErr == nil && folder.Type == model.FolderTypeFiles {
			responses, err = h.propfindItem(r.Context(), username, parts[0], parts[1])
			// Rebuild with file-specific props for the correct content type
			if len(responses) > 0 {
				if item, itemErr := h.store.ItemStore().Get(r.Context(), model.ItemKey(folder.ID, parts[1])); itemErr == nil {
					itemHref := buildHref(username, folder.Path, parts[1])
					for i := range responses {
						responses[i] = fileItemToPropResp(item, itemHref)
					}
				}
			}
		} else {
			responses, err = h.propfindItem(r.Context(), username, parts[0], parts[1])
		}
	}

	if errors.Is(err, errResourceNotFound) {
		h.respondError(w, r, http.StatusNotFound, "not-found", "resource not found")
		return
	}
	if err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}
	h.addQuota(r.Context(), username, request, responses)
	request.restrict(responses)
	writeMultistatus(w, responses)
}

// addQuota adds the account's storage use and the space left under its
// quota (RFC 4331) to collection responses when either was requested by
// name, as Apple Calendar and macOS Finder do; allprop does not include
// them. Without a storage limit only the use is reported.
func (h *Handler) addQuota(ctx context.Context, username string, request propRequest, responses []response) {
	used, available := xml.Name{Space: NSDAV, Local: "quota-used-bytes"}, xml.Name{Space: NSDAV, Local: "quota-available-bytes"}
	if request.names == nil || (!request.wants(used) && !request.wants(available)) {
		return
	}
	usage, err := h.store.space.AccountUsage(ctx, davAccess(ctx, username))
	if err != nil {
		return
	}
	bytesUsed := usage.Quota.CurrentStorageBytes
	if bytesUsed == 0 {
		bytesUsed = usage.LogicalBytes
	}
	for index := range responses {
		prop := responses[index].Prop
		if prop == nil || prop.ResourceType == nil || prop.ResourceType.Collection == nil {
			continue
		}
		prop.QuotaUsedBytes = strPtr(strconv.FormatInt(bytesUsed, 10))
		if usage.Quota.MaxStorageBytes > 0 {
			prop.QuotaAvailableBytes = strPtr(strconv.FormatInt(max(usage.Quota.MaxStorageBytes-bytesUsed, 0), 10))
		}
	}
}

// errResourceNotFound marks a PROPFIND target that does not exist, which is
// answered with 404 rather than as a server error.
var errResourceNotFound = errors.New("resource not found")

// propfindUserRoot returns a response for the user's root collection.
// When depth is 1 or infinity, it also lists the user's collections.
func (h *Handler) propfindUserRoot(ctx context.Context, username string, pf *propfind, depth string) ([]response, error) {
	href := buildHref(username) + "/"
	displayName := username
	if user, err := h.store.UserStore().Get(ctx, username); err == nil && strings.TrimSpace(user.DisplayName) != "" {
		displayName = user.DisplayName
	}
	etag := `""`
	lastMod := formatHTTPTime(time.Now())
	created := formatXMLTime(time.Now())

	resp := response{
		Href:   href,
		Status: "HTTP/1.1 200 OK",
		Prop: &propResp{
			Displayname:     &displayName,
			ResourceType:    &resourceType{Collection: &empty{}, Principal: &empty{}},
			Getetag:         &etag,
			Getlastmodified: &lastMod,
			Creationdate:    &created,
		},
	}
	// The account root doubles as the principal and as both home sets, which
	// is what discovery clients (vdirsyncer, DAVx5, Apple, Thunderbird) walk.
	actor := username
	if id, _ := ctx.Value(authenticatedUserKey{}).(string); id != "" {
		actor = id
	}
	resp.Prop.CurrentUserPrincipal = &davCurrentUserPrincipal{Href: buildHref(actor) + "/"}
	resp.Prop.CalendarHomeSet = &davHomeSet{Href: href}
	resp.Prop.AddressbookHomeSet = &davHomeSet{Href: href}
	// RFC 6638 scheduling discovery: where to look up free/busy time and
	// which addresses identify this calendar user as an organizer.
	resp.Prop.ScheduleInboxURL = &davHomeSet{Href: buildHref(username, model.ScheduleInboxPath) + "/"}
	resp.Prop.ScheduleOutboxURL = &davHomeSet{Href: buildHref(username, model.ScheduleOutboxPath) + "/"}
	resp.Prop.CalendarUserAddressSet = &davCalendarUserAddressSet{Hrefs: h.calendarUserAddresses(ctx, username)}
	userType := h.calendarUserType(ctx, username)
	resp.Prop.CalendarUserType = &userType
	resp.Prop.PrincipalURL = &davHomeSet{Href: href}
	resp.Prop.PrincipalCollectionSet = &davHomeSet{Href: "/dav/"}

	responses := []response{resp}

	if depth == "0" {
		return responses, nil
	}

	// List all folders for this user
	folders, err := h.store.FolderStore().ListForUser(ctx, username)
	if err != nil {
		return nil, err
	}

	for _, folder := range folders {
		var sharees []model.Sharee
		if calendarCollection(folder) {
			sharees, _ = h.store.FolderStore().ListCalendarSharing(ctx, folder.ID)
		}
		folderHref := buildHref(username, folder.Path) + "/"
		child := folderToPropRespACL(folder, folderHref, sharees, actor)
		h.decorateCollection(ctx, folder, &child)
		responses = append(responses, child)
	}

	return responses, nil
}

// propfindCollection returns responses for a collection and optionally its children.
func (h *Handler) propfindCollection(ctx context.Context, username, collectionPath string, pf *propfind, depth string) ([]response, error) {
	var folder model.Folder
	var err error
	if collectionPath == model.ScheduleInboxPath || collectionPath == model.ScheduleOutboxPath {
		// The principal advertises both schedule collections, so they
		// exist from the first lookup.
		folder, err = h.ensureScheduleCollection(ctx, username, collectionPath)
	} else {
		folder, err = h.store.FolderStore().GetByPath(ctx, username, collectionPath)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResourceNotFound, err)
	}

	// Load sharing info for calendar collections
	var sharees []model.Sharee
	if calendarCollection(folder) {
		sharees, _ = h.store.FolderStore().ListCalendarSharing(ctx, folder.ID)
	}

	href := buildHref(username, folder.Path) + "/"
	actor := username
	if id, _ := ctx.Value(authenticatedUserKey{}).(string); id != "" {
		actor = id
	}
	collection := folderToPropRespACL(folder, href, sharees, actor)
	h.decorateCollection(ctx, folder, &collection)
	responses := []response{collection}

	if depth == "0" {
		return responses, nil
	}

	// Only an explicit calendar-data request returns object bodies.
	wantCalendarData := pf.Prop != nil && requestFor(pf).wants(xml.Name{Space: NSSCalDAV, Local: "calendar-data"})

	// List items in the collection
	items, err := h.store.ItemStore().List(ctx, folder.ID)
	if err != nil {
		return nil, err
	}

	for _, itemKey := range items {
		item, err := h.store.ItemStore().Get(ctx, itemKey)
		if err != nil {
			continue
		}

		itemID := item.Name
		if itemID == "" {
			itemID = item.ID
		}
		itemHref := buildHref(username, folder.Path, itemID)

		resp := itemToPropResp(item, itemHref)
		if wantCalendarData {
			calData := string(item.Data)
			resp.Prop.CalendarData = &calData
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

// propfindItem returns a response for a single item.
func (h *Handler) propfindItem(ctx context.Context, username, collectionPath, itemID string) ([]response, error) {
	folder, err := h.store.FolderStore().GetByPath(ctx, username, collectionPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResourceNotFound, err)
	}

	itemKey := model.ItemKey(folder.ID, itemID)
	item, err := h.store.ItemStore().Get(ctx, itemKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResourceNotFound, err)
	}

	href := buildHref(username, folder.Path, itemID)
	if folder.Type == model.FolderTypeContacts {
		return []response{vCardItemToPropResp(item, href)}, nil
	}
	return []response{itemToPropResp(item, href)}, nil
}

// handleProppatch handles PROPPATCH requests.
func (h *Handler) handleProppatch(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 1 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "PROPPATCH requires a target resource")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}
	if len(parts) == 1 {
		if folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0]); err == nil && (calendarCollection(folder) || folder.Type == model.FolderTypeContacts) {
			h.handleCollectionProppatch(w, r, username, folder, body)
			return
		}
	}
	// Other resources keep no dead properties; the change is acknowledged
	// as before (macOS Finder sets Win32 attributes on files).
	changes, err := parsePropertyChanges(body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid PROPPATCH body: %v", err))
		return
	}
	statuses := make([]int, len(changes))
	for index := range statuses {
		statuses[index] = http.StatusOK
	}
	writeMultistatus(w, []response{changeResponse(buildHref(username, parts...), changes, statuses)})
}

// handleMkcol handles MKCOL requests. An extended MKCOL (RFC 5689) whose
// resourcetype names an address book or calendar creates that collection
// with the requested properties; a plain MKCOL creates a files folder.
func (h *Handler) handleMkcol(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 1 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "MKCOL requires a target collection path")
		return
	}

	collectionPath := parts[0]

	// Chunked bodies have no Content-Length, so read whatever is sent.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}

	if len(body) > 0 && isAddressbookMKCOL(body) {
		h.createCollection(w, r, username, parts, model.FolderTypeContacts, body)
		return
	}
	if len(body) > 0 && bytes.Contains(body, []byte("calendar")) {
		// A collection restricted to VTODO is a task list (RFC 4791 5.2.3).
		folderType, ok := calendarCollectionType(body)
		if !ok {
			h.respondError(w, r, http.StatusForbidden, "supported-calendar-component", "only event calendars and task lists can be created")
			return
		}
		h.createCollection(w, r, username, parts, folderType, body)
		return
	}

	// MKCOL needs an unmapped URL (DAV:resource-must-be-null).
	if _, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath); err == nil {
		h.respondError(w, r, http.StatusConflict, "resource-must-be-null", "collection already exists")
		return
	}

	// Create parent ID if nested
	parentID := ""
	parentPath := getParentPath(collectionPath)
	if parentPath != "" {
		if parent, err := h.store.FolderStore().GetByPath(r.Context(), username, parentPath); err == nil {
			parentID = parent.ID
		}
	}

	if err := h.store.FolderStore().Create(r.Context(), username, collectionPath, model.FolderTypeFiles, parentID); err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}

	href := buildHref(username, collectionPath) + "/"
	w.Header().Set("Location", href)
	w.WriteHeader(http.StatusCreated)
}

// handleMove handles MOVE requests.
func (h *Handler) handleMove(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	h.handleTransfer(w, r, username, parts, true)
}

// handleCopy handles COPY requests.
func (h *Handler) handleCopy(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	h.handleTransfer(w, r, username, parts, false)
}

// handleTransfer routes MOVE and COPY of objects to the files or the
// calendar and address book implementation. Collections cannot be moved
// or copied; that used to be acknowledged with 204 and ignored.
func (h *Handler) handleTransfer(w http.ResponseWriter, r *http.Request, username string, parts []string, move bool) {
	method := "COPY"
	if move {
		method = "MOVE"
	}
	if r.Header.Get("Destination") == "" {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "Destination header required for "+method)
		return
	}
	if len(parts) < 2 {
		h.respondError(w, r, http.StatusForbidden, "forbidden", "collections cannot be moved or copied")
		return
	}
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0])
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "source collection not found")
		return
	}
	switch {
	case folder.Type == model.FolderTypeFiles && move:
		h.handleFilesMove(w, r, username, parts)
	case folder.Type == model.FolderTypeFiles:
		h.handleFilesCopy(w, r, username, parts)
	case calendarCollection(folder) || folder.Type == model.FolderTypeContacts:
		h.handleObjectTransfer(w, r, username, folder, parts[1], move)
	default:
		h.respondError(w, r, http.StatusForbidden, "forbidden", method+" is not supported for this collection")
	}
}

// handleLock handles LOCK requests.
func (h *Handler) handleLock(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	// Veksel does not implement DAV locking; return a dummy lock token
	w.Header().Set("Lock-Token", "<opaquelocktoken:veksel-nolock>")
	w.Header().Set("Timeout", "Second-120")
	w.WriteHeader(http.StatusOK)
}

// handleUnlock handles UNLOCK requests.
func (h *Handler) handleUnlock(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	w.WriteHeader(http.StatusNoContent)
}
