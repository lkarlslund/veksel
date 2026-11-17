package caldav

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// propertyChange is one property of a PROPPATCH, MKCALENDAR, or extended
// MKCOL body, with its text value.
type propertyChange struct {
	name   xml.Name
	value  string
	remove bool
}

// parsePropertyChanges collects the properties under DAV:set/DAV:prop and
// DAV:remove/DAV:prop of a propertyupdate, mkcalendar, or mkcol body.
func parsePropertyChanges(body []byte) ([]propertyChange, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var changes []propertyChange
	var stack []xml.Name
	remove := false
	current := -1
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return changes, nil
		}
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth := len(stack)
			switch {
			case element.Name.Space == NSDAV && (element.Name.Local == "set" || element.Name.Local == "remove") && depth == 1:
				remove = element.Name.Local == "remove"
			case depth == 3 && stack[1].Space == NSDAV && stack[2] == xml.Name{Space: NSDAV, Local: "prop"}:
				changes = append(changes, propertyChange{name: element.Name, remove: remove})
				current = len(changes) - 1
			}
			stack = append(stack, element.Name)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
			if len(stack) == 3 {
				current = -1
			}
		case xml.CharData:
			if current >= 0 && len(stack) == 4 {
				changes[current].value += string(element)
			}
		}
	}
}

var colorValue = regexp.MustCompile(`^#[0-9A-Fa-f]{6}([0-9A-Fa-f]{2})?$`)

// protectedProperties are computed by the server and cannot be set
// (RFC 4918 §15, RFC 4791 §5.2, RFC 6578 §4).
var protectedProperties = []xml.Name{
	{Space: NSDAV, Local: "resourcetype"}, {Space: NSDAV, Local: "getetag"}, {Space: NSDAV, Local: "getlastmodified"},
	{Space: NSDAV, Local: "creationdate"}, {Space: NSDAV, Local: "getcontentlength"}, {Space: NSDAV, Local: "getcontenttype"},
	{Space: NSDAV, Local: "sync-token"}, {Space: NSDAV, Local: "owner"}, {Space: NSDAV, Local: "current-user-privilege-set"},
	{Space: NSDAV, Local: "supported-report-set"}, {Space: NSDAV, Local: "current-user-principal"},
	{Space: NSCalendarServer, Local: "getctag"}, {Space: NSSCalDAV, Local: "supported-calendar-component-set"},
	{Space: NSSCalDAV, Local: "supported-calendar-data"}, {Space: NSCardDAV, Local: "supported-address-data"},
}

// collectionUpdate maps property changes to a folder update and a status
// per change: 200 for stored and for accepted dead properties, 403 for a
// protected property, and 409 for an invalid value. creating permits the
// properties that only describe a new collection's type.
func collectionUpdate(changes []propertyChange, creating bool) (service.FolderUpdate, []int) {
	var update service.FolderUpdate
	statuses := make([]int, len(changes))
	for index, change := range changes {
		statuses[index] = http.StatusOK
		value := strings.TrimSpace(change.value)
		switch change.name {
		case xml.Name{Space: NSDAV, Local: "displayname"}:
			if !change.remove && value != "" {
				update.Name = &value
			}
		case xml.Name{Space: NSAppleICal, Local: "calendar-color"}:
			if change.remove {
				value = ""
			}
			if value != "" && !colorValue.MatchString(value) {
				// Named colors are not stored; clients send #RRGGBB[AA].
				statuses[index] = http.StatusConflict
				continue
			}
			update.Color = &value
		case xml.Name{Space: NSAppleICal, Local: "calendar-order"}:
			order := 0
			if !change.remove {
				parsed, err := strconv.Atoi(value)
				if err != nil {
					statuses[index] = http.StatusConflict
					continue
				}
				order = parsed
			}
			update.Order = &order
		case xml.Name{Space: NSSCalDAV, Local: "calendar-description"}, xml.Name{Space: NSCardDAV, Local: "addressbook-description"}:
			if change.remove {
				value = ""
			}
			update.Description = &value
		default:
			creationType := change.name == xml.Name{Space: NSDAV, Local: "resourcetype"} ||
				change.name == xml.Name{Space: NSSCalDAV, Local: "supported-calendar-component-set"}
			if slices.Contains(protectedProperties, change.name) && !(creating && creationType) {
				statuses[index] = http.StatusForbidden
			}
			// Other dead properties (calendar-timezone,
			// schedule-calendar-transp, client-private ones) are accepted
			// without being stored, as before.
		}
	}
	return update, statuses
}

// failedDependency turns the statuses of an all-or-nothing request with a
// failure into 424 for the changes that would otherwise have succeeded.
func failedDependency(statuses []int) bool {
	failed := slices.ContainsFunc(statuses, func(status int) bool { return status != http.StatusOK })
	if failed {
		for index, status := range statuses {
			if status == http.StatusOK {
				statuses[index] = http.StatusFailedDependency
			}
		}
	}
	return failed
}

// changeResponse reports per-property PROPPATCH results.
func changeResponse(href string, changes []propertyChange, statuses []int) response {
	byStatus := map[int][]xml.Name{}
	var order []int
	for index, change := range changes {
		status := statuses[index]
		if _, seen := byStatus[status]; !seen {
			order = append(order, status)
		}
		byStatus[status] = append(byStatus[status], change.name)
	}
	resp := response{Href: href}
	for _, status := range order {
		resp.nameStats = append(resp.nameStats, nameStat{names: byStatus[status], status: "HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status)})
	}
	return resp
}

// handleCollectionProppatch applies a PROPPATCH to a calendar, task list,
// or address book. Apple Calendar, Thunderbird, DAVx5, and Evolution rename
// and recolor collections this way; the change is all or nothing (RFC 4918
// §9.2) and is visible to the next PROPFIND.
func (h *Handler) handleCollectionProppatch(w http.ResponseWriter, r *http.Request, username string, folder model.Folder, body []byte) {
	changes, err := parsePropertyChanges(body)
	if err != nil || len(changes) == 0 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "invalid PROPPATCH body")
		return
	}
	update, statuses := collectionUpdate(changes, false)
	if !failedDependency(statuses) && (update != service.FolderUpdate{}) {
		if _, err := h.store.FolderStore().Update(r.Context(), folder.ID, update); err != nil {
			status := http.StatusConflict
			if errors.Is(err, service.ErrForbidden) {
				status = http.StatusForbidden
			}
			for index := range statuses {
				statuses[index] = status
			}
		}
	}
	writeMultistatus(w, []response{changeResponse(buildHref(username, folder.Path)+"/", changes, statuses)})
}

// handleMkcalendar creates a calendar collection (RFC 4791 §5.3.1), applying
// the displayname, color, description, order, and component set of the
// request body as Apple Calendar, Evolution, and GNOME send them.
func (h *Handler) handleMkcalendar(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}
	folderType, ok := calendarCollectionType(body)
	if !ok {
		h.respondError(w, r, http.StatusForbidden, "supported-calendar-component", "only event calendars and task lists can be created")
		return
	}
	h.createCollection(w, r, username, parts, folderType, body)
}

// calendarCollectionType is the collection a MKCALENDAR or extended MKCOL
// asks for: a task list when its component set is VTODO only, otherwise an
// event calendar. A set naming neither VEVENT nor VTODO (a VJOURNAL
// journal) cannot be stored and is refused (RFC 4791 §5.3.1.1).
func calendarCollectionType(body []byte) (model.FolderType, bool) {
	components := requestedComponents(body)
	switch {
	case len(components) == 0 || slices.Contains(components, "VEVENT"):
		return model.FolderTypeCalendar, true
	case slices.Contains(components, "VTODO"):
		return model.FolderTypeTasks, true
	}
	return "", false
}

// createCollection creates the collection parts[0] of folderType and
// applies the properties of an MKCALENDAR or extended MKCOL body.
func (h *Handler) createCollection(w http.ResponseWriter, r *http.Request, username string, parts []string, folderType model.FolderType, body []byte) {
	if len(parts) != 1 {
		h.respondError(w, r, http.StatusForbidden, "calendar-collection-location-ok", "collections can only be created directly in the home collection")
		return
	}
	collectionPath := parts[0]
	changes, err := parsePropertyChanges(body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "invalid request body")
		return
	}
	update, statuses := collectionUpdate(changes, true)
	if failedDependency(statuses) {
		h.respondError(w, r, http.StatusForbidden, "cannot-modify-protected-property", "a requested property cannot be set")
		return
	}
	// MKCOL and MKCALENDAR need an unmapped URL (DAV:resource-must-be-null).
	if _, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath); err == nil {
		h.respondError(w, r, http.StatusConflict, "resource-must-be-null", "collection already exists")
		return
	}
	if err := h.store.FolderStore().Create(r.Context(), username, collectionPath, folderType, ""); err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}
	if update != (service.FolderUpdate{}) {
		folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
		if err == nil {
			_, err = h.store.FolderStore().Update(r.Context(), folder.ID, update)
		}
		if err != nil {
			// The request is atomic: remove the collection again.
			if folder.ID != "" {
				_ = h.store.FolderStore().Delete(r.Context(), folder.ID)
			}
			h.respondError(w, r, http.StatusConflict, "invalid-property", err.Error())
			return
		}
	}
	w.Header().Set("Location", buildHref(username, collectionPath)+"/")
	w.WriteHeader(http.StatusCreated)
}
