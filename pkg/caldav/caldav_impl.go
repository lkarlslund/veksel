package caldav

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// --- CalDAV-specific methods ---

// handleReport handles CalDAV REPORT requests (calendar-query, multiget, etc.).
func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 1 {
		if h.handlePrincipalReport(w, r) {
			return
		}
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "REPORT requires a target collection")
		return
	}

	// Read the body first so we can inspect the root element and re-parse
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}

	// Determine the report type from the XML root element
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var startElem xml.StartElement
	for {
		token, err := decoder.Token()
		if err != nil {
			h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("cannot parse REPORT body: %v", err))
			return
		}
		if se, ok := token.(xml.StartElement); ok {
			startElem = se
			break
		}
		// Skip prologue, char data, etc.
	}

	reportName := startElem.Name.Local
	if freeBusyOnly(r.Context()) && (reportName != "free-busy-query" || startElem.Name.Space != NSSCalDAV) {
		h.respondError(w, r, http.StatusForbidden, "need-privileges", "only free-busy-query is permitted on this calendar")
		return
	}
	if reportName == "sync-collection" {
		h.handleSyncCollection(w, r, username, parts, body)
		return
	}

	// Detect CardDAV vs CalDAV reports
	if isCardDAVReport(body) {
		h.handleCardDAVReport(w, r, username, parts, body, reportName)
		return
	}

	switch reportName {
	case "calendar-query":
		h.handleCalendarQuery(w, r, username, parts, body)
	case "multiget", "calendar-multiget":
		h.handleMultiget(w, r, username, parts, body)
	case "free-busy-query":
		h.handleFreeBusyQuery(w, r, username, parts, body)
	case "mkcalendar":
		// MKCALENDAR is handled via MKCOL, but some clients use REPORT
		h.handleMkcol(w, r, username, parts)
	case "schedule-inbox-query":
		h.handleScheduleInboxQuery(w, r, username, parts, body)
	case "schedule-outbox-query":
		h.handleScheduleOutboxQuery(w, r, username, parts, body)
	default:
		h.respondError(w, r, http.StatusBadRequest, "bad-report", fmt.Sprintf("unsupported report: %s", reportName))
	}
}

func (h *Handler) handleSyncCollection(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	var request syncCollection
	if err := xml.Unmarshal(body, &request); err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "invalid sync-collection report")
		return
	}
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0])
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "collection not found")
		return
	}
	reader, ok := h.store.space.(service.FolderChangeReader)
	if !ok {
		h.respondError(w, r, http.StatusNotImplemented, "sync-traversal-supported", "incremental sync is unavailable")
		return
	}
	props := reportPropRequest(request.Prop)
	// The actor reads a shared collection in its own right, as item access does.
	access := davAccess(r.Context(), "")
	scope := service.ChangeScope{FolderID: folder.ID, Object: service.ChangeObjectItem}
	limit := request.Limit.NResults
	if limit < 1 || limit > 10_000 {
		limit = 1000
	}
	itemResponse := func(item model.Item) response {
		href := buildHref(username, folder.Path, item.Name)
		if folder.Type == model.FolderTypeContacts {
			return vCardItemToPropResp(item, href)
		}
		return itemToPropResp(item, href)
	}
	responses := []response{}
	var newToken string
	clientToken := parseSyncToken(request.SyncToken)
	if clientToken == "" {
		items, listErr := h.store.space.ListItems(r.Context(), access, folder.ID, service.ItemQuery{})
		if listErr != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", listErr.Error())
			return
		}
		// RFC 6578 §3.7: an initial snapshot has no continuation, so a
		// DAV:limit it would exceed is refused rather than silently ignored.
		if request.Limit.NResults > 0 && len(items) > request.Limit.NResults {
			h.respondError(w, r, http.StatusInsufficientStorage, "number-of-matches-within-limits", "the collection holds more members than the requested limit")
			return
		}
		for _, item := range items {
			responses = append(responses, itemResponse(item))
		}
		newToken, err = reader.CurrentChangeState(r.Context(), access, scope)
	} else {
		var page service.ChangePage
		page, err = reader.ListChanges(r.Context(), access, scope, clientToken, limit)
		if err == nil {
			// Report each member once, in its final state (RFC 6578 §3.5).
			index := map[string]int{}
			add := func(resp response) {
				if at, seen := index[resp.Href]; seen {
					responses[at] = resp
					return
				}
				index[resp.Href] = len(responses)
				responses = append(responses, resp)
			}
			for _, record := range page.Records {
				for _, change := range record.Changes {
					deleted := change.Operation == service.ChangeDestroy || change.Operation == service.ChangeTrash || (change.Operation == service.ChangeMove && change.FolderID != folder.ID)
					if deleted {
						name := change.Name
						if change.PreviousFolderID == folder.ID && change.PreviousName != "" {
							name = change.PreviousName
						}
						add(response{Href: buildHref(username, folder.Path, name), Status: "HTTP/1.1 404 Not Found"})
						continue
					}
					item, getErr := h.store.space.GetItem(r.Context(), access, change.ID)
					if getErr == nil && item.FolderID == folder.ID {
						add(itemResponse(item))
					}
				}
			}
			newToken = page.NewState
			if page.HasMoreChanges {
				// RFC 6578 §3.6: a truncated page names the collection
				// with 507 so the client continues from the new token.
				responses = append(responses, response{Href: buildHref(username, folder.Path) + "/", Status: "HTTP/1.1 507 Insufficient Storage"})
			}
		}
	}
	if err != nil {
		// RFC 6578 §3.2: an unknown or expired token is 403 with the
		// DAV:valid-sync-token precondition, after which clients resync.
		h.respondError(w, r, http.StatusForbidden, "valid-sync-token", "sync token is no longer valid")
		return
	}
	props.restrict(responses)
	token := syncTokenURI(newToken)
	writeSyncMultistatus(w, responses, &token)
}

// syncTokenPrefix makes the change state a URI, as RFC 6578 §3.1 requires
// of DAV:sync-token values.
const syncTokenPrefix = "urn:veksel:sync:"

func syncTokenURI(state string) string { return syncTokenPrefix + state }

// parseSyncToken returns the change state of a client's sync token; tokens
// issued before they were URIs are accepted as they are.
func parseSyncToken(token string) string {
	return strings.TrimPrefix(strings.TrimSpace(token), syncTokenPrefix)
}

// handleCalendarMultitargetPut handles the calendar-multitarget PUT (RFC 6638 §3.7).
// It delivers an iTIP scheduling message to multiple calendar collections at once.
// The body contains the iTIP iCalendar data with a METHOD property.
func (h *Handler) handleCalendarMultitargetPut(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}

	// Validate that this contains a VCALENDAR component
	if !bytes.Contains(bytes.ToUpper(data), []byte("BEGIN:VCALENDAR")) {
		h.respondError(w, r, http.StatusBadRequest, "bad-data", "body must contain a VCALENDAR component")
		return
	}

	// Parse the iTIP message to get UID and method
	msg, err := calendar.ParseITIP(data)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid iTIP message: %v", err))
		return
	}

	// Store in the user's schedule-outbox
	h.storeScheduleOutbox(r.Context(), username, data, msg.Method)

	// If this is a REQUEST, also process it through the schedule-inbox
	// to create/update events in the calendar
	if msg.Method == calendar.MethodRequest {
		h.processScheduleInbox(r.Context(), username, data, msg.Method)
	}

	// Return 200 OK with the stored message
	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", time.Now().UnixNano()))
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

// handleCalendarQuery handles the CalDAV calendar-query REPORT.
// It searches for events matching the time range filter and returns them.
func (h *Handler) handleCalendarQuery(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	cq, err := parseCalendarQuery(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid calendar-query: %v", err))
		return
	}

	collectionPath := parts[0]
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
		return
	}

	// Parse time range from the filter (search recursively through comp-filters)
	var startT, endT time.Time
	var hasTimeRange bool
	if cq.Filter != nil && cq.Filter.CompSet != nil {
		if tr, ok := findTimeRange(cq.Filter.CompSet); ok {
			if tr.Start != "" {
				startT, err = parseCalDAVTime(tr.Start)
				if err != nil {
					h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid start time: %v", err))
					return
				}
				hasTimeRange = true
			}
			if tr.End != "" {
				endT, err = parseCalDAVTime(tr.End)
				if err != nil {
					h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid end time: %v", err))
					return
				}
				hasTimeRange = true
			}
		}
	}

	request := reportPropRequest(cq.Prop)
	wantCalendarData := request.wants(calendarDataName)
	expandStart, expandEnd, wantExpand, err := expandRange(body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid expand range: %v", err))
		return
	}

	// List all items in the calendar folder
	items, err := h.store.ItemStore().List(r.Context(), folder.ID)
	if err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", "cannot list calendar items")
		return
	}
	wantComponent := queriedComponent(cq)
	propertyFilters := cq.Filter != nil && hasPropertyFilters(cq.Filter.CompSet)

	responses := []response{}
	for _, itemKey := range items {
		item, err := h.store.ItemStore().Get(r.Context(), itemKey)
		if err != nil {
			continue
		}
		isTask := calendar.IsTask(item.Data)
		if !componentMatches(wantComponent, item.Data, isTask) {
			continue
		}
		if hasTimeRange && !objectMatchesTimeRange(item.Data, isTask, startT, endT) {
			continue
		}
		if propertyFilters && !objectMatchesPropertyFilters(item.Data, cq.Filter.CompSet) {
			continue
		}
		itemID := item.Name
		if itemID == "" {
			itemID = item.ID
		}
		// One response per object (RFC 4918 §14.24): a recurring event is
		// returned once, as stored, unless calendar-data asks for expand.
		resp := itemToPropResp(item, buildHref(username, folder.Path, itemID))
		if wantCalendarData {
			data := item.Data
			if wantExpand {
				data = expandedCalendarData(data, expandStart, expandEnd)
			}
			calData := string(data)
			resp.Prop.CalendarData = &calData
		}
		responses = append(responses, resp)
	}

	request.restrict(responses)
	writeMultistatus(w, responses)
}

// calendarDataName is the CALDAV:calendar-data property.
var calendarDataName = xml.Name{Space: NSSCalDAV, Local: "calendar-data"}

// reportPropRequest is the property request of a REPORT body's DAV:prop;
// a report without one is answered with every property.
func reportPropRequest(p *prop) propRequest {
	if p == nil {
		return propRequest{}
	}
	names := make([]xml.Name, len(p.Elements))
	for index, name := range p.Elements {
		// CARDDAV:vcard is a draft-era alias of address-data that early
		// Veksel callers send.
		if name == (xml.Name{Space: NSCardDAV, Local: "vcard"}) {
			name = addressDataName
		}
		names[index] = name
	}
	return propRequest{names: names}
}

// componentMatches applies the calendar-query component filter: the
// VCALENDAR child comp-filter names the component type an object must hold.
// Veksel stores events and tasks only, so a VJOURNAL or VFREEBUSY filter
// matches nothing.
func componentMatches(want string, data []byte, isTask bool) bool {
	switch want {
	case "":
		return true
	case "VTODO":
		return isTask
	case "VEVENT":
		return containsVEVENT(data)
	default:
		return false
	}
}

// objectMatchesTimeRange applies a calendar-query time-range to an object:
// a recurring event matches when any instance overlaps the range.
func objectMatchesTimeRange(data []byte, isTask bool, startT, endT time.Time) bool {
	if isTask {
		// RFC 4791 9.9: a task overlaps a range through its start or due
		// time; undated tasks always match.
		return taskMatchesTimeRange(data, startT, endT)
	}
	recurring := hasRecurrence(data)
	rangeEnd := endT
	if rangeEnd.IsZero() {
		// Bound an open-ended range so an unbounded rule stays cheap.
		rangeEnd = time.Now().AddDate(50, 0, 0)
		if startT.After(time.Now()) {
			rangeEnd = startT.AddDate(50, 0, 0)
		}
	}
	// RFC 4791 §9.9 overlap, with DURATION and open-ended ranges; an event
	// go-ical cannot place (a non-IANA TZID) falls back to the older
	// matchers, which know the VTIMEZONE conversions.
	if overlaps, ok := objectOverlaps(data, startT, rangeEnd); ok {
		return overlaps
	}
	if !recurring {
		return eventMatchesTimeRange(data, startT, endT)
	}
	return len(getEventOccurrences(data, startT, rangeEnd)) > 0
}

// handleMultiget handles the CalDAV multiget REPORT.
// It fetches multiple calendar objects by their hrefs.
func (h *Handler) handleMultiget(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	mg, err := parseMultiget(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid multiget: %v", err))
		return
	}

	collectionPath := parts[0]
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
		return
	}

	request := reportPropRequest(mg.Prop)
	wantCalendarData := request.wants(calendarDataName)
	expandStart, expandEnd, wantExpand, err := expandRange(body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid expand range: %v", err))
		return
	}
	responses := []response{}

	for _, href := range mg.Hrefs {
		hrefVal := strings.TrimSpace(href.Value)
		// Hrefs are percent-encoded: /dav/{username}/{calendar}/{itemID}
		itemID, ok := objectNameFromHref(hrefVal)
		var item model.Item
		if ok {
			item, err = h.store.ItemStore().Get(r.Context(), model.ItemKey(folder.ID, itemID))
		}
		if !ok || err != nil {
			// Item not found
			responses = append(responses, response{
				Href:   hrefVal,
				Status: "HTTP/1.1 404 Not Found",
			})
			continue
		}

		resp := itemToPropResp(item, hrefVal)
		if wantCalendarData {
			// Keep the metadata props (notably getetag, which sync clients
			// such as vdirsyncer require in every multiget response).
			data := item.Data
			if wantExpand {
				data = expandedCalendarData(data, expandStart, expandEnd)
			}
			calData := string(data)
			resp.Prop.CalendarData = &calData
		}
		responses = append(responses, resp)
	}

	request.restrict(responses)
	writeMultistatus(w, responses)
}

// handleGet handles GET requests for calendar and contact objects.
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		// GET on a collection — return a directory listing or error
		if len(parts) == 1 && parts[0] != "" {
			// List items in the collection via PROPFIND-style
			h.handlePropfind(w, r, username, parts)
			return
		}
		h.respondError(w, r, http.StatusNotFound, "not-found", "resource not found")
		return
	}

	collectionPath := parts[0]
	itemID := parts[1]

	// Handle VTIMEZONE requests: /dav/{user}/timezone/{TZID}
	// Per RFC 5545, clients may request VTIMEZONE components by TZID
	// TZID may contain slashes (e.g., America/New_York), so rejoin remaining parts
	if collectionPath == "timezone" {
		tzID := strings.Join(parts[1:], "/")
		h.handleVTimezoneGet(w, r, tzID)
		return
	}

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
		return
	}

	// Dispatch to file handler for files folders
	if folder.Type == model.FolderTypeFiles {
		h.handleFilesGet(w, r, username, parts)
		return
	}

	// Dispatch to CardDAV handler for contacts folders
	if folder.Type == model.FolderTypeContacts {
		h.handleCardDAVGet(w, r, username, parts)
		return
	}

	itemKey := model.ItemKey(folder.ID, itemID)
	item, err := h.store.ItemStore().Get(r.Context(), itemKey)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "calendar object not found")
		return
	}

	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
	respondCalendarData(w, item.Data, etag, item.UpdatedAt)
}

// handleVTimezoneGet handles GET requests for VTIMEZONE components.
// The client requests a specific IANA timezone by ID, and we generate
// the VTIMEZONE component from Go's time.Location data.
func (h *Handler) handleVTimezoneGet(w http.ResponseWriter, r *http.Request, tzID string) {
	if tzID == "" {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "timezone ID required")
		return
	}

	// Validate that the timezone is known
	if _, err := time.LoadLocation(tzID); err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", fmt.Sprintf("timezone %q not found", tzID))
		return
	}

	vtzData, err := generateVTimezone(tzID)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 24 hours (tz data is stable)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(vtzData))
}

// handlePut handles PUT requests for creating/updating calendar and contact objects.
func (h *Handler) handlePut(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "PUT requires a target object path")
		return
	}

	collectionPath := parts[0]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		// For schedule inbox/outbox, create the collection on first PUT
		if collectionPath == model.ScheduleInboxPath || collectionPath == model.ScheduleOutboxPath {
			h.handleSchedulePut(w, r, username, parts)
			return
		}
		h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
		return
	}

	// Dispatch to file handler for files folders
	if folder.Type == model.FolderTypeFiles {
		h.handleFilesPut(w, r, username, parts)
		return
	}

	// Dispatch to CardDAV handler for contacts folders
	if folder.Type == model.FolderTypeContacts {
		h.handleCardDAVPut(w, r, username, parts)
		return
	}

	// Handle schedule inbox/outbox — accept iTIP messages
	if folder.Type == model.FolderTypeScheduleInbox || folder.Type == model.FolderTypeScheduleOutbox {
		h.handleSchedulePut(w, r, username, parts)
		return
	}

	itemID := parts[1]

	// Read the calendar data
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}
	data = normalizeObjectBody(r.Header.Get("Content-Type"), data)

	// Each collection stores one component type (RFC 4791 5.3.2.1
	// supported-calendar-component precondition).
	if !bytes.Contains(bytes.ToUpper(data), []byte("BEGIN:VCALENDAR")) {
		h.respondError(w, r, http.StatusBadRequest, "valid-calendar-data", "body must be an iCalendar object")
		return
	}
	if folder.Type == model.FolderTypeTasks {
		if !calendar.IsTask(data) || containsVEVENT(data) {
			h.respondError(w, r, http.StatusForbidden, "supported-calendar-component", "task lists accept VTODO components only")
			return
		}
	} else if !containsVEVENT(data) {
		// A VTODO or VJOURNAL is valid iCalendar this calendar does not
		// store; python caldav and Thunderbird expect the precondition.
		h.respondError(w, r, http.StatusForbidden, "supported-calendar-component", "calendars accept VEVENT components only")
		return
	}

	// Extract UID from the VEVENT
	uid := extractUID(data)
	if uid == "" {
		uid = itemID
	}

	h.putObject(w, r, username, folder, itemID, data, map[string]string{"UID": uid})
}

// handleDelete handles DELETE requests for calendar, contact, and file objects.
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		// DELETE on a collection
		if len(parts) == 1 && parts[0] != "" {
			folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0])
			if err != nil {
				h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
				return
			}
			// Dispatch to file handler for files folders
			if folder.Type == model.FolderTypeFiles {
				h.handleFilesDelete(w, r, username, parts)
				return
			}
			// Dispatch to CardDAV handler for contacts folders
			if folder.Type == model.FolderTypeContacts {
				h.handleCardDAVDelete(w, r, username, parts)
				return
			}
			if err := h.store.FolderStore().Delete(r.Context(), folder.ID); err != nil {
				h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.respondError(w, r, http.StatusNotFound, "not-found", "resource not found")
		return
	}

	collectionPath := parts[0]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
		return
	}

	// Dispatch to file handler for files folders
	if folder.Type == model.FolderTypeFiles {
		h.handleFilesDelete(w, r, username, parts)
		return
	}

	// Dispatch to CardDAV handler for contacts folders
	if folder.Type == model.FolderTypeContacts {
		h.handleCardDAVDelete(w, r, username, parts)
		return
	}

	itemID := parts[1]

	h.deleteObject(w, r, folder, itemID, "calendar object not found")
}

// findTimeRange recursively searches comp-filters for a time-range element.
// It returns the first time-range found, or nil, false if none exists.
func findTimeRange(cf *compFilter) (*timeRange, bool) {
	if cf.TimeRange != nil {
		return cf.TimeRange, true
	}
	for _, nested := range cf.CompFilters {
		if tr, ok := findTimeRange(&nested); ok {
			return tr, true
		}
	}
	return nil, false
}

// queriedComponent returns the component a calendar-query asks for
// (VEVENT, VTODO, ...) or "" when the filter names none.
func queriedComponent(cq *calendarQuery) string {
	if cq.Filter == nil || cq.Filter.CompSet == nil {
		return ""
	}
	for _, nested := range cq.Filter.CompSet.CompFilters {
		if name := strings.ToUpper(strings.TrimSpace(nested.Name)); name != "" {
			return name
		}
	}
	return ""
}

// taskMatchesTimeRange applies the RFC 4791 9.9 VTODO overlap rules using
// DTSTART and DUE (COMPLETED and CREATED are not consulted).
func taskMatchesTimeRange(data []byte, startT, endT time.Time) bool {
	task, err := calendar.ProjectTask(data)
	if err != nil {
		return true
	}
	parse := func(value string) time.Time {
		if value == "" {
			return time.Time{}
		}
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			return parsed
		}
		parsed, _ := time.ParseInLocation(time.DateOnly, value, time.Local)
		return parsed
	}
	from, due := parse(task.Start), parse(task.Due)
	if from.IsZero() && due.IsZero() {
		return true
	}
	if due.IsZero() && !from.IsZero() {
		// DTSTART with DURATION ends at DTSTART+DURATION (RFC 4791 §9.9).
		due = from.Add(taskDuration(data))
	}
	if from.IsZero() {
		from = due
	}
	return (endT.IsZero() || from.Before(endT)) && (startT.IsZero() || !due.Before(startT))
}

// taskDuration is the DURATION of a calendar object's first VTODO, or 0.
func taskDuration(data []byte) time.Duration {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return 0
	}
	for _, child := range cal.Children {
		if child.Name != ical.CompToDo {
			continue
		}
		if prop := child.Props.Get(ical.PropDuration); prop != nil {
			if duration, err := prop.Duration(); err == nil && duration > 0 {
				return duration
			}
		}
		return 0
	}
	return 0
}

// requestedComponents lists the comp names of a MKCALENDAR or extended
// MKCOL supported-calendar-component-set.
func requestedComponents(body []byte) []string {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	inSet := false
	var names []string
	for {
		token, err := decoder.Token()
		if err != nil {
			return names
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Local == "supported-calendar-component-set" {
				inSet = true
			}
			if inSet && element.Name.Local == "comp" {
				for _, attribute := range element.Attr {
					if attribute.Name.Local == "name" {
						names = append(names, strings.ToUpper(attribute.Value))
					}
				}
			}
		case xml.EndElement:
			if element.Name.Local == "supported-calendar-component-set" {
				inSet = false
			}
		}
	}
}

// --- VEVENT parsing helpers ---

// containsVEVENT checks if the data contains a VEVENT component.
func containsVEVENT(data []byte) bool {
	return bytes.Contains(bytes.ToUpper(data), []byte("BEGIN:VEVENT"))
}

// extractUID extracts the UID property from a VEVENT.
func extractUID(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "UID:") {
			// Extract value from the original line, preserving case
			idx := strings.Index(line, ":")
			if idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

// eventMatchesTimeRange checks if a VEVENT overlaps with the given time range.
// It handles timezone-aware DTSTART/DTEND by converting to UTC for comparison.
func eventMatchesTimeRange(data []byte, startT, endT time.Time) bool {
	// Extract DTSTART and DTEND with timezone info
	dtStart, sourceTZID := extractDTStartWithTZ(data)
	dtEnd, _ := extractDTEndWithTZ(data)

	if dtStart.IsZero() && dtEnd.IsZero() {
		// No time info, include it
		return true
	}

	// If no end time, use start time
	if dtEnd.IsZero() {
		dtEnd = dtStart
	}

	// Convert timezone-aware times to UTC for comparison
	if sourceTZID != "" {
		dtStart = convertToLocalTime(dtStart, sourceTZID, "")
		dtEnd = convertToLocalTime(dtEnd, sourceTZID, "")
	}

	// Check overlap: event overlaps if event.start <= query.end && event.end >= query.start
	if !startT.IsZero() && !endT.IsZero() {
		if dtStart.After(endT) || dtEnd.Before(startT) {
			return false
		}
	}

	return true
}

// parseCalDAVTime parses a CalDAV time string (YYYYMMDDTHHMMSSZ).
func parseCalDAVTime(s string) (time.Time, error) {
	layouts := []string{
		"20060102T150405Z",
		"20060102T150405",
		"20060102",
		time.RFC3339,
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse CalDAV time: %q", s)
}

// extractDTStart extracts the DTSTART property from a VEVENT.
// For timezone-aware events (TZID parameter), it returns the UTC equivalent.
func extractDTStart(data []byte) time.Time {
	t, tzID := extractDTStartWithTZ(data)
	if tzID != "" {
		return convertToLocalTime(t, tzID, "")
	}
	return t
}

// extractDTEnd extracts the DTEND property from a VEVENT.
// For timezone-aware events (TZID parameter), it returns the UTC equivalent.
func extractDTEnd(data []byte) time.Time {
	t, tzID := extractDTEndWithTZ(data)
	if tzID != "" {
		return convertToLocalTime(t, tzID, "")
	}
	return t
}

// handleSchedulePut handles PUT to schedule-inbox or schedule-outbox collections.
// It stores iTIP scheduling messages (REQUEST, REPLY, CANCEL).
func (h *Handler) handleSchedulePut(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	itemID := parts[1]

	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}

	// Validate that this contains a VCALENDAR component
	if !bytes.Contains(bytes.ToUpper(data), []byte("BEGIN:VCALENDAR")) {
		h.respondError(w, r, http.StatusBadRequest, "bad-data", "body must contain a VCALENDAR component")
		return
	}

	collectionPath := parts[0]
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		// Create the schedule collection on first PUT
		var folderType model.FolderType
		if collectionPath == model.ScheduleInboxPath {
			folderType = model.FolderTypeScheduleInbox
		} else if collectionPath == model.ScheduleOutboxPath {
			folderType = model.FolderTypeScheduleOutbox
		} else {
			h.respondError(w, r, http.StatusNotFound, "no-calendar", "collection not found")
			return
		}
		if err := h.store.FolderStore().Create(r.Context(), username, collectionPath, folderType, ""); err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
		folder, err = h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
		if err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
	}

	// Extract UID and METHOD from the iTIP message
	uid := extractUID(data)
	method := extractMethod(data)
	if uid == "" {
		uid = itemID
	}

	// Store the scheduling message
	itemKey := model.ItemKey(folder.ID, itemID)
	item, err := h.store.ItemStore().Get(r.Context(), itemKey)

	if err != nil {
		// Create new item
		now := time.Now().UTC()
		headers := map[string]string{"UID": uid}
		if method != "" {
			headers["METHOD"] = method
		}
		item = model.Item{
			ID:           itemKey,
			FolderID:     folder.ID,
			Data:         data,
			Headers:      headers,
			Size:         int64(len(data)),
			UID:          0,
			Flags:        nil,
			InternalDate: now,
			ModSeq:       1,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := h.store.ItemStore().SetItem(r.Context(), item); err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}

		// Process schedule-inbox messages (REQUEST, CANCEL)
		if collectionPath == model.ScheduleInboxPath {
			h.processScheduleInbox(r.Context(), username, data, method)
		}

		etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
		w.Header().Set("ETag", etag)
		w.Header().Set("Location", buildHref(username, folder.Path, itemID))
		w.WriteHeader(http.StatusCreated)
	} else {
		// Update existing item
		item.Data = data
		item.Size = int64(len(data))
		item.ModSeq++
		item.UpdatedAt = time.Now().UTC()
		if item.Headers == nil {
			item.Headers = make(map[string]string)
		}
		item.Headers["UID"] = uid
		if method != "" {
			item.Headers["METHOD"] = method
		}

		if err := h.store.ItemStore().SetItem(r.Context(), item); err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}

		// Process schedule-inbox messages (REQUEST, CANCEL)
		if collectionPath == model.ScheduleInboxPath {
			h.processScheduleInbox(r.Context(), username, data, method)
		}

		etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNoContent)
	}
}

// processScheduleInbox processes iTIP messages received in the schedule-inbox.
// For REQUEST: creates/updates the event in the user's calendar and auto-accepts.
// For CANCEL: removes the event from the user's calendar.
// For REPLY: stores the response in the schedule-outbox.
func (h *Handler) processScheduleInbox(ctx context.Context, username string, data []byte, method string) {
	msg, err := calendar.ParseITIP(data)
	if err != nil {
		log.Warn("caldav: parse iTIP message", "error", err)
		return
	}

	switch method {
	case calendar.MethodRequest:
		h.handleScheduleRequest(ctx, username, msg)
	case calendar.MethodCancel:
		h.handleScheduleCancel(ctx, username, msg)
	case calendar.MethodReply, calendar.MethodCounter, calendar.MethodDeclineCounter:
		// Store replies in the schedule-outbox for the organizer to pick up
		h.storeScheduleOutbox(ctx, username, data, method)
	}
}

// handleScheduleRequest processes a calendar invitation (REQUEST).
// It creates or updates the event in the user's default calendar and
// auto-generates an ACCEPTED reply stored in the schedule-outbox.
func (h *Handler) handleScheduleRequest(ctx context.Context, username string, msg *calendar.ITIPMessage) {
	// Find the user's default calendar
	var target model.Folder
	var err error
	target, err = h.store.FolderStore().GetByPath(ctx, username, "Calendar")
	if err != nil {
		// Try to find any calendar folder for this user
		folders, ferr := h.store.FolderStore().ListForUser(ctx, username)
		if ferr != nil {
			log.Warn("caldav: schedule request - list folders", "error", ferr)
			return
		}
		for _, f := range folders {
			if f.Type == model.FolderTypeCalendar {
				target = f
				break
			}
		}
		if target.ID == "" {
			log.Warn("caldav: schedule request - no calendar found", "user", username)
			return
		}
	}

	// Build the event item ID from the UID
	itemID := sanitizeItemID(msg.UID)
	itemKey := model.ItemKey(target.ID, itemID)

	// Check if event already exists (update case)
	existing, err := h.store.ItemStore().Get(ctx, itemKey)
	var initialModSeq uint64 = 1
	var initialCreatedAt time.Time = time.Now().UTC()
	if err == nil {
		initialModSeq = existing.ModSeq + 1
		initialCreatedAt = existing.CreatedAt
	}

	now := time.Now().UTC()
	item := model.Item{
		ID:           itemKey,
		FolderID:     target.ID,
		Data:         msg.Raw,
		Headers:      map[string]string{"UID": msg.UID, "METHOD": calendar.MethodRequest},
		Size:         int64(len(msg.Raw)),
		UID:          0,
		Flags:        []string{"\\Seen"},
		InternalDate: now,
		ModSeq:       initialModSeq,
		CreatedAt:    initialCreatedAt,
		UpdatedAt:    now,
	}

	if err := h.store.ItemStore().SetItem(ctx, item); err != nil {
		log.Error("caldav: schedule request - store event", "error", err)
		return
	}

	// Auto-generate an ACCEPTED reply and store in schedule-outbox
	replyData, err := calendar.BuildReply(msg, buildCalAddress(username), calendar.PartStatAccepted)
	if err != nil {
		log.Error("caldav: schedule request - build reply", "error", err)
		return
	}
	h.storeScheduleOutbox(ctx, username, replyData, calendar.MethodReply)
	log.Info("caldav: schedule request processed", "user", username, "uid", msg.UID, "summary", msg.Summary)
}

// handleScheduleCancel processes a calendar cancellation (CANCEL).
// It removes the event from the user's calendar.
func (h *Handler) handleScheduleCancel(ctx context.Context, username string, msg *calendar.ITIPMessage) {
	// Find the event in the user's calendars
	folders, err := h.store.FolderStore().ListForUser(ctx, username)
	if err != nil {
		log.Warn("caldav: schedule cancel - list folders", "error", err)
		return
	}

	for _, f := range folders {
		if f.Type != model.FolderTypeCalendar {
			continue
		}
		// Search for the event by UID
		items, err := h.store.ItemStore().List(ctx, f.ID)
		if err != nil {
			continue
		}
		for _, itemKey := range items {
			item, err := h.store.ItemStore().Get(ctx, itemKey)
			if err != nil {
				continue
			}
			if item.Headers != nil && item.Headers["UID"] == msg.UID {
				if err := h.store.ItemStore().Delete(ctx, itemKey); err != nil {
					log.Error("caldav: schedule cancel - delete event", "error", err)
				} else {
					log.Info("caldav: schedule cancel processed", "user", username, "uid", msg.UID)
					return
				}
			}
		}
	}
}

// storeScheduleOutbox stores a scheduling message in the schedule-outbox.
func (h *Handler) storeScheduleOutbox(ctx context.Context, username string, data []byte, method string) {
	folder, err := h.store.FolderStore().GetByPath(ctx, username, model.ScheduleOutboxPath)
	if err != nil {
		if err := h.store.FolderStore().Create(ctx, username, model.ScheduleOutboxPath, model.FolderTypeScheduleOutbox, ""); err != nil {
			log.Error("caldav: create schedule-outbox", "error", err)
			return
		}
		folder, err = h.store.FolderStore().GetByPath(ctx, username, model.ScheduleOutboxPath)
		if err != nil {
			log.Error("caldav: get schedule-outbox", "error", err)
			return
		}
	}

	// Generate a unique item ID for the outbox message
	msg, _ := calendar.ParseITIP(data)
	var itemID string
	if msg != nil && msg.UID != "" {
		itemID = fmt.Sprintf("reply-%s-%d", sanitizeItemID(msg.UID), time.Now().UnixNano())
	} else {
		itemID = fmt.Sprintf("outbox-%d", time.Now().UnixNano())
	}

	itemKey := model.ItemKey(folder.ID, itemID)
	now := time.Now().UTC()
	item := model.Item{
		ID:           itemKey,
		FolderID:     folder.ID,
		Data:         data,
		Headers:      map[string]string{"METHOD": method},
		Size:         int64(len(data)),
		UID:          0,
		Flags:        nil,
		InternalDate: now,
		ModSeq:       1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.store.ItemStore().SetItem(ctx, item); err != nil {
		log.Error("caldav: store schedule-outbox", "error", err)
	}
}

// buildCalAddress builds a CAL-ADDRESS (mailto:xxx) for a username.
func buildCalAddress(username string) string {
	// Try to find the user's primary email address
	return "mailto:" + strings.ToLower(username)
}

// sanitizeItemID creates a safe item ID from a UID by replacing problematic characters.
func sanitizeItemID(uid string) string {
	// Remove angle brackets and replace problematic characters
	s := strings.ReplaceAll(uid, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// extractMethod extracts the METHOD property from a VCALENDAR.
func extractMethod(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "METHOD:") {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

// --- Free/Busy Query (RFC 4791 §7.10) ---

// defaultFreeBusySpan completes a time-range missing its start or end;
// maxFreeBusySpan bounds the recurrence expansion one query may demand.
const (
	defaultFreeBusySpan = 31 * 24 * time.Hour
	maxFreeBusySpan     = 2 * 366 * 24 * time.Hour
)

// freeBusyOnly reports whether the request may only run free-busy-query.
func freeBusyOnly(ctx context.Context) bool {
	only, _ := ctx.Value(freeBusyOnlyKey{}).(bool)
	return only
}

// handleFreeBusyQuery answers the CalDAV free-busy-query REPORT with one
// VFREEBUSY covering the requested range. Busy time comes from the shared
// calendar range index, so recurrence, overrides, EXDATE, transparency,
// cancellation and tentative status are handled exactly as in the web
// scheduling assistant, iMIP resource booking and published free/busy.
// The requester needs read or read-free-busy on the calendar; the owner's
// events are then read with the owner's access and only their busy times
// leave the server.
func (h *Handler) handleFreeBusyQuery(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	fbq, err := parseFreeBusyQuery(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid free-busy-query: %v", err))
		return
	}
	startStr, endStr := fbq.GetStart(), fbq.GetEnd()
	if startStr == "" && endStr == "" {
		h.respondError(w, r, http.StatusBadRequest, "valid-filter", "free-busy-query requires a time-range")
		return
	}
	var startT, endT time.Time
	if startStr != "" {
		if startT, err = parseCalDAVTime(startStr); err != nil {
			h.respondError(w, r, http.StatusBadRequest, "valid-filter", fmt.Sprintf("invalid start time: %v", err))
			return
		}
	}
	if endStr != "" {
		if endT, err = parseCalDAVTime(endStr); err != nil {
			h.respondError(w, r, http.StatusBadRequest, "valid-filter", fmt.Sprintf("invalid end time: %v", err))
			return
		}
	}
	if startT.IsZero() {
		startT = endT.Add(-defaultFreeBusySpan)
	}
	if endT.IsZero() {
		endT = startT.Add(defaultFreeBusySpan)
	}
	if !endT.After(startT) || endT.Sub(startT) > maxFreeBusySpan {
		h.respondError(w, r, http.StatusBadRequest, "valid-filter", "time-range end must follow its start by at most two years")
		return
	}

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0])
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-calendar", "calendar not found")
		return
	}
	if folder.Type != model.FolderTypeCalendar {
		h.respondError(w, r, http.StatusForbidden, "supported-report", "free-busy-query applies to calendar collections")
		return
	}
	if !h.mayReadFreeBusy(r.Context(), folder) {
		h.respondError(w, r, http.StatusForbidden, "need-privileges", "read-free-busy privilege required")
		return
	}

	periods, err := h.calendars.OwnerBusy(r.Context(), h.store.space, h.store.users, folder.UserID, []model.Folder{folder}, startT, endT, 0)
	if err != nil {
		_ = noteDAVError(r.Context(), err)
		log.Error("caldav: free-busy-query", "folder", folder.ID, "error", err)
		h.respondError(w, r, http.StatusInternalServerError, "server-error", "cannot compute free/busy time")
		return
	}
	now := time.Now().UTC()
	uid := fmt.Sprintf("freebusy-%d@veksel", now.UnixNano())
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(calendarindex.EncodeVFreeBusy(periods, startT, endT, now, uid, "-//Veksel//CalDAV//EN"))
}

// mayReadFreeBusy reports whether the request's actor holds CALDAV:read or
// CALDAV:read-free-busy (RFC 4791 §6.1.1) on folder.
func (h *Handler) mayReadFreeBusy(ctx context.Context, folder model.Folder) bool {
	actor, _ := ctx.Value(authenticatedUserKey{}).(string)
	if actor == "" || strings.EqualFold(actor, folder.UserID) {
		return actor != ""
	}
	for _, action := range []authz.Action{authz.CalendarFreeBusyRead, authz.FolderItemsRead} {
		decision, err := h.authorizer.Check(ctx, authz.Request{
			Actor:    model.PrincipalRef{Kind: model.PrincipalUser, ID: actor},
			Action:   action,
			Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID},
		})
		if err == nil && decision.Allowed {
			return true
		}
	}
	return false
}

// extractIsAllDay checks if the VEVENT uses DATE (all-day) values.
func extractIsAllDay(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upperLine := strings.ToUpper(line)
		// Check for VALUE=DATE parameter on DTSTART or DTEND
		if strings.Contains(upperLine, "VALUE=DATE") {
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				propName := strings.ToUpper(line[:colonIdx])
				// Strip parameters after ;
				if semiIdx := strings.Index(propName, ";"); semiIdx > 0 {
					propName = propName[:semiIdx]
				}
				if propName == "DTSTART" || propName == "DTEND" {
					return true
				}
			}
		}
		// Also check if the value looks like a DATE (8 chars: YYYYMMDD).
		// The colon is found in line itself: upper-casing can change byte
		// lengths, so an index into upperLine may not fit line.
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		propName := strings.ToUpper(line[:colonIdx])
		// Strip parameters after ;
		if semiIdx := strings.Index(propName, ";"); semiIdx > 0 {
			propName = propName[:semiIdx]
		}
		if propName == "DTSTART" || propName == "DTEND" {
			val := strings.TrimSpace(line[colonIdx+1:])
			// DATE values are exactly 8 digits with no T
			if len(val) == 8 {
				isDate := true
				for _, c := range val {
					if c < '0' || c > '9' {
						isDate = false
						break
					}
				}
				if isDate {
					return true
				}
			}
		}
	}
	return false
}

// --- Schedule Inbox/Outbox (RFC 7959) ---

// handleScheduleInboxQuery handles the schedule-inbox-query REPORT (RFC 7959).
// It lists iTIP scheduling messages stored in the user's schedule-inbox.
func (h *Handler) handleScheduleInboxQuery(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	_, err := parseScheduleInboxQuery(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid schedule-inbox-query: %v", err))
		return
	}

	// Use the schedule-inbox virtual collection
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, model.ScheduleInboxPath)
	if err != nil {
		// Create it on first access
		if err := h.store.FolderStore().Create(r.Context(), username, model.ScheduleInboxPath, model.FolderTypeScheduleInbox, ""); err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
		folder, err = h.store.FolderStore().GetByPath(r.Context(), username, model.ScheduleInboxPath)
		if err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
	}

	var responses []response
	items, err := h.store.ItemStore().List(r.Context(), folder.ID)
	if err != nil {
		writeMultistatus(w, responses)
		return
	}

	for _, itemKey := range items {
		item, err := h.store.ItemStore().Get(r.Context(), itemKey)
		if err != nil {
			continue
		}
		itemID := item.Name
		if itemID == "" {
			itemID = item.ID
		}
		itemHref := buildHref(username, folder.Path, itemID)
		resp := itemToPropResp(item, itemHref)
		responses = append(responses, resp)
	}

	writeMultistatus(w, responses)
}

// handleScheduleOutboxQuery handles the schedule-outbox-query REPORT (RFC 7959).
// It lists iTIP scheduling messages stored in the user's schedule-outbox.
func (h *Handler) handleScheduleOutboxQuery(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	_, err := parseScheduleOutboxQuery(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid schedule-outbox-query: %v", err))
		return
	}

	// Use the schedule-outbox virtual collection
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, model.ScheduleOutboxPath)
	if err != nil {
		// Create it on first access
		if err := h.store.FolderStore().Create(r.Context(), username, model.ScheduleOutboxPath, model.FolderTypeScheduleOutbox, ""); err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
		folder, err = h.store.FolderStore().GetByPath(r.Context(), username, model.ScheduleOutboxPath)
		if err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
	}

	var responses []response
	items, err := h.store.ItemStore().List(r.Context(), folder.ID)
	if err != nil {
		writeMultistatus(w, responses)
		return
	}

	for _, itemKey := range items {
		item, err := h.store.ItemStore().Get(r.Context(), itemKey)
		if err != nil {
			continue
		}
		itemID := item.Name
		if itemID == "" {
			itemID = item.ID
		}
		itemHref := buildHref(username, folder.Path, itemID)
		resp := itemToPropResp(item, itemHref)
		responses = append(responses, resp)
	}

	writeMultistatus(w, responses)
}
