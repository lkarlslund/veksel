package caldav

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- CardDAV addressbook-query REPORT (RFC 6352 Section 7.6) ---

// handleAddressbookQuery handles the CardDAV addressbook-query REPORT.
// It searches contacts matching the vCard property filters and returns them.
func (h *Handler) handleAddressbookQuery(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	aq, err := parseAddressbookQuery(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid addressbook-query: %v", err))
		return
	}

	collectionPath := parts[0]
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-addressbook", "address book not found")
		return
	}

	// Verify this is a contacts folder
	if folder.Type != model.FolderTypeContacts {
		h.respondError(w, r, http.StatusNotFound, "no-addressbook", "not an address book")
		return
	}

	// Extract filter criteria from the query
	matches := func(data []byte) bool { return true }
	if aq.Filter != nil && len(aq.Filter.PropFilters) > 0 {
		matches = func(data []byte) bool { return cardMatchesQuery(data, aq.Filter) }
	} else if filters := extractCardDAVFilters(aq.Filter); len(filters) > 0 {
		matches = func(data []byte) bool { return vCardMatchesFilters(data, filters) }
	}
	limit := 0
	if aq.Limit != nil && aq.Limit.NResults > 0 {
		limit = aq.Limit.NResults
	}

	request := reportPropRequest(aq.Prop)
	wantVCardData := request.wants(addressDataName)

	// List all items in the addressbook folder
	items, err := h.store.ItemStore().List(r.Context(), folder.ID)
	if err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", "cannot list addressbook items")
		return
	}

	responses := []response{}
	for _, itemKey := range items {
		item, err := h.store.ItemStore().Get(r.Context(), itemKey)
		if err != nil {
			continue
		}

		// Filter by vCard property criteria
		if !matches(item.Data) {
			continue
		}
		if limit > 0 && len(responses) == limit {
			// RFC 6352 §8.6.1: a truncated result names the request URI
			// with 507.
			responses = append(responses, response{Href: buildHref(username, folder.Path) + "/", Status: "HTTP/1.1 507 Insufficient Storage"})
			break
		}

		itemID := item.Name
		if itemID == "" {
			itemID = item.ID
		}
		itemHref := buildHref(username, folder.Path, itemID)

		resp := vCardItemToPropResp(item, itemHref)

		// Keep getetag beside the vCard (Evolution and Apple need both).
		if wantVCardData {
			vcardData := string(item.Data)
			resp.Prop.VCardData = &vcardData
		}

		responses = append(responses, resp)
	}

	request.restrict(responses)
	writeMultistatus(w, responses)
}

// --- CardDAV multiget REPORT (RFC 6352 Section 7.5) ---

// handleCardDAVMultiget handles the CardDAV multiget REPORT.
// It fetches multiple vCard objects by their hrefs.
func (h *Handler) handleCardDAVMultiget(w http.ResponseWriter, r *http.Request, username string, parts []string, body []byte) {
	mg, err := parseCardDAVMultiget(bytes.NewReader(body))
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", fmt.Sprintf("invalid multiget: %v", err))
		return
	}

	collectionPath := parts[0]
	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-addressbook", "address book not found")
		return
	}

	request := reportPropRequest(mg.Prop)
	wantVCardData := request.wants(addressDataName)
	responses := []response{}

	for _, href := range mg.Hrefs {
		hrefVal := strings.TrimSpace(href.Value)
		// Hrefs are percent-encoded: /dav/{username}/{addressbook}/{itemID}
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

		resp := vCardItemToPropResp(item, hrefVal)
		if wantVCardData {
			vcardData := string(item.Data)
			resp.Prop.VCardData = &vcardData
		}
		responses = append(responses, resp)
	}

	request.restrict(responses)
	writeMultistatus(w, responses)
}

// addressDataName is the CARDDAV:address-data property.
var addressDataName = xml.Name{Space: NSCardDAV, Local: "address-data"}

// --- CardDAV PUT/GET/DELETE for contact objects ---

// handleCardDAVGet handles GET requests for vCard objects.
func (h *Handler) handleCardDAVGet(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		// GET on an addressbook collection — return a directory listing
		if len(parts) == 1 && parts[0] != "" {
			h.handlePropfind(w, r, username, parts)
			return
		}
		h.respondError(w, r, http.StatusNotFound, "not-found", "resource not found")
		return
	}

	collectionPath := parts[0]
	itemID := parts[1]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-addressbook", "address book not found")
		return
	}

	itemKey := model.ItemKey(folder.ID, itemID)
	item, err := h.store.ItemStore().Get(r.Context(), itemKey)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "contact not found")
		return
	}

	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
	respondVCardData(w, item.Data, etag, item.UpdatedAt)
}

// handleCardDAVPut handles PUT requests for creating/updating vCard objects.
func (h *Handler) handleCardDAVPut(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "PUT requires a target contact path")
		return
	}

	collectionPath := parts[0]
	itemID := parts[1]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-addressbook", "address book not found")
		return
	}

	// Read the vCard data
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
		return
	}
	data = normalizeObjectBody(r.Header.Get("Content-Type"), data)

	// Validate that this is a vCard
	if !containsVCARD(data) {
		h.respondError(w, r, http.StatusBadRequest, "bad-data", "body must contain a VCARD component")
		return
	}

	// Extract UID from the vCard
	uid := extractVCARDUID(data)
	if uid == "" {
		uid = itemID
	}

	h.putObject(w, r, username, folder, itemID, data, map[string]string{"UID": uid})
}

// handleCardDAVDelete handles DELETE requests for vCard objects.
func (h *Handler) handleCardDAVDelete(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		// DELETE on an addressbook collection
		if len(parts) == 1 && parts[0] != "" {
			folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0])
			if err != nil {
				h.respondError(w, r, http.StatusNotFound, "no-addressbook", "address book not found")
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
	itemID := parts[1]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-addressbook", "address book not found")
		return
	}

	h.deleteObject(w, r, folder, itemID, "contact not found")
}

// --- CardDAV-aware PROPFIND for addressbooks ---

// propfindAddressbook returns responses for an addressbook collection.
// Similar to propfindCollection but uses addressbook resource type.
func (h *Handler) propfindAddressbook(ctx context.Context, username, collectionPath string, pf *propfind, depth string) ([]response, error) {
	folder, err := h.store.FolderStore().GetByPath(ctx, username, collectionPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResourceNotFound, err)
	}

	href := buildHref(username, folder.Path) + "/"
	collection := folderToAddressbookResp(folder, href)
	h.decorateCollection(ctx, folder, &collection)
	responses := []response{collection}

	if depth == "0" {
		return responses, nil
	}

	// Only an explicit address-data request returns vCard bodies.
	wantVCardData := pf.Prop != nil && requestFor(pf).wants(xml.Name{Space: NSCardDAV, Local: "address-data"})

	// List items in the addressbook
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

		resp := vCardItemToPropResp(item, itemHref)
		if wantVCardData {
			vcardData := string(item.Data)
			resp.Prop.VCardData = &vcardData
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

// --- Filter extraction and matching ---

// cardDAVFilter represents a parsed vCard property filter from a CardDAV query.
type cardDAVFilter struct {
	PropName  string // e.g. "FN", "N", "EMAIL", "TEL", "CATEGORIES"
	TextMatch string // the text to match (case-insensitive)
}

// extractCardDAVFilters parses the filter from an addressbook-query and returns
// a list of property filters to match against.
func extractCardDAVFilters(f *carddavFilter) []cardDAVFilter {
	if f == nil || f.CompSet == nil {
		return nil
	}
	return extractCardDAVFiltersFromComp(f.CompSet)
}

// extractCardDAVFiltersFromComp recursively extracts property filters from comp-filters.
func extractCardDAVFiltersFromComp(cf *carddavCompFilter) []cardDAVFilter {
	var filters []cardDAVFilter
	for _, pf := range cf.PropFilters {
		if pf.TextMatch != nil && pf.TextMatch.TextValue != "" {
			filters = append(filters, cardDAVFilter{
				PropName:  pf.PropName,
				TextMatch: pf.TextMatch.TextValue,
			})
		}
	}
	for _, nested := range cf.CompFilters {
		filters = append(filters, extractCardDAVFiltersFromComp(&nested)...)
	}
	return filters
}

// vCardMatchesFilters checks if a vCard matches all the given filters.
// All filters must match (AND logic).
// CATEGORIES filters use exact category matching (case-insensitive).
func vCardMatchesFilters(data []byte, filters []cardDAVFilter) bool {
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		if strings.EqualFold(f.PropName, "CATEGORIES") {
			if !model.VCardHasCategory(data, f.TextMatch) {
				return false
			}
		} else {
			if !vCardPropertyMatches(data, f.PropName, f.TextMatch) {
				return false
			}
		}
	}
	return true
}
