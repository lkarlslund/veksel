package caldav

import (
	"context"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

// handleObjectTransfer moves or copies a calendar object or vCard to the
// Destination URL (RFC 4918 §9.8, §9.9). Apple Calendar moves an event to
// another calendar this way and then expects it only at the destination;
// the request used to be acknowledged with 204 and ignored.
func (h *Handler) handleObjectTransfer(w http.ResponseWriter, r *http.Request, username string, source model.Folder, itemID string, move bool) {
	item, err := h.store.ItemStore().Get(r.Context(), model.ItemKey(source.ID, itemID))
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "source object not found")
		return
	}
	destParts := parseDestinationParts(parseDestination(r.Header.Get("Destination")))
	if len(destParts) != 3 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "Destination must name an object in a collection")
		return
	}
	if !strings.EqualFold(destParts[0], source.UserID) {
		h.respondError(w, r, http.StatusBadGateway, "bad-destination", "objects can only be moved within one account")
		return
	}
	dest, err := h.store.FolderStore().GetByPath(r.Context(), source.UserID, destParts[1])
	if err != nil {
		h.respondError(w, r, http.StatusConflict, "no-destination", "destination collection not found")
		return
	}
	if !acceptsObject(dest, item.Data) {
		h.respondError(w, r, http.StatusForbidden, "supported-calendar-component", "the destination collection does not store this kind of object")
		return
	}
	if dest.ID == source.ID && destParts[2] == itemID {
		h.respondError(w, r, http.StatusForbidden, "same-resource", "source and destination are the same")
		return
	}
	status := http.StatusCreated
	if existing, err := h.store.ItemStore().Get(r.Context(), model.ItemKey(dest.ID, destParts[2])); err == nil {
		// Overwrite defaults to T (RFC 4918 §10.6).
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("Overwrite")), "F") {
			h.respondError(w, r, http.StatusPreconditionFailed, "precondition-failed", "destination exists and Overwrite is F")
			return
		}
		if err := h.store.ItemStore().Delete(r.Context(), existing.ID); err != nil {
			h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
			return
		}
		status = http.StatusNoContent
	}
	var result model.Item
	if move {
		result, err = h.store.ItemStore().Move(r.Context(), item.ID, dest.ID, destParts[2])
	} else {
		result, err = h.store.ItemStore().Copy(r.Context(), item.ID, dest.ID, destParts[2])
	}
	if err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}
	w.Header().Set("ETag", itemETag(result))
	if status == http.StatusCreated {
		w.Header().Set("Location", buildHref(dest.UserID, dest.Path, destParts[2]))
	}
	w.WriteHeader(status)
}

// acceptsObject reports whether folder stores the kind of object data is.
func acceptsObject(folder model.Folder, data []byte) bool {
	switch folder.Type {
	case model.FolderTypeContacts:
		return containsVCARD(data)
	case model.FolderTypeTasks:
		return calendar.IsTask(data) && !containsVEVENT(data)
	case model.FolderTypeCalendar:
		return containsVEVENT(data)
	}
	return false
}

// Copy duplicates an object into destinationFolderID under destinationName.
func (s *davItems) Copy(ctx context.Context, id, destinationFolderID, destinationName string) (model.Item, error) {
	item, err := s.Get(ctx, id)
	if err != nil {
		return model.Item{}, err
	}
	copied, err := s.space.CopyItem(ctx, davAccess(ctx, ""), item.ID, destinationFolderID, destinationName)
	return copied, noteDAVError(ctx, err)
}
