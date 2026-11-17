package caldav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// errPreconditionFailed reports that a conditional write lost a race with a
// concurrent change after its If-Match or If-None-Match check.
var errPreconditionFailed = errors.New("precondition failed")

// itemETag is the strong entity tag of a stored DAV object.
func itemETag(item model.Item) string {
	return fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
}

// conditionalRequest reports whether r carries If-Match or If-None-Match.
func conditionalRequest(r *http.Request) bool {
	return r.Header.Get("If-Match") != "" || r.Header.Get("If-None-Match") != ""
}

// preconditionFailed evaluates If-Match and If-None-Match (RFC 9110 §13.1.1,
// §13.1.2) for a state-changing request on a resource that exists with etag
// or does not exist. Clients create with If-None-Match: * and update or
// delete with If-Match: "<etag>", and expect 412 when either no longer
// holds rather than a silent overwrite.
func preconditionFailed(r *http.Request, exists bool, etag string) bool {
	if header := r.Header.Get("If-Match"); header != "" {
		if !exists || !entityTagListMatches(header, etag) {
			return true
		}
	}
	if header := r.Header.Get("If-None-Match"); header != "" {
		if exists && entityTagListMatches(header, etag) {
			return true
		}
	}
	return false
}

// entityTagListMatches reports whether a comma-separated entity-tag list,
// or "*", matches etag. Weak tags compare by their opaque value.
func entityTagListMatches(header, etag string) bool {
	for candidate := range strings.SplitSeq(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
	}
	return false
}

// normalizeObjectBody prepares an iCalendar or vCard PUT body for storage,
// which is always served as UTF-8: a UTF-8 byte order mark is dropped and a
// body declared as ISO-8859-1 (older Outlook connectors and vCard 2.1
// exporters) is transcoded. Other bodies are stored as sent.
func normalizeObjectBody(contentType string, data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if utf8.Valid(data) {
		return data
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return data
	}
	switch strings.ToLower(params["charset"]) {
	case "iso-8859-1", "iso8859-1", "latin1", "l1":
		var out strings.Builder
		out.Grow(len(data) + len(data)/8)
		for _, b := range data {
			out.WriteRune(rune(b))
		}
		return []byte(out.String())
	}
	return data
}

// putObject creates or replaces the object itemID in folder from a PUT
// body, honoring If-Match and If-None-Match, and answers with the ETag the
// store assigned so a following If-Match or sync comparison sees the same
// value as GET and PROPFIND.
func (h *Handler) putObject(w http.ResponseWriter, r *http.Request, username string, folder model.Folder, itemID string, data []byte, headers map[string]string) {
	existing, err := h.store.ItemStore().Get(r.Context(), model.ItemKey(folder.ID, itemID))
	exists := err == nil
	if preconditionFailed(r, exists, itemETag(existing)) {
		h.respondError(w, r, http.StatusPreconditionFailed, "precondition-failed", "the resource does not match the request preconditions")
		return
	}
	var existingPtr *model.Item
	if exists {
		existingPtr = &existing
	}
	stored, err := h.store.ItemStore().Write(r.Context(), folder.ID, itemID, existingPtr, data, headers, conditionalRequest(r))
	if errors.Is(err, errPreconditionFailed) {
		h.respondError(w, r, http.StatusPreconditionFailed, "precondition-failed", "the resource changed while it was being written")
		return
	}
	if err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}
	var previous []byte
	if exists {
		previous = existing.Data
	}
	if h.replyAsAttendee(r.Context(), folder, stored, previous) {
		// The scheduling reply rewrote the object, so the stored ETag is
		// stale; RFC 4791 §5.3.4 then omits it and the client refetches.
	} else {
		w.Header().Set("ETag", itemETag(stored))
	}
	if exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Location", buildHref(username, folder.Path, itemID))
	w.WriteHeader(http.StatusCreated)
}

// Write creates the object name in folderID, or replaces existing, and
// returns the stored item. A conditional write uses the store's atomic
// compare-and-swap so a change between the precondition check and the write
// fails with errPreconditionFailed instead of being overwritten.
func (s *davItems) Write(ctx context.Context, folderID, name string, existing *model.Item, data []byte, headers map[string]string, conditional bool) (model.Item, error) {
	access := davAccess(ctx, "")
	if existing != nil {
		merged := make(map[string]string, len(existing.Headers)+len(headers))
		maps.Copy(merged, existing.Headers)
		maps.Copy(merged, headers)
		var (
			item model.Item
			err  error
		)
		if updater, ok := s.space.(service.ConditionalItemUpdater); ok && conditional && existing.ModSeq != 0 {
			item, err = updater.UpdateItemIfModSeq(ctx, access, existing.ID, existing.ModSeq, data, merged)
		} else {
			item, err = s.space.UpdateItem(ctx, access, existing.ID, data, merged)
		}
		if errors.Is(err, service.ErrItemUpdateConflict) {
			return model.Item{}, errPreconditionFailed
		}
		return item, noteDAVError(ctx, err)
	}
	input := service.ItemInput{Name: name, Data: data, Headers: headers}
	var (
		item model.Item
		err  error
	)
	if creator, ok := s.space.(service.ExclusiveItemCreator); ok && conditional {
		item, err = creator.CreateItemIfAbsent(ctx, access, folderID, input)
	} else {
		item, err = s.space.CreateItem(ctx, access, folderID, input)
	}
	if errors.Is(err, store.ErrExists) {
		return model.Item{}, errPreconditionFailed
	}
	return item, noteDAVError(ctx, err)
}

// deleteObject removes the object itemID from folder, honoring If-Match so a
// client deleting the version it last saw does not remove a newer one.
func (h *Handler) deleteObject(w http.ResponseWriter, r *http.Request, folder model.Folder, itemID, notFound string) {
	itemKey := model.ItemKey(folder.ID, itemID)
	existing, err := h.store.ItemStore().Get(r.Context(), itemKey)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", notFound)
		return
	}
	if preconditionFailed(r, true, itemETag(existing)) {
		h.respondError(w, r, http.StatusPreconditionFailed, "precondition-failed", "the resource does not match the request preconditions")
		return
	}
	if err := h.store.ItemStore().Delete(r.Context(), itemKey); err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", notFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
