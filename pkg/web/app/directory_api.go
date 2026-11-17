package app

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/directory"
)

// DirectoryControl is the administration boundary of LDAP directory accounts.
type DirectoryControl interface {
	Status(context.Context) (directory.Status, error)
	Sync(ctx context.Context, actor string) (directory.SyncResult, error)
	Test(context.Context) (directory.Diagnostic, error)
}

// ConfigureDirectory installs directory account administration.
func (h *Handler) ConfigureDirectory(control DirectoryControl) { h.directory = control }

func (h *Handler) requireDirectory(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireAdminAPI(w, r) {
		return false
	}
	if h.directory == nil {
		jsonError(w, http.StatusServiceUnavailable, "directory accounts are unavailable")
		return false
	}
	return true
}

func (h *Handler) apiAdminDirectory(w http.ResponseWriter, r *http.Request) {
	if !h.requireDirectory(w, r) {
		return
	}
	status, err := h.directory.Status(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiAdminDirectorySync(w http.ResponseWriter, r *http.Request) {
	if !h.requireDirectory(w, r) {
		return
	}
	result, err := h.directory.Sync(r.Context(), currentActor(r).ID)
	switch {
	case errors.Is(err, directory.ErrSyncRunning):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, directory.ErrDisabled):
		jsonError(w, http.StatusConflict, "enable directory accounts before syncing")
	default:
		// A failed sync is still a recorded result the page shows.
		jsonResponse(w, http.StatusOK, result)
	}
}

func (h *Handler) apiAdminDirectoryTest(w http.ResponseWriter, r *http.Request) {
	if !h.requireDirectory(w, r) {
		return
	}
	diagnostic, err := h.directory.Test(r.Context())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit.Log(currentActor(r).ID, "directory.test", "ldap", map[string]string{"ok": strconv.FormatBool(diagnostic.OK)})
	jsonResponse(w, http.StatusOK, diagnostic)
}
