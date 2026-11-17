package app

import (
	"errors"
	"net/http"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func (h *Handler) itemHistory() (service.ItemHistoryFolderSpace, error) {
	history, ok := h.folderSpace.(service.ItemHistoryFolderSpace)
	if !ok {
		return nil, service.ErrItemHistoryUnavailable
	}
	return history, nil
}

func (h *Handler) apiItemHistoryPolicy(w http.ResponseWriter, r *http.Request) {
	history, err := h.itemHistory()
	if err != nil {
		apiError(w, err)
		return
	}
	folderID := r.PathValue("id")
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	policy, err := history.GetItemHistoryPolicy(r.Context(), access, folderID)
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.folderSpace.GetFolder(r.Context(), access, folderID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"folder_id": folder.ID,
		"policy":    policy,
		"accounting": map[string]any{
			"versions":      folder.HistoryVersionCount,
			"logical_bytes": folder.HistoryLogicalBytes,
			"ready":         folder.HistoryUsageVersion == 1 || (folder.HistoryUsageVersion == 0 && folder.HistoryVersionCount == 0),
		},
	})
}

func (h *Handler) apiConfigureItemHistory(w http.ResponseWriter, r *http.Request) {
	history, err := h.itemHistory()
	if err != nil {
		apiError(w, err)
		return
	}
	var policy model.ItemHistoryPolicy
	if err := decodeJSON(r, &policy); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	folder, err := history.ConfigureItemHistory(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.PathValue("id"), policy)
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "folder.history.configured", folder.ID, map[string]any{"enabled": folder.History.Enabled})
	jsonResponse(w, http.StatusOK, folder)
}

func (h *Handler) apiItemVersions(w http.ResponseWriter, r *http.Request) {
	history, err := h.itemHistory()
	if err != nil {
		apiError(w, err)
		return
	}
	versions, err := history.ListItemVersions(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.PathValue("id"), r.PathValue("itemID"))
	if err != nil {
		apiError(w, err)
		return
	}
	if versions == nil {
		versions = []model.ItemVersion{}
	}
	jsonResponse(w, http.StatusOK, map[string]any{"versions": versions, "count": len(versions)})
}

func (h *Handler) apiItemVersion(w http.ResponseWriter, r *http.Request) {
	history, err := h.itemHistory()
	if err != nil {
		apiError(w, err)
		return
	}
	version, err := history.GetItemVersion(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.PathValue("id"), r.PathValue("itemID"), r.PathValue("versionID"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, version)
}

func (h *Handler) apiRestoreItemVersion(w http.ResponseWriter, r *http.Request) {
	history, err := h.itemHistory()
	if err != nil {
		apiError(w, err)
		return
	}
	item, err := history.RestoreItemVersion(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.PathValue("id"), r.PathValue("itemID"), r.PathValue("versionID"))
	if err != nil {
		if errors.Is(err, model.ErrItemHistoryConflict) {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "item.history.restored", item.ID, map[string]any{"folder_id": item.FolderID, "version_id": r.PathValue("versionID")})
	jsonResponse(w, http.StatusOK, item)
}
