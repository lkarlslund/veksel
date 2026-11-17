package app

import "net/http"

func (h *Handler) apiAdminSyncCredentialKeys(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	jsonResponse(w, http.StatusOK, h.migrationJobs.CredentialKeyStatus())
}

func (h *Handler) apiAdminRotateSyncCredentialKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	status, err := h.migrationJobs.RotateCredentialKey(r.Context())
	details := map[string]string{}
	if err != nil {
		details["error"] = err.Error()
		h.audit.Log(currentActor(r).ID, "sync.credentials.rotate", "sync-credentials", details)
		apiError(w, err)
		return
	}
	details["active_key_id"] = status.ActiveKeyID
	h.audit.Log(currentActor(r).ID, "sync.credentials.rotate", "sync-credentials", details)
	jsonResponse(w, http.StatusOK, status)
}
