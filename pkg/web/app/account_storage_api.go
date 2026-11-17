package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/accountverify"
	"github.com/lkarlslund/veksel/pkg/store"
)

type accountVerificationStatusView struct {
	SchemaVersion   int        `json:"schema_version"`
	AccountID       string     `json:"account_id"`
	Login           string     `json:"login"`
	State           string     `json:"state"`
	LastResult      string     `json:"last_result,omitempty"`
	JobID           string     `json:"job_id,omitempty"`
	ReportID        string     `json:"report_id,omitempty"`
	IssueCount      int        `json:"issue_count"`
	LastStartedAt   *time.Time `json:"last_started_at,omitzero"`
	LastCompletedAt *time.Time `json:"last_completed_at,omitzero"`
	DueAt           *time.Time `json:"due_at,omitzero"`
	NextAttemptAt   *time.Time `json:"next_attempt_at,omitzero"`
	Error           string     `json:"error,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitzero"`
}

func projectAccountVerificationStatus(status accountverify.Status) accountVerificationStatusView {
	view := accountVerificationStatusView{
		SchemaVersion: status.SchemaVersion, AccountID: status.AccountID, Login: status.Login,
		State: status.State, LastResult: status.LastResult, JobID: status.JobID, ReportID: status.ReportID,
		IssueCount: status.IssueCount, Error: status.Error,
	}
	set := func(value time.Time, target **time.Time) {
		if !value.IsZero() {
			copy := value
			*target = &copy
		}
	}
	set(status.LastStartedAt, &view.LastStartedAt)
	set(status.LastCompletedAt, &view.LastCompletedAt)
	set(status.DueAt, &view.DueAt)
	set(status.NextAttemptAt, &view.NextAttemptAt)
	set(status.UpdatedAt, &view.UpdatedAt)
	return view
}

func (h *Handler) apiAdminAccountVerifications(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.accountVerification == nil {
		jsonError(w, http.StatusServiceUnavailable, "account verification is unavailable")
		return
	}
	now := time.Now().UTC()
	statuses, err := h.accountVerification.Statuses(r.Context(), now)
	if err != nil {
		apiError(w, err)
		return
	}
	policy := h.accountVerification.Policy()
	views := make([]accountVerificationStatusView, len(statuses))
	for index, status := range statuses {
		views[index] = projectAccountVerificationStatus(status)
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"policy": map[string]any{
			"enabled":        policy.Enabled,
			"interval_hours": int(policy.Interval / time.Hour),
			"workers":        policy.Workers,
		},
		"statuses":    views,
		"observation": h.accountVerification.Observation(r.Context(), now),
	})
}

func (h *Handler) apiAdminAccountStorage(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.accountManager == nil {
		jsonError(w, http.StatusServiceUnavailable, "account storage is unavailable")
		return
	}
	jobs, err := h.accountManager.LifecycleJobs("")
	if err != nil {
		apiError(w, err)
		return
	}
	conversionJobs := make([]account.ConversionJob, 0)
	for _, entry := range h.accountManager.Entries() {
		entryJobs, jobsErr := h.accountManager.Jobs(entry.Manifest.Login)
		if jobsErr != nil {
			apiError(w, jobsErr)
			return
		}
		conversionJobs = append(conversionJobs, entryJobs...)
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"accounts":        h.accountManager.Entries(),
		"issues":          h.accountManager.Issues(),
		"roots":           h.accountManager.Roots(),
		"default_engine":  h.accountManager.DefaultEngine(),
		"engines":         account.ProductionEngines,
		"lifecycle_jobs":  jobs,
		"conversion_jobs": conversionJobs,
		"encryption":      h.accountManager.EncryptionStatus(),
	})
}

func (h *Handler) apiAdminStorageEncryption(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.accountManager == nil {
		jsonError(w, http.StatusServiceUnavailable, "account storage is unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, h.accountManager.EncryptionStatus())
}

// apiAdminStorageEncryptionRotate rotates the installation key and rewraps
// what it protects: stored sync credentials and every account
// data-encryption key. Encrypted account data is not rewritten.
func (h *Handler) apiAdminStorageEncryptionRotate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	key, err := h.migrationJobs.RotateCredentialKey(r.Context())
	if err != nil {
		h.audit.Log(currentActor(r).ID, "account.storage.encryption.rotate", "installation-key", map[string]string{"error": err.Error()})
		apiError(w, err)
		return
	}
	h.respondRewrap(w, r, "account.storage.encryption.rotate", map[string]any{"key": key})
}

// apiAdminStorageEncryptionRewrap completes an interrupted rotation by
// rewrapping account keys still sealed under a retired installation key.
func (h *Handler) apiAdminStorageEncryptionRewrap(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	h.respondRewrap(w, r, "account.storage.encryption.rewrap", map[string]any{})
}

func (h *Handler) respondRewrap(w http.ResponseWriter, r *http.Request, action string, body map[string]any) {
	report, err := h.accountManager.RewrapKeys(r.Context())
	details := map[string]string{"active_key_id": report.ActiveKeyID, "rewrapped": fmt.Sprint(report.Rewrapped)}
	if err != nil {
		details["error"] = err.Error()
	}
	h.audit.Log(currentActor(r).ID, action, "account-storage", details)
	if err != nil {
		apiError(w, err)
		return
	}
	body["accounts"] = report
	jsonResponse(w, http.StatusOK, body)
}

func (h *Handler) apiAdminAccountMove(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	var request struct {
		RootID string `json:"root_id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.RootID == "" {
		jsonError(w, http.StatusBadRequest, "root_id is required")
		return
	}
	job, err := h.accountManager.StartMove(r.PathValue("login"), request.RootID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.move", r.PathValue("login"), map[string]string{"root_id": request.RootID, "job_id": job.ID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountPurge(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	login := r.PathValue("login")
	job, err := h.accountManager.StartPurge(login, request.Confirmation)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.purge", login, map[string]string{"job_id": job.ID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountLifecycle(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	jobs, err := h.accountManager.LifecycleJobs(r.PathValue("login"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, jobs)
}

func (h *Handler) apiAdminAccountRollback(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	login, jobID := r.PathValue("login"), r.PathValue("job")
	job, err := h.accountManager.StartRollback(login, jobID, request.Confirmation)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.rollback", login, map[string]string{"job_id": job.ID, "move_job_id": jobID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountRetainedCleanup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	login, jobID := r.PathValue("login"), r.PathValue("job")
	job, err := h.accountManager.StartRetainedCleanup(login, jobID, request.Confirmation)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.cleanup_retained", login, map[string]string{"job_id": job.ID, "parent_job_id": jobID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountExport(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	login := r.PathValue("login")
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="veksel-%s.tar.gz"`, login))
	if err := h.accountManager.Export(r.Context(), login, w); err != nil {
		// Headers may already be committed by a streaming failure; auditing still
		// preserves the operational outcome.
		h.audit.Log(currentActor(r).ID, "account.storage.export_failed", login, map[string]string{"error": err.Error()})
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.export", login, nil)
}

func (h *Handler) apiAdminAccountRestore(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	engine := store.Backend(r.URL.Query().Get("engine"))
	if engine == "" {
		entry, found := h.accountManager.ByLogin(r.PathValue("login"))
		if !found {
			jsonError(w, http.StatusNotFound, "account not found")
			return
		}
		engine = entry.Manifest.Engine
	}
	report, err := h.accountManager.Restore(r.Context(), r.PathValue("login"), http.MaxBytesReader(w, r.Body, 1<<40), engine)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.restore", r.PathValue("login"), map[string]string{"report_id": report.ID, "engine": string(engine)})
	jsonResponse(w, http.StatusOK, report)
}

func (h *Handler) apiAdminAccountConversions(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.accountManager == nil {
		jsonError(w, http.StatusServiceUnavailable, "account storage is unavailable")
		return
	}
	login := r.PathValue("login")
	if r.Method == http.MethodGet {
		jobs, err := h.accountManager.Jobs(login)
		if err != nil {
			apiError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, jobs)
		return
	}
	// Engine and encryption default to the account's current storage, so a
	// request may change either or both, or rotate the data-encryption key.
	var request struct {
		Engine    store.Backend `json:"engine"`
		Encrypted *bool         `json:"encrypted"`
		RotateKey bool          `json:"rotate_key"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	entry, found := h.accountManager.ByLogin(login)
	if !found {
		jsonError(w, http.StatusNotFound, "account not found")
		return
	}
	target := account.ConversionTarget{Engine: request.Engine, Encrypted: entry.Manifest.Encrypted, RotateKey: request.RotateKey}
	if target.Engine == "" {
		target.Engine = entry.Manifest.Engine
	}
	if request.Encrypted != nil {
		target.Encrypted = *request.Encrypted
	}
	if !account.SupportedEngine(target.Engine) {
		jsonError(w, http.StatusBadRequest, "engine must be pebble or badger")
		return
	}
	if target.Encrypted && !h.accountManager.EncryptionAvailable() {
		jsonError(w, http.StatusServiceUnavailable, "the installation key ring is unavailable")
		return
	}
	job, err := h.accountManager.StartConversionTo(login, target)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.convert", login, map[string]string{"engine": string(target.Engine), "encrypted": fmt.Sprint(target.Encrypted), "rotate_key": fmt.Sprint(target.RotateKey), "job_id": job.ID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountConversionCancel(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	login, jobID := r.PathValue("login"), r.PathValue("job")
	job, err := h.accountManager.CancelConversion(login, jobID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.conversion.cancel", login, map[string]string{"job_id": jobID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountConversionRollback(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	login, jobID := r.PathValue("login"), r.PathValue("job")
	job, err := h.accountManager.StartConversionRollback(login, jobID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.conversion.rollback", login, map[string]string{"job_id": job.ID, "parent_job_id": jobID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountConversionCleanup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	login, jobID := r.PathValue("login"), r.PathValue("job")
	job, err := h.accountManager.StartConversionRetainedCleanup(login, jobID, request.Confirmation)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.storage.conversion.cleanup_retained", login, map[string]string{"job_id": job.ID, "parent_job_id": jobID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountCheck(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.accountManager == nil {
		jsonError(w, http.StatusServiceUnavailable, "account storage is unavailable")
		return
	}
	repair := r.URL.Query().Get("repair") == "true"
	job, err := h.accountManager.StartIntegrityCheck(r.PathValue("login"), repair)
	if err != nil {
		apiError(w, err)
		return
	}
	action := "account.storage.verify"
	if repair {
		action = "account.storage.repair"
	}
	h.audit.Log(currentActor(r).ID, action, r.PathValue("login"), map[string]string{"job_id": job.ID})
	jsonResponse(w, http.StatusAccepted, job)
}

func (h *Handler) apiAdminAccountCheckReport(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) || h.accountManager == nil {
		return
	}
	report, err := h.accountManager.IntegrityReport(r.PathValue("login"), r.PathValue("report"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, report)
}
