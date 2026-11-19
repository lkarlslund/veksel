package app

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/virus"
)

type quarantineDigestPreferenceResponse struct {
	Available  bool                             `json:"available"`
	Enabled    bool                             `json:"enabled"`
	Preference virus.QuarantineDigestPreference `json:"preference"`
}

func (h *Handler) apiQuarantineDigestPreference(w http.ResponseWriter, r *http.Request) {
	userID := settingsUserID(r)
	digests := h.quarantineDigests.Load()
	if digests == nil {
		jsonResponse(w, http.StatusOK, quarantineDigestPreferenceResponse{Available: false, Enabled: false, Preference: virus.QuarantineDigestPreference{UserID: userID, Schedule: virus.QuarantineDigestOff, HourUTC: 8, Weekday: int(time.Monday)}})
		return
	}
	preference, err := digests.GetPreference(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, quarantineDigestPreferenceResponse{Available: true, Enabled: true, Preference: preference})
}

func (h *Handler) apiUpdateQuarantineDigestPreference(w http.ResponseWriter, r *http.Request) {
	digests := h.quarantineDigests.Load()
	if digests == nil {
		jsonError(w, http.StatusServiceUnavailable, "quarantine digests are disabled by the administrator")
		return
	}
	var request struct {
		Schedule string `json:"schedule"`
		HourUTC  int    `json:"hour_utc"`
		Weekday  int    `json:"weekday"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID := settingsUserID(r)
	preference, err := digests.SetPreference(r.Context(), virus.QuarantineDigestPreference{UserID: userID, Schedule: request.Schedule, HourUTC: request.HourUTC, Weekday: request.Weekday})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.auditSettings(r, "quarantine.digest.update", userID, map[string]string{"schedule": preference.Schedule})
	h.events.Publish(events.Event{Type: "quarantine.digest.updated", Resource: userID, Recipients: []string{userID}})
	jsonResponse(w, http.StatusOK, quarantineDigestPreferenceResponse{Available: true, Enabled: true, Preference: preference})
}

type adminQuarantineDigestJob struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	Recipient     string    `json:"recipient"`
	ScheduledFor  time.Time `json:"scheduled_for"`
	EntryCount    int       `json:"entry_count"`
	Truncated     bool      `json:"truncated"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	CompletedAt   time.Time `json:"completed_at,omitzero"`
}

func quarantineDigestJobView(job virus.QuarantineDigestJob) adminQuarantineDigestJob {
	return adminQuarantineDigestJob{ID: job.ID, UserID: job.UserID, Recipient: job.Recipient, ScheduledFor: job.ScheduledFor, EntryCount: job.EntryCount, Truncated: job.Truncated, Status: job.Status, Attempts: job.Attempts, NextAttemptAt: job.NextAttemptAt, LastError: job.LastError, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt, CompletedAt: job.CompletedAt}
}

func (h *Handler) apiAdminQuarantineStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	status, err := h.quarantineStore().Status(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	preferences, jobs := 0, []virus.QuarantineDigestJob{}
	digests := h.quarantineDigests.Load()
	if digests != nil {
		listed, listErr := digests.ListPreferences(r.Context())
		if listErr != nil {
			apiError(w, listErr)
			return
		}
		preferences = len(listed)
		jobs, err = digests.ListJobs(r.Context())
		if err != nil {
			apiError(w, err)
			return
		}
	}
	jobCounts := make(map[string]int)
	for _, job := range jobs {
		jobCounts[job.Status]++
	}
	jsonResponse(w, http.StatusOK, map[string]any{"storage": status, "digests_enabled": digests != nil, "digest_preferences": preferences, "digest_jobs": jobCounts})
}

func (h *Handler) apiAdminQuarantineDigests(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	digests := h.quarantineDigests.Load()
	if digests == nil {
		jsonResponse(w, http.StatusOK, []adminQuarantineDigestJob{})
		return
	}
	jobs, err := digests.ListJobs(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	result := make([]adminQuarantineDigestJob, 0, len(jobs))
	for _, job := range jobs {
		result = append(result, quarantineDigestJobView(job))
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiAdminQuarantineCleanup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	limit := 10_000
	if h.cfg != nil && h.cfg.QuarantineCleanupBatchSize > 0 {
		limit = h.cfg.QuarantineCleanupBatchSize
	}
	cleanup, err := h.quarantineStore().CleanupExpired(r.Context(), time.Now().UTC(), limit)
	if err != nil {
		apiError(w, err)
		return
	}
	actions := 0
	if h.quarantineActions != nil {
		actions, err = h.quarantineActions.Cleanup(r.Context(), time.Now().UTC(), limit)
		if err != nil {
			apiError(w, err)
			return
		}
	}
	h.audit.Log(currentActor(r).ID, "quarantine.cleanup", "quarantine", map[string]string{"entries": fmt.Sprint(cleanup.Removed), "actions": fmt.Sprint(actions)})
	jsonResponse(w, http.StatusOK, map[string]any{"entries_removed": cleanup.Removed, "bytes_removed": cleanup.Bytes, "actions_removed": actions})
}

func (h *Handler) apiAdminQuarantineRebuild(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	status, err := h.quarantineStore().RebuildAccounting(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "quarantine.rebuild", "quarantine", nil)
	jsonResponse(w, http.StatusOK, status)
}

func quarantineActionHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

var quarantineActionPage = template.Must(template.New("quarantine-action").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Veksel quarantine</title><style>body{margin:0;background:#eef5f4;color:#17343a;font:16px system-ui,sans-serif}main{max-width:560px;margin:12vh auto;background:#fff;border:1px solid #b8ceca;padding:32px;box-shadow:0 12px 35px #17343a22}h1{margin:0 0 12px;font-size:25px}p{line-height:1.5;color:#47656a}.message{padding:16px;background:#edf7f5;border-left:4px solid #13a38b;margin:20px 0}.message strong,.message span{display:block}.message span{margin-top:5px;color:#607a7e}button,a{display:inline-block;border:0;border-radius:2px;padding:11px 17px;background:#087f6d;color:#fff;font-weight:700;text-decoration:none;cursor:pointer}.danger{background:#ba3f4c}.error{border-left-color:#ba3f4c}</style></head><body><main><span>VEKSEL · QUARANTINE</span><h1>{{.Title}}</h1><p>{{.Message}}</p>{{if .Subject}}<div class="message"><strong>{{.Subject}}</strong><span>{{.Sender}}</span></div>{{end}}{{if .Token}}<form method="post" action="/quarantine/action"><input type="hidden" name="token" value="{{.Token}}"><button class="{{if eq .Action "spam"}}danger{{end}}">{{.Button}}</button></form>{{else}}<a href="/app/quarantine">Open Veksel</a>{{end}}</main></body></html>`))

type quarantineActionPageData struct {
	Title, Message, Subject, Sender, Token, Action, Button string
}

func (h *Handler) quarantineActionConfirmation(w http.ResponseWriter, r *http.Request) {
	quarantineActionHeaders(w)
	if h.quarantineActions == nil {
		h.renderQuarantineActionError(w, http.StatusNotFound, "Action unavailable", "This quarantine action is not available.")
		return
	}
	token := r.URL.Query().Get("token")
	claims, err := h.quarantineActions.Inspect(r.Context(), token)
	if err != nil {
		h.renderQuarantineActionFailure(w, err)
		return
	}
	entry, err := h.quarantineStore().Get(r.Context(), claims.EntryID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.renderQuarantineActionError(w, http.StatusServiceUnavailable, "Temporarily unavailable", "The quarantine store could not be checked. Try again shortly.")
		return
	}
	if err == nil && !strings.EqualFold(entry.OwnerID, claims.OwnerID) {
		h.renderQuarantineActionError(w, http.StatusNotFound, "Action unavailable", "This quarantine action is not available.")
		return
	}
	data := quarantineActionPageData{Token: token, Action: claims.Action}
	if entry != nil {
		data.Subject, data.Sender = entry.Subject, entry.Sender
	}
	if claims.Action == virus.QuarantineActionRelease {
		data.Title, data.Message, data.Button = "Release this message?", "This will queue the isolated message for delivery to your Inbox.", "Release to Inbox"
	} else {
		data.Title, data.Message, data.Button = "Confirm this message as spam?", "This will remove the isolated message and add its sender to your private block list.", "Confirm spam and block sender"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = quarantineActionPage.Execute(w, data)
}

func (h *Handler) quarantineActionExecute(w http.ResponseWriter, r *http.Request) {
	quarantineActionHeaders(w)
	if h.quarantineActions == nil {
		h.renderQuarantineActionError(w, http.StatusNotFound, "Action unavailable", "This quarantine action is not available.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		h.renderQuarantineActionError(w, http.StatusBadRequest, "Invalid request", "The action request could not be read.")
		return
	}
	claim, err := h.quarantineActions.Claim(r.Context(), r.FormValue("token"))
	if err != nil {
		h.renderQuarantineActionFailure(w, err)
		return
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = h.quarantineActions.Complete(r.Context(), claim, false)
		}
	}()
	var detail string
	if claim.Claims.Action == virus.QuarantineActionRelease {
		queueID, ownerID, recipient, actionErr := h.releaseQuarantine(r.Context(), claim.Claims.EntryID, claim.Claims.OwnerID)
		if actionErr != nil {
			h.renderQuarantineActionError(w, http.StatusServiceUnavailable, "Release delayed", "The message could not be queued right now. The link remains usable; try again shortly.")
			return
		}
		detail = "The message has been queued for delivery to your Inbox."
		h.audit.Log("digest-link", "quarantine.release", claim.Claims.EntryID, map[string]string{"owner": ownerID, "recipient": recipient, "queue_id": queueID})
		h.events.Publish(events.Event{Type: "quarantine.released", Resource: claim.Claims.EntryID, Recipients: []string{ownerID}})
	} else {
		sender, ownerID, _, actionErr := h.confirmQuarantineSpam(r.Context(), claim.Claims.EntryID, claim.Claims.OwnerID)
		if actionErr != nil {
			h.renderQuarantineActionError(w, http.StatusServiceUnavailable, "Action delayed", "The message could not be confirmed right now. The link remains usable; try again shortly.")
			return
		}
		detail = "The message was removed and its sender was added to your private block list."
		h.audit.Log("digest-link", "quarantine.confirm_spam", claim.Claims.EntryID, map[string]string{"owner": ownerID, "sender": sender})
		h.events.Publish(events.Event{Type: "quarantine.spam_confirmed", Resource: claim.Claims.EntryID, Recipients: []string{ownerID}})
	}
	if err := h.quarantineActions.Complete(r.Context(), claim, true); err != nil {
		h.renderQuarantineActionError(w, http.StatusServiceUnavailable, "Action completed", "The message action completed, but its confirmation state could not be saved. Retrying the link is safe.")
		return
	}
	succeeded = true
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = quarantineActionPage.Execute(w, quarantineActionPageData{Title: "Action completed", Message: detail})
}

func (h *Handler) renderQuarantineActionFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, virus.ErrQuarantineActionExpired):
		h.renderQuarantineActionError(w, http.StatusGone, "Link expired", "This quarantine action has expired. Open Veksel to inspect current quarantine.")
	case errors.Is(err, virus.ErrQuarantineActionConsumed):
		h.renderQuarantineActionError(w, http.StatusConflict, "Already completed", "This single-use quarantine action has already been completed.")
	case errors.Is(err, virus.ErrQuarantineActionInProgress):
		h.renderQuarantineActionError(w, http.StatusConflict, "Action in progress", "This action is already being processed. Wait a moment before trying again.")
	default:
		h.renderQuarantineActionError(w, http.StatusNotFound, "Action unavailable", "This quarantine action is invalid or no longer available.")
	}
}

func (h *Handler) renderQuarantineActionError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = quarantineActionPage.Execute(w, quarantineActionPageData{Title: title, Message: message})
}
