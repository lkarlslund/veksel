package app

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/scheduledsend"
	"github.com/lkarlslund/veksel/pkg/service"
)

type scheduledSubmissionView struct {
	SchemaVersion int                       `json:"schema_version"`
	ID            string                    `json:"id"`
	OwnerID       string                    `json:"owner_id"`
	DraftID       string                    `json:"draft_id"`
	State         scheduledsend.State       `json:"state"`
	DueAt         time.Time                 `json:"due_at"`
	Undo          bool                      `json:"undo,omitempty"`
	NextAttemptAt *time.Time                `json:"next_attempt_at,omitzero"`
	LeaseUntil    *time.Time                `json:"lease_until,omitzero"`
	Attempts      int                       `json:"attempts"`
	LastError     string                    `json:"last_error,omitempty"`
	Submission    *service.SubmissionResult `json:"submission,omitempty"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
	CompletedAt   *time.Time                `json:"completed_at,omitzero"`
	CancelledAt   *time.Time                `json:"cancelled_at,omitzero"`
}

func scheduledSubmissionResponse(job scheduledsend.Job) scheduledSubmissionView {
	view := scheduledSubmissionView{
		SchemaVersion: job.SchemaVersion,
		ID:            job.ID,
		OwnerID:       job.OwnerID,
		DraftID:       job.DraftID,
		State:         job.State,
		DueAt:         job.DueAt,
		Undo:          job.Undo,
		Attempts:      job.Attempts,
		LastError:     job.LastError,
		CreatedAt:     job.CreatedAt,
		UpdatedAt:     job.UpdatedAt,
	}
	if !job.NextAttemptAt.IsZero() {
		view.NextAttemptAt = &job.NextAttemptAt
	}
	if !job.LeaseUntil.IsZero() {
		view.LeaseUntil = &job.LeaseUntil
	}
	if job.Submission.ID != "" {
		view.Submission = &job.Submission
	}
	if !job.CompletedAt.IsZero() {
		view.CompletedAt = &job.CompletedAt
	}
	if !job.CancelledAt.IsZero() {
		view.CancelledAt = &job.CancelledAt
	}
	return view
}

func scheduledSubmissionListResponse(jobs []scheduledsend.Job) []scheduledSubmissionView {
	views := make([]scheduledSubmissionView, len(jobs))
	for index, job := range jobs {
		views[index] = scheduledSubmissionResponse(job)
	}
	return views
}

func (h *Handler) apiScheduledSubmissions(w http.ResponseWriter, r *http.Request) {
	if h.scheduledMail == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled sending is unavailable")
		return
	}
	ownerID := currentActor(r).ID
	if r.Method == http.MethodGet {
		jobs, err := h.scheduledMail.List(r.Context(), ownerID)
		if err != nil {
			apiError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, scheduledSubmissionListResponse(jobs))
		return
	}
	var request struct {
		DraftID string    `json:"draft_id"`
		DueAt   time.Time `json:"due_at"`
		// UndoSeconds holds the draft for an undo-send window instead of
		// a chosen time; it is the composer's normal Send when enabled.
		UndoSeconds int `json:"undo_seconds,omitempty"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var job scheduledsend.Job
	var err error
	if request.UndoSeconds != 0 {
		job, err = h.scheduledMail.HoldForUndo(r.Context(), ownerID, request.DraftID, time.Duration(request.UndoSeconds)*time.Second)
	} else {
		job, err = h.scheduledMail.Schedule(r.Context(), ownerID, request.DraftID, request.DueAt)
	}
	if err != nil {
		scheduledSendError(w, err)
		return
	}
	h.audit.Log(ownerID, "mail.schedule", job.ID, map[string]string{"draft_id": job.DraftID, "due_at": job.DueAt.Format(time.RFC3339), "undo": strconv.FormatBool(job.Undo)})
	jsonResponse(w, http.StatusCreated, scheduledSubmissionResponse(job))
}

func (h *Handler) apiScheduledSubmission(w http.ResponseWriter, r *http.Request) {
	if h.scheduledMail == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled sending is unavailable")
		return
	}
	ownerID, id := currentActor(r).ID, r.PathValue("id")
	if r.Method == http.MethodGet {
		job, err := h.scheduledMail.Get(r.Context(), ownerID, id)
		if err != nil {
			scheduledSendError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, scheduledSubmissionResponse(job))
		return
	}
	var request struct {
		DueAt time.Time `json:"due_at"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	job, err := h.scheduledMail.Reschedule(r.Context(), ownerID, id, request.DueAt)
	if err != nil {
		scheduledSendError(w, err)
		return
	}
	h.audit.Log(ownerID, "mail.schedule.reschedule", id, map[string]string{"due_at": job.DueAt.Format(time.RFC3339)})
	jsonResponse(w, http.StatusOK, scheduledSubmissionResponse(job))
}

func (h *Handler) apiScheduledSubmissionCancel(w http.ResponseWriter, r *http.Request) {
	if h.scheduledMail == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled sending is unavailable")
		return
	}
	ownerID, id := currentActor(r).ID, r.PathValue("id")
	job, err := h.scheduledMail.Cancel(r.Context(), ownerID, id)
	if err != nil {
		scheduledSendError(w, err)
		return
	}
	h.audit.Log(ownerID, "mail.schedule.cancel", id, nil)
	jsonResponse(w, http.StatusOK, scheduledSubmissionResponse(job))
}

func (h *Handler) apiScheduledSubmissionSend(w http.ResponseWriter, r *http.Request) {
	if h.scheduledMail == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled sending is unavailable")
		return
	}
	ownerID, id := currentActor(r).ID, r.PathValue("id")
	job, err := h.scheduledMail.SendNow(r.Context(), ownerID, id)
	if err != nil {
		scheduledSendError(w, err)
		return
	}
	h.audit.Log(ownerID, "mail.schedule.send_now", id, nil)
	jsonResponse(w, http.StatusAccepted, scheduledSubmissionResponse(job))
}

func scheduledSendError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scheduledsend.ErrNotFound):
		jsonError(w, http.StatusNotFound, "scheduled submission not found")
	case errors.Is(err, scheduledsend.ErrConflict):
		jsonError(w, http.StatusConflict, err.Error())
	default:
		apiError(w, err)
	}
}
