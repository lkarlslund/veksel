package app

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dmarc"
)

type adminDMARCReportJob struct {
	ID            string    `json:"id"`
	Day           string    `json:"day"`
	PolicyDomain  string    `json:"policy_domain"`
	Destination   string    `json:"destination"`
	Recipient     string    `json:"recipient,omitempty"`
	Status        string    `json:"status"`
	ReportID      string    `json:"report_id"`
	Filename      string    `json:"filename"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitzero"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type adminDMARCReportPage struct {
	Items      []adminDMARCReportJob `json:"items"`
	Days       []string              `json:"retained_days"`
	Running    bool                  `json:"scheduler_running"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	Total      int                   `json:"total"`
	TotalPages int                   `json:"total_pages"`
}

func (h *Handler) requireDMARCAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if h.dmarcAggregateAdmin == nil {
		jsonError(w, http.StatusServiceUnavailable, "DMARC aggregate administration is unavailable")
		return false
	}
	return true
}
func (h *Handler) apiAdminDMARCReports(w http.ResponseWriter, r *http.Request) {
	if !h.requireDMARCAdmin(w, r) {
		return
	}
	page, pageSize, err := quotaPageParameters(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && !oneOf(status, dmarc.AggregateReportPending, dmarc.AggregateReportRetrying, dmarc.AggregateReportDelivered, dmarc.AggregateReportIgnored, dmarc.AggregateReportExpired) {
		jsonError(w, http.StatusBadRequest, "invalid DMARC report status")
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	jobs, err := h.dmarcAggregateAdmin.Jobs(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	days, err := h.dmarcAggregateAdmin.Days(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	filtered := jobs[:0]
	for _, job := range jobs {
		if status != "" && job.Status != status {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{job.Day, job.PolicyDomain, job.Destination, job.Recipient, job.Status, job.LastError}, " ")), query) {
			continue
		}
		filtered = append(filtered, job)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].UpdatedAt.After(filtered[j].UpdatedAt) })
	start, end, pages := pageBounds(len(filtered), page, pageSize)
	if page > pages {
		page = pages
		start, end, _ = pageBounds(len(filtered), page, pageSize)
	}
	views := make([]adminDMARCReportJob, 0, end-start)
	for _, job := range filtered[start:end] {
		views = append(views, projectDMARCReportJob(job))
	}
	jsonResponse(w, http.StatusOK, adminDMARCReportPage{Items: views, Days: days, Running: h.dmarcReportingRunning(), Page: page, PageSize: pageSize, Total: len(filtered), TotalPages: pages})
}
func projectDMARCReportJob(job dmarc.AggregateReportJob) adminDMARCReportJob {
	return adminDMARCReportJob{ID: job.ID, Day: job.Day, PolicyDomain: job.PolicyDomain, Destination: job.Destination, Recipient: job.Recipient, Status: job.Status, ReportID: job.ReportID, Filename: job.Filename, Attempts: job.Attempts, LastError: job.LastError, LastAttemptAt: job.LastAttemptAt, NextAttemptAt: job.NextAttemptAt, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt}
}
func (h *Handler) apiAdminRetryDMARCReports(w http.ResponseWriter, r *http.Request) {
	if !h.requireDMARCAdmin(w, r) {
		return
	}
	if h.dmarcAggregateRunner == nil || !h.dmarcReportingRunning() {
		jsonError(w, http.StatusServiceUnavailable, "DMARC report scheduler is not configured")
		return
	}
	day := r.PathValue("day")
	start, err := time.Parse(time.DateOnly, day)
	if err != nil || !start.Add(24*time.Hour).Before(time.Now().UTC().Add(time.Second)) {
		jsonError(w, http.StatusBadRequest, "a completed UTC report day is required")
		return
	}
	jobs, err := h.dmarcAggregateRunner.ProcessDay(r.Context(), day)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "dmarc.aggregate.retry", day, map[string]string{"jobs": strconv.Itoa(len(jobs))})
	states := make(map[string]int)
	for _, job := range jobs {
		states[job.Status]++
	}
	jsonResponse(w, http.StatusOK, map[string]any{"jobs": len(jobs), "states": states})
}
