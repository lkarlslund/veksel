package app

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/dane"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/tlsrpt"
)

// MTASTSAdministration is the read/refresh surface shared by outbound SMTP
// and the operator workspace.
type MTASTSAdministration interface {
	List(context.Context) ([]mtasts.CacheEntry, error)
	Refresh(context.Context, string) (mtasts.Result, error)
}

// TLSReportAdministration exposes metadata-only aggregate and delivery state.
// Report payload bytes are deliberately omitted from the HTTP projection.
type TLSReportAdministration interface {
	Days(context.Context) ([]string, error)
	Jobs(context.Context) ([]tlsrpt.ReportJob, error)
}

// ConfigureOutboundTLS installs the same durable services used by SMTP.
func (h *Handler) ConfigureOutboundTLS(policies MTASTSAdministration, reports TLSReportAdministration, schedulerRunning bool) {
	h.mtaSTSAdmin = policies
	h.tlsReportAdmin = reports
	h.tlsReportRunning = schedulerRunning
}

// ConfigureDANE installs the outbound DANE status source shown with the
// outbound TLS summary.
func (h *Handler) ConfigureDANE(status func() dane.Status) {
	h.daneStatus = status
}

type adminMTASTSEntry struct {
	mtasts.CacheEntry
	State     string `json:"state"`
	Effective bool   `json:"effective"`
}

type adminTLSReportJob struct {
	ID                 string                 `json:"id"`
	Day                string                 `json:"day"`
	PolicyDomain       string                 `json:"policy_domain"`
	Status             string                 `json:"status"`
	ReportingPolicy    tlsrpt.ReportingPolicy `json:"reporting_policy"`
	SuccessfulSessions int64                  `json:"successful_sessions"`
	FailedSessions     int64                  `json:"failed_sessions"`
	FailureDetails     int                    `json:"failure_details"`
	Attempts           int                    `json:"attempts"`
	LastError          string                 `json:"last_error,omitempty"`
	LastAttemptAt      time.Time              `json:"last_attempt_at,omitzero"`
	NextAttemptAt      time.Time              `json:"next_attempt_at,omitzero"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

type adminMTASTSPage struct {
	Items      []adminMTASTSEntry `json:"items"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	Total      int                `json:"total"`
	TotalPages int                `json:"total_pages"`
}

type adminTLSReportPage struct {
	Items      []adminTLSReportJob `json:"items"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	Total      int                 `json:"total"`
	TotalPages int                 `json:"total_pages"`
}

func (h *Handler) requireOutboundTLSAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if h.mtaSTSAdmin == nil || h.tlsReportAdmin == nil {
		jsonError(w, http.StatusServiceUnavailable, "outbound TLS administration is unavailable")
		return false
	}
	return true
}

func (h *Handler) apiAdminOutboundTLSStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireOutboundTLSAdmin(w, r) {
		return
	}
	entries, err := h.mtaSTSAdmin.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jobs, err := h.tlsReportAdmin.Jobs(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	days, err := h.tlsReportAdmin.Days(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	policyStates := make(map[string]int)
	for _, entry := range entries {
		policyStates[mtaSTSState(entry, time.Now().UTC())]++
	}
	reportStates := make(map[string]int)
	for _, job := range jobs {
		reportStates[job.Status]++
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"scheduler_running": h.tlsReportRunning,
		"policy_total":      len(entries),
		"policy_states":     policyStates,
		"report_total":      len(jobs),
		"report_states":     reportStates,
		"retained_days":     len(days),
		"dane":              h.outboundDANEStatus(),
	})
}

// outboundDANEStatus reports outbound DANE state; without a configured
// source DANE is shown as disabled.
func (h *Handler) outboundDANEStatus() dane.Status {
	if h.daneStatus == nil {
		return dane.Status{Validating: dane.ValidatingUnknown, Detail: "DANE is not configured", Resolvers: []string{}}
	}
	return h.daneStatus()
}

func (h *Handler) apiAdminMTASTSPolicies(w http.ResponseWriter, r *http.Request) {
	if !h.requireOutboundTLSAdmin(w, r) {
		return
	}
	page, pageSize, err := quotaPageParameters(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	state := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("state")))
	if state != "" && !oneOf(state, "active", "degraded", "failed", "expired", "none") {
		jsonError(w, http.StatusBadRequest, "invalid MTA-STS state")
		return
	}
	sortKey := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("sort")))
	if sortKey == "" {
		sortKey = "domain"
	}
	if !oneOf(sortKey, "domain", "state", "mode", "expires", "checked") {
		jsonError(w, http.StatusBadRequest, "invalid MTA-STS sort")
		return
	}
	direction := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("direction")))
	if direction == "" {
		direction = "asc"
	}
	if direction != "asc" && direction != "desc" {
		jsonError(w, http.StatusBadRequest, "invalid sort direction")
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	entries, err := h.mtaSTSAdmin.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	now := time.Now().UTC()
	views := make([]adminMTASTSEntry, 0, len(entries))
	for _, entry := range entries {
		view := adminMTASTSEntry{CacheEntry: entry, State: mtaSTSState(entry, now), Effective: mtaSTSEffective(entry, now)}
		if state != "" && view.State != state {
			continue
		}
		mode := ""
		if entry.Policy != nil {
			mode = string(entry.Policy.Mode)
		}
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{entry.Domain, entry.PolicyID, mode, view.State, failureMessage(entry)}, " ")), query) {
			continue
		}
		views = append(views, view)
	}
	sort.SliceStable(views, func(i, j int) bool {
		comparison := compareMTASTS(views[i], views[j], sortKey)
		if direction == "desc" {
			return comparison > 0
		}
		return comparison < 0
	})
	start, end, totalPages := pageBounds(len(views), page, pageSize)
	if page > totalPages {
		page = totalPages
		start, end, _ = pageBounds(len(views), page, pageSize)
	}
	jsonResponse(w, http.StatusOK, adminMTASTSPage{Items: views[start:end], Page: page, PageSize: pageSize, Total: len(views), TotalPages: totalPages})
}

func (h *Handler) apiAdminRefreshMTASTSPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireOutboundTLSAdmin(w, r) {
		return
	}
	domain := strings.TrimSpace(r.PathValue("domain"))
	if domain == "" || len(domain) > 253 {
		jsonError(w, http.StatusBadRequest, "valid policy domain required")
		return
	}
	canonical, err := mtasts.CanonicalDomain(domain)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "valid policy domain required")
		return
	}
	domain = canonical
	result, err := h.mtaSTSAdmin.Refresh(r.Context(), domain)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "outbound_tls.mta_sts.refresh", domain, map[string]string{"source": result.Source, "failure": strconv.FormatBool(result.Failure != nil)})
	_ = h.PublishAdminEvent(r.Context(), events.Event{Type: "outbound_tls.policy_refreshed", Resource: domain})
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiAdminTLSReports(w http.ResponseWriter, r *http.Request) {
	if !h.requireOutboundTLSAdmin(w, r) {
		return
	}
	page, pageSize, err := quotaPageParameters(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))
	if status != "" && !oneOf(status, tlsrpt.ReportPending, tlsrpt.ReportRetrying, tlsrpt.ReportDelivered, tlsrpt.ReportIgnored, tlsrpt.ReportExpired) {
		jsonError(w, http.StatusBadRequest, "invalid TLS report status")
		return
	}
	sortKey := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("sort")))
	if sortKey == "" {
		sortKey = "day"
	}
	if !oneOf(sortKey, "day", "domain", "status", "attempts", "updated") {
		jsonError(w, http.StatusBadRequest, "invalid TLS report sort")
		return
	}
	direction := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("direction")))
	if direction == "" {
		direction = "desc"
	}
	if direction != "asc" && direction != "desc" {
		jsonError(w, http.StatusBadRequest, "invalid sort direction")
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	jobs, err := h.tlsReportAdmin.Jobs(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	views := make([]adminTLSReportJob, 0, len(jobs))
	for _, job := range jobs {
		if status != "" && job.Status != status {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{job.Day, job.PolicyDomain, job.Status, job.ID, job.LastError, strings.Join(job.Policy.URIs, " ")}, " ")), query) {
			continue
		}
		views = append(views, reportJobView(job))
	}
	sort.SliceStable(views, func(i, j int) bool {
		comparison := compareTLSReport(views[i], views[j], sortKey)
		if direction == "desc" {
			return comparison > 0
		}
		return comparison < 0
	})
	start, end, totalPages := pageBounds(len(views), page, pageSize)
	if page > totalPages {
		page = totalPages
		start, end, _ = pageBounds(len(views), page, pageSize)
	}
	jsonResponse(w, http.StatusOK, adminTLSReportPage{Items: views[start:end], Page: page, PageSize: pageSize, Total: len(views), TotalPages: totalPages})
}

func reportJobView(job tlsrpt.ReportJob) adminTLSReportJob {
	view := adminTLSReportJob{ID: job.ID, Day: job.Day, PolicyDomain: job.PolicyDomain, Status: job.Status,
		ReportingPolicy: job.Policy, Attempts: job.Attempts, LastError: job.LastError, LastAttemptAt: job.LastAttemptAt,
		NextAttemptAt: job.NextAttemptAt, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt}
	for _, policy := range job.Report.Policies {
		view.SuccessfulSessions += policy.Summary.Successful
		view.FailedSessions += policy.Summary.Failure
		view.FailureDetails += len(policy.FailureDetails)
	}
	return view
}

func mtaSTSEffective(entry mtasts.CacheEntry, now time.Time) bool {
	return entry.Policy != nil && !entry.ExpiresAt.Before(now)
}

func mtaSTSState(entry mtasts.CacheEntry, now time.Time) string {
	effective := mtaSTSEffective(entry, now)
	switch {
	case effective && entry.LastFailure != nil:
		return "degraded"
	case effective:
		return "active"
	case entry.LastFailure != nil:
		return "failed"
	case entry.Policy != nil:
		return "expired"
	default:
		return "none"
	}
}

func failureMessage(entry mtasts.CacheEntry) string {
	if entry.LastFailure == nil {
		return ""
	}
	return entry.LastFailure.Type + " " + entry.LastFailure.Message
}

func compareMTASTS(left, right adminMTASTSEntry, key string) int {
	switch key {
	case "state":
		return strings.Compare(left.State, right.State)
	case "mode":
		return strings.Compare(policyMode(left.Policy), policyMode(right.Policy))
	case "expires":
		return left.ExpiresAt.Compare(right.ExpiresAt)
	case "checked":
		return left.LastCheckedAt.Compare(right.LastCheckedAt)
	default:
		return strings.Compare(left.Domain, right.Domain)
	}
}

func compareTLSReport(left, right adminTLSReportJob, key string) int {
	switch key {
	case "domain":
		return strings.Compare(left.PolicyDomain, right.PolicyDomain)
	case "status":
		return strings.Compare(left.Status, right.Status)
	case "attempts":
		return left.Attempts - right.Attempts
	case "updated":
		return left.UpdatedAt.Compare(right.UpdatedAt)
	default:
		return strings.Compare(left.Day, right.Day)
	}
}

func policyMode(policy *mtasts.Policy) string {
	if policy == nil {
		return ""
	}
	return string(policy.Mode)
}

func pageBounds(total, page, pageSize int) (start, end, totalPages int) {
	totalPages = max(1, (total+pageSize-1)/pageSize)
	page = min(max(1, page), totalPages)
	start = min(total, (page-1)*pageSize)
	end = min(total, start+pageSize)
	return start, end, totalPages
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
