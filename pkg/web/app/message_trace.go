package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/messagetrace"
)

type messageTracePruneRequest struct {
	OlderThanDays int  `json:"older_than_days"`
	Limit         int  `json:"limit"`
	DryRun        bool `json:"dry_run"`
}

func (h *Handler) apiAdminMessageTrace(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	if h.messageTrace == nil {
		jsonResponse(w, http.StatusOK, messagetrace.Page{Records: []messagetrace.Record{}})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	updatedAfter, err := parseMessageTraceTime(r.URL.Query().Get("after"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "after must be an RFC 3339 timestamp")
		return
	}
	updatedBefore, err := parseMessageTraceTime(r.URL.Query().Get("before"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "before must be an RFC 3339 timestamp")
		return
	}
	if !updatedAfter.IsZero() && !updatedBefore.IsZero() && !updatedAfter.Before(updatedBefore) {
		jsonError(w, http.StatusBadRequest, "after must be earlier than before")
		return
	}
	page, err := h.messageTrace.List(r.Context(), messagetrace.Query{
		Text:          strings.TrimSpace(r.URL.Query().Get("q")),
		Sender:        strings.TrimSpace(r.URL.Query().Get("sender")),
		Recipient:     strings.TrimSpace(r.URL.Query().Get("recipient")),
		Status:        strings.TrimSpace(r.URL.Query().Get("status")),
		Direction:     strings.TrimSpace(r.URL.Query().Get("direction")),
		CorrelationID: strings.TrimSpace(r.URL.Query().Get("correlation_id")),
		Cursor:        strings.TrimSpace(r.URL.Query().Get("cursor")),
		Limit:         limit,
		UpdatedAfter:  updatedAfter,
		UpdatedBefore: updatedBefore,
		Visible:       traceRecordFilter(h.traceScopeFor(r.Context(), currentActor(r).ID, scope)),
	})
	if err != nil {
		apiError(w, err)
		return
	}
	if page.Records == nil {
		page.Records = []messagetrace.Record{}
	}
	if !scope.system {
		// Installation-wide totals are not a domain administrator's to see.
		page.Stats = messagetrace.Stats{}
	}
	jsonResponse(w, http.StatusOK, page)
}

// traceRecordFilter adapts an address visibility rule to trace records.
func traceRecordFilter(visible func(direction, sender, recipient string) bool) func(messagetrace.Record) bool {
	if visible == nil {
		return nil
	}
	return func(record messagetrace.Record) bool {
		return visible(record.Direction, record.EnvelopeSender, record.Recipient)
	}
}

func parseMessageTraceTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}

func (h *Handler) apiAdminMessageTraceDetail(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	if h.messageTrace == nil {
		jsonError(w, http.StatusNotFound, "message trace is unavailable")
		return
	}
	record, err := h.messageTrace.GetWithRelations(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if visible := h.traceScopeFor(r.Context(), currentActor(r).ID, scope); visible != nil {
		if !visible(record.Direction, record.EnvelopeSender, record.Recipient) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		related := record.Related[:0]
		for _, entry := range record.Related {
			if visible(record.Direction, record.EnvelopeSender, entry.Recipient) {
				related = append(related, entry)
			}
		}
		record.Related = related
	}
	jsonResponse(w, http.StatusOK, record)
}

func (h *Handler) apiAdminMessageTraceStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.messageTrace == nil {
		jsonError(w, http.StatusServiceUnavailable, "message trace is unavailable")
		return
	}
	status, err := h.messageTrace.MaintenanceStatus(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiAdminMessageTraceRebuild(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.messageTrace == nil {
		jsonError(w, http.StatusServiceUnavailable, "message trace is unavailable")
		return
	}
	status, err := h.messageTrace.RebuildIndex(r.Context())
	details := map[string]string{}
	if err != nil {
		details["error"] = err.Error()
		h.audit.Log(currentActor(r).ID, "message_trace.index.rebuild", "message-trace", details)
		apiError(w, err)
		return
	}
	details["records"] = strconv.Itoa(status.Records)
	h.audit.Log(currentActor(r).ID, "message_trace.index.rebuild", "message-trace", details)
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiAdminMessageTracePrune(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	var request messageTracePruneRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.OlderThanDays < 1 || request.OlderThanDays > 3650 {
		jsonError(w, http.StatusBadRequest, "older_than_days must be between 1 and 3650")
		return
	}
	if request.Limit == 0 {
		request.Limit = 500
	}
	if request.Limit < 1 || request.Limit > messagetrace.MaxPruneRecords {
		jsonError(w, http.StatusBadRequest, "limit must be between 1 and "+strconv.Itoa(messagetrace.MaxPruneRecords))
		return
	}
	if h.messageTrace == nil {
		jsonError(w, http.StatusServiceUnavailable, "message trace is unavailable")
		return
	}
	result, pruneErr := h.messageTrace.PruneWithOptions(r.Context(), time.Now().UTC().AddDate(0, 0, -request.OlderThanDays), request.Limit, request.DryRun)
	details := map[string]string{
		"dry_run": strconv.FormatBool(request.DryRun), "examined": strconv.Itoa(result.Examined),
		"removed": strconv.Itoa(result.Removed), "before": result.Before.Format(time.RFC3339),
	}
	if pruneErr != nil {
		details["error"] = pruneErr.Error()
	}
	h.audit.Log(currentActor(r).ID, "message_trace.prune", "message-trace", details)
	errorText := ""
	if pruneErr != nil {
		errorText = pruneErr.Error()
	}
	jsonResponse(w, http.StatusOK, map[string]any{"result": result, "error": errorText})
}
