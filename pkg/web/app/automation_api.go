package app

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/rules"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

type automationResponse struct {
	Document rules.Document    `json:"document"`
	Runs     []rules.Run       `json:"runs"`
	Evidence []rules.Execution `json:"evidence"`
}

type automationRuleRequest struct {
	Revision string     `json:"revision"`
	Rule     rules.Rule `json:"rule"`
}

type automationRevisionRequest struct {
	Revision string `json:"revision"`
}

type automationReorderRequest struct {
	Revision string   `json:"revision"`
	RuleIDs  []string `json:"rule_ids"`
}

func (h *Handler) automationAccess(r *http.Request) service.AccessContext {
	return webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
}

func (h *Handler) requireAutomation(w http.ResponseWriter) bool {
	if h.automation == nil {
		jsonError(w, http.StatusServiceUnavailable, "folder automation is unavailable")
		return false
	}
	return true
}

func (h *Handler) apiAutomation(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	access := h.automationAccess(r)
	document, err := h.automation.Document(r.Context(), access)
	if err != nil {
		automationError(w, err)
		return
	}
	runs, err := h.automation.Runs(r.Context(), access)
	if err != nil {
		automationError(w, err)
		return
	}
	evidence, err := h.automation.Evidence(r.Context(), access, "", 25)
	if err != nil {
		automationError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, automationResponse{Document: document, Runs: runs, Evidence: evidence})
}

func (h *Handler) apiCreateAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	var request automationRuleRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	document, err := h.automation.CreateRule(r.Context(), h.automationAccess(r), request.Revision, request.Rule)
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.rule.create", document.Rules[len(document.Rules)-1].ID, map[string]string{"owner": currentSubject(r).ID})
	jsonResponse(w, http.StatusCreated, document)
}

func (h *Handler) apiUpdateAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	var request automationRuleRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	document, err := h.automation.UpdateRule(r.Context(), h.automationAccess(r), request.Revision, r.PathValue("id"), request.Rule)
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.rule.update", r.PathValue("id"), map[string]string{"owner": currentSubject(r).ID})
	jsonResponse(w, http.StatusOK, document)
}

func (h *Handler) apiDeleteAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	var request automationRevisionRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	document, err := h.automation.DeleteRule(r.Context(), h.automationAccess(r), request.Revision, r.PathValue("id"))
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.rule.delete", r.PathValue("id"), map[string]string{"owner": currentSubject(r).ID})
	jsonResponse(w, http.StatusOK, document)
}

func (h *Handler) apiReorderAutomationRules(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	var request automationReorderRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	document, err := h.automation.Reorder(r.Context(), h.automationAccess(r), request.Revision, request.RuleIDs)
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.rules.reorder", currentSubject(r).ID, nil)
	jsonResponse(w, http.StatusOK, document)
}

func (h *Handler) apiPreviewAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	var request struct {
		Limit int `json:"limit"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	preview, err := h.automation.Preview(r.Context(), h.automationAccess(r), r.PathValue("id"), request.Limit)
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.rule.preview", r.PathValue("id"), map[string]string{"examined": strconv.FormatInt(preview.Examined, 10), "matched": strconv.FormatInt(preview.Matched, 10)})
	jsonResponse(w, http.StatusOK, preview)
}

func (h *Handler) apiRunAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	var request struct {
		DryRun bool `json:"dry_run"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	run, err := h.automation.StartRun(r.Context(), h.automationAccess(r), r.PathValue("id"), request.DryRun)
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.run.start", run.ID, map[string]string{"rule": run.RuleID, "dry_run": strconv.FormatBool(run.DryRun)})
	jsonResponse(w, http.StatusAccepted, run)
}

func (h *Handler) apiAutomationRuns(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	runs, err := h.automation.Runs(r.Context(), h.automationAccess(r))
	if err != nil {
		automationError(w, err)
		return
	}
	if runs == nil {
		runs = []rules.Run{}
	}
	jsonResponse(w, http.StatusOK, runs)
}

func (h *Handler) apiCancelAutomationRun(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	run, err := h.automation.CancelRun(r.Context(), h.automationAccess(r), r.PathValue("id"))
	if err != nil {
		automationError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "automation.run.cancel", run.ID, map[string]string{"rule": run.RuleID})
	jsonResponse(w, http.StatusAccepted, run)
}

func (h *Handler) apiAutomationEvidence(w http.ResponseWriter, r *http.Request) {
	if !h.requireAutomation(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	evidence, err := h.automation.Evidence(r.Context(), h.automationAccess(r), r.URL.Query().Get("rule_id"), limit)
	if err != nil {
		automationError(w, err)
		return
	}
	if evidence == nil {
		evidence = []rules.Execution{}
	}
	jsonResponse(w, http.StatusOK, evidence)
}

func automationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rules.ErrRevisionConflict), errors.Is(err, store.ErrPreconditionFailed):
		jsonError(w, http.StatusConflict, "rules changed; reload and try again")
	default:
		apiError(w, err)
	}
}
