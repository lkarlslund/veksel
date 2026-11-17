package app

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/mailpolicy"
)

type mailPolicyResponse struct {
	Document mailpolicy.Document `json:"document"`
	Stats    mailpolicy.Stats    `json:"stats"`
}

type mailPolicyRuleRequest struct {
	Revision string          `json:"revision"`
	Rule     mailpolicy.Rule `json:"rule"`
}

type mailPolicyRevisionRequest struct {
	Revision string `json:"revision"`
}

type mailPolicyReorderRequest struct {
	Revision string   `json:"revision"`
	RuleIDs  []string `json:"rule_ids"`
}

type mailPolicySimulationRequest struct {
	Message mailpolicy.Message `json:"message"`
}

type mailPolicyDecisionView struct {
	Rejected           bool                `json:"rejected"`
	RejectReason       string              `json:"reject_reason,omitempty"`
	EnhancedStatusCode string              `json:"enhanced_status_code,omitempty"`
	Quarantine         string              `json:"quarantine,omitempty"`
	Route              string              `json:"route,omitempty"`
	Headers            []mailpolicy.Action `json:"headers,omitempty"`
}

type mailPolicySimulationResponse struct {
	Result   mailpolicy.Result      `json:"result"`
	Decision mailPolicyDecisionView `json:"decision"`
}

func (h *Handler) apiAdminMailPolicies(w http.ResponseWriter, r *http.Request) {
	if !h.requireMailPolicies(w, r) {
		return
	}
	jsonResponse(w, http.StatusOK, h.mailPolicyResponse())
}

func (h *Handler) apiAdminCreateMailPolicyRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireMailPolicies(w, r) {
		return
	}
	var request mailPolicyRuleRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Rule.ID == "" {
		id, err := mailpolicy.NewRuleID()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "could not generate rule ID")
			return
		}
		request.Rule.ID = id
	}
	document := h.mailPolicies.Document()
	if slices.ContainsFunc(document.Rules, func(rule mailpolicy.Rule) bool { return rule.ID == request.Rule.ID }) {
		jsonError(w, http.StatusConflict, "rule already exists")
		return
	}
	document.Rules = append(document.Rules, request.Rule)
	updated, ok := h.commitMailPolicy(w, r, request.Revision, document, "mail_policy.rule.create", request.Rule.ID)
	if !ok {
		return
	}
	jsonResponse(w, http.StatusCreated, updated)
}

func (h *Handler) apiAdminUpdateMailPolicyRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireMailPolicies(w, r) {
		return
	}
	var request mailPolicyRuleRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	if request.Rule.ID != "" && request.Rule.ID != id {
		jsonError(w, http.StatusBadRequest, "rule ID cannot be changed")
		return
	}
	request.Rule.ID = id
	document := h.mailPolicies.Document()
	index := slices.IndexFunc(document.Rules, func(rule mailpolicy.Rule) bool { return rule.ID == id })
	if index < 0 {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	document.Rules[index] = request.Rule
	updated, ok := h.commitMailPolicy(w, r, request.Revision, document, "mail_policy.rule.update", id)
	if !ok {
		return
	}
	jsonResponse(w, http.StatusOK, updated)
}

func (h *Handler) apiAdminDeleteMailPolicyRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireMailPolicies(w, r) {
		return
	}
	var request mailPolicyRevisionRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	document := h.mailPolicies.Document()
	index := slices.IndexFunc(document.Rules, func(rule mailpolicy.Rule) bool { return rule.ID == id })
	if index < 0 {
		jsonError(w, http.StatusNotFound, "rule not found")
		return
	}
	document.Rules = slices.Delete(document.Rules, index, index+1)
	if _, ok := h.commitMailPolicy(w, r, request.Revision, document, "mail_policy.rule.delete", id); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiAdminReorderMailPolicyRules(w http.ResponseWriter, r *http.Request) {
	if !h.requireMailPolicies(w, r) {
		return
	}
	var request mailPolicyReorderRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	document := h.mailPolicies.Document()
	if len(request.RuleIDs) != len(document.Rules) {
		jsonError(w, http.StatusBadRequest, "rule_ids must contain every rule exactly once")
		return
	}
	byID := make(map[string]mailpolicy.Rule, len(document.Rules))
	for _, rule := range document.Rules {
		byID[rule.ID] = rule
	}
	ordered := make([]mailpolicy.Rule, 0, len(request.RuleIDs))
	for index, id := range request.RuleIDs {
		rule, found := byID[id]
		if !found {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("unknown or duplicate rule %q", id))
			return
		}
		delete(byID, id)
		rule.Priority = index * 10
		ordered = append(ordered, rule)
	}
	document.Rules = ordered
	updated, ok := h.commitMailPolicy(w, r, request.Revision, document, "mail_policy.rules.reorder", "mail-policy")
	if !ok {
		return
	}
	jsonResponse(w, http.StatusOK, updated)
}

func (h *Handler) apiAdminSimulateMailPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireMailPolicies(w, r) {
		return
	}
	var request mailPolicySimulationRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := request.Message.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := h.mailPolicies.Simulate(request.Message)
	decision := result.Decision()
	view := mailPolicyDecisionView{Headers: decision.Headers}
	if decision.Reject != nil {
		view.Rejected, view.RejectReason, view.EnhancedStatusCode = true, decision.Reject.Value, decision.Reject.EnhancedStatusCode
	}
	if decision.Quarantine != nil {
		view.Quarantine = decision.Quarantine.Value
	}
	if decision.Route != nil {
		view.Route = decision.Route.Value
	}
	h.audit.Log(currentActor(r).ID, "mail_policy.simulate", result.Revision, map[string]string{"matched_rules": strconv.Itoa(len(result.MatchedRuleIDs()))})
	jsonResponse(w, http.StatusOK, mailPolicySimulationResponse{Result: result, Decision: view})
}

func (h *Handler) requireMailPolicies(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireAdminAPI(w, r) {
		return false
	}
	if h.mailPolicies == nil {
		jsonError(w, http.StatusServiceUnavailable, "mail policy service is unavailable")
		return false
	}
	return true
}

func (h *Handler) mailPolicyResponse() mailPolicyResponse {
	return mailPolicyResponse{Document: h.mailPolicies.Document(), Stats: h.mailPolicies.Stats()}
}

func (h *Handler) commitMailPolicy(w http.ResponseWriter, r *http.Request, expected string, document mailpolicy.Document, action, target string) (mailPolicyResponse, bool) {
	candidate := document
	candidate.Version, candidate.Revision = mailpolicy.CurrentVersion, "candidate"
	if _, err := mailpolicy.Compile(candidate); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return mailPolicyResponse{}, false
	}
	if _, err := h.mailPolicies.Replace(r.Context(), expected, document); err != nil {
		if errors.Is(err, mailpolicy.ErrRevisionConflict) {
			jsonError(w, http.StatusConflict, err.Error())
		} else {
			jsonError(w, http.StatusInternalServerError, "mail policy activation failed")
		}
		return mailPolicyResponse{}, false
	}
	h.audit.Log(currentActor(r).ID, action, target, map[string]string{"rules": strconv.Itoa(len(document.Rules))})
	return h.mailPolicyResponse(), true
}
