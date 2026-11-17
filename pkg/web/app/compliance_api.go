package app

import (
	"bytes"
	"context"
	"errors"
	"mime"
	"net/http"
	"net/mail"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// compliancePolicy is the live administration policy for compliance actions.
type compliancePolicy struct {
	domainAdminHolds bool
	minDomainDays    int
}

func compliancePolicyFromConfig(cfg *config.Config) *compliancePolicy {
	return &compliancePolicy{domainAdminHolds: cfg.LegalHoldDomainAdmins, minDomainDays: cfg.RetentionMinDays}
}

func (h *Handler) currentCompliancePolicy() compliancePolicy {
	if policy := h.compliancePolicy.Load(); policy != nil {
		return *policy
	}
	return compliancePolicy{minDomainDays: 30}
}

// Compliance returns the hold and retention registry shared with the
// retention job and installed on the FolderSpace stack.
func (h *Handler) Compliance() *service.Compliance { return h.compliance }

// ConfigureCompliance replaces the handler's registry with the process-wide
// one already installed on the FolderSpace stack, and installs the
// background retention job.
func (h *Handler) ConfigureCompliance(compliance *service.Compliance, job *service.RetentionJob) {
	if compliance != nil {
		h.compliance = compliance
		service.ConfigureLegalHolds(h.folderSpace, compliance)
	}
	h.retention = job
}

func (h *Handler) registerComplianceRoutes(api apiRouter) {
	api.handle("GET /api/v1/admin/compliance", h.apiAdminCompliance)
	api.handle("POST /api/v1/admin/compliance/holds", h.apiAdminPlaceHold)
	api.handle("POST /api/v1/admin/compliance/holds/{id}/release", h.apiAdminReleaseHold)
	api.handle("GET /api/v1/admin/compliance/held-items", h.apiAdminHeldItems)
	api.handle("POST /api/v1/admin/compliance/policies", h.apiAdminPutRetentionPolicy)
	api.handle("PUT /api/v1/admin/compliance/policies/{id}", h.apiAdminPutRetentionPolicy)
	api.handle("DELETE /api/v1/admin/compliance/policies/{id}", h.apiAdminDeleteRetentionPolicy)
	api.handle("POST /api/v1/admin/compliance/retention/run", h.apiAdminRunRetention)
	api.handle("GET /api/v1/admin/compliance/export", h.apiAdminDiscoveryExport)
	api.handle("GET /api/v1/workspace/folders/{id}/retention", h.apiFolderRetention)
}

// complianceScopeAllows reports whether the actor administers scope/target:
// system administrators everywhere, domain administrators for their domains
// and the accounts whose primary identity is in them. Holds and eDiscovery
// additionally require legal_hold_domain_admins for domain administrators.
func (h *Handler) complianceScopeAllows(ctx context.Context, actor, scope, target string, holds bool) bool {
	if h.isAdmin(ctx, actor) {
		// As in requireAccountAdmin, only an owner reaches an owner account.
		return scope != service.HoldScopeAccount || target == actor || h.isOwner(ctx, actor) || !h.isOwner(ctx, target)
	}
	if holds && !h.currentCompliancePolicy().domainAdminHolds {
		return false
	}
	domain := target
	switch scope {
	case service.HoldScopeAccount:
		var err error
		if domain, err = h.users.PrimaryDomain(ctx, target); err != nil || domain == "" || h.holdsSystemAuthority(ctx, target) {
			return false
		}
	case service.HoldScopeDomain:
	default:
		return false
	}
	return h.domainAllowed(ctx, actor, domain, authz.DomainAccountsManage)
}

func (h *Handler) apiAdminCompliance(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	ctx, actor := authz.WithRequestScope(r.Context()), currentActor(r).ID
	policy := h.currentCompliancePolicy()
	holds := make([]service.LegalHold, 0)
	for _, hold := range h.compliance.ListHolds() {
		if scope.system || h.complianceScopeAllows(ctx, actor, hold.Scope, hold.Target, false) {
			holds = append(holds, hold)
		}
	}
	policies := make([]service.RetentionPolicy, 0)
	for _, retention := range h.compliance.ListPolicies() {
		if scope.system || retention.Scope != service.RetentionScopeInstallation && h.complianceScopeAllows(ctx, actor, retention.Scope, retention.Target, false) {
			policies = append(policies, retention)
		}
	}
	response := map[string]any{
		"scope": scope.name(), "domains": scope.domains, "holds": holds, "policies": policies,
		"can_hold":                 scope.system || policy.domainAdminHolds,
		"legal_hold_domain_admins": policy.domainAdminHolds, "retention_min_days": policy.minDomainDays,
		"now": time.Now().UTC(),
	}
	if scope.system && h.retention != nil {
		response["retention"] = h.retention.Status(ctx)
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminPlaceHold(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Scope  string `json:"scope"`
		Target string `json:"target"`
		Reason string `json:"reason"`
		CaseID string `json:"case_id"`
		EndsAt string `json:"ends_at"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := currentActor(r).ID
	target := strings.ToLower(strings.TrimSpace(request.Target))
	if !h.complianceScopeAllows(authz.WithRequestScope(r.Context()), actor, request.Scope, target, true) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	hold := service.LegalHold{Scope: request.Scope, Target: target, Reason: request.Reason, CaseID: request.CaseID, CreatedBy: actor}
	if strings.TrimSpace(request.EndsAt) != "" {
		endsAt, err := parseComplianceDate(request.EndsAt, true)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "ends_at: "+err.Error())
			return
		}
		hold.EndsAt = endsAt
	}
	hold, err := h.compliance.PlaceHold(r.Context(), hold)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(actor, "legal_hold.place", hold.Scope+":"+hold.Target, holdAuditDetails(hold))
	jsonResponse(w, http.StatusCreated, hold)
}

func (h *Handler) apiAdminReleaseHold(w http.ResponseWriter, r *http.Request) {
	actor := currentActor(r).ID
	hold, err := h.compliance.GetHold(r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if !h.complianceScopeAllows(authz.WithRequestScope(r.Context()), actor, hold.Scope, hold.Target, true) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	hold, err = h.compliance.ReleaseHold(r.Context(), hold.ID, actor)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(actor, "legal_hold.release", hold.Scope+":"+hold.Target, holdAuditDetails(hold))
	jsonResponse(w, http.StatusOK, hold)
}

func holdAuditDetails(hold service.LegalHold) map[string]string {
	details := map[string]string{"hold_id": hold.ID, "reason": hold.Reason, "case_id": hold.CaseID}
	if !hold.EndsAt.IsZero() {
		details["ends_at"] = hold.EndsAt.Format(time.RFC3339)
	}
	return details
}

// apiAdminHeldItems lists the items a held account's user deleted, which
// only compliance access can see.
func (h *Handler) apiAdminHeldItems(w http.ResponseWriter, r *http.Request) {
	actor := currentActor(r).ID
	accountID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("account")))
	if !h.complianceScopeAllows(authz.WithRequestScope(r.Context()), actor, service.HoldScopeAccount, accountID, true) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	access := service.ComplianceAccess(accountID)
	items := make([]map[string]any, 0)
	for _, folderType := range []model.FolderType{model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeFiles, model.FolderTypeNotes} {
		listed, err := h.folderSpace.ListItems(r.Context(), access, model.HeldDeletedFolderID(accountID, folderType), service.ItemQuery{MetadataOnly: true, Limit: 500})
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			apiError(w, err)
			return
		}
		for _, item := range listed {
			full, err := h.folderSpace.GetItem(r.Context(), access, item.ID)
			if err != nil {
				continue
			}
			subject, from := full.Headers["Subject"], full.Headers["From"]
			if message, parseErr := mail.ReadMessage(bytes.NewReader(full.Data)); parseErr == nil && folderType == model.FolderTypeMail {
				subject, from = message.Header.Get("Subject"), message.Header.Get("From")
			}
			items = append(items, map[string]any{
				"id": full.ID, "type": folderType, "subject": subject, "from": from,
				"internal_date": full.InternalDate, "held_deleted_at": full.HeldDeletedAt, "held_deleted_from": full.HeldDeletedFrom, "size": full.Size,
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i]["held_deleted_at"].(time.Time).After(items[j]["held_deleted_at"].(time.Time))
	})
	h.audit.Log(actor, "legal_hold.held_items.read", accountID, map[string]string{"items": strconv.Itoa(len(items))})
	jsonResponse(w, http.StatusOK, map[string]any{"account": accountID, "items": items})
}

func (h *Handler) apiAdminPutRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var policy service.RetentionPolicy
	if err := decodeJSON(r, &policy); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	policy.ID = r.PathValue("id")
	actor := currentActor(r).ID
	ctx := authz.WithRequestScope(r.Context())
	normalized, err := service.NormalizePolicy(policy)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	system := h.isAdmin(ctx, actor)
	if policy.ID != "" {
		existing, err := h.compliance.GetPolicy(policy.ID)
		if err != nil {
			apiError(w, err)
			return
		}
		if !system && (existing.Scope == service.RetentionScopeInstallation || !h.complianceScopeAllows(ctx, actor, existing.Scope, existing.Target, false)) {
			jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	if !system {
		if normalized.Scope == service.RetentionScopeInstallation || !h.complianceScopeAllows(ctx, actor, normalized.Scope, normalized.Target, false) {
			jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		if floor := h.currentCompliancePolicy().minDomainDays; normalized.Action == service.RetentionActionDelete && normalized.Days < floor {
			jsonError(w, http.StatusBadRequest, "domain administrators may not delete mail younger than "+strconv.Itoa(floor)+" days")
			return
		}
	}
	normalized.CreatedBy = actor
	stored, err := h.compliance.PutPolicy(r.Context(), normalized)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(actor, "retention_policy.update", stored.ID, map[string]string{
		"scope": stored.Scope, "target": stored.Target, "action": stored.Action, "days": strconv.Itoa(stored.Days),
		"special_use": stored.SpecialUse, "folder_pattern": stored.Pattern,
	})
	status := http.StatusOK
	if policy.ID == "" {
		status = http.StatusCreated
	}
	jsonResponse(w, status, stored)
}

func (h *Handler) apiAdminDeleteRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	actor := currentActor(r).ID
	ctx := authz.WithRequestScope(r.Context())
	policy, err := h.compliance.GetPolicy(r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if !h.isAdmin(ctx, actor) && (policy.Scope == service.RetentionScopeInstallation || !h.complianceScopeAllows(ctx, actor, policy.Scope, policy.Target, false)) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.compliance.DeletePolicy(r.Context(), policy.ID); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(actor, "retention_policy.delete", policy.ID, map[string]string{"scope": policy.Scope, "target": policy.Target})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiAdminRunRetention(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.retention == nil {
		jsonError(w, http.StatusServiceUnavailable, "the retention job is unavailable")
		return
	}
	report, err := h.retention.RunOnce(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, report)
}

// apiAdminDiscoveryExport streams an eDiscovery ZIP for one account or every
// account with an identity in one domain.
func (h *Handler) apiAdminDiscoveryExport(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	actor := currentActor(r).ID
	ctx := authz.WithRequestScope(r.Context())
	scope, target := query.Get("scope"), strings.ToLower(strings.TrimSpace(query.Get("target")))
	if !h.complianceScopeAllows(ctx, actor, scope, target, true) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	request := service.DiscoveryQuery{Keywords: query.Get("keywords"), HeldOnly: query.Get("held_only") == "1" || query.Get("held_only") == "true"}
	for _, participant := range strings.Split(query.Get("participants"), ",") {
		request.Participants = append(request.Participants, participant)
	}
	var err error
	if value := query.Get("since"); value != "" {
		if request.Since, err = parseComplianceDate(value, false); err != nil {
			jsonError(w, http.StatusBadRequest, "since: "+err.Error())
			return
		}
	}
	if value := query.Get("until"); value != "" {
		if request.Until, err = parseComplianceDate(value, true); err != nil {
			jsonError(w, http.StatusBadRequest, "until: "+err.Error())
			return
		}
	}
	if value := query.Get("max_items"); value != "" {
		if request.MaxItems, err = strconv.Atoi(value); err != nil {
			jsonError(w, http.StatusBadRequest, "max_items must be a number")
			return
		}
	}
	switch scope {
	case service.HoldScopeAccount:
		if _, err := h.users.Get(ctx, target); err != nil {
			apiError(w, err)
			return
		}
		request.Accounts = []string{target}
	case service.HoldScopeDomain:
		addresses, err := h.users.ListEmailAddressesForDomain(ctx, target)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			apiError(w, err)
			return
		}
		for _, address := range addresses {
			// An account with an identity in the domain is exported only
			// when the actor could export it on its own: a domain
			// administrator never reaches an account whose primary
			// identity is elsewhere or that administers the system.
			account := strings.ToLower(address.UserID)
			if account != "" && !slices.Contains(request.Accounts, account) && h.complianceScopeAllows(ctx, actor, service.HoldScopeAccount, account, true) {
				request.Accounts = append(request.Accounts, account)
			}
		}
		sort.Strings(request.Accounts)
	}
	if request, err = service.NormalizeDiscoveryQuery(request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	filename := "ediscovery-" + safeComplianceName(target) + "-" + time.Now().UTC().Format("20060102-150405") + ".zip"
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename}); disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	refreshExportWriteDeadline(w)
	counter := &responseByteCounter{ResponseWriter: w}
	details := map[string]string{
		"scope": scope, "accounts": strconv.Itoa(len(request.Accounts)), "keywords": request.Keywords,
		"participants": strings.Join(request.Participants, ","), "held_only": strconv.FormatBool(request.HeldOnly),
	}
	if !request.Since.IsZero() {
		details["since"] = request.Since.Format(time.RFC3339)
	}
	if !request.Until.IsZero() {
		details["until"] = request.Until.Format(time.RFC3339)
	}
	report, err := service.ExportDiscovery(r.Context(), h.folderSpace, h.search, request, actor, counter)
	if err != nil {
		details["result"], details["error"] = "failed", err.Error()
		h.audit.Log(actor, "ediscovery.export", scope+":"+target, details)
		if counter.written == 0 {
			w.Header().Del("Content-Disposition")
			w.Header().Set("Content-Type", "application/json")
			apiError(w, err)
		}
		return
	}
	details["result"], details["items"], details["bytes"] = "succeeded", strconv.Itoa(report.Items), strconv.FormatInt(report.Bytes, 10)
	details["truncated"], details["search_index"] = strconv.FormatBool(report.Truncated), strconv.FormatBool(report.Search)
	h.audit.Log(actor, "ediscovery.export", scope+":"+target, details)
	if counter.written == 0 {
		w.WriteHeader(http.StatusOK)
	}
}

// apiFolderRetention reports the retention policy in effect for one of the
// caller's folders. Legal holds are deliberately not disclosed to users.
func (h *Handler) apiFolderRetention(w http.ResponseWriter, r *http.Request) {
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	folder, err := h.folderSpace.GetFolder(r.Context(), access, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	response := map[string]any{"folder_id": folder.ID, "enabled": h.retention == nil || h.retention.Status(r.Context()).Enabled}
	if policy, ok := h.compliance.EffectivePolicy(folder.UserID, h.compliance.PrimaryDomain(r.Context(), folder.UserID), folder); ok {
		response["policy"] = map[string]any{"scope": policy.Scope, "action": policy.Action, "days": policy.Days, "special_use": policy.SpecialUse, "folder_pattern": policy.Pattern}
	}
	jsonResponse(w, http.StatusOK, response)
}

// parseComplianceDate accepts RFC 3339 or a calendar date; an end date names
// the whole day, so it resolves to the following midnight.
func parseComplianceDate(value string, end bool) (time.Time, error) {
	value = strings.TrimSpace(value)
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, errors.New("use YYYY-MM-DD or RFC 3339")
	}
	if end {
		parsed = parsed.AddDate(0, 0, 1)
	}
	return parsed.UTC(), nil
}

func safeComplianceName(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, value)
}
