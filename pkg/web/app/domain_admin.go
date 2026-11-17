package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/store"
)

// adminScope is the administration an actor holds: system-wide, or delegated
// over the domains where a domain.admin binding grants domain.read.
type adminScope struct {
	system  bool
	domains []string
}

func (s adminScope) any() bool { return s.system || len(s.domains) > 0 }

// covers reports whether domain is inside the scope.
func (s adminScope) covers(domain string) bool {
	return s.system || slices.Contains(s.domains, strings.ToLower(strings.TrimSpace(domain)))
}

// coversAddress reports whether address belongs to a domain in the scope.
func (s adminScope) coversAddress(address string) bool {
	at := strings.LastIndex(address, "@")
	return s.system || at >= 0 && s.covers(address[at+1:])
}

// name is how the UI and audit label the scope.
func (s adminScope) name() string {
	if s.system {
		return "system"
	}
	return "domain"
}

// adminScopeFor resolves userID's administration. System administrators are
// never enumerated per domain.
func (h *Handler) adminScopeFor(ctx context.Context, userID string) adminScope {
	if userID == "" {
		return adminScope{}
	}
	if h.isAdmin(ctx, userID) {
		return adminScope{system: true}
	}
	domains, err := h.ts.DomainStore().List(ctx)
	if err != nil {
		return adminScope{}
	}
	ctx = authz.WithRequestScope(ctx)
	var scope adminScope
	for _, domain := range domains {
		if h.domainAllowed(ctx, userID, domain.ID, authz.DomainRead) {
			scope.domains = append(scope.domains, domain.ID)
		}
	}
	sort.Strings(scope.domains)
	return scope
}

// domainAllowed checks action on one Domain resource. System bindings with
// subtree inheritance satisfy it for every domain. Without a domain (a
// malformed address) only a system administrator passes, so the handler
// can report the input error itself.
func (h *Handler) domainAllowed(ctx context.Context, userID, domainID string, action authz.Action) bool {
	domainID = strings.ToLower(strings.TrimSpace(domainID))
	if userID == "" {
		return false
	}
	if domainID == "" {
		return h.isAdmin(ctx, userID)
	}
	decision, err := h.authorizer.Check(ctx, authz.Request{
		Actor:    model.PrincipalRef{Kind: model.PrincipalUser, ID: userID},
		Action:   action,
		Resource: model.ResourceRef{Kind: model.ResourceDomain, ID: domainID},
	})
	return err == nil && decision.Allowed
}

// requireAdminScope admits system and domain administrators.
func (h *Handler) requireAdminScope(w http.ResponseWriter, r *http.Request) (adminScope, bool) {
	scope := h.adminScopeFor(r.Context(), currentActor(r).ID)
	if !scope.any() {
		jsonError(w, http.StatusForbidden, "forbidden")
		return scope, false
	}
	return scope, true
}

// requireDomainAction authorizes action on domainID or writes 403.
func (h *Handler) requireDomainAction(w http.ResponseWriter, r *http.Request, domainID string, action authz.Action) bool {
	if !h.domainAllowed(r.Context(), currentActor(r).ID, domainID, action) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

// requireOwnerAPI admits only owner authority; see isOwner.
func (h *Handler) requireOwnerAPI(w http.ResponseWriter, r *http.Request) bool {
	if !h.isOwner(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "this operation requires a system owner")
		return false
	}
	return true
}

// accountAccess is how an administrator reached an account: its primary
// domain, and whether the reach was delegated (a domain administrator).
type accountAccess struct {
	domain    string
	delegated bool
}

// auditDetails marks delegated actions with the domain they were authorized
// through. The acting administrator is always the audit actor.
func (a accountAccess) auditDetails(details map[string]string) map[string]string {
	if !a.delegated {
		return details
	}
	if details == nil {
		details = map[string]string{}
	}
	details["admin_scope"] = "domain:" + a.domain
	return details
}

// requireAccountAdmin authorizes managing account userID under action.
// System administrators reach every account except, for system.admin, a
// system owner's. A domain administrator reaches an account whose primary
// identity is in a domain it holds action on, unless that account holds
// authority the actor does not: any system-scope binding (built-in or
// custom role), or delegated administration of another domain. Resetting
// such an account would hand the actor that authority.
func (h *Handler) requireAccountAdmin(w http.ResponseWriter, r *http.Request, userID string, action authz.Action) (accountAccess, bool) {
	ctx := authz.WithRequestScope(r.Context())
	actor := currentActor(r).ID
	userID = strings.ToLower(strings.TrimSpace(userID))
	domain, err := h.users.PrimaryDomain(ctx, userID)
	if err != nil {
		apiError(w, err)
		return accountAccess{}, false
	}
	if h.isAdmin(ctx, actor) {
		if userID != actor && !h.isOwner(ctx, actor) && h.isOwner(ctx, userID) {
			jsonError(w, http.StatusForbidden, "only a system owner can manage a system owner account")
			return accountAccess{}, false
		}
		return accountAccess{domain: domain}, true
	}
	if domain == "" || !h.domainAllowed(ctx, actor, domain, action) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return accountAccess{}, false
	}
	if userID != actor {
		if h.holdsSystemAuthority(ctx, userID) {
			jsonError(w, http.StatusForbidden, "a domain administrator cannot manage an account with system-wide roles")
			return accountAccess{}, false
		}
		actorScope, targetScope := h.adminScopeFor(ctx, actor), h.adminScopeFor(ctx, userID)
		for _, administered := range targetScope.domains {
			if !actorScope.covers(administered) {
				jsonError(w, http.StatusForbidden, "the account administers a domain outside your scope")
				return accountAccess{}, false
			}
		}
	}
	return accountAccess{domain: domain, delegated: true}, true
}

// holdsSystemAuthority reports whether userID holds any system-scope
// binding, which no domain administrator may reach. A lookup failure counts
// as holding one.
func (h *Handler) holdsSystemAuthority(ctx context.Context, userID string) bool {
	held, err := h.authorizer.HoldsSystemBinding(ctx, userID)
	return err != nil || held
}

// filterUsersToScope keeps accounts whose primary identity is in scope.
func (h *Handler) filterUsersToScope(ctx context.Context, scope adminScope, users []model.User) []model.User {
	if scope.system {
		return users
	}
	kept := users[:0]
	for _, user := range users {
		if domain, err := h.users.PrimaryDomain(ctx, user.ID); err == nil && domain != "" && scope.covers(domain) {
			kept = append(kept, user)
		}
	}
	return kept
}

// traceScopeFor narrows trace and queue visibility to the domains where the
// actor holds domain.trace.read. A nil result means unrestricted. The
// envelope sender of inbound mail is whatever the remote client claimed,
// so it reveals a message only when the message left the server.
func (h *Handler) traceScopeFor(ctx context.Context, actor string, scope adminScope) func(direction, sender, recipient string) bool {
	if scope.system {
		return nil
	}
	ctx = authz.WithRequestScope(ctx)
	var readable adminScope
	for _, domain := range scope.domains {
		if h.domainAllowed(ctx, actor, domain, authz.DomainTraceRead) {
			readable.domains = append(readable.domains, domain)
		}
	}
	return func(direction, sender, recipient string) bool {
		return readable.coversAddress(strings.ToLower(recipient)) ||
			strings.EqualFold(direction, string(queue.DirectionOutbound)) && readable.coversAddress(strings.ToLower(sender))
	}
}

func filterQueueMessages(messages []*queue.Message, visible func(direction, sender, recipient string) bool) []*queue.Message {
	if visible == nil {
		return messages
	}
	kept := make([]*queue.Message, 0, len(messages))
	for _, message := range messages {
		if message != nil && visible(string(message.Direction), message.EnvelopeSender, message.Recipient) {
			kept = append(kept, message)
		}
	}
	return kept
}

func addressDomain(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	if at := strings.LastIndex(address, "@"); at >= 0 {
		return address[at+1:]
	}
	return ""
}

// checkAccountCapacity rejects a new account beyond the domain's maximum.
// Callers hold domainLimitMu.
func (h *Handler) checkAccountCapacity(ctx context.Context, domainID string) error {
	domain, usage, err := h.domainWithUsage(ctx, domainID)
	if err != nil {
		return err
	}
	if domain.Limits.MaxAccounts > 0 && usage.Accounts >= domain.Limits.MaxAccounts {
		return fmt.Errorf("%w: %s allows at most %d accounts", model.ErrDomainLimit, domain.ID, domain.Limits.MaxAccounts)
	}
	return nil
}

// checkAliasCapacity rejects a new alias (non-primary identity or recipient
// alias) beyond the domain's maximum. Callers hold domainLimitMu.
func (h *Handler) checkAliasCapacity(ctx context.Context, domainID string) error {
	domain, usage, err := h.domainWithUsage(ctx, domainID)
	if err != nil {
		return err
	}
	if domain.Limits.MaxAliases > 0 && usage.Aliases >= domain.Limits.MaxAliases {
		return fmt.Errorf("%w: %s allows at most %d aliases", model.ErrDomainLimit, domain.ID, domain.Limits.MaxAliases)
	}
	return nil
}

// checkAccountQuota validates quota for an account in domainID. previous is
// the quota the account already counts toward the domain's assigned storage
// (zero for a new account). The per-account maximum binds domain
// administrators; the storage ceiling binds everyone. Callers hold
// domainLimitMu.
func (h *Handler) checkAccountQuota(ctx context.Context, domainID string, previous, quota int64, delegated bool) error {
	domain, usage, err := h.domainWithUsage(ctx, domainID)
	if err != nil {
		return err
	}
	limits := domain.Limits
	if delegated && limits.MaxAccountStorageBytes > 0 && (quota == 0 || quota > limits.MaxAccountStorageBytes) {
		return fmt.Errorf("%w: %s allows account storage quotas of at most %d bytes", model.ErrDomainLimit, domain.ID, limits.MaxAccountStorageBytes)
	}
	if limits.MaxStorageBytes > 0 {
		if quota == 0 {
			return fmt.Errorf("%w: %s has a storage ceiling, so the account needs a storage quota", model.ErrDomainLimit, domain.ID)
		}
		if assigned := usage.AssignedStorageBytes - previous + quota; assigned > limits.MaxStorageBytes {
			return fmt.Errorf("%w: %s would assign %d of its %d byte storage ceiling", model.ErrDomainLimit, domain.ID, assigned, limits.MaxStorageBytes)
		}
	}
	return nil
}

func (h *Handler) domainWithUsage(ctx context.Context, domainID string) (model.Domain, model.DomainUsage, error) {
	domain, err := h.ts.DomainStore().Get(ctx, domainID)
	if err != nil {
		return model.Domain{}, model.DomainUsage{}, err
	}
	usage, err := h.ts.DomainStore().Usage(ctx, domain.ID)
	return domain, usage, err
}

// domainAdministrator is one domain.admin binding on a domain.
type domainAdministrator struct {
	BindingID string `json:"binding_id"`
	UserID    string `json:"user_id"`
	GrantedBy string `json:"granted_by"`
}

func (h *Handler) domainAdministrators(ctx context.Context, domainID string) ([]domainAdministrator, error) {
	bindings, err := model.NewPolicyStore(h.ts).ListForResource(ctx, model.ResourceRef{Kind: model.ResourceDomain, ID: domainID})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	result := []domainAdministrator{}
	for _, binding := range bindings {
		if binding.RoleID == authz.RoleDomainAdmin && binding.Effect == model.EffectAllow && binding.Principal.Kind == model.PrincipalUser {
			result = append(result, domainAdministrator{BindingID: binding.ID, UserID: binding.Principal.ID, GrantedBy: binding.GrantedBy})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UserID < result[j].UserID })
	return result, nil
}

func (h *Handler) registerDomainAdminRoutes(api apiRouter) {
	api.handle("PUT /api/v1/admin/domains/{id}/limits", h.apiAdminDomainLimits)
	api.handle("GET /api/v1/admin/domains/{id}/admins", h.apiAdminDomainAdmins)
	api.handle("POST /api/v1/admin/domains/{id}/admins", h.apiAdminAddDomainAdmin)
	api.handle("DELETE /api/v1/admin/domains/{id}/admins/{user}", h.apiAdminRemoveDomainAdmin)
}

func (h *Handler) apiAdminDomainLimits(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if !h.requireDomainAction(w, r, id, authz.DomainLimitsManage) {
		return
	}
	var limits model.DomainLimits
	if err := decodeJSON(r, &limits); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := limits.Validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.ts.DomainStore().SetLimits(r.Context(), id, limits); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.limits.update", id, map[string]string{
		"max_accounts": fmt.Sprint(limits.MaxAccounts), "max_aliases": fmt.Sprint(limits.MaxAliases),
		"max_storage_bytes": fmt.Sprint(limits.MaxStorageBytes), "default_account_storage_bytes": fmt.Sprint(limits.DefaultAccountStorageBytes),
		"max_account_storage_bytes": fmt.Sprint(limits.MaxAccountStorageBytes),
	})
	domain, usage, err := h.domainWithUsage(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	response := projectAdminDomain(domain)
	response.Usage = &usage
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminDomainAdmins(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if !h.requireDomainAction(w, r, id, authz.DomainAdminsManage) {
		return
	}
	if _, err := h.ts.DomainStore().Get(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	admins, err := h.domainAdministrators(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, admins)
}

func (h *Handler) apiAdminAddDomainAdmin(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if !h.requireDomainAction(w, r, id, authz.DomainAdminsManage) {
		return
	}
	var request struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.UserID = strings.ToLower(strings.TrimSpace(request.UserID))
	if _, err := h.ts.DomainStore().Get(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.users.Get(r.Context(), request.UserID); err != nil {
		apiError(w, err)
		return
	}
	admins, err := h.domainAdministrators(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	for _, admin := range admins {
		if admin.UserID == request.UserID {
			jsonResponse(w, http.StatusOK, admin)
			return
		}
	}
	binding, err := model.NewPolicyStore(h.ts).Create(r.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: request.UserID},
		Resource:  model.ResourceRef{Kind: model.ResourceDomain, ID: id},
		Effect:    model.EffectAllow, RoleID: authz.RoleDomainAdmin, Inheritance: model.InheritanceSubtree,
		GrantedBy: currentActor(r).ID,
	})
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.admin.grant", id, map[string]string{"user_id": request.UserID, "binding_id": binding.ID})
	jsonResponse(w, http.StatusCreated, domainAdministrator{BindingID: binding.ID, UserID: request.UserID, GrantedBy: binding.GrantedBy})
}

func (h *Handler) apiAdminRemoveDomainAdmin(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if !h.requireDomainAction(w, r, id, authz.DomainAdminsManage) {
		return
	}
	userID := strings.ToLower(strings.TrimSpace(r.PathValue("user")))
	admins, err := h.domainAdministrators(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	removed := 0
	for _, admin := range admins {
		if admin.UserID != userID {
			continue
		}
		if err := model.NewPolicyStore(h.ts).Delete(r.Context(), admin.BindingID); err != nil {
			apiError(w, err)
			return
		}
		removed++
	}
	if removed == 0 {
		jsonError(w, http.StatusNotFound, "not a domain administrator")
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.admin.revoke", id, map[string]string{"user_id": userID})
	w.WriteHeader(http.StatusNoContent)
}
