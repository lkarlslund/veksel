package app

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// userAliasPolicy is the live self-service temporary alias policy.
type userAliasPolicy struct {
	enabled    bool
	maxPerUser int
	domains    []string
}

func userAliasPolicyFromConfig(cfg *config.Config) *userAliasPolicy {
	domains := make([]string, 0, len(cfg.UserAliasesDomains))
	for _, domain := range cfg.UserAliasesDomains {
		domains = append(domains, strings.ToLower(strings.TrimSpace(domain)))
	}
	return &userAliasPolicy{enabled: cfg.UserAliasesEnabled, maxPerUser: cfg.UserAliasesMaxPerUser, domains: domains}
}

// currentUserAliasPolicy returns the live policy, or the defaults before
// configuration is installed.
func (h *Handler) currentUserAliasPolicy() *userAliasPolicy {
	if policy := h.userAliases.Load(); policy != nil {
		return policy
	}
	return userAliasPolicyFromConfig(config.Default())
}

// allows reports whether users may create aliases on domain.
func (p *userAliasPolicy) allows(domain string) bool {
	return p.enabled && (len(p.domains) == 0 || slices.Contains(p.domains, strings.ToLower(domain)))
}

// userAliasExpiries are the lifetimes a user can pick; "never" is zero.
var userAliasExpiries = map[string]time.Duration{
	"day": 24 * time.Hour, "week": 7 * 24 * time.Hour, "month": 30 * 24 * time.Hour, "never": 0,
}

type userAliasView struct {
	Address       string `json:"address"`
	Label         string `json:"label,omitempty"`
	FolderPath    string `json:"folder_path,omitempty"`
	Enabled       bool   `json:"enabled"`
	AdminDisabled bool   `json:"admin_disabled,omitempty"`
	Expired       bool   `json:"expired,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	OnInactive    string `json:"on_inactive"`
	CreatedAt     string `json:"created_at"`
	UserID        string `json:"user_id,omitempty"`
}

func projectUserAlias(alias model.UserAlias, now time.Time, withOwner bool) userAliasView {
	view := userAliasView{
		Address: alias.Address, Label: alias.Label, FolderPath: alias.FolderPath, Enabled: alias.Enabled,
		AdminDisabled: alias.AdminDisabled, Expired: alias.Expired(now), OnInactive: alias.OnInactive,
		CreatedAt: alias.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !alias.ExpiresAt.IsZero() {
		view.ExpiresAt = alias.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if withOwner {
		view.UserID = alias.UserID
	}
	return view
}

func projectUserAliases(aliases []model.UserAlias, withOwner bool) []userAliasView {
	now := time.Now()
	views := make([]userAliasView, 0, len(aliases))
	for _, alias := range aliases {
		views = append(views, projectUserAlias(alias, now, withOwner))
	}
	return views
}

func (h *Handler) registerUserAliasRoutes(api apiRouter) {
	api.handle("GET /api/v1/user/aliases", h.apiUserAliases)
	api.handle("POST /api/v1/user/aliases", h.apiCreateUserAlias)
	api.handle("PATCH /api/v1/user/aliases/{address}", h.apiUpdateUserAlias)
	api.handle("DELETE /api/v1/user/aliases/{address}", h.apiDeleteUserAlias)
	api.handle("GET /api/v1/admin/users/{id}/aliases", h.apiAdminUserAliases)
	api.handle("PUT /api/v1/admin/users/{id}/aliases/{address}/lock", h.apiAdminLockUserAlias)
}

// userAliasDomains lists the hosted domains where the user may create
// aliases: those of the user's enabled identities that the policy allows.
func (h *Handler) userAliasDomains(r *http.Request, userID string) ([]string, error) {
	identities, err := h.users.ListEmailAddressesForUser(r.Context(), userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	policy := h.currentUserAliasPolicy()
	domains := []string{}
	for _, identity := range identities {
		if identity.Enabled && policy.allows(identity.DomainID) && !slices.Contains(domains, identity.DomainID) {
			domains = append(domains, identity.DomainID)
		}
	}
	slices.Sort(domains)
	return domains, nil
}

func (h *Handler) apiUserAliases(w http.ResponseWriter, r *http.Request) {
	userID := settingsUserID(r)
	aliases, err := h.ts.UserAliasStore().ListForUser(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	domains, err := h.userAliasDomains(r, userID)
	if err != nil {
		apiError(w, err)
		return
	}
	policy := h.currentUserAliasPolicy()
	jsonResponse(w, http.StatusOK, map[string]any{
		"aliases": projectUserAliases(aliases, false), "domains": domains,
		"enabled": policy.enabled, "max_per_user": policy.maxPerUser,
		"expiries": []string{"day", "week", "month", "never"},
	})
}

func (h *Handler) apiCreateUserAlias(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Domain     string `json:"domain"`
		Prefix     string `json:"prefix"`
		Label      string `json:"label"`
		Expiry     string `json:"expiry"`
		FolderPath string `json:"folder_path"`
		OnInactive string `json:"on_inactive"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID := settingsUserID(r)
	policy := h.currentUserAliasPolicy()
	if !policy.enabled {
		jsonError(w, http.StatusForbidden, "temporary aliases are disabled")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(request.Domain))
	allowed, err := h.userAliasDomains(r, userID)
	if err != nil {
		apiError(w, err)
		return
	}
	if domain == "" && len(allowed) == 1 {
		domain = allowed[0]
	}
	if !slices.Contains(allowed, domain) {
		jsonError(w, http.StatusBadRequest, "temporary aliases are not available on that domain")
		return
	}
	expiry, ok := userAliasExpiries[strings.ToLower(strings.TrimSpace(request.Expiry))]
	if !ok {
		if request.Expiry != "" {
			jsonError(w, http.StatusBadRequest, "expiry must be day, week, month, or never")
			return
		}
		expiry = userAliasExpiries["never"]
	}
	h.domainLimitMu.Lock()
	defer h.domainLimitMu.Unlock()
	if err := h.checkAliasCapacity(r.Context(), domain); err != nil {
		apiError(w, err)
		return
	}
	alias, err := h.ts.UserAliasStore().Create(r.Context(), model.UserAliasRequest{
		UserID: userID, DomainID: domain, Prefix: request.Prefix, Label: request.Label, FolderPath: request.FolderPath,
		Expiry: expiry, OnInactive: request.OnInactive, MaxPerUser: policy.maxPerUser,
	})
	if err != nil {
		userAliasError(w, err)
		return
	}
	h.auditSettings(r, "user_alias.create", alias.Address, map[string]string{"domain": domain})
	jsonResponse(w, http.StatusCreated, projectUserAlias(alias, time.Now(), false))
}

func (h *Handler) apiUpdateUserAlias(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Label      *string `json:"label"`
		FolderPath *string `json:"folder_path"`
		Enabled    *bool   `json:"enabled"`
		OnInactive *string `json:"on_inactive"`
		Expiry     *string `json:"expiry"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	update := model.UserAliasUpdate{Label: request.Label, FolderPath: request.FolderPath, Enabled: request.Enabled, OnInactive: request.OnInactive}
	if request.Expiry != nil {
		expiry, ok := userAliasExpiries[strings.ToLower(strings.TrimSpace(*request.Expiry))]
		if !ok {
			jsonError(w, http.StatusBadRequest, "expiry must be day, week, month, or never")
			return
		}
		update.Expiry = &expiry
	}
	userID := settingsUserID(r)
	alias, err := h.ts.UserAliasStore().Update(r.Context(), r.PathValue("address"), userID, update)
	if err != nil {
		userAliasError(w, err)
		return
	}
	h.auditSettings(r, "user_alias.update", alias.Address, nil)
	jsonResponse(w, http.StatusOK, projectUserAlias(alias, time.Now(), false))
}

func (h *Handler) apiDeleteUserAlias(w http.ResponseWriter, r *http.Request) {
	userID := settingsUserID(r)
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	if err := h.ts.UserAliasStore().Delete(r.Context(), address, userID); err != nil {
		userAliasError(w, err)
		return
	}
	h.auditSettings(r, "user_alias.delete", address, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiAdminUserAliases(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if _, ok := h.requireAccountAdmin(w, r, userID, authz.DomainAccountsManage); !ok {
		return
	}
	aliases, err := h.ts.UserAliasStore().ListForUser(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, projectUserAliases(aliases, true))
}

// apiAdminLockUserAlias disables an account's temporary alias so the owner
// cannot enable it, or lifts that lock.
func (h *Handler) apiAdminLockUserAlias(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	reach, ok := h.requireAccountAdmin(w, r, userID, authz.DomainAccountsManage)
	if !ok {
		return
	}
	var request struct {
		Disabled bool `json:"disabled"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	current, err := h.ts.UserAliasStore().Get(r.Context(), address)
	if err != nil || current.UserID != userID || current.Tombstone() {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	alias, err := h.ts.UserAliasStore().SetAdminDisabled(r.Context(), address, request.Disabled)
	if err != nil {
		userAliasError(w, err)
		return
	}
	reach.domain = alias.DomainID
	h.audit.Log(currentActor(r).ID, "user_alias.lock", address, reach.auditDetails(map[string]string{"user_id": userID, "disabled": boolString(request.Disabled)}))
	jsonResponse(w, http.StatusOK, projectUserAlias(alias, time.Now(), true))
}

func userAliasError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, model.ErrUserAliasInvalid):
		jsonError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, model.ErrUserAliasLimit), errors.Is(err, model.ErrUserAliasLocked):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, model.ErrUserAliasNotOwner):
		jsonError(w, http.StatusNotFound, "not found")
	default:
		apiError(w, err)
	}
}
