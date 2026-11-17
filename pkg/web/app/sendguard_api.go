package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/sendguard"
)

// ConfigureSendGuard installs the outbound sending guard whose limits,
// holds, and held mail the account administration manages. Successful
// browser sign-ins feed its login-spread heuristic.
func (h *Handler) ConfigureSendGuard(guard *sendguard.Guard) { h.sendGuard = guard }

func (h *Handler) registerSendGuardRoutes(api apiRouter) {
	api.handle("GET /api/v1/admin/outbound/holds", h.apiAdminOutboundHolds)
	api.handle("GET /api/v1/admin/users/{id}/sending", h.apiAdminAccountSending)
	api.handle("PUT /api/v1/admin/users/{id}/sending/limits", h.apiAdminAccountSendLimits)
	api.handle("POST /api/v1/admin/users/{id}/sending/release", h.apiAdminAccountSendingRelease)
	api.handle("POST /api/v1/admin/users/{id}/sending/purge", h.apiAdminAccountSendingPurge)
	api.handle("POST /api/v1/admin/users/{id}/credentials/reset", h.apiAdminResetCredentials)
}

// sendGuardAdmin authorizes an administrator and returns the guard, or
// writes the error response.
func (h *Handler) sendGuardAdmin(w http.ResponseWriter, r *http.Request) (*sendguard.Guard, bool) {
	if !h.requireAdminAPI(w, r) {
		return nil, false
	}
	if h.sendGuard == nil {
		jsonError(w, http.StatusServiceUnavailable, "outbound protection is unavailable")
		return nil, false
	}
	return h.sendGuard, true
}

func (h *Handler) apiAdminOutboundHolds(w http.ResponseWriter, r *http.Request) {
	guard, ok := h.sendGuardAdmin(w, r)
	if !ok {
		return
	}
	jsonResponse(w, http.StatusOK, guard.HeldAccounts())
}

// sendGuardAccountAdmin authorizes managing one account's sending and
// returns the guard, or writes the error response.
func (h *Handler) sendGuardAccountAdmin(w http.ResponseWriter, r *http.Request, account string) (*sendguard.Guard, accountAccess, bool) {
	reach, ok := h.requireAccountAdmin(w, r, account, authz.DomainAccountsManage)
	if !ok {
		return nil, reach, false
	}
	if h.sendGuard == nil {
		jsonError(w, http.StatusServiceUnavailable, "outbound protection is unavailable")
		return nil, reach, false
	}
	return h.sendGuard, reach, true
}

// checkSendLimitCeiling keeps a domain administrator's overrides at or
// below what the account inherits (server defaults with the domain's
// defaults applied); zero means unlimited, so it exceeds any set ceiling.
func checkSendLimitCeiling(limits model.SendLimits, inherited sendguard.Limits) error {
	for _, entry := range []struct {
		name    string
		value   *int
		ceiling int
	}{
		{sendguard.LimitMessagesPerHour, limits.MessagesPerHour, inherited.MessagesPerHour},
		{sendguard.LimitRecipientsPerHour, limits.RecipientsPerHour, inherited.RecipientsPerHour},
		{sendguard.LimitRecipientsPerDay, limits.RecipientsPerDay, inherited.RecipientsPerDay},
	} {
		if entry.value == nil || entry.ceiling == 0 {
			continue
		}
		if *entry.value == 0 || *entry.value > entry.ceiling {
			return fmt.Errorf("%w: %s may be at most %d for this domain", model.ErrDomainLimit, entry.name, entry.ceiling)
		}
	}
	return nil
}

func (h *Handler) apiAdminAccountSending(w http.ResponseWriter, r *http.Request) {
	guard, _, ok := h.sendGuardAccountAdmin(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	status, err := guard.Status(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiAdminAccountSendLimits(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	guard, reach, ok := h.sendGuardAccountAdmin(w, r, id)
	if !ok {
		return
	}
	var request model.SendLimits
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := sendguard.ValidateOverride(&request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if reach.delegated {
		if err := checkSendLimitCeiling(request, guard.AccountDefaults(r.Context(), id)); err != nil {
			apiError(w, err)
			return
		}
	}
	if err := guard.SetLimits(r.Context(), currentActor(r).ID, id, &request); err != nil {
		apiError(w, err)
		return
	}
	status, err := guard.Status(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiAdminAccountSendingRelease(w http.ResponseWriter, r *http.Request) {
	guard, ok := h.sendGuardAdmin(w, r)
	if !ok {
		return
	}
	released, err := guard.Release(r.Context(), currentActor(r).ID, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]int{"released": released})
}

func (h *Handler) apiAdminAccountSendingPurge(w http.ResponseWriter, r *http.Request) {
	guard, ok := h.sendGuardAdmin(w, r)
	if !ok {
		return
	}
	purged, err := guard.Purge(r.Context(), currentActor(r).ID, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]int{"purged": purged})
}

// credentialReset reports what one Reset credentials action changed. The
// generated password is returned once and never stored in plain text.
type credentialReset struct {
	PasswordReset       bool   `json:"password_reset"`
	GeneratedPassword   string `json:"generated_password,omitempty"`
	SessionsRevoked     int    `json:"sessions_revoked"`
	AppPasswordsRevoked int    `json:"app_passwords_revoked"`
}

// apiAdminResetCredentials replaces a local account's password (with the
// supplied one, or a generated one returned once), signs out every browser
// session, and revokes every application password. A directory account's
// password belongs to the directory, so only sessions and application
// passwords are revoked.
func (h *Handler) apiAdminResetCredentials(w http.ResponseWriter, r *http.Request) {
	reach, ok := h.requireAccountAdmin(w, r, r.PathValue("id"), authz.DomainAccountsManage)
	if !ok {
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Password != "" && len(request.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "password must contain at least 8 characters")
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	user, err := h.users.Get(r.Context(), id)
	if err != nil {
		apiError(w, err)
		return
	}
	if user.Resource != nil {
		apiError(w, model.ErrResourceAccount)
		return
	}
	result, err := h.resetCredentials(r.Context(), user, request.Password)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "account.credentials.reset", id, reach.auditDetails(map[string]string{
		"password_reset": strconv.FormatBool(result.PasswordReset), "sessions_revoked": strconv.Itoa(result.SessionsRevoked),
		"app_passwords_revoked": strconv.Itoa(result.AppPasswordsRevoked),
	}))
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) resetCredentials(ctx context.Context, user model.User, password string) (credentialReset, error) {
	var result credentialReset
	var passwordHash string
	if !user.Directory() {
		if password == "" {
			password = rand.Text()
			result.GeneratedPassword = password
		}
		var err error
		if passwordHash, err = auth.HashPassword(password); err != nil {
			return credentialReset{}, err
		}
	}
	deleted, err := h.sessions.UpdateActorAndDeleteOthers(ctx, user.ID, "", func(batchCtx context.Context) error {
		if passwordHash == "" {
			return nil
		}
		return h.users.Update(batchCtx, user.ID, func(record *model.User) { record.PasswordHash = passwordHash })
	})
	if err != nil {
		return credentialReset{}, fmt.Errorf("reset password and sessions: %w", err)
	}
	result.PasswordReset, result.SessionsRevoked = passwordHash != "", len(deleted)
	passwords, err := h.appPasswords.ListByUser(ctx, user.ID)
	if err != nil {
		return result, fmt.Errorf("list application passwords: %w", err)
	}
	var errs []error
	for _, credential := range passwords {
		if credential.Revoked {
			continue
		}
		if err := h.appPasswords.Revoke(ctx, credential.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		result.AppPasswordsRevoked++
	}
	return result, errors.Join(errs...)
}
