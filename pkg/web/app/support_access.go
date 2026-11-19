package app

import (
	"maps"
	"net/http"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// Support access (impersonation) lets an administrator work as a user: the
// user's mailbox and every user setting, including credentials, sessions,
// sharing, webhooks and synchronization. Every change is audited under the
// administrator. A delegate working in another mailbox keeps their own
// settings.

func supportAccess(r *http.Request) bool {
	return currentActingMode(r) == authz.ActingImpersonation
}

// settingsUserID is the account whose personal settings a request reads
// and changes: the account being supported under support access, otherwise
// the signed-in user.
func settingsUserID(r *http.Request) string {
	if supportAccess(r) {
		return currentSubject(r).ID
	}
	return currentActor(r).ID
}

// onBehalf adds the supported account to audit details recorded under the
// administrator's name during support access.
func onBehalf(r *http.Request, details map[string]string) map[string]string {
	if !supportAccess(r) {
		return details
	}
	out := make(map[string]string, len(details)+1)
	maps.Copy(out, details)
	out["subject_id"] = currentSubject(r).ID
	return out
}

// settingsPrincipal is settingsUserID as a principal, for services that
// act on behalf of one account.
func settingsPrincipal(r *http.Request) model.PrincipalRef {
	return model.PrincipalRef{Kind: model.PrincipalUser, ID: settingsUserID(r)}
}

// auditSupportAccess records every changing API request made during support
// access under the administrator, naming the supported account, the route
// and the outcome. Handlers that audit under the account they act on stay
// attributable to the person who made the change.
func (h *Handler) auditSupportAccess(route apiRoute, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !supportAccess(r) {
			next.ServeHTTP(w, r)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		h.audit.Log(currentActor(r).ID, "support_access.request", currentSubject(r).ID, map[string]string{
			"method": route.Method, "route": route.Path, "status": strconv.Itoa(recorder.status), "reason": currentActingReason(r),
		})
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func currentActingReason(r *http.Request) string {
	session, _ := sessionFromContext(r.Context())
	return session.ActingReason
}

// auditSettings records a personal-settings change under the signed-in
// user, naming the supported account during support access.
func (h *Handler) auditSettings(r *http.Request, action, resource string, details map[string]string) {
	h.audit.Log(currentActor(r).ID, action, resource, onBehalf(r, details))
}
