package app

import (
	"maps"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
)

// Support access (impersonation) lets an administrator work as a user to
// help them: the user's mailbox and the user's personal settings. It does
// not reach the user's credentials, sign-in sessions, sharing grants,
// webhooks, synchronization jobs or account export, which could outlive the
// 15-minute session or hand the administrator lasting access; those routes
// refuse while it is active. A delegate working in another mailbox keeps
// their own settings.

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

// supportAccessExcludedPrefixes are the routes support access refuses.
var supportAccessExcludedPrefixes = []string{
	"/api/v1/user/two-factor",
	"/api/v1/user/browser-sessions",
	"/api/v1/user/app-passwords",
	"/api/v1/user/api-keys",
	"/api/v1/user/webhooks",
	"/api/v1/user/export",
	"/api/v1/user/mobileconfig",
	"/api/v1/grants",
	"/api/v1/folders/{id}/grants",
	"/api/v1/identities/{id}/grants",
	"/api/v1/share-links",
	"/api/v1/sync-jobs",
}

func supportAccessExcluded(method, path string) bool {
	if method == http.MethodPost && path == "/api/v1/user/eas-devices/{id}/wipe" {
		return true
	}
	for _, prefix := range supportAccessExcludedPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// supportAccessSections are the settings pages of routes it refuses.
var supportAccessSections = map[string]bool{
	"two-factor": true, "sessions": true, "app-passwords": true, "api-keys": true, "webhooks": true,
	"access": true, "delegation": true, "share-links": true, "migration": true,
}

func refuseDuringSupportAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if supportAccess(r) {
			jsonError(w, http.StatusForbidden, "not available during support access; return to your account to use it")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auditSettings records a personal-settings change under the signed-in
// user, naming the supported account during support access.
func (h *Handler) auditSettings(r *http.Request, action, resource string, details map[string]string) {
	h.audit.Log(currentActor(r).ID, action, resource, onBehalf(r, details))
}
