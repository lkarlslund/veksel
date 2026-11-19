package app

import (
	"context"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// apiKeyHeader carries a REST API key. Unlike the session cookie, browsers
// never attach it on their own, so key-authenticated requests need no CSRF
// token.
const apiKeyHeader = "X-API-Key"

// apiAccess selects which credentials may reach a REST route.
type apiAccess uint8

const (
	// apiAnyCredential admits a browser session (with a CSRF token on unsafe
	// methods) or an administrator's X-API-Key.
	apiAnyCredential apiAccess = iota
	// apiBrowserOnly admits only a browser session. Such routes manage the
	// session itself or stream session-bound events.
	apiBrowserOnly
	// apiPublic needs no credential; the handler applies its own checks.
	apiPublic
)

// apiScope selects whether a route's authorization checks share one
// request-scoped cache of the actor's policy bindings (authz.WithRequestScope).
type apiScope uint8

const (
	// scopeSafeMethods scopes GET and HEAD requests. Reads never change
	// authorization state, so a cached binding cannot go stale within them.
	scopeSafeMethods apiScope = iota
	// scopeAlways also scopes changing requests. Use it only for bounded
	// handlers that evaluate many resources without changing grants, groups,
	// or roles, such as search and bulk item actions.
	scopeAlways
	// scopeNever is for long-lived connections, which must observe grants
	// revoked while they stay open.
	scopeNever
)

// apiRoute describes one registered REST route. The table drives the
// OpenAPI reference.
type apiRoute struct {
	Method  string
	Path    string
	Access  apiAccess
	Summary string
	Scope   apiScope
	// ReadOnly marks a POST route whose handler only reads, such as a query
	// with a request body or an archive download. Named keys need api.read
	// for it; browser sessions still need a CSRF token.
	ReadOnly bool
}

// apiRouter registers REST routes behind the two authentication front-ends:
// browser session + CSRF, or X-API-Key + scope.
type apiRouter struct {
	h   *Handler
	mux *http.ServeMux
}

// handle registers a route reachable with a browser session or an API key.
func (a apiRouter) handle(pattern string, handler http.HandlerFunc) {
	a.register(pattern, apiRoute{Access: apiAnyCredential, Scope: scopeSafeMethods}, handler)
}

// handleBulk registers a changing route like handle, but lets its many
// authorization checks share one request scope; see scopeAlways.
func (a apiRouter) handleBulk(pattern string, handler http.HandlerFunc) {
	a.register(pattern, apiRoute{Access: apiAnyCredential, Scope: scopeAlways}, handler)
}

// readOnly registers a POST route whose handler only reads; see
// apiRoute.ReadOnly. Reads never change grants, so its authorization checks
// share one request scope.
func (a apiRouter) readOnly(pattern string, handler http.HandlerFunc) {
	a.register(pattern, apiRoute{Access: apiAnyCredential, Scope: scopeAlways, ReadOnly: true}, handler)
}

// browserOnly registers a route reachable only with a browser session.
func (a apiRouter) browserOnly(pattern string, handler http.HandlerFunc) {
	a.register(pattern, apiRoute{Access: apiBrowserOnly, Scope: scopeSafeMethods}, handler)
}

// stream registers a long-lived, browser-session-only route such as the
// events websocket. Its authorization checks are never request-scoped.
func (a apiRouter) stream(pattern string, handler http.HandlerFunc) {
	a.register(pattern, apiRoute{Access: apiBrowserOnly, Scope: scopeNever}, handler)
}

// public registers a route that needs no credential, such as sign-in,
// setup, health probes, and public share links.
func (a apiRouter) public(pattern string, handler http.HandlerFunc) {
	a.register(pattern, apiRoute{Access: apiPublic, Scope: scopeSafeMethods}, handler)
}

// register completes route with the pattern's method and path and mounts
// handler behind the route's authentication front-ends.
func (a apiRouter) register(pattern string, route apiRoute, handler http.HandlerFunc) {
	route.Method, route.Path, _ = strings.Cut(pattern, " ")
	route.Summary = handlerSummary(handler)
	var next http.Handler = handler
	if !safeMethod(route.Method) {
		next = a.h.auditSupportAccess(route, next)
	}
	if route.Scope == scopeAlways || route.Scope == scopeSafeMethods && safeMethod(route.Method) {
		next = requestScoped(next)
	}
	if route.Access != apiPublic {
		if !safeMethod(route.Method) {
			next = a.h.requireAPICSRF(next)
		}
		next = a.h.authenticateAPI(route, next)
	}
	a.mux.Handle(pattern, next)
	a.h.apiRoutes = append(a.h.apiRoutes, route)
}

// requestScoped resolves each actor's policy bindings at most once per
// request, so handlers that authorize many folders or items do not reload
// them per decision. Later requests start a fresh scope and observe revoked
// grants.
func requestScoped(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(authz.WithRequestScope(r.Context())))
	})
}

func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// apiKeyCredential is the context value of a key-authenticated request.
type apiKeyCredential struct {
	UserID string
	Key    *model.APIKey
}

type apiKeyContextKey struct{}

func apiKeyFromContext(ctx context.Context) (apiKeyCredential, bool) {
	credential, ok := ctx.Value(apiKeyContextKey{}).(apiKeyCredential)
	return credential, ok
}

// permits reports whether the credential grants scope.
func (c apiKeyCredential) permits(scope string) bool {
	return c.Key.Permits(scope)
}

// authenticateAPI is the authentication front-end of every REST route.
// Requests carrying X-API-Key are authenticated by key, everything else by
// browser session.
func (h *Handler) authenticateAPI(route apiRoute, next http.Handler) http.Handler {
	bySession := h.requireAPISession(next)
	scope := route.requiredKeyScope()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := r.Header.Get(apiKeyHeader)
		if secret == "" {
			bySession.ServeHTTP(w, r)
			return
		}
		if route.Access == apiBrowserOnly {
			jsonError(w, http.StatusForbidden, "this endpoint requires a browser session")
			return
		}
		credential, status, message := h.authenticateAPIKey(r.Context(), secret)
		if status != http.StatusOK {
			jsonError(w, status, message)
			return
		}
		if !credential.permits(scope) {
			jsonError(w, http.StatusForbidden, "API key scope does not permit this operation")
			return
		}
		ctx := withSession(r.Context(), model.Session{ActorID: credential.UserID, SubjectID: credential.UserID})
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, apiKeyContextKey{}, credential)))
	})
}

// authenticateAPIKey resolves secret to an enabled system administrator.
// The REST control plane is administrative, so keys of other users are
// refused; their keys serve MCP only. Only named keys authenticate, so an
// invalid key costs the named-key lookup and never a scan of user records.
func (h *Handler) authenticateAPIKey(ctx context.Context, secret string) (apiKeyCredential, int, string) {
	key, err := h.apiKeys.GetBySecret(ctx, secret)
	if err != nil || key == nil {
		return apiKeyCredential{}, http.StatusUnauthorized, "invalid API key"
	}
	credential := apiKeyCredential{UserID: key.UserID, Key: key}
	user, err := h.users.Get(ctx, credential.UserID)
	if err != nil || !user.Enabled {
		return credential, http.StatusUnauthorized, "invalid API key"
	}
	if !h.isAdmin(ctx, user.ID) {
		return credential, http.StatusForbidden, "API access requires a system administrator"
	}
	_ = h.apiKeys.UpdateLastUsed(ctx, key.ID)
	return credential, http.StatusOK, ""
}

// requiredKeyScope is the named-key scope the route needs: reads need
// api.read, changes api.write, and changes to API keys keys.manage.
func (route apiRoute) requiredKeyScope() string {
	switch {
	case safeMethod(route.Method) || route.ReadOnly:
		return model.APIKeyScopeAPIRead
	case strings.HasPrefix(route.Path, "/api/v1/user/api-keys"):
		return model.APIKeyScopeKeysManage
	default:
		return model.APIKeyScopeAPIWrite
	}
}
