package app

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	httpSwagger "github.com/swaggo/http-swagger"
)

// registerReference serves the OpenAPI document of the registered REST
// routes and its interactive viewer. Both describe the full administrative
// surface, so they require a browser session or an administrator API key.
func (h *Handler) registerReference(api apiRouter) {
	api.handle("GET /api/v1/swagger.json", h.apiReference)
	viewer := httpSwagger.Handler(
		httpSwagger.URL("/api/v1/swagger.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
	)
	byKey := h.authenticateAPI(apiRoute{Method: http.MethodGet, Path: "/api/docs/", Access: apiAnyCredential}, viewer)
	bySession := h.requireSession(viewer)
	api.mux.Handle("GET /api/docs/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(apiKeyHeader) != "" {
			byKey.ServeHTTP(w, r)
			return
		}
		bySession.ServeHTTP(w, r)
	}))
}

func (h *Handler) apiReference(w http.ResponseWriter, _ *http.Request) {
	h.referenceOnce.Do(func() { h.reference, h.referenceErr = json.Marshal(openAPIDocument(h.apiRoutes)) })
	if h.referenceErr != nil {
		jsonError(w, http.StatusInternalServerError, "API reference unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(h.reference)
}

const referenceDescription = "The Veksel REST control plane: the same API the web interface uses. " +
	"Requests authenticate with a browser session, whose POST, PUT, PATCH, and DELETE requests need " +
	"the X-CSRF-Token header, or with an X-API-Key whose owner is a system administrator. " +
	"Named keys need api.read for reads (including read-only POST operations such as search and " +
	"backup download), api.write for changes, and keys.manage for changes to API keys; they need no CSRF token. " +
	"Routes marked browser-only refuse API keys."

var pathParameter = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(\.\.\.)?\}`)

// openAPIDocument describes routes as an OpenAPI 3 document. Request and
// response bodies are not modelled; the document lists every operation with
// its parameters and credentials.
func openAPIDocument(routes []apiRoute) map[string]any {
	paths := map[string]map[string]any{}
	for _, route := range routes {
		parameters := []map[string]any{}
		for _, match := range pathParameter.FindAllStringSubmatch(route.Path, -1) {
			parameters = append(parameters, map[string]any{
				"name": match[1], "in": "path", "required": true, "schema": map[string]string{"type": "string"},
			})
		}
		path := pathParameter.ReplaceAllString(route.Path, "{$1}")
		operation := map[string]any{
			"summary":    route.Summary,
			"tags":       []string{referenceTag(path)},
			"parameters": parameters,
			"responses":  map[string]any{"200": map[string]string{"description": "Success"}},
		}
		switch route.Access {
		case apiPublic:
			operation["security"] = []map[string][]string{}
		case apiBrowserOnly:
			operation["description"] = "Browser session only."
			operation["security"] = []map[string][]string{{"session": {}}}
			addAuthenticationResponses(operation)
		default:
			operation["description"] = "API keys need the " + route.requiredKeyScope() + " scope."
			operation["security"] = []map[string][]string{{"session": {}}, {"apiKey": {}}}
			addAuthenticationResponses(operation)
		}
		if paths[path] == nil {
			paths[path] = map[string]any{}
		}
		paths[path][strings.ToLower(route.Method)] = operation
	}
	return map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]string{"title": "Veksel REST API", "version": "v1", "description": referenceDescription},
		"paths":   paths,
		"components": map[string]any{"securitySchemes": map[string]any{
			"session": map[string]string{"type": "apiKey", "in": "cookie", "name": sessionCookie},
			"apiKey":  map[string]string{"type": "apiKey", "in": "header", "name": apiKeyHeader},
		}},
	}
}

func addAuthenticationResponses(operation map[string]any) {
	responses := operation["responses"].(map[string]any)
	responses["401"] = map[string]string{"description": "Missing or invalid credentials"}
	responses["403"] = map[string]string{"description": "Forbidden, missing CSRF token, or insufficient API key scope"}
}

// referenceTag groups /api/v1/<area>/... and /api/v1/admin/<area>/...
func referenceTag(path string) string {
	segments := strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/")
	if segments[0] == "admin" && len(segments) > 1 {
		return "admin/" + segments[1]
	}
	return segments[0]
}

// handlerSummary turns a handler method name such as apiAdminDKIMKeys into
// "Admin DKIM keys".
func handlerSummary(handler http.HandlerFunc) string {
	name := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()
	name = strings.TrimSuffix(name[strings.LastIndex(name, ".")+1:], "-fm")
	for _, prefix := range []string{"api", "handle"} {
		if trimmed, ok := strings.CutPrefix(name, prefix); ok && trimmed != "" {
			name = trimmed
			break
		}
	}
	runes := []rune(name)
	var words []string
	start := 0
	for i := 1; i <= len(runes); i++ {
		boundary := i == len(runes) || unicode.IsUpper(runes[i]) &&
			(unicode.IsLower(runes[i-1]) || i+1 < len(runes) && unicode.IsLower(runes[i+1]))
		if !boundary {
			continue
		}
		word := string(runes[start:i])
		if strings.ToUpper(word) != word || len(word) == 1 {
			word = strings.ToLower(word)
		}
		words = append(words, word)
		start = i
	}
	if len(words) == 0 {
		return ""
	}
	first := []rune(words[0])
	first[0] = unicode.ToUpper(first[0])
	words[0] = string(first)
	return strings.Join(words, " ")
}
