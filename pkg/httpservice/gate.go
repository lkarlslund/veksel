package httpservice

import (
	"net/http"
	"sync"
)

// ServiceGate switches HTTP services on and off at runtime. Service
// handlers stay mounted; a request for a disabled service gets 404, so a
// toggle needs neither a restart nor a route change. Services that were
// never set are enabled.
type ServiceGate struct {
	disabled sync.Map // service name → struct{}
}

// Set enables or disables service (a ServiceForPath name).
func (g *ServiceGate) Set(service string, enabled bool) {
	if enabled {
		g.disabled.Delete(service)
	} else {
		g.disabled.Store(service, struct{}{})
	}
}

// Enabled reports whether requests for service are served.
func (g *ServiceGate) Enabled(service string) bool {
	_, disabled := g.disabled.Load(service)
	return !disabled
}

// Handler serves next only for enabled services.
func (g *ServiceGate) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Enabled(ServiceForPath(r.URL.Path)) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
