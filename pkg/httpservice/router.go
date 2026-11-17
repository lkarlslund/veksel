// Package httpservice maps requests on shared HTTP(S) listeners to Veksel services.
package httpservice

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

// ServiceForPath classifies the public HTTP endpoint owning path.
func ServiceForPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, "/dav/"):
		return "dav"
	case lower == "/.well-known/jmap" || strings.HasPrefix(lower, "/jmap/"):
		return "jmap"
	case lower == "/mcp" || strings.HasPrefix(lower, "/mcp/"):
		return "mcp"
	case strings.HasPrefix(lower, "/ews/"):
		return "ews"
	case lower == "/microsoft-server-activesync":
		return "eas"
	case strings.HasPrefix(lower, "/autodiscover/"), strings.HasPrefix(lower, "/mail/"), strings.HasPrefix(lower, "/browser/"), strings.HasPrefix(lower, "/.well-known/"):
		return "autodiscover"
	default:
		return "web"
	}
}

// Handler limits a common application mux to the services bound to one
// listener. A configured HSTS policy is sent on every response of an HTTPS
// listener; on a plain-HTTP listener it is sent only when a trusted reverse
// proxy reports that the client connected over HTTPS (see RequestClient), so
// it requires TrustedProxies.Handler to wrap this handler.
func Handler(listener config.HTTPListener, next http.Handler) http.Handler {
	bound := make(map[string]struct{}, len(listener.Services))
	for _, service := range listener.Services {
		bound[service] = struct{}{}
	}
	logger := logpkg.For(logpkg.ModuleWeb).With("listener", listener.ID)
	hsts := hstsHeader(listener)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hsts != "" && (listener.Transport == config.HTTPSTransport || RequestClient(r).HTTPS) {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
		service := ServiceForPath(r.URL.Path)
		if _, ok := bound[service]; !ok {
			http.NotFound(w, r)
			return
		}
		if !listener.AccessLog {
			next.ServeHTTP(w, r)
			return
		}
		started := time.Now()
		next.ServeHTTP(w, r)
		fields := []any{"method", r.Method, "path", r.URL.Path, "service", service, "remote", r.RemoteAddr, "client", RequestClient(r).IP, "duration", time.Since(started)}
		switch listener.LogLevel {
		case "trace":
			logger.Trace("HTTP request", fields...)
		case "debug":
			logger.Debug("HTTP request", fields...)
		case "warn":
			logger.Warn("HTTP request", fields...)
		case "error":
			logger.Error("HTTP request", fields...)
		default:
			logger.Info("HTTP request", fields...)
		}
	})
}

func hstsHeader(listener config.HTTPListener) string {
	if listener.HSTSMaxAgeDays == nil {
		return ""
	}
	value := fmt.Sprintf("max-age=%d", int64(*listener.HSTSMaxAgeDays)*24*60*60)
	if listener.HSTSIncludeSubdomains {
		value += "; includeSubDomains"
	}
	if listener.HSTSPreload {
		value += "; preload"
	}
	return value
}
