package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

const (
	HTTPTransport      = "http"
	HTTPSTransport     = "https"
	MaxHSTSMaxAgeDays  = 730
	MinHSTSPreloadDays = 365
)

var HTTPServices = []string{"web", "dav", "jmap", "mcp", "ews", "eas", "autodiscover"}

// HTTPListener owns transport concerns for every HTTP-based Veksel service.
// Protocol configuration only decides which services are exposed by a listener.
type HTTPListener struct {
	ID          string `toml:"id" json:"id"`
	Name        string `toml:"name" json:"name"`
	Enabled     bool   `toml:"enabled" json:"enabled"`
	Transport   string `toml:"transport" json:"transport"`
	Address     string `toml:"address" json:"address"`
	Certificate string `toml:"certificate,omitempty" json:"certificate,omitempty"`
	// HSTS settings apply to every response of an HTTPS listener. On an HTTP
	// listener they apply only when a trusted reverse proxy reports HTTPS.
	HSTSMaxAgeDays        *int     `toml:"hsts_max_age_days,omitempty" json:"hsts_max_age_days,omitempty"`
	HSTSIncludeSubdomains bool     `toml:"hsts_include_subdomains,omitempty" json:"hsts_include_subdomains,omitempty"`
	HSTSPreload           bool     `toml:"hsts_preload,omitempty" json:"hsts_preload,omitempty"`
	AccessLog             bool     `toml:"access_log" json:"access_log"`
	LogLevel              string   `toml:"log_level" json:"log_level"`
	Services              []string `toml:"services" json:"services"`
}

func defaultHTTPListeners() []HTTPListener {
	return []HTTPListener{{
		ID: "default-http", Name: "Default HTTP", Enabled: true,
		Transport: HTTPTransport, Address: "0.0.0.0:8472", LogLevel: "inherit",
		Services: slices.Clone(HTTPServices),
	}}
}

func migratedHTTPListeners(cfg *Config) []HTTPListener {
	services := slices.Clone(HTTPServices)
	listeners := []HTTPListener{{
		ID: "default-http", Name: "Default HTTP", Enabled: true,
		Transport: HTTPTransport, Address: cfg.ListenAddr, LogLevel: "inherit", Services: services,
	}}
	if cfg.HTTPSEnabled {
		listeners = append(listeners, HTTPListener{
			ID: "default-https", Name: "Default HTTPS", Enabled: true,
			Transport: HTTPSTransport, Address: cfg.HTTPSListen,
			Certificate: cfg.HTTPSCertificate, LogLevel: "inherit", Services: slices.Clone(services),
		})
	}
	return listeners
}

func validateHTTPListeners(listeners []HTTPListener) error {
	if len(listeners) == 0 {
		return errors.New("http_listeners must contain at least one listener")
	}
	ids, addresses := make(map[string]struct{}, len(listeners)), make(map[string]string, len(listeners))
	hasWeb := false
	for i, listener := range listeners {
		prefix := fmt.Sprintf("http_listeners[%d]", i)
		listener.ID = strings.TrimSpace(listener.ID)
		if listener.ID == "" || strings.ContainsAny(listener.ID, "/\\\x00") {
			return fmt.Errorf("%s.id is invalid", prefix)
		}
		if _, exists := ids[listener.ID]; exists {
			return fmt.Errorf("duplicate HTTP listener id %q", listener.ID)
		}
		ids[listener.ID] = struct{}{}
		if strings.TrimSpace(listener.Name) == "" {
			return fmt.Errorf("%s.name is required", prefix)
		}
		if listener.Transport != HTTPTransport && listener.Transport != HTTPSTransport {
			return fmt.Errorf("%s.transport must be http or https", prefix)
		}
		if err := validateAddress(listener.Address); err != nil {
			return fmt.Errorf("%s.address: %w", prefix, err)
		}
		if other, exists := addresses[listener.Address]; exists {
			return fmt.Errorf("HTTP listeners %q and %q use the same address", other, listener.ID)
		}
		addresses[listener.Address] = listener.ID
		if listener.Transport == HTTPSTransport && listener.Enabled && strings.TrimSpace(listener.Certificate) == "" {
			return fmt.Errorf("%s.certificate is required for enabled HTTPS", prefix)
		}
		if listener.Transport == HTTPTransport && strings.TrimSpace(listener.Certificate) != "" {
			return fmt.Errorf("%s.certificate is only valid for HTTPS", prefix)
		}
		if listener.HSTSMaxAgeDays != nil && (*listener.HSTSMaxAgeDays < 0 || *listener.HSTSMaxAgeDays > MaxHSTSMaxAgeDays) {
			return fmt.Errorf("%s.hsts_max_age_days must be between 0 and %d", prefix, MaxHSTSMaxAgeDays)
		}
		if (listener.HSTSMaxAgeDays == nil || *listener.HSTSMaxAgeDays == 0) && (listener.HSTSIncludeSubdomains || listener.HSTSPreload) {
			return fmt.Errorf("%s HSTS directives require a positive max age", prefix)
		}
		if listener.HSTSPreload && (!listener.HSTSIncludeSubdomains || *listener.HSTSMaxAgeDays < MinHSTSPreloadDays) {
			return fmt.Errorf("%s HSTS preload requires include-subdomains and a max age of at least one year", prefix)
		}
		if listener.LogLevel != "inherit" {
			if _, err := logpkg.ParseLevelStrict(listener.LogLevel); err != nil {
				return fmt.Errorf("%s.log_level: %w", prefix, err)
			}
		}
		seenServices := make(map[string]struct{}, len(listener.Services))
		for _, service := range listener.Services {
			if !slices.Contains(HTTPServices, service) {
				return fmt.Errorf("%s.services contains unknown service %q", prefix, service)
			}
			if _, exists := seenServices[service]; exists {
				return fmt.Errorf("%s.services contains duplicate service %q", prefix, service)
			}
			seenServices[service] = struct{}{}
			if listener.Enabled && service == "web" {
				hasWeb = true
			}
		}
	}
	if !hasWeb {
		return errors.New("at least one enabled HTTP listener must expose the web service")
	}
	return nil
}
