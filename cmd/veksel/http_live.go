package main

import (
	"fmt"

	"github.com/lkarlslund/veksel/pkg/config"
)

// httpServiceToggle is one HTTP service switched by a boolean setting. The
// service stays mounted; the service gate answers 404 while it is off.
type httpServiceToggle struct {
	key, service, label string
	compiled            bool
	enabled             func(*config.Config) bool
}

func httpServiceToggles() []httpServiceToggle {
	return []httpServiceToggle{
		{"dav_enabled", "dav", "DAV", true, func(c *config.Config) bool { return c.DavEnabled }},
		{"jmap_enabled", "jmap", "JMAP", true, func(c *config.Config) bool { return c.JmapEnabled }},
		{"mcp_enabled", "mcp", "MCP", true, func(c *config.Config) bool { return c.MCPEnabled }},
		{"ews_enabled", "ews", "EWS", ewsCompiled, func(c *config.Config) bool { return c.EwsEnabled }},
		{"eas_enabled", "eas", "EAS", easCompiled, func(c *config.Config) bool { return c.EasEnabled }},
	}
}

// applyHTTPServiceState sets the startup state of the live HTTP settings.
func (s *server) applyHTTPServiceState(cfg *config.Config) {
	for _, toggle := range httpServiceToggles() {
		s.services.Set(toggle.service, toggle.compiled && toggle.enabled(cfg))
	}
	token := cfg.MetricsToken
	s.metricsToken.Store(&token)
}

// registerHTTPLiveSettings makes every HTTP-side setting apply without a
// restart: service toggles, the metrics token, HTTP(S) listeners (including
// the legacy listener keys they are migrated from), the pprof listener, and
// ACME.
func (s *server) registerHTTPLiveSettings() error {
	type applier struct {
		keys  []string
		apply config.Applier
	}
	var appliers []applier
	for _, toggle := range httpServiceToggles() {
		appliers = append(appliers, applier{[]string{toggle.key}, func(cfg *config.Config) error {
			enabled := toggle.enabled(cfg)
			if enabled && !toggle.compiled {
				return fmt.Errorf("%s is not compiled into this build", toggle.label)
			}
			s.services.Set(toggle.service, enabled)
			if toggle.service == "ews" {
				// Autodiscover advertises EWS only while it is served.
				s.autodiscover.Store(s.newAutodiscover(cfg))
			}
			return nil
		}})
	}
	appliers = append(appliers,
		applier{[]string{"metrics_token"}, func(cfg *config.Config) error {
			token := cfg.MetricsToken
			s.metricsToken.Store(&token)
			return nil
		}},
		applier{[]string{"webdav_max_file_size"}, func(cfg *config.Config) error {
			s.dav.SetMaxWebdavFileSize(cfg.WebdavMaxFileSize)
			// The web app's workspace upload limit reads the shared runtime
			// configuration, as its own live settings do.
			s.cfg.WebdavMaxFileSize = cfg.WebdavMaxFileSize
			return nil
		}},
		applier{[]string{"http_listeners", "listen_addr", "https_enabled", "https_listen", "https_certificate"}, func(cfg *config.Config) error {
			if s.httpListeners == nil {
				return fmt.Errorf("HTTP listeners are not running")
			}
			return s.httpListeners.Apply(cfg.HTTPListeners)
		}},
		applier{[]string{"pprof_listen"}, func(cfg *config.Config) error {
			if s.pprofListener == nil {
				return fmt.Errorf("pprof listener is not running")
			}
			return s.pprofListener.Apply(pprofListeners(cfg.PprofListenAddr))
		}},
		applier{[]string{"acme_enabled", "acme_accept_tos", "acme_email", "acme_domains", "acme_http_listen", "acme_directory_url", "acme_challenge", "acme_dns_propagation_seconds"}, func(cfg *config.Config) error {
			return s.certificates.Reconfigure(cfg)
		}},
	)
	for _, a := range appliers {
		if err := s.cfgService.RegisterApplier(a.apply, a.keys...); err != nil {
			return err
		}
	}
	return nil
}
