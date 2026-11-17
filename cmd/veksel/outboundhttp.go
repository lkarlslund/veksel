package main

import (
	"github.com/lkarlslund/veksel/pkg/alertnotify"
	"github.com/lkarlslund/veksel/pkg/config"
)

// registerOutboundHTTP applies outbound_http_allow_private_networks to every
// client of administrator-configured HTTP endpoints: webhook subscriptions,
// the alert push URL, and DNS provider APIs. Each refuses loopback, private,
// and link-local addresses unless the setting allows them.
func (s *server) registerOutboundHTTP() error {
	apply := func(cfg *config.Config) error {
		allow := cfg.OutboundHTTPAllowPrivateNetworks
		if s.webhooks != nil {
			s.webhooks.SetAllowPrivateNetworks(allow)
		}
		if s.appHandler != nil {
			s.appHandler.DNSZones().SetAllowPrivateNetworks(allow)
		}
		if s.alertNotifier != nil {
			s.alertNotifier.SetPolicy(alertnotify.PolicyFromConfig(cfg))
		}
		return nil
	}
	_ = apply(s.cfg)
	if err := s.cfgService.RegisterApplier(apply, "outbound_http_allow_private_networks"); err != nil {
		return err
	}
	applyDestinations := func(cfg *config.Config) error {
		destinations, err := config.ParseDestinations("webhook_private_destinations", cfg.WebhookPrivateDestinations)
		if err != nil {
			return err
		}
		if s.webhooks != nil {
			s.webhooks.SetPrivateDestinations(destinations)
		}
		return nil
	}
	if err := applyDestinations(s.cfg); err != nil {
		return err
	}
	return s.cfgService.RegisterApplier(applyDestinations, "webhook_private_destinations")
}
