package main

import (
	"context"
	"errors"
	"slices"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

// spamSettingKeys are the built-in spam scoring settings applied together.
var spamSettingKeys = []string{
	"antispam_enabled", "antispam_junk_threshold", "antispam_greylist_threshold", "antispam_reject_threshold",
	"antispam_symbol_scores", "antispam_dnsbl_zones", "antispam_rhsbl_zones", "antispam_uribl_zones",
	"antispam_dns_resolver", "antispam_trusted_networks", "antispam_protected_brands", "antispam_url_shorteners",
}

// isHostedDomain reports whether domain is an enabled hosted domain.
func (s *server) isHostedDomain(ctx context.Context, domain string) (bool, error) {
	candidate, err := s.ts.DomainStore().Get(ctx, domain)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return candidate.Enabled, nil
}

// spamDirectory lists the enabled hosted domains and local display names
// that phishing checks protect from impersonation.
type spamDirectory struct{ s *server }

func (d spamDirectory) LocalIdentities(ctx context.Context) (spam.LocalIdentities, error) {
	domains, err := d.s.ts.DomainStore().List(ctx)
	if err != nil {
		return spam.LocalIdentities{}, err
	}
	users, err := d.s.ts.UserStore().List(ctx)
	if err != nil {
		return spam.LocalIdentities{}, err
	}
	var identities spam.LocalIdentities
	for _, domain := range domains {
		if domain.Enabled {
			identities.Domains = append(identities.Domains, domain.ID)
		}
	}
	for _, user := range users {
		if user.DisplayName != "" {
			identities.DisplayNames = append(identities.DisplayNames, user.DisplayName)
		}
	}
	return identities, nil
}

// applySpamFiltering builds the spam engine for cfg and swaps it in for the
// next transaction, or returns an error and keeps the current engine. The
// shared DNS layer keeps its cache and zone health; a changed resolver
// starts with an empty cache.
func (s *server) applySpamFiltering(cfg *config.Config) error {
	if !cfg.AntispamEnabled {
		s.delivery.spam.Set(nil)
		return nil
	}
	settings, err := spam.ParseSettings(cfg.AntispamSettings())
	if err != nil {
		return err
	}
	if settings.TrustedNetworks, err = config.ParseAddressPrefixes("antispam_trusted_networks", cfg.AntispamTrustedNetworks); err != nil {
		return err
	}
	address, err := spam.ResolverAddress(cfg.AntispamDNSResolver)
	if err != nil {
		return err
	}
	resolver, err := spam.NewResolver(address)
	if err != nil {
		return err
	}
	settings.Observer = metrics.NewSpamObserver(s.met)
	settings.IsLocalDomain = func(ctx context.Context, domain string) bool {
		hosted, hostedErr := s.isHostedDomain(ctx, domain)
		if hostedErr != nil {
			// Unknown is treated as hosted: never leak a possibly local
			// domain to a third-party list.
			log.Warn("spam filtering: hosted domain lookup failed", "domain", domain, "error", hostedErr)
			return true
		}
		return hosted
	}
	settings.Identities = s.delivery.spamIdentities
	settings.Reputation = &s.delivery.reputation
	settings.Fuzzy = &s.delivery.fuzzy
	engine, err := spam.NewEngine(settings, s.delivery.spamDNS)
	if err != nil {
		return err
	}
	s.delivery.spamDNS.SetResolver(resolver, address)
	s.delivery.spam.Set(engine)
	return nil
}

// spamHealthObservation reports blocklist reachability: degraded while a
// list refuses the configured resolver or lookups keep failing.
func (s *server) spamHealthObservation(cfg *config.Config) health.Observation {
	observation := health.Observation{ID: "antispam-dns", Label: "Spam blocklist lookups", Kind: "dependency", Desired: cfg.AntispamEnabled, State: health.StateDisabled}
	if !cfg.AntispamEnabled || s.delivery.spamDNS == nil {
		return observation
	}
	settings, err := spam.ParseSettings(cfg.AntispamSettings())
	if err != nil {
		observation.State, observation.Reason = health.StateDegraded, err.Error()
		return observation
	}
	healthy, reason, details := s.delivery.spamDNS.Health(slices.Concat(settings.DNSBL, settings.RHSBL, settings.URIBL))
	observation.State, observation.Reason, observation.Details = health.StateHealthy, reason, details
	if !healthy {
		observation.State = health.StateDegraded
	}
	return observation
}
