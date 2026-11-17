package main

import (
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/ban"
	"github.com/lkarlslund/veksel/pkg/config"
)

// banSettings are the abuse ban keys applied by startBans. The exemptions
// it shares (mail_connection_limit_exempt, http_trusted_proxies) are applied
// by their own owners: the mail protocol group and the trusted-proxy
// resolver.
var banSettings = []string{"ban_enabled", "ban_auth_failures", "ban_second_factor_failures", "ban_rcpt_unknown", "ban_protocol_errors", "ban_spamtrap_hits", "ban_durations", "ban_ipv6_prefix"}

// banPolicy returns the abuse ban policy for cfg. Values were validated when
// the configuration was accepted. Exempt networks are the mail connection
// limit exemptions; HTTP trusted proxies are consulted live through the
// resolver (see buildAppHandler).
func banPolicy(cfg *config.Config) ban.Policy {
	rule := func(key, value string) ban.Rule {
		threshold, _ := config.ParseBanThreshold(key, value)
		return ban.Rule{Count: threshold.Count, Window: threshold.Window}
	}
	durations, _ := config.ParseBanDurations(cfg.BanDurations)
	exempt, _ := config.ParseAddressPrefixes("mail_connection_limit_exempt", cfg.MailConnectionLimitExempt)
	return ban.Policy{
		Enabled: cfg.BanEnabled,
		Rules: map[ban.Trigger]ban.Rule{
			ban.TriggerAuth:         rule("ban_auth_failures", cfg.BanAuthFailures),
			ban.TriggerSecondFactor: rule("ban_second_factor_failures", cfg.BanSecondFactorFailures),
			ban.TriggerRecipient:    rule("ban_rcpt_unknown", cfg.BanRcptUnknown),
			ban.TriggerProtocol:     rule("ban_protocol_errors", cfg.BanProtocolErrors),
			ban.TriggerSpamtrap:     rule("ban_spamtrap_hits", cfg.BanSpamtrapHits),
		},
		Durations:  durations,
		IPv6Prefix: cfg.BanIPv6Prefix,
		Exempt:     exempt,
	}
}

// startBans opens the abuse ban engine, feeds it every failed and successful
// login through the shared authentication throttle, and makes its settings
// live.
func (s *server) startBans() error {
	bans, err := ban.New(s.ctx, s.ts.Store(), audit.New(s.ts), s.met, banPolicy(s.cfg))
	if err != nil {
		return startupError("initialize abuse bans", err)
	}
	s.bans = bans
	s.protocolAuth.Throttle().SetObserver(bans.ObserveAuth)
	s.background.Every(time.Minute, false, func() { bans.Maintain(s.ctx) })
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		bans.Configure(banPolicy(cfg))
		return nil
	}, banSettings...); err != nil {
		return startupError("register abuse ban settings", err)
	}
	return nil
}
