package main

import (
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/dnsserver"
	"github.com/lkarlslund/veksel/pkg/log"
)

// dnsServerKeys are the built-in DNS server settings applied live.
var dnsServerKeys = []string{"dns_server_enabled", "dns_server_listen", "dns_server_nameservers", "dns_server_dnssec", "dns_server_axfr_tsig"}

// dnsServerSettings converts cfg, which was validated when it was accepted.
func dnsServerSettings(cfg *config.Config) dnsserver.Settings {
	settings := dnsserver.Settings{Enabled: cfg.DNSServerEnabled, Listen: cfg.DNSServerListen, Nameservers: cfg.DNSServerNameservers, DNSSEC: cfg.DNSServerDNSSEC}
	if key, _ := config.ParseDNSServerTSIG(cfg.DNSServerAXFRTSIG); key != nil {
		settings.AXFR = &dnsserver.TSIGKey{Name: key.Name, Algorithm: dnsprovider.TSIGAlgorithms[key.Algorithm], Secret: key.Secret}
	}
	return settings
}

// startDNSServer starts the built-in authoritative DNS server for the zones
// the builtin DNS provider hosts and makes its settings live. A listener
// that cannot bind at startup is reported in health and the admin view.
func (s *server) startDNSServer() error {
	server := dnsserver.New(s.appHandler.DNSZones().Hosted())
	server.DefaultNameserver = s.smtpServerName
	s.dnsServer = server
	s.cleanup.push(server.Close)
	s.appHandler.ConfigureDNSServer(server)
	if err := server.Apply(dnsServerSettings(s.cfg)); err != nil {
		log.Error("dns: built-in DNS server unavailable", "error", err)
	}
	if err := s.cfgService.RegisterApplier(func(cfg *config.Config) error {
		return server.Apply(dnsServerSettings(cfg))
	}, dnsServerKeys...); err != nil {
		return startupError("register DNS server settings", err)
	}
	return nil
}
