package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/mtasts"
	"github.com/lkarlslund/veksel/pkg/netguard"
	"github.com/lkarlslund/veksel/pkg/ntlm"
)

// syncNetwork is the network policy of external sync sources. Any signed-in
// user may create a sync job into their own account, so sources reach only
// public addresses plus the private prefixes an administrator listed in
// sync_private_networks (for example an on-premises Exchange server).
type syncNetwork struct {
	allowed atomic.Pointer[[]netip.Prefix]
}

var syncSourceNetwork = &syncNetwork{}

// Set replaces the permitted private prefixes.
func (n *syncNetwork) Set(values []string) error {
	prefixes, err := config.ParseAddressPrefixes("sync_private_networks", values)
	if err != nil {
		return err
	}
	n.allowed.Store(&prefixes)
	return nil
}

func (n *syncNetwork) allows(address netip.Addr) bool {
	prefixes := n.allowed.Load()
	return prefixes != nil && slices.ContainsFunc(*prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}

func (n *syncNetwork) dialer() *netguard.Dialer {
	return &netguard.Dialer{AllowAddress: n.allows, Timeout: 30 * time.Second}
}

// httpClient returns a client that dials only permitted addresses, on every
// redirect too.
func (n *syncNetwork) httpClient(tlsConfig *tls.Config, timeout time.Duration) *http.Client {
	transport := n.dialer().Transport()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport, Timeout: timeout}
}

// exchangeHTTPClient is httpClient for Exchange's EWS and ActiveSync:
// it signs in with NTLM (or Negotiate answered with NTLM, bound to the TLS
// channel for Extended Protection) when the server asks for it and with
// Basic otherwise. NTLM authenticates a connection, so it speaks HTTP/1.1.
// Redirects are not followed: an EWS or ActiveSync endpoint answers itself,
// and a redirect means the address reached something else (a firewall,
// proxy or login portal), which the caller reports.
func (n *syncNetwork) exchangeHTTPClient(tlsConfig *tls.Config, timeout time.Duration) *http.Client {
	transport := n.dialer().Transport()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport:     &ntlm.Transport{Base: ntlm.HTTP1Only(transport), AllowBasic: true, Observe: logExchangeRequest},
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var syncLog = log.For(log.ModuleSync)

// logExchangeRequest logs each EWS/ActiveSync request with the address it
// reached, the authentication used and every status in the handshake.
func logExchangeRequest(exchange ntlm.Exchange) {
	statuses := make([]string, len(exchange.Statuses))
	for i, status := range exchange.Statuses {
		statuses[i] = fmt.Sprint(status)
	}
	scheme := exchange.Scheme
	if scheme == "" {
		scheme = "none"
	} else if scheme != "Basic" {
		scheme += " (NTLMv2)"
	}
	attrs := []any{"method", exchange.Method, "url", exchange.URL, "user", exchange.User, "remote", exchange.Remote, "auth", scheme, "statuses", strings.Join(statuses, " → ")}
	last := 0
	if len(exchange.Statuses) > 0 {
		last = exchange.Statuses[len(exchange.Statuses)-1]
	}
	switch {
	case exchange.Err != nil:
		syncLog.Warn("sync source request failed", append(attrs, "error", exchange.Err)...)
	case last != http.StatusOK:
		syncLog.Warn("sync source request refused", attrs...)
	default:
		syncLog.Debug("sync source request", attrs...)
	}
}

// pin resolves a host:port source address once through the policy and
// returns the permitted IP to dial, so a later DNS answer cannot redirect
// the connection. tlsConfig's ServerName is set to the host name so TLS
// still verifies the name the user entered.
func (n *syncNetwork) pin(ctx context.Context, address string, tlsConfig *tls.Config) (string, *tls.Config, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", nil, fmt.Errorf("server address must be host:port: %w", err)
	}
	addresses, err := n.dialer().Resolve(ctx, host)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w; an administrator can allow internal servers with sync_private_networks", host, err)
	}
	pinned := tlsConfig.Clone()
	if pinned.ServerName == "" {
		pinned.ServerName = host
	}
	return net.JoinHostPort(addresses[0].String(), port), pinned, nil
}

// registerSyncNetwork applies sync_private_networks live.
func (s *server) registerSyncNetwork() error {
	apply := func(cfg *config.Config) error { return syncSourceNetwork.Set(cfg.SyncPrivateNetworks) }
	if err := apply(s.cfg); err != nil {
		return err
	}
	return s.cfgService.RegisterApplier(apply, "sync_private_networks")
}

// registerProtocolPasswordPolicy applies two_factor_requires_app_passwords
// live to the protocol credential service.
func (s *server) registerProtocolPasswordPolicy() error {
	apply := func(cfg *config.Config) error {
		s.protocolAuth.SetRequireAppPasswords(cfg.TwoFactorRequiresAppPasswords)
		return nil
	}
	_ = apply(s.cfg)
	return s.cfgService.RegisterApplier(apply, "two_factor_requires_app_passwords")
}

// mtaSTSPolicy is the policy served on mta-sts.<domain> for an enabled
// hosted domain, following mta_sts_mode live.
func (s *server) mtaSTSPolicy(ctx context.Context, host string) (string, bool) {
	cfg := s.cfgService.Current().Config
	mode := cfg.MtaStsMode
	if mode == "" || mode == mtasts.PublishedOff || cfg.SmtpServerName == "" {
		return "", false
	}
	domain, ok := strings.CutPrefix(host, "mta-sts.")
	if !ok || domain == "" {
		return "", false
	}
	if hosted, err := s.isHostedDomain(ctx, domain); err != nil || !hosted {
		return "", false
	}
	policy, _ := mtasts.PublishedPolicy(mode, []string{cfg.SmtpServerName})
	return policy, true
}

// registerMTASTSPolicy registers mta_sts_mode, which mtaSTSPolicy reads per
// request, as a live setting.
func (s *server) registerMTASTSPolicy() error {
	return s.cfgService.RegisterApplier(func(*config.Config) error { return nil }, "mta_sts_mode")
}
