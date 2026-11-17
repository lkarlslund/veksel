package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
)

// recipientCallout returns the callout cache shared by every SMTP listener.
func (s *server) recipientCallout() *smtp.RecipientCallout {
	s.calloutOnce.Do(func() {
		s.callout = &smtp.RecipientCallout{ServerName: func() string { return s.cfgService.Current().Config.SmtpServerName }}
	})
	return s.callout
}

// routeUnknownRecipient is split delivery at RCPT time: an address in a
// hosted domain that no local identity hosts is accepted for the domain's
// relay route (the server it shares the domain with) when the domain routes
// unknown recipients, the mail did not come from that server, and that
// server accepts the address.
func (s *server) routeUnknownRecipient(ctx context.Context, recipient, peerIP string) (bool, error) {
	at := strings.LastIndex(recipient, "@")
	if at <= 0 {
		return false, nil
	}
	name := strings.ToLower(recipient[at+1:])
	domain, err := s.ts.DomainStore().Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up domain: %w", err)
	}
	if !domain.Enabled || !domain.UnknownRecipients.Route {
		return false, nil
	}
	route, err := s.ts.OutboundRouteStore().Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up outbound route: %w", err)
	}
	if !route.Enabled || route.Transport != model.OutboundTransportRelay || route.RelayHost == "" {
		return false, nil
	}
	// An address neither server hosts would otherwise travel back and forth.
	if fromRoute, err := hostHasAddress(ctx, route.RelayHost, peerIP); err != nil {
		return false, err
	} else if fromRoute {
		log.Info("smtp: unknown recipient arrived from its split-delivery server; refusing to route it back", "recipient", recipient, "server", route.RelayHost)
		return false, nil
	}
	if domain.UnknownRecipients.CheckMode() == model.UnknownRecipientAccept {
		return true, nil
	}
	return s.recipientCallout().Check(ctx, smtp.CalloutTarget{Host: route.RelayHost, Port: route.RelayPort, TLSSkipVerify: route.TLSSkipVerify}, recipient)
}

// hostHasAddress reports whether host (a name or literal) resolves to ip.
func hostHasAddress(ctx context.Context, host, ip string) (bool, error) {
	peer, err := netip.ParseAddr(ip)
	if err != nil {
		return false, nil
	}
	peer = peer.Unmap()
	if literal, err := netip.ParseAddr(host); err == nil {
		return literal.Unmap() == peer, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return false, fmt.Errorf("resolve split-delivery server %s: %w", host, err)
	}
	for _, address := range addresses {
		if address.Unmap() == peer {
			return true, nil
		}
	}
	return false, nil
}

// trustedDomainRelay reports whether peerIP is the split-delivery server of
// the hosted domain: the relay route host of a domain that routes unknown
// recipients. That server sends the domain's own mail during a migration.
func (s *server) trustedDomainRelay(ctx context.Context, name, peerIP string) (bool, error) {
	domain, err := s.ts.DomainStore().Get(ctx, strings.ToLower(name))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !domain.Enabled || !domain.UnknownRecipients.Route {
		return false, nil
	}
	route, err := s.ts.OutboundRouteStore().Get(ctx, domain.ID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !route.Enabled || route.Transport != model.OutboundTransportRelay || route.RelayHost == "" {
		return false, nil
	}
	return hostHasAddress(ctx, route.RelayHost, peerIP)
}
