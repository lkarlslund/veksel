package model

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// OutboundTransport identifies how messages for a destination leave Veksel.
type OutboundTransport string

const (
	OutboundTransportMX    OutboundTransport = "mx"
	OutboundTransportRelay OutboundTransport = "relay"
)

// OutboundRoute is an exact-domain outbound delivery rule. An MX route uses
// DNS and port 25; a relay route uses RelayHost and RelayPort.
type OutboundRoute struct {
	Domain        string            `json:"domain"`
	Transport     OutboundTransport `json:"transport"`
	RelayHost     string            `json:"relay_host,omitempty"`
	RelayPort     int               `json:"relay_port"`
	RequireTLS    bool              `json:"require_tls"`
	TLSSkipVerify bool              `json:"tls_skip_verify"`
	Enabled       bool              `json:"enabled"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// OutboundRouteStore provides durable CRUD and O(1) exact-domain resolution.
type OutboundRouteStore struct{ routes collection[OutboundRoute] }

func NewOutboundRouteStore(ts *TypedStore) *OutboundRouteStore {
	return &OutboundRouteStore{routes: newCollection[OutboundRoute](ts, NSOutboundRoutes)}
}

func normalizeRoute(route OutboundRoute) (OutboundRoute, error) {
	route.Domain = normalizeID(route.Domain)
	route.RelayHost = strings.TrimSpace(route.RelayHost)
	if route.Domain == "" || strings.ContainsAny(route.Domain, "@:/\\ ") || net.ParseIP(route.Domain) != nil || !strings.Contains(route.Domain, ".") {
		return route, fmt.Errorf("valid destination domain required")
	}
	switch route.Transport {
	case OutboundTransportMX:
		route.RelayHost = ""
		route.RelayPort = 25
	case OutboundTransportRelay:
		if route.RelayHost == "" {
			return route, fmt.Errorf("relay_host is required for relay transport")
		}
		if route.RelayPort == 0 {
			route.RelayPort = 25
		}
	default:
		return route, fmt.Errorf("transport must be mx or relay")
	}
	if route.RelayPort < 1 || route.RelayPort > 65535 {
		return route, fmt.Errorf("relay_port must be between 1 and 65535")
	}
	return route, nil
}

func (rs *OutboundRouteStore) Create(ctx context.Context, route OutboundRoute) (OutboundRoute, error) {
	var err error
	route, err = normalizeRoute(route)
	if err != nil {
		return route, err
	}
	now := time.Now().UTC()
	route.CreatedAt, route.UpdatedAt = now, now
	if err := rs.routes.put(ctx, route.Domain, route); err != nil {
		return route, err
	}
	return route, nil
}

func (rs *OutboundRouteStore) Get(ctx context.Context, domain string) (OutboundRoute, error) {
	return rs.routes.get(ctx, normalizeID(domain))
}

func (rs *OutboundRouteStore) Set(ctx context.Context, domain string, route OutboundRoute) (OutboundRoute, error) {
	existing, err := rs.Get(ctx, domain)
	if err != nil {
		return route, err
	}
	route.Domain = existing.Domain
	route, err = normalizeRoute(route)
	if err != nil {
		return route, err
	}
	route.CreatedAt, route.UpdatedAt = existing.CreatedAt, time.Now().UTC()
	if err := rs.routes.set(ctx, route.Domain, route); err != nil {
		return route, err
	}
	return route, nil
}

func (rs *OutboundRouteStore) Delete(ctx context.Context, domain string) error {
	if _, err := rs.Get(ctx, domain); err != nil {
		return err
	}
	return rs.routes.delete(ctx, normalizeID(domain))
}

func (rs *OutboundRouteStore) List(ctx context.Context) ([]OutboundRoute, error) {
	return rs.routes.list(ctx)
}
