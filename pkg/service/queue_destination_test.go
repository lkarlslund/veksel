package service

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

func TestClassifyQueueDestination(t *testing.T) {
	backendErr := errors.New("backend unavailable")
	tests := []struct {
		name       string
		address    model.EmailAddress
		addressErr error
		domain     model.Domain
		domainErr  error
		route      model.OutboundRoute
		routeErr   error
		wantLocal  bool
		wantRoute  bool
		wantErr    error
	}{
		{name: "local", address: model.EmailAddress{ID: "alice@example.test", UserID: "alice", Enabled: true}, wantLocal: true},
		{name: "disabled local", address: model.EmailAddress{ID: "alice@example.test", UserID: "alice"}, wantErr: ErrDisabledLocalRecipient},
		{name: "address outage", addressErr: backendErr, wantErr: backendErr},
		{name: "unknown local", addressErr: store.ErrNotFound, domain: model.Domain{ID: "example.test", Enabled: true}, wantErr: ErrUnknownLocalRecipient},
		{name: "domain outage", addressErr: store.ErrNotFound, domainErr: backendErr, wantErr: backendErr},
		{name: "route", addressErr: store.ErrNotFound, domainErr: store.ErrNotFound, route: model.OutboundRoute{Domain: "example.test", Enabled: true}, wantRoute: true},
		{name: "disabled domain permits route", addressErr: store.ErrNotFound, domain: model.Domain{ID: "example.test"}, route: model.OutboundRoute{Domain: "example.test", Enabled: true}, wantRoute: true},
		{name: "disabled route falls back", addressErr: store.ErrNotFound, domainErr: store.ErrNotFound, route: model.OutboundRoute{Domain: "example.test"}},
		{name: "route absent falls back", addressErr: store.ErrNotFound, domainErr: store.ErrNotFound, routeErr: store.ErrNotFound},
		{name: "route outage", addressErr: store.ErrNotFound, domainErr: store.ErrNotFound, routeErr: backendErr, wantErr: backendErr},
		{name: "split delivery routes unknown local", addressErr: store.ErrNotFound,
			domain: model.Domain{ID: "example.test", Enabled: true, UnknownRecipients: model.UnknownRecipientPolicy{Route: true}},
			route:  model.OutboundRoute{Domain: "example.test", Transport: model.OutboundTransportRelay, RelayHost: "exchange.example.test", Enabled: true}, wantRoute: true},
		{name: "split delivery without relay route stays unknown", addressErr: store.ErrNotFound,
			domain: model.Domain{ID: "example.test", Enabled: true, UnknownRecipients: model.UnknownRecipientPolicy{Route: true}},
			route:  model.OutboundRoute{Domain: "example.test", Transport: model.OutboundTransportMX, Enabled: true}, wantErr: ErrUnknownLocalRecipient},
		{name: "split delivery never overrides a local identity",
			address: model.EmailAddress{ID: "alice@example.test", UserID: "alice", Enabled: true},
			domain:  model.Domain{ID: "example.test", Enabled: true, UnknownRecipients: model.UnknownRecipientPolicy{Route: true}}, wantLocal: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ClassifyQueueDestination(t.Context(), "alice@example.test",
				func(context.Context, string) (model.EmailAddress, error) { return test.address, test.addressErr },
				func(context.Context, string) (model.Domain, error) { return test.domain, test.domainErr },
				func(context.Context, string) (model.OutboundRoute, error) { return test.route, test.routeErr })
			if !errors.Is(err, test.wantErr) || (got.Local != nil) != test.wantLocal || (got.Route != nil) != test.wantRoute {
				t.Fatalf("destination=%+v error=%v", got, err)
			}
		})
	}
}

func TestClassifyQueueDestinationRejectsMalformedRecipientBeforeLookup(t *testing.T) {
	called := false
	lookupAddress := func(context.Context, string) (model.EmailAddress, error) {
		called = true
		return model.EmailAddress{}, nil
	}
	lookupRoute := func(context.Context, string) (model.OutboundRoute, error) {
		called = true
		return model.OutboundRoute{}, nil
	}
	lookupDomain := func(context.Context, string) (model.Domain, error) {
		called = true
		return model.Domain{}, nil
	}
	if _, err := ClassifyQueueDestination(t.Context(), "not-an-address", lookupAddress, lookupDomain, lookupRoute); err == nil || called {
		t.Fatalf("error=%v called=%t", err, called)
	}
}
