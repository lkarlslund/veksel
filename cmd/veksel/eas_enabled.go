//go:build !noeas

package main

import (
	"context"
	"crypto/tls"
	"sort"
	"time"

	"github.com/lkarlslund/veksel/pkg/eas"
	"github.com/lkarlslund/veksel/pkg/migration"
	easmigration "github.com/lkarlslund/veksel/pkg/migration/eas"
	"github.com/lkarlslund/veksel/pkg/model"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
)

const easCompiled = true

func registerEAS(deps exchangeDependencies) error {
	authenticate := func(ctx context.Context, username, password string) (string, error) {
		return deps.authenticate(ctx, username, password, model.AppProtocolEAS)
	}
	cfg := eas.Config{Space: deps.space, Authenticate: authenticate, Store: deps.store, Submit: deps.submit}
	if deps.users != nil {
		cfg.Account = newEASAccounts(deps)
	}
	if deps.search != nil {
		cfg.Search = lazySearch{resolve: deps.search}
	}
	if deps.respond != nil {
		cfg.Scheduler = easScheduler{respond: deps.respond}
	}
	ctx := deps.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	handler, err := eas.New(ctx, cfg)
	if err != nil {
		return err
	}
	// IIS matches the endpoint case-insensitively and some clients send it
	// in lower case.
	deps.mux.Handle("/Microsoft-Server-ActiveSync", handler)
	deps.mux.Handle("/microsoft-server-activesync", handler)
	if deps.configureEASDevices != nil {
		deps.configureEASDevices(easDeviceInventory{states: handler.DeviceStates()})
	}
	return nil
}

type easDeviceInventory struct{ states *eas.StateStore }

func (inventory easDeviceInventory) ListEASDevices(ctx context.Context, userID string) ([]webapp.EASDevice, error) {
	states, err := inventory.states.List(ctx, userID)
	if err != nil {
		return nil, err
	}
	devices := make([]webapp.EASDevice, 0, len(states))
	for _, state := range states {
		devices = append(devices, webapp.EASDevice{
			ID: state.DeviceID, Type: state.DeviceType, Protocol: state.Protocol,
			UserAgent: state.UserAgent, Model: state.Model, FriendlyName: state.FriendlyName,
			OS: state.OS, OSLanguage: state.OSLanguage, LastCommand: state.LastCommand,
			FirstSeenAt: state.FirstSeenAt, LastSeenAt: state.LastSeenAt,
			WipeRequestedAt: state.WipeRequestedAt, WipeAcknowledgedAt: state.WipeAcknowledgedAt,
		})
	}
	// StateStore already returns this order; retaining the adapter sort makes
	// the account API contract independent of protocol-store internals.
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].LastSeenAt.Equal(devices[j].LastSeenAt) {
			return devices[i].ID < devices[j].ID
		}
		return devices[i].LastSeenAt.After(devices[j].LastSeenAt)
	})
	return devices, nil
}

func (inventory easDeviceInventory) WipeEASDevice(ctx context.Context, userID, deviceID string) (bool, error) {
	return inventory.states.RequestWipe(ctx, userID, deviceID)
}

func (inventory easDeviceInventory) RemoveEASDevice(ctx context.Context, userID, deviceID string) (bool, error) {
	return inventory.states.Remove(ctx, userID, deviceID)
}

func registerEASMigration(factories map[string]migration.SourceFactory) {
	factories["eas"] = func(_ context.Context, options migration.SourceOptions) (migration.Source, error) {
		endpoint, err := migration.NormalizeHTTPEndpoint(options.Endpoint, options.TLSMode, "/Microsoft-Server-ActiveSync")
		if err != nil {
			return nil, err
		}
		return easmigration.New(easmigration.Config{
			Endpoint: endpoint, Username: options.Username, Password: options.Password,
			DeviceID:   options.ClientID,
			HTTPClient: syncSourceNetwork.exchangeHTTPClient(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}, 5*time.Minute), //nolint:gosec -- explicit migration option
		})
	}
}
