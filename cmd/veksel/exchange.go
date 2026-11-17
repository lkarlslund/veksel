package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/migration"
	caldavmigration "github.com/lkarlslund/veksel/pkg/migration/caldav"
	carddavmigration "github.com/lkarlslund/veksel/pkg/migration/carddav"
	imapmigration "github.com/lkarlslund/veksel/pkg/migration/imap"
	pop3migration "github.com/lkarlslund/veksel/pkg/migration/pop3"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	webapp "github.com/lkarlslund/veksel/pkg/web/app"
)

type exchangeDependencies struct {
	// ctx ends when shutdown begins; long polls answer when it does.
	ctx                 context.Context
	mux                 *http.ServeMux
	space               service.FolderSpace
	store               store.Store
	authenticate        func(context.Context, string, string, string) (string, error)
	submit              func(context.Context, string, []byte) error
	configureEASDevices func(webapp.EASDeviceInventory)
	// users backs ActiveSync's account profile, out-of-office settings and
	// global address list.
	users *model.UserStore
	// search and respond resolve late-built services: search indexing and
	// iMIP scheduling start after the HTTP handlers are mounted.
	search  func() service.SearchReader
	respond func(context.Context, service.AccessContext, string, string) error
	// freeBusy reports an address's busy periods when access may see them
	// (the calendar free/busy rule the web scheduler and CalDAV share).
	freeBusy func(context.Context, service.AccessContext, string, time.Time, time.Time) ([]calendarindex.BusyPeriod, bool, error)
}

func migrationSourceFactories() map[string]migration.SourceFactory {
	factories := map[string]migration.SourceFactory{
		"carddav": func(_ context.Context, options migration.SourceOptions) (migration.Source, error) {
			endpoint, err := migration.NormalizeHTTPEndpoint(options.Endpoint, options.TLSMode, "/")
			if err != nil {
				return nil, err
			}
			return carddavmigration.New(carddavmigration.Config{Endpoint: endpoint, Username: options.Username, Password: options.Password,
				HTTPClient: syncSourceNetwork.httpClient(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}, 90*time.Second)}) //nolint:gosec -- explicit sync option
		},
		"caldav": func(_ context.Context, options migration.SourceOptions) (migration.Source, error) {
			endpoint, err := migration.NormalizeHTTPEndpoint(options.Endpoint, options.TLSMode, "/")
			if err != nil {
				return nil, err
			}
			return caldavmigration.New(caldavmigration.Config{Endpoint: endpoint, Username: options.Username, Password: options.Password,
				HTTPClient: syncSourceNetwork.httpClient(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}, 90*time.Second)}) //nolint:gosec -- explicit sync option
		},
		"imap": func(ctx context.Context, options migration.SourceOptions) (migration.Source, error) {
			mode, err := imapMigrationTLSMode(options.TLSMode)
			if err != nil {
				return nil, err
			}
			address, tlsConfig, err := syncSourceNetwork.pin(ctx, options.Endpoint, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}) //nolint:gosec -- explicit migration option
			if err != nil {
				return nil, err
			}
			return imapmigration.Dial(imapmigration.Config{
				Address: address, Username: options.Username, Password: options.Password, TLSMode: mode,
				TLSConfig: tlsConfig,
				PageSize:  uint32(options.PageSize),
			})
		},
		"pop3": func(ctx context.Context, options migration.SourceOptions) (migration.Source, error) {
			security, err := migration.NormalizeMailSecurityMode(options.TLSMode)
			if err != nil {
				return nil, err
			}
			address, tlsConfig, err := syncSourceNetwork.pin(ctx, options.Endpoint, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}) //nolint:gosec -- explicit migration option
			if err != nil {
				return nil, err
			}
			return pop3migration.Dial(ctx, pop3migration.Config{
				Address: address, Username: options.Username, Password: options.Password, TLSMode: security,
				TLSConfig: tlsConfig,
				PageSize:  options.PageSize,
			})
		},
	}
	registerEWSMigration(factories)
	registerEASMigration(factories)
	return factories
}

func imapMigrationTLSMode(value string) (imapmigration.TLSMode, error) {
	security, err := migration.NormalizeMailSecurityMode(value)
	if err != nil {
		return "", err
	}
	switch security {
	case migration.MailSecurityStartTLS:
		return imapmigration.TLSStartTLS, nil
	case migration.MailSecurityPlain:
		return imapmigration.TLSNone, nil
	default:
		return imapmigration.TLSImplicit, nil
	}
}

func newExchangeDependencies(mux *http.ServeMux, ts *model.TypedStore, space service.FolderSpace, authenticator *protocolauth.Service, configureEASDevices func(webapp.EASDeviceInventory)) exchangeDependencies {
	return exchangeDependencies{
		mux: mux, space: space, store: ts.Store(), configureEASDevices: configureEASDevices, users: ts.UserStore(),
		authenticate: func(ctx context.Context, username, password, protocol string) (string, error) {
			return authenticateProtocolUser(ctx, authenticator, protocol, username, password)
		},
	}
}
