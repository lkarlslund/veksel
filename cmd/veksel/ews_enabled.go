//go:build !noews

package main

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/ews"
	"github.com/lkarlslund/veksel/pkg/migration"
	ewsmigration "github.com/lkarlslund/veksel/pkg/migration/ews"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const ewsCompiled = true

func registerEWS(deps exchangeDependencies) error {
	authenticate := func(ctx context.Context, username, password string) (string, error) {
		return deps.authenticate(ctx, username, password, model.AppProtocolEWS)
	}
	cfg := ews.Config{Space: deps.space, Authenticate: authenticate, Submit: deps.submit, Context: deps.ctx}
	if deps.users != nil {
		directory := accountDirectory{users: deps.users}
		cfg.Directory = func(ctx context.Context, userID, query string, limit int) ([]ews.DirectoryEntry, error) {
			entries, err := directory.search(ctx, userID, query, limit)
			result := make([]ews.DirectoryEntry, 0, len(entries))
			for _, entry := range entries {
				result = append(result, ews.DirectoryEntry{Name: entry.DisplayName, Address: entry.Addresses[0]})
			}
			return result, err
		}
		cfg.Profile = func(ctx context.Context, userID string) (ews.Profile, error) {
			user, err := deps.users.Get(ctx, userID)
			if err != nil {
				return ews.Profile{}, err
			}
			return ews.Profile{DisplayName: user.DisplayName, Addresses: directory.addresses(ctx, user.ID), TimeZone: user.DisplayPreferences.TimeZone}, nil
		}
		cfg.OutOfOffice = func(ctx context.Context, userID string) (ews.OutOfOffice, error) {
			user, err := deps.users.Get(ctx, userID)
			if err != nil {
				return ews.OutOfOffice{}, err
			}
			return ews.OutOfOffice{Enabled: user.VacationEnabled, Start: user.VacationStart, End: user.VacationEnd, Subject: user.VacationSubject, Message: user.VacationMessage}, nil
		}
		cfg.SetOutOfOffice = func(ctx context.Context, userID string, oof ews.OutOfOffice) error {
			return deps.users.UpdateVacation(ctx, userID, oof.Enabled, oof.Start, oof.End, oof.Subject, oof.Message)
		}
	}
	if deps.respond != nil {
		cfg.Respond = deps.respond
	}
	if deps.freeBusy != nil {
		cfg.FreeBusy = func(ctx context.Context, access service.AccessContext, address string, start, end time.Time) ([]ews.BusyPeriod, bool, error) {
			periods, known, err := deps.freeBusy(ctx, access, address, start, end)
			result := make([]ews.BusyPeriod, 0, len(periods))
			for _, period := range periods {
				result = append(result, ews.BusyPeriod{Start: period.Start, End: period.End, Tentative: period.Type == calendarindex.BusyTentativeType})
			}
			return result, known, err
		}
	}
	handler, err := ews.New(cfg)
	if err != nil {
		return err
	}
	deps.mux.Handle("/EWS/Exchange.asmx", handler)
	deps.mux.Handle("/ews/exchange.asmx", handler)
	return nil
}

func registerEWSMigration(factories map[string]migration.SourceFactory) {
	factories["ews"] = func(_ context.Context, options migration.SourceOptions) (migration.Source, error) {
		endpoint, err := migration.NormalizeHTTPEndpoint(options.Endpoint, options.TLSMode, "/EWS/Exchange.asmx")
		if err != nil {
			return nil, err
		}
		return ewsmigration.New(ewsmigration.Config{
			Endpoint: endpoint, Username: options.Username, Password: options.Password, PageSize: options.PageSize,
			HTTPClient: syncSourceNetwork.exchangeHTTPClient(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}, 5*time.Minute), //nolint:gosec -- explicit migration option
		})
	}
}
