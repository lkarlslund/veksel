//go:build !noeas

package main

import (
	"context"
	"errors"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"github.com/lkarlslund/veksel/pkg/eas"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// easAccounts adapts the user store to ActiveSync's account directory.
type easAccounts struct {
	users     *model.UserStore
	directory accountDirectory
	freeBusy  func(context.Context, service.AccessContext, string, time.Time, time.Time) ([]calendarindex.BusyPeriod, bool, error)
}

func newEASAccounts(deps exchangeDependencies) easAccounts {
	return easAccounts{users: deps.users, directory: accountDirectory{users: deps.users}, freeBusy: deps.freeBusy}
}

func (a easAccounts) Profile(ctx context.Context, userID string) (eas.Profile, error) {
	user, err := a.users.Get(ctx, userID)
	if err != nil {
		return eas.Profile{}, err
	}
	return eas.Profile{ID: user.ID, DisplayName: user.DisplayName, Addresses: a.directory.addresses(ctx, user.ID), TimeZone: user.DisplayPreferences.TimeZone}, nil
}

func (a easAccounts) OutOfOffice(ctx context.Context, userID string) (eas.OutOfOffice, error) {
	user, err := a.users.Get(ctx, userID)
	if err != nil {
		return eas.OutOfOffice{}, err
	}
	return eas.OutOfOffice{Enabled: user.VacationEnabled, Start: user.VacationStart, End: user.VacationEnd, Message: user.VacationMessage}, nil
}

func (a easAccounts) SetOutOfOffice(ctx context.Context, userID string, oof eas.OutOfOffice) error {
	user, err := a.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	return a.users.UpdateVacation(ctx, userID, oof.Enabled, oof.Start, oof.End, user.VacationSubject, oof.Message)
}

func (a easAccounts) Directory(ctx context.Context, userID, query string, limit int) ([]eas.Profile, error) {
	entries, err := a.directory.search(ctx, userID, query, limit)
	if err != nil {
		return nil, err
	}
	profiles := make([]eas.Profile, 0, len(entries))
	for _, entry := range entries {
		profiles = append(profiles, eas.Profile{ID: entry.ID, DisplayName: entry.DisplayName, Addresses: entry.Addresses})
	}
	return profiles, nil
}

// FreeBusy answers ResolveRecipients availability under the shared
// free/busy visibility rule.
func (a easAccounts) FreeBusy(ctx context.Context, access service.AccessContext, address string, start, end time.Time) ([]eas.BusyPeriod, bool, error) {
	if a.freeBusy == nil {
		return nil, false, nil
	}
	periods, known, err := a.freeBusy(ctx, access, address, start, end)
	if err != nil || !known {
		return nil, known, err
	}
	result := make([]eas.BusyPeriod, 0, len(periods))
	for _, period := range periods {
		result = append(result, eas.BusyPeriod{Start: period.Start, End: period.End, Tentative: period.Type == calendarindex.BusyTentativeType})
	}
	return result, true, nil
}

// lazySearch reaches the search manager, which starts after the HTTP
// handlers are mounted.
type lazySearch struct{ resolve func() service.SearchReader }

var errSearchStarting = errors.New("search is starting")

func (l lazySearch) Search(ctx context.Context, access service.AccessContext, query service.SearchQuery) (service.SearchPage, error) {
	if reader := l.resolve(); reader != nil {
		return reader.Search(ctx, access, query)
	}
	return service.SearchPage{}, errSearchStarting
}

func (l lazySearch) SearchStatus(ctx context.Context, access service.AccessContext, accountID string) (service.SearchIndexStatus, error) {
	if reader := l.resolve(); reader != nil {
		return reader.SearchStatus(ctx, access, accountID)
	}
	return service.SearchIndexStatus{}, errSearchStarting
}

func (l lazySearch) RequestSearchRebuild(ctx context.Context, access service.AccessContext, accountID string) error {
	if reader := l.resolve(); reader != nil {
		return reader.RequestSearchRebuild(ctx, access, accountID)
	}
	return errSearchStarting
}

type easScheduler struct {
	respond func(context.Context, service.AccessContext, string, string) error
}

func (s easScheduler) Respond(ctx context.Context, access service.AccessContext, itemID, partStat string) error {
	return s.respond(ctx, access, itemID, partStat)
}
