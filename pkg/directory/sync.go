package directory

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// MaxSyncEntries bounds one sync. A directory matching more entries fails the
// sync instead of disabling accounts from a partial list.
const MaxSyncEntries = 100_000

// firstSyncDelay postpones the first scheduled sync after startup or a
// settings change so it never competes with startup work.
const firstSyncDelay = time.Minute

const lastSyncKey = "directory.ldap.last_sync"

// SyncResult records one sync run. It is persisted so status survives restarts.
type SyncResult struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Actor      string    `json:"actor"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	Warning    string    `json:"warning,omitempty"`
	// Entries is the number of directory entries the sync filter matched.
	Entries int `json:"entries"`
	// Accounts is the number of local directory accounts examined.
	Accounts  int `json:"accounts"`
	Updated   int `json:"updated"`
	Disabled  int `json:"disabled"`
	Enabled   int `json:"enabled"`
	Unchanged int `json:"unchanged"`
	Failed    int `json:"failed"`
}

// Status summarizes directory configuration and sync state for administrators.
type Status struct {
	Enabled             bool        `json:"enabled"`
	Connected           bool        `json:"connected"`
	Servers             []string    `json:"servers"`
	SyncIntervalMinutes int         `json:"sync_interval_minutes"`
	Running             bool        `json:"running"`
	LastSync            *SyncResult `json:"last_sync,omitempty"`
	NextSync            time.Time   `json:"next_sync,omitzero"`
	Accounts            int         `json:"accounts"`
	DisabledAccounts    int         `json:"disabled_accounts"`
}

// Sync refreshes every local directory account from the directory and
// disables accounts whose entry is gone or disabled. It never creates or
// deletes accounts, and an empty directory result disables nothing.
func (s *Service) Sync(ctx context.Context, actor string) (SyncResult, error) {
	if !s.syncing.TryLock() {
		return SyncResult{}, ErrSyncRunning
	}
	defer s.syncing.Unlock()
	s.running.Store(true)
	defer s.running.Store(false)
	result := SyncResult{StartedAt: time.Now().UTC(), Actor: actor}
	err := s.sync(ctx, &result)
	result.FinishedAt, result.OK = time.Now().UTC(), err == nil
	if err != nil {
		result.Error = err.Error()
		log.Warn("directory sync failed", "error", err)
	} else {
		log.Info("directory sync completed", "entries", result.Entries, "accounts", result.Accounts, "updated", result.Updated, "disabled", result.Disabled, "enabled", result.Enabled, "failed", result.Failed)
	}
	if persistErr := s.ts.Set(context.WithoutCancel(ctx), model.NSMetadata, lastSyncKey, result); persistErr != nil {
		log.Error("record directory sync result", "error", persistErr)
	}
	s.audit.Log(actor, "directory.sync", "ldap", map[string]string{
		"ok": strconv.FormatBool(result.OK), "error": result.Error, "entries": strconv.Itoa(result.Entries),
		"updated": strconv.Itoa(result.Updated), "disabled": strconv.Itoa(result.Disabled), "enabled": strconv.Itoa(result.Enabled), "failed": strconv.Itoa(result.Failed),
	})
	return result, err
}

func (s *Service) sync(ctx context.Context, result *SyncResult) error {
	directory, settings := s.current()
	if directory == nil {
		return ErrDisabled
	}
	entries, err := directory.Users(ctx, MaxSyncEntries)
	if err != nil {
		return err
	}
	result.Entries = len(entries)
	byGUID, byDN, byLogin := map[string]Entry{}, map[string]Entry{}, map[string]Entry{}
	for _, entry := range entries {
		if entry.GUID != "" {
			byGUID[entry.GUID] = entry
		}
		byDN[strings.ToLower(entry.DN)] = entry
		byLogin[entry.Login] = entry
	}
	users, err := s.users.List(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	for _, user := range users {
		if !user.Directory() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result.Accounts++
		// An account with a stable identity matches only that identity: a
		// different entry reusing its login is another person.
		var entry Entry
		var found bool
		if user.DirectoryID != "" {
			entry, found = byGUID[user.DirectoryID]
		} else if entry, found = byDN[strings.ToLower(user.DirectoryDN)]; !found {
			entry, found = byLogin[user.ID]
		}
		switch {
		case found && !entry.Disabled:
			s.provision.Lock()
			_, changed, err := s.refresh(ctx, user, entry, settings, true)
			s.provision.Unlock()
			switch {
			case err != nil:
				result.Failed++
				log.Warn("directory sync could not update account", "account", user.ID, "error", err)
			case changed && !user.Enabled && user.DirectoryDisabled:
				result.Enabled++
			case changed:
				result.Updated++
			default:
				result.Unchanged++
			}
		case len(entries) == 0:
			result.Unchanged++
			result.Warning = "the directory returned no entries, so no accounts were disabled"
		default:
			reason := "not found in directory"
			if found {
				reason = "disabled in directory"
			}
			disabled, err := s.disable(ctx, user, reason)
			switch {
			case err != nil:
				result.Failed++
				log.Warn("directory sync could not disable account", "account", user.ID, "error", err)
			case disabled:
				result.Disabled++
			default:
				result.Unchanged++
			}
		}
	}
	return nil
}

// disable turns off a directory account whose entry is gone or disabled and
// revokes the administrator role the directory granted. Data is kept.
func (s *Service) disable(ctx context.Context, user model.User, reason string) (bool, error) {
	s.provision.Lock()
	defer s.provision.Unlock()
	if _, err := s.setAdmin(ctx, user.ID, false, ""); err != nil {
		return false, err
	}
	if !user.Enabled {
		return false, nil
	}
	if err := s.users.Update(ctx, user.ID, func(u *model.User) { u.Enabled, u.DirectoryDisabled = false, true }); err != nil {
		return false, err
	}
	log.Info("disabled directory account", "account", user.ID, "reason", reason)
	s.audit.Log(auditActor, "directory.account.disable", user.ID, map[string]string{"reason": reason, "dn": user.DirectoryDN})
	return true, nil
}

// Status reports configuration, the last sync, and directory account counts.
func (s *Service) Status(ctx context.Context) (Status, error) {
	directory, settings := s.current()
	status := Status{
		Enabled: settings.Enabled, Connected: directory != nil, Servers: append([]string{}, settings.URLs...),
		SyncIntervalMinutes: int(settings.SyncInterval / time.Minute),
	}
	status.Running = s.running.Load()
	if last, ok := s.lastSync(ctx); ok {
		status.LastSync = &last
	}
	if delay, ok := s.nextDelay(ctx); ok {
		status.NextSync = time.Now().UTC().Add(delay).Truncate(time.Second)
	}
	users, err := s.users.List(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return status, err
	}
	for _, user := range users {
		if user.Directory() {
			status.Accounts++
			if !user.Enabled {
				status.DisabledAccounts++
			}
		}
	}
	return status, nil
}

// Test checks the current settings with a fresh connection, whether or not
// directory accounts are enabled, so settings can be verified first.
func (s *Service) Test(ctx context.Context) (Diagnostic, error) {
	_, settings := s.current()
	directory, err := s.connect(settings)
	if err != nil {
		return Diagnostic{}, err
	}
	defer directory.Close()
	return directory.Test(ctx), nil
}

func (s *Service) lastSync(ctx context.Context) (SyncResult, bool) {
	var last SyncResult
	if err := s.ts.Get(ctx, model.NSMetadata, lastSyncKey, &last); err != nil {
		return SyncResult{}, false
	}
	return last, true
}

// nextDelay returns how long until the next scheduled sync, and false when
// scheduled sync is off. A restart resumes the schedule from the persisted
// last run.
func (s *Service) nextDelay(ctx context.Context) (time.Duration, bool) {
	directory, settings := s.current()
	if directory == nil || settings.SyncInterval <= 0 {
		return 0, false
	}
	delay := firstSyncDelay
	if last, ok := s.lastSync(ctx); ok {
		delay = max(time.Until(last.StartedAt.Add(settings.SyncInterval)), firstSyncDelay)
	}
	return delay, true
}

// Start runs scheduled syncs until ctx ends or the returned stop is called.
// A settings change reschedules immediately.
func (s *Service) Start(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var fire <-chan time.Time
			var timer *time.Timer
			if delay, ok := s.nextDelay(ctx); ok {
				timer = time.NewTimer(delay)
				fire = timer.C
			}
			select {
			case <-ctx.Done():
			case <-s.wake:
			case <-fire:
				_, _ = s.Sync(ctx, "system")
			}
			if timer != nil {
				timer.Stop()
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	return func() { cancel(); <-done }
}
