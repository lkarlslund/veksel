package main

import (
	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/health"
)

// backupScheduleKeys are the settings the backup scheduler applies live.
var backupScheduleKeys = []string{"backup_schedule", "backup_directory", "backup_age_recipients", "backup_retention_daily", "backup_retention_weekly"}

// startBackupSchedule opens the durable backup scheduler, starts its loop,
// and makes the scheduled backup settings live. Its runs take the same
// online backup path, and the same single-flight gate, as administrator
// downloads.
func (s *server) startBackupSchedule() error {
	scheduler, err := backup.NewScheduler(s.ctx, backup.SchedulerOptions{
		Store: s.ts,
		Source: func() backup.InstallationSource {
			source := backup.LiveSource(s.ts.Store(), s.ts.Backend(), s.accountManager, s.cfgService.Path())
			source.VekselVersion = buildVersion
			return source
		},
		Audit:    audit.New(s.ts),
		Capacity: health.OSCapacityProber{},
	})
	if err != nil {
		return startupError("initialize scheduled backups", err)
	}
	apply := func(cfg *config.Config) error {
		policy, err := backup.SchedulePolicyFromConfig(cfg)
		if err != nil {
			return err
		}
		return scheduler.SetPolicy(s.ctx, policy)
	}
	if err := apply(s.cfg); err != nil {
		return startupError("initialize scheduled backups", err)
	}
	s.backupScheduler = scheduler
	s.cleanup.push(scheduler.Start(s.ctx))
	return s.cfgService.RegisterApplier(apply, backupScheduleKeys...)
}
