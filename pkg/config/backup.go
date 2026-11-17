package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/backup/archivecrypt"
	"github.com/lkarlslund/veksel/pkg/backup/schedule"
)

// validateBackups checks the scheduled backup settings.
func validateBackups(cfg *Config) error {
	if _, err := schedule.Parse(cfg.BackupSchedule); err != nil {
		return fmt.Errorf("backup_schedule: %w", err)
	}
	if strings.TrimSpace(cfg.BackupDirectory) == "" {
		return errors.New("backup_directory must not be empty")
	}
	if _, err := archivecrypt.ParseRecipients(cfg.BackupAgeRecipients); err != nil {
		return fmt.Errorf("backup_age_recipients: %w", err)
	}
	if cfg.BackupRetentionDaily < 0 || cfg.BackupRetentionDaily > 3650 || cfg.BackupRetentionWeekly < 0 || cfg.BackupRetentionWeekly > 520 || cfg.BackupRetentionDaily+cfg.BackupRetentionWeekly < 1 {
		return errors.New("backup retention requires 0-3650 daily and 0-520 weekly archives, keeping at least one")
	}
	return nil
}
