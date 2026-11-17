package main

import (
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/config"
)

func TestBackupScheduleSettingsApplyLive(t *testing.T) {
	s := &server{}
	t.Cleanup(func() {
		s.cleanup.run(true)
	})
	dataDir := t.TempDir()
	if err := s.openRuntime(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := s.startBackupSchedule(); err != nil {
		t.Fatal(err)
	}
	if status := s.backupScheduler.Status(); status.Enabled || status.Directory != filepath.Join(dataDir, "backups") || !status.Downloadable {
		t.Fatalf("default status = %+v", status)
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "nas")
	patchAndApply(t, s, map[string]any{
		"backup_schedule": "sat 02:30", "backup_directory": destination, "backup_age_recipients": []string{identity.Recipient().String()},
		"backup_retention_daily": 2, "backup_retention_weekly": 1,
	})
	for _, key := range backupScheduleKeys {
		if status := applyState(t, s, key); status.State != config.ApplyEffective || status.RestartRequired {
			t.Fatalf("%s state = %+v", key, status)
		}
	}
	status := s.backupScheduler.Status()
	if status.Schedule != "weekly sat 02:30" || status.Directory != destination || !status.Encrypted || status.KeepDaily != 2 || status.KeepWeekly != 1 || status.Downloadable || status.State.NextRunAt.IsZero() {
		t.Fatalf("applied status = %+v", status)
	}
	if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, map[string]any{"backup_age_recipients": []string{identity.String()}}); err == nil || strings.Contains(err.Error(), identity.String()) {
		t.Fatalf("private key as recipient = %v", err)
	}
	if _, err := s.cfgService.Patch(s.cfgService.Current().Revision, map[string]any{"backup_schedule": "hourly"}); err == nil {
		t.Fatal("an invalid schedule was accepted")
	}

	archive, err := s.backupScheduler.Run(t.Context(), backup.TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !archive.Encrypted || archive.Directory != destination {
		t.Fatalf("archive = %+v", archive)
	}
	if observation := s.backupScheduler.Observation(archive.CreatedAt); observation.State != "healthy" {
		t.Fatalf("observation after a successful run = %+v", observation)
	}
}
