package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

func TestServiceCreatesSecureDefaults(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := service.Current()
	if snapshot.Config.StorePath != filepath.Join(dir, "pebble") {
		t.Fatalf("derived store path = %q", snapshot.Config.StorePath)
	}
	if snapshot.Revision == "" || len(snapshot.Schema) < 20 {
		t.Fatalf("incomplete snapshot: revision=%q schema=%d", snapshot.Revision, len(snapshot.Schema))
	}
	info, err := os.Stat(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
}

func TestServiceLoadsRetiredSettings(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, configFileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// queue_max_retries was retired in favour of age-bounded retry.
	retired := bytes.Replace(contents, []byte("\nqueue_max_age_hours"), []byte("\nqueue_max_retries = 5\nqueue_max_age_hours"), 1)
	if bytes.Equal(retired, contents) {
		t.Fatal("default document has no queue_max_age_hours anchor")
	}
	if err := os.WriteFile(path, retired, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Reload(); err != nil {
		t.Fatalf("reload with retired setting: %v", err)
	}
}

func TestEmptyServerNamesUseHostnameWithoutPersistingIt(t *testing.T) {
	previous := systemHostname
	systemHostname = func() string { return "mail.example.test" }
	t.Cleanup(func() { systemHostname = previous })
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := service.Current().Config
	if cfg.SmtpServerName != "mail.example.test" || cfg.ImapServerName != "mail.example.test" || cfg.RelayServerName != "mail.example.test" {
		t.Fatalf("derived names = %q %q %q", cfg.SmtpServerName, cfg.ImapServerName, cfg.RelayServerName)
	}
	if _, err := service.Patch(service.Current().Revision, map[string]any{"log_format": "json"}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte("smtp_server_name = ''")) || bytes.Contains(contents, []byte("mail.example.test")) {
		t.Fatalf("derived host name was persisted:\n%s", contents)
	}
}

func TestPatchPreservesCommentsAndRejectsStaleRevision(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, configFileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents = append([]byte("# administrator note\n"), contents...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := service.Reload()
	if err != nil {
		t.Fatal(err)
	}
	after, err := service.Patch(before.Revision, map[string]any{"smtp_max_recipients": int64(250)})
	if err != nil {
		t.Fatal(err)
	}
	if after.Config.SmtpMaxRecipients != 250 {
		t.Fatalf("smtp max recipients = %d", after.Config.SmtpMaxRecipients)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "# administrator note") {
		t.Fatal("patch discarded administrator comment")
	}
	if _, err := service.Patch(before.Revision, map[string]any{"smtp_enabled": false}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale patch error = %v", err)
	}
}

func TestModuleLogLevelsPersistWithCommentsAndApplyLive(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	registerNoopAppliers(t, service)
	initial := service.Current()
	if !reflect.DeepEqual(initial.Config.LogModuleLevels, logpkg.DefaultModuleLevels()) {
		t.Fatalf("default module levels are incomplete: %v", initial.Config.LogModuleLevels)
	}
	path := filepath.Join(dir, configFileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents = append([]byte("# retain this operator comment\n"), contents...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err = service.Reload()
	if err != nil {
		t.Fatal(err)
	}
	levels := logpkg.DefaultModuleLevels()
	levels["imap"] = "trace"
	updated, plan, err := service.PatchWithPlan(initial.Revision, map[string]any{"log_module_levels": levels}, MutationMetadata{Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RestartRequired || !slices.Contains(plan.LiveApplyKeys, "log_module_levels") || updated.Config.LogModuleLevels["imap"] != "trace" {
		t.Fatalf("module logging plan=%+v config=%v", plan, updated.Config.LogModuleLevels)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), "# retain this operator comment") || !strings.Contains(string(persisted), "imap = 'trace'") && !strings.Contains(string(persisted), `imap = "trace"`) {
		t.Fatalf("module logging patch lost comments or value:\n%s", persisted)
	}
	if _, _, err := service.PreviewPatch(updated.Revision, map[string]any{"log_module_levels": map[string]string{"not-a-module": "debug"}}); err == nil {
		t.Fatal("unknown module was accepted")
	}
	if _, _, err := service.PreviewPatch(updated.Revision, map[string]any{"log_module_levels": map[string]string{"imap": "verbose"}}); err == nil {
		t.Fatal("unknown module level was accepted")
	}
	withoutModuleTable := strings.Split(string(persisted), "\n[log_module_levels]\n")[0]
	upgraded, err := service.decode([]byte(withoutModuleTable))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(upgraded.LogModuleLevels, logpkg.DefaultModuleLevels()) {
		t.Fatalf("configuration without a module table did not inherit defaults: %v", upgraded.LogModuleLevels)
	}
}

func TestQuotaThresholdPlanValidatesDependencyAndAppliesLive(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registerNoopAppliers(t, service)
	initial := service.Current()
	if _, _, err := service.PreviewPatch(initial.Revision, map[string]any{
		"quota_warning_percent": int64(96), "quota_critical_percent": int64(95),
	}); err == nil {
		t.Fatal("warning at or above critical was accepted")
	}
	_, plan, err := service.PreviewPatch(initial.Revision, map[string]any{
		"quota_warning_percent": int64(85), "quota_critical_percent": int64(97),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RestartRequired || !slices.Equal(plan.LiveApplyKeys, []string{"quota_warning_percent", "quota_critical_percent"}) {
		t.Fatalf("quota plan = %+v", plan)
	}
	if len(plan.DependencyGroups) != 1 || plan.DependencyGroups[0].ID != "quota-pressure" || !slices.Equal(plan.DependencyGroups[0].ChangedKeys, plan.LiveApplyKeys) {
		t.Fatalf("quota dependency plan = %+v", plan.DependencyGroups)
	}
}

func TestGreylistingPlanValidatesTimingAndRestartDependency(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Current()
	for name, changes := range map[string]map[string]any{
		"delay exceeds retry": {"greylist_minimum_delay_seconds": int64(3600), "greylist_retry_window_minutes": int64(30)},
		"pending too short":   {"greylist_retry_window_minutes": int64(300), "greylist_pending_lifetime_hours": int64(4)},
		"invalid prefix":      {"greylist_ipv6_prefix_bits": int64(129)},
		"capacity too small":  {"greylist_max_entries": int64(99)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := service.PreviewPatch(initial.Revision, changes); err == nil {
				t.Fatal("invalid greylisting configuration was accepted")
			}
		})
	}
	_, plan, err := service.PreviewPatch(initial.Revision, map[string]any{
		"greylist_enabled": true, "greylist_minimum_delay_seconds": int64(600),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.RestartRequired || len(plan.DependencyGroups) != 1 || plan.DependencyGroups[0].ID != "greylisting" || len(plan.DependencyGroups[0].ChangedKeys) != 2 {
		t.Fatalf("greylisting plan = %+v", plan)
	}
}

func TestAddressingSettingsValidate(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Current()
	if cfg := initial.Config; cfg.RecipientDelimiter != "+" || !cfg.SrsEnabled || cfg.SrsDomain != "" {
		t.Fatalf("addressing defaults = %q, %t, %q", cfg.RecipientDelimiter, cfg.SrsEnabled, cfg.SrsDomain)
	}
	for _, changes := range []map[string]any{
		{"recipient_delimiter": "a"}, {"recipient_delimiter": "@"}, {"recipient_delimiter": "+ "}, {"recipient_delimiter": "+-_=#~!$%"},
		{"srs_domain": "bad domain"}, {"srs_domain": "user@example.com"}, {"srs_domain": "-bad.example"},
	} {
		if _, _, err := service.PreviewPatch(initial.Revision, changes); err == nil {
			t.Errorf("invalid addressing setting %v was accepted", changes)
		}
	}
	_, plan, err := service.PreviewPatch(initial.Revision, map[string]any{"recipient_delimiter": "+-", "srs_domain": "fwd.example.com", "srs_enabled": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DependencyGroups) != 1 || plan.DependencyGroups[0].ID != "addressing" {
		t.Fatalf("addressing plan = %+v", plan.DependencyGroups)
	}
}

func TestHealthAlertPlanValidatesDependenciesAndAppliesLive(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registerNoopAppliers(t, service)
	initial := service.Current()
	for name, changes := range map[string]map[string]any{
		"queue ordering":       {"alert_queue_warning_minutes": int64(90), "alert_queue_critical_minutes": int64(60)},
		"webhook ordering":     {"alert_webhook_warning_minutes": int64(60), "alert_webhook_critical_minutes": int64(30)},
		"storage ordering":     {"alert_storage_warning_free_percent": int64(5), "alert_storage_critical_free_percent": int64(10)},
		"certificate ordering": {"alert_certificate_warning_days": int64(7), "alert_certificate_critical_days": int64(7)},
		"evaluation minimum":   {"alert_evaluation_seconds": int64(4)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := service.PreviewPatch(initial.Revision, changes); err == nil {
				t.Fatal("invalid alert policy was accepted")
			}
		})
	}
	changes := map[string]any{
		"alert_evaluation_seconds": int64(30), "alert_queue_warning_minutes": int64(20),
		"alert_queue_critical_minutes": int64(90), "alert_certificate_warning_days": int64(45),
		"alert_webhook_warning_minutes": int64(10), "alert_webhook_critical_minutes": int64(45),
		"alert_storage_warning_free_percent": int64(20), "alert_storage_critical_free_percent": int64(8),
		"alert_certificate_critical_days": int64(10), "alert_notifications_enabled": false,
	}
	_, plan, err := service.PreviewPatch(initial.Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RestartRequired || len(plan.LiveApplyKeys) != len(changes) || len(plan.DependencyGroups) != 1 || plan.DependencyGroups[0].ID != "health-alerts" {
		t.Fatalf("health alert plan = %+v", plan)
	}
}

func TestHistoryRecordsActorReasonAndSecretRedactedStructuredDiff(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Current()
	after, err := service.PatchWithMetadata(initial.Revision, map[string]any{
		"smtp_max_recipients": int64(321),
		"relay_password":      "history-must-not-contain-this-secret",
	}, MutationMetadata{Actor: " admin\nuser ", Reason: " incident\tchange ", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	history, err := service.History(10)
	if err != nil || len(history) != 2 {
		t.Fatalf("history = %+v, %v", history, err)
	}
	latest := history[0]
	if latest.Revision != after.Revision || latest.ParentRevision != initial.Revision || latest.Actor != "admin user" || latest.Reason != "incident change" || latest.Source != "test" {
		t.Fatalf("latest history = %+v", latest)
	}
	changes := make(map[string]Change, len(latest.Changes))
	for _, change := range latest.Changes {
		changes[change.Key] = change
	}
	if fmt.Sprint(changes["smtp_max_recipients"].After) != "321" {
		t.Fatalf("ordinary diff = %+v", changes["smtp_max_recipients"])
	}
	secret := changes["relay_password"]
	if !secret.Sensitive || secret.Before != redactedValue || secret.After != redactedValue {
		t.Fatalf("secret diff = %+v", secret)
	}
	metadata, err := os.ReadFile(service.historyMetadataPath(latest.ID))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), "history-must-not-contain-this-secret") {
		t.Fatal("configuration history metadata contains a secret")
	}
}

func TestHistorySanitizesTamperedMetadataAgainstCurrentSchema(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	current := service.Current()
	if _, err := service.PatchWithMetadata(current.Revision, map[string]any{
		"relay_password":      "never-return-this-secret",
		"smtp_max_recipients": int64(321),
	}, MutationMetadata{Actor: "operator"}); err != nil {
		t.Fatal(err)
	}
	history, err := service.History(1)
	if err != nil || len(history) != 1 {
		t.Fatalf("history = %+v, %v", history, err)
	}
	entry := history[0]
	metadataPath := service.historyMetadataPath(entry.ID)
	entry.ID = "../../outside-history"
	entry.ParentRevision = "invalid-parent"
	entry.Actor = " tampered\nactor "
	entry.Changes = []Change{
		{Key: "relay_password", Before: "old-secret", After: "new-secret"},
		{Key: "unknown_secret", Before: "unknown-old", After: "unknown-new"},
		{Key: "smtp_max_recipients", Before: float64(100), After: float64(321)},
		{Key: "smtp_max_recipients", Before: "duplicate", After: "duplicate"},
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	history, err = service.History(1)
	if err != nil || len(history) != 1 {
		t.Fatalf("sanitized history = %+v, %v", history, err)
	}
	got := history[0]
	if got.ID != history[0].ID || got.ParentRevision != "" || got.Actor != "tampered actor" || len(got.Changes) != 2 {
		t.Fatalf("sanitized entry = %+v", got)
	}
	if got.Changes[0].Key != "smtp_max_recipients" || fmt.Sprint(got.Changes[0].Before) != "100" || got.Changes[1].Key != "relay_password" || !got.Changes[1].Sensitive || got.Changes[1].Before != redactedValue || got.Changes[1].After != redactedValue {
		t.Fatalf("sanitized changes = %+v", got.Changes)
	}
	serialized, _ := json.Marshal(got)
	for _, secret := range []string{"old-secret", "new-secret", "unknown-old", "unknown-new", "duplicate"} {
		if bytes.Contains(serialized, []byte(secret)) {
			t.Fatalf("sanitized history retained %q: %s", secret, serialized)
		}
	}
}

func TestApplyStateSeparatesDesiredEffectivePendingAndFailure(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registerNoopAppliers(t, service)
	initial := applyStateByKey(service.ApplyStates())
	if initial["smtp_max_recipients"].State != ApplyEffective {
		t.Fatalf("initial state = %+v", initial["smtp_max_recipients"])
	}
	after, err := service.Patch(service.Current().Revision, map[string]any{
		"smtp_max_recipients":  int64(222),
		"trash_retention_days": int64(45),
		"relay_password":       "never-return-this-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	states := applyStateByKey(service.ApplyStates())
	if got := states["smtp_max_recipients"]; got.State != ApplyPendingRestart || fmt.Sprint(got.Desired) != "222" || fmt.Sprint(got.Effective) != "100" || !got.RestartRequired {
		t.Fatalf("pending state = %+v", got)
	}
	if got := states["trash_retention_days"]; got.State != ApplyPendingRestart || got.RestartRequired {
		t.Fatalf("live pending state = %+v", got)
	}
	if got := states["relay_password"]; got.Desired != redactedValue || got.Effective != redactedValue {
		t.Fatalf("sensitive apply state = %+v", got)
	}
	if err := service.MarkApplying("trash_retention_days"); err != nil {
		t.Fatal(err)
	}
	if got := applyStateByKey(service.ApplyStates())["trash_retention_days"]; got.State != ApplyApplying || got.AttemptedAt.IsZero() {
		t.Fatalf("applying state = %+v", got)
	}
	if err := service.MarkEffective("trash_retention_days"); err != nil {
		t.Fatal(err)
	}
	if got := applyStateByKey(service.ApplyStates())["trash_retention_days"]; got.State != ApplyEffective || fmt.Sprint(got.Effective) != "45" {
		t.Fatalf("effective live state = %+v", got)
	}
	longFailure := strings.Repeat("failed\n", 200)
	if err := service.MarkFailed(errors.New(longFailure), "smtp_max_recipients"); err != nil {
		t.Fatal(err)
	}
	failed := applyStateByKey(service.ApplyStates())["smtp_max_recipients"]
	if failed.State != ApplyFailed || failed.AttemptedAt.IsZero() || strings.Contains(failed.Error, "\n") || len([]rune(failed.Error)) > maxApplyErrorRunes {
		t.Fatalf("failed state = %+v", failed)
	}
	if _, err := service.Patch(after.Revision, map[string]any{"smtp_max_recipients": int64(333)}); err != nil {
		t.Fatal(err)
	}
	if got := applyStateByKey(service.ApplyStates())["smtp_max_recipients"]; got.State != ApplyPendingRestart || got.Error != "" {
		t.Fatalf("stale failure leaked into new desired value = %+v", got)
	}
	if err := service.MarkEffective("unknown"); err == nil {
		t.Fatal("unknown apply key was accepted")
	}
}

func TestPreviewAndCommitUseTheSameDependencyAwarePlan(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registerNoopAppliers(t, service)
	initial := service.Current()
	changes := map[string]any{
		"queue_workers":             float64(8),
		"queue_max_per_destination": float64(4),
		"trash_retention_days":      float64(60),
		"relay_password":            "plan-must-not-return-secret",
	}
	preview, plan, err := service.PreviewPatch(initial.Revision, changes)
	if err != nil {
		t.Fatal(err)
	}
	if service.Current().Revision != initial.Revision || preview.Revision != plan.ProposedRevision || plan.BaseRevision != initial.Revision || !plan.RestartRequired {
		t.Fatalf("preview mutated or returned inconsistent plan: snapshot=%+v plan=%+v", preview, plan)
	}
	groups := make(map[string]DependencyGroup, len(plan.DependencyGroups))
	for _, group := range plan.DependencyGroups {
		groups[group.ID] = group
	}
	if !reflect.DeepEqual(groups["queue"].ChangedKeys, []string{"queue_workers", "queue_max_per_destination"}) {
		t.Fatalf("queue dependency group = %+v", groups["queue"])
	}
	if !slices.Contains(plan.LiveApplyKeys, "trash_retention_days") {
		t.Fatalf("live apply keys = %q", plan.LiveApplyKeys)
	}
	for _, change := range plan.Changes {
		if change.Key == "relay_password" && (change.Before != redactedValue || change.After != redactedValue || change.Effective != redactedValue) {
			t.Fatalf("secret plan change = %+v", change)
		}
	}
	committed, committedPlan, err := service.PatchWithPlan(initial.Revision, changes, MutationMetadata{Actor: "planner"})
	if err != nil {
		t.Fatal(err)
	}
	if committed.Revision != preview.Revision || !reflect.DeepEqual(committedPlan, plan) {
		t.Fatalf("committed a different plan: preview=%+v committed=%+v", plan, committedPlan)
	}
	if _, _, err := service.PreviewPatch(committed.Revision, map[string]any{"queue_workers": float64(1)}); err == nil {
		t.Fatal("dependency-invalid queue plan was accepted")
	}
}

func TestPlanRejectsUnreloadedExternalDrift(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	current := service.Current()
	path := filepath.Join(dir, configFileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	drifted := []byte(strings.Replace(string(contents), "smtp_max_recipients = 100", "smtp_max_recipients = 101", 1))
	if err := os.WriteFile(path, drifted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PlanPatch(current.Revision, map[string]any{"smtp_max_recipients": int64(200)}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("external drift plan error = %v", err)
	}
	if _, err := service.Patch(current.Revision, map[string]any{"smtp_max_recipients": int64(200)}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("external drift patch error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(drifted) {
		t.Fatalf("drifted file was overwritten: %v", err)
	}
}

func applyStateByKey(states []SettingApplyStatus) map[string]SettingApplyStatus {
	result := make(map[string]SettingApplyStatus, len(states))
	for _, state := range states {
		result[state.Key] = state
	}
	return result
}

func TestHistoryIsBoundedAndRetainsCurrentRevision(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaxHistoryRevisions+8; index++ {
		current := service.Current()
		if _, err := service.Patch(current.Revision, map[string]any{"smtp_max_recipients": int64(100 + index)}); err != nil {
			t.Fatal(err)
		}
	}
	history, err := service.History(0)
	if err != nil || len(history) != MaxHistoryRevisions {
		t.Fatalf("bounded history has %d entries: %v", len(history), err)
	}
	if history[0].Revision != service.Current().Revision {
		t.Fatalf("newest revision = %q, current = %q", history[0].Revision, service.Current().Revision)
	}
	files, err := os.ReadDir(service.historyDir)
	if err != nil || len(files) != MaxHistoryRevisions*2 {
		t.Fatalf("history files = %d, %v", len(files), err)
	}
}

func TestReloadAddsExternalRevisionToHistory(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := service.Current()
	path := filepath.Join(dir, configFileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the existing key instead of leaving invalid duplicate TOML.
	contents = []byte(strings.Replace(string(contents), "smtp_max_recipients = 100", "# external change\nsmtp_max_recipients = 222", 1))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := service.Reload()
	if err != nil || after.Revision == before.Revision || after.Config.SmtpMaxRecipients != 222 {
		t.Fatalf("reload = %+v, %v", after, err)
	}
	history, err := service.History(2)
	if err != nil || len(history) != 2 || history[0].Source != "reload" || history[0].ParentRevision != before.Revision {
		t.Fatalf("reload history = %+v, %v", history, err)
	}
}

func TestRestoreSelectedRevisionCreatesASeparateActivationEvent(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Current()
	changed, err := service.Patch(initial.Revision, map[string]any{"smtp_max_recipients": int64(444)})
	if err != nil {
		t.Fatal(err)
	}
	restored, activation, plan, err := service.RestoreRevisionWithPlan(changed.Revision, initial.Revision, MutationMetadata{Actor: "operator", Reason: "roll back incident"})
	if err != nil || restored.Revision != initial.Revision || restored.Config.SmtpMaxRecipients != initial.Config.SmtpMaxRecipients {
		t.Fatalf("restore = %+v, activation=%+v, err=%v", restored, activation, err)
	}
	if activation.Source != "restore" || activation.Actor != "operator" || activation.Reason != "roll back incident" || activation.ParentRevision != changed.Revision || activation.Revision != initial.Revision {
		t.Fatalf("activation = %+v", activation)
	}
	if plan.BaseRevision != changed.Revision || plan.ProposedRevision != initial.Revision || len(plan.Changes) != 1 || plan.Changes[0].Key != "smtp_max_recipients" {
		t.Fatalf("restore plan = %+v", plan)
	}
	history, err := service.History(10)
	if err != nil || len(history) != 3 || history[0].ID != activation.ID || history[0].Revision != history[2].Revision {
		t.Fatalf("restored history = %+v, %v", history, err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopenedHistory, err := reopened.History(10)
	if err != nil || len(reopenedHistory) != 3 {
		t.Fatalf("reopen added a synthetic history event: %+v, %v", reopenedHistory, err)
	}
}

func TestPatchIsValidatedAndAtomic(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := service.Current()
	path := filepath.Join(dir, configFileName)
	original, _ := os.ReadFile(path)
	if _, err := service.Patch(before.Revision, map[string]any{"smtp_listen": "invalid"}); err == nil {
		t.Fatal("invalid listener was accepted")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(original) {
		t.Fatal("failed patch changed the file")
	}
	if _, err := service.Patch(before.Revision, map[string]any{"not_a_setting": true}); err == nil {
		t.Fatal("unknown setting was accepted")
	}
	if _, err := service.Patch(before.Revision, map[string]any{"smtp_max_received_headers": int64(0)}); err == nil {
		t.Fatal("invalid SMTP loop limit was accepted")
	}
	if _, err := service.Patch(before.Revision, map[string]any{"queue_receipt_retention_days": int64(0)}); err == nil {
		t.Fatal("invalid queue receipt retention was accepted")
	}
}

func TestPatchQueueReceiptRetentionRoundTrips(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Patch(service.Current().Revision, map[string]any{"queue_receipt_retention_days": int64(21)})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Config.QueueReceiptRetentionDays != 21 {
		t.Fatalf("retention = %d, want 21", updated.Config.QueueReceiptRetentionDays)
	}
}

func TestPatchQuarantinePolicyRoundTripsAndValidates(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Patch(service.Current().Revision, map[string]any{
		"quarantine_retention_days":     int64(45),
		"quarantine_max_entries":        int64(250_000),
		"quarantine_max_bytes":          int64(20 << 30),
		"quarantine_cleanup_minutes":    int64(15),
		"quarantine_cleanup_batch_size": int64(5_000),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg := updated.Config; cfg.QuarantineRetentionDays != 45 || cfg.QuarantineMaxEntries != 250_000 || cfg.QuarantineMaxBytes != 20<<30 || cfg.QuarantineCleanupMinutes != 15 || cfg.QuarantineCleanupBatchSize != 5_000 {
		t.Fatalf("quarantine policy = %+v", cfg)
	}
	if _, err := service.Patch(updated.Revision, map[string]any{"quarantine_max_bytes": int64(1024)}); err == nil {
		t.Fatal("undersized quarantine capacity was accepted")
	}
}

func TestPatchQuarantineDigestRequiresSecurePublicOrigin(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Patch(service.Current().Revision, map[string]any{"quarantine_digest_enabled": true}); err == nil {
		t.Fatal("enabled digest without a public origin was accepted")
	}
	updated, err := service.Patch(service.Current().Revision, map[string]any{
		"quarantine_digest_enabled":  true,
		"quarantine_digest_base_url": "https://mail.example.test",
		"quarantine_digest_from":     "Quarantine <postmaster@example.test>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Config.QuarantineDigestEnabled || updated.Config.QuarantineDigestBaseURL != "https://mail.example.test" {
		t.Fatalf("digest configuration = %+v", updated.Config)
	}
}

func TestPatchAccountRetainedCleanupRoundTripsAndValidates(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := service.Current().Config.AccountRetainedCleanupDays; got != 30 {
		t.Fatalf("default retention = %d, want 30", got)
	}
	updated, err := service.Patch(service.Current().Revision, map[string]any{"account_retained_cleanup_days": int64(45)})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Config.AccountRetainedCleanupDays != 45 {
		t.Fatalf("retention = %d, want 45", updated.Config.AccountRetainedCleanupDays)
	}
	if _, err := service.Patch(updated.Revision, map[string]any{"account_retained_cleanup_days": int64(0)}); err == nil {
		t.Fatal("zero retained cleanup period was accepted")
	}
	reloaded, err := service.Reload()
	if err != nil || reloaded.Config.AccountRetainedCleanupDays != 45 {
		t.Fatalf("reloaded retention = %d, %v", reloaded.Config.AccountRetainedCleanupDays, err)
	}
}

func TestPatchAccountVerificationPolicyRoundTripsAndValidates(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Current()
	updated, err := service.Patch(initial.Revision, map[string]any{
		"account_verification_enabled":        true,
		"account_verification_interval_hours": int64(24),
		"account_verification_workers":        int64(3),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Config.AccountVerificationEnabled || updated.Config.AccountVerificationIntervalHrs != 24 || updated.Config.AccountVerificationWorkers != 3 {
		t.Fatalf("verification policy = enabled %t, interval %d, workers %d", updated.Config.AccountVerificationEnabled, updated.Config.AccountVerificationIntervalHrs, updated.Config.AccountVerificationWorkers)
	}
	for key, value := range map[string]any{"account_verification_interval_hours": int64(0), "account_verification_workers": int64(17)} {
		if _, err := service.Patch(updated.Revision, map[string]any{key: value}); err == nil {
			t.Fatalf("invalid %s accepted", key)
		}
	}
	reloaded, err := service.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Config.AccountVerificationEnabled || reloaded.Config.AccountVerificationIntervalHrs != 24 || reloaded.Config.AccountVerificationWorkers != 3 {
		t.Fatalf("reloaded verification policy = %+v", reloaded.Config)
	}
}

func TestAccountStorageRootConfigurationValidation(t *testing.T) {
	cfg := DefaultAt(t.TempDir())
	cfg.AccountStorageRoots = []string{"fast=accounts/fast", "archive=accounts/archive"}
	cfg.PrimaryAccountRoot = "fast"
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.AccountStorageRoots = append(cfg.AccountStorageRoots, "fast=duplicate")
	if err := Validate(cfg); err == nil {
		t.Fatal("duplicate account root was accepted")
	}
	cfg.AccountStorageRoots = []string{"fast=accounts/fast"}
	cfg.PrimaryAccountRoot = "missing"
	if err := Validate(cfg); err == nil {
		t.Fatal("missing primary account root was accepted")
	}
}

func TestMetricsTokenValidationAndRedaction(t *testing.T) {
	for token, valid := range map[string]bool{
		"":                           true,
		"0123456789abcdef":           true,
		"short":                      false,
		"0123456789abcdef with sp":   false,
		"0123456789abcdef\x00ctrl":   false,
		"Zm9vYmFyYmF6cXV4LXNjcmFwZQ": true,
	} {
		cfg := DefaultAt(t.TempDir())
		cfg.MetricsToken = token
		if err := Validate(cfg); (err == nil) != valid {
			t.Errorf("Validate(metrics_token=%q) error = %v, want valid=%v", token, err, valid)
		}
	}
	for _, spec := range buildSchema() {
		if spec.Key == "metrics_token" {
			if !spec.Sensitive {
				t.Fatal("metrics_token is not marked sensitive")
			}
			return
		}
	}
	t.Fatal("metrics_token missing from schema")
}

func TestContentScannerConfigurationValidation(t *testing.T) {
	mutations := map[string]func(*Config){
		"no engines": func(cfg *Config) { cfg.BuiltinScannerEnabled = false },
		"timeout":    func(cfg *Config) { cfg.RspamdTimeoutSeconds = 0 },
		"input":      func(cfg *Config) { cfg.ClamdMaxBytes = 1 },
		"policy":     func(cfg *Config) { cfg.BuiltinScannerFailurePolicy = "ignore" },
		"clamd": func(cfg *Config) {
			cfg.ClamdEnabled = true
			cfg.ClamdSocket = "missing-port"
		},
		"rspamd": func(cfg *Config) {
			cfg.RspamdEnabled = true
			cfg.RspamdEndpoint = "ftp://scanner.example.test"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultAt(t.TempDir())
			mutate(cfg)
			if err := Validate(cfg); err == nil {
				t.Fatal("invalid scanner configuration was accepted")
			}
		})
	}
}

func TestLocalDomainSpoofPolicyConfiguration(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := service.Current()
	if before.Config.LocalDomainSpoofPolicy != "reject" {
		t.Fatalf("default local identity policy = %q", before.Config.LocalDomainSpoofPolicy)
	}
	after, err := service.Patch(before.Revision, map[string]any{"local_domain_spoof_policy": "warn"})
	if err != nil || after.Config.LocalDomainSpoofPolicy != "warn" {
		t.Fatalf("patched local identity policy = %q, %v", after.Config.LocalDomainSpoofPolicy, err)
	}
	if _, err := service.Patch(after.Revision, map[string]any{"local_domain_spoof_policy": "accept"}); err == nil {
		t.Fatal("invalid local identity policy was accepted")
	}
	reloaded, err := service.Reload()
	if err != nil || reloaded.Config.LocalDomainSpoofPolicy != "warn" {
		t.Fatalf("reloaded local identity policy = %q, %v", reloaded.Config.LocalDomainSpoofPolicy, err)
	}
}

func TestPatchContentScannerConfigurationRoundTrips(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := service.Current()
	after, err := service.Patch(before.Revision, map[string]any{
		"rspamd_enabled":         true,
		"rspamd_endpoint":        "https://scanner.example.test/checkv2",
		"rspamd_password":        "secret",
		"rspamd_timeout_seconds": int64(20),
		"rspamd_failure_policy":  "quarantine",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !after.Config.RspamdEnabled || after.Config.RspamdEndpoint != "https://scanner.example.test/checkv2" || after.Config.RspamdPassword != "secret" || after.Config.RspamdTimeoutSeconds != 20 || after.Config.RspamdFailurePolicy != "quarantine" {
		t.Fatalf("scanner configuration = %+v", after.Config)
	}
	reloaded, err := service.Reload()
	if err != nil || reloaded.Config.RspamdPassword != "secret" || !reloaded.Config.RspamdEnabled {
		t.Fatalf("reloaded scanner configuration = %+v, %v", reloaded.Config, err)
	}
}

func TestPatchAccountStorageRoots(t *testing.T) {
	service, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := service.Current()
	after, err := service.Patch(before.Revision, map[string]any{
		"account_storage_roots": []string{"fast=accounts/fast", "archive=accounts/archive"},
		"primary_account_root":  "fast",
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.Config.PrimaryAccountRoot != "fast" || len(after.Config.AccountStorageRoots) != 2 {
		t.Fatalf("account roots = %q, primary = %q", after.Config.AccountStorageRoots, after.Config.PrimaryAccountRoot)
	}
	if _, err := service.Patch(after.Revision, map[string]any{
		"account_storage_roots": []string{"one=accounts", "nested=accounts/nested"},
		"primary_account_root":  "one",
	}); err == nil {
		t.Fatal("overlapping account roots were accepted through patch API")
	}
}

func TestOpenOverlaysDefaultsForMissingKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte("smtp_enabled = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := service.Current().Config
	if cfg.SmtpEnabled || cfg.ListenAddr != "0.0.0.0:8472" {
		t.Fatalf("defaults were not overlaid: smtp=%v listen=%q", cfg.SmtpEnabled, cfg.ListenAddr)
	}
}

func TestValidateDMARCAggregateSettings(t *testing.T) {
	cfg := Default()
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.DmarcAggregateOrganization = ""
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("organization error=%v", err)
	}
	cfg = Default()
	cfg.DmarcAggregateEmail = "Display <report@example.test>"
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("email error=%v", err)
	}
	cfg = Default()
	cfg.DmarcAggregateRetentionDays = 6
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("retention error=%v", err)
	}
}

func TestValidateRejectsServerNamesThatInjectLines(t *testing.T) {
	for _, name := range []string{"mx.example.com\r\nBcc: victim@example.net", "mx example.com", "mx\texample.com"} {
		cfg := Default()
		cfg.SmtpServerName = name
		if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "smtp_server_name") {
			t.Fatalf("%q: error=%v", name, err)
		}
	}
	cfg := Default()
	cfg.RelayServerName = "relay.example.com\n"
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "relay_server_name") {
		t.Fatalf("relay error=%v", err)
	}
}

func TestValidateNoopAndRecoverPrevious(t *testing.T) {
	dir := t.TempDir()
	service, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	initial := service.Current()
	path := filepath.Join(dir, configFileName)
	before, _ := os.ReadFile(path)
	noop, err := service.Patch(initial.Revision, nil)
	if err != nil || noop.Revision != initial.Revision {
		t.Fatalf("no-op patch: snapshot=%+v err=%v", noop, err)
	}
	afterNoop, _ := os.ReadFile(path)
	if string(before) != string(afterNoop) {
		t.Fatal("no-op patch changed bytes")
	}
	validated, err := service.ValidatePatch(initial.Revision, map[string]any{"smtp_max_recipients": float64(333)})
	if err != nil || validated.Config.SmtpMaxRecipients != 333 || service.Current().Config.SmtpMaxRecipients == 333 {
		t.Fatalf("validate patch changed live configuration: validated=%+v err=%v", validated.Config, err)
	}
	changed, err := service.Patch(initial.Revision, map[string]any{"smtp_max_recipients": int64(444)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, previousConfigFileName)); err != nil {
		t.Fatalf("previous revision missing: %v", err)
	}
	recovered, err := service.RecoverPrevious(changed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Config.SmtpMaxRecipients != initial.Config.SmtpMaxRecipients {
		t.Fatalf("recovered max recipients = %d", recovered.Config.SmtpMaxRecipients)
	}
}

func TestOpenRejectsSymlinkedConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(target, []byte("smtp_enabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, configFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Open symlink error = %v", err)
	}
}

// registerNoopAppliers stands in for the runtime owners that register live
// appliers at server startup, so plan and apply-state tests see live keys.
func registerNoopAppliers(t *testing.T, service *Service) {
	t.Helper()
	noop := func(*Config) error { return nil }
	for _, group := range [][]string{
		{"default_account_engine"}, {"account_retained_cleanup_days"},
		{"account_verification_enabled", "account_verification_interval_hours", "account_verification_workers"},
		{"trash_retention_days"}, {"change_history_retention_days", "change_history_max_entries"},
		{"quota_warning_percent", "quota_critical_percent"},
		{"alert_evaluation_seconds", "alert_queue_warning_minutes", "alert_queue_critical_minutes", "alert_webhook_warning_minutes", "alert_webhook_critical_minutes", "alert_storage_warning_free_percent", "alert_storage_critical_free_percent", "alert_certificate_warning_days", "alert_certificate_critical_days", "alert_notifications_enabled"},
		{"log_console_level"}, {"log_file_level"}, {"log_file_retention_days", "log_file_max_files"}, {"log_format"}, {"log_module_levels"}, {"http_trusted_proxies", "http_forwarded_header"}, {"web_two_factor_required"}, {"two_factor_requires_app_passwords"},
	} {
		if err := service.RegisterApplier(noop, group...); err != nil {
			t.Fatal(err)
		}
	}
}
