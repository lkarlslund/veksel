package alertnotify

import (
	"context"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestQuotaWarningsFireOncePerCrossingAndReset(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err := backend.CreateNamespace(t.Context(), model.NSHealthAlerts); err != nil {
		t.Fatal(err)
	}
	accounts := []string{"alice", "bob"}
	used := map[string]int64{"alice": 50, "bob": 10}
	var subjects, recipients []string
	watcher, err := NewQuotaWatcher(backend, QuotaSource{
		Accounts: func(context.Context) ([]string, error) { return accounts, nil },
		Limited:  func(_ context.Context, account string) (bool, error) { return account == "alice", nil },
		Usage: func(_ context.Context, account string) (service.AccountUsage, error) {
			return service.AccountUsage{AccountID: account, AccountingReady: true, LogicalBytes: used[account], Quota: model.QuotaInfo{MaxStorageBytes: 100}}, nil
		},
		Recipient: func(_ context.Context, account string) (string, error) { return account + "@example.com", nil },
	}, func(_ context.Context, recipient string, message Message) error {
		recipients, subjects = append(recipients, recipient), append(subjects, message.Subject)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := service.QuotaPolicy{WarningPercent: 80, CriticalPercent: 95}
	scan := func(percent int64, notify bool) QuotaScan {
		t.Helper()
		used["alice"] = percent
		result, err := watcher.Scan(t.Context(), policy, notify)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if observation := watcher.Observation(); observation.State != health.StateHealthy || observation.Details["scan"] != "pending" {
		t.Fatalf("observation before first scan = %#v", observation)
	}
	scan(50, true)
	scan(85, false) // warnings disabled: nothing sent, state untouched
	if len(subjects) != 0 {
		t.Fatalf("unexpected warnings %v", subjects)
	}
	if result := scan(85, true); result.Notified != 1 || result.Checked != 1 {
		t.Fatalf("warning scan = %#v", result)
	}
	scan(88, true)
	scan(96, true)
	result := scan(100, true)
	if len(result.Exceeded) != 1 || result.Exceeded[0] != "alice" {
		t.Fatalf("exceeded scan = %#v", result)
	}
	if observation := watcher.Observation(); observation.State != health.StateDegraded || observation.Details["exceeded_accounts"] != "alice" {
		t.Fatalf("exceeded observation = %#v", observation)
	}
	want := []string{"getting full (85.0%)", "almost full (96.0%)", "is full (100.0%)"}
	if len(subjects) != len(want) {
		t.Fatalf("subjects = %v", subjects)
	}
	for index, fragment := range want {
		if !strings.Contains(subjects[index], fragment) || recipients[index] != "alice@example.com" {
			t.Fatalf("warning %d = %q to %q", index, subjects[index], recipients[index])
		}
	}
	// Falling to critical lowers the level silently; crossing back warns.
	scan(96, true)
	scan(100, true)
	scan(40, true)
	if observation := watcher.Observation(); observation.State != health.StateHealthy {
		t.Fatalf("recovered observation = %#v", observation)
	}
	scan(85, true)
	if len(subjects) != 5 || !strings.Contains(subjects[3], "is full") || !strings.Contains(subjects[4], "getting full") {
		t.Fatalf("re-crossing subjects = %v", subjects)
	}

	// A watcher over the same backend (a restart) does not repeat warnings,
	// and state of removed accounts is pruned.
	restarted, err := NewQuotaWatcher(backend, watcher.source, watcher.mail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Scan(t.Context(), policy, true); err != nil || len(subjects) != 5 {
		t.Fatalf("restart scan err=%v subjects=%v", err, subjects)
	}
	accounts = []string{"bob"}
	if _, err := restarted.Scan(t.Context(), policy, true); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Get(t.Context(), model.NSHealthAlerts, quotaStatePrefix+"alice"); err == nil {
		t.Fatal("removed account warning state was not pruned")
	}
}
