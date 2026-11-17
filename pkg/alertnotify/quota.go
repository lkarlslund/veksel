package alertnotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	quotaStatePrefix       = "quota:"
	quotaComponentID       = "account-quota"
	maxQuotaDetailAccounts = 10
)

// Quota warning levels, ordered by pressure.
const (
	quotaLevelNone = iota
	quotaLevelWarning
	quotaLevelCritical
	quotaLevelExceeded
)

// QuotaSource supplies the accounts a scan inspects. Accounts lists account
// IDs; Usage returns metadata-only usage for one account (accounts without a
// quota limit should be skipped cheaply by the caller via Limited); Recipient
// resolves the address a warning is delivered to.
type QuotaSource struct {
	Accounts  func(ctx context.Context) ([]string, error)
	Limited   func(ctx context.Context, account string) (bool, error)
	Usage     func(ctx context.Context, account string) (service.AccountUsage, error)
	Recipient func(ctx context.Context, account string) (string, error)
}

// QuotaScan summarizes one pass.
type QuotaScan struct {
	At       time.Time `json:"at"`
	Checked  int       `json:"checked"`
	Notified int       `json:"notified"`
	Exceeded []string  `json:"exceeded"`
	Errors   int       `json:"errors"`
}

// QuotaWatcher sends a user one warning per upward threshold crossing and
// reports accounts at or above their full quota to the health registry. The
// last warned level is durable per account and drops with usage, so a later
// crossing warns again.
type QuotaWatcher struct {
	backend store.Store
	source  QuotaSource
	mail    func(ctx context.Context, recipient string, message Message) error
	now     func() time.Time

	run  sync.Mutex
	mu   sync.Mutex
	last QuotaScan
	done bool
}

type quotaState struct {
	Level      int       `json:"level"`
	Percent    float64   `json:"percent"`
	NotifiedAt time.Time `json:"notified_at,omitzero"`
}

// NewQuotaWatcher creates a watcher that keeps its per-account state in the
// health-alert namespace of backend.
func NewQuotaWatcher(backend store.Store, source QuotaSource, mail func(context.Context, string, Message) error) (*QuotaWatcher, error) {
	if backend == nil || source.Accounts == nil || source.Usage == nil {
		return nil, errors.New("quota watcher requires a backend, an account list, and usage")
	}
	return &QuotaWatcher{backend: backend, source: source, mail: mail, now: func() time.Time { return time.Now().UTC() }}, nil
}

func quotaLevel(state string) (int, bool) {
	switch state {
	case service.QuotaPressureUnlimited, service.QuotaPressureNormal:
		return quotaLevelNone, true
	case service.QuotaPressureWarning:
		return quotaLevelWarning, true
	case service.QuotaPressureCritical:
		return quotaLevelCritical, true
	case service.QuotaPressureExceeded:
		return quotaLevelExceeded, true
	default:
		return 0, false
	}
}

// Scan classifies every limited account once. With notify unset, warning
// state is left untouched so enabling warnings later still reaches accounts
// already above a threshold.
func (w *QuotaWatcher) Scan(ctx context.Context, policy service.QuotaPolicy, notify bool) (QuotaScan, error) {
	w.run.Lock()
	defer w.run.Unlock()
	now := w.now()
	scan := QuotaScan{At: now, Exceeded: []string{}}
	accounts, err := w.source.Accounts(ctx)
	if err != nil {
		return scan, err
	}
	present := make(map[string]bool, len(accounts))
	var errs []error
	for _, account := range accounts {
		if ctx.Err() != nil {
			return scan, ctx.Err()
		}
		present[account] = true
		if w.source.Limited != nil {
			limited, limitErr := w.source.Limited(ctx, account)
			if limitErr != nil || !limited {
				if limitErr == nil && notify {
					errs = append(errs, w.resetState(ctx, account))
				}
				continue
			}
		}
		usage, usageErr := w.source.Usage(ctx, account)
		if usageErr != nil {
			scan.Errors++
			continue
		}
		scan.Checked++
		status := policy.Classify(usage)
		level, known := quotaLevel(status.State)
		if !known {
			continue
		}
		if level == quotaLevelExceeded {
			scan.Exceeded = append(scan.Exceeded, account)
		}
		if !notify {
			continue
		}
		sent, stateErr := w.reconcile(ctx, account, level, status, now)
		if stateErr != nil {
			scan.Errors++
			errs = append(errs, fmt.Errorf("quota warning for %s: %w", account, stateErr))
		}
		if sent {
			scan.Notified++
		}
	}
	errs = append(errs, w.prune(ctx, present))
	w.mu.Lock()
	w.last, w.done = scan, true
	w.mu.Unlock()
	return scan, errors.Join(errs...)
}

// reconcile warns once when usage rises above the last warned level and
// lowers the level silently when usage falls.
func (w *QuotaWatcher) reconcile(ctx context.Context, account string, level int, status service.QuotaStatus, now time.Time) (bool, error) {
	state, err := w.state(ctx, account)
	if err != nil {
		return false, err
	}
	switch {
	case level == state.Level:
		return false, nil
	case level < state.Level:
		if level == quotaLevelNone {
			return false, w.resetState(ctx, account)
		}
		return false, w.setState(ctx, account, quotaState{Level: level, Percent: status.Percent, NotifiedAt: state.NotifiedAt})
	}
	if w.mail == nil || w.source.Recipient == nil {
		return false, errors.New("quota warning mail is unavailable")
	}
	recipient, err := w.source.Recipient(ctx, account)
	if err != nil {
		return false, fmt.Errorf("resolve recipient: %w", err)
	}
	if err := w.mail(ctx, recipient, quotaMessage(account, level, status, now)); err != nil {
		return false, err
	}
	return true, w.setState(ctx, account, quotaState{Level: level, Percent: status.Percent, NotifiedAt: now})
}

func quotaMessage(account string, level int, status service.QuotaStatus, now time.Time) Message {
	percent := strconv.FormatFloat(status.Percent, 'f', 1, 64)
	subject, advice := "", ""
	switch level {
	case quotaLevelExceeded:
		subject = "Your mailbox is full"
		advice = "New messages may be rejected until you delete or archive mail and empty the trash."
	case quotaLevelCritical:
		subject = "Your mailbox is almost full"
		advice = "Delete or archive mail and empty the trash soon to keep receiving messages."
	default:
		subject = "Your mailbox is getting full"
		advice = "Consider deleting or archiving mail you no longer need."
	}
	text := &strings.Builder{}
	fmt.Fprintf(text, "Your mailbox (%s) is using %s%% of its quota.\r\n\r\n%s\r\n", account, percent, advice)
	if status.StorageLimited {
		fmt.Fprintf(text, "\r\nStorage: %s%% used\r\n", strconv.FormatFloat(status.StoragePercent, 'f', 1, 64))
	}
	if status.ItemsLimited {
		fmt.Fprintf(text, "Items: %s%% used\r\n", strconv.FormatFloat(status.ItemsPercent, 'f', 1, 64))
	}
	text.WriteString("\r\nThis message was sent automatically by Veksel.\r\n")
	return Message{
		ID: "quota-" + account + "-" + strconv.Itoa(level) + "-" + now.UTC().Format("20060102T150405"), Event: "quota.warning",
		Subject: subject + " (" + percent + "%)", Text: text.String(), Severity: health.SeverityWarning, At: now,
		Payload: map[string]any{"account_id": account, "percent": status.Percent, "level": level},
	}
}

func (w *QuotaWatcher) state(ctx context.Context, account string) (quotaState, error) {
	encoded, err := w.backend.Get(ctx, model.NSHealthAlerts, quotaStatePrefix+account)
	if errors.Is(err, store.ErrNotFound) {
		return quotaState{}, nil
	}
	if err != nil {
		return quotaState{}, err
	}
	var state quotaState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return quotaState{}, fmt.Errorf("decode quota warning state: %w", err)
	}
	return state, nil
}

func (w *QuotaWatcher) setState(ctx context.Context, account string, state quotaState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return w.backend.Set(ctx, model.NSHealthAlerts, quotaStatePrefix+account, encoded)
}

func (w *QuotaWatcher) resetState(ctx context.Context, account string) error {
	if err := w.backend.Delete(ctx, model.NSHealthAlerts, quotaStatePrefix+account); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// prune drops warning state of accounts that no longer exist.
func (w *QuotaWatcher) prune(ctx context.Context, present map[string]bool) error {
	var stale []string
	if err := w.backend.Iterate(ctx, model.NSHealthAlerts, quotaStatePrefix, func(key string, _ []byte) (bool, error) {
		if account := strings.TrimPrefix(key, quotaStatePrefix); !present[account] {
			stale = append(stale, account)
		}
		return true, nil
	}); err != nil {
		return err
	}
	var errs []error
	for _, account := range stale {
		errs = append(errs, w.resetState(ctx, account))
	}
	return errors.Join(errs...)
}

// Observation reports accounts at or above their full quota as a degraded
// component so the alert lifecycle raises and resolves an operator alert.
func (w *QuotaWatcher) Observation() health.Observation {
	observation := health.Observation{ID: quotaComponentID, Label: "Account quotas", Kind: "quota", Desired: true, State: health.StateHealthy}
	w.mu.Lock()
	scan, done := w.last, w.done
	w.mu.Unlock()
	if !done {
		observation.Details = map[string]string{"scan": "pending"}
		return observation
	}
	observation.Details = map[string]string{"checked_accounts": strconv.Itoa(scan.Checked), "scanned_at": scan.At.Format(time.RFC3339)}
	if len(scan.Exceeded) > 0 {
		accounts := slices.Clone(scan.Exceeded)
		slices.Sort(accounts)
		if len(accounts) > maxQuotaDetailAccounts {
			accounts = append(accounts[:maxQuotaDetailAccounts], "…")
		}
		observation.State, observation.Severity = health.StateDegraded, health.SeverityWarning
		observation.Reason = fmt.Sprintf("%d account(s) at or above 100%% of quota", len(scan.Exceeded))
		observation.Details["exceeded_accounts"] = strings.Join(accounts, ", ")
	}
	return observation
}
