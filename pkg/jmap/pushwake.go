package jmap

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"
)

const (
	// notifiedPushInterval is the fallback poll of push loops when commit
	// notifications wake them; it covers what no notification reports, such
	// as an account newly shared with the user.
	notifiedPushInterval = 60 * time.Second
	// pushSettle coalesces a burst of commits into one state check, which
	// lists every folder of the user's accounts.
	pushSettle = 100 * time.Millisecond
)

// pushWakes wakes push loops when a journal they report on advances.
type pushWakes struct {
	mu        sync.Mutex
	byAccount map[string]map[*pushWatcher]struct{}
}

// changesCommitted is the service.FolderChangeNotifier listener. It runs on
// the committing goroutine, so it only signals the account's watchers.
func (w *pushWakes) changesCommitted(accountID string, _ []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for watcher := range w.byAccount[accountID] {
		select {
		case watcher.wake <- struct{}{}:
		default:
		}
	}
}

// pushWatcher is one push loop's subscription to the accounts it reports.
type pushWatcher struct {
	wakes    *pushWakes
	accounts []string
	// wake has capacity one, so commits coalesce until the loop checks; it
	// is nil when the folder space sends no notifications.
	wake chan struct{}
}

func (h *Handler) newPushWatcher() *pushWatcher {
	if h.wakes == nil {
		return &pushWatcher{}
	}
	return &pushWatcher{wakes: h.wakes, wake: make(chan struct{}, 1)}
}

// follow watches the accounts the tracker reports on. Call it after each
// state check, as the user's accounts can change.
func (p *pushWatcher) follow(tracker *pushTracker) {
	if p.wakes == nil {
		return
	}
	accounts := slices.Sorted(maps.Keys(tracker.last))
	if slices.Equal(accounts, p.accounts) {
		return
	}
	p.wakes.mu.Lock()
	defer p.wakes.mu.Unlock()
	p.removeLocked()
	p.accounts = accounts
	for _, accountID := range accounts {
		if p.wakes.byAccount[accountID] == nil {
			p.wakes.byAccount[accountID] = map[*pushWatcher]struct{}{}
		}
		p.wakes.byAccount[accountID][p] = struct{}{}
	}
}

func (p *pushWatcher) close() {
	if p.wakes == nil {
		return
	}
	p.wakes.mu.Lock()
	defer p.wakes.mu.Unlock()
	p.removeLocked()
	p.accounts = nil
}

func (p *pushWatcher) removeLocked() {
	for _, accountID := range p.accounts {
		delete(p.wakes.byAccount[accountID], p)
		if len(p.wakes.byAccount[accountID]) == 0 {
			delete(p.wakes.byAccount, accountID)
		}
	}
}

// settle waits pushSettle after a wake so a burst of commits costs one state
// check, then consumes the wakes the burst left. It reports false when ctx
// ends first.
func (p *pushWatcher) settle(ctx context.Context) bool {
	timer := time.NewTimer(pushSettle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
	}
	select {
	case <-p.wake:
	default:
	}
	return true
}
