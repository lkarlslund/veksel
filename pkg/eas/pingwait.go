package eas

import (
	"sync"
	"time"
)

// Fallback polls for waiting Ping and Sync requests. With commit
// notifications the poll only covers what no notification reports, such as
// journal expiry; without them it is the only way to see changes.
const (
	notifiedPingPoll   = 60 * time.Second
	unnotifiedPingPoll = 5 * time.Second
)

// pingWaiter is one waiting Ping or Sync request.
type pingWaiter struct {
	device   string
	folders  []string
	accounts []string
	// wake has capacity one, so commits coalesce until the waiter rechecks.
	wake chan struct{}
	// superseded is closed when a newer request from the same device starts
	// waiting.
	superseded chan struct{}
}

// pingWaits indexes waiting requests by watched folder, by the accounts that
// own those folders, and by device, so a commit wakes only the requests
// that watch a changed folder.
type pingWaits struct {
	mu        sync.Mutex
	byFolder  map[string]map[*pingWaiter]struct{}
	byAccount map[string]map[*pingWaiter]struct{}
	byDevice  map[string]*pingWaiter
}

func newPingWaits() *pingWaits {
	return &pingWaits{
		byFolder:  map[string]map[*pingWaiter]struct{}{},
		byAccount: map[string]map[*pingWaiter]struct{}{},
		byDevice:  map[string]*pingWaiter{},
	}
}

// register starts a wait for device on folders, owned by accounts, and
// supersedes the device's previous wait. The caller registers before it
// reads the journal for the last time, so no commit falls between that read
// and the wait, and it must unregister the waiter.
func (p *pingWaits) register(device string, folders, accounts []string) *pingWaiter {
	waiter := &pingWaiter{device: device, folders: folders, accounts: accounts, wake: make(chan struct{}, 1), superseded: make(chan struct{})}
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous := p.byDevice[device]; previous != nil {
		close(previous.superseded)
	}
	p.byDevice[device] = waiter
	for _, folderID := range folders {
		addWaiter(p.byFolder, folderID, waiter)
	}
	for _, accountID := range accounts {
		addWaiter(p.byAccount, accountID, waiter)
	}
	return waiter
}

func (p *pingWaits) unregister(waiter *pingWaiter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byDevice[waiter.device] == waiter {
		delete(p.byDevice, waiter.device)
	}
	for _, folderID := range waiter.folders {
		removeWaiter(p.byFolder, folderID, waiter)
	}
	for _, accountID := range waiter.accounts {
		removeWaiter(p.byAccount, accountID, waiter)
	}
}

// changesCommitted is the service.FolderChangeNotifier listener. It runs on
// the committing goroutine, so it only signals the affected waiters. Without
// folder detail every wait on the account's folders wakes.
func (p *pingWaits) changesCommitted(accountID string, folderIDs []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if folderIDs == nil {
		signalWaiters(p.byAccount[accountID])
		return
	}
	for _, folderID := range folderIDs {
		signalWaiters(p.byFolder[folderID])
	}
}

// waiting reports the number of registered waits.
func (p *pingWaits) waiting() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byDevice)
}

func addWaiter(index map[string]map[*pingWaiter]struct{}, key string, waiter *pingWaiter) {
	if index[key] == nil {
		index[key] = map[*pingWaiter]struct{}{}
	}
	index[key][waiter] = struct{}{}
}

func removeWaiter(index map[string]map[*pingWaiter]struct{}, key string, waiter *pingWaiter) {
	delete(index[key], waiter)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}

func signalWaiters(waiters map[*pingWaiter]struct{}) {
	for waiter := range waiters {
		select {
		case waiter.wake <- struct{}{}:
		default:
		}
	}
}
