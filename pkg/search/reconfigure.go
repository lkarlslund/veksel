package search

import (
	"context"
	"errors"
	"sync"
	"time"
)

// settings returns the current effective search configuration.
func (m *Manager) settings() Config {
	return *m.config.Load()
}

// Reconfigure applies config to the running manager. Worker count, batch
// size, idle close, extraction limit, and query result limits take effect
// for subsequent work; builds already holding a worker finish under the new
// limits as they read them. Disabling cancels background indexing, waits for
// in-flight builds to stop at their next durable checkpoint, and closes open
// indexes, after which queries report search unavailable. Enabling restarts
// the poller and resumes each account from its persisted checkpoint.
func (m *Manager) Reconfigure(config Config) error {
	if err := m.ctx.Err(); err != nil {
		return errors.New("search manager is closed")
	}
	config = config.normalized()
	m.reconfigureMu.Lock()
	defer m.reconfigureMu.Unlock()
	m.workers.resize(config.Workers)
	m.lifecycleMu.Lock()
	previous := *m.config.Load()
	m.config.Store(&config)
	wasEnabled := m.indexCancel != nil
	var stop context.CancelFunc
	switch {
	case config.Enabled && !wasEnabled:
		m.startIndexingLocked()
	case !config.Enabled && wasEnabled:
		stop = m.indexCancel
		m.indexCtx, m.indexCancel = nil, nil
	}
	m.lifecycleMu.Unlock()
	switch {
	case stop != nil:
		stop()
		m.indexWG.Wait()
		m.closeIdle(time.Now())
	case config.Enabled && !wasEnabled:
		m.ensureAllBuilds()
	case config.Enabled && previous.IndexEncryptedAccounts != config.IndexEncryptedAccounts:
		// Drop or build the indexes of encrypted accounts now.
		m.ensureAllBuilds()
	}
	return nil
}

// startIndexingLocked starts the background poller under a fresh indexing
// context. The caller holds lifecycleMu for writing.
func (m *Manager) startIndexingLocked() {
	m.indexCtx, m.indexCancel = context.WithCancel(m.ctx)
	m.indexWG.Add(1)
	m.wg.Add(1)
	go m.poll(m.indexCtx)
}

// beginIndexing registers one indexing goroutine when indexing is enabled.
// The returned done function must be called exactly once when enabled is
// true.
func (m *Manager) beginIndexing() (ctx context.Context, done func(), enabled bool) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.indexCtx == nil {
		return nil, nil, false
	}
	m.indexWG.Add(1)
	m.wg.Add(1)
	return m.indexCtx, func() {
		m.indexWG.Done()
		m.wg.Done()
	}, true
}

func (m *Manager) ensureAllBuilds() {
	for _, entry := range m.accounts.Entries() {
		m.ensureBuild(entry.Manifest.Login)
	}
}

// workerPool is a resizable counting semaphore. Shrinking never interrupts
// holders; waiters keep their place until capacity frees up.
type workerPool struct {
	mu     sync.Mutex
	limit  int
	active int
	wake   chan struct{}
}

func newWorkerPool(limit int) *workerPool {
	return &workerPool{limit: limit, wake: make(chan struct{})}
}

func (p *workerPool) acquire(ctx context.Context) error {
	for {
		p.mu.Lock()
		if p.active < p.limit {
			p.active++
			p.mu.Unlock()
			return nil
		}
		wake := p.wake
		p.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *workerPool) release() {
	p.mu.Lock()
	p.active--
	p.wakeLocked()
	p.mu.Unlock()
}

func (p *workerPool) resize(limit int) {
	p.mu.Lock()
	p.limit = limit
	p.wakeLocked()
	p.mu.Unlock()
}

func (p *workerPool) wakeLocked() {
	close(p.wake)
	p.wake = make(chan struct{})
}
