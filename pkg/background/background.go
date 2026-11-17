// Package background runs long-lived goroutines that stop together, so a
// server can stop every background job before it closes the stores they use.
package background

import (
	"context"
	"sync"
	"time"
)

// Group tracks goroutines that share one context. Stop cancels the context
// and waits for every goroutine to return. The zero Group is not usable; use
// New.
type Group struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mu orders Go against Stop so no goroutine is added once Stop waits.
	mu      sync.Mutex
	stopped bool
}

// New returns a Group whose context derives from parent.
func New(parent context.Context) *Group {
	ctx, cancel := context.WithCancel(parent)
	return &Group{ctx: ctx, cancel: cancel}
}

// Context returns the context the group's goroutines run under. It ends when
// Stop is called.
func (g *Group) Context() context.Context {
	return g.ctx
}

// Go runs fn in a new goroutine with the group's context. After Stop it does
// nothing and reports false.
func (g *Group) Go(fn func(ctx context.Context)) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return false
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		fn(g.ctx)
	}()
	return true
}

// Every runs fn every interval in the group until Stop. When immediate is
// set, fn also runs once at the start.
func (g *Group) Every(interval time.Duration, immediate bool, fn func()) {
	g.Go(func(ctx context.Context) {
		if immediate {
			fn()
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fn()
			}
		}
	})
}

// Stop cancels the group's context and waits for its goroutines to return.
// It is safe to call more than once and concurrently.
func (g *Group) Stop() {
	g.mu.Lock()
	g.stopped = true
	g.cancel()
	g.mu.Unlock()
	g.wg.Wait()
}
