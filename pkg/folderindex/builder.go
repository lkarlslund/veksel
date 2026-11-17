package folderindex

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// ErrBuilding reports that a projection is missing or stale and is being
// built in the background. Interactive callers answer without it and pick up
// the projection once the build's Ready callback has run.
var ErrBuilding = errors.New("derived index is being built")

// Priority orders queued background builds; lower values run first.
type Priority int

const (
	// PriorityViewed is a folder the user is looking at right now.
	PriorityViewed Priority = iota
	PriorityInbox
	PriorityFavorite
	PriorityFolder
	// PriorityWarm is a speculative warm-up after sign-in or startup.
	PriorityWarm
)

// Build describes a background build an interactive caller may queue.
type Build struct {
	Priority Priority
	// Ready runs on the builder goroutine with the current snapshot, which
	// it must treat as read-only. Waiters are the distinct access contexts
	// whose requests were deferred to this build, first requester first.
	Ready func(folder model.Folder, snapshot *Snapshot, waiters []service.AccessContext)
}

// Builder runs full projection builds on a bounded worker pool, shared by
// every Index attached to it. Queued builds of one folder projection merge;
// the most urgent request's priority wins, and at most one build per account
// runs at a time so a single large mailbox cannot occupy every worker.
type Builder struct {
	ctx     context.Context
	workers int

	mu       sync.Mutex
	idle     *sync.Cond
	queued   map[buildKey]*buildJob
	running  map[buildKey]*buildJob
	owners   map[string]int
	active   int
	sequence uint64
}

type buildKey struct {
	index    *Index
	name     string
	folderID string
}

type buildJob struct {
	key        buildKey
	entry      *entry
	space      service.FolderSpace
	folder     model.Folder
	definition Definition
	priority   Priority
	sequence   uint64
	waiters    []service.AccessContext
	ready      func(model.Folder, *Snapshot, []service.AccessContext)
}

// NewBuilder returns a builder whose builds run until ctx ends. Workers
// start on demand and exit when the queue drains.
func NewBuilder(ctx context.Context, workers int) *Builder {
	b := &Builder{ctx: ctx, workers: max(1, workers), queued: make(map[buildKey]*buildJob), running: make(map[buildKey]*buildJob), owners: make(map[string]int)}
	b.idle = sync.NewCond(&b.mu)
	return b
}

// SetBuilder lets interactive queries defer full rebuilds to builder.
func (i *Index) SetBuilder(builder *Builder) {
	if i != nil {
		i.builder.Store(builder)
	}
}

// Schedule queues a build of folder's projection, which also catches up or
// merely verifies a current one. It is how callers warm projections ahead of
// the first interactive query.
func (i *Index) Schedule(space service.FolderSpace, access service.AccessContext, folder model.Folder, definition Definition, build Build) error {
	builder := i.builder.Load()
	if builder == nil {
		return errors.New("folder derived index has no background builder")
	}
	if !folder.HasIndex(definition.Name(), definition.Version()) {
		return fmt.Errorf("%w: %s", ErrIndexNotAttached, definition.Name())
	}
	builder.enqueue(i, i.entry(definition.Name(), folder.ID), space, access, folder, definition, build, false)
	return nil
}

// enqueue queues or joins a build. stale marks a caller that found the
// projection unusable: interactive queries then defer to the build instead of
// waiting for its entry lock.
func (b *Builder) enqueue(index *Index, e *entry, space service.FolderSpace, access service.AccessContext, folder model.Folder, definition Definition, build Build, stale bool) {
	key := buildKey{index: index, name: definition.Name(), folderID: folder.ID}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx.Err() != nil {
		return
	}
	if stale {
		e.pending.Store(true)
	}
	if job := b.running[key]; job != nil {
		job.addWaiter(access)
		return
	}
	if job := b.queued[key]; job != nil {
		job.priority = min(job.priority, build.Priority)
		job.addWaiter(access)
		if job.ready == nil {
			job.ready = build.Ready
		}
		return
	}
	b.sequence++
	b.queued[key] = &buildJob{key: key, entry: e, space: space, folder: folder, definition: definition, priority: build.Priority, sequence: b.sequence, waiters: []service.AccessContext{access}, ready: build.Ready}
	if b.active < b.workers {
		b.active++
		go b.work()
	}
}

func (j *buildJob) addWaiter(access service.AccessContext) {
	for _, waiter := range j.waiters {
		if waiter.Actor == access.Actor && waiter.Subject == access.Subject {
			return
		}
	}
	j.waiters = append(j.waiters, access)
}

// next takes the most urgent queued build whose account has no build
// running. Called with b.mu held.
func (b *Builder) next() *buildJob {
	var best *buildJob
	for _, job := range b.queued {
		if b.owners[job.folder.UserID] > 0 {
			continue
		}
		if best == nil || job.priority < best.priority || job.priority == best.priority && job.sequence < best.sequence {
			best = job
		}
	}
	if best != nil {
		delete(b.queued, best.key)
		b.running[best.key] = best
		b.owners[best.folder.UserID]++
	}
	return best
}

func (b *Builder) work() {
	for {
		b.mu.Lock()
		var job *buildJob
		if b.ctx.Err() == nil {
			job = b.next()
		}
		if job == nil {
			// Builds still queued belong to accounts another worker is
			// building; that worker takes them next.
			b.active--
			if b.active == 0 {
				b.idle.Broadcast()
			}
			b.mu.Unlock()
			return
		}
		b.mu.Unlock()
		b.run(job)
		b.mu.Lock()
		delete(b.running, job.key)
		b.owners[job.folder.UserID]--
		if b.owners[job.folder.UserID] == 0 {
			delete(b.owners, job.folder.UserID)
		}
		b.mu.Unlock()
	}
}

func (b *Builder) run(job *buildJob) {
	b.mu.Lock()
	access := job.waiters[0]
	b.mu.Unlock()
	// The queued folder generation may be old by now.
	folder, err := job.space.GetFolder(b.ctx, access, job.folder.ID)
	if err == nil {
		err = job.key.index.withSnapshot(b.ctx, job.space, access, folder, job.definition, nil, func(snapshot *Snapshot) error {
			// Clear pending before announcing readiness, so a client reacting
			// to the announcement finds the projection instead of ErrBuilding.
			job.entry.pending.Store(false)
			if job.ready != nil {
				b.mu.Lock()
				waiters := append([]service.AccessContext(nil), job.waiters...)
				b.mu.Unlock()
				job.ready(folder, snapshot, waiters)
			}
			return nil
		})
	}
	job.entry.pending.Store(false)
	if err != nil && b.ctx.Err() == nil {
		log.Warn("background folder index build failed", "index", job.definition.Name(), "folder_id", job.folder.ID, "error", err)
	}
}

// Wait blocks until no build is queued or running.
func (b *Builder) Wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.active > 0 {
		b.idle.Wait()
	}
}
