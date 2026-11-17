package app

import (
	"context"
	"errors"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/migration"
)

// StartSyncScheduler runs persisted sync jobs on the handler's background
// group until it stops.
func (h *Handler) StartSyncScheduler() {
	h.background.Every(time.Minute, true, func() {
		h.runScheduledSyncs(h.background.Context(), time.Now().UTC())
	})
}

func (h *Handler) runScheduledSyncs(ctx context.Context, now time.Time) {
	jobs, err := h.migrationJobs.List(ctx, "")
	if err != nil {
		return
	}
	for _, job := range jobs {
		resumeInterrupted := job.State == migration.StateInterrupted
		interval := job.Schedule.Interval()
		if !job.CredentialStored {
			continue
		}
		if !resumeInterrupted {
			if interval == 0 {
				continue
			}
			if job.NextRunAt.IsZero() {
				job.NextRunAt = now.Add(interval)
				_ = h.migrationJobs.Save(ctx, job)
				continue
			}
			if now.Before(job.NextRunAt) || job.State == migration.StateRunning {
				continue
			}
		}
		job, err = h.migrationJobs.PrepareRun(ctx, job)
		if err != nil {
			continue
		}
		password, err := h.migrationJobs.Credential(ctx, job.ID)
		if err != nil {
			job.State = migration.StateCredentialsRequired
			job.CredentialStored = false
			job.LastError = "stored sync credential is unavailable; password is required to resume"
			job.NextRunAt = time.Time{}
			_ = h.migrationJobs.Save(ctx, job)
			continue
		}
		factory := h.migrationSources[job.SourceType]
		if factory == nil {
			_, _ = h.migrationJobs.RecordFatalAttempt(ctx, job.ID, errors.New("sync source is unavailable in this build"), migration.FailureContext{Phase: migration.FailurePhaseConnect})
			continue
		}
		job.LastRunAt = now
		job.LastError = ""
		if interval > 0 {
			job.NextRunAt = now.Add(interval)
		}
		if err := h.migrationJobs.Save(ctx, job); err != nil {
			continue
		}
		source, err := factory(ctx, job.Connection.SourceOptions(password))
		if err != nil {
			_, _ = h.migrationJobs.RecordFatalAttempt(ctx, job.ID, err, migration.FailureContext{Phase: migration.FailurePhaseConnect})
			continue
		}
		h.publishSyncStarted(job)
		h.runSync(job, source)
	}
}

// runSync runs one sync job on the background group and publishes its
// outcome. Stopping the group cancels the run, which keeps its checkpoint and
// resumes after restart.
func (h *Handler) runSync(job migration.Job, source migration.Source) {
	if !h.background.Go(func(ctx context.Context) {
		err := h.migrationRunner.Run(ctx, job.ID, source)
		eventType := h.syncRunEventType(context.WithoutCancel(ctx), job.ID, err)
		h.events.Publish(events.Event{Type: eventType, Resource: job.ID, Recipients: []string{job.OwnerID}})
	}) {
		_ = source.Close()
	}
}
