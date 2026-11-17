package virus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/mailidentity"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	QuarantineDigestOff    = "off"
	QuarantineDigestDaily  = "daily"
	QuarantineDigestWeekly = "weekly"

	quarantineDigestPending   = "pending"
	quarantineDigestSending   = "sending"
	quarantineDigestSent      = "sent"
	quarantineDigestFailed    = "failed"
	quarantineDigestCancelled = "cancelled"
	quarantineDigestLease     = 5 * time.Minute
)

// QuarantineDigestPreference is a per-user, UTC-based opt-in schedule.
// Weekday follows time.Weekday (Sunday=0). It is ignored for daily schedules.
type QuarantineDigestPreference struct {
	UserID       string    `json:"user_id"`
	Schedule     string    `json:"schedule"`
	HourUTC      int       `json:"hour_utc"`
	Weekday      int       `json:"weekday"`
	NextRunAt    time.Time `json:"next_run_at,omitzero"`
	LastRunAt    time.Time `json:"last_run_at,omitzero"`
	LastSentAt   time.Time `json:"last_sent_at,omitzero"`
	PendingJobID string    `json:"pending_job_id,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (p QuarantineDigestPreference) Validate() error {
	if strings.TrimSpace(p.UserID) == "" {
		return errors.New("digest user is required")
	}
	if p.Schedule != QuarantineDigestOff && p.Schedule != QuarantineDigestDaily && p.Schedule != QuarantineDigestWeekly {
		return errors.New("digest schedule must be off, daily, or weekly")
	}
	if p.HourUTC < 0 || p.HourUTC > 23 || p.Weekday < 0 || p.Weekday > 6 {
		return errors.New("digest hour must be 0-23 and weekday 0-6")
	}
	return nil
}

type QuarantineDigestJob struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	Recipient     string    `json:"recipient"`
	ScheduledFor  time.Time `json:"scheduled_for"`
	EntryCount    int       `json:"entry_count"`
	Truncated     bool      `json:"truncated"`
	FullMessage   []byte    `json:"full_message,omitempty"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`
	LeaseToken    string    `json:"lease_token,omitempty"`
	LeaseAt       time.Time `json:"lease_at,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	CompletedAt   time.Time `json:"completed_at,omitzero"`
}

type QuarantineDigestConfig struct {
	BaseURL       string
	FromAddress   string
	MaxEntries    int
	MaxJobsPerRun int
	MaxAttempts   int
	RetryBase     time.Duration
	JobRetention  time.Duration
}

func (c QuarantineDigestConfig) Validate() error {
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" && base.Path != "/" || base.Scheme != "https" && !(base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1" || base.Hostname() == "::1")) {
		return errors.New("digest base URL must be an HTTPS origin (HTTP is allowed only for loopback)")
	}
	address, err := mail.ParseAddress(c.FromAddress)
	if err != nil || address.Address == "" {
		return errors.New("digest sender must be a valid email address")
	}
	if c.MaxEntries < 1 || c.MaxEntries > 1000 || c.MaxJobsPerRun < 1 || c.MaxJobsPerRun > 10000 || c.MaxAttempts < 1 || c.MaxAttempts > 100 || c.RetryBase < time.Second || c.RetryBase > 24*time.Hour || c.JobRetention < 24*time.Hour {
		return errors.New("digest limits, retry delay, or retention are invalid")
	}
	return nil
}

type QuarantineDigestRecipientResolver func(context.Context, string) (address string, err error)
type QuarantineDigestSender func(context.Context, QuarantineDigestJob) error

type QuarantineDigestRun struct {
	Prepared int `json:"prepared"`
	Empty    int `json:"empty"`
	Sent     int `json:"sent"`
	Retried  int `json:"retried"`
	Failed   int `json:"failed"`
}

type QuarantineDigestService struct {
	ts         *model.TypedStore
	quarantine *QuarantineStore
	actions    *QuarantineActionService
	resolve    QuarantineDigestRecipientResolver
	config     atomic.Pointer[QuarantineDigestConfig]
	now        func() time.Time
}

func quarantineDigestPreferencePrefix() string { return "quarantine-digest-pref:" }
func quarantineDigestPreferenceKey(userID string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(userID))))
	return quarantineDigestPreferencePrefix() + hex.EncodeToString(digest[:])
}
func quarantineDigestJobPrefix() string       { return "quarantine-digest-job:" }
func quarantineDigestJobKey(id string) string { return quarantineDigestJobPrefix() + id }

func NewQuarantineDigestService(ts *model.TypedStore, quarantine *QuarantineStore, actions *QuarantineActionService, resolve QuarantineDigestRecipientResolver, config QuarantineDigestConfig) (*QuarantineDigestService, error) {
	if ts == nil || quarantine == nil || actions == nil || resolve == nil {
		return nil, errors.New("digest store, quarantine, action service, and recipient resolver are required")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	service := &QuarantineDigestService{ts: ts, quarantine: quarantine, actions: actions, resolve: resolve, now: time.Now}
	service.config.Store(&config)
	return service, nil
}

func (s *QuarantineDigestService) currentConfig() QuarantineDigestConfig { return *s.config.Load() }

// SetConfig replaces the digest settings; the next scheduler pass and the
// next digest built use them.
func (s *QuarantineDigestService) SetConfig(config QuarantineDigestConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	s.config.Store(&config)
	return nil
}

func nextQuarantineDigestRun(after time.Time, schedule string, hourUTC, weekday int) time.Time {
	after = after.UTC()
	candidate := time.Date(after.Year(), after.Month(), after.Day(), hourUTC, 0, 0, 0, time.UTC)
	if schedule == QuarantineDigestDaily {
		if !candidate.After(after) {
			candidate = candidate.AddDate(0, 0, 1)
		}
		return candidate
	}
	days := (weekday - int(candidate.Weekday()) + 7) % 7
	candidate = candidate.AddDate(0, 0, days)
	if !candidate.After(after) {
		candidate = candidate.AddDate(0, 0, 7)
	}
	return candidate
}

func (s *QuarantineDigestService) GetPreference(ctx context.Context, userID string) (QuarantineDigestPreference, error) {
	var preference QuarantineDigestPreference
	if err := s.ts.Get(ctx, model.NSMetadata, quarantineDigestPreferenceKey(userID), &preference); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return QuarantineDigestPreference{UserID: strings.ToLower(strings.TrimSpace(userID)), Schedule: QuarantineDigestOff, HourUTC: 8, Weekday: int(time.Monday)}, nil
		}
		return QuarantineDigestPreference{}, err
	}
	return preference, nil
}

func (s *QuarantineDigestService) SetPreference(ctx context.Context, preference QuarantineDigestPreference) (QuarantineDigestPreference, error) {
	preference.UserID = strings.ToLower(strings.TrimSpace(preference.UserID))
	if err := preference.Validate(); err != nil {
		return QuarantineDigestPreference{}, err
	}
	now := s.now().UTC()
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		current, err := s.GetPreference(batchCtx, preference.UserID)
		if err != nil {
			return err
		}
		if current.PendingJobID != "" {
			var job QuarantineDigestJob
			if err := s.ts.Get(batchCtx, model.NSMetadata, quarantineDigestJobKey(current.PendingJobID), &job); err == nil && job.Status != quarantineDigestSent && job.Status != quarantineDigestFailed {
				job.Status, job.UpdatedAt, job.CompletedAt = quarantineDigestCancelled, now, now
				job.FullMessage = nil
				if err := s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestJobKey(job.ID), job); err != nil {
					return err
				}
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		preference.LastRunAt, preference.LastSentAt = current.LastRunAt, current.LastSentAt
		preference.PendingJobID = ""
		if preference.Schedule == QuarantineDigestOff {
			preference.NextRunAt = time.Time{}
		} else {
			preference.NextRunAt = nextQuarantineDigestRun(now, preference.Schedule, preference.HourUTC, preference.Weekday)
		}
		preference.UpdatedAt = now
		return s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestPreferenceKey(preference.UserID), preference)
	})
	return preference, err
}

func (s *QuarantineDigestService) ListPreferences(ctx context.Context) ([]QuarantineDigestPreference, error) {
	keys, err := s.ts.Scan(ctx, model.NSMetadata, quarantineDigestPreferencePrefix())
	if err != nil {
		return nil, err
	}
	preferences := make([]QuarantineDigestPreference, 0, len(keys))
	for _, key := range keys {
		var preference QuarantineDigestPreference
		if err := s.ts.Get(ctx, model.NSMetadata, key, &preference); err != nil {
			return nil, err
		}
		preferences = append(preferences, preference)
	}
	sort.Slice(preferences, func(i, j int) bool { return preferences[i].NextRunAt.Before(preferences[j].NextRunAt) })
	return preferences, nil
}

func (s *QuarantineDigestService) Run(ctx context.Context, sender QuarantineDigestSender) (QuarantineDigestRun, error) {
	if sender == nil {
		return QuarantineDigestRun{}, errors.New("digest sender is required")
	}
	now := s.now().UTC()
	result, err := s.prepareDue(ctx, now)
	if err != nil {
		return result, err
	}
	jobs, err := s.ListJobs(ctx)
	if err != nil {
		return result, err
	}
	processed := 0
	for _, job := range jobs {
		if processed >= s.currentConfig().MaxJobsPerRun || job.Status != quarantineDigestPending && !(job.Status == quarantineDigestSending && job.LeaseAt.Add(quarantineDigestLease).Before(now)) || job.NextAttemptAt.After(now) {
			continue
		}
		processed++
		outcome, err := s.deliverJob(ctx, job.ID, sender, now)
		if err != nil {
			return result, err
		}
		switch outcome {
		case quarantineDigestSent:
			result.Sent++
		case quarantineDigestFailed:
			result.Failed++
		case quarantineDigestPending:
			result.Retried++
		}
	}
	return result, nil
}

func (s *QuarantineDigestService) prepareDue(ctx context.Context, now time.Time) (QuarantineDigestRun, error) {
	preferences, err := s.ListPreferences(ctx)
	if err != nil {
		return QuarantineDigestRun{}, err
	}
	var result QuarantineDigestRun
	for _, preference := range preferences {
		if result.Prepared+result.Empty >= s.currentConfig().MaxJobsPerRun || preference.Schedule == QuarantineDigestOff || preference.NextRunAt.IsZero() || preference.NextRunAt.After(now) || preference.PendingJobID != "" {
			continue
		}
		prepared, empty, err := s.preparePreference(ctx, preference.UserID, now)
		if err != nil {
			return result, err
		}
		if prepared {
			result.Prepared++
		}
		if empty {
			result.Empty++
		}
	}
	return result, nil
}

func (s *QuarantineDigestService) preparePreference(ctx context.Context, userID string, now time.Time) (prepared, empty bool, retErr error) {
	recipient, err := s.resolve(ctx, userID)
	if err != nil {
		return false, false, fmt.Errorf("resolve digest recipient %s: %w", userID, err)
	}
	parsedRecipient, err := mail.ParseAddress(recipient)
	if err != nil || parsedRecipient.Address == "" {
		return false, false, fmt.Errorf("resolve digest recipient %s: invalid email address", userID)
	}
	recipient = parsedRecipient.Address
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		preference, err := s.GetPreference(batchCtx, userID)
		if err != nil {
			return err
		}
		if preference.Schedule == QuarantineDigestOff || preference.PendingJobID != "" || preference.NextRunAt.IsZero() || preference.NextRunAt.After(now) {
			return nil
		}
		scheduledFor := preference.NextRunAt
		preference.LastRunAt = now
		preference.NextRunAt = nextQuarantineDigestRun(scheduledFor, preference.Schedule, preference.HourUTC, preference.Weekday)
		entries, err := s.quarantine.ListForOwner(batchCtx, userID)
		if err != nil {
			return err
		}
		live := entries[:0]
		for _, entry := range entries {
			if entry.ExpiresAt.IsZero() || entry.ExpiresAt.After(now) {
				live = append(live, entry)
			}
		}
		if len(live) == 0 {
			preference.UpdatedAt = now
			empty = true
			return s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestPreferenceKey(userID), preference)
		}
		truncated := len(live) > s.currentConfig().MaxEntries
		if truncated {
			live = live[:s.currentConfig().MaxEntries]
		}
		jobID := quarantineDigestJobID(userID, scheduledFor)
		fullMessage, err := s.buildMessage(batchCtx, jobID, recipient, live, truncated)
		if err != nil {
			return err
		}
		job := QuarantineDigestJob{ID: jobID, UserID: userID, Recipient: recipient, ScheduledFor: scheduledFor, EntryCount: len(live), Truncated: truncated, FullMessage: fullMessage, Status: quarantineDigestPending, NextAttemptAt: now, CreatedAt: now, UpdatedAt: now}
		if err := s.ts.Put(batchCtx, model.NSMetadata, quarantineDigestJobKey(job.ID), job); err != nil && !errors.Is(err, store.ErrExists) {
			return err
		}
		preference.PendingJobID, preference.UpdatedAt = job.ID, now
		if err := s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestPreferenceKey(userID), preference); err != nil {
			return err
		}
		prepared = true
		return nil
	})
	return prepared, empty, err
}

func quarantineDigestJobID(userID string, scheduledFor time.Time) string {
	digest := sha256.Sum256([]byte(strings.ToLower(userID) + "\x00" + scheduledFor.UTC().Format(time.RFC3339Nano)))
	return "qdg_" + hex.EncodeToString(digest[:16])
}

func sanitizeDigestHeader(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}

func (s *QuarantineDigestService) buildMessage(ctx context.Context, jobID, recipient string, entries []QuarantineEntry, truncated bool) ([]byte, error) {
	baseURL := strings.TrimRight(s.currentConfig().BaseURL, "/")
	plain := &strings.Builder{}
	htmlBody := &strings.Builder{}
	fmt.Fprintf(plain, "Veksel quarantine digest\r\n\r\n%d message(s) are currently isolated.\r\n\r\n", len(entries))
	fmt.Fprintf(htmlBody, "<!doctype html><html><body><h1>Quarantine digest</h1><p>%d message(s) are currently isolated.</p><table><thead><tr><th>Received</th><th>Sender</th><th>Subject</th><th>Actions</th></tr></thead><tbody>", len(entries))
	for _, entry := range entries {
		releaseToken, err := s.actions.Issue(ctx, entry, QuarantineActionRelease)
		if err != nil {
			return nil, err
		}
		spamToken, err := s.actions.Issue(ctx, entry, QuarantineActionSpam)
		if err != nil {
			return nil, err
		}
		releaseURL := baseURL + "/quarantine/action?token=" + url.QueryEscape(releaseToken)
		spamURL := baseURL + "/quarantine/action?token=" + url.QueryEscape(spamToken)
		fmt.Fprintf(plain, "%s | %s | %s\r\nRelease: %s\r\nConfirm spam: %s\r\n\r\n", sanitizeDigestHeader(entry.Date), sanitizeDigestHeader(entry.Sender), sanitizeDigestHeader(entry.Subject), releaseURL, spamURL)
		fmt.Fprintf(htmlBody, "<tr><td>%s</td><td>%s</td><td>%s</td><td><a href=\"%s\">Release</a> · <a href=\"%s\">Confirm spam</a></td></tr>", html.EscapeString(entry.Date), html.EscapeString(entry.Sender), html.EscapeString(entry.Subject), html.EscapeString(releaseURL), html.EscapeString(spamURL))
	}
	if truncated {
		plain.WriteString("More messages are available in the Veksel quarantine view.\r\n")
		htmlBody.WriteString("</tbody></table><p>More messages are available in the Veksel quarantine view.</p>")
	} else {
		htmlBody.WriteString("</tbody></table>")
	}
	htmlBody.WriteString("<p>Each link is expiring, single-purpose, and can be used only once.</p></body></html>")
	boundary := "veksel-" + jobID
	from := sanitizeDigestHeader(s.currentConfig().FromAddress)
	to := sanitizeDigestHeader(recipient)
	message := &strings.Builder{}
	fmt.Fprintf(message, "From: %s\r\nTo: %s\r\nSubject: Veksel quarantine digest (%d messages)\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nAuto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\nContent-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", from, to, len(entries), s.now().UTC().Format(time.RFC1123Z), jobID, mailidentity.MessageIDDomain(from, ""), boundary)
	fmt.Fprintf(message, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n", boundary, plain.String())
	fmt.Fprintf(message, "--%s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n", boundary, htmlBody.String())
	fmt.Fprintf(message, "--%s--\r\n", boundary)
	return []byte(message.String()), nil
}

func (s *QuarantineDigestService) deliverJob(ctx context.Context, id string, sender QuarantineDigestSender, now time.Time) (string, error) {
	leaseToken, err := newQuarantineID()
	if err != nil {
		return "", err
	}
	var claimed QuarantineDigestJob
	if err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		if err := s.ts.Get(batchCtx, model.NSMetadata, quarantineDigestJobKey(id), &claimed); err != nil {
			return err
		}
		if claimed.Status != quarantineDigestPending && !(claimed.Status == quarantineDigestSending && claimed.LeaseAt.Add(quarantineDigestLease).Before(now)) || claimed.NextAttemptAt.After(now) {
			return store.ErrPreconditionFailed
		}
		claimed.Status, claimed.LeaseToken, claimed.LeaseAt, claimed.UpdatedAt = quarantineDigestSending, leaseToken, now, now
		return s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestJobKey(id), claimed)
	}); err != nil {
		if errors.Is(err, store.ErrPreconditionFailed) {
			return "", nil
		}
		return "", err
	}
	sendErr := sender(ctx, claimed)
	status := quarantineDigestSent
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		var job QuarantineDigestJob
		if err := s.ts.Get(batchCtx, model.NSMetadata, quarantineDigestJobKey(id), &job); err != nil {
			return err
		}
		if job.LeaseToken != leaseToken || job.Status != quarantineDigestSending {
			return store.ErrPreconditionFailed
		}
		job.Attempts++
		job.LeaseAt, job.LeaseToken, job.UpdatedAt = time.Time{}, "", now
		if sendErr == nil {
			job.Status, job.CompletedAt, job.LastError, job.FullMessage = quarantineDigestSent, now, "", nil
		} else {
			job.LastError = truncateDigestError(sendErr.Error())
			if job.Attempts >= s.currentConfig().MaxAttempts {
				job.Status, job.CompletedAt, job.FullMessage, status = quarantineDigestFailed, now, nil, quarantineDigestFailed
			} else {
				job.Status, status = quarantineDigestPending, quarantineDigestPending
				job.NextAttemptAt = now.Add(quarantineDigestRetryDelay(s.currentConfig().RetryBase, job.Attempts))
			}
		}
		if err := s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestJobKey(id), job); err != nil {
			return err
		}
		if job.Status == quarantineDigestSent || job.Status == quarantineDigestFailed {
			preference, err := s.GetPreference(batchCtx, job.UserID)
			if err != nil {
				return err
			}
			if preference.PendingJobID == job.ID {
				preference.PendingJobID = ""
				if job.Status == quarantineDigestSent {
					preference.LastSentAt = now
				}
				preference.UpdatedAt = now
				return s.ts.Set(batchCtx, model.NSMetadata, quarantineDigestPreferenceKey(job.UserID), preference)
			}
		}
		return nil
	})
	return status, err
}

func quarantineDigestRetryDelay(base time.Duration, attempt int) time.Duration {
	delay := base
	for step := 1; step < attempt && delay < 24*time.Hour; step++ {
		if delay >= 12*time.Hour {
			return 24 * time.Hour
		}
		delay *= 2
	}
	return min(delay, 24*time.Hour)
}

func truncateDigestError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

func (s *QuarantineDigestService) ListJobs(ctx context.Context) ([]QuarantineDigestJob, error) {
	keys, err := s.ts.Scan(ctx, model.NSMetadata, quarantineDigestJobPrefix())
	if err != nil {
		return nil, err
	}
	jobs := make([]QuarantineDigestJob, 0, len(keys))
	for _, key := range keys {
		var job QuarantineDigestJob
		if err := s.ts.Get(ctx, model.NSMetadata, key, &job); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.Before(jobs[j].CreatedAt) })
	return jobs, nil
}

func (s *QuarantineDigestService) Cleanup(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit < 1 {
		return 0, errors.New("digest cleanup limit must be positive")
	}
	jobs, err := s.ListJobs(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	cutoff := now.UTC().Add(-s.currentConfig().JobRetention)
	for _, job := range jobs {
		if removed >= limit {
			break
		}
		if (job.Status == quarantineDigestSent || job.Status == quarantineDigestFailed || job.Status == quarantineDigestCancelled) && job.CompletedAt.Before(cutoff) {
			if err := s.ts.Delete(ctx, model.NSMetadata, quarantineDigestJobKey(job.ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}
