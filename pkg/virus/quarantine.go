package virus

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const quarantineAccountingVersion = 2

var ErrQuarantineCapacity = errors.New("quarantine capacity exceeded")

// QuarantinePolicy bounds retained quarantine data. Zero values disable the
// corresponding limit, which keeps the constructor useful to offline tools.
type QuarantinePolicy struct {
	Retention  time.Duration
	MaxEntries int64
	MaxBytes   int64
}

func (p QuarantinePolicy) Validate() error {
	if p.Retention < 0 || p.MaxEntries < 0 || p.MaxBytes < 0 {
		return errors.New("quarantine policy values cannot be negative")
	}
	return nil
}

// QuarantineStatus is the constant-time durable accounting projection.
type QuarantineStatus struct {
	Entries           int64     `json:"entries"`
	LogicalBytes      int64     `json:"logical_bytes"`
	AccountingVersion int       `json:"accounting_version"`
	UpdatedAt         time.Time `json:"updated_at"`
	RetentionSeconds  int64     `json:"retention_seconds"`
	MaxEntries        int64     `json:"max_entries"`
	MaxBytes          int64     `json:"max_bytes"`
	EntryPressure     float64   `json:"entry_pressure"`
	BytePressure      float64   `json:"byte_pressure"`
	AtCapacity        bool      `json:"at_capacity"`
}

// QuarantineCleanup reports bounded expiry work.
type QuarantineCleanup struct {
	Removed int64 `json:"removed"`
	Bytes   int64 `json:"bytes"`
}

type quarantineAccounting struct {
	Entries      int64     `json:"entries"`
	LogicalBytes int64     `json:"logical_bytes"`
	Version      int       `json:"version"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// QuarantineStore manages virus quarantine entries using the model store.
type QuarantineStore struct {
	ts            *model.TypedStore
	policy        atomic.Pointer[QuarantinePolicy]
	ownerResolver func(context.Context, string) (string, error)
	now           func() time.Time
}

// NewQuarantineStore creates a store backed by the typed model store.
func NewQuarantineStore(ts *model.TypedStore, policies ...QuarantinePolicy) *QuarantineStore {
	var policy QuarantinePolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	qs := &QuarantineStore{ts: ts, now: time.Now}
	qs.policy.Store(&policy)
	return qs
}

func (qs *QuarantineStore) currentPolicy() QuarantinePolicy { return *qs.policy.Load() }

// SetPolicy replaces the retention and capacity limits. Entries already held
// keep their recorded expiry; the new limits govern later admissions.
func (qs *QuarantineStore) SetPolicy(policy QuarantinePolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	qs.policy.Store(&policy)
	return nil
}

// SetOwnerResolver installs local-recipient ownership resolution for legacy
// and direct-admission records that do not already carry a queue owner.
func (qs *QuarantineStore) SetOwnerResolver(resolve func(context.Context, string) (string, error)) {
	qs.ownerResolver = resolve
}

// quarantineKey builds the store key for a quarantine entry.
func quarantineKey(id string) string {
	return "quarantine:" + id
}

// quarantinePrefix returns the prefix for scanning all quarantine entries.
func quarantinePrefix() string {
	return "quarantine:"
}

func quarantineExpiryPrefix() string { return "quarantine-expiry:" }

func quarantineExpiryKey(expiresAt time.Time, id string) string {
	return fmt.Sprintf("%s%020d:%s", quarantineExpiryPrefix(), expiresAt.UnixNano(), id)
}

func quarantineAccountingKey() string { return "quarantine-accounting" }

func quarantineOwnerPrefix(ownerID string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(ownerID))))
	return "quarantine-owner:" + hex.EncodeToString(digest[:]) + ":"
}

func quarantineOwnerKey(entry QuarantineEntry) string {
	return fmt.Sprintf("%s%020d:%s", quarantineOwnerPrefix(entry.OwnerID), entry.CreatedAt.UnixNano(), entry.ID)
}

func quarantineReleaseKey(id string) string { return "quarantine-release:" + id }

func quarantineSpamKey(id string) string { return "quarantine-spam:" + id }

// ReleaseReceipt makes the release endpoint idempotent after the quarantined
// content has been removed. QueueID is also the local-delivery idempotency key.
type ReleaseReceipt struct {
	EntryID    string    `json:"entry_id"`
	QueueID    string    `json:"queue_id"`
	OwnerID    string    `json:"owner_id"`
	Recipient  string    `json:"recipient"`
	AcceptedAt time.Time `json:"accepted_at"`
}

type SpamReceipt struct {
	EntryID     string    `json:"entry_id"`
	OwnerID     string    `json:"owner_id"`
	Blocked     string    `json:"blocked"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

// Add stores a quarantined message. Returns the entry ID.
func (qs *QuarantineStore) Add(ctx context.Context, entry *QuarantineEntry) (string, error) {
	if entry == nil {
		return "", errors.New("quarantine entry is required")
	}
	if err := qs.currentPolicy().Validate(); err != nil {
		return "", err
	}
	if entry.ID == "" {
		id, err := newQuarantineID()
		if err != nil {
			return "", err
		}
		entry.ID = id
	}
	if strings.TrimSpace(entry.ID) == "" {
		return "", errors.New("quarantine entry ID is required")
	}
	now := qs.now().UTC()
	entryCopy := *entry
	entryCopy.Headers = cloneHeaders(entry.Headers)
	entryCopy.MessageData = append([]byte(nil), entry.MessageData...)
	if err := store.Batch(ctx, qs.ts.Store(), func(batchCtx context.Context) error {
		accounting, err := qs.loadAccounting(batchCtx, now)
		if err != nil {
			return err
		}
		if _, err := qs.pruneExpired(batchCtx, &accounting, now, 0); err != nil {
			return err
		}

		var previous QuarantineEntry
		previousFound := false
		if err := qs.ts.Get(batchCtx, model.NSMetadata, quarantineKey(entryCopy.ID), &previous); err == nil {
			previousFound = true
			accounting.Entries = max(0, accounting.Entries-1)
			accounting.LogicalBytes = max(0, accounting.LogicalBytes-quarantineEntrySize(previous))
			if !previous.ExpiresAt.IsZero() {
				_ = qs.ts.Delete(batchCtx, model.NSMetadata, quarantineExpiryKey(previous.ExpiresAt, previous.ID))
			}
			if previous.OwnerID != "" && !previous.CreatedAt.IsZero() {
				_ = qs.ts.Delete(batchCtx, model.NSMetadata, quarantineOwnerKey(previous))
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		normalizeQuarantineEntry(&entryCopy, now, qs.currentPolicy().Retention, previousFound, previous)
		if err := qs.resolveOwner(batchCtx, &entryCopy); err != nil {
			return err
		}
		size := quarantineEntrySize(entryCopy)
		if qs.currentPolicy().MaxEntries > 0 && accounting.Entries+1 > qs.currentPolicy().MaxEntries || qs.currentPolicy().MaxBytes > 0 && accounting.LogicalBytes+size > qs.currentPolicy().MaxBytes {
			return fmt.Errorf("%w: retaining message would use %d entries and %d bytes", ErrQuarantineCapacity, accounting.Entries+1, accounting.LogicalBytes+size)
		}
		if err := qs.ts.Set(batchCtx, model.NSMetadata, quarantineKey(entryCopy.ID), entryCopy); err != nil {
			return err
		}
		if !entryCopy.ExpiresAt.IsZero() {
			if err := qs.ts.Set(batchCtx, model.NSMetadata, quarantineExpiryKey(entryCopy.ExpiresAt, entryCopy.ID), entryCopy.ID); err != nil {
				return err
			}
		}
		if entryCopy.OwnerID != "" {
			if err := qs.ts.Set(batchCtx, model.NSMetadata, quarantineOwnerKey(entryCopy), entryCopy.ID); err != nil {
				return err
			}
		}
		accounting.Entries++
		accounting.LogicalBytes += size
		return qs.putAccounting(batchCtx, accounting, now)
	}); err != nil {
		return "", fmt.Errorf("store quarantine entry: %w", err)
	}
	*entry = entryCopy
	return entry.ID, nil
}

func (qs *QuarantineStore) resolveOwner(ctx context.Context, entry *QuarantineEntry) error {
	entry.OwnerID = strings.ToLower(strings.TrimSpace(entry.OwnerID))
	if entry.OwnerID != "" || qs.ownerResolver == nil || strings.TrimSpace(entry.Recipient) == "" {
		return nil
	}
	ownerID, err := qs.ownerResolver(ctx, entry.Recipient)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve quarantine owner: %w", err)
	}
	entry.OwnerID = strings.ToLower(strings.TrimSpace(ownerID))
	return nil
}

func newQuarantineID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate quarantine ID: %w", err)
	}
	return "qrn_" + hex.EncodeToString(random[:]), nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}

func normalizeQuarantineEntry(entry *QuarantineEntry, now time.Time, retention time.Duration, replacing bool, previous QuarantineEntry) {
	entry.ID = strings.TrimSpace(entry.ID)
	entry.MessageSize = max(entry.MessageSize, int64(len(entry.MessageData)))
	if replacing && !previous.CreatedAt.IsZero() {
		entry.CreatedAt = previous.CreatedAt
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	if retention > 0 {
		entry.ExpiresAt = entry.CreatedAt.Add(retention)
	} else if replacing {
		entry.ExpiresAt = previous.ExpiresAt
	}
	if entry.Date == "" {
		entry.Date = entry.CreatedAt.Format(time.RFC3339)
	}
}

func quarantineEntrySize(entry QuarantineEntry) int64 {
	return max(entry.MessageSize, int64(len(entry.MessageData)))
}

// Get returns a quarantined message by ID.
func (qs *QuarantineStore) Get(ctx context.Context, id string) (*QuarantineEntry, error) {
	var entry QuarantineEntry
	if err := qs.ts.Get(ctx, model.NSMetadata, quarantineKey(id), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// List returns all quarantined messages.
func (qs *QuarantineStore) List(ctx context.Context) ([]QuarantineEntry, error) {
	var entries []QuarantineEntry
	err := store.View(ctx, qs.ts.Store(), func(viewCtx context.Context) error {
		keys, err := qs.ts.Scan(viewCtx, model.NSMetadata, quarantinePrefix())
		if err != nil {
			return err
		}
		entries = make([]QuarantineEntry, 0, len(keys))
		for _, key := range keys {
			var entry QuarantineEntry
			if err := qs.ts.Get(viewCtx, model.NSMetadata, key, &entry); err != nil {
				return err
			}
			entries = append(entries, entry)
		}
		return nil
	})
	return entries, err
}

// ListForOwner uses the derived owner index and never scans another account's
// quarantine records. Results are ordered newest first.
func (qs *QuarantineStore) ListForOwner(ctx context.Context, ownerID string) ([]QuarantineEntry, error) {
	var entries []QuarantineEntry
	err := store.View(ctx, qs.ts.Store(), func(viewCtx context.Context) error {
		keys, err := qs.ts.Scan(viewCtx, model.NSMetadata, quarantineOwnerPrefix(ownerID))
		if err != nil {
			return err
		}
		entries = make([]QuarantineEntry, 0, len(keys))
		for index := len(keys) - 1; index >= 0; index-- {
			var id string
			if err := qs.ts.Get(viewCtx, model.NSMetadata, keys[index], &id); err != nil {
				return err
			}
			var entry QuarantineEntry
			if err := qs.ts.Get(viewCtx, model.NSMetadata, quarantineKey(id), &entry); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					continue
				}
				return err
			}
			if strings.EqualFold(entry.OwnerID, ownerID) {
				entries = append(entries, entry)
			}
		}
		return nil
	})
	return entries, err
}

// Delete permanently removes a quarantined message.
func (qs *QuarantineStore) Delete(ctx context.Context, id string) error {
	return store.Batch(ctx, qs.ts.Store(), func(batchCtx context.Context) error {
		accounting, err := qs.loadAccounting(batchCtx, qs.now().UTC())
		if err != nil {
			return err
		}
		var entry QuarantineEntry
		if err := qs.ts.Get(batchCtx, model.NSMetadata, quarantineKey(id), &entry); err != nil {
			return err
		}
		if err := qs.deleteEntry(batchCtx, entry); err != nil {
			return err
		}
		accounting.Entries = max(0, accounting.Entries-1)
		accounting.LogicalBytes = max(0, accounting.LogicalBytes-quarantineEntrySize(entry))
		return qs.putAccounting(batchCtx, accounting, qs.now().UTC())
	})
}

// CleanupExpired removes at most limit expired entries. A zero limit removes
// all currently expired entries. The ordered expiry index bounds normal work.
func (qs *QuarantineStore) CleanupExpired(ctx context.Context, now time.Time, limit int) (QuarantineCleanup, error) {
	if limit < 0 {
		return QuarantineCleanup{}, errors.New("cleanup limit cannot be negative")
	}
	now = now.UTC()
	var cleanup QuarantineCleanup
	err := store.Batch(ctx, qs.ts.Store(), func(batchCtx context.Context) error {
		accounting, err := qs.loadAccounting(batchCtx, now)
		if err != nil {
			return err
		}
		cleanup, err = qs.pruneExpired(batchCtx, &accounting, now, limit)
		if err != nil {
			return err
		}
		return qs.putAccounting(batchCtx, accounting, now)
	})
	return cleanup, err
}

// Status reads constant-time durable accounting. It rebuilds legacy metadata
// once when no current accounting record exists.
func (qs *QuarantineStore) Status(ctx context.Context) (QuarantineStatus, error) {
	if err := qs.currentPolicy().Validate(); err != nil {
		return QuarantineStatus{}, err
	}
	now := qs.now().UTC()
	var accounting quarantineAccounting
	err := store.Batch(ctx, qs.ts.Store(), func(batchCtx context.Context) error {
		var err error
		accounting, err = qs.loadAccounting(batchCtx, now)
		return err
	})
	if err != nil {
		return QuarantineStatus{}, err
	}
	status := QuarantineStatus{Entries: accounting.Entries, LogicalBytes: accounting.LogicalBytes, AccountingVersion: accounting.Version, UpdatedAt: accounting.UpdatedAt, RetentionSeconds: int64(qs.currentPolicy().Retention.Seconds()), MaxEntries: qs.currentPolicy().MaxEntries, MaxBytes: qs.currentPolicy().MaxBytes}
	if qs.currentPolicy().MaxEntries > 0 {
		status.EntryPressure = float64(accounting.Entries) / float64(qs.currentPolicy().MaxEntries)
		status.AtCapacity = accounting.Entries >= qs.currentPolicy().MaxEntries
	}
	if qs.currentPolicy().MaxBytes > 0 {
		status.BytePressure = float64(accounting.LogicalBytes) / float64(qs.currentPolicy().MaxBytes)
		status.AtCapacity = status.AtCapacity || accounting.LogicalBytes >= qs.currentPolicy().MaxBytes
	}
	return status, nil
}

// RebuildAccounting reconstructs the summary and expiry index from durable
// entries. It is safe to run after repair/import tooling changed raw records.
func (qs *QuarantineStore) RebuildAccounting(ctx context.Context) (QuarantineStatus, error) {
	if err := store.Batch(ctx, qs.ts.Store(), func(batchCtx context.Context) error {
		if err := qs.ts.Delete(batchCtx, model.NSMetadata, quarantineAccountingKey()); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		keys, err := qs.ts.Scan(batchCtx, model.NSMetadata, quarantineExpiryPrefix())
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := qs.ts.Delete(batchCtx, model.NSMetadata, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		ownerKeys, err := qs.ts.Scan(batchCtx, model.NSMetadata, "quarantine-owner:")
		if err != nil {
			return err
		}
		for _, key := range ownerKeys {
			if err := qs.ts.Delete(batchCtx, model.NSMetadata, key); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		_, err = qs.loadAccounting(batchCtx, qs.now().UTC())
		return err
	}); err != nil {
		return QuarantineStatus{}, err
	}
	return qs.Status(ctx)
}

func (qs *QuarantineStore) loadAccounting(ctx context.Context, now time.Time) (quarantineAccounting, error) {
	var accounting quarantineAccounting
	if err := qs.ts.Get(ctx, model.NSMetadata, quarantineAccountingKey(), &accounting); err == nil && accounting.Version == quarantineAccountingVersion {
		return accounting, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return quarantineAccounting{}, err
	}
	return qs.rebuildAccounting(ctx, now)
}

func (qs *QuarantineStore) rebuildAccounting(ctx context.Context, now time.Time) (quarantineAccounting, error) {
	keys, err := qs.ts.Scan(ctx, model.NSMetadata, quarantinePrefix())
	if err != nil {
		return quarantineAccounting{}, err
	}
	accounting := quarantineAccounting{Version: quarantineAccountingVersion, UpdatedAt: now}
	for _, key := range keys {
		var entry QuarantineEntry
		if err := qs.ts.Get(ctx, model.NSMetadata, key, &entry); err != nil {
			return quarantineAccounting{}, err
		}
		normalizeQuarantineEntry(&entry, legacyCreatedAt(entry, now), qs.currentPolicy().Retention, false, QuarantineEntry{})
		if err := qs.resolveOwner(ctx, &entry); err != nil {
			return quarantineAccounting{}, err
		}
		if err := qs.ts.Set(ctx, model.NSMetadata, key, entry); err != nil {
			return quarantineAccounting{}, err
		}
		if !entry.ExpiresAt.IsZero() {
			if err := qs.ts.Set(ctx, model.NSMetadata, quarantineExpiryKey(entry.ExpiresAt, entry.ID), entry.ID); err != nil {
				return quarantineAccounting{}, err
			}
		}
		if entry.OwnerID != "" {
			if err := qs.ts.Set(ctx, model.NSMetadata, quarantineOwnerKey(entry), entry.ID); err != nil {
				return quarantineAccounting{}, err
			}
		}
		accounting.Entries++
		accounting.LogicalBytes += quarantineEntrySize(entry)
	}
	if err := qs.putAccounting(ctx, accounting, now); err != nil {
		return quarantineAccounting{}, err
	}
	return accounting, nil
}

func legacyCreatedAt(entry QuarantineEntry, fallback time.Time) time.Time {
	if !entry.CreatedAt.IsZero() {
		return entry.CreatedAt.UTC()
	}
	if parsed, err := time.Parse(time.RFC3339, entry.Date); err == nil {
		return parsed.UTC()
	}
	return fallback
}

func (qs *QuarantineStore) pruneExpired(ctx context.Context, accounting *quarantineAccounting, now time.Time, limit int) (QuarantineCleanup, error) {
	keys, err := qs.ts.Scan(ctx, model.NSMetadata, quarantineExpiryPrefix())
	if err != nil {
		return QuarantineCleanup{}, err
	}
	sort.Strings(keys)
	cutoff := quarantineExpiryKey(now, "") + "\xff"
	var cleanup QuarantineCleanup
	for _, key := range keys {
		if key > cutoff || limit > 0 && cleanup.Removed >= int64(limit) {
			break
		}
		var id string
		if err := qs.ts.Get(ctx, model.NSMetadata, key, &id); err != nil {
			return cleanup, err
		}
		var entry QuarantineEntry
		if err := qs.ts.Get(ctx, model.NSMetadata, quarantineKey(id), &entry); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				_ = qs.ts.Delete(ctx, model.NSMetadata, key)
				continue
			}
			return cleanup, err
		}
		if entry.ExpiresAt.IsZero() || entry.ExpiresAt.After(now) {
			continue
		}
		if err := qs.deleteEntry(ctx, entry); err != nil {
			return cleanup, err
		}
		size := quarantineEntrySize(entry)
		accounting.Entries = max(0, accounting.Entries-1)
		accounting.LogicalBytes = max(0, accounting.LogicalBytes-size)
		cleanup.Removed++
		cleanup.Bytes += size
	}
	return cleanup, nil
}

func (qs *QuarantineStore) deleteEntry(ctx context.Context, entry QuarantineEntry) error {
	if err := qs.ts.Delete(ctx, model.NSMetadata, quarantineKey(entry.ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if !entry.ExpiresAt.IsZero() {
		if err := qs.ts.Delete(ctx, model.NSMetadata, quarantineExpiryKey(entry.ExpiresAt, entry.ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if entry.OwnerID != "" && !entry.CreatedAt.IsZero() {
		if err := qs.ts.Delete(ctx, model.NSMetadata, quarantineOwnerKey(entry)); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (qs *QuarantineStore) putAccounting(ctx context.Context, accounting quarantineAccounting, now time.Time) error {
	accounting.Version = quarantineAccountingVersion
	accounting.UpdatedAt = now
	return qs.ts.Set(ctx, model.NSMetadata, quarantineAccountingKey(), accounting)
}

func (qs *QuarantineStore) PutReleaseReceipt(ctx context.Context, receipt ReleaseReceipt) error {
	return qs.ts.Set(ctx, model.NSMetadata, quarantineReleaseKey(receipt.EntryID), receipt)
}

func (qs *QuarantineStore) GetReleaseReceipt(ctx context.Context, id string) (ReleaseReceipt, error) {
	var receipt ReleaseReceipt
	err := qs.ts.Get(ctx, model.NSMetadata, quarantineReleaseKey(id), &receipt)
	return receipt, err
}

func (qs *QuarantineStore) PutSpamReceipt(ctx context.Context, receipt SpamReceipt) error {
	return qs.ts.Set(ctx, model.NSMetadata, quarantineSpamKey(receipt.EntryID), receipt)
}

func (qs *QuarantineStore) GetSpamReceipt(ctx context.Context, id string) (SpamReceipt, error) {
	var receipt SpamReceipt
	err := qs.ts.Get(ctx, model.NSMetadata, quarantineSpamKey(id), &receipt)
	return receipt, err
}
