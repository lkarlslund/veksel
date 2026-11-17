package model

import (
	"context"
	"errors"
)

// ErrQuotaExceeded is returned when an operation would exceed a user's
// mailbox quota (storage bytes or item count).
var ErrQuotaExceeded = errors.New("mailbox quota exceeded")

type quotaExemptKey struct{}

// WithQuotaExempt marks ctx so item writes made with it count toward usage
// but are never refused for exceeding a quota. Administrative copies, such
// as journal mail, use it so compliance capture cannot be lost to a full
// mailbox.
func WithQuotaExempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, quotaExemptKey{}, true)
}

func quotaExempt(ctx context.Context) bool {
	exempt, _ := ctx.Value(quotaExemptKey{}).(bool)
	return exempt
}

// QuotaInfo holds the quota limits and current usage for a user.
type QuotaInfo struct {
	MaxStorageBytes     int64 `json:"max_storage_bytes"`
	MaxItems            int   `json:"max_items"`
	CurrentStorageBytes int64 `json:"current_storage_bytes"`
	CurrentItems        int   `json:"current_items"`
}

// CheckStorage returns true if adding size bytes would exceed the storage quota.
// Zero MaxStorageBytes means unlimited.
func (q QuotaInfo) CheckStorage(size int64) bool {
	if q.MaxStorageBytes == 0 {
		return true // unlimited
	}
	return q.CurrentStorageBytes+size <= q.MaxStorageBytes
}

// CheckItems returns true if adding count items would exceed the item quota.
// Zero MaxItems means unlimited.
func (q QuotaInfo) CheckItems(count int) bool {
	if q.MaxItems == 0 {
		return true // unlimited
	}
	return q.CurrentItems+count <= q.MaxItems
}

// StorageUsagePercent returns the percentage of storage used (0-100).
// Returns 0 if unlimited.
func (q QuotaInfo) StorageUsagePercent() float64 {
	if q.MaxStorageBytes == 0 {
		return 0
	}
	return float64(q.CurrentStorageBytes) / float64(q.MaxStorageBytes) * 100
}

// ItemsUsagePercent returns the percentage of items used (0-100).
// Returns 0 if unlimited.
func (q QuotaInfo) ItemsUsagePercent() float64 {
	if q.MaxItems == 0 {
		return 0
	}
	return float64(q.CurrentItems) / float64(q.MaxItems) * 100
}
