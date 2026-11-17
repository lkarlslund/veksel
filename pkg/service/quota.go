package service

import (
	"errors"
	"math"
)

const (
	QuotaPressureUnlimited  = "unlimited"
	QuotaPressureNormal     = "normal"
	QuotaPressureWarning    = "warning"
	QuotaPressureCritical   = "critical"
	QuotaPressureExceeded   = "exceeded"
	QuotaPressureUnverified = "unverified"
)

// QuotaPolicy defines server-wide account pressure thresholds. Percentages
// are evaluated against both item and logical-byte limits; the higher bounded
// resource pressure determines the account state.
type QuotaPolicy struct {
	WarningPercent  int `json:"warning_percent"`
	CriticalPercent int `json:"critical_percent"`
}

func (p QuotaPolicy) Validate() error {
	if p.WarningPercent < 1 || p.WarningPercent > 99 || p.CriticalPercent < 2 || p.CriticalPercent > 100 || p.WarningPercent >= p.CriticalPercent {
		return errors.New("quota thresholds require warning between 1 and 99, critical between 2 and 100, and warning below critical")
	}
	return nil
}

// QuotaStatus is the deterministic policy projection shared by user and
// administration APIs.
type QuotaStatus struct {
	State           string  `json:"state"`
	Percent         float64 `json:"percent"`
	StoragePercent  float64 `json:"storage_percent"`
	ItemsPercent    float64 `json:"items_percent"`
	StorageLimited  bool    `json:"storage_limited"`
	ItemsLimited    bool    `json:"items_limited"`
	WarningPercent  int     `json:"warning_percent"`
	CriticalPercent int     `json:"critical_percent"`
}

// Classify returns an account pressure state from authoritative folder totals.
func (p QuotaPolicy) Classify(usage AccountUsage) QuotaStatus {
	status := QuotaStatus{WarningPercent: p.WarningPercent, CriticalPercent: p.CriticalPercent}
	if !usage.AccountingReady {
		status.State = QuotaPressureUnverified
		return status
	}
	if usage.Quota.MaxStorageBytes > 0 {
		status.StorageLimited = true
		status.StoragePercent = percent(float64(usage.LogicalBytes), float64(usage.Quota.MaxStorageBytes))
	}
	if usage.Quota.MaxItems > 0 {
		status.ItemsLimited = true
		status.ItemsPercent = percent(float64(usage.Items), float64(usage.Quota.MaxItems))
	}
	status.Percent = math.Max(status.StoragePercent, status.ItemsPercent)
	if !status.StorageLimited && !status.ItemsLimited {
		status.State = QuotaPressureUnlimited
	} else if status.Percent >= 100 {
		status.State = QuotaPressureExceeded
	} else if status.Percent >= float64(p.CriticalPercent) {
		status.State = QuotaPressureCritical
	} else if status.Percent >= float64(p.WarningPercent) {
		status.State = QuotaPressureWarning
	} else {
		status.State = QuotaPressureNormal
	}
	return status
}

func percent(used, limit float64) float64 {
	if limit <= 0 {
		return 0
	}
	return used / limit * 100
}
