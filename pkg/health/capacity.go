package health

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// CapacityTarget is one configured storage location whose containing
// filesystem must remain writable. Multiple targets may share a device.
type CapacityTarget struct {
	ID    string
	Label string
	Path  string
}

// Capacity is one platform probe result. AvailableBytes deliberately uses
// space available to the service rather than raw free blocks.
type Capacity struct {
	DeviceID       string
	TotalBytes     uint64
	AvailableBytes uint64
}

// CapacityProber isolates platform-specific filesystem inspection.
type CapacityProber interface {
	Capacity(path string) (Capacity, error)
}

// CapacitySample is a deduplicated, payload-free filesystem observation.
type CapacitySample struct {
	DeviceID       string
	TargetIDs      []string
	TargetLabels   []string
	TotalBytes     uint64
	AvailableBytes uint64
	CollectedAt    time.Time
	Pending        bool
	Stale          bool
	Error          string
}

// CapacityCollector caches bounded filesystem metadata. It never enumerates
// directories, accounts, folders, or items.
type CapacityCollector struct {
	mu         sync.Mutex
	prober     CapacityProber
	ttl        time.Duration
	signature  string
	observed   time.Time
	samples    []CapacitySample
	refreshing bool
	refreshAt  time.Time
}

// NewCapacityCollector creates a collector with a one-minute default TTL.
func NewCapacityCollector(prober CapacityProber, ttl time.Duration) *CapacityCollector {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &CapacityCollector{prober: prober, ttl: ttl}
}

// Snapshot returns cached samples immediately and starts at most one probe in
// the background when the cache is stale. Filesystem metadata calls can block
// on an unhealthy remote mount, so health requests and server startup never
// wait for them. A stuck call consumes one bounded goroutine and prevents
// additional probes from accumulating.
func (c *CapacityCollector) Snapshot(now time.Time, targets []CapacityTarget) []CapacitySample {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	targets = append([]CapacityTarget(nil), targets...)
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].ID == targets[j].ID {
			return targets[i].Path < targets[j].Path
		}
		return targets[i].ID < targets[j].ID
	})
	var signature strings.Builder
	for _, target := range targets {
		fmt.Fprintf(&signature, "%s\x00%s\x00%s\x00", target.ID, target.Label, target.Path)
	}

	signatureValue := signature.String()
	c.mu.Lock()
	if c.signature != signatureValue {
		c.signature = signatureValue
		c.observed = time.Time{}
		c.samples = pendingCapacitySamples(targets)
	}
	if !c.observed.IsZero() && now.Sub(c.observed) >= 0 && now.Sub(c.observed) < c.ttl {
		result := c.snapshotLocked(now)
		c.mu.Unlock()
		return result
	}
	if !c.refreshing {
		c.refreshing = true
		c.refreshAt = now
		go c.refresh(now, signatureValue, targets)
	}
	result := c.snapshotLocked(now)
	c.mu.Unlock()
	return result
}

func (c *CapacityCollector) snapshotLocked(now time.Time) []CapacitySample {
	result := cloneCapacitySamples(c.samples)
	if !c.refreshing {
		return result
	}
	if c.observed.IsZero() && !c.refreshAt.IsZero() && now.Sub(c.refreshAt) >= c.ttl {
		for index := range result {
			if result[index].Pending {
				result[index].Pending = false
				result[index].Error = "filesystem capacity collection has not completed"
			}
		}
	} else if !c.observed.IsZero() && now.Sub(c.observed) >= 2*c.ttl {
		for index := range result {
			result[index].Stale = true
		}
	}
	return result
}

func (c *CapacityCollector) refresh(now time.Time, signature string, targets []CapacityTarget) {
	samples := c.probe(targets)
	for index := range samples {
		samples[index].CollectedAt = now
	}
	c.mu.Lock()
	if c.signature == signature {
		c.observed, c.samples = now, samples
	}
	c.refreshing = false
	c.refreshAt = time.Time{}
	c.mu.Unlock()
}

func pendingCapacitySamples(targets []CapacityTarget) []CapacitySample {
	ids := make([]string, 0, len(targets))
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.ID)
		labels = append(labels, target.Label)
	}
	slices.Sort(ids)
	slices.Sort(labels)
	// Keep one stable placeholder until device identities are known. Returning
	// one row prevents duplicate transient components for roots that may share
	// the same filesystem.
	return []CapacitySample{{DeviceID: "probe", TargetIDs: ids, TargetLabels: labels, Pending: true}}
}

func (c *CapacityCollector) probe(targets []CapacityTarget) []CapacitySample {
	if c.prober == nil {
		return []CapacitySample{{DeviceID: "probe", Error: "filesystem capacity probing is unsupported"}}
	}
	byDevice := make(map[string]*CapacitySample)
	for _, target := range targets {
		capacity, err := c.prober.Capacity(target.Path)
		if err != nil {
			byDevice["error:"+target.ID] = &CapacitySample{
				DeviceID: "error:" + target.ID, TargetIDs: []string{target.ID}, TargetLabels: []string{target.Label}, Error: err.Error(),
			}
			continue
		}
		if strings.TrimSpace(capacity.DeviceID) == "" || capacity.TotalBytes == 0 || capacity.AvailableBytes > capacity.TotalBytes {
			byDevice["error:"+target.ID] = &CapacitySample{
				DeviceID: "error:" + target.ID, TargetIDs: []string{target.ID}, TargetLabels: []string{target.Label}, Error: "filesystem returned invalid capacity metadata",
			}
			continue
		}
		sample := byDevice[capacity.DeviceID]
		if sample == nil {
			sample = &CapacitySample{DeviceID: capacity.DeviceID, TotalBytes: capacity.TotalBytes, AvailableBytes: capacity.AvailableBytes}
			byDevice[capacity.DeviceID] = sample
		}
		sample.TargetIDs = append(sample.TargetIDs, target.ID)
		sample.TargetLabels = append(sample.TargetLabels, target.Label)
		// Mount aliases should report the same values. Retain the most
		// conservative sample if a filesystem changes during collection.
		if capacity.TotalBytes < sample.TotalBytes {
			sample.TotalBytes = capacity.TotalBytes
		}
		if capacity.AvailableBytes < sample.AvailableBytes {
			sample.AvailableBytes = capacity.AvailableBytes
		}
	}
	keys := make([]string, 0, len(byDevice))
	for key := range byDevice {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]CapacitySample, 0, len(keys))
	for _, key := range keys {
		sample := *byDevice[key]
		slices.Sort(sample.TargetIDs)
		slices.Sort(sample.TargetLabels)
		result = append(result, sample)
	}
	return result
}

func cloneCapacitySamples(samples []CapacitySample) []CapacitySample {
	result := make([]CapacitySample, len(samples))
	for index, sample := range samples {
		result[index] = sample
		result[index].TargetIDs = slices.Clone(sample.TargetIDs)
		result[index].TargetLabels = slices.Clone(sample.TargetLabels)
	}
	return result
}

func validateCapacityThresholds(warningFreePercent, criticalFreePercent int) error {
	if criticalFreePercent < 1 || warningFreePercent <= criticalFreePercent || warningFreePercent > 99 {
		return errors.New("capacity critical free percentage must be positive and below warning percentage")
	}
	return nil
}

// CapacityObservations applies free-space policy to deduplicated samples.
func (p Policy) CapacityObservations(samples []CapacitySample) []Observation {
	result := make([]Observation, 0, len(samples))
	for _, sample := range samples {
		label := strings.Join(sample.TargetLabels, ", ")
		if label == "" {
			label = "Filesystem capacity probe"
		}
		observation := Observation{
			ID: "filesystem:" + sample.DeviceID, Label: label, Kind: "storage", Desired: true, Required: true, State: StateHealthy,
			Details: map[string]string{"targets": strings.Join(sample.TargetIDs, ", ")},
		}
		if sample.Pending {
			observation.Reason = "filesystem capacity collection is in progress"
			result = append(result, observation)
			continue
		}
		if !sample.CollectedAt.IsZero() {
			observation.Details["collected_at"] = sample.CollectedAt.UTC().Format(time.RFC3339Nano)
		}
		if sample.Error != "" {
			observation.State, observation.Severity = StateDegraded, SeverityWarning
			observation.Reason = "filesystem capacity could not be measured"
			observation.Details["error"] = sample.Error
			result = append(result, observation)
			continue
		}
		freePercent := float64(sample.AvailableBytes) * 100 / float64(sample.TotalBytes)
		observation.Details["device_id"] = sample.DeviceID
		observation.Details["total_bytes"] = fmt.Sprint(sample.TotalBytes)
		observation.Details["available_bytes"] = fmt.Sprint(sample.AvailableBytes)
		observation.Details["free_percent"] = fmt.Sprintf("%.1f", freePercent)
		observation.Details["used_percent"] = fmt.Sprintf("%.1f", 100-freePercent)
		switch {
		case freePercent <= float64(p.StorageCriticalFreePercent):
			observation.State, observation.Severity = StateDegraded, SeverityCritical
			observation.Reason = "filesystem free space is at or below the critical threshold"
		case freePercent <= float64(p.StorageWarningFreePercent):
			observation.State, observation.Severity = StateDegraded, SeverityWarning
			observation.Reason = "filesystem free space is at or below the warning threshold"
		}
		if sample.Stale && observation.State == StateHealthy {
			observation.State, observation.Severity = StateDegraded, SeverityWarning
			observation.Reason = "filesystem capacity evidence is stale"
		}
		result = append(result, observation)
	}
	return result
}
