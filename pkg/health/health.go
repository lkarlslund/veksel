// Package health owns the canonical runtime-health projection used by probes,
// administration, alert evaluation, and event publication.
package health

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	StateDisabled    = "disabled"
	StateHealthy     = "healthy"
	StateDegraded    = "degraded"
	StateUnavailable = "unavailable"

	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"

	StatusReady       = "ready"
	StatusDegraded    = "degraded"
	StatusUnavailable = "unavailable"

	maxReasonRunes = 512
	maxDetailRunes = 256
	maxDetails     = 16
)

// Observation is one producer's current view of a runtime component. IDs are
// stable machine identifiers; labels, reasons, and details are display data.
type Observation struct {
	ID       string            `json:"id"`
	Label    string            `json:"label"`
	Kind     string            `json:"kind"`
	Desired  bool              `json:"desired"`
	Required bool              `json:"required"`
	State    string            `json:"state"`
	Severity string            `json:"severity"`
	Reason   string            `json:"reason,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
}

// Component is a validated observation with transition and observation time.
type Component struct {
	Observation
	Since      time.Time `json:"since"`
	ObservedAt time.Time `json:"observed_at"`
}

// Snapshot is an immutable, deterministically ordered runtime-health view.
type Snapshot struct {
	Status      string      `json:"status"`
	GeneratedAt time.Time   `json:"generated_at"`
	Components  []Component `json:"components"`
}

// Registry retains the newest validated observation for every component and
// preserves transition time while its operational state remains unchanged.
type Registry struct {
	mu         sync.RWMutex
	components map[string]Component
}

func New() *Registry {
	return &Registry{components: make(map[string]Component)}
}

// Replace atomically publishes a complete component set. Missing components
// are removed so stale protocol state cannot linger after reconfiguration.
func (r *Registry) Replace(now time.Time, observations []Observation) error {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	next := make(map[string]Component, len(observations))
	for _, observation := range observations {
		validated, err := validate(observation)
		if err != nil {
			return err
		}
		if _, exists := next[validated.ID]; exists {
			return errors.New("health component IDs must be unique")
		}
		next[validated.ID] = Component{Observation: validated, Since: now, ObservedAt: now}
	}
	r.mu.Lock()
	for id, component := range next {
		if previous, found := r.components[id]; found && sameOperationalState(previous.Observation, component.Observation) {
			component.Since = previous.Since
			next[id] = component
		}
	}
	r.components = next
	r.mu.Unlock()
	return nil
}

// Snapshot returns a detached copy safe for concurrent callers and mutation by
// encoders. Readiness fails only for desired, required unavailable components.
func (r *Registry) Snapshot(now time.Time) Snapshot {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	r.mu.RLock()
	components := make([]Component, 0, len(r.components))
	for _, component := range r.components {
		component.Details = cloneDetails(component.Details)
		components = append(components, component)
	}
	r.mu.RUnlock()
	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })
	status := StatusReady
	for _, component := range components {
		if component.Desired && component.Required && component.State == StateUnavailable {
			status = StatusUnavailable
			break
		}
		if component.Desired && component.State != StateHealthy && component.State != StateDisabled {
			status = StatusDegraded
		}
	}
	return Snapshot{Status: status, GeneratedAt: now, Components: components}
}

func validate(observation Observation) (Observation, error) {
	observation.ID = strings.TrimSpace(observation.ID)
	observation.Label = strings.TrimSpace(observation.Label)
	observation.Kind = strings.TrimSpace(observation.Kind)
	if observation.ID == "" || observation.Label == "" || observation.Kind == "" {
		return Observation{}, errors.New("health components require id, label, and kind")
	}
	switch observation.State {
	case StateDisabled:
		observation.Desired = false
		observation.Required = false
	case StateHealthy, StateDegraded, StateUnavailable:
	default:
		return Observation{}, errors.New("invalid health component state")
	}
	if observation.Severity == "" {
		switch observation.State {
		case StateUnavailable:
			observation.Severity = SeverityCritical
		case StateDegraded:
			observation.Severity = SeverityWarning
		default:
			observation.Severity = SeverityInfo
		}
	}
	switch observation.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		return Observation{}, errors.New("invalid health component severity")
	}
	observation.Reason = bounded(observation.Reason, maxReasonRunes)
	if len(observation.Details) > maxDetails {
		return Observation{}, errors.New("health component details exceed limit")
	}
	details := make(map[string]string, len(observation.Details))
	for key, value := range observation.Details {
		key = strings.TrimSpace(key)
		if key == "" {
			return Observation{}, errors.New("health component detail keys cannot be empty")
		}
		details[key] = bounded(value, maxDetailRunes)
	}
	observation.Details = details
	return observation, nil
}

func sameOperationalState(left, right Observation) bool {
	return left.Desired == right.Desired && left.Required == right.Required && left.State == right.State && left.Severity == right.Severity
}

func bounded(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func cloneDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	result := make(map[string]string, len(details))
	for key, value := range details {
		result[key] = value
	}
	return result
}
