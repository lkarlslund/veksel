package config

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// ApplyState names the relationship between a desired setting and the value
// currently used by the running process.
type ApplyState string

const (
	ApplyEffective      ApplyState = "effective"
	ApplyPendingRestart ApplyState = "pending_restart"
	ApplyApplying       ApplyState = "applying"
	ApplyFailed         ApplyState = "failed"
)

const maxApplyErrorRunes = 512

// SettingApplyStatus is the detached, secret-safe operational state of one
// public setting. Desired and Effective are redacted for sensitive settings.
type SettingApplyStatus struct {
	Key             string     `json:"key"`
	Desired         any        `json:"desired,omitempty"`
	Effective       any        `json:"effective,omitempty"`
	State           ApplyState `json:"state"`
	RestartRequired bool       `json:"restart_required"`
	AttemptedAt     time.Time  `json:"attempted_at,omitzero"`
	Error           string     `json:"error,omitempty"`
}

type applyEvidence struct {
	state       ApplyState
	attemptedAt time.Time
	err         string
	desired     any
}

// ApplyStates returns every setting in schema order. It never exposes a
// sensitive desired or effective value.
func (s *Service) ApplyStates() []SettingApplyStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.applyStatesLocked()
}

func (s *Service) applyStatesLocked() []SettingApplyStatus {
	desired := publicConfigValues(s.desired)
	result := make([]SettingApplyStatus, 0, len(s.schema))
	for _, spec := range s.schema {
		wanted, active := desired[spec.Key], s.effective[spec.Key]
		state := ApplyEffective
		if !reflect.DeepEqual(wanted, active) {
			state = ApplyPendingRestart
		}
		evidence := s.apply[spec.Key]
		evidenceCurrent := reflect.DeepEqual(evidence.desired, wanted) && (evidence.state == ApplyApplying || evidence.state == ApplyFailed)
		if evidenceCurrent {
			state = evidence.state
		}
		status := SettingApplyStatus{
			Key: spec.Key, Desired: wanted, Effective: active, State: state,
			RestartRequired: spec.RestartRequired,
		}
		if evidenceCurrent {
			status.AttemptedAt, status.Error = evidence.attemptedAt, evidence.err
		}
		if spec.Sensitive {
			status.Desired, status.Effective = redactedValue, redactedValue
		}
		result = append(result, status)
	}
	return result
}

// MarkApplying records that a runtime owner has started applying keys. The
// keys must come from the public schema so callers cannot create ghost state.
func (s *Service) MarkApplying(keys ...string) error {
	return s.markApply(keys, ApplyApplying, nil)
}

// MarkEffective promotes the current desired values for keys to the effective
// process snapshot after their runtime owner has accepted the change.
func (s *Service) MarkEffective(keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.validApplyKeysLocked(keys)
	if err != nil {
		return err
	}
	desired := publicConfigValues(s.desired)
	for _, key := range keys {
		s.effective[key] = desired[key]
		delete(s.apply, key)
	}
	return nil
}

// MarkFailed records bounded failure evidence without changing either the
// desired value or the last known effective value.
func (s *Service) MarkFailed(err error, keys ...string) error {
	if err == nil {
		return errors.New("apply failure is required")
	}
	return s.markApply(keys, ApplyFailed, err)
}

func (s *Service) markApply(keys []string, state ApplyState, applyErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.validApplyKeysLocked(keys)
	if err != nil {
		return err
	}
	desired := publicConfigValues(s.desired)
	evidence := applyEvidence{state: state, attemptedAt: time.Now().UTC()}
	if applyErr != nil {
		evidence.err = boundedApplyError(applyErr.Error())
	}
	for _, key := range keys {
		item := evidence
		item.desired = desired[key]
		s.apply[key] = item
	}
	return nil
}

func (s *Service) validApplyKeysLocked(keys []string) ([]string, error) {
	keys = slices.Compact(slices.Sorted(slices.Values(keys)))
	if len(keys) == 0 {
		return nil, errors.New("at least one setting key is required")
	}
	known := make(map[string]struct{}, len(s.schema))
	for _, spec := range s.schema {
		known[spec.Key] = struct{}{}
	}
	for _, key := range keys {
		if _, ok := known[key]; !ok {
			return nil, fmt.Errorf("unknown setting %q", key)
		}
	}
	return keys, nil
}

func boundedApplyError(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > maxApplyErrorRunes {
		value = string(runes[:maxApplyErrorRunes])
	}
	return value
}
