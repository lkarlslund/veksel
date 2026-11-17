package config

import (
	"fmt"
	"slices"
)

// Applier applies accepted settings from cfg to a running component. It is
// called after a change is persisted and must leave the component consistent
// whether it succeeds or fails.
type Applier func(cfg *Config) error

type applierGroup struct {
	keys  []string
	apply Applier
}

// RegisterApplier makes keys apply live: when any of them changes, apply runs
// with the new configuration and the keys' apply state records the outcome.
// A setting without a registered applier requires a restart. Keys must be
// schema settings and each key may have only one applier.
func (s *Service) RegisterApplier(apply Applier, keys ...string) error {
	if apply == nil || len(keys) == 0 {
		return fmt.Errorf("applier requires a function and at least one key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validApplyKeysLocked(keys); err != nil {
		return err
	}
	for _, group := range s.appliers {
		for _, key := range keys {
			if slices.Contains(group.keys, key) {
				return fmt.Errorf("setting %q already has a live applier", key)
			}
		}
	}
	s.appliers = append(s.appliers, applierGroup{keys: slices.Clone(keys), apply: apply})
	for i := range s.schema {
		if slices.Contains(keys, s.schema[i].Key) {
			s.schema[i].RestartRequired = false
		}
	}
	return nil
}

// Apply runs the appliers for the requested keys (every applier when
// requested is nil) against snapshot and records applying, effective, or
// failed state for each affected key.
func (s *Service) Apply(snapshot Snapshot, requested map[string]any) {
	if snapshot.Config == nil {
		return
	}
	s.mu.RLock()
	groups := slices.Clone(s.appliers)
	s.mu.RUnlock()
	for _, group := range groups {
		keys := selectedKeys(group.keys, requested)
		if len(keys) == 0 {
			continue
		}
		if err := s.MarkApplying(keys...); err != nil {
			continue
		}
		if err := group.apply(snapshot.Config); err != nil {
			_ = s.MarkFailed(err, keys...)
			continue
		}
		_ = s.MarkEffective(keys...)
	}
}

// UnappliedKeys lists settings that still require a restart because no live
// applier is registered for them.
func (s *Service) UnappliedKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for _, spec := range s.schema {
		if spec.RestartRequired {
			keys = append(keys, spec.Key)
		}
	}
	return keys
}

func selectedKeys(group []string, requested map[string]any) []string {
	if requested == nil {
		return slices.Clone(group)
	}
	var selected []string
	for _, key := range group {
		if _, ok := requested[key]; ok {
			selected = append(selected, key)
		}
	}
	return selected
}
