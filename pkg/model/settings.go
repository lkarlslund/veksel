// Package model — runtime settings persisted to the KV store.
package model

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const NSSettings = "settings"

// Setting represents a single runtime-overridden config value.
// When a setting is saved, its ValueJSON is stored in the KV store under
// the NSSettings namespace.  The SettingsStore merges overrides with the
// boot-time config so the UI always shows the effective value.
type Setting struct {
	// Key is the dotted config path, e.g. "smtp.max_message_size".
	Key string `json:"key"`
	// Label is the human-readable name shown in the UI.
	Label string `json:"label"`
	// Category determines the tab the setting appears under.
	Category string `json:"category"`
	// Type controls the UI widget: string, int, int64, bool, enum, duration.
	Type string `json:"type"`
	// Description is shown as helper text.
	Description string `json:"description"`
	// ValueJSON holds the current (effective) value as a JSON-encoded value.
	ValueJSON json.RawMessage `json:"value"`
	// DefaultJSON holds the default (boot-time) value.
	DefaultJSON json.RawMessage `json:"default"`
	// EnumOptions lists allowed values when Type is "enum".
	EnumOptions []string `json:"enumOptions,omitempty"`
	// RestartRequired is true when a change needs a server restart.
	RestartRequired bool `json:"restartRequired"`
	// Sensitive masks the value in the UI (e.g. passwords).
	Sensitive bool `json:"sensitive"`
	// Advanced hides uncommon tuning values in the normal configuration view.
	Advanced bool `json:"advanced"`
	// Min/Max are validation bounds for numeric types.
	Min float64 `json:"min,omitempty"`
	Max float64 `json:"max,omitempty"`
	// Placeholder is a hint shown when the value is empty.
	Placeholder string `json:"placeholder,omitempty"`
}

// BoolValue returns the value as a bool.
func (s *Setting) BoolValue() bool {
	var v bool
	if err := json.Unmarshal(s.ValueJSON, &v); err == nil {
		return v
	}
	return false
}

// StringValue returns the value as a string.
func (s *Setting) StringValue() string {
	var v string
	if err := json.Unmarshal(s.ValueJSON, &v); err == nil {
		return v
	}
	return ""
}

// IntValue returns the value as an int.
func (s *Setting) IntValue() int {
	var v float64
	if err := json.Unmarshal(s.ValueJSON, &v); err == nil {
		return int(v)
	}
	return 0
}

// Int64Value returns the value as an int64.
func (s *Setting) Int64Value() int64 {
	var v float64
	if err := json.Unmarshal(s.ValueJSON, &v); err == nil {
		return int64(v)
	}
	return 0
}

// DefaultValueString returns the default value as a human-readable string.
func (s *Setting) DefaultValueString() string {
	if s.DefaultJSON == nil {
		return ""
	}
	switch s.Type {
	case "bool":
		var v bool
		json.Unmarshal(s.DefaultJSON, &v) //nolint
		return strconv.FormatBool(v)
	case "int", "int64":
		var v float64
		json.Unmarshal(s.DefaultJSON, &v) //nolint
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		var v string
		json.Unmarshal(s.DefaultJSON, &v) //nolint
		return v
	}
}

// SettingsStore provides CRUD operations for runtime settings.
type SettingsStore struct {
	ts *TypedStore
}

// NewSettingsStore creates a SettingsStore backed by ts.
func NewSettingsStore(ts *TypedStore) *SettingsStore {
	return &SettingsStore{ts: ts}
}

// GetOverride returns the user-saved override for key, or ErrNotFound when no
// override exists yet.
func (s *SettingsStore) GetOverride(ctx context.Context, key string) (json.RawMessage, error) {
	data, err := s.ts.s.Get(ctx, NSSettings, key)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// SetOverride persists a new override value for key.
func (s *SettingsStore) SetOverride(ctx context.Context, key string, value json.RawMessage) error {
	return s.ts.s.Set(ctx, NSSettings, key, value)
}

// DeleteOverride removes a previously saved override.
func (s *SettingsStore) DeleteOverride(ctx context.Context, key string) error {
	return s.ts.s.Delete(ctx, NSSettings, key)
}

// ListOverrides returns all keys that have a user override.
func (s *SettingsStore) ListOverrides(ctx context.Context) ([]string, error) {
	return s.ts.s.List(ctx, NSSettings)
}

// BuildEffectiveSettings returns the full list of settings with effective
// values (override when present, default otherwise).
// cfg supplies the boot-time defaults; overrides are merged from the store.
func (s *SettingsStore) BuildEffectiveSettings(ctx context.Context, defaults []Setting) ([]Setting, error) {
	overrides, err := s.ListOverrides(ctx)
	if err != nil {
		return nil, fmt.Errorf("list settings overrides: %w", err)
	}
	overrideMap := make(map[string]json.RawMessage)
	for _, key := range overrides {
		data, err := s.GetOverride(ctx, key)
		if err != nil {
			continue
		}
		overrideMap[key] = data
	}

	out := make([]Setting, 0, len(defaults))
	for _, d := range defaults {
		s := d
		if ov, ok := overrideMap[d.Key]; ok {
			s.ValueJSON = ov
		} else {
			s.ValueJSON = s.DefaultJSON
		}
		out = append(out, s)
	}
	return out, nil
}

// Validate checks the new value against the setting constraints and returns an
// error when the value is invalid.
func Validate(s Setting, newValue json.RawMessage) error {
	switch s.Type {
	case "bool":
		var v bool
		if err := json.Unmarshal(newValue, &v); err != nil {
			// Accept string "true"/"false" as well
			var sv string
			if err2 := json.Unmarshal(newValue, &sv); err2 != nil {
				return fmt.Errorf("invalid boolean value")
			}
			if !slices.Contains([]string{"true", "false", "1", "0", "on", "off"}, strings.ToLower(sv)) {
				return fmt.Errorf("invalid boolean value: %q", sv)
			}
		}
		return nil

	case "int", "int64":
		var v float64
		if err := json.Unmarshal(newValue, &v); err != nil {
			// Try parsing from string (form inputs are strings)
			var sv string
			if err2 := json.Unmarshal(newValue, &sv); err2 != nil {
				return fmt.Errorf("invalid numeric value")
			}
			n, err3 := strconv.ParseFloat(sv, 64)
			if err3 != nil {
				return fmt.Errorf("invalid numeric value: %q", sv)
			}
			v = n
		}
		if s.Min > 0 && v < s.Min {
			return fmt.Errorf("value %.0f is less than minimum %.0f", v, s.Min)
		}
		if s.Max > 0 && v > s.Max {
			return fmt.Errorf("value %.0f is greater than maximum %.0f", v, s.Max)
		}
		return nil

	case "enum":
		var v string
		if err := json.Unmarshal(newValue, &v); err != nil {
			return fmt.Errorf("invalid value")
		}
		if len(s.EnumOptions) > 0 && !slices.Contains(s.EnumOptions, v) {
			return fmt.Errorf("value %q is not one of %v", v, s.EnumOptions)
		}
		return nil

	case "checklist":
		var value string
		if err := json.Unmarshal(newValue, &value); err != nil {
			return fmt.Errorf("invalid checklist value")
		}
		for _, option := range strings.Split(value, ",") {
			option = strings.TrimSpace(option)
			if option != "" && !slices.Contains(s.EnumOptions, option) {
				return fmt.Errorf("value %q is not one of %v", option, s.EnumOptions)
			}
		}
		return nil

	case "list":
		var value []string
		if err := json.Unmarshal(newValue, &value); err != nil {
			return fmt.Errorf("invalid string list")
		}
		return nil

	case "string", "duration", "certificate":
		// Any non-null string is valid.
		var v string
		if err := json.Unmarshal(newValue, &v); err != nil {
			return fmt.Errorf("invalid string value")
		}
		return nil

	default:
		return nil
	}
}
