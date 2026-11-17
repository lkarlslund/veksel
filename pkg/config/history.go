package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	configHistoryDirName = "config-history"
	MaxHistoryRevisions  = 50
	redactedValue        = "[redacted]"
	maxHistoryMetadata   = 4 << 20
)

type MutationMetadata struct {
	Actor  string
	Reason string
	Source string
}

type Change struct {
	Key       string `json:"key"`
	Before    any    `json:"before,omitempty"`
	After     any    `json:"after,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

type RevisionEntry struct {
	ID             string    `json:"id"`
	Revision       string    `json:"revision"`
	ParentRevision string    `json:"parent_revision,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	Actor          string    `json:"actor"`
	Reason         string    `json:"reason,omitempty"`
	Source         string    `json:"source"`
	Changes        []Change  `json:"changes"`
}

func normalizeMutation(metadata MutationMetadata) MutationMetadata {
	metadata.Actor = boundedHistoryText(metadata.Actor, 256)
	metadata.Reason = boundedHistoryText(metadata.Reason, 1024)
	metadata.Source = boundedHistoryText(metadata.Source, 64)
	if metadata.Actor == "" {
		metadata.Actor = "system"
	}
	if metadata.Source == "" {
		metadata.Source = "patch"
	}
	return metadata
}

func boundedHistoryText(value string, limit int) string {
	value = strings.Map(func(character rune) rune {
		if character == '\r' || character == '\n' || character == '\t' {
			return ' '
		}
		if character < 32 || character == 127 {
			return -1
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return value
}

func (s *Service) prepareRevision(previousContents, nextContents []byte, previous, next *Config, metadata MutationMetadata) (RevisionEntry, error) {
	metadata = normalizeMutation(metadata)
	entry := RevisionEntry{
		Revision: revision(nextContents), CreatedAt: time.Now().UTC(), Actor: metadata.Actor,
		Reason: metadata.Reason, Source: metadata.Source, Changes: configurationDiff(previous, next, s.schema),
	}
	entry.ID = fmt.Sprintf("%020d-%s", entry.CreatedAt.UnixNano(), entry.Revision[:12])
	if len(previousContents) > 0 {
		entry.ParentRevision = revision(previousContents)
	}
	snapshotPath := s.historySnapshotPath(entry.Revision)
	if _, err := os.Stat(snapshotPath); errors.Is(err, fs.ErrNotExist) {
		if err := atomicWrite(snapshotPath, nextContents, 0o600); err != nil {
			return RevisionEntry{}, fmt.Errorf("write configuration history snapshot: %w", err)
		}
	} else if err != nil {
		return RevisionEntry{}, err
	}
	encoded, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return RevisionEntry{}, err
	}
	encoded = append(encoded, '\n')
	if err := atomicWrite(s.historyMetadataPath(entry.ID), encoded, 0o600); err != nil {
		return RevisionEntry{}, fmt.Errorf("write configuration history metadata: %w", err)
	}
	return entry, nil
}

func configurationDiff(previous, next *Config, schema []SettingSpec) []Change {
	before := publicConfigValues(previous)
	after := publicConfigValues(next)
	changes := make([]Change, 0)
	for _, spec := range schema {
		left, right := before[spec.Key], after[spec.Key]
		if reflect.DeepEqual(left, right) {
			continue
		}
		change := Change{Key: spec.Key, Before: left, After: right, Sensitive: spec.Sensitive}
		if spec.Sensitive {
			change.Before, change.After = redactedValue, redactedValue
		}
		changes = append(changes, change)
	}
	return changes
}

func publicConfigValues(cfg *Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}
	encoded, err := toml.Marshal(cfg)
	if err != nil {
		return map[string]any{}
	}
	values := make(map[string]any)
	if err := toml.Unmarshal(encoded, &values); err != nil {
		return map[string]any{}
	}
	return values
}

func (s *Service) History(limit int) ([]RevisionEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > MaxHistoryRevisions {
		limit = MaxHistoryRevisions
	}
	return s.historyLocked(limit)
}

func (s *Service) RestoreRevision(expectedRevision, targetRevision string, metadata MutationMetadata) (Snapshot, RevisionEntry, error) {
	snapshot, entry, _, err := s.RestoreRevisionWithPlan(expectedRevision, targetRevision, metadata)
	return snapshot, entry, err
}

// RestoreRevisionWithPlan restores and returns the exact dependency-aware plan
// prepared under the same revision lock.
func (s *Service) RestoreRevisionWithPlan(expectedRevision, targetRevision string, metadata MutationMetadata) (Snapshot, RevisionEntry, ChangePlan, error) {
	if !validRevision(targetRevision) {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, errors.New("valid target revision is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedRevision == "" || expectedRevision != s.revision {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, ErrRevisionConflict
	}
	if targetRevision == s.revision {
		plan := ChangePlan{BaseRevision: s.revision, ProposedRevision: s.revision}
		return Snapshot{Config: clone(s.desired), Revision: s.revision, Schema: slices.Clone(s.schema)}, RevisionEntry{}, plan, nil
	}
	targetContents, err := os.ReadFile(s.historySnapshotPath(targetRevision))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Snapshot{}, RevisionEntry{}, ChangePlan{}, storeNotFoundRevision(targetRevision)
		}
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	if revision(targetContents) != targetRevision {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, errors.New("configuration history snapshot checksum mismatch")
	}
	candidate, err := s.decode(targetContents)
	if err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	currentContents, err := os.ReadFile(s.path)
	if err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	if revision(currentContents) != s.revision {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, fmt.Errorf("%w: configuration file changed outside Veksel; reload it before restoring", ErrRevisionConflict)
	}
	prepared, err := s.prepareCandidatePlanLocked(currentContents, targetContents, candidate)
	if err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	if err := atomicWrite(filepath.Join(s.dataDir, previousConfigFileName), currentContents, 0o600); err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	metadata.Source = "restore"
	entry, err := s.prepareRevision(currentContents, targetContents, s.desired, candidate, metadata)
	if err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	if err := s.pruneHistoryLocked(); err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	if err := atomicWrite(s.path, targetContents, 0o600); err != nil {
		return Snapshot{}, RevisionEntry{}, ChangePlan{}, err
	}
	s.desired = clone(candidate)
	s.revision = targetRevision
	return Snapshot{Config: clone(candidate), Revision: targetRevision, Schema: slices.Clone(s.schema)}, entry, prepared.ChangePlan, nil
}

func storeNotFoundRevision(revision string) error {
	return fmt.Errorf("configuration revision %s is not retained", revision)
}

func (s *Service) historyLocked(limit int) ([]RevisionEntry, error) {
	entries, err := os.ReadDir(s.historyDir)
	if err != nil {
		return nil, err
	}
	result := make([]RevisionEntry, 0, len(entries)/2)
	for _, file := range entries {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.historyDir, file.Name()))
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > maxHistoryMetadata {
			return nil, fmt.Errorf("configuration history %q exceeds the metadata limit", file.Name())
		}
		var entry RevisionEntry
		if decodeErr := json.Unmarshal(data, &entry); decodeErr != nil {
			return nil, fmt.Errorf("decode configuration history %q: %w", file.Name(), decodeErr)
		}
		if !validRevision(entry.Revision) {
			return nil, fmt.Errorf("invalid configuration history revision %q", entry.Revision)
		}
		// The directory entry, not mutable JSON metadata, is authoritative for
		// later pruning paths. A malformed embedded ID must never influence an
		// os.Remove target.
		entry.ID = strings.TrimSuffix(file.Name(), ".json")
		if entry.ParentRevision != "" && !validRevision(entry.ParentRevision) {
			entry.ParentRevision = ""
		}
		entry.Actor = boundedHistoryText(entry.Actor, 256)
		entry.Reason = boundedHistoryText(entry.Reason, 1024)
		entry.Source = boundedHistoryText(entry.Source, 64)
		entry.Changes = sanitizeHistoryChanges(entry.Changes, s.schema)
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].Revision > result[j].Revision
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	if limit <= 0 || limit > len(result) {
		limit = len(result)
	}
	return slices.Clone(result[:min(limit, len(result))]), nil
}

// sanitizeHistoryChanges treats retained metadata as untrusted presentation
// input. The current schema remains authoritative for known keys, ordering and
// sensitivity, while unknown or duplicate records are omitted.
func sanitizeHistoryChanges(changes []Change, schema []SettingSpec) []Change {
	byKey := make(map[string]Change, len(changes))
	for _, change := range changes {
		if _, duplicate := byKey[change.Key]; !duplicate {
			byKey[change.Key] = change
		}
	}
	result := make([]Change, 0, min(len(changes), len(schema)))
	for _, spec := range schema {
		change, found := byKey[spec.Key]
		if !found {
			continue
		}
		change.Key = spec.Key
		change.Sensitive = change.Sensitive || spec.Sensitive
		if change.Sensitive {
			change.Before, change.After = redactedValue, redactedValue
		}
		result = append(result, change)
	}
	return result
}

func (s *Service) pruneHistoryLocked() error {
	entries, err := s.historyLocked(MaxHistoryRevisions + 1)
	if err != nil {
		return err
	}
	if len(entries) <= MaxHistoryRevisions {
		return nil
	}
	for _, entry := range entries[MaxHistoryRevisions:] {
		if err := os.Remove(s.historyMetadataPath(entry.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	retained, err := s.historyLocked(MaxHistoryRevisions)
	if err != nil {
		return err
	}
	referenced := map[string]bool{s.revision: true}
	for _, entry := range retained {
		referenced[entry.Revision] = true
	}
	files, err := os.ReadDir(s.historyDir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".toml" {
			continue
		}
		revision := strings.TrimSuffix(file.Name(), ".toml")
		if !referenced[revision] {
			if err := os.Remove(filepath.Join(s.historyDir, file.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func (s *Service) historyMetadataPath(id string) string {
	return filepath.Join(s.historyDir, id+".json")
}

func (s *Service) historySnapshotPath(revision string) string {
	return filepath.Join(s.historyDir, revision+".toml")
}

func validRevision(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
