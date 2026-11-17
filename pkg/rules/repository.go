package rules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var ErrRevisionConflict = errors.New("automation rule revision conflict")

type Repository struct{ store store.Store }

func NewRepository(ctx context.Context, backend store.Store) (*Repository, error) {
	if backend == nil {
		return nil, errors.New("automation repository requires a store")
	}
	for _, namespace := range []string{model.NSAutomationRules, model.NSAutomationRuns, model.NSAutomationEvidence} {
		exists, err := backend.NamespaceExists(ctx, namespace)
		if err != nil {
			return nil, fmt.Errorf("inspect %s namespace: %w", namespace, err)
		}
		if !exists {
			if err := backend.CreateNamespace(ctx, namespace); err != nil && !errors.Is(err, store.ErrExists) {
				return nil, fmt.Errorf("create %s namespace: %w", namespace, err)
			}
		}
	}
	return &Repository{store: backend}, nil
}

func (r *Repository) Load(ctx context.Context, ownerID string) (Document, error) {
	_, document, err := r.loadRaw(ctx, ownerID)
	return cloneDocument(document), err
}

func (r *Repository) Replace(ctx context.Context, ownerID, expectedRevision string, candidate Document) (Document, error) {
	if ownerID = strings.TrimSpace(ownerID); ownerID == "" || expectedRevision == "" {
		return Document{}, errors.New("owner and expected revision are required")
	}
	currentRaw, current, err := r.loadRaw(ctx, ownerID)
	if err != nil {
		return Document{}, err
	}
	if current.Revision != expectedRevision {
		return Document{}, fmt.Errorf("%w: expected %q, active %q", ErrRevisionConflict, expectedRevision, current.Revision)
	}
	revision, err := newID("")
	if err != nil {
		return Document{}, err
	}
	now := time.Now().UTC()
	candidate.Version, candidate.OwnerID, candidate.Revision, candidate.UpdatedAt = CurrentVersion, ownerID, revision, now
	for index := range candidate.Rules {
		if candidate.Rules[index].CreatedAt.IsZero() {
			candidate.Rules[index].CreatedAt = now
		}
		candidate.Rules[index].UpdatedAt = now
		candidate.Rules[index].Priority = index * 10
	}
	if err := ValidateDocument(candidate); err != nil {
		return Document{}, err
	}
	nextRaw, err := json.Marshal(candidate)
	if err != nil {
		return Document{}, fmt.Errorf("encode automation rules: %w", err)
	}
	if err := r.store.CompareAndSwap(ctx, model.NSAutomationRules, ownerID, currentRaw, nextRaw); err != nil {
		if errors.Is(err, store.ErrPreconditionFailed) || errors.Is(err, store.ErrNotFound) {
			return Document{}, fmt.Errorf("%w: active rules changed", ErrRevisionConflict)
		}
		return Document{}, fmt.Errorf("activate automation rules: %w", err)
	}
	return cloneDocument(candidate), nil
}

func (r *Repository) loadRaw(ctx context.Context, ownerID string) ([]byte, Document, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, Document{}, errors.New("automation owner is required")
	}
	raw, err := r.store.Get(ctx, model.NSAutomationRules, ownerID)
	if errors.Is(err, store.ErrNotFound) {
		initial := Document{Version: CurrentVersion, OwnerID: ownerID, Revision: "initial", Rules: []Rule{}, UpdatedAt: time.Now().UTC()}
		raw, err = json.Marshal(initial)
		if err != nil {
			return nil, Document{}, err
		}
		if err = r.store.Put(ctx, model.NSAutomationRules, ownerID, raw); errors.Is(err, store.ErrExists) {
			raw, err = r.store.Get(ctx, model.NSAutomationRules, ownerID)
		}
	}
	if err != nil {
		return nil, Document{}, fmt.Errorf("load automation rules: %w", err)
	}
	var document Document
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, Document{}, fmt.Errorf("decode automation rules: %w", err)
	}
	if err := ValidateDocument(document); err != nil {
		return nil, Document{}, fmt.Errorf("validate durable automation rules: %w", err)
	}
	return raw, document, nil
}

func (r *Repository) SaveRun(ctx context.Context, run Run) error {
	if run.ID == "" || run.OwnerID == "" {
		return errors.New("run ID and owner are required")
	}
	raw, err := json.Marshal(run)
	if err != nil {
		return err
	}
	if err := r.store.Set(ctx, model.NSAutomationRuns, runKey(run.OwnerID, run.ID), raw); err != nil {
		return fmt.Errorf("save automation run: %w", err)
	}
	if run.Status == RunQueued || run.Status == RunCompleted || run.Status == RunCompletedWithErrors || run.Status == RunFailed || run.Status == RunCancelled {
		return r.pruneRuns(ctx, run.OwnerID)
	}
	return nil
}

func (r *Repository) GetRun(ctx context.Context, ownerID, id string) (Run, error) {
	raw, err := r.store.Get(ctx, model.NSAutomationRuns, runKey(ownerID, id))
	if err != nil {
		return Run{}, err
	}
	var run Run
	if err := json.Unmarshal(raw, &run); err != nil {
		return Run{}, fmt.Errorf("decode automation run: %w", err)
	}
	return run, nil
}

func (r *Repository) ListRuns(ctx context.Context, ownerID string) ([]Run, error) {
	var result []Run
	err := r.store.Iterate(ctx, model.NSAutomationRuns, ownerID+"/", func(_ string, raw []byte) (bool, error) {
		var run Run
		if err := json.Unmarshal(raw, &run); err != nil {
			return false, err
		}
		result = append(result, run)
		return true, nil
	})
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, err
}

func (r *Repository) ActiveRuns(ctx context.Context) ([]Run, error) {
	var result []Run
	err := r.store.Iterate(ctx, model.NSAutomationRuns, "", func(_ string, raw []byte) (bool, error) {
		var run Run
		if err := json.Unmarshal(raw, &run); err != nil {
			return false, err
		}
		if run.Status == RunQueued || run.Status == RunRunning || run.Status == RunCancelling {
			result = append(result, run)
		}
		return true, nil
	})
	return result, err
}

func (r *Repository) SaveExecution(ctx context.Context, execution Execution) error {
	raw, err := json.Marshal(execution)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s/%020d/%s", execution.OwnerID, execution.StartedAt.UnixNano(), execution.ID)
	if err := r.store.Set(ctx, model.NSAutomationEvidence, key, raw); err != nil {
		return fmt.Errorf("save automation evidence: %w", err)
	}
	keys, err := r.store.Scan(ctx, model.NSAutomationEvidence, execution.OwnerID+"/")
	if err != nil {
		return err
	}
	for len(keys) > MaxEvidencePerOwner {
		if err := r.store.Delete(ctx, model.NSAutomationEvidence, keys[0]); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		keys = keys[1:]
	}
	return nil
}

func (r *Repository) ListEvidence(ctx context.Context, ownerID, ruleID string, limit int) ([]Execution, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	var result []Execution
	err := r.store.Iterate(ctx, model.NSAutomationEvidence, ownerID+"/", func(_ string, raw []byte) (bool, error) {
		var execution Execution
		if err := json.Unmarshal(raw, &execution); err != nil {
			return false, err
		}
		if ruleID == "" || execution.RuleID == ruleID {
			result = append(result, execution)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StartedAt.After(result[j].StartedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (r *Repository) pruneRuns(ctx context.Context, ownerID string) error {
	runs, err := r.ListRuns(ctx, ownerID)
	if err != nil {
		return err
	}
	for index := len(runs) - 1; len(runs) > MaxRunHistoryPerOwner && index >= 0; index-- {
		run := runs[index]
		if run.Status == RunQueued || run.Status == RunRunning || run.Status == RunCancelling {
			continue
		}
		if err := r.store.Delete(ctx, model.NSAutomationRuns, runKey(ownerID, run.ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		runs = append(runs[:index], runs[index+1:]...)
	}
	return nil
}

func runKey(ownerID, id string) string { return ownerID + "/" + id }

func newID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate automation identifier: %w", err)
	}
	return prefix + hex.EncodeToString(buffer), nil
}
