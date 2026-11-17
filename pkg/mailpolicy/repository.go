package mailpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const activeDocumentKey = "active"

// ErrRevisionConflict means the caller attempted to replace a policy revision
// that is no longer active.
var ErrRevisionConflict = errors.New("mail policy revision conflict")

// Repository persists the single active policy document in the generic system
// store. It retains JSON as canonical truth and uses byte-level CAS for atomic
// optimistic activation.
type Repository struct {
	store store.Store
}

func NewRepository(systemStore store.Store) *Repository {
	return &Repository{store: systemStore}
}

// Load returns a detached copy of the active document, creating the harmless
// empty initial policy on first use.
func (r *Repository) Load(ctx context.Context) (Document, error) {
	_, document, err := r.loadRaw(ctx)
	return cloneDocument(document), err
}

// Replace validates and atomically activates candidate when expectedRevision
// is still current. The returned compiled snapshot exactly matches the durable
// document committed by this call.
func (r *Repository) Replace(ctx context.Context, expectedRevision string, candidate Document) (Document, *Compiled, error) {
	if expectedRevision == "" {
		return Document{}, nil, errors.New("expected mail policy revision is required")
	}
	currentRaw, current, err := r.loadRaw(ctx)
	if err != nil {
		return Document{}, nil, err
	}
	if current.Revision != expectedRevision {
		return Document{}, nil, fmt.Errorf("%w: expected %q, active %q", ErrRevisionConflict, expectedRevision, current.Revision)
	}
	revision, err := newRevision()
	if err != nil {
		return Document{}, nil, err
	}
	candidate.Version = CurrentVersion
	candidate.Revision = revision
	compiled, err := Compile(candidate)
	if err != nil {
		return Document{}, nil, err
	}
	nextRaw, err := json.Marshal(candidate)
	if err != nil {
		return Document{}, nil, fmt.Errorf("encode mail policy: %w", err)
	}
	if err := r.store.CompareAndSwap(ctx, model.NSMailPolicies, activeDocumentKey, currentRaw, nextRaw); err != nil {
		if errors.Is(err, store.ErrPreconditionFailed) || errors.Is(err, store.ErrNotFound) {
			return Document{}, nil, fmt.Errorf("%w: active policy changed", ErrRevisionConflict)
		}
		return Document{}, nil, fmt.Errorf("activate mail policy: %w", err)
	}
	return cloneDocument(candidate), compiled, nil
}

func (r *Repository) loadRaw(ctx context.Context) ([]byte, Document, error) {
	if r == nil || r.store == nil {
		return nil, Document{}, errors.New("mail policy repository has no store")
	}
	if err := ensureNamespace(ctx, r.store); err != nil {
		return nil, Document{}, err
	}
	raw, err := r.store.Get(ctx, model.NSMailPolicies, activeDocumentKey)
	if errors.Is(err, store.ErrNotFound) {
		initial := Document{Version: CurrentVersion, Revision: "initial", Rules: []Rule{}}
		raw, err = json.Marshal(initial)
		if err != nil {
			return nil, Document{}, fmt.Errorf("encode initial mail policy: %w", err)
		}
		if err = r.store.Put(ctx, model.NSMailPolicies, activeDocumentKey, raw); errors.Is(err, store.ErrExists) {
			raw, err = r.store.Get(ctx, model.NSMailPolicies, activeDocumentKey)
		}
	}
	if err != nil {
		return nil, Document{}, fmt.Errorf("load mail policy: %w", err)
	}
	var document Document
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, Document{}, fmt.Errorf("decode mail policy: %w", err)
	}
	if _, err := Compile(document); err != nil {
		return nil, Document{}, fmt.Errorf("validate durable mail policy: %w", err)
	}
	return raw, document, nil
}

func ensureNamespace(ctx context.Context, backend store.Store) error {
	exists, err := backend.NamespaceExists(ctx, model.NSMailPolicies)
	if err != nil {
		return fmt.Errorf("inspect mail policy namespace: %w", err)
	}
	if exists {
		return nil
	}
	if err := backend.CreateNamespace(ctx, model.NSMailPolicies); err != nil && !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("create mail policy namespace: %w", err)
	}
	return nil
}

func newRevision() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate mail policy revision: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// NewRuleID returns an unpredictable identifier suitable for a new rule.
func NewRuleID() (string, error) {
	revision, err := newRevision()
	if err != nil {
		return "", err
	}
	return "rule_" + revision, nil
}

func cloneDocument(document Document) Document {
	document.Rules = cloneRules(document.Rules)
	return document
}

func cloneRules(rules []Rule) []Rule {
	result := make([]Rule, len(rules))
	for index, rule := range rules {
		rule.Conditions = cloneConditions(rule.Conditions)
		rule.Exceptions = cloneConditions(rule.Exceptions)
		rule.Actions = append([]Action(nil), rule.Actions...)
		result[index] = rule
	}
	return result
}
