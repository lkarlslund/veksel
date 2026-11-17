package mailpolicy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type serviceState struct {
	document Document
	compiled *Compiled
	stats    *runtimeStats
}

type runtimeStats struct {
	evaluations atomic.Uint64
	matched     atomic.Uint64
	rejected    atomic.Uint64
	quarantined atomic.Uint64
	routed      atomic.Uint64
	lastAt      atomic.Int64
	byRule      sync.Map
}

type ruleCounter struct{ matches atomic.Uint64 }

// Stats is a constant-time snapshot for the current effective revision.
type Stats struct {
	Revision        string            `json:"revision"`
	Evaluations     uint64            `json:"evaluations"`
	Matched         uint64            `json:"matched"`
	Rejected        uint64            `json:"rejected"`
	Quarantined     uint64            `json:"quarantined"`
	Routed          uint64            `json:"routed"`
	LastEvaluatedAt time.Time         `json:"last_evaluated_at,omitzero"`
	RuleMatches     map[string]uint64 `json:"rule_matches"`
}

// Service owns the effective compiled policy snapshot. Reads are lock-free;
// replacement is serialized so a later durable CAS can never be overwritten
// in memory by an earlier updater completing out of order.
type Service struct {
	repository *Repository
	updateMu   sync.Mutex
	state      atomic.Pointer[serviceState]
}

func NewService(ctx context.Context, repository *Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("mail policy repository is required")
	}
	document, err := repository.Load(ctx)
	if err != nil {
		return nil, err
	}
	compiled, err := Compile(document)
	if err != nil {
		return nil, err
	}
	service := &Service{repository: repository}
	service.state.Store(&serviceState{document: cloneDocument(document), compiled: compiled, stats: &runtimeStats{}})
	return service, nil
}

// Document returns a detached copy of the effective policy document.
func (s *Service) Document() Document {
	state := s.state.Load()
	if state == nil {
		return Document{}
	}
	return cloneDocument(state.document)
}

// Evaluate uses one immutable revision even while a policy replacement is in
// progress.
func (s *Service) Evaluate(message Message) Result {
	state := s.state.Load()
	if state == nil || state.compiled == nil {
		return Result{}
	}
	result := state.compiled.Evaluate(message)
	stats := state.stats
	stats.evaluations.Add(1)
	stats.lastAt.Store(time.Now().UTC().UnixNano())
	matched := result.MatchedRuleIDs()
	if len(matched) > 0 {
		stats.matched.Add(1)
	}
	for _, id := range matched {
		value, _ := stats.byRule.LoadOrStore(id, &ruleCounter{})
		value.(*ruleCounter).matches.Add(1)
	}
	decision := result.Decision()
	if decision.Reject != nil {
		stats.rejected.Add(1)
	}
	if decision.Quarantine != nil {
		stats.quarantined.Add(1)
	}
	if decision.Route != nil {
		stats.routed.Add(1)
	}
	return result
}

// Simulate evaluates the current snapshot without changing runtime counters.
func (s *Service) Simulate(message Message) Result {
	state := s.state.Load()
	if state == nil || state.compiled == nil {
		return Result{}
	}
	return state.compiled.Evaluate(message)
}

// Stats returns counters for the current revision without reading traces or
// queue records. Replacing policy starts a fresh revision-scoped snapshot.
func (s *Service) Stats() Stats {
	state := s.state.Load()
	if state == nil || state.stats == nil {
		return Stats{RuleMatches: map[string]uint64{}}
	}
	stats := Stats{Revision: state.document.Revision, Evaluations: state.stats.evaluations.Load(), Matched: state.stats.matched.Load(), Rejected: state.stats.rejected.Load(), Quarantined: state.stats.quarantined.Load(), Routed: state.stats.routed.Load(), RuleMatches: make(map[string]uint64)}
	if timestamp := state.stats.lastAt.Load(); timestamp > 0 {
		stats.LastEvaluatedAt = time.Unix(0, timestamp).UTC()
	}
	state.stats.byRule.Range(func(key, value any) bool {
		stats.RuleMatches[key.(string)] = value.(*ruleCounter).matches.Load()
		return true
	})
	return stats
}

// Replace validates, durably activates, and then publishes a candidate. A
// failed validation, write, or revision guard leaves the working snapshot
// untouched.
func (s *Service) Replace(ctx context.Context, expectedRevision string, candidate Document) (Document, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	document, compiled, err := s.repository.Replace(ctx, expectedRevision, candidate)
	if err != nil {
		return Document{}, err
	}
	s.state.Store(&serviceState{document: cloneDocument(document), compiled: compiled, stats: &runtimeStats{}})
	return cloneDocument(document), nil
}
