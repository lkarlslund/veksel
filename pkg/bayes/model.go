package bayes

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/spam"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Key layout inside a model's namespace. Values are compact JSON so account
// bundles carry them unchanged.
const (
	metaKey      = "meta"
	tokenPrefix  = "t:"
	recordPrefix = "r:"
	// pruneBatch bounds the deletions committed in one batch.
	pruneBatch = 1000
	// pruneTarget is the fraction of a cap a pruning pass shrinks to, so a
	// model at its cap is not pruned again by the next message.
	pruneTarget = 0.9
)

// Class is the trained class of a message.
type Class string

const (
	ClassSpam Class = "spam"
	ClassHam  Class = "ham"
)

// Source records who decided a training class.
type Source string

const (
	// SourceUser is an explicit action: a move into or out of Junk.
	SourceUser Source = "user"
	// SourceAuto is auto-learning at a confident score; an explicit action
	// always overrides it.
	SourceAuto Source = "auto"
)

// meta holds a model's message totals and approximate sizes.
type meta struct {
	Spam    uint32 `json:"spam"`
	Ham     uint32 `json:"ham"`
	Tokens  int    `json:"tokens"`
	Records int    `json:"records"`
	Updated int64  `json:"updated,omitempty"`
}

// record is how one message was trained, keyed by its sample key. Global
// reports that the shared model also learned it.
type record struct {
	Class  Class  `json:"c"`
	Source Source `json:"s"`
	Global bool   `json:"g,omitempty"`
	Day    uint32 `json:"d"`
}

// tokenValue is a token's spam count, ham count, and last-trained day.
type tokenValue [3]uint32

// tokenModel is one classifier's storage: an account's index namespace or the
// shared model in the system store.
type tokenModel struct {
	store     store.Store
	namespace string
}

func today() uint32 { return uint32(time.Now().Unix() / 86400) }

func (m tokenModel) ensure(ctx context.Context) error {
	exists, err := m.store.NamespaceExists(ctx, m.namespace)
	if err != nil || exists {
		return err
	}
	if err := m.store.CreateNamespace(ctx, m.namespace); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return nil
}

func (m tokenModel) getJSON(ctx context.Context, key string, value any) (bool, error) {
	data, err := m.store.Get(ctx, m.namespace, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, value)
}

func (m tokenModel) setJSON(ctx context.Context, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return m.store.Set(ctx, m.namespace, key, data)
}

func (m tokenModel) meta(ctx context.Context) (meta, error) {
	var value meta
	_, err := m.getJSON(ctx, metaKey, &value)
	return value, err
}

func (m tokenModel) record(ctx context.Context, key string) (record, bool, error) {
	var value record
	found, err := m.getJSON(ctx, recordPrefix+key, &value)
	return value, found, err
}

// counts reads the trained counts of tokens in one stable view.
func (m tokenModel) counts(ctx context.Context, tokens []string) (map[string]spam.TokenCounts, error) {
	counts := make(map[string]spam.TokenCounts, len(tokens))
	err := store.View(ctx, m.store, func(viewCtx context.Context) error {
		for _, token := range tokens {
			var value tokenValue
			found, err := m.getJSON(viewCtx, tokenPrefix+token, &value)
			if err != nil {
				return err
			}
			if found {
				counts[token] = spam.TokenCounts{Spam: value[0], Ham: value[1]}
			}
		}
		return nil
	})
	return counts, err
}

// train adds (delta 1) or removes (delta -1) one message of class with
// tokens. Callers run it inside a batch.
func (m tokenModel) train(ctx context.Context, current *meta, tokens []string, class Class, delta int) error {
	day := today()
	for _, token := range tokens {
		var value tokenValue
		found, err := m.getJSON(ctx, tokenPrefix+token, &value)
		if err != nil {
			return err
		}
		if !found && delta < 0 {
			continue
		}
		index := 1
		if class == ClassSpam {
			index = 0
		}
		value[index] = adjust(value[index], delta)
		if value[0] == 0 && value[1] == 0 {
			if found {
				if err := m.store.Delete(ctx, m.namespace, tokenPrefix+token); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
				current.Tokens = max(current.Tokens-1, 0)
			}
			continue
		}
		if delta > 0 {
			value[2] = day
		}
		if !found {
			current.Tokens++
		}
		if err := m.setJSON(ctx, tokenPrefix+token, value); err != nil {
			return err
		}
	}
	if class == ClassSpam {
		current.Spam = adjust(current.Spam, delta)
	} else {
		current.Ham = adjust(current.Ham, delta)
	}
	current.Updated = time.Now().Unix()
	return nil
}

func adjust(value uint32, delta int) uint32 {
	if delta < 0 {
		if value == 0 {
			return 0
		}
		return value - 1
	}
	return value + 1
}

// apply moves one message into class, untraining previous first when the
// message was trained the other way. It runs in its own batch.
func (m tokenModel) apply(ctx context.Context, tokens []string, previous, class Class) error {
	return store.Batch(ctx, m.store, func(batchCtx context.Context) error {
		current, err := m.meta(batchCtx)
		if err != nil {
			return err
		}
		if previous != "" && previous != class {
			if err := m.train(batchCtx, &current, tokens, previous, -1); err != nil {
				return err
			}
		}
		if class != "" {
			if err := m.train(batchCtx, &current, tokens, class, 1); err != nil {
				return err
			}
		}
		return m.setJSON(batchCtx, metaKey, current)
	})
}

type pruneCandidate struct {
	key      string
	priority int64
}

// prune deletes the least valuable tokens beyond maxTokens and the oldest
// training records beyond maxRecords. A token's value grows with its count
// and how recently it was trained, so rare, stale tokens go first.
func (m tokenModel) prune(ctx context.Context, maxTokens, maxRecords int) (int, int, error) {
	var tokens, records []pruneCandidate
	err := m.store.Iterate(ctx, m.namespace, "", func(key string, value []byte) (bool, error) {
		switch {
		case strings.HasPrefix(key, tokenPrefix):
			var counts tokenValue
			if json.Unmarshal(value, &counts) == nil {
				total := min(int64(counts[0])+int64(counts[1]), 8)
				tokens = append(tokens, pruneCandidate{key: key, priority: int64(counts[2]) + 7*total})
			}
		case strings.HasPrefix(key, recordPrefix):
			var trained record
			if json.Unmarshal(value, &trained) == nil {
				records = append(records, pruneCandidate{key: key, priority: int64(trained.Day)})
			}
		}
		return true, nil
	})
	if err != nil {
		return 0, 0, err
	}
	removedTokens, err := m.pruneCandidates(ctx, tokens, maxTokens, func(current *meta, removed int) {
		current.Tokens = len(tokens) - removed
	})
	if err != nil {
		return removedTokens, 0, err
	}
	removedRecords, err := m.pruneCandidates(ctx, records, maxRecords, func(current *meta, removed int) {
		current.Records = len(records) - removed
	})
	return removedTokens, removedRecords, err
}

func (m tokenModel) pruneCandidates(ctx context.Context, candidates []pruneCandidate, limit int, account func(*meta, int)) (int, error) {
	excess := 0
	if limit > 0 && len(candidates) > limit {
		excess = len(candidates) - int(float64(limit)*pruneTarget)
	}
	slices.SortFunc(candidates, func(a, b pruneCandidate) int { return cmp.Compare(a.priority, b.priority) })
	for start := 0; ; start += pruneBatch {
		end := min(start+pruneBatch, excess)
		err := store.Batch(ctx, m.store, func(batchCtx context.Context) error {
			for _, candidate := range candidates[start:end] {
				if err := m.store.Delete(batchCtx, m.namespace, candidate.key); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
			current, err := m.meta(batchCtx)
			if err != nil {
				return err
			}
			account(&current, end)
			return m.setJSON(batchCtx, metaKey, current)
		})
		if err != nil {
			return start, err
		}
		if end >= excess {
			return end, nil
		}
	}
}

// reset deletes the model.
func (m tokenModel) reset(ctx context.Context) error {
	if err := m.store.DeleteNamespace(ctx, m.namespace); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
