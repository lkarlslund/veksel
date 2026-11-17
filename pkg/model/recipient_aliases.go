package model

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

const MaxRecipientAliasTargets = 100

var (
	ErrRecipientAliasInvalid    = errors.New("invalid recipient alias")
	ErrRecipientAliasReferenced = errors.New("email identity is a recipient alias target")
)

type RecipientAliasStore struct{ ts *TypedStore }

func NewRecipientAliasStore(ts *TypedStore) *RecipientAliasStore {
	return &RecipientAliasStore{ts: ts}
}

func recipientAliasKey(address string) string { return strings.ToLower(strings.TrimSpace(address)) }

func normalizeRecipientAddress(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || strings.Count(value, "@") != 1 {
		return "", fmt.Errorf("%w: valid bare email address required", ErrRecipientAliasInvalid)
	}
	return value, nil
}

func (s *RecipientAliasStore) Get(ctx context.Context, address string) (RecipientAlias, error) {
	var alias RecipientAlias
	err := s.ts.Get(ctx, NSRecipientAliases, recipientAliasKey(address), &alias)
	return alias, err
}

func (s *RecipientAliasStore) List(ctx context.Context) ([]RecipientAlias, error) {
	keys, err := s.ts.List(ctx, NSRecipientAliases)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return []RecipientAlias{}, nil
		}
		return nil, err
	}
	result := make([]RecipientAlias, 0, len(keys))
	for _, key := range keys {
		alias, getErr := s.Get(ctx, key)
		if getErr != nil {
			return nil, getErr
		}
		result = append(result, alias)
	}
	slices.SortFunc(result, func(left, right RecipientAlias) int { return strings.Compare(left.Address, right.Address) })
	return result, nil
}

func (s *RecipientAliasStore) Create(ctx context.Context, address string, targets []string, enabled bool) (RecipientAlias, error) {
	now := time.Now().UTC()
	alias := RecipientAlias{Address: address, Targets: targets, Enabled: enabled, CreatedAt: now, UpdatedAt: now}
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		validated, err := s.validate(batchCtx, alias)
		if err != nil {
			return err
		}
		alias = validated
		return s.ts.Put(batchCtx, NSRecipientAliases, recipientAliasKey(alias.Address), alias)
	})
	return alias, err
}

func (s *RecipientAliasStore) Update(ctx context.Context, address string, targets []string, enabled bool) (RecipientAlias, error) {
	var alias RecipientAlias
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		current, err := s.Get(batchCtx, address)
		if err != nil {
			return err
		}
		current.Targets = targets
		current.Enabled = enabled
		current.UpdatedAt = time.Now().UTC()
		validated, err := s.validate(batchCtx, current)
		if err != nil {
			return err
		}
		alias = validated
		return s.ts.Set(batchCtx, NSRecipientAliases, recipientAliasKey(alias.Address), alias)
	})
	return alias, err
}

func (s *RecipientAliasStore) Delete(ctx context.Context, address string) error {
	return s.ts.Delete(ctx, NSRecipientAliases, recipientAliasKey(address))
}

// Expand returns terminal enabled local identities. A disabled alias is
// intentionally indistinguishable from an absent local recipient to SMTP.
func (s *RecipientAliasStore) Expand(ctx context.Context, address string) ([]string, error) {
	alias, err := s.Get(ctx, address)
	if err != nil {
		return nil, err
	}
	if !alias.Enabled {
		return nil, store.ErrNotFound
	}
	validated, err := s.validate(ctx, alias)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), validated.Targets...), nil
}

func (s *RecipientAliasStore) validate(ctx context.Context, alias RecipientAlias) (RecipientAlias, error) {
	address, err := normalizeRecipientAddress(alias.Address)
	if err != nil {
		return RecipientAlias{}, err
	}
	at := strings.LastIndex(address, "@")
	domainID := address[at+1:]
	domain, err := s.ts.DomainStore().Get(ctx, domainID)
	if err != nil || !domain.Enabled {
		return RecipientAlias{}, fmt.Errorf("%w: alias domain must be enabled and hosted", ErrRecipientAliasInvalid)
	}
	if _, err := s.ts.UserStore().GetEmailAddress(ctx, address); err == nil {
		return RecipientAlias{}, fmt.Errorf("%w: address is already an email identity", ErrRecipientAliasInvalid)
	} else if !errors.Is(err, store.ErrNotFound) {
		return RecipientAlias{}, err
	}
	if len(alias.Targets) == 0 || len(alias.Targets) > MaxRecipientAliasTargets {
		return RecipientAlias{}, fmt.Errorf("%w: between 1 and %d targets required", ErrRecipientAliasInvalid, MaxRecipientAliasTargets)
	}
	targets := make([]string, 0, len(alias.Targets))
	for _, raw := range alias.Targets {
		target, normalizeErr := normalizeRecipientAddress(raw)
		if normalizeErr != nil || target == address {
			return RecipientAlias{}, fmt.Errorf("%w: target %q must be a different local identity", ErrRecipientAliasInvalid, raw)
		}
		identity, identityErr := s.ts.UserStore().GetEmailAddress(ctx, target)
		if identityErr != nil || !identity.Enabled {
			return RecipientAlias{}, fmt.Errorf("%w: target %q is not an enabled local identity", ErrRecipientAliasInvalid, raw)
		}
		user, userErr := s.ts.UserStore().Get(ctx, identity.UserID)
		if userErr != nil || !user.Enabled {
			return RecipientAlias{}, fmt.Errorf("%w: target %q account is unavailable", ErrRecipientAliasInvalid, raw)
		}
		targets = append(targets, target)
	}
	slices.Sort(targets)
	targets = slices.Compact(targets)
	if len(targets) != len(alias.Targets) {
		return RecipientAlias{}, fmt.Errorf("%w: duplicate targets are not allowed", ErrRecipientAliasInvalid)
	}
	alias.Address = address
	alias.DomainID = domainID
	alias.Targets = targets
	return alias, nil
}

func (s *RecipientAliasStore) Referencing(ctx context.Context, target string) ([]RecipientAlias, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	aliases, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(aliases, func(alias RecipientAlias) bool { return !slices.Contains(alias.Targets, target) }), nil
}
