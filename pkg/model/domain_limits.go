package model

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// ErrDomainLimit reports a create or update that a domain limit rejects.
var ErrDomainLimit = errors.New("domain limit reached")

// maxDomainSendLimit mirrors the sending guard's per-value ceiling so domain
// defaults are validated without importing it.
const maxDomainSendLimit = 10_000_000

// Validate rejects negative values and defaults that exceed their ceilings.
func (l DomainLimits) Validate() error {
	if l.MaxAccounts < 0 || l.MaxAliases < 0 || l.MaxStorageBytes < 0 || l.DefaultAccountStorageBytes < 0 || l.MaxAccountStorageBytes < 0 {
		return fmt.Errorf("domain limits cannot be negative")
	}
	if l.MaxAccountStorageBytes > 0 && l.DefaultAccountStorageBytes > l.MaxAccountStorageBytes {
		return fmt.Errorf("the default account quota exceeds the maximum account quota")
	}
	if l.MaxStorageBytes > 0 && (l.DefaultAccountStorageBytes > l.MaxStorageBytes || l.MaxAccountStorageBytes > l.MaxStorageBytes) {
		return fmt.Errorf("account quotas cannot exceed the domain storage ceiling")
	}
	if l.DefaultSendLimits != nil {
		for _, value := range []*int{l.DefaultSendLimits.MessagesPerHour, l.DefaultSendLimits.RecipientsPerHour, l.DefaultSendLimits.RecipientsPerDay} {
			if value != nil && (*value < 0 || *value > maxDomainSendLimit) {
				return fmt.Errorf("sending limits must be between 0 and %d", maxDomainSendLimit)
			}
		}
	}
	return nil
}

// SetLimits replaces a domain's limits after validating them.
func (ds *DomainStore) SetLimits(ctx context.Context, id string, limits DomainLimits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	if sl := limits.DefaultSendLimits; sl != nil && sl.MessagesPerHour == nil && sl.RecipientsPerHour == nil && sl.RecipientsPerDay == nil {
		limits.DefaultSendLimits = nil
	}
	return ds.Update(ctx, id, func(domain *Domain) { domain.Limits = limits })
}

// DomainUsage is what a domain currently consumes against its limits.
type DomainUsage struct {
	Accounts int `json:"accounts"`
	Aliases  int `json:"aliases"`
	// AssignedStorageBytes sums the per-account quotas of the domain's
	// accounts; UnlimitedAccounts counts accounts without a quota.
	AssignedStorageBytes int64 `json:"assigned_storage_bytes"`
	UnlimitedAccounts    int   `json:"unlimited_accounts"`
}

// Usage counts the domain's accounts (by primary identity), aliases
// (non-primary identities plus recipient aliases), and assigned quotas.
func (ds *DomainStore) Usage(ctx context.Context, id string) (DomainUsage, error) {
	id = normalizeID(id)
	users := ds.ts.UserStore()
	identities, err := users.ListEmailAddressesForDomain(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return DomainUsage{}, err
	}
	var usage DomainUsage
	for _, identity := range identities {
		if !identity.Primary {
			usage.Aliases++
			continue
		}
		user, err := users.Get(ctx, identity.UserID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return DomainUsage{}, err
		}
		usage.Accounts++
		if user.MaxStorageBytes > 0 {
			usage.AssignedStorageBytes += user.MaxStorageBytes
		} else {
			usage.UnlimitedAccounts++
		}
	}
	aliases, err := ds.ts.RecipientAliasStore().List(ctx)
	if err != nil {
		return DomainUsage{}, err
	}
	for _, alias := range aliases {
		if alias.DomainID == id {
			usage.Aliases++
		}
	}
	temporary, err := ds.ts.UserAliasStore().CountForDomain(ctx, id, time.Now())
	if err != nil {
		return DomainUsage{}, err
	}
	usage.Aliases += temporary
	return usage, nil
}

// PrimaryDomain returns the domain of the account's primary identity, or ""
// when the account has none. Delegated domain administration and per-domain
// defaults follow it.
func (us *UserStore) PrimaryDomain(ctx context.Context, userID string) (string, error) {
	identities, err := us.ListEmailAddressesForUser(ctx, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	for _, identity := range identities {
		if identity.Primary {
			return strings.ToLower(identity.DomainID), nil
		}
	}
	return "", nil
}
