package model

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/srs"
	"github.com/lkarlslund/veksel/pkg/store"
)

// RecipientRoute is the local destination of an envelope recipient.
type RecipientRoute struct {
	// Identity is the terminal identity that receives the message. It is
	// zero when the recipient is an alias.
	Identity EmailAddress
	// Targets are the enabled terminal identities of a recipient alias.
	Targets []string
	// Disabled reports a matching identity or alias that is switched off;
	// callers reject it rather than trying a broader match.
	Disabled bool
	// Detail is the subaddress detail when the recipient matched through a
	// recipient delimiter (RFC 5233).
	Detail string
	// CatchAll reports that only the domain catch-all matched.
	CatchAll bool
	// UserAlias reports a match on an owner's temporary alias, whose
	// Identity is the alias acting as the owner's identity.
	UserAlias bool
	// FolderPath is the owner's folder a temporary alias delivers to; empty
	// means the Inbox.
	FolderPath string
	// Discard reports an inactive temporary alias that accepts and drops mail.
	Discard bool
}

// Mailbox returns the single identity that receives the route, with Enabled
// false for a disabled match. Aliases have no single mailbox and report
// store.ErrNotFound.
func (r RecipientRoute) Mailbox() (EmailAddress, error) {
	if r.Targets != nil || r.Discard {
		return EmailAddress{}, store.ErrNotFound
	}
	identity := r.Identity
	identity.Enabled = !r.Disabled
	return identity, nil
}

// SplitSubaddress splits a local part at the first occurrence of any of the
// delimiter characters, as Postfix recipient_delimiter does. ok is false when
// no delimiter is configured or present, or the user part would be empty.
func SplitSubaddress(local, delimiters string) (user, detail string, ok bool) {
	if delimiters == "" {
		return local, "", false
	}
	index := strings.IndexAny(local, delimiters)
	if index <= 0 {
		return local, "", false
	}
	return local[:index], local[index+1:], true
}

// ResolveRecipient routes an envelope recipient to local identities. The
// most specific match wins: the exact identity, the exact alias, the
// subaddress base identity or alias (user+detail@domain resolves as
// user@domain), and finally the domain catch-all. SRS addresses never reach
// the catch-all. It returns store.ErrNotFound when nothing local matches.
func (ts *TypedStore) ResolveRecipient(ctx context.Context, address, delimiters string) (RecipientRoute, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	at := strings.LastIndex(address, "@")
	if at <= 0 || at == len(address)-1 {
		return RecipientRoute{}, store.ErrNotFound
	}
	local, domainID := address[:at], address[at+1:]
	route, err := ts.resolveExactRecipient(ctx, address)
	if !errors.Is(err, store.ErrNotFound) {
		return route, err
	}
	if user, detail, ok := SplitSubaddress(local, delimiters); ok {
		route, err = ts.resolveExactRecipient(ctx, user+"@"+domainID)
		if err == nil {
			route.Detail = detail
		}
		if !errors.Is(err, store.ErrNotFound) {
			return route, err
		}
	}
	if srs.IsSRS(local) {
		return RecipientRoute{}, store.ErrNotFound
	}
	domain, err := ts.DomainStore().Get(ctx, domainID)
	if err != nil {
		return RecipientRoute{}, err
	}
	if !domain.Enabled || domain.CatchAll == "" {
		return RecipientRoute{}, store.ErrNotFound
	}
	identity, err := ts.UserStore().GetEmailAddress(ctx, domain.CatchAll)
	if err != nil {
		return RecipientRoute{}, err
	}
	return RecipientRoute{Identity: identity, Disabled: !identity.Enabled, CatchAll: true}, nil
}

func (ts *TypedStore) resolveExactRecipient(ctx context.Context, address string) (RecipientRoute, error) {
	identity, err := ts.UserStore().GetEmailAddress(ctx, address)
	if err == nil {
		return RecipientRoute{Identity: identity, Disabled: !identity.Enabled}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return RecipientRoute{}, err
	}
	alias, err := ts.RecipientAliasStore().Get(ctx, address)
	if errors.Is(err, store.ErrNotFound) {
		return ts.resolveUserAlias(ctx, address)
	}
	if err != nil {
		return RecipientRoute{}, err
	}
	if !alias.Enabled {
		return RecipientRoute{Disabled: true}, nil
	}
	targets, err := ts.RecipientAliasStore().Expand(ctx, address)
	if err != nil {
		return RecipientRoute{}, err
	}
	return RecipientRoute{Targets: targets}, nil
}

// resolveUserAlias routes a temporary alias. An expired, disabled, or
// tombstoned alias never falls through to a broader match.
func (ts *TypedStore) resolveUserAlias(ctx context.Context, address string) (RecipientRoute, error) {
	alias, err := ts.UserAliasStore().Get(ctx, address)
	if err != nil {
		return RecipientRoute{}, err
	}
	owner, err := ts.UserStore().Get(ctx, alias.UserID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return RecipientRoute{}, err
	}
	return alias.route(time.Now(), err == nil && owner.Enabled), nil
}

// SetCatchAll sets or clears (empty target) the domain catch-all. The target
// must be an enabled local email identity.
func (ds *DomainStore) SetCatchAll(ctx context.Context, id, target string) error {
	target = strings.ToLower(strings.TrimSpace(target))
	if target != "" {
		identity, err := ds.ts.UserStore().GetEmailAddress(ctx, target)
		if errors.Is(err, store.ErrNotFound) || err == nil && !identity.Enabled {
			return fmt.Errorf("%w: catch-all target %q is not an enabled local identity", ErrCatchAllInvalid, target)
		}
		if err != nil {
			return err
		}
	}
	return ds.Update(ctx, id, func(domain *Domain) { domain.CatchAll = target })
}

// catchAllDomain returns a domain whose catch-all targets address, if any.
func (ds *DomainStore) catchAllDomain(ctx context.Context, address string) (string, error) {
	domains, err := ds.List(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	for _, domain := range domains {
		if domain.CatchAll == address {
			return domain.ID, nil
		}
	}
	return "", nil
}

// ErrCatchAllInvalid reports an unusable domain catch-all target.
var ErrCatchAllInvalid = errors.New("invalid catch-all target")
