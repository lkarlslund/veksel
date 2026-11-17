package model

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// Temporary alias lifecycle and policy constants.
const (
	// UserAliasRejectInactive answers mail to an expired or disabled alias
	// with a permanent 550 5.1.1; UserAliasDiscardInactive accepts and drops it.
	UserAliasRejectInactive  = "reject"
	UserAliasDiscardInactive = "discard"

	// UserAliasPurgeAfter is how long an expired alias keeps its record
	// before cleanup turns it into a tombstone, and UserAliasTombstoneFor how
	// long that tombstone reserves the address so it is not reissued.
	UserAliasPurgeAfter   = 7 * 24 * time.Hour
	UserAliasTombstoneFor = 90 * 24 * time.Hour

	userAliasSuffixLength   = 8
	userAliasMaxPrefix      = 24
	userAliasCreateAttempts = 20
	userAliasAlphabet       = "abcdefghjkmnpqrstuvwxyz23456789"
)

var (
	ErrUserAliasInvalid  = errors.New("invalid temporary alias")
	ErrUserAliasLimit    = errors.New("temporary alias limit reached")
	ErrUserAliasLocked   = errors.New("temporary alias was disabled by an administrator")
	ErrUserAliasNotOwner = errors.New("temporary alias belongs to another account")
)

// UserAlias is a self-service disposable address that delivers to its owner.
// A record with a non-zero TombstoneUntil is a tombstone: it holds no
// delivery settings, rejects mail, and only reserves the address.
type UserAlias struct {
	Address  string `json:"address"`
	DomainID string `json:"domain_id"`
	UserID   string `json:"user_id"`
	Label    string `json:"label,omitempty"`
	// FolderPath is the owner's folder that receives the mail; empty means
	// the Inbox.
	FolderPath string `json:"folder_path,omitempty"`
	Enabled    bool   `json:"enabled"`
	// AdminDisabled marks an alias an administrator switched off; the owner
	// cannot enable it again.
	AdminDisabled bool `json:"admin_disabled,omitempty"`
	// ExpiresAt is zero for an alias that never expires.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// OnInactive is UserAliasRejectInactive or UserAliasDiscardInactive and
	// decides what happens to mail after the alias expires or is disabled.
	OnInactive     string    `json:"on_inactive"`
	TombstoneUntil time.Time `json:"tombstone_until,omitzero"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Tombstone reports whether the record only reserves its address.
func (a UserAlias) Tombstone() bool { return !a.TombstoneUntil.IsZero() }

// Expired reports whether the alias has passed its expiry at now.
func (a UserAlias) Expired(now time.Time) bool {
	return !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt)
}

// Active reports whether the alias currently delivers mail.
func (a UserAlias) Active(now time.Time) bool {
	return !a.Tombstone() && a.Enabled && !a.Expired(now)
}

// countsTowardLimits reports whether the alias uses user and domain quota:
// live records that have not expired.
func (a UserAlias) countsTowardLimits(now time.Time) bool {
	return !a.Tombstone() && !a.Expired(now)
}

// UserAliasRequest creates a temporary alias. Prefix is optional; the
// store always appends a random suffix so addresses cannot be guessed.
type UserAliasRequest struct {
	UserID     string
	DomainID   string
	Prefix     string
	Label      string
	FolderPath string
	// Expiry is the lifetime from now; zero means the alias never expires.
	Expiry     time.Duration
	OnInactive string
	// MaxPerUser bounds the owner's unexpired aliases when positive.
	MaxPerUser int
}

// UserAliasUpdate changes the mutable fields of an alias. Nil fields are kept.
type UserAliasUpdate struct {
	Label      *string
	FolderPath *string
	Enabled    *bool
	OnInactive *string
	// Expiry replaces the expiry with now plus the duration; a zero
	// duration makes the alias permanent.
	Expiry *time.Duration
}

// userAliasRetainedFactor bounds an account's live, expired, and tombstoned
// alias records together at this multiple of its live alias limit.
const userAliasRetainedFactor = 4

// UserAliasStore persists temporary aliases and tombstones.
type UserAliasStore struct{ ts *TypedStore }

func NewUserAliasStore(ts *TypedStore) *UserAliasStore { return &UserAliasStore{ts: ts} }

func (s *UserAliasStore) Get(ctx context.Context, address string) (UserAlias, error) {
	var alias UserAlias
	err := s.ts.Get(ctx, NSUserAliases, recipientAliasKey(address), &alias)
	return alias, err
}

// List returns every record, tombstones included, sorted by address.
func (s *UserAliasStore) List(ctx context.Context) ([]UserAlias, error) {
	keys, err := s.ts.List(ctx, NSUserAliases)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return []UserAlias{}, nil
		}
		return nil, err
	}
	result := make([]UserAlias, 0, len(keys))
	for _, key := range keys {
		alias, err := s.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, alias)
	}
	slices.SortFunc(result, func(left, right UserAlias) int { return strings.Compare(left.Address, right.Address) })
	return result, nil
}

// ListForUser returns the user's live (non-tombstone) aliases.
func (s *UserAliasStore) ListForUser(ctx context.Context, userID string) ([]UserAlias, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	userID = normalizeID(userID)
	return slices.DeleteFunc(all, func(alias UserAlias) bool { return alias.Tombstone() || alias.UserID != userID }), nil
}

// CountForDomain counts the aliases of a domain that use its alias limit.
func (s *UserAliasStore) CountForDomain(ctx context.Context, domainID string, now time.Time) (int, error) {
	all, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, alias := range all {
		if alias.DomainID == domainID && alias.countsTowardLimits(now) {
			count++
		}
	}
	return count, nil
}

// Create allocates a new alias with a random suffix. The address is unique
// among identities, recipient aliases, temporary aliases and tombstones.
func (s *UserAliasStore) Create(ctx context.Context, request UserAliasRequest) (UserAlias, error) {
	now := time.Now().UTC()
	prefix, err := cleanUserAliasPrefix(request.Prefix)
	if err != nil {
		return UserAlias{}, err
	}
	if request.OnInactive == "" {
		request.OnInactive = UserAliasRejectInactive
	}
	if err := validateUserAliasPolicy(request.OnInactive, request.Label); err != nil {
		return UserAlias{}, err
	}
	if request.Expiry < 0 {
		return UserAlias{}, fmt.Errorf("%w: expiry must not be negative", ErrUserAliasInvalid)
	}
	var created UserAlias
	err = store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		userID := normalizeID(request.UserID)
		user, err := s.ts.UserStore().Get(batchCtx, userID)
		if err != nil {
			return err
		}
		if !user.Enabled {
			return fmt.Errorf("%w: account is disabled", ErrUserAliasInvalid)
		}
		domain, err := s.ts.DomainStore().Get(batchCtx, normalizeID(request.DomainID))
		if err != nil || !domain.Enabled {
			return fmt.Errorf("%w: domain must be enabled and hosted", ErrUserAliasInvalid)
		}
		if err := s.checkFolder(batchCtx, userID, request.FolderPath); err != nil {
			return err
		}
		if request.MaxPerUser > 0 {
			all, err := s.List(batchCtx)
			if err != nil {
				return err
			}
			used, retained := 0, 0
			for _, alias := range all {
				if alias.UserID != userID {
					continue
				}
				retained++
				if alias.countsTowardLimits(now) {
					used++
				}
			}
			if used >= request.MaxPerUser {
				return fmt.Errorf("%w: at most %d temporary aliases per account", ErrUserAliasLimit, request.MaxPerUser)
			}
			// Deleted and expired aliases stay as tombstones for
			// UserAliasTombstoneFor; bounding them too keeps create/delete
			// churn from growing the store without limit.
			if retained >= request.MaxPerUser*userAliasRetainedFactor {
				return fmt.Errorf("%w: too many recently deleted or expired temporary aliases; try again later", ErrUserAliasLimit)
			}
		}
		for range userAliasCreateAttempts {
			suffix, err := randomUserAliasSuffix()
			if err != nil {
				return err
			}
			local := suffix
			if prefix != "" {
				local = prefix + "-" + suffix
			}
			address := local + "@" + domain.ID
			taken, err := s.AddressTaken(batchCtx, address)
			if err != nil {
				return err
			}
			if taken {
				continue
			}
			alias := UserAlias{
				Address: address, DomainID: domain.ID, UserID: userID, Label: strings.TrimSpace(request.Label),
				FolderPath: request.FolderPath, Enabled: true, OnInactive: request.OnInactive,
				CreatedAt: now, UpdatedAt: now,
			}
			if request.Expiry > 0 {
				alias.ExpiresAt = now.Add(request.Expiry)
			}
			if err := s.ts.Put(batchCtx, NSUserAliases, address, alias); err != nil {
				if errors.Is(err, store.ErrExists) {
					continue
				}
				return err
			}
			created = alias
			return nil
		}
		return fmt.Errorf("%w: could not allocate a unique address", ErrUserAliasInvalid)
	})
	return created, err
}

// AddressTaken reports whether address is used by an identity, recipient
// alias, temporary alias, or tombstone.
func (s *UserAliasStore) AddressTaken(ctx context.Context, address string) (bool, error) {
	if _, err := s.ts.UserStore().GetEmailAddress(ctx, address); err == nil {
		return true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if _, err := s.ts.RecipientAliasStore().Get(ctx, address); err == nil {
		return true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if _, err := s.Get(ctx, address); err == nil {
		return true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	return false, nil
}

func (s *UserAliasStore) checkFolder(ctx context.Context, userID, path string) error {
	if path == "" {
		return nil
	}
	if _, err := s.ts.FolderStore().GetByPath(ctx, userID, path); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: folder %q does not exist", ErrUserAliasInvalid, path)
		}
		return err
	}
	return nil
}

func validateUserAliasPolicy(onInactive, label string) error {
	if onInactive != UserAliasRejectInactive && onInactive != UserAliasDiscardInactive {
		return fmt.Errorf("%w: on_inactive must be %s or %s", ErrUserAliasInvalid, UserAliasRejectInactive, UserAliasDiscardInactive)
	}
	if len([]rune(label)) > 200 {
		return fmt.Errorf("%w: label is limited to 200 characters", ErrUserAliasInvalid)
	}
	return nil
}

// Update changes an alias on behalf of its owner (ownerID non-empty) or an
// administrator (ownerID empty). The administrative lock is set and lifted
// only through SetAdminDisabled.
func (s *UserAliasStore) Update(ctx context.Context, address, ownerID string, update UserAliasUpdate) (UserAlias, error) {
	var result UserAlias
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		alias, err := s.Get(batchCtx, address)
		if err != nil {
			return err
		}
		if alias.Tombstone() {
			return store.ErrNotFound
		}
		if ownerID != "" && alias.UserID != normalizeID(ownerID) {
			return ErrUserAliasNotOwner
		}
		if update.Label != nil {
			alias.Label = strings.TrimSpace(*update.Label)
		}
		if update.FolderPath != nil {
			if err := s.checkFolder(batchCtx, alias.UserID, *update.FolderPath); err != nil {
				return err
			}
			alias.FolderPath = *update.FolderPath
		}
		if update.OnInactive != nil {
			alias.OnInactive = *update.OnInactive
		}
		if err := validateUserAliasPolicy(alias.OnInactive, alias.Label); err != nil {
			return err
		}
		if update.Enabled != nil {
			if *update.Enabled && alias.AdminDisabled {
				return ErrUserAliasLocked
			}
			alias.Enabled = *update.Enabled
		}
		if update.Expiry != nil {
			if *update.Expiry < 0 {
				return fmt.Errorf("%w: expiry must not be negative", ErrUserAliasInvalid)
			}
			alias.ExpiresAt = time.Time{}
			if *update.Expiry > 0 {
				alias.ExpiresAt = time.Now().UTC().Add(*update.Expiry)
			}
		}
		alias.UpdatedAt = time.Now().UTC()
		result = alias
		return s.ts.Set(batchCtx, NSUserAliases, alias.Address, alias)
	})
	return result, err
}

// SetAdminDisabled switches an alias off and locks it against the owner, or
// lifts the lock, which leaves the alias disabled for the owner to enable.
func (s *UserAliasStore) SetAdminDisabled(ctx context.Context, address string, disabled bool) (UserAlias, error) {
	var result UserAlias
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		alias, err := s.Get(batchCtx, address)
		if err != nil {
			return err
		}
		if alias.Tombstone() {
			return store.ErrNotFound
		}
		alias.AdminDisabled = disabled
		if disabled {
			alias.Enabled = false
		}
		alias.UpdatedAt = time.Now().UTC()
		result = alias
		return s.ts.Set(batchCtx, NSUserAliases, alias.Address, alias)
	})
	return result, err
}

// Delete retires an alias into a tombstone so the address is not reissued
// to another account for UserAliasTombstoneFor. An empty ownerID skips the
// ownership check (administrators).
func (s *UserAliasStore) Delete(ctx context.Context, address, ownerID string) error {
	return store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		alias, err := s.Get(batchCtx, address)
		if err != nil {
			return err
		}
		if alias.Tombstone() {
			return store.ErrNotFound
		}
		if ownerID != "" && alias.UserID != normalizeID(ownerID) {
			return ErrUserAliasNotOwner
		}
		return s.ts.Set(batchCtx, NSUserAliases, alias.Address, tombstoneOf(alias, time.Now().UTC()))
	})
}

func tombstoneOf(alias UserAlias, now time.Time) UserAlias {
	return UserAlias{
		Address: alias.Address, DomainID: alias.DomainID, UserID: alias.UserID, OnInactive: UserAliasRejectInactive,
		TombstoneUntil: now.Add(UserAliasTombstoneFor), CreatedAt: alias.CreatedAt, UpdatedAt: now,
	}
}

// Cleanup turns aliases expired for UserAliasPurgeAfter into tombstones and
// deletes tombstones past their reservation.
func (s *UserAliasStore) Cleanup(ctx context.Context, now time.Time) (tombstoned, purged int, err error) {
	all, err := s.List(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, alias := range all {
		switch {
		case alias.Tombstone() && !now.Before(alias.TombstoneUntil):
			if err := s.ts.Delete(ctx, NSUserAliases, alias.Address); err != nil && !errors.Is(err, store.ErrNotFound) {
				return tombstoned, purged, err
			}
			purged++
		case !alias.Tombstone() && !alias.ExpiresAt.IsZero() && !now.Before(alias.ExpiresAt.Add(UserAliasPurgeAfter)):
			if err := s.ts.Set(ctx, NSUserAliases, alias.Address, tombstoneOf(alias, now)); err != nil {
				return tombstoned, purged, err
			}
			tombstoned++
		}
	}
	return tombstoned, purged, nil
}

// SendingIdentity returns the alias as a sending identity for its owner, so
// replies need not reveal the real address. Only an active alias qualifies.
func (s *UserAliasStore) SendingIdentity(ctx context.Context, address string, now time.Time) (EmailAddress, error) {
	alias, err := s.Get(ctx, address)
	if err != nil {
		return EmailAddress{}, err
	}
	if !alias.Active(now) {
		return EmailAddress{}, store.ErrNotFound
	}
	return alias.identity(), nil
}

func (a UserAlias) identity() EmailAddress {
	local := a.Address[:strings.LastIndex(a.Address, "@")]
	return EmailAddress{ID: a.Address, UserID: a.UserID, DomainID: a.DomainID, LocalPart: local, Enabled: true, CreatedAt: a.CreatedAt}
}

// route is the resolver's view of the alias at now.
func (a UserAlias) route(now time.Time, ownerEnabled bool) RecipientRoute {
	if a.Tombstone() {
		return RecipientRoute{Disabled: true}
	}
	if !a.Active(now) || !ownerEnabled {
		if a.OnInactive == UserAliasDiscardInactive {
			return RecipientRoute{Discard: true}
		}
		return RecipientRoute{Disabled: true}
	}
	return RecipientRoute{Identity: a.identity(), FolderPath: a.FolderPath, UserAlias: true}
}

func cleanUserAliasPrefix(prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) > userAliasMaxPrefix {
		return "", fmt.Errorf("%w: prefix is limited to %d characters", ErrUserAliasInvalid, userAliasMaxPrefix)
	}
	for _, r := range prefix {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", fmt.Errorf("%w: prefix may contain only letters, digits, dot, dash and underscore", ErrUserAliasInvalid)
		}
	}
	if prefix != "" && (strings.HasPrefix(prefix, ".") || strings.HasSuffix(prefix, ".") || strings.Contains(prefix, "..")) {
		return "", fmt.Errorf("%w: prefix must not start or end with a dot or contain consecutive dots", ErrUserAliasInvalid)
	}
	return prefix, nil
}

func randomUserAliasSuffix() (string, error) {
	out := make([]byte, userAliasSuffixLength)
	limit := big.NewInt(int64(len(userAliasAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = userAliasAlphabet[n.Int64()]
	}
	return string(out), nil
}
