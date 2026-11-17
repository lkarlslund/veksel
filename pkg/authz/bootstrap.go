package authz

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const setupJournalKey = "setup"

// ErrSetupToken is returned when first-owner creation lacks the one-time
// setup token printed at server startup.
var ErrSetupToken = errors.New("setup token is missing or invalid")

// SetupState describes whether the installation can accept its first owner.
type SetupState string

const (
	SetupReady    SetupState = "ready"
	SetupComplete SetupState = "complete"
	SetupBlocked  SetupState = "blocked"
)

type setupJournal struct {
	Username  string    `json:"username"`
	StartedAt time.Time `json:"started_at"`
	Complete  bool      `json:"complete"`
}

// Bootstrap owns the one-time transition from an empty store to its first
// system owner. Its journal allows startup to finish a request interrupted
// after the user record was written. Claiming setup requires a per-process
// random token so a network client cannot race the operator to ownership.
type Bootstrap struct {
	mu       sync.Mutex
	token    string
	ts       *model.TypedStore
	users    *model.UserStore
	folders  *model.FolderStore
	policies *model.PolicyStore
}

func NewBootstrap(ts *model.TypedStore) *Bootstrap {
	return &Bootstrap{
		token: rand.Text(),
		ts:    ts, users: model.NewUserStore(ts), folders: model.NewFolderStore(ts),
		policies: model.NewPolicyStore(ts),
	}
}

// SetupToken returns the token that authorizes first-owner creation, or an
// empty string once setup no longer accepts an owner.
func (b *Bootstrap) SetupToken(ctx context.Context) (string, error) {
	state, err := b.State(ctx)
	if err != nil || state != SetupReady {
		return "", err
	}
	return b.token, nil
}

// State returns the current installation setup state and repairs an
// interrupted first-owner creation when possible.
func (b *Bootstrap) State(ctx context.Context) (SetupState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stateLocked(ctx)
}

func (b *Bootstrap) stateLocked(ctx context.Context) (SetupState, error) {
	users, err := b.users.List(ctx)
	if err != nil {
		return "", fmt.Errorf("list setup users: %w", err)
	}
	if len(users) == 0 {
		var journal setupJournal
		if err := b.ts.Get(ctx, model.NSAuthorizationMetadata, setupJournalKey, &journal); err == nil {
			_ = b.ts.Delete(ctx, model.NSAuthorizationMetadata, setupJournalKey)
		}
		return SetupReady, nil
	}
	if owner, err := b.hasEnabledOwner(ctx); err != nil {
		return "", err
	} else if owner {
		return SetupComplete, nil
	}

	var journal setupJournal
	if err := b.ts.Get(ctx, model.NSAuthorizationMetadata, setupJournalKey, &journal); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return SetupBlocked, nil
		}
		return "", fmt.Errorf("read setup journal: %w", err)
	}
	if journal.Complete || journal.Username == "" {
		return SetupBlocked, nil
	}
	if _, err := b.users.Get(ctx, journal.Username); err != nil {
		return SetupBlocked, nil
	}
	if err := b.finishLocked(ctx, journal.Username); err != nil {
		return "", fmt.Errorf("resume setup: %w", err)
	}
	return SetupComplete, nil
}

// CreateOwner creates the first local user and makes it system owner. token
// must match SetupToken.
func (b *Bootstrap) CreateOwner(ctx context.Context, token, username, displayName, password string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	state, err := b.stateLocked(ctx)
	if err != nil {
		return err
	}
	if state != SetupReady {
		return fmt.Errorf("setup is %s", state)
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(b.token)) != 1 {
		return ErrSetupToken
	}
	username = strings.ToLower(strings.TrimSpace(username))
	displayName = strings.TrimSpace(displayName)
	if username == "" || strings.ContainsAny(username, "@:/\\ ") {
		return fmt.Errorf("username must not be empty or contain spaces, @, colon, or slash")
	}
	if displayName == "" {
		displayName = username
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	journal := setupJournal{Username: username, StartedAt: time.Now().UTC()}
	if err := b.ts.Put(ctx, model.NSAuthorizationMetadata, setupJournalKey, journal); err != nil {
		return fmt.Errorf("claim setup: %w", err)
	}
	if err := b.users.Create(ctx, username, displayName, password); err != nil {
		_ = b.ts.Delete(ctx, model.NSAuthorizationMetadata, setupJournalKey)
		return fmt.Errorf("create owner: %w", err)
	}
	return b.finishLocked(ctx, username)
}

func (b *Bootstrap) finishLocked(ctx context.Context, username string) error {
	if err := b.folders.EnsureForUser(ctx, username); err != nil {
		return err
	}
	principal := model.PrincipalRef{Kind: model.PrincipalUser, ID: username}
	bindings, err := b.policies.ListForPrincipal(ctx, principal)
	if err != nil {
		return fmt.Errorf("list setup policy: %w", err)
	}
	found := false
	for _, binding := range bindings {
		if binding.Effect == model.EffectAllow && binding.RoleID == RoleSystemOwner && binding.Resource == (model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}) {
			found = true
			break
		}
	}
	if !found {
		if _, err := b.policies.Create(ctx, model.PolicyBinding{
			Principal: principal,
			Resource:  model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
			Effect:    model.EffectAllow, RoleID: RoleSystemOwner,
			Inheritance: model.InheritanceSubtree, GrantedBy: "setup",
		}); err != nil {
			return fmt.Errorf("grant system owner: %w", err)
		}
	}
	return b.ts.Set(ctx, model.NSAuthorizationMetadata, setupJournalKey, setupJournal{
		Username: username, StartedAt: time.Now().UTC(), Complete: true,
	})
}

func (b *Bootstrap) hasEnabledOwner(ctx context.Context) (bool, error) {
	bindings, err := b.policies.ListForResource(ctx, model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID})
	if err != nil {
		return false, fmt.Errorf("list system owners: %w", err)
	}
	for _, binding := range bindings {
		if binding.Effect != model.EffectAllow || binding.RoleID != RoleSystemOwner || binding.Principal.Kind != model.PrincipalUser {
			continue
		}
		user, err := b.users.Get(ctx, binding.Principal.ID)
		if err == nil && user.Enabled && (binding.ExpiresAt.IsZero() || binding.ExpiresAt.After(time.Now().UTC())) {
			return true, nil
		}
	}
	return false, nil
}
