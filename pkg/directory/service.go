package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleAuth)

// auditActor attributes automatic directory changes in the audit log.
const auditActor = "directory"

// grantedBy marks administrator role bindings the directory owns; only these
// are revoked when group membership ends.
const grantedBy = "directory:ldap"

// adminRole is the role the administrator group grants: system.owner by
// default (the original behavior), or system.admin when AdminRole is
// "admin". Local owners are never touched, because only bindings marked
// grantedBy are revoked.
func adminRole(settings Settings) string {
	if settings.AdminRole == "admin" {
		return authz.RoleSystemAdmin
	}
	return authz.RoleSystemOwner
}

// directoryAdminRole reports whether role is one the directory grants.
func directoryAdminRole(role string) bool {
	return role == authz.RoleSystemOwner || role == authz.RoleSystemAdmin
}

// Accounts creates accounts with their storage and refreshes account
// manifests after identity changes (account.Provisioner).
type Accounts interface {
	Create(ctx context.Context, user model.User) error
	Sync(ctx context.Context, userID string) (bool, error)
}

// Connector builds a Directory from settings; tests substitute a fake.
type Connector func(Settings) (Directory, error)

// ConnectLDAP is the production Connector.
func ConnectLDAP(settings Settings) (Directory, error) { return NewLDAP(settings) }

// Service maps directory entries onto local accounts. It implements
// protocolauth.Directory and owns the periodic sync.
type Service struct {
	ts       *model.TypedStore
	users    *model.UserStore
	policies *model.PolicyStore
	accounts Accounts
	audit    *audit.Logger
	connect  Connector

	mu        sync.RWMutex
	settings  Settings
	directory Directory

	// provision serializes account creation and refresh so concurrent
	// sign-ins and sync never race on one account.
	provision sync.Mutex
	syncing   sync.Mutex
	running   atomic.Bool
	wake      chan struct{}
}

// New returns a service with directory accounts disabled until Configure.
func New(ts *model.TypedStore, accounts Accounts, connect Connector) *Service {
	if connect == nil {
		connect = ConnectLDAP
	}
	return &Service{
		ts: ts, users: ts.UserStore(), policies: model.NewPolicyStore(ts), accounts: accounts,
		audit: audit.New(ts), connect: connect, wake: make(chan struct{}, 1),
	}
}

// Configure applies settings live. On failure directory accounts stay off,
// so local accounts keep working, and the error is returned.
func (s *Service) Configure(settings Settings) error {
	var directory Directory
	var err error
	if settings.Enabled {
		directory, err = s.connect(settings)
	}
	s.mu.Lock()
	previous := s.directory
	s.settings, s.directory = settings, directory
	s.mu.Unlock()
	if previous != nil {
		previous.Close()
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return err
}

// Close releases the directory connection.
func (s *Service) Close() {
	s.mu.Lock()
	directory := s.directory
	s.directory = nil
	s.mu.Unlock()
	if directory != nil {
		directory.Close()
	}
}

func (s *Service) current() (Directory, Settings) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.directory, s.settings
}

// Authenticate verifies login and password against the directory and returns
// the local account for the entry, provisioning it on first sign-in and
// refreshing its name, addresses and administrator role otherwise.
func (s *Service) Authenticate(ctx context.Context, login, password string) (model.User, error) {
	if password == "" {
		return model.User{}, ErrInvalidCredentials
	}
	directory, settings := s.current()
	if directory == nil {
		return model.User{}, ErrDisabled
	}
	entry, err := directory.Authenticate(ctx, login, password)
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return model.User{}, err
	case err != nil:
		log.Warn("directory sign-in failed", "error", err)
		return model.User{}, err
	case entry.Disabled:
		return model.User{}, ErrInvalidCredentials
	case entry.Login == "":
		log.Warn("directory entry has none of the configured ID attributes", "dn", entry.DN, "attributes", settings.IDAttributes)
		return model.User{}, ErrInvalidCredentials
	}
	s.provision.Lock()
	defer s.provision.Unlock()
	user, found, err := s.match(ctx, entry)
	if err != nil {
		return model.User{}, err
	}
	if !found {
		if user, err = s.create(ctx, entry); err != nil {
			return model.User{}, err
		}
	}
	user, _, err = s.refresh(ctx, user, entry, settings, false)
	return user, err
}

// match finds the local account for entry: by its account ID, then, for a
// renamed entry, by stable directory identity. An account ID held by a local
// account or by another directory entry is a conflict, never a takeover.
func (s *Service) match(ctx context.Context, entry Entry) (model.User, bool, error) {
	user, err := s.users.Get(ctx, entry.Login)
	if err == nil {
		if !user.Directory() || entry.GUID != "" && user.DirectoryID != "" && user.DirectoryID != entry.GUID {
			log.Warn("directory entry refused: its account ID belongs to another account", "account", user.ID, "dn", entry.DN)
			s.audit.Log(auditActor, "directory.account.conflict", user.ID, map[string]string{"dn": entry.DN})
			return model.User{}, false, ErrAccountConflict
		}
		return user, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return model.User{}, false, err
	}
	if entry.GUID == "" {
		return model.User{}, false, nil
	}
	users, err := s.users.List(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return model.User{}, false, err
	}
	for _, candidate := range users {
		if candidate.Directory() && candidate.DirectoryID == entry.GUID {
			return candidate, true, nil
		}
	}
	return model.User{}, false, nil
}

func (s *Service) create(ctx context.Context, entry Entry) (model.User, error) {
	if !validAccountID(entry.Login) {
		log.Warn("directory entry refused: its ID attribute is not a valid account ID", "login", entry.Login, "dn", entry.DN)
		return model.User{}, fmt.Errorf("%w: %q is not a valid account ID", ErrAccountConflict, entry.Login)
	}
	user := model.User{ID: entry.Login, DisplayName: displayName(entry), Source: model.UserSourceLDAP, DirectoryDN: entry.DN, DirectoryID: entry.GUID}
	if err := s.accounts.Create(ctx, user); err != nil {
		if errors.Is(err, store.ErrExists) {
			return model.User{}, ErrAccountConflict
		}
		return model.User{}, fmt.Errorf("provision directory account: %w", err)
	}
	log.Info("provisioned directory account", "account", user.ID, "dn", entry.DN)
	s.audit.Log(auditActor, "directory.account.provision", user.ID, map[string]string{"dn": entry.DN})
	return s.users.Get(ctx, user.ID)
}

// refresh brings a directory account in step with its entry and reports
// whether anything changed. reenable restores an account that sync disabled.
// Callers hold s.provision.
func (s *Service) refresh(ctx context.Context, user model.User, entry Entry, settings Settings, reenable bool) (model.User, bool, error) {
	name := displayName(entry)
	guid := user.DirectoryID
	if entry.GUID != "" {
		guid = entry.GUID
	}
	enable := reenable && user.DirectoryDisabled && !user.Enabled
	changed := false
	if user.DisplayName != name || user.DirectoryDN != entry.DN || user.DirectoryID != guid || enable {
		err := s.users.Update(ctx, user.ID, func(u *model.User) {
			u.DisplayName, u.DirectoryDN, u.DirectoryID = name, entry.DN, guid
			if enable {
				u.Enabled, u.DirectoryDisabled = true, false
			}
		})
		if err != nil {
			return user, false, fmt.Errorf("update directory account: %w", err)
		}
		changed = true
		if enable {
			s.audit.Log(auditActor, "directory.account.enable", user.ID, map[string]string{"dn": entry.DN})
		}
	}
	added, err := s.addAddresses(ctx, user.ID, entry.Addresses)
	if err != nil {
		return user, changed, err
	}
	if added {
		if _, err := s.accounts.Sync(ctx, user.ID); err != nil {
			return user, true, fmt.Errorf("refresh account storage: %w", err)
		}
	}
	admin, err := s.setAdmin(ctx, user.ID, settings.AdminGroupDN != "" && entry.Admin, adminRole(settings))
	if err != nil {
		return user, true, err
	}
	if changed = changed || added || admin; changed {
		if user, err = s.users.Get(ctx, user.ID); err != nil {
			return user, true, err
		}
	}
	return user, changed, nil
}

// addAddresses adds the entry's addresses on hosted, enabled domains as
// identities of userID. An address another account already owns is skipped,
// and addresses the directory drops are kept: identities are only added.
func (s *Service) addAddresses(ctx context.Context, userID string, addresses []string) (bool, error) {
	existing, err := s.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	hasPrimary := false
	for _, identity := range existing {
		hasPrimary = hasPrimary || identity.Primary
	}
	added := false
	for _, address := range addresses {
		domainID := address[strings.LastIndex(address, "@")+1:]
		if domain, err := s.ts.DomainStore().Get(ctx, domainID); err != nil || !domain.Enabled {
			continue
		}
		identity, err := s.users.GetEmailAddress(ctx, address)
		if err == nil {
			if identity.UserID != userID {
				log.Warn("directory address skipped: it belongs to another account", "address", address, "account", userID, "owner", identity.UserID)
			}
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return added, err
		}
		if err := s.users.AddEmailAddress(ctx, address, userID, domainID, !hasPrimary); err != nil {
			log.Warn("directory address skipped", "address", address, "account", userID, "error", err)
			continue
		}
		hasPrimary, added = true, true
		s.audit.Log(auditActor, "directory.identity.add", address, map[string]string{"user_id": userID})
	}
	return added, nil
}

// setAdmin grants role to userID, or revokes it when admin is false, and
// reports whether anything changed. A directory binding for the other
// administrator role (left by a changed ldap_admin_role) is replaced. Roles
// granted by other means are never touched.
func (s *Service) setAdmin(ctx context.Context, userID string, admin bool, role string) (bool, error) {
	principal := model.PrincipalRef{Kind: model.PrincipalUser, ID: userID}
	bindings, err := s.policies.ListForPrincipal(ctx, principal)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, fmt.Errorf("list role bindings: %w", err)
	}
	var stale []model.PolicyBinding
	current := false
	for _, binding := range bindings {
		if binding.GrantedBy != grantedBy || !directoryAdminRole(binding.RoleID) {
			continue
		}
		if admin && binding.RoleID == role && !current {
			current = true
			continue
		}
		stale = append(stale, binding)
	}
	changed := false
	if admin && !current {
		if _, err := s.policies.Create(ctx, model.PolicyBinding{
			Principal: principal, Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
			Effect: model.EffectAllow, RoleID: role, Inheritance: model.InheritanceSubtree, GrantedBy: grantedBy,
		}); err != nil {
			return false, fmt.Errorf("grant administrator role: %w", err)
		}
		s.audit.Log(auditActor, "directory.admin.grant", userID, map[string]string{"role": role})
		changed = true
	}
	for _, binding := range stale {
		if err := s.policies.Delete(ctx, binding.ID); err != nil {
			return false, fmt.Errorf("revoke administrator role: %w", err)
		}
		s.audit.Log(auditActor, "directory.admin.revoke", userID, map[string]string{"role": binding.RoleID})
		changed = true
	}
	return changed, nil
}

func displayName(entry Entry) string {
	if entry.DisplayName != "" {
		return entry.DisplayName
	}
	return entry.Login
}

// validAccountID accepts the IDs administrators can create: no address,
// path or whitespace characters.
func validAccountID(id string) bool {
	return id != "" && len(id) <= 128 && !strings.ContainsFunc(id, func(r rune) bool {
		return strings.ContainsRune("@:/\\", r) || unicode.IsSpace(r) || unicode.IsControl(r)
	})
}
