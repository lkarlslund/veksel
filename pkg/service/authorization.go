// Package service contains authorization-enforced application operations.
package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// ErrForbidden indicates a valid actor lacks the requested authority.
var ErrForbidden = errors.New("forbidden")

// ErrInvalidRequest indicates a mutation whose arguments can never succeed,
// such as an empty or multi-segment folder name. Like ErrForbidden it is a
// permanent failure that must not be replayed from the mutation journal.
var ErrInvalidRequest = errors.New("invalid request")

// Authorization manages roles, groups, and resource policy.
type Authorization struct {
	engine   *authz.Engine
	roles    *model.RoleStore
	groups   *model.GroupStore
	policies *model.PolicyStore
	users    *model.UserStore
	folders  *model.FolderStore
	audit    *audit.Logger
	events   events.Publisher
}

// ManagedGrantUpdate is the complete mutable portion of a user-managed grant.
// ExpectedUpdatedAt prevents a stale modal from overwriting a newer change.
type ManagedGrantUpdate struct {
	Effect            model.BindingEffect      `json:"effect"`
	RoleID            string                   `json:"role_id,omitempty"`
	Permissions       []string                 `json:"permissions,omitempty"`
	Inheritance       model.BindingInheritance `json:"inheritance"`
	ExpiresAt         *time.Time               `json:"expires_at"`
	ExpectedUpdatedAt time.Time                `json:"expected_updated_at"`
}

// ManagedGrantPermissionDecision is the effective policy result for one
// permission represented by a managed grant.
type ManagedGrantPermissionDecision struct {
	Permission        string   `json:"permission"`
	Allowed           bool     `json:"allowed"`
	Reason            string   `json:"reason"`
	MatchedBindingIDs []string `json:"matched_binding_ids,omitempty"`
}

// ManagedGrantEffective expands a binding into the permissions and current
// combined policy result visible to its resource manager.
type ManagedGrantEffective struct {
	Binding      model.PolicyBinding              `json:"binding"`
	Permissions  []string                         `json:"permissions"`
	Active       bool                             `json:"active"`
	Status       string                           `json:"status"`
	EvaluatedAt  time.Time                        `json:"evaluated_at"`
	GroupMembers int                              `json:"group_members,omitempty"`
	Decisions    []ManagedGrantPermissionDecision `json:"decisions,omitempty"`
}

// AuthorizedSendingIdentity is an enabled identity owned by another account
// that the actor may use through an effective sending grant.
type AuthorizedSendingIdentity struct {
	Address string
	Modes   []authz.Action
}

func (s *Authorization) SetEventPublisher(publisher events.Publisher) { s.events = publisher }

func NewAuthorization(ts *model.TypedStore, engine *authz.Engine) *Authorization {
	return &Authorization{
		engine: engine, roles: model.NewRoleStore(ts), groups: model.NewGroupStore(ts),
		policies: model.NewPolicyStore(ts), users: model.NewUserStore(ts), folders: model.NewFolderStore(ts),
		audit: audit.New(ts),
	}
}

func (s *Authorization) ListRoles(ctx context.Context, actor model.PrincipalRef) ([]model.Role, error) {
	roles := authz.BuiltInRoles()
	decision, err := s.engine.Check(ctx, authz.Request{
		Actor: actor, Action: authz.AuthorizationRolesRead,
		Resource: model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID},
	})
	if err != nil {
		return nil, err
	}
	if decision.Allowed {
		custom, err := s.roles.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list custom roles: %w", err)
		}
		return append(roles, custom...), nil
	}
	visible := make([]model.Role, 0, 5)
	for _, role := range roles {
		if len(role.ResourceKinds) == 1 && (role.ResourceKinds[0] == model.ResourceFolder || role.ID == authz.RoleAccountDelegate || role.ID == authz.RoleAccountSearcher) {
			visible = append(visible, role)
		}
	}
	return visible, nil
}

func (s *Authorization) CreateRole(ctx context.Context, actor model.PrincipalRef, role model.Role) error {
	if err := s.require(ctx, actor, authz.AuthorizationRolesWrite, model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}); err != nil {
		return err
	}
	role.ID = strings.ToLower(strings.TrimSpace(role.ID))
	if _, builtIn := authz.BuiltInRole(role.ID); builtIn {
		return fmt.Errorf("built-in role %q cannot be replaced", role.ID)
	}
	if role.Name == "" || len(role.Permissions) == 0 || len(role.ResourceKinds) == 0 {
		return fmt.Errorf("role name, permissions, and resource kinds are required")
	}
	if err := s.roles.Set(ctx, role); err != nil {
		return err
	}
	s.audit.Log(actor.ID, "authorization.role.set", role.ID, nil)
	return nil
}

func (s *Authorization) ListGroups(ctx context.Context, actor model.PrincipalRef) ([]model.Group, error) {
	if err := s.require(ctx, actor, authz.AuthorizationGroupsRead, model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}); err != nil {
		return nil, err
	}
	return s.groups.List(ctx)
}

func (s *Authorization) SetGroup(ctx context.Context, actor model.PrincipalRef, group model.Group) error {
	if err := s.require(ctx, actor, authz.AuthorizationGroupsWrite, model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID}); err != nil {
		return err
	}
	if group.Name == "" {
		return fmt.Errorf("group name is required")
	}
	for _, member := range group.Members {
		if _, err := s.users.Get(ctx, member); err != nil {
			return fmt.Errorf("group member %q: %w", member, err)
		}
	}
	if err := s.groups.Set(ctx, group); err != nil {
		return err
	}
	s.audit.Log(actor.ID, "authorization.group.set", group.ID, map[string]string{"members": strings.Join(group.Members, ",")})
	return nil
}

func (s *Authorization) ListFolderGrants(ctx context.Context, actor model.PrincipalRef, folderID string) ([]model.PolicyBinding, error) {
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: folderID}
	if err := s.require(ctx, actor, authz.FolderPermissionsRead, resource); err != nil {
		return nil, err
	}
	return s.policies.ListForResource(ctx, resource)
}

func (s *Authorization) CreateFolderGrant(ctx context.Context, actor model.PrincipalRef, binding model.PolicyBinding) (model.PolicyBinding, error) {
	if binding.Resource.Kind != model.ResourceFolder {
		return model.PolicyBinding{}, fmt.Errorf("folder resource required")
	}
	if _, err := s.folders.Get(ctx, binding.Resource.ID); err != nil {
		return model.PolicyBinding{}, fmt.Errorf("load folder: %w", err)
	}
	if err := s.require(ctx, actor, authz.FolderPermissionsManage, binding.Resource); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.validatePrincipal(ctx, binding.Principal); err != nil {
		return model.PolicyBinding{}, err
	}
	permissions, err := s.resolveBindingPermissions(ctx, binding)
	if err != nil {
		return model.PolicyBinding{}, err
	}
	for _, permission := range permissions {
		decision, err := s.engine.Check(ctx, authz.Request{Actor: actor, Action: authz.Action(permission), Resource: binding.Resource})
		if err != nil {
			return model.PolicyBinding{}, err
		}
		if !decision.Allowed {
			return model.PolicyBinding{}, fmt.Errorf("cannot grant permission %q which actor does not hold", permission)
		}
	}
	binding.GrantedBy = actor.ID
	if binding.Effect == "" {
		binding.Effect = model.EffectAllow
	}
	if binding.Inheritance == "" {
		binding.Inheritance = model.InheritanceSelf
	}
	created, err := s.policies.Create(ctx, binding)
	if err == nil {
		s.audit.Log(actor.ID, "authorization.folder_grant.create", binding.Resource.ID, grantAuditDetails(created))
		s.publishGrantEvent("authorization.grant.created", actor, created)
	}
	return created, err
}

func (s *Authorization) DeleteFolderGrant(ctx context.Context, actor model.PrincipalRef, folderID, bindingID string) error {
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: folderID}
	if err := s.require(ctx, actor, authz.FolderPermissionsManage, resource); err != nil {
		return err
	}
	binding, err := s.policies.Get(ctx, bindingID)
	if err != nil {
		return err
	}
	if binding.Resource != resource {
		return store.ErrNotFound
	}
	if err := s.policies.Delete(ctx, bindingID); err != nil {
		return err
	}
	s.audit.Log(actor.ID, "authorization.folder_grant.delete", folderID, grantAuditDetails(binding))
	s.publishGrantEvent("authorization.grant.deleted", actor, binding)
	return nil
}

func (s *Authorization) ListIdentityGrants(ctx context.Context, actor model.PrincipalRef, identityID string) ([]model.PolicyBinding, error) {
	resource := model.ResourceRef{Kind: model.ResourceIdentity, ID: strings.ToLower(strings.TrimSpace(identityID))}
	if _, err := s.users.GetEmailAddress(ctx, resource.ID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, actor, authz.IdentityPermissionsRead, resource); err != nil {
		return nil, err
	}
	return s.policies.ListForResource(ctx, resource)
}

// ListDelegatedSendingIdentities discovers effective direct and group grants
// without scanning every address in the system. Candidate identities come from
// the policy principal indexes; the authorization engine then applies current
// allow, deny, group, and expiry semantics before anything is returned.
func (s *Authorization) ListDelegatedSendingIdentities(ctx context.Context, actor model.PrincipalRef, now time.Time) ([]AuthorizedSendingIdentity, error) {
	if actor.Kind != model.PrincipalUser || strings.TrimSpace(actor.ID) == "" {
		return nil, fmt.Errorf("user actor required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	principals := []model.PrincipalRef{actor}
	groups, err := s.groups.ListForUser(ctx, actor.ID)
	if err != nil {
		return nil, fmt.Errorf("list actor groups: %w", err)
	}
	for _, group := range groups {
		principals = append(principals, model.PrincipalRef{Kind: model.PrincipalGroup, ID: group.ID})
	}
	candidates := make(map[string]struct{})
	for _, principal := range principals {
		bindings, err := s.policies.ListForPrincipal(ctx, principal)
		if err != nil {
			return nil, fmt.Errorf("list identity grants for %s %q: %w", principal.Kind, principal.ID, err)
		}
		for _, binding := range bindings {
			if binding.Resource.Kind == model.ResourceIdentity {
				candidates[strings.ToLower(strings.TrimSpace(binding.Resource.ID))] = struct{}{}
			}
		}
	}
	result := make([]AuthorizedSendingIdentity, 0, len(candidates))
	for address := range candidates {
		identity, err := s.users.GetEmailAddress(ctx, address)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load delegated identity %q: %w", address, err)
		}
		if !identity.Enabled || identity.UserID == actor.ID {
			continue
		}
		resource := model.ResourceRef{Kind: model.ResourceIdentity, ID: identity.ID}
		modes := make([]authz.Action, 0, 2)
		for _, action := range []authz.Action{authz.IdentitySendAs, authz.IdentitySendOnBehalf} {
			decision, err := s.engine.Check(ctx, authz.Request{Actor: actor, Subject: actor, Action: action, Resource: resource, Now: now})
			if err != nil {
				return nil, fmt.Errorf("check %s for identity %q: %w", action, address, err)
			}
			if decision.Allowed {
				modes = append(modes, action)
			}
		}
		if len(modes) != 0 {
			result = append(result, AuthorizedSendingIdentity{Address: identity.ID, Modes: modes})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Address < result[j].Address })
	return result, nil
}

func (s *Authorization) CreateIdentityGrant(ctx context.Context, actor model.PrincipalRef, binding model.PolicyBinding) (model.PolicyBinding, error) {
	resource := binding.Resource
	resource.ID = strings.ToLower(strings.TrimSpace(resource.ID))
	if resource.Kind != model.ResourceIdentity {
		return model.PolicyBinding{}, fmt.Errorf("identity resource required")
	}
	if _, err := s.users.GetEmailAddress(ctx, resource.ID); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.require(ctx, actor, authz.IdentityPermissionsManage, resource); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.validatePrincipal(ctx, binding.Principal); err != nil {
		return model.PolicyBinding{}, err
	}
	if binding.RoleID != "" {
		return model.PolicyBinding{}, fmt.Errorf("identity grants require direct permissions")
	}
	for _, permission := range binding.Permissions {
		if permission != string(authz.IdentitySendAs) && permission != string(authz.IdentitySendOnBehalf) {
			return model.PolicyBinding{}, fmt.Errorf("unsupported identity permission %q", permission)
		}
	}
	binding.Resource = resource
	return s.createManagedGrant(ctx, actor, binding)
}

func (s *Authorization) DeleteIdentityGrant(ctx context.Context, actor model.PrincipalRef, identityID, bindingID string) error {
	resource := model.ResourceRef{Kind: model.ResourceIdentity, ID: strings.ToLower(strings.TrimSpace(identityID))}
	return s.deleteManagedGrant(ctx, actor, resource, bindingID, authz.IdentityPermissionsManage)
}

func (s *Authorization) ListAccountDelegations(ctx context.Context, actor model.PrincipalRef, accountID string) ([]model.PolicyBinding, error) {
	resource := model.ResourceRef{Kind: model.ResourceAccount, ID: strings.ToLower(strings.TrimSpace(accountID))}
	if _, err := s.users.Get(ctx, resource.ID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, actor, authz.AccountPermissionsRead, resource); err != nil {
		return nil, err
	}
	return s.policies.ListForResource(ctx, resource)
}

func (s *Authorization) CreateAccountDelegation(ctx context.Context, actor model.PrincipalRef, binding model.PolicyBinding) (model.PolicyBinding, error) {
	resource := binding.Resource
	resource.ID = strings.ToLower(strings.TrimSpace(resource.ID))
	if resource.Kind != model.ResourceAccount {
		return model.PolicyBinding{}, fmt.Errorf("account resource required")
	}
	if _, err := s.users.Get(ctx, resource.ID); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.require(ctx, actor, authz.AccountPermissionsManage, resource); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.validatePrincipal(ctx, binding.Principal); err != nil {
		return model.PolicyBinding{}, err
	}
	if binding.RoleID != authz.RoleAccountDelegate || len(binding.Permissions) != 0 {
		return model.PolicyBinding{}, fmt.Errorf("account delegation requires role %q", authz.RoleAccountDelegate)
	}
	binding.Resource = resource
	return s.createManagedGrant(ctx, actor, binding)
}

func (s *Authorization) DeleteAccountDelegation(ctx context.Context, actor model.PrincipalRef, accountID, bindingID string) error {
	resource := model.ResourceRef{Kind: model.ResourceAccount, ID: strings.ToLower(strings.TrimSpace(accountID))}
	return s.deleteManagedGrant(ctx, actor, resource, bindingID, authz.AccountPermissionsManage)
}

// ListAccountSearchGrants returns the dedicated search bindings on an account.
func (s *Authorization) ListAccountSearchGrants(ctx context.Context, actor model.PrincipalRef, accountID string) ([]model.PolicyBinding, error) {
	resource := model.ResourceRef{Kind: model.ResourceAccount, ID: strings.ToLower(strings.TrimSpace(accountID))}
	if _, err := s.users.Get(ctx, resource.ID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, actor, authz.AccountPermissionsRead, resource); err != nil {
		return nil, err
	}
	bindings, err := s.policies.ListForResource(ctx, resource)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(bindings, func(binding model.PolicyBinding) bool {
		return binding.RoleID != authz.RoleAccountSearcher && !slices.Contains(binding.Permissions, string(authz.AccountItemsSearch))
	}), nil
}

// CreateAccountSearchGrant grants search without broadening item visibility.
func (s *Authorization) CreateAccountSearchGrant(ctx context.Context, actor model.PrincipalRef, binding model.PolicyBinding) (model.PolicyBinding, error) {
	resource := binding.Resource
	resource.ID = strings.ToLower(strings.TrimSpace(resource.ID))
	if resource.Kind != model.ResourceAccount {
		return model.PolicyBinding{}, fmt.Errorf("account resource required")
	}
	if _, err := s.users.Get(ctx, resource.ID); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.require(ctx, actor, authz.AccountPermissionsManage, resource); err != nil {
		return model.PolicyBinding{}, err
	}
	if err := s.validatePrincipal(ctx, binding.Principal); err != nil {
		return model.PolicyBinding{}, err
	}
	if binding.RoleID != authz.RoleAccountSearcher || len(binding.Permissions) != 0 {
		return model.PolicyBinding{}, fmt.Errorf("account search grant requires role %q", authz.RoleAccountSearcher)
	}
	binding.Resource = resource
	return s.createManagedGrant(ctx, actor, binding)
}

func (s *Authorization) DeleteAccountSearchGrant(ctx context.Context, actor model.PrincipalRef, accountID, bindingID string) error {
	resource := model.ResourceRef{Kind: model.ResourceAccount, ID: strings.ToLower(strings.TrimSpace(accountID))}
	binding, err := s.policies.Get(ctx, bindingID)
	if err != nil {
		return err
	}
	if binding.Resource != resource || binding.RoleID != authz.RoleAccountSearcher {
		return store.ErrNotFound
	}
	return s.deleteManagedGrant(ctx, actor, resource, bindingID, authz.AccountPermissionsManage)
}

// ListManagedGrants returns user-facing grants on resources whose permissions
// the actor may manage. System/domain policy and unrelated account policy are
// deliberately excluded from this self-service surface.
func (s *Authorization) ListManagedGrants(ctx context.Context, actor model.PrincipalRef) ([]model.PolicyBinding, error) {
	bindings, err := s.policies.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list policy bindings: %w", err)
	}
	managed := make([]model.PolicyBinding, 0, len(bindings))
	for _, binding := range bindings {
		action, ok := managedGrantAction(binding)
		if !ok {
			continue
		}
		allowed, err := s.canManagePersonalGrant(ctx, actor, action, binding.Resource)
		if err != nil {
			return nil, fmt.Errorf("check grant management for %s: %w", binding.ID, err)
		}
		if allowed {
			managed = append(managed, binding)
		}
	}
	sort.Slice(managed, func(i, j int) bool {
		left, right := managed[i], managed[j]
		if left.Resource.Kind != right.Resource.Kind {
			return left.Resource.Kind < right.Resource.Kind
		}
		if left.Resource.ID != right.Resource.ID {
			return left.Resource.ID < right.Resource.ID
		}
		if left.Principal.Kind != right.Principal.Kind {
			return left.Principal.Kind < right.Principal.Kind
		}
		if left.Principal.ID != right.Principal.ID {
			return left.Principal.ID < right.Principal.ID
		}
		return left.ID < right.ID
	})
	return managed, nil
}

// GetManagedGrant returns one binding only when the actor may manage that
// binding through the personal resource boundary used by the overview.
func (s *Authorization) GetManagedGrant(ctx context.Context, actor model.PrincipalRef, bindingID string) (model.PolicyBinding, error) {
	binding, _, err := s.managedGrant(ctx, actor, bindingID)
	return binding, err
}

// UpdateManagedGrant changes access, effect, scope, or expiry while keeping the
// principal and resource immutable. Moving a grant is a revoke/create action.
func (s *Authorization) UpdateManagedGrant(ctx context.Context, actor model.PrincipalRef, bindingID string, update ManagedGrantUpdate) (model.PolicyBinding, error) {
	current, _, err := s.managedGrant(ctx, actor, bindingID)
	if err != nil {
		return model.PolicyBinding{}, err
	}
	if update.ExpectedUpdatedAt.IsZero() {
		return model.PolicyBinding{}, fmt.Errorf("expected_updated_at is required")
	}
	candidate := current
	candidate.Effect = update.Effect
	candidate.RoleID = update.RoleID
	candidate.Permissions = append([]string(nil), update.Permissions...)
	candidate.Inheritance = update.Inheritance
	candidate.ExpiresAt = time.Time{}
	if update.ExpiresAt != nil {
		candidate.ExpiresAt = update.ExpiresAt.UTC()
	}
	if err := s.validateManagedGrantUpdate(ctx, actor, candidate); err != nil {
		return model.PolicyBinding{}, err
	}
	updated, err := s.policies.Update(ctx, bindingID, func(binding *model.PolicyBinding) error {
		if !binding.UpdatedAt.Equal(update.ExpectedUpdatedAt) {
			return store.ErrPreconditionFailed
		}
		binding.Effect = candidate.Effect
		binding.RoleID = candidate.RoleID
		binding.Permissions = append([]string(nil), candidate.Permissions...)
		binding.Inheritance = candidate.Inheritance
		binding.ExpiresAt = candidate.ExpiresAt
		return nil
	})
	if err != nil {
		return model.PolicyBinding{}, err
	}
	s.audit.Log(actor.ID, "authorization.grant.update", updated.Resource.ID, grantAuditDetails(updated))
	s.publishGrantEvent("authorization.grant.updated", actor, updated)
	return updated, nil
}

// EffectiveManagedGrant expands role permissions and, for a user principal,
// evaluates the complete current policy including other allows and denies.
func (s *Authorization) EffectiveManagedGrant(ctx context.Context, actor model.PrincipalRef, bindingID string, now time.Time) (ManagedGrantEffective, error) {
	binding, _, err := s.managedGrant(ctx, actor, bindingID)
	if err != nil {
		return ManagedGrantEffective{}, err
	}
	permissions, err := s.resolveBindingPermissions(ctx, binding)
	if err != nil {
		return ManagedGrantEffective{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := ManagedGrantEffective{Binding: binding, Permissions: permissions, Active: binding.ExpiresAt.IsZero() || binding.ExpiresAt.After(now), EvaluatedAt: now}
	switch {
	case !result.Active:
		result.Status = "expired"
	case binding.Effect == model.EffectDeny:
		result.Status = "deny"
	default:
		result.Status = "allow"
	}
	if binding.Principal.Kind == model.PrincipalGroup {
		group, err := s.groups.Get(ctx, binding.Principal.ID)
		if err != nil {
			return ManagedGrantEffective{}, fmt.Errorf("load grantee group: %w", err)
		}
		result.GroupMembers = len(group.Members)
		return result, nil
	}
	result.Decisions = make([]ManagedGrantPermissionDecision, 0, len(permissions))
	for _, permission := range permissions {
		decision, err := s.engine.Check(ctx, authz.Request{Actor: binding.Principal, Subject: binding.Principal, Action: authz.Action(permission), Resource: binding.Resource, Now: now})
		if err != nil {
			return ManagedGrantEffective{}, fmt.Errorf("evaluate permission %q: %w", permission, err)
		}
		result.Decisions = append(result.Decisions, ManagedGrantPermissionDecision{Permission: permission, Allowed: decision.Allowed, Reason: decision.Reason, MatchedBindingIDs: decision.MatchedBindingIDs})
	}
	return result, nil
}

// DeleteManagedGrant revokes one grant through the same resource-management
// boundary used by the specialized endpoints.
func (s *Authorization) DeleteManagedGrant(ctx context.Context, actor model.PrincipalRef, bindingID string) error {
	binding, _, err := s.managedGrant(ctx, actor, bindingID)
	if err != nil {
		return err
	}
	if err := s.policies.Delete(ctx, bindingID); err != nil {
		return err
	}
	s.audit.Log(actor.ID, "authorization.grant.delete", binding.Resource.ID, grantAuditDetails(binding))
	s.publishGrantEvent("authorization.grant.deleted", actor, binding)
	return nil
}

func (s *Authorization) managedGrant(ctx context.Context, actor model.PrincipalRef, bindingID string) (model.PolicyBinding, authz.Action, error) {
	binding, err := s.policies.Get(ctx, bindingID)
	if err != nil {
		return model.PolicyBinding{}, "", err
	}
	action, ok := managedGrantAction(binding)
	if !ok {
		return model.PolicyBinding{}, "", store.ErrNotFound
	}
	allowed, err := s.canManagePersonalGrant(ctx, actor, action, binding.Resource)
	if err != nil {
		return model.PolicyBinding{}, "", err
	}
	if !allowed {
		return model.PolicyBinding{}, "", ErrForbidden
	}
	return binding, action, nil
}

func (s *Authorization) validateManagedGrantUpdate(ctx context.Context, actor model.PrincipalRef, binding model.PolicyBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	permissions, err := s.resolveBindingPermissions(ctx, binding)
	if err != nil {
		return err
	}
	switch binding.Resource.Kind {
	case model.ResourceFolder:
		if _, err := s.folders.Get(ctx, binding.Resource.ID); err != nil {
			return fmt.Errorf("load folder: %w", err)
		}
		for _, permission := range permissions {
			decision, err := s.engine.Check(ctx, authz.Request{Actor: actor, Action: authz.Action(permission), Resource: binding.Resource})
			if err != nil {
				return err
			}
			if !decision.Allowed {
				return fmt.Errorf("cannot grant permission %q which actor does not hold", permission)
			}
		}
	case model.ResourceIdentity:
		if binding.Inheritance != model.InheritanceSelf {
			return fmt.Errorf("identity grants apply only to the identity itself")
		}
		if binding.RoleID != "" || len(binding.Permissions) == 0 {
			return fmt.Errorf("identity grants require direct permissions")
		}
		for _, permission := range permissions {
			if permission != string(authz.IdentitySendAs) && permission != string(authz.IdentitySendOnBehalf) {
				return fmt.Errorf("unsupported identity permission %q", permission)
			}
		}
	case model.ResourceAccount:
		if binding.Inheritance != model.InheritanceSelf {
			return fmt.Errorf("account grants apply only to the account itself")
		}
		validRole := (binding.RoleID == authz.RoleAccountDelegate || binding.RoleID == authz.RoleAccountSearcher) && len(binding.Permissions) == 0
		directSearch := binding.RoleID == "" && len(binding.Permissions) == 1 && binding.Permissions[0] == string(authz.AccountItemsSearch)
		if !validRole && !directSearch {
			return fmt.Errorf("account grant requires delegation or search access")
		}
	default:
		return store.ErrNotFound
	}
	return nil
}

func managedGrantAction(binding model.PolicyBinding) (authz.Action, bool) {
	switch binding.Resource.Kind {
	case model.ResourceFolder:
		return authz.FolderPermissionsManage, true
	case model.ResourceIdentity:
		return authz.IdentityPermissionsManage, true
	case model.ResourceAccount:
		if binding.RoleID == authz.RoleAccountDelegate || binding.RoleID == authz.RoleAccountSearcher || slices.Contains(binding.Permissions, string(authz.AccountItemsSearch)) {
			return authz.AccountPermissionsManage, true
		}
	}
	return "", false
}

func (s *Authorization) canManagePersonalGrant(ctx context.Context, actor model.PrincipalRef, action authz.Action, resource model.ResourceRef) (bool, error) {
	decision, err := s.engine.Check(ctx, authz.Request{Actor: actor, Action: action, Resource: resource})
	if err != nil || !decision.Allowed {
		return false, err
	}
	if decision.Reason == "resource_owner" {
		return true, nil
	}
	if decision.Reason != "explicit_allow" {
		return false, nil
	}
	for _, bindingID := range decision.MatchedBindingIDs {
		binding, err := s.policies.Get(ctx, bindingID)
		if err != nil {
			return false, fmt.Errorf("read matched binding %q: %w", bindingID, err)
		}
		if binding.Resource.Kind == model.ResourceFolder || binding.Resource.Kind == model.ResourceAccount || binding.Resource.Kind == model.ResourceIdentity {
			return true, nil
		}
	}
	return false, nil
}

func (s *Authorization) createManagedGrant(ctx context.Context, actor model.PrincipalRef, binding model.PolicyBinding) (model.PolicyBinding, error) {
	binding.GrantedBy = actor.ID
	if binding.Effect == "" {
		binding.Effect = model.EffectAllow
	}
	if binding.Inheritance == "" {
		binding.Inheritance = model.InheritanceSelf
	}
	created, err := s.policies.Create(ctx, binding)
	if err == nil {
		s.audit.Log(actor.ID, "authorization."+string(binding.Resource.Kind)+"_grant.create", binding.Resource.ID, grantAuditDetails(created))
		s.publishGrantEvent("authorization.grant.created", actor, created)
	}
	return created, err
}

func (s *Authorization) deleteManagedGrant(ctx context.Context, actor model.PrincipalRef, resource model.ResourceRef, bindingID string, action authz.Action) error {
	if err := s.require(ctx, actor, action, resource); err != nil {
		return err
	}
	binding, err := s.policies.Get(ctx, bindingID)
	if err != nil {
		return err
	}
	if binding.Resource != resource {
		return store.ErrNotFound
	}
	if err := s.policies.Delete(ctx, bindingID); err != nil {
		return err
	}
	s.audit.Log(actor.ID, "authorization."+string(resource.Kind)+"_grant.delete", resource.ID, grantAuditDetails(binding))
	s.publishGrantEvent("authorization.grant.deleted", actor, binding)
	return nil
}

func (s *Authorization) publishGrantEvent(eventType string, actor model.PrincipalRef, binding model.PolicyBinding) {
	if s.events == nil {
		return
	}
	recipients := []string{actor.ID}
	if binding.Principal.Kind == model.PrincipalUser {
		recipients = append(recipients, binding.Principal.ID)
	}
	s.events.Publish(events.Event{Type: eventType, Resource: string(binding.Resource.Kind) + ":" + binding.Resource.ID,
		Data: map[string]any{"binding_id": binding.ID, "effect": binding.Effect}, Recipients: recipients})
}

func grantAuditDetails(binding model.PolicyBinding) map[string]string {
	return map[string]string{
		"binding_id": binding.ID, "principal_kind": string(binding.Principal.Kind),
		"principal_id": binding.Principal.ID, "effect": string(binding.Effect),
		"role_id": binding.RoleID, "permissions": strings.Join(binding.Permissions, ","),
		"expires_at": binding.ExpiresAt.Format(time.RFC3339),
	}
}

func (s *Authorization) validatePrincipal(ctx context.Context, principal model.PrincipalRef) error {
	switch principal.Kind {
	case model.PrincipalUser:
		if _, err := s.users.Get(ctx, principal.ID); err != nil {
			return fmt.Errorf("load grantee: %w", err)
		}
	case model.PrincipalGroup:
		if _, err := s.groups.Get(ctx, principal.ID); err != nil {
			return fmt.Errorf("load grantee group: %w", err)
		}
	default:
		return fmt.Errorf("invalid grantee kind")
	}
	return nil
}

func (s *Authorization) resolveBindingPermissions(ctx context.Context, binding model.PolicyBinding) ([]string, error) {
	if binding.RoleID == "" {
		if len(binding.Permissions) == 0 {
			return nil, fmt.Errorf("role_id or permissions is required")
		}
		return binding.Permissions, nil
	}
	role, ok := authz.BuiltInRole(binding.RoleID)
	if !ok {
		var err error
		role, err = s.roles.Get(ctx, binding.RoleID)
		if err != nil {
			return nil, fmt.Errorf("load role: %w", err)
		}
	}
	validKind := false
	for _, kind := range role.ResourceKinds {
		if kind == binding.Resource.Kind {
			validKind = true
			break
		}
	}
	if !validKind {
		return nil, fmt.Errorf("role %q does not support %q resources", role.ID, binding.Resource.Kind)
	}
	return role.Permissions, nil
}

func (s *Authorization) require(ctx context.Context, actor model.PrincipalRef, action authz.Action, resource model.ResourceRef) error {
	decision, err := s.engine.Check(ctx, authz.Request{Actor: actor, Action: action, Resource: resource, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: %s", ErrForbidden, decision.Reason)
	}
	return nil
}
