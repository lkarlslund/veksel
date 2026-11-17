package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Request describes one authorization decision.
type Request struct {
	Actor    model.PrincipalRef
	Subject  model.PrincipalRef
	Mode     ActingMode
	Action   Action
	Resource model.ResourceRef
	Now      time.Time
}

// ActingMode describes why Actor and Subject differ.
type ActingMode string

const (
	ActingNone          ActingMode = ""
	ActingDelegation    ActingMode = "delegation"
	ActingImpersonation ActingMode = "impersonation"
)

// Decision explains the result of an authorization check.
type Decision struct {
	Allowed           bool     `json:"allowed"`
	Reason            string   `json:"reason"`
	MatchedBindingIDs []string `json:"matched_binding_ids,omitempty"`
}

// Engine evaluates persisted policy against the resource hierarchy.
type Engine struct {
	users    *model.UserStore
	folders  *model.FolderStore
	roles    *model.RoleStore
	groups   *model.GroupStore
	policies *model.PolicyStore
	builtIns map[string]model.Role
}

// New returns an authorization engine backed by ts.
func New(ts *model.TypedStore) *Engine {
	builtIns := make(map[string]model.Role)
	for _, role := range BuiltInRoles() {
		builtIns[role.ID] = role
	}
	return &Engine{
		users: model.NewUserStore(ts), folders: model.NewFolderStore(ts),
		roles: model.NewRoleStore(ts), groups: model.NewGroupStore(ts),
		policies: model.NewPolicyStore(ts), builtIns: builtIns,
	}
}

// Check evaluates req. Errors indicate unavailable or inconsistent policy
// data and callers must fail closed.
func (e *Engine) Check(ctx context.Context, req Request) (Decision, error) {
	if req.Actor.Kind != model.PrincipalUser || req.Actor.ID == "" {
		return Decision{Reason: "invalid_actor"}, nil
	}
	actor, err := e.users.Get(ctx, req.Actor.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Decision{Reason: "actor_not_found"}, nil
		}
		return Decision{}, fmt.Errorf("load actor: %w", err)
	}
	if !actor.Enabled {
		return Decision{Reason: "actor_disabled"}, nil
	}
	if req.Subject.ID == "" {
		req.Subject = req.Actor
	}
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}
	if req.Subject != req.Actor {
		allowed, err := e.canActAs(ctx, req)
		if err != nil {
			return Decision{}, err
		}
		if !allowed {
			return Decision{Reason: "subject_not_authorized"}, nil
		}
	}

	owner, err := e.isResourceOwner(ctx, req.Subject, req.Resource)
	if err != nil {
		return Decision{}, err
	}
	if owner {
		return Decision{Allowed: true, Reason: "resource_owner"}, nil
	}
	bindings, err := e.bindingsForActor(ctx, req.Actor)
	if err != nil {
		return Decision{}, err
	}
	if e.hasSystemOwner(bindings, req.Now) {
		return Decision{Allowed: true, Reason: "system_owner"}, nil
	}

	chain, err := e.resourceChain(ctx, req.Resource)
	if err != nil {
		return Decision{}, err
	}
	var allows, denies []string
	administrativeOnly := true
	for _, binding := range bindings {
		if !binding.ExpiresAt.IsZero() && !binding.ExpiresAt.After(req.Now) {
			continue
		}
		if !bindingApplies(binding, chain) {
			continue
		}
		permissions, err := e.bindingPermissions(ctx, binding)
		if err != nil {
			return Decision{}, err
		}
		if !permissionMatches(permissions, string(req.Action)) {
			continue
		}
		if binding.Effect == model.EffectDeny {
			denies = append(denies, binding.ID)
		} else {
			allows = append(allows, binding.ID)
			if binding.Resource.Kind != model.ResourceSystem && binding.Resource.Kind != model.ResourceDomain {
				administrativeOnly = false
			}
		}
	}
	if len(denies) > 0 {
		return Decision{Reason: "explicit_deny", MatchedBindingIDs: denies}, nil
	}
	if len(allows) > 0 && administrativeOnly {
		protected, err := e.protectsOwnerAccount(ctx, req.Actor, chain, req.Now)
		if err != nil {
			return Decision{}, err
		}
		if protected {
			return Decision{Reason: "owner_account_protected"}, nil
		}
	}
	if len(allows) > 0 {
		return Decision{Allowed: true, Reason: "explicit_allow", MatchedBindingIDs: allows}, nil
	}
	return Decision{Reason: "default_deny"}, nil
}

func (e *Engine) canActAs(ctx context.Context, req Request) (bool, error) {
	var action Action
	switch req.Mode {
	case ActingDelegation:
		action = AccountDelegate
	case ActingImpersonation:
		action = AccountImpersonate
	default:
		return false, nil
	}
	decision, err := e.Check(ctx, Request{
		Actor:    req.Actor,
		Subject:  req.Actor,
		Action:   action,
		Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: req.Subject.ID},
		Now:      req.Now,
	})
	return decision.Allowed, err
}

type requestScopeKey struct{}

type requestScope struct {
	mu       sync.Mutex
	bindings map[model.PrincipalRef][]model.PolicyBinding
}

// WithRequestScope returns a context in which Check memoizes each actor's
// effective policy bindings (direct plus group-inherited) for the lifetime of
// ctx. Use it for one bounded request that evaluates many resources, such as
// a folder catalog; never for long-lived connections, because policy changes
// made while the scope is alive are not observed by later checks in it.
func WithRequestScope(ctx context.Context) context.Context {
	if _, ok := ctx.Value(requestScopeKey{}).(*requestScope); ok {
		return ctx
	}
	return context.WithValue(ctx, requestScopeKey{}, &requestScope{bindings: make(map[model.PrincipalRef][]model.PolicyBinding)})
}

func (e *Engine) bindingsForActor(ctx context.Context, actor model.PrincipalRef) ([]model.PolicyBinding, error) {
	scope, ok := ctx.Value(requestScopeKey{}).(*requestScope)
	if !ok {
		return e.loadBindingsForActor(ctx, actor)
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if bindings, found := scope.bindings[actor]; found {
		return bindings, nil
	}
	bindings, err := e.loadBindingsForActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	scope.bindings[actor] = bindings
	return bindings, nil
}

func (e *Engine) loadBindingsForActor(ctx context.Context, actor model.PrincipalRef) ([]model.PolicyBinding, error) {
	bindings, err := e.policies.ListForPrincipal(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("list user policy: %w", err)
	}
	groups, err := e.groups.ListForUser(ctx, actor.ID)
	if err != nil {
		return nil, fmt.Errorf("list actor groups: %w", err)
	}
	for _, group := range groups {
		groupBindings, err := e.policies.ListForPrincipal(ctx, model.PrincipalRef{Kind: model.PrincipalGroup, ID: group.ID})
		if err != nil {
			return nil, fmt.Errorf("list group %q policy: %w", group.ID, err)
		}
		bindings = append(bindings, groupBindings...)
	}
	return bindings, nil
}

func (e *Engine) hasSystemOwner(bindings []model.PolicyBinding, now time.Time) bool {
	for _, binding := range bindings {
		if binding.Effect == model.EffectAllow && binding.RoleID == RoleSystemOwner && binding.Resource.Kind == model.ResourceSystem && binding.Resource.ID == model.SystemResourceID && (binding.ExpiresAt.IsZero() || binding.ExpiresAt.After(now)) {
			return true
		}
	}
	return false
}

// HoldsSystemBinding reports whether userID holds an unexpired allow binding
// on the system resource, directly or through a group. Any such binding,
// built-in or custom role or direct permissions, reaches beyond a single
// domain, so delegated domain administration must not manage the account.
func (e *Engine) HoldsSystemBinding(ctx context.Context, userID string) (bool, error) {
	bindings, err := e.bindingsForActor(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: strings.ToLower(strings.TrimSpace(userID))})
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	for _, binding := range bindings {
		if binding.Effect == model.EffectAllow && binding.Resource.Kind == model.ResourceSystem && (binding.ExpiresAt.IsZero() || binding.ExpiresAt.After(now)) {
			return true, nil
		}
	}
	return false, nil
}

// protectsOwnerAccount reports whether chain reaches another user's account
// that holds system.owner. Administrative bindings below ownership
// (system.admin, domain.admin) must not reach an owner's account, folders,
// or identities, or impersonating or resetting the owner would turn them
// into an owner. Grants made directly on the resources (shares,
// delegation) are unaffected.
func (e *Engine) protectsOwnerAccount(ctx context.Context, actor model.PrincipalRef, chain []model.ResourceRef, now time.Time) (bool, error) {
	for _, resource := range chain {
		if resource.Kind != model.ResourceAccount || strings.EqualFold(resource.ID, actor.ID) {
			continue
		}
		bindings, err := e.bindingsForActor(ctx, model.PrincipalRef{Kind: model.PrincipalUser, ID: strings.ToLower(resource.ID)})
		if err != nil {
			return false, err
		}
		return e.hasSystemOwner(bindings, now), nil
	}
	return false, nil
}

func (e *Engine) isResourceOwner(ctx context.Context, subject model.PrincipalRef, resource model.ResourceRef) (bool, error) {
	if subject.Kind != model.PrincipalUser {
		return false, nil
	}
	switch resource.Kind {
	case model.ResourceAccount:
		return strings.EqualFold(subject.ID, resource.ID), nil
	case model.ResourceFolder:
		folder, err := e.folders.Get(ctx, resource.ID)
		if err != nil {
			return false, fmt.Errorf("load folder owner: %w", err)
		}
		return strings.EqualFold(subject.ID, folder.UserID), nil
	case model.ResourceIdentity:
		identity, err := e.users.GetEmailAddress(ctx, resource.ID)
		if err != nil {
			return false, fmt.Errorf("load identity owner: %w", err)
		}
		return strings.EqualFold(subject.ID, identity.UserID), nil
	default:
		return false, nil
	}
}

func (e *Engine) resourceChain(ctx context.Context, resource model.ResourceRef) ([]model.ResourceRef, error) {
	chain := []model.ResourceRef{resource}
	switch resource.Kind {
	case model.ResourceFolder:
		folder, err := e.folders.Get(ctx, resource.ID)
		if err != nil {
			return nil, fmt.Errorf("load folder hierarchy: %w", err)
		}
		seen := map[string]struct{}{folder.ID: {}}
		for folder.ParentID != "" {
			parentID := folder.ParentID
			if _, ok := seen[parentID]; ok {
				return nil, fmt.Errorf("folder hierarchy cycle at %q", parentID)
			}
			seen[parentID] = struct{}{}
			chain = append(chain, model.ResourceRef{Kind: model.ResourceFolder, ID: parentID})
			folder, err = e.folders.Get(ctx, parentID)
			if err != nil {
				return nil, fmt.Errorf("load parent folder %q: %w", parentID, err)
			}
		}
		chain = append(chain, model.ResourceRef{Kind: model.ResourceAccount, ID: folder.UserID})
	case model.ResourceIdentity:
		identity, err := e.users.GetEmailAddress(ctx, resource.ID)
		if err != nil {
			return nil, fmt.Errorf("load identity hierarchy: %w", err)
		}
		chain = append(chain,
			model.ResourceRef{Kind: model.ResourceAccount, ID: identity.UserID},
			model.ResourceRef{Kind: model.ResourceDomain, ID: identity.DomainID},
		)
	}
	if resource.Kind != model.ResourceSystem {
		chain = append(chain, model.ResourceRef{Kind: model.ResourceSystem, ID: model.SystemResourceID})
	}
	return chain, nil
}

func bindingApplies(binding model.PolicyBinding, chain []model.ResourceRef) bool {
	for index, resource := range chain {
		if resource == binding.Resource {
			return index == 0 || binding.Inheritance == model.InheritanceSubtree
		}
	}
	return false
}

func (e *Engine) bindingPermissions(ctx context.Context, binding model.PolicyBinding) ([]string, error) {
	if binding.RoleID == "" {
		return binding.Permissions, nil
	}
	if role, ok := e.builtIns[binding.RoleID]; ok {
		if !roleSupportsResource(role, binding.Resource.Kind) {
			return nil, fmt.Errorf("role %q cannot bind to %q", role.ID, binding.Resource.Kind)
		}
		return role.Permissions, nil
	}
	role, err := e.roles.Get(ctx, binding.RoleID)
	if err != nil {
		return nil, fmt.Errorf("load role %q: %w", binding.RoleID, err)
	}
	if !roleSupportsResource(role, binding.Resource.Kind) {
		return nil, fmt.Errorf("role %q cannot bind to %q", role.ID, binding.Resource.Kind)
	}
	return role.Permissions, nil
}

func roleSupportsResource(role model.Role, resourceKind model.ResourceKind) bool {
	for _, kind := range role.ResourceKinds {
		if kind == resourceKind {
			return true
		}
	}
	return false
}

func permissionMatches(permissions []string, action string) bool {
	for _, permission := range permissions {
		if permission == "*" || permission == action {
			return true
		}
		if strings.HasSuffix(permission, ".*") && strings.HasPrefix(action, strings.TrimSuffix(permission, "*")) {
			return true
		}
	}
	return false
}
