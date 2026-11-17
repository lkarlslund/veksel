package model

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// PrincipalKind identifies an entity which may receive authorization policy.
type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalGroup PrincipalKind = "group"
)

// ResourceKind identifies an authorization boundary.
type ResourceKind string

// SystemResourceID identifies the one system resource that every
// system-level role binding (owners, administrators) is stored against.
const SystemResourceID = "veksel"

const (
	ResourceSystem   ResourceKind = "system"
	ResourceDomain   ResourceKind = "domain"
	ResourceAccount  ResourceKind = "account"
	ResourceFolder   ResourceKind = "folder"
	ResourceIdentity ResourceKind = "identity"
)

// BindingEffect determines whether a binding grants or rejects permissions.
type BindingEffect string

const (
	EffectAllow BindingEffect = "allow"
	EffectDeny  BindingEffect = "deny"
)

// BindingInheritance controls whether a binding applies below its resource.
type BindingInheritance string

const (
	InheritanceSelf    BindingInheritance = "self"
	InheritanceSubtree BindingInheritance = "subtree"
)

// PrincipalRef identifies a user or group.
type PrincipalRef struct {
	Kind PrincipalKind `json:"kind"`
	ID   string        `json:"id"`
}

// ResourceRef identifies an authorization resource.
type ResourceRef struct {
	Kind ResourceKind `json:"kind"`
	ID   string       `json:"id"`
}

// Role is a reusable collection of permissions.
type Role struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	ResourceKinds []ResourceKind `json:"resource_kinds"`
	Permissions   []string       `json:"permissions"`
	BuiltIn       bool           `json:"built_in"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// Group is a flat collection of local users.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Members     []string  `json:"members"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PolicyBinding attaches either a role or direct permissions to a principal.
// Exactly one of RoleID and Permissions must be populated.
type PolicyBinding struct {
	ID          string             `json:"id"`
	Principal   PrincipalRef       `json:"principal"`
	Resource    ResourceRef        `json:"resource"`
	Effect      BindingEffect      `json:"effect"`
	RoleID      string             `json:"role_id,omitempty"`
	Permissions []string           `json:"permissions,omitempty"`
	Inheritance BindingInheritance `json:"inheritance"`
	ExpiresAt   time.Time          `json:"expires_at,omitzero"`
	GrantedBy   string             `json:"granted_by"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// Validate checks the invariants required for safe policy evaluation.
func (b PolicyBinding) Validate() error {
	if b.Principal.ID == "" || (b.Principal.Kind != PrincipalUser && b.Principal.Kind != PrincipalGroup) {
		return fmt.Errorf("invalid principal")
	}
	if b.Resource.ID == "" || !validResourceKind(b.Resource.Kind) {
		return fmt.Errorf("invalid resource")
	}
	if b.Effect != EffectAllow && b.Effect != EffectDeny {
		return fmt.Errorf("invalid effect")
	}
	if b.Inheritance != InheritanceSelf && b.Inheritance != InheritanceSubtree {
		return fmt.Errorf("invalid inheritance")
	}
	if (b.RoleID == "") == (len(b.Permissions) == 0) {
		return fmt.Errorf("exactly one of role_id or permissions is required")
	}
	for _, permission := range b.Permissions {
		if strings.TrimSpace(permission) == "" {
			return fmt.Errorf("empty permission")
		}
	}
	return nil
}

func validResourceKind(kind ResourceKind) bool {
	switch kind {
	case ResourceSystem, ResourceDomain, ResourceAccount, ResourceFolder, ResourceIdentity:
		return true
	default:
		return false
	}
}

// RoleStore provides persistence for custom roles. Built-in roles are defined
// by the authorization package and are not stored here.
type RoleStore struct{ roles collection[Role] }

func NewRoleStore(ts *TypedStore) *RoleStore {
	return &RoleStore{roles: newCollection[Role](ts, NSRoles)}
}

func (s *RoleStore) Set(ctx context.Context, role Role) error {
	role.ID = normalizeID(role.ID)
	if role.ID == "" || role.BuiltIn {
		return fmt.Errorf("invalid custom role")
	}
	now := time.Now().UTC()
	if role.CreatedAt.IsZero() {
		role.CreatedAt = now
	}
	role.UpdatedAt = now
	role.Permissions = normalizedAuthorizationStrings(role.Permissions)
	return s.roles.set(ctx, role.ID, role)
}

func (s *RoleStore) Get(ctx context.Context, id string) (Role, error) {
	return s.roles.get(ctx, normalizeID(id))
}

func (s *RoleStore) Delete(ctx context.Context, id string) error {
	return s.roles.delete(ctx, normalizeID(id))
}

func (s *RoleStore) List(ctx context.Context) ([]Role, error) {
	roles, err := s.roles.filter(ctx, keepAll)
	if err == nil && roles == nil {
		roles = []Role{}
	}
	return roles, err
}

// GroupStore provides persistence and member lookup for flat groups.
type GroupStore struct{ groups collection[Group] }

func NewGroupStore(ts *TypedStore) *GroupStore {
	return &GroupStore{groups: newCollection[Group](ts, NSGroups)}
}

func (s *GroupStore) Set(ctx context.Context, group Group) error {
	group.ID = normalizeID(group.ID)
	if group.ID == "" {
		return fmt.Errorf("empty group id")
	}
	now := time.Now().UTC()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	group.UpdatedAt = now
	group.Members = normalizedAuthorizationStrings(group.Members)
	return s.groups.set(ctx, group.ID, group)
}

func (s *GroupStore) Get(ctx context.Context, id string) (Group, error) {
	return s.groups.get(ctx, normalizeID(id))
}

func (s *GroupStore) Delete(ctx context.Context, id string) error {
	return s.groups.delete(ctx, normalizeID(id))
}

func (s *GroupStore) List(ctx context.Context) ([]Group, error) {
	groups, err := s.groups.filter(ctx, keepAll)
	if err == nil && groups == nil {
		groups = []Group{}
	}
	return groups, err
}

func (s *GroupStore) ListForUser(ctx context.Context, userID string) ([]Group, error) {
	groups, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	userID = normalizeID(userID)
	result := make([]Group, 0)
	for _, group := range groups {
		for _, member := range group.Members {
			if member == userID {
				result = append(result, group)
				break
			}
		}
	}
	return result, nil
}

// PolicyStore stores policy bindings and derived principal/resource indexes.
type PolicyStore struct{ ts *TypedStore }

func NewPolicyStore(ts *TypedStore) *PolicyStore { return &PolicyStore{ts: ts} }

func (s *PolicyStore) Create(ctx context.Context, binding PolicyBinding) (PolicyBinding, error) {
	if binding.ID == "" {
		id, err := newAuthorizationID()
		if err != nil {
			return PolicyBinding{}, err
		}
		binding.ID = id
	}
	binding.Principal.ID = normalizeID(binding.Principal.ID)
	binding.Resource.ID = strings.TrimSpace(binding.Resource.ID)
	binding.RoleID = normalizeID(binding.RoleID)
	binding.Permissions = normalizedAuthorizationStrings(binding.Permissions)
	if err := binding.Validate(); err != nil {
		return PolicyBinding{}, err
	}
	now := time.Now().UTC()
	binding.CreatedAt = now
	binding.UpdatedAt = now
	if err := s.ts.Put(ctx, NSPolicyBindings, binding.ID, binding); err != nil {
		return PolicyBinding{}, err
	}
	if err := s.writeIndexes(ctx, binding); err != nil {
		_ = s.ts.Delete(ctx, NSPolicyBindings, binding.ID)
		return PolicyBinding{}, fmt.Errorf("index policy binding: %w", err)
	}
	return binding, nil
}

func (s *PolicyStore) Get(ctx context.Context, id string) (PolicyBinding, error) {
	var binding PolicyBinding
	err := s.ts.Get(ctx, NSPolicyBindings, id, &binding)
	return binding, err
}

// Update changes the mutable policy attributes while preserving the binding's
// identity, principal, resource, creator, and creation time. Keeping indexed
// identity immutable makes the authoritative record and its derived indexes a
// single stable lifecycle.
func (s *PolicyStore) Update(ctx context.Context, id string, update func(*PolicyBinding) error) (PolicyBinding, error) {
	if update == nil {
		return PolicyBinding{}, fmt.Errorf("policy update is required")
	}
	var result PolicyBinding
	err := store.Batch(ctx, s.ts.Store(), func(batchCtx context.Context) error {
		current, err := s.Get(batchCtx, id)
		if err != nil {
			return err
		}
		candidate := current
		candidate.Permissions = append([]string(nil), current.Permissions...)
		if err := update(&candidate); err != nil {
			return err
		}
		if candidate.ID != current.ID || candidate.Principal != current.Principal || candidate.Resource != current.Resource || candidate.GrantedBy != current.GrantedBy || !candidate.CreatedAt.Equal(current.CreatedAt) {
			return fmt.Errorf("policy binding identity is immutable")
		}
		candidate.RoleID = normalizeID(candidate.RoleID)
		candidate.Permissions = normalizedAuthorizationStrings(candidate.Permissions)
		if err := candidate.Validate(); err != nil {
			return err
		}
		candidate.UpdatedAt = time.Now().UTC()
		if err := s.ts.Set(batchCtx, NSPolicyBindings, candidate.ID, candidate); err != nil {
			return err
		}
		result = candidate
		return nil
	})
	return result, err
}

func (s *PolicyStore) Delete(ctx context.Context, id string) error {
	binding, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.ts.Delete(ctx, NSPolicyBindings, id); err != nil {
		return err
	}
	_ = s.ts.Delete(ctx, NSPolicyIndexes, principalBindingIndex(binding.Principal, id))
	_ = s.ts.Delete(ctx, NSPolicyIndexes, resourceBindingIndex(binding.Resource, id))
	return nil
}

func (s *PolicyStore) ListForPrincipal(ctx context.Context, principal PrincipalRef) ([]PolicyBinding, error) {
	return s.listFromIndex(ctx, principalBindingPrefix(principal))
}

func (s *PolicyStore) ListForResource(ctx context.Context, resource ResourceRef) ([]PolicyBinding, error) {
	return s.listFromIndex(ctx, resourceBindingPrefix(resource))
}

// List returns every authoritative policy binding. Callers must apply their
// own authorization filter before exposing the result.
func (s *PolicyStore) List(ctx context.Context) ([]PolicyBinding, error) {
	ids, err := s.ts.List(ctx, NSPolicyBindings)
	if err != nil {
		return nil, err
	}
	bindings := make([]PolicyBinding, 0, len(ids))
	for _, id := range ids {
		binding, err := s.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("read policy binding %q: %w", id, err)
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

// RebuildIndexes recreates all derived indexes from authoritative bindings.
// It is safe to call at startup and repairs interrupted multi-key writes. The
// rebuild commits as one batch, so readers never see an empty index and the
// store syncs once instead of once per index key.
func (s *PolicyStore) RebuildIndexes(ctx context.Context) error {
	return store.Batch(ctx, s.ts.Store(), s.rebuildIndexes)
}

func (s *PolicyStore) rebuildIndexes(ctx context.Context) error {
	indexKeys, err := s.ts.List(ctx, NSPolicyIndexes)
	if err != nil {
		return fmt.Errorf("list policy indexes: %w", err)
	}
	for _, key := range indexKeys {
		if err := s.ts.Delete(ctx, NSPolicyIndexes, key); err != nil {
			return fmt.Errorf("delete policy index %q: %w", key, err)
		}
	}
	bindingIDs, err := s.ts.List(ctx, NSPolicyBindings)
	if err != nil {
		return fmt.Errorf("list policy bindings: %w", err)
	}
	for _, id := range bindingIDs {
		binding, err := s.Get(ctx, id)
		if err != nil {
			return fmt.Errorf("read policy binding %q: %w", id, err)
		}
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("validate policy binding %q: %w", id, err)
		}
		if err := s.writeIndexes(ctx, binding); err != nil {
			return fmt.Errorf("rebuild policy binding %q: %w", id, err)
		}
	}
	return nil
}

func (s *PolicyStore) listFromIndex(ctx context.Context, prefix string) ([]PolicyBinding, error) {
	keys, err := s.ts.Scan(ctx, NSPolicyIndexes, prefix)
	if err != nil {
		return nil, err
	}
	bindings := make([]PolicyBinding, 0, len(keys))
	for _, key := range keys {
		var id string
		if err := s.ts.Get(ctx, NSPolicyIndexes, key, &id); err != nil {
			return nil, fmt.Errorf("read policy index %q: %w", key, err)
		}
		binding, err := s.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("read indexed policy %q: %w", id, err)
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func (s *PolicyStore) writeIndexes(ctx context.Context, binding PolicyBinding) error {
	principalKey := principalBindingIndex(binding.Principal, binding.ID)
	if err := s.ts.Put(ctx, NSPolicyIndexes, principalKey, binding.ID); err != nil {
		return err
	}
	if err := s.ts.Put(ctx, NSPolicyIndexes, resourceBindingIndex(binding.Resource, binding.ID), binding.ID); err != nil {
		_ = s.ts.Delete(ctx, NSPolicyIndexes, principalKey)
		return err
	}
	return nil
}

func principalBindingPrefix(principal PrincipalRef) string {
	return fmt.Sprintf("principal:%s:%s:", principal.Kind, normalizeID(principal.ID))
}

func principalBindingIndex(principal PrincipalRef, bindingID string) string {
	return principalBindingPrefix(principal) + bindingID
}

func resourceBindingPrefix(resource ResourceRef) string {
	return fmt.Sprintf("resource:%s:%s:", resource.Kind, resource.ID)
}

func resourceBindingIndex(resource ResourceRef, bindingID string) string {
	return resourceBindingPrefix(resource) + bindingID
}

func normalizedAuthorizationStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func newAuthorizationID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate authorization id: %w", err)
	}
	return hex.EncodeToString(data[:]), nil
}
