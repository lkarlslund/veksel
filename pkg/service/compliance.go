package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// Compliance protocols name the internal callers whose FolderSpace access
// differs from a user's: compliance access sees held-deleted items and the
// search indexer indexes them, while compliance and retention deletions are
// refused outright under legal hold instead of being preserved.
const (
	ProtocolCompliance    = "compliance"
	ProtocolRetention     = "retention"
	ProtocolSearchIndexer = "search-indexer"
)

// ErrLegalHold reports a destructive operation refused by an active legal hold.
var ErrLegalHold = errors.New("legal hold prevents deletion")

const (
	nsLegalHolds        = "compliance_holds"
	nsRetentionPolicies = "compliance_retention_policies"
	nsComplianceState   = "compliance_state"
)

// ComplianceAccess is the access context compliance officers' tooling uses to
// read an account, including items preserved by legal hold.
func ComplianceAccess(accountID string) AccessContext {
	return UserAccess(accountID, ProtocolCompliance)
}

// heldVisible reports whether access may see held-deleted folders and items.
func heldVisible(access AccessContext) bool {
	return access.Protocol == ProtocolCompliance || access.Protocol == ProtocolSearchIndexer
}

// systemDeletion reports whether a deletion is made by policy rather than by a
// user. Such deletions are refused under hold instead of being preserved.
func systemDeletion(access AccessContext) bool {
	return access.Protocol == ProtocolCompliance || access.Protocol == ProtocolRetention
}

// LegalHoldChecker answers whether an account is under an active legal hold.
type LegalHoldChecker interface {
	AccountHeld(ctx context.Context, accountID string) bool
}

// LegalHoldConfigurer is implemented by FolderSpace layers that enforce holds.
type LegalHoldConfigurer interface {
	SetLegalHolds(LegalHoldChecker)
}

// ConfigureLegalHolds installs checker on space when it enforces holds.
func ConfigureLegalHolds(space FolderSpace, checker LegalHoldChecker) {
	if configurable, ok := space.(LegalHoldConfigurer); ok {
		configurable.SetLegalHolds(checker)
	}
}

// Legal hold scopes.
const (
	HoldScopeAccount = "account"
	HoldScopeDomain  = "domain"
)

// LegalHold preserves every item of an account, or of every account with an
// identity in a domain, from deletion until released or past EndsAt.
type LegalHold struct {
	ID         string    `json:"id"`
	Scope      string    `json:"scope"`
	Target     string    `json:"target"`
	Reason     string    `json:"reason"`
	CaseID     string    `json:"case_id,omitempty"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	EndsAt     time.Time `json:"ends_at,omitzero"`
	ReleasedBy string    `json:"released_by,omitempty"`
	ReleasedAt time.Time `json:"released_at,omitzero"`
}

// Active reports whether the hold applies at now.
func (h LegalHold) Active(now time.Time) bool {
	return h.ReleasedAt.IsZero() && (h.EndsAt.IsZero() || now.Before(h.EndsAt))
}

// Retention scopes, from least to most specific.
const (
	RetentionScopeInstallation = "installation"
	RetentionScopeDomain       = "domain"
	RetentionScopeAccount      = "account"
)

// Retention actions.
const (
	RetentionActionDelete  = "delete"
	RetentionActionArchive = "archive"
)

// MaxRetentionDays bounds a retention age to one hundred years.
const MaxRetentionDays = 36500

// RetentionPolicy deletes, or moves to Archive, mail items older than Days by
// internal date. A policy applies to every mail folder in its scope, to the
// folders with one special use, or to the folders whose path matches a
// pattern; the most specific matching policy wins.
type RetentionPolicy struct {
	ID         string    `json:"id"`
	Scope      string    `json:"scope"`
	Target     string    `json:"target,omitempty"`
	SpecialUse string    `json:"special_use,omitempty"`
	Pattern    string    `json:"folder_pattern,omitempty"`
	Action     string    `json:"action"`
	Days       int       `json:"days"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

var retentionSpecialUses = []string{model.SpecialUseInbox, model.SpecialUseSent, model.SpecialUseArchive, model.SpecialUseTrash, model.SpecialUseJunk}

// Matches reports whether the policy applies to folder of an account with the
// given primary domain.
func (p RetentionPolicy) Matches(accountID, domain string, folder model.Folder) bool {
	switch p.Scope {
	case RetentionScopeAccount:
		if !strings.EqualFold(p.Target, accountID) {
			return false
		}
	case RetentionScopeDomain:
		if domain == "" || !strings.EqualFold(p.Target, domain) {
			return false
		}
	}
	if folder.Type != model.FolderTypeMail || model.IsHeldDeletedFolder(folder) {
		return false
	}
	switch {
	case p.SpecialUse != "":
		return folder.SpecialUse == p.SpecialUse
	case p.Pattern != "":
		return folderPatternMatches(p.Pattern, folder.Path)
	}
	return true
}

// specificity orders policies: scope first, then a special use or path
// pattern before a policy covering every folder.
func (p RetentionPolicy) specificity() int {
	rank := map[string]int{RetentionScopeInstallation: 0, RetentionScopeDomain: 1, RetentionScopeAccount: 2}[p.Scope] * 10
	switch {
	case p.SpecialUse != "":
		rank += 2
	case p.Pattern != "":
		rank++
	}
	return rank
}

// folderPatternMatches matches a case-insensitive path.Match pattern; a
// trailing "/**" also matches every descendant of the prefix.
func folderPatternMatches(pattern, folderPath string) bool {
	pattern, folderPath = strings.ToLower(strings.Trim(pattern, "/")), strings.ToLower(strings.Trim(folderPath, "/"))
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		return folderPath == prefix || strings.HasPrefix(folderPath, prefix+"/")
	}
	matched, err := path.Match(pattern, folderPath)
	return err == nil && matched
}

// Compliance owns legal holds and retention policies in the system store.
// Holds are held in memory so every FolderSpace deletion can check them
// without a store read when no hold is active.
type Compliance struct {
	ts    *model.TypedStore
	users *model.UserStore

	mu       sync.RWMutex
	now      func() time.Time
	holds    map[string]LegalHold
	policies map[string]RetentionPolicy
}

// NewCompliance loads holds and policies from the system store.
func NewCompliance(ctx context.Context, ts *model.TypedStore) (*Compliance, error) {
	if ts == nil {
		return nil, errors.New("compliance requires a system store")
	}
	for _, namespace := range []string{nsLegalHolds, nsRetentionPolicies, nsComplianceState} {
		if err := ts.EnsureNamespace(ctx, namespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("initialize %s: %w", namespace, err)
		}
	}
	c := &Compliance{ts: ts, users: ts.UserStore(), now: time.Now, holds: map[string]LegalHold{}, policies: map[string]RetentionPolicy{}}
	if err := ts.Store().Iterate(ctx, nsLegalHolds, "", func(_ string, value []byte) (bool, error) {
		var hold LegalHold
		if err := json.Unmarshal(value, &hold); err != nil {
			return false, err
		}
		c.holds[hold.ID] = hold
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("load legal holds: %w", err)
	}
	if err := ts.Store().Iterate(ctx, nsRetentionPolicies, "", func(_ string, value []byte) (bool, error) {
		var policy RetentionPolicy
		if err := json.Unmarshal(value, &policy); err != nil {
			return false, err
		}
		c.policies[policy.ID] = policy
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("load retention policies: %w", err)
	}
	return c, nil
}

// SetClock replaces the time source; tests use it to expire holds.
func (c *Compliance) SetClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func (c *Compliance) clock() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now().UTC()
}

func complianceID(prefix string) string {
	var raw [12]byte
	_, _ = rand.Read(raw[:])
	return prefix + "_" + hex.EncodeToString(raw[:])
}

// ListHolds returns every hold, active ones first, newest first.
func (c *Compliance) ListHolds() []LegalHold {
	c.mu.RLock()
	now := c.now()
	holds := make([]LegalHold, 0, len(c.holds))
	for _, hold := range c.holds {
		holds = append(holds, hold)
	}
	c.mu.RUnlock()
	sort.Slice(holds, func(i, j int) bool {
		if left, right := holds[i].Active(now), holds[j].Active(now); left != right {
			return left
		}
		return holds[i].CreatedAt.After(holds[j].CreatedAt)
	})
	return holds
}

// GetHold returns one hold.
func (c *Compliance) GetHold(id string) (LegalHold, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hold, ok := c.holds[id]
	if !ok {
		return LegalHold{}, store.ErrNotFound
	}
	return hold, nil
}

// PlaceHold validates and persists a new hold.
func (c *Compliance) PlaceHold(ctx context.Context, hold LegalHold) (LegalHold, error) {
	hold.Scope = strings.ToLower(strings.TrimSpace(hold.Scope))
	hold.Target = strings.ToLower(strings.TrimSpace(hold.Target))
	hold.Reason, hold.CaseID = strings.TrimSpace(hold.Reason), strings.TrimSpace(hold.CaseID)
	switch hold.Scope {
	case HoldScopeAccount:
		if _, err := c.users.Get(ctx, hold.Target); err != nil {
			return LegalHold{}, fmt.Errorf("account %q: %w", hold.Target, err)
		}
	case HoldScopeDomain:
		if _, err := c.ts.DomainStore().Get(ctx, hold.Target); err != nil {
			return LegalHold{}, fmt.Errorf("domain %q: %w", hold.Target, err)
		}
	default:
		return LegalHold{}, errors.New("hold scope must be account or domain")
	}
	if hold.Reason == "" && hold.CaseID == "" {
		return LegalHold{}, errors.New("a reason or case ID is required")
	}
	if len(hold.Reason) > 1024 || len(hold.CaseID) > 128 {
		return LegalHold{}, errors.New("reason or case ID is too long")
	}
	now := c.clock()
	if !hold.EndsAt.IsZero() && !hold.EndsAt.After(now) {
		return LegalHold{}, errors.New("hold end date must be in the future")
	}
	hold.ID, hold.CreatedAt, hold.ReleasedAt, hold.ReleasedBy = complianceID("hold"), now, time.Time{}, ""
	if err := c.ts.Put(ctx, nsLegalHolds, hold.ID, hold); err != nil {
		return LegalHold{}, err
	}
	c.mu.Lock()
	c.holds[hold.ID] = hold
	c.mu.Unlock()
	return hold, nil
}

// ReleaseHold ends a hold. Released holds remain as evidence.
func (c *Compliance) ReleaseHold(ctx context.Context, id, actor string) (LegalHold, error) {
	hold, err := c.GetHold(id)
	if err != nil {
		return LegalHold{}, err
	}
	if !hold.ReleasedAt.IsZero() {
		return LegalHold{}, errors.New("hold is already released")
	}
	hold.ReleasedAt, hold.ReleasedBy = c.clock(), actor
	if err := c.ts.Set(ctx, nsLegalHolds, hold.ID, hold); err != nil {
		return LegalHold{}, err
	}
	c.mu.Lock()
	c.holds[hold.ID] = hold
	c.mu.Unlock()
	return hold, nil
}

// HoldsFor returns the holds active now on accountID, directly or through a
// domain of any of its identities.
func (c *Compliance) HoldsFor(ctx context.Context, accountID string) []LegalHold {
	accountID = strings.ToLower(strings.TrimSpace(accountID))
	c.mu.RLock()
	now := c.now()
	var direct, domain []LegalHold
	for _, hold := range c.holds {
		if !hold.Active(now) {
			continue
		}
		if hold.Scope == HoldScopeAccount && hold.Target == accountID {
			direct = append(direct, hold)
		} else if hold.Scope == HoldScopeDomain {
			domain = append(domain, hold)
		}
	}
	c.mu.RUnlock()
	if len(domain) > 0 {
		// A domain hold covers the accounts whose primary identity is in the
		// domain, the same membership that domain administration uses; an
		// alias there does not bring another tenant's account under it.
		if primary := c.PrimaryDomain(ctx, accountID); primary != "" {
			for _, hold := range domain {
				if hold.Target == primary {
					direct = append(direct, hold)
				}
			}
		}
	}
	sort.Slice(direct, func(i, j int) bool { return direct[i].CreatedAt.Before(direct[j].CreatedAt) })
	return direct
}

// AccountHeld implements LegalHoldChecker.
func (c *Compliance) AccountHeld(ctx context.Context, accountID string) bool {
	return len(c.HoldsFor(ctx, accountID)) > 0
}

// RequireAccountDeletable refuses deleting a held account.
func (c *Compliance) RequireAccountDeletable(ctx context.Context, accountID string) error {
	if holds := c.HoldsFor(ctx, accountID); len(holds) > 0 {
		return fmt.Errorf("%w: account %s is held by %s", ErrLegalHold, accountID, holds[0].ID)
	}
	return nil
}

// ListPolicies returns every retention policy, least specific first.
func (c *Compliance) ListPolicies() []RetentionPolicy {
	c.mu.RLock()
	policies := make([]RetentionPolicy, 0, len(c.policies))
	for _, policy := range c.policies {
		policies = append(policies, policy)
	}
	c.mu.RUnlock()
	sort.Slice(policies, func(i, j int) bool {
		if left, right := policies[i].specificity(), policies[j].specificity(); left != right {
			return left < right
		}
		if policies[i].Target != policies[j].Target {
			return policies[i].Target < policies[j].Target
		}
		return policies[i].ID < policies[j].ID
	})
	return policies
}

// GetPolicy returns one retention policy.
func (c *Compliance) GetPolicy(id string) (RetentionPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	policy, ok := c.policies[id]
	if !ok {
		return RetentionPolicy{}, store.ErrNotFound
	}
	return policy, nil
}

// NormalizePolicy validates a policy's shape without persisting it.
func NormalizePolicy(policy RetentionPolicy) (RetentionPolicy, error) {
	policy.Scope = strings.ToLower(strings.TrimSpace(policy.Scope))
	policy.Target = strings.ToLower(strings.TrimSpace(policy.Target))
	policy.SpecialUse = strings.ToLower(strings.TrimSpace(policy.SpecialUse))
	policy.Pattern = strings.Trim(strings.TrimSpace(policy.Pattern), "/")
	policy.Action = strings.ToLower(strings.TrimSpace(policy.Action))
	switch policy.Scope {
	case RetentionScopeInstallation:
		policy.Target = ""
	case RetentionScopeDomain, RetentionScopeAccount:
		if policy.Target == "" {
			return RetentionPolicy{}, fmt.Errorf("a %s policy requires a target", policy.Scope)
		}
	default:
		return RetentionPolicy{}, errors.New("policy scope must be installation, domain, or account")
	}
	if policy.SpecialUse != "" && policy.Pattern != "" {
		return RetentionPolicy{}, errors.New("choose a special folder or a folder pattern, not both")
	}
	if policy.SpecialUse != "" && !slices.Contains(retentionSpecialUses, policy.SpecialUse) {
		return RetentionPolicy{}, fmt.Errorf("special folder must be one of %s", strings.Join(retentionSpecialUses, ", "))
	}
	if policy.Pattern != "" {
		if len(policy.Pattern) > 256 {
			return RetentionPolicy{}, errors.New("folder pattern is too long")
		}
		if _, err := path.Match(strings.TrimSuffix(policy.Pattern, "/**"), ""); err != nil {
			return RetentionPolicy{}, fmt.Errorf("invalid folder pattern: %w", err)
		}
	}
	if policy.Action != RetentionActionDelete && policy.Action != RetentionActionArchive {
		return RetentionPolicy{}, errors.New("policy action must be delete or archive")
	}
	if policy.Action == RetentionActionArchive && policy.SpecialUse == model.SpecialUseArchive {
		return RetentionPolicy{}, errors.New("an archive policy cannot target the Archive folder")
	}
	if policy.Days < 1 || policy.Days > MaxRetentionDays {
		return RetentionPolicy{}, fmt.Errorf("days must be between 1 and %d", MaxRetentionDays)
	}
	return policy, nil
}

// PutPolicy creates a policy, or replaces the policy with the same ID.
func (c *Compliance) PutPolicy(ctx context.Context, policy RetentionPolicy) (RetentionPolicy, error) {
	policy, err := NormalizePolicy(policy)
	if err != nil {
		return RetentionPolicy{}, err
	}
	switch policy.Scope {
	case RetentionScopeDomain:
		if _, err := c.ts.DomainStore().Get(ctx, policy.Target); err != nil {
			return RetentionPolicy{}, fmt.Errorf("domain %q: %w", policy.Target, err)
		}
	case RetentionScopeAccount:
		if _, err := c.users.Get(ctx, policy.Target); err != nil {
			return RetentionPolicy{}, fmt.Errorf("account %q: %w", policy.Target, err)
		}
	}
	now := c.clock()
	if policy.ID == "" {
		policy.ID, policy.CreatedAt = complianceID("ret"), now
	} else {
		existing, err := c.GetPolicy(policy.ID)
		if err != nil {
			return RetentionPolicy{}, err
		}
		policy.CreatedAt, policy.CreatedBy = existing.CreatedAt, existing.CreatedBy
	}
	policy.UpdatedAt = now
	if err := c.ts.Set(ctx, nsRetentionPolicies, policy.ID, policy); err != nil {
		return RetentionPolicy{}, err
	}
	c.mu.Lock()
	c.policies[policy.ID] = policy
	c.mu.Unlock()
	return policy, nil
}

// DeletePolicy removes a retention policy.
func (c *Compliance) DeletePolicy(ctx context.Context, id string) error {
	if _, err := c.GetPolicy(id); err != nil {
		return err
	}
	if err := c.ts.Delete(ctx, nsRetentionPolicies, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	c.mu.Lock()
	delete(c.policies, id)
	c.mu.Unlock()
	return nil
}

// EffectivePolicy returns the most specific policy for folder, owned by
// accountID whose primary identity is in domain. Equal specificity prefers
// the policy keeping items longest, so overlapping rules never delete early.
func (c *Compliance) EffectivePolicy(accountID, domain string, folder model.Folder) (RetentionPolicy, bool) {
	accountID, domain = strings.ToLower(accountID), strings.ToLower(domain)
	var best RetentionPolicy
	found := false
	for _, policy := range c.ListPolicies() {
		if !policy.Matches(accountID, domain, folder) {
			continue
		}
		if !found || policy.specificity() > best.specificity() || policy.specificity() == best.specificity() && policy.Days > best.Days {
			best, found = policy, true
		}
	}
	return best, found
}

// PrimaryDomain returns accountID's primary identity domain.
func (c *Compliance) PrimaryDomain(ctx context.Context, accountID string) string {
	domain, _ := c.users.PrimaryDomain(ctx, accountID)
	return domain
}
