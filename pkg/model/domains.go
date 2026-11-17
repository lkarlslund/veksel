package model

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const MaxDKIMKeysPerDomain = 8

var (
	ErrDKIMRevisionConflict = errors.New("DKIM key revision conflict")
	ErrDKIMSelectorExists   = errors.New("DKIM selector already exists")
	ErrDKIMKeyNotFound      = errors.New("DKIM key not found")
	ErrDKIMKeyState         = errors.New("DKIM key state does not allow this operation")
	ErrDKIMKeyLimit         = errors.New("DKIM key limit reached")
	dkimSelectorPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$`)
)

// DomainStore provides typed CRUD for Domain entities.
type DomainStore struct {
	ts      *TypedStore
	domains collection[Domain]
}

// NewDomainStore returns a DomainStore backed by ts.
func NewDomainStore(ts *TypedStore) *DomainStore {
	return &DomainStore{ts: ts, domains: newCollection[Domain](ts, NSDomains)}
}

// Create stores a new domain. Returns store.ErrExists if the domain already exists.
func (ds *DomainStore) Create(ctx context.Context, id string) error {
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	d := Domain{
		ID:               normalizeID(id),
		Enabled:          true,
		VirusScanEnabled: true,
		CreatedAt:        time.Now().UTC(),
	}
	return ds.domains.put(ctx, d.ID, d)
}

// Get returns a domain by ID.
func (ds *DomainStore) Get(ctx context.Context, id string) (Domain, error) {
	return ds.domains.get(ctx, normalizeID(id))
}

// Update modifies an existing domain.
func (ds *DomainStore) Update(ctx context.Context, id string, fn func(*Domain)) error {
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	return ds.updateLocked(ctx, id, fn)
}

func (ds *DomainStore) updateLocked(ctx context.Context, id string, fn func(*Domain)) error {
	d, err := ds.Get(ctx, id)
	if err != nil {
		return err
	}
	fn(&d)
	return ds.domains.set(ctx, d.ID, d)
}

// Delete removes a domain.
func (ds *DomainStore) Delete(ctx context.Context, id string) error {
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	id = normalizeID(id)
	aliases, err := ds.ts.RecipientAliasStore().List(ctx)
	if err != nil {
		return err
	}
	for _, alias := range aliases {
		if alias.DomainID == id {
			return fmt.Errorf("domain %q still has recipient aliases", id)
		}
	}
	return ds.domains.delete(ctx, id)
}

// List returns all domains.
func (ds *DomainStore) List(ctx context.Context) ([]Domain, error) {
	return ds.domains.filter(ctx, keepAll)
}

// SetDKIMKeys stores DKIM key pair and selector for a domain.
func (ds *DomainStore) SetDKIMKeys(ctx context.Context, id string, privateKey, publicKey, selector string) error {
	selector, err := ValidateDKIMSelector(selector)
	if err != nil {
		return err
	}
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	domain, err := ds.Get(ctx, id)
	if err != nil {
		return err
	}
	if len(DKIMKeys(domain)) != 0 {
		return ErrDKIMSelectorExists
	}
	now := time.Now().UTC()
	domain.DkimPrivateKey = privateKey
	domain.DkimPublicKey = publicKey
	domain.DkimSelector = selector
	domain.DKIMKeys = []DKIMKey{{Selector: selector, PrivateKey: privateKey, PublicKey: publicKey, State: DKIMKeyActive, CreatedAt: now, ActivatedAt: now}}
	domain.DKIMRevision++
	return ds.domains.set(ctx, domain.ID, domain)
}

// RemoveDKIMKeys clears DKIM key pair and selector for a domain.
func (ds *DomainStore) RemoveDKIMKeys(ctx context.Context, id string) error {
	return ds.Update(ctx, id, func(d *Domain) {
		d.DkimPrivateKey = ""
		d.DkimPublicKey = ""
		d.DkimSelector = ""
		d.DKIMKeys = nil
		d.DKIMRevision++
	})
}

// HasDKIM returns true if the domain has DKIM keys configured.
func (ds *DomainStore) HasDKIM(ctx context.Context, id string) (bool, error) {
	d, err := ds.Get(ctx, id)
	if err != nil {
		return false, err
	}
	return len(DKIMKeys(d)) != 0, nil
}

// ValidateDKIMSelector normalizes and validates a selector as one or more DNS
// labels. Underscores are accepted because they are deployed by DKIM tooling.
func ValidateDKIMSelector(selector string) (string, error) {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" || len(selector) > 253 || !dkimSelectorPattern.MatchString(selector) {
		return "", fmt.Errorf("invalid DKIM selector %q", selector)
	}
	return selector, nil
}

// DKIMKeys returns the canonical key set. Legacy single-key domains are
// represented as one active key without mutating storage.
func DKIMKeys(domain Domain) []DKIMKey {
	keys := append([]DKIMKey(nil), domain.DKIMKeys...)
	if len(keys) == 0 && domain.DkimPrivateKey != "" && domain.DkimPublicKey != "" && domain.DkimSelector != "" {
		keys = []DKIMKey{{
			Selector: domain.DkimSelector, PrivateKey: domain.DkimPrivateKey,
			PublicKey: domain.DkimPublicKey, State: DKIMKeyActive,
			CreatedAt: domain.CreatedAt, ActivatedAt: domain.CreatedAt,
		}}
	}
	return keys
}

// ActiveDKIMKey returns the only key eligible for outbound signing.
func ActiveDKIMKey(domain Domain) (DKIMKey, bool) {
	for _, key := range DKIMKeys(domain) {
		if key.State == DKIMKeyActive && key.PrivateKey != "" && key.Selector != "" {
			return key, true
		}
	}
	return DKIMKey{}, false
}

// StageDKIMKey adds generated material without changing the active signer.
func (ds *DomainStore) StageDKIMKey(ctx context.Context, id string, expectedRevision uint64, key DKIMKey) (Domain, error) {
	selector, err := ValidateDKIMSelector(key.Selector)
	if err != nil {
		return Domain{}, err
	}
	if strings.TrimSpace(key.PrivateKey) == "" || strings.TrimSpace(key.PublicKey) == "" {
		return Domain{}, errors.New("DKIM private and public keys are required")
	}
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	domain, err := ds.Get(ctx, id)
	if err != nil {
		return Domain{}, err
	}
	if domain.DKIMRevision != expectedRevision {
		return Domain{}, ErrDKIMRevisionConflict
	}
	keys := DKIMKeys(domain)
	if len(keys) >= MaxDKIMKeysPerDomain {
		return Domain{}, ErrDKIMKeyLimit
	}
	for _, existing := range keys {
		if strings.EqualFold(existing.Selector, selector) {
			return Domain{}, ErrDKIMSelectorExists
		}
	}
	key.Selector = selector
	key.State = DKIMKeyStaged
	key.CreatedAt = time.Now().UTC()
	key.ActivatedAt = time.Time{}
	domain.DKIMKeys = append(keys, key)
	domain.DKIMRevision++
	syncActiveDKIMFields(&domain)
	if err := ds.domains.set(ctx, domain.ID, domain); err != nil {
		return Domain{}, err
	}
	return domain, nil
}

// ActivateDKIMKey switches signing atomically and retains the former active
// key as retiring. A retiring key may be activated again to roll back.
func (ds *DomainStore) ActivateDKIMKey(ctx context.Context, id, selector string, expectedRevision uint64) (Domain, error) {
	selector, err := ValidateDKIMSelector(selector)
	if err != nil {
		return Domain{}, err
	}
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	domain, err := ds.Get(ctx, id)
	if err != nil {
		return Domain{}, err
	}
	if domain.DKIMRevision != expectedRevision {
		return Domain{}, ErrDKIMRevisionConflict
	}
	domain.DKIMKeys = DKIMKeys(domain)
	target := -1
	for i := range domain.DKIMKeys {
		if strings.EqualFold(domain.DKIMKeys[i].Selector, selector) {
			target = i
			break
		}
	}
	if target < 0 {
		return Domain{}, ErrDKIMKeyNotFound
	}
	if state := domain.DKIMKeys[target].State; state != DKIMKeyStaged && state != DKIMKeyRetiring {
		return Domain{}, ErrDKIMKeyState
	}
	for i := range domain.DKIMKeys {
		if domain.DKIMKeys[i].State == DKIMKeyActive {
			domain.DKIMKeys[i].State = DKIMKeyRetiring
		}
	}
	domain.DKIMKeys[target].State = DKIMKeyActive
	domain.DKIMKeys[target].ActivatedAt = time.Now().UTC()
	domain.DKIMRevision++
	syncActiveDKIMFields(&domain)
	if err := ds.domains.set(ctx, domain.ID, domain); err != nil {
		return Domain{}, err
	}
	return domain, nil
}

// DeleteDKIMKey cancels a staged key or retires an old key. The active signer
// cannot be removed through this operation.
func (ds *DomainStore) DeleteDKIMKey(ctx context.Context, id, selector string, expectedRevision uint64) (Domain, error) {
	selector, err := ValidateDKIMSelector(selector)
	if err != nil {
		return Domain{}, err
	}
	ds.ts.domainMu.Lock()
	defer ds.ts.domainMu.Unlock()
	domain, err := ds.Get(ctx, id)
	if err != nil {
		return Domain{}, err
	}
	if domain.DKIMRevision != expectedRevision {
		return Domain{}, ErrDKIMRevisionConflict
	}
	domain.DKIMKeys = DKIMKeys(domain)
	target := -1
	for i := range domain.DKIMKeys {
		if strings.EqualFold(domain.DKIMKeys[i].Selector, selector) {
			target = i
			break
		}
	}
	if target < 0 {
		return Domain{}, ErrDKIMKeyNotFound
	}
	if domain.DKIMKeys[target].State == DKIMKeyActive {
		return Domain{}, ErrDKIMKeyState
	}
	domain.DKIMKeys = append(domain.DKIMKeys[:target], domain.DKIMKeys[target+1:]...)
	domain.DKIMRevision++
	syncActiveDKIMFields(&domain)
	if err := ds.domains.set(ctx, domain.ID, domain); err != nil {
		return Domain{}, err
	}
	return domain, nil
}

func syncActiveDKIMFields(domain *Domain) {
	domain.DkimPrivateKey = ""
	domain.DkimPublicKey = ""
	domain.DkimSelector = ""
	for _, key := range domain.DKIMKeys {
		if key.State == DKIMKeyActive {
			domain.DkimPrivateKey = key.PrivateKey
			domain.DkimPublicKey = key.PublicKey
			domain.DkimSelector = key.Selector
			return
		}
	}
}

func normalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
