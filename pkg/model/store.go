package model

import (
	"context"
	"encoding/json"
	"sync"

	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
)

var log = logpkg.For(logpkg.ModuleModel)

// TypedStore wraps the generic store.Store with JSON serialization helpers.
type TypedStore struct {
	s        store.Store
	b        store.Backend
	objects  *objectstore.Store
	domainMu sync.Mutex

	// Typed stores are initialized together by NewTypedStore so concurrent
	// protocol workers can use these accessors without synchronization.
	userStore           *UserStore
	recipientAliasStore *RecipientAliasStore
	userAliasStore      *UserAliasStore
	folderStore         *FolderStore
	itemStore           *ItemStore
	itemHistoryStore    *ItemHistoryStore
	domainStore         *DomainStore
	outboundRouteStore  *OutboundRouteStore
	senderRouteStore    *SenderRouteStore
	addressRewriteStore *AddressRewriteStore
	journalRuleStore    *JournalRuleStore
	bccRuleStore        *BCCRuleStore
	tlsCertStore        *TLSCertStore
	settingsStore       *SettingsStore
}

// NewTypedStore wraps s for typed access.
// The backend parameter identifies the store backend (e.g. "json" or "pebble").
func NewTypedStore(s store.Store, backend store.Backend) *TypedStore {
	return NewTypedStoreWithObjects(s, backend, nil)
}

// NewTypedStoreWithObjects wraps an index store and keeps item payloads in the
// supplied immutable object store. A nil object store retains the legacy
// inline-payload behavior for test and migration compatibility.
func NewTypedStoreWithObjects(s store.Store, backend store.Backend, objects *objectstore.Store) *TypedStore {
	ts := &TypedStore{s: s, b: backend, objects: objects}
	ts.userStore = NewUserStore(ts)
	ts.recipientAliasStore = NewRecipientAliasStore(ts)
	ts.userAliasStore = NewUserAliasStore(ts)
	ts.folderStore = NewFolderStore(ts)
	ts.itemStore = NewItemStore(ts)
	ts.itemStore.SetUserStore(ts.userStore)
	ts.itemHistoryStore = NewItemHistoryStore(ts)
	ts.domainStore = NewDomainStore(ts)
	ts.outboundRouteStore = NewOutboundRouteStore(ts)
	ts.senderRouteStore = newMailFlowStore[SenderRoute](ts, NSSenderRoutes, nil)
	ts.addressRewriteStore = newMailFlowStore[AddressRewrite](ts, NSAddressRewrites, checkRewriteChains)
	ts.journalRuleStore = newMailFlowStore[JournalRule](ts, NSJournalRules, nil)
	ts.bccRuleStore = newMailFlowStore[BCCRule](ts, NSBCCRules, nil)
	ts.tlsCertStore = NewTLSCertStore(ts)
	ts.settingsStore = NewSettingsStore(ts)
	return ts
}

// Store returns the underlying generic store.Store.
func (ts *TypedStore) Store() store.Store {
	return ts.s
}

// Backend returns the store backend identifier (e.g. "json" or "pebble").
func (ts *TypedStore) Backend() store.Backend {
	return ts.b
}

// UserStore returns the UserStore instance.
func (ts *TypedStore) UserStore() *UserStore {
	return ts.userStore
}

// RecipientAliasStore returns the global local-recipient alias store.
func (ts *TypedStore) RecipientAliasStore() *RecipientAliasStore {
	return ts.recipientAliasStore
}

// UserAliasStore returns the self-service temporary alias store.
func (ts *TypedStore) UserAliasStore() *UserAliasStore {
	return ts.userAliasStore
}

// FolderStore returns the FolderStore instance.
func (ts *TypedStore) FolderStore() *FolderStore {
	return ts.folderStore
}

// ItemStore returns the ItemStore instance.
func (ts *TypedStore) ItemStore() *ItemStore {
	return ts.itemStore
}

// ItemHistoryStore returns the generic immutable item-version store.
func (ts *TypedStore) ItemHistoryStore() *ItemHistoryStore {
	return ts.itemHistoryStore
}

// DomainStore returns the DomainStore instance.
func (ts *TypedStore) DomainStore() *DomainStore {
	return ts.domainStore
}

// OutboundRouteStore returns the destination-specific outbound routing store.
func (ts *TypedStore) OutboundRouteStore() *OutboundRouteStore {
	return ts.outboundRouteStore
}

// SenderRouteStore returns the sender-dependent outbound routing store.
func (ts *TypedStore) SenderRouteStore() *SenderRouteStore { return ts.senderRouteStore }

// AddressRewriteStore returns the address rewriting (canonical map) store.
func (ts *TypedStore) AddressRewriteStore() *AddressRewriteStore { return ts.addressRewriteStore }

// JournalRuleStore returns the journaling rule store.
func (ts *TypedStore) JournalRuleStore() *JournalRuleStore { return ts.journalRuleStore }

// BCCRuleStore returns the always-BCC rule store.
func (ts *TypedStore) BCCRuleStore() *BCCRuleStore { return ts.bccRuleStore }

// TLSCertStore returns the TLSCertStore instance.
func (ts *TypedStore) TLSCertStore() *TLSCertStore {
	return ts.tlsCertStore
}

// SettingsStore returns the SettingsStore instance.
func (ts *TypedStore) SettingsStore() *SettingsStore {
	return ts.settingsStore
}

// Get decodes a JSON value from the store.
func (ts *TypedStore) Get(ctx context.Context, ns, key string, v any) error {
	data, err := ts.s.Get(ctx, ns, key)
	if err != nil {
		log.Debug("model: get failed", "namespace", ns, "key", key, "error", err)
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		log.Debug("model: unmarshal failed", "namespace", ns, "key", key, "error", err)
		return err
	}
	return nil
}

// Set encodes and stores v as JSON.
func (ts *TypedStore) Set(ctx context.Context, ns, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		log.Debug("model: marshal failed", "namespace", ns, "key", key, "error", err)
		return err
	}
	if err := ts.s.Set(ctx, ns, key, data); err != nil {
		log.Debug("model: set failed", "namespace", ns, "key", key, "error", err)
		return err
	}
	return nil
}

// Put encodes and stores v only if the key does not exist.
func (ts *TypedStore) Put(ctx context.Context, ns, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ts.s.Put(ctx, ns, key, data)
}

// Delete delegates to the underlying store.
func (ts *TypedStore) Delete(ctx context.Context, ns, key string) error {
	return ts.s.Delete(ctx, ns, key)
}

// List delegates to the underlying store.
func (ts *TypedStore) List(ctx context.Context, ns string) ([]string, error) {
	return ts.s.List(ctx, ns)
}

// Scan delegates to the underlying store.
func (ts *TypedStore) Scan(ctx context.Context, ns, prefix string) ([]string, error) {
	return ts.s.Scan(ctx, ns, prefix)
}

// StringList gets a JSON array of strings.
func (ts *TypedStore) StringList(ctx context.Context, ns, key string) ([]string, error) {
	var out []string
	if err := ts.Get(ctx, ns, key, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetStringList stores a JSON array of strings.
func (ts *TypedStore) SetStringList(ctx context.Context, ns, key string, list []string) error {
	return ts.Set(ctx, ns, key, list)
}

// EnsureNamespace creates ns if it does not exist.
func (ts *TypedStore) EnsureNamespace(ctx context.Context, ns string) error {
	return ensureNamespace(ctx, ts.s, ns)
}

// ListNamespaces delegates to the underlying store.
func (ts *TypedStore) ListNamespaces(ctx context.Context) ([]string, error) {
	return ts.s.ListNamespaces(ctx)
}

// CreateNamespace delegates to the underlying store.
func (ts *TypedStore) CreateNamespace(ctx context.Context, ns string) error {
	return ts.s.CreateNamespace(ctx, ns)
}

// DeleteNamespace delegates to the underlying store.
func (ts *TypedStore) DeleteNamespace(ctx context.Context, ns string) error {
	return ts.s.DeleteNamespace(ctx, ns)
}

// Close delegates to the underlying store.
func (ts *TypedStore) Close() error {
	return ts.s.Close()
}
