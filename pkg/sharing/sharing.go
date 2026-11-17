// Package sharing implements revocable, resource-scoped bearer links over the
// same authorization-aware FolderSpace used by authenticated protocols.
package sharing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	TokenVersion = "v1"
	MaxPageSize  = 100
	MaxItemBytes = 50 << 20
	MaxUseLimit  = 1_000_000
)

var (
	ErrUnavailable    = errors.New("share link is unavailable")
	ErrReadOnly       = errors.New("share link is read-only")
	ErrTargetMismatch = errors.New("item is outside the shared resource")
	ErrInvalidInput   = errors.New("invalid share request")
)

// TargetKind distinguishes a whole-folder capability from an exact-item one.
type TargetKind string

const (
	TargetFolder TargetKind = "folder"
	TargetItem   TargetKind = "item"
)

// Access is the bounded operation set granted by a link.
type Access string

const (
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

// PublishFormat turns a read-only calendar folder link into a published
// iCalendar feed that serves either every event or only busy times. A
// published link serves nothing but its feed.
type PublishFormat string

const (
	PublishICS      PublishFormat = "ics"
	PublishFreeBusy PublishFormat = "freebusy"
)

// Link is the secret-free management lifecycle projection.
type Link struct {
	ID            string           `json:"id"`
	CreatedBy     string           `json:"created_by"`
	TargetOwnerID string           `json:"target_owner_id"`
	TargetKind    TargetKind       `json:"target_kind"`
	FolderID      string           `json:"folder_id"`
	ItemID        string           `json:"item_id,omitempty"`
	TargetName    string           `json:"target_name"`
	FolderType    model.FolderType `json:"folder_type"`
	Access        Access           `json:"access"`
	Publish       PublishFormat    `json:"publish,omitempty"`
	ExpiresAt     time.Time        `json:"expires_at,omitzero"`
	MaxUses       uint64           `json:"max_uses,omitempty"`
	UseCount      uint64           `json:"use_count"`
	LastUsedAt    time.Time        `json:"last_used_at,omitzero"`
	RevokedAt     time.Time        `json:"revoked_at,omitzero"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// Active reports whether time, revocation, and use bounds currently permit a
// request. Authorization and target existence are rechecked separately.
func (l Link) Active(now time.Time) bool {
	return l.RevokedAt.IsZero() && (l.ExpiresAt.IsZero() || l.ExpiresAt.After(now)) && (l.MaxUses == 0 || l.UseCount < l.MaxUses)
}

// RemainingUses returns nil for unlimited links.
func (l Link) RemainingUses() *uint64 {
	if l.MaxUses == 0 {
		return nil
	}
	remaining := l.MaxUses - min(l.MaxUses, l.UseCount)
	return &remaining
}

type record struct {
	Link
	SecretHash []byte `json:"secret_hash"`
}

// CreateRequest defines one exact capability target and its lifecycle bounds.
type CreateRequest struct {
	TargetKind TargetKind `json:"target_kind"`
	FolderID   string     `json:"folder_id,omitempty"`
	ItemID     string     `json:"item_id,omitempty"`
	Access     Access     `json:"access"`
	// Publish, when set, publishes a calendar folder as a read-only feed.
	Publish   PublishFormat `json:"publish,omitempty"`
	ExpiresAt time.Time     `json:"expires_at,omitzero"`
	MaxUses   uint64        `json:"max_uses,omitempty"`
}

// IssuedLink includes the bearer token exactly once. It is never persisted.
type IssuedLink struct {
	Link
	Token string `json:"token"`
}

// Item is the storage-neutral public projection. Internal indexes and external
// synchronization identifiers are deliberately omitted.
type Item struct {
	ID           string            `json:"id"`
	Name         string            `json:"name,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Flags        []string          `json:"flags,omitempty"`
	Size         int64             `json:"size"`
	InternalDate time.Time         `json:"internal_date,omitzero"`
	Data         []byte            `json:"data,omitempty"`
}

// Folder is the public folder projection. Ownership, hierarchy identities,
// synchronization metadata, and storage counters not needed by the public UI
// are deliberately omitted.
type Folder struct {
	Name         string           `json:"name"`
	Path         string           `json:"path"`
	Type         model.FolderType `json:"type"`
	ItemCount    int64            `json:"item_count"`
	LogicalBytes int64            `json:"logical_bytes"`
}

// Resource is one claimed public response. Folder links return a bounded page;
// item links return only their exact item.
type Resource struct {
	TargetKind    TargetKind       `json:"target_kind"`
	TargetName    string           `json:"target_name"`
	FolderType    model.FolderType `json:"folder_type"`
	Access        Access           `json:"access"`
	ExpiresAt     time.Time        `json:"expires_at,omitzero"`
	Folder        Folder           `json:"folder"`
	Items         []Item           `json:"items,omitempty"`
	Item          *Item            `json:"item,omitempty"`
	Total         int64            `json:"total,omitempty"`
	NextBeforeUID uint32           `json:"next_before_uid,omitempty"`
	Remaining     *uint64          `json:"remaining_uses,omitempty"`
}

// ItemInput is the bounded public mutation payload.
type ItemInput struct {
	Name    string            `json:"name,omitempty"`
	Data    []byte            `json:"data"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Service owns capability lifecycle, policy checks, and the FolderSpace
// adapter. Link records live in the global control-plane store; target data
// remains in its account-selected backend.
type Service struct {
	ts         *model.TypedStore
	space      service.FolderSpace
	authorizer *authz.Engine
	audit      *audit.Logger
	now        func() time.Time
	random     io.Reader
}

func New(ctx context.Context, ts *model.TypedStore, space service.FolderSpace, authorizer *authz.Engine) (*Service, error) {
	if ts == nil || space == nil || authorizer == nil {
		return nil, errors.New("share store, folder space, and authorizer are required")
	}
	if err := ts.EnsureNamespace(ctx, model.NSShareLinks); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, fmt.Errorf("initialize share links: %w", err)
	}
	return &Service{ts: ts, space: space, authorizer: authorizer, audit: audit.New(ts), now: time.Now, random: rand.Reader}, nil
}

// SetFolderSpace replaces the bootstrap space with the fully routed production
// stack. It must be called during process wiring before handlers start serving.
func (s *Service) SetFolderSpace(space service.FolderSpace) {
	if space != nil {
		s.space = space
	}
}

func (s *Service) Create(ctx context.Context, actor model.PrincipalRef, request CreateRequest) (IssuedLink, error) {
	if actor.Kind != model.PrincipalUser || actor.ID == "" {
		return IssuedLink{}, service.ErrForbidden
	}
	if request.TargetKind != TargetFolder && request.TargetKind != TargetItem {
		return IssuedLink{}, invalidInput("target_kind must be folder or item")
	}
	if request.Access != AccessRead && request.Access != AccessWrite {
		return IssuedLink{}, invalidInput("access must be read or write")
	}
	if request.MaxUses > MaxUseLimit {
		return IssuedLink{}, invalidInput("max_uses cannot exceed %d", MaxUseLimit)
	}
	now := s.now().UTC()
	if !request.ExpiresAt.IsZero() && !request.ExpiresAt.After(now) {
		return IssuedLink{}, invalidInput("expires_at must be in the future")
	}
	access := service.UserAccess(actor.ID, "share-management")
	var item model.Item
	var err error
	if request.TargetKind == TargetItem {
		if strings.TrimSpace(request.ItemID) == "" {
			return IssuedLink{}, invalidInput("item_id is required")
		}
		item, err = s.space.GetItem(ctx, access, request.ItemID)
		if err != nil {
			return IssuedLink{}, err
		}
		if request.FolderID != "" && request.FolderID != item.FolderID {
			return IssuedLink{}, ErrTargetMismatch
		}
		request.FolderID = item.FolderID
	} else if strings.TrimSpace(request.FolderID) == "" {
		return IssuedLink{}, invalidInput("folder_id is required")
	}
	folder, err := s.space.GetFolder(ctx, access, request.FolderID)
	if err != nil {
		return IssuedLink{}, err
	}
	if request.Publish != "" {
		if request.Publish != PublishICS && request.Publish != PublishFreeBusy {
			return IssuedLink{}, invalidInput("publish must be ics or freebusy")
		}
		if request.TargetKind != TargetFolder || request.Access != AccessRead || folder.Type != model.FolderTypeCalendar {
			return IssuedLink{}, invalidInput("only a calendar can be published, read-only")
		}
	}
	if err := s.requireAuthority(ctx, actor.ID, folder.ID, request.TargetKind, request.Access); err != nil {
		return IssuedLink{}, err
	}
	id, err := randomString(s.random, 16)
	if err != nil {
		return IssuedLink{}, fmt.Errorf("generate share ID: %w", err)
	}
	secret, err := randomBytes(s.random, 32)
	if err != nil {
		return IssuedLink{}, fmt.Errorf("generate share secret: %w", err)
	}
	targetName := folder.Path
	if request.TargetKind == TargetItem {
		targetName = item.Name
		if targetName == "" {
			targetName = firstNonEmpty(item.Headers["Subject"], item.Headers["FN"], item.ID)
		}
	}
	link := Link{ID: id, CreatedBy: actor.ID, TargetOwnerID: folder.UserID, TargetKind: request.TargetKind, FolderID: folder.ID, ItemID: item.ID, TargetName: targetName, FolderType: folder.Type, Access: request.Access, Publish: request.Publish, ExpiresAt: request.ExpiresAt.UTC(), MaxUses: request.MaxUses, CreatedAt: now, UpdatedAt: now}
	record := record{Link: link, SecretHash: secretHash(id, secret)}
	if err := s.ts.Put(ctx, model.NSShareLinks, id, record); err != nil {
		return IssuedLink{}, fmt.Errorf("persist share link: %w", err)
	}
	token := TokenVersion + "." + id + "." + base64.RawURLEncoding.EncodeToString(secret)
	s.audit.Log(actor.ID, "share.link.create", id, auditDetails(link))
	return IssuedLink{Link: link, Token: token}, nil
}

func (s *Service) List(ctx context.Context, actor model.PrincipalRef) ([]Link, error) {
	if actor.Kind != model.PrincipalUser || actor.ID == "" {
		return nil, service.ErrForbidden
	}
	records := make([]record, 0)
	err := s.ts.Store().Iterate(ctx, model.NSShareLinks, "", func(_ string, value []byte) (bool, error) {
		var record record
		if err := json.Unmarshal(value, &record); err != nil {
			return false, fmt.Errorf("decode share link: %w", err)
		}
		records = append(records, record)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	// Authorization may read the same backend. Evaluate it after iteration so
	// no backend's iterator lock or transaction is recursively entered.
	links := make([]Link, 0, len(records))
	for _, record := range records {
		allowed, err := s.canManage(ctx, actor.ID, record.Link)
		if err != nil {
			return nil, err
		}
		if allowed {
			links = append(links, record.Link)
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].CreatedAt.After(links[j].CreatedAt) })
	return links, nil
}

func (s *Service) Get(ctx context.Context, actor model.PrincipalRef, id string) (Link, error) {
	record, _, err := s.load(ctx, id)
	if err != nil {
		return Link{}, err
	}
	allowed, err := s.canManage(ctx, actor.ID, record.Link)
	if err != nil {
		return Link{}, err
	}
	if actor.Kind != model.PrincipalUser || !allowed {
		return Link{}, service.ErrForbidden
	}
	return record.Link, nil
}

func (s *Service) Revoke(ctx context.Context, actor model.PrincipalRef, id string) (Link, error) {
	if actor.Kind != model.PrincipalUser || actor.ID == "" {
		return Link{}, service.ErrForbidden
	}
	for attempt := 0; attempt < 32; attempt++ {
		record, raw, err := s.load(ctx, id)
		if err != nil {
			return Link{}, err
		}
		allowed, err := s.canManage(ctx, actor.ID, record.Link)
		if err != nil {
			return Link{}, err
		}
		if !allowed {
			return Link{}, service.ErrForbidden
		}
		if !record.RevokedAt.IsZero() {
			return record.Link, nil
		}
		now := s.now().UTC()
		record.RevokedAt, record.UpdatedAt = now, now
		updated, err := json.Marshal(record)
		if err != nil {
			return Link{}, err
		}
		if err := s.ts.Store().CompareAndSwap(ctx, model.NSShareLinks, id, raw, updated); errors.Is(err, store.ErrPreconditionFailed) {
			continue
		} else if err != nil {
			return Link{}, err
		}
		s.audit.Log(actor.ID, "share.link.revoke", id, auditDetails(record.Link))
		return record.Link, nil
	}
	return Link{}, store.ErrPreconditionFailed
}

func (s *Service) Open(ctx context.Context, token string, beforeUID uint32, limit int) (Resource, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxPageSize {
		return Resource{}, invalidInput("limit cannot exceed %d", MaxPageSize)
	}
	preview, err := s.inspect(ctx, token, AccessRead)
	if err != nil {
		return Resource{}, err
	}
	if preview.Publish != "" {
		return Resource{}, ErrUnavailable // published calendars serve only their feed
	}
	if _, err := s.space.GetFolder(ctx, s.publicAccess(preview.Link), preview.FolderID); err != nil {
		return Resource{}, unavailable(err)
	}
	if preview.TargetKind == TargetItem {
		if _, err := s.scopedItem(ctx, preview.Link, preview.ItemID); err != nil {
			return Resource{}, unavailable(err)
		}
	}
	record, err := s.claim(ctx, token, AccessRead, "open")
	if err != nil {
		return Resource{}, err
	}
	access := s.publicAccess(record.Link)
	folder, err := s.space.GetFolder(ctx, access, record.FolderID)
	if err != nil {
		return Resource{}, err
	}
	resource := Resource{TargetKind: record.TargetKind, TargetName: record.TargetName, FolderType: record.FolderType, Access: record.Access, ExpiresAt: record.ExpiresAt, Folder: publicFolder(folder), Remaining: record.RemainingUses()}
	if record.TargetKind == TargetItem {
		item, err := s.space.GetItem(ctx, access, record.ItemID)
		if err != nil || item.FolderID != record.FolderID {
			return Resource{}, unavailable(err)
		}
		projected := publicItem(item, true)
		resource.Item = &projected
		return resource, nil
	}
	if pager, ok := s.space.(service.FolderItemPager); ok {
		page, err := pager.ListItemPage(ctx, access, record.FolderID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: limit})
		if err != nil {
			return Resource{}, err
		}
		resource.Items = projectItems(page.Items, false)
		resource.Total, resource.NextBeforeUID = page.Total, page.NextBeforeUID
		return resource, nil
	}
	items, err := s.space.ListItems(ctx, access, record.FolderID, service.ItemQuery{Limit: limit, MetadataOnly: true})
	if err != nil {
		return Resource{}, err
	}
	resource.Items, resource.Total = projectItems(items, false), folder.ItemCount
	return resource, nil
}

// OpenCalendar claims one request of a published calendar link and returns
// the link with the owner-scoped access its feed is read with.
func (s *Service) OpenCalendar(ctx context.Context, token string) (Link, service.AccessContext, error) {
	preview, err := s.inspect(ctx, token, AccessRead)
	if err != nil {
		return Link{}, service.AccessContext{}, err
	}
	if preview.Publish == "" || preview.TargetKind != TargetFolder {
		return Link{}, service.AccessContext{}, ErrUnavailable
	}
	if _, err := s.space.GetFolder(ctx, s.publicAccess(preview.Link), preview.FolderID); err != nil {
		return Link{}, service.AccessContext{}, unavailable(err)
	}
	record, err := s.claim(ctx, token, AccessRead, "calendar.publish")
	if err != nil {
		return Link{}, service.AccessContext{}, err
	}
	return record.Link, s.publicAccess(record.Link), nil
}

func (s *Service) ReadItem(ctx context.Context, token, itemID string) (Item, error) {
	preview, err := s.inspect(ctx, token, AccessRead)
	if err != nil {
		return Item{}, err
	}
	if preview.Publish != "" {
		return Item{}, ErrUnavailable
	}
	if _, err := s.scopedItem(ctx, preview.Link, itemID); err != nil {
		return Item{}, err
	}
	record, err := s.claim(ctx, token, AccessRead, "item.read")
	if err != nil {
		return Item{}, err
	}
	item, err := s.scopedItem(ctx, record.Link, itemID)
	if err != nil {
		return Item{}, err
	}
	return publicItem(item, true), nil
}

func (s *Service) CreateItem(ctx context.Context, token string, input ItemInput) (Item, error) {
	preview, err := s.inspect(ctx, token, AccessWrite)
	if err != nil {
		return Item{}, err
	}
	if preview.TargetKind != TargetFolder {
		return Item{}, ErrTargetMismatch
	}
	if err := validateItemInput(input); err != nil {
		return Item{}, err
	}
	if _, err := s.space.GetFolder(ctx, s.publicAccess(preview.Link), preview.FolderID); err != nil {
		return Item{}, unavailable(err)
	}
	record, err := s.claim(ctx, token, AccessWrite, "item.create")
	if err != nil {
		return Item{}, err
	}
	item, err := s.space.CreateItem(ctx, s.publicAccess(record.Link), record.FolderID, service.ItemInput{Name: strings.TrimSpace(input.Name), Data: slices.Clone(input.Data), Headers: cloneHeaders(input.Headers)})
	if err != nil {
		return Item{}, err
	}
	return publicItem(item, true), nil
}

func (s *Service) UpdateItem(ctx context.Context, token, itemID string, input ItemInput) (Item, error) {
	preview, err := s.inspect(ctx, token, AccessWrite)
	if err != nil {
		return Item{}, err
	}
	if err := validateItemInput(input); err != nil {
		return Item{}, err
	}
	if _, err := s.scopedItem(ctx, preview.Link, itemID); err != nil {
		return Item{}, err
	}
	record, err := s.claim(ctx, token, AccessWrite, "item.update")
	if err != nil {
		return Item{}, err
	}
	if _, err := s.scopedItem(ctx, record.Link, itemID); err != nil {
		return Item{}, err
	}
	item, err := s.space.UpdateItem(ctx, s.publicAccess(record.Link), itemID, slices.Clone(input.Data), cloneHeaders(input.Headers))
	if err != nil {
		return Item{}, err
	}
	return publicItem(item, true), nil
}

func (s *Service) DeleteItem(ctx context.Context, token, itemID string) error {
	preview, err := s.inspect(ctx, token, AccessWrite)
	if err != nil {
		return err
	}
	if _, err := s.scopedItem(ctx, preview.Link, itemID); err != nil {
		return err
	}
	record, err := s.claim(ctx, token, AccessWrite, "item.delete")
	if err != nil {
		return err
	}
	if _, err := s.scopedItem(ctx, record.Link, itemID); err != nil {
		return err
	}
	return s.space.DeleteItem(ctx, s.publicAccess(record.Link), itemID)
}

func (s *Service) inspect(ctx context.Context, token string, required Access) (record, error) {
	id, secret, err := parseToken(token)
	if err != nil {
		return record{}, ErrUnavailable
	}
	record, _, err := s.load(ctx, id)
	if err != nil || subtle.ConstantTimeCompare(record.SecretHash, secretHash(id, secret)) != 1 || !record.Active(s.now().UTC()) {
		return record, ErrUnavailable
	}
	if required == AccessWrite && record.Access != AccessWrite {
		return record, ErrReadOnly
	}
	if err := s.requireAuthority(ctx, record.CreatedBy, record.FolderID, record.TargetKind, record.Access); err != nil {
		return record, ErrUnavailable
	}
	return record, nil
}

func (s *Service) scopedItem(ctx context.Context, link Link, itemID string) (model.Item, error) {
	if itemID == "" || (link.TargetKind == TargetItem && itemID != link.ItemID) {
		return model.Item{}, ErrTargetMismatch
	}
	item, err := s.space.GetItem(ctx, s.publicAccess(link), itemID)
	if err != nil {
		return model.Item{}, err
	}
	if item.FolderID != link.FolderID {
		return model.Item{}, ErrTargetMismatch
	}
	return item, nil
}

// publishedUseInterval is how often a published feed without a use limit
// records a use; fetches in between are served without a write.
const publishedUseInterval = time.Minute

func (s *Service) claim(ctx context.Context, token string, required Access, operation string) (record, error) {
	id, secret, err := parseToken(token)
	if err != nil {
		return record{}, ErrUnavailable
	}
	for attempt := 0; attempt < 32; attempt++ {
		record, raw, err := s.load(ctx, id)
		if err != nil || subtle.ConstantTimeCompare(record.SecretHash, secretHash(id, secret)) != 1 {
			return record, ErrUnavailable
		}
		now := s.now().UTC()
		if !record.Active(now) {
			return record, ErrUnavailable
		}
		if required == AccessWrite && record.Access != AccessWrite {
			return record, ErrReadOnly
		}
		if err := s.requireAuthority(ctx, record.CreatedBy, record.FolderID, record.TargetKind, record.Access); err != nil {
			return record, ErrUnavailable
		}
		if record.Publish != "" && record.MaxUses == 0 && now.Sub(record.LastUsedAt) < publishedUseInterval {
			// Feed readers poll published calendars; anyone holding the
			// URL could otherwise turn every fetch into a store write and
			// an audit entry.
			return record, nil
		}
		record.UseCount++
		record.LastUsedAt, record.UpdatedAt = now, now
		updated, err := json.Marshal(record)
		if err != nil {
			return record, err
		}
		if err := s.ts.Store().CompareAndSwap(ctx, model.NSShareLinks, id, raw, updated); errors.Is(err, store.ErrPreconditionFailed) {
			continue
		} else if err != nil {
			return record, err
		}
		s.audit.Log("capability:"+id, "share.link.use", id, map[string]string{"operation": operation, "target_kind": string(record.TargetKind), "folder_id": record.FolderID, "item_id": record.ItemID})
		return record, nil
	}
	return record{}, ErrUnavailable
}

func (s *Service) requireAuthority(ctx context.Context, actorID, folderID string, target TargetKind, access Access) error {
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}
	resource := model.ResourceRef{Kind: model.ResourceFolder, ID: folderID}
	actions := []authz.Action{authz.FolderSharesManage, authz.FolderItemsRead}
	if target == TargetFolder {
		actions = append(actions, authz.FolderItemsList)
	}
	if access == AccessWrite {
		actions = append(actions, authz.FolderItemsUpdate, authz.FolderItemsDelete)
		if target == TargetFolder {
			actions = append(actions, authz.FolderItemsCreate)
		}
	}
	for _, action := range actions {
		decision, err := s.authorizer.Check(ctx, authz.Request{Actor: actor, Subject: actor, Action: action, Resource: resource})
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return service.ErrForbidden
		}
	}
	return nil
}

func (s *Service) canManage(ctx context.Context, actorID string, link Link) (bool, error) {
	if actorID == "" {
		return false, nil
	}
	if actorID == link.CreatedBy || actorID == link.TargetOwnerID {
		return true, nil
	}
	decision, err := s.authorizer.Check(ctx, authz.Request{Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}, Action: authz.FolderSharesManage, Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: link.FolderID}})
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return decision.Allowed, err
}

func (s *Service) load(ctx context.Context, id string) (record, []byte, error) {
	if id == "" {
		return record{}, nil, store.ErrNotFound
	}
	raw, err := s.ts.Store().Get(ctx, model.NSShareLinks, id)
	if err != nil {
		return record{}, nil, err
	}
	var record record
	if err := json.Unmarshal(raw, &record); err != nil || record.ID != id || len(record.SecretHash) != sha256.Size {
		return record, nil, ErrUnavailable
	}
	return record, raw, nil
}

func (s *Service) publicAccess(link Link) service.AccessContext {
	return service.UserAccess(link.TargetOwnerID, "share:"+link.ID)
}

func parseToken(token string) (string, []byte, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] != TokenVersion || len(parts[1]) < 20 || len(parts[1]) > 32 {
		return "", nil, ErrUnavailable
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return "", nil, ErrUnavailable
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return "", nil, ErrUnavailable
	}
	return parts[1], secret, nil
}

func secretHash(id string, secret []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("veksel-share-v1\x00"))
	_, _ = hash.Write([]byte(id))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(secret)
	return hash.Sum(nil)
}

func randomString(random io.Reader, size int) (string, error) {
	value, err := randomBytes(random, size)
	return base64.RawURLEncoding.EncodeToString(value), err
}

func randomBytes(random io.Reader, size int) ([]byte, error) {
	value := make([]byte, size)
	_, err := io.ReadFull(random, value)
	return value, err
}

func validateItemInput(input ItemInput) error {
	if len(input.Data) > MaxItemBytes {
		return invalidInput("item data cannot exceed %d bytes", MaxItemBytes)
	}
	if len(strings.TrimSpace(input.Name)) > 255 {
		return invalidInput("item name cannot exceed 255 characters")
	}
	if len(input.Headers) > 100 {
		return invalidInput("item headers cannot exceed 100 fields")
	}
	for key, value := range input.Headers {
		if len(key) > 128 || len(value) > 8192 {
			return invalidInput("item header exceeds its size limit")
		}
	}
	return nil
}

func publicItem(item model.Item, includeData bool) Item {
	result := Item{ID: item.ID, Name: item.Name, Headers: cloneHeaders(item.Headers), Flags: slices.Clone(item.Flags), Size: item.Size, InternalDate: item.InternalDate}
	if includeData {
		result.Data = slices.Clone(item.Data)
	}
	return result
}

func projectItems(items []model.Item, includeData bool) []Item {
	result := make([]Item, 0, len(items))
	for _, item := range items {
		result = append(result, publicItem(item, includeData))
	}
	return result
}

func publicFolder(folder model.Folder) Folder {
	return Folder{Name: folder.Name, Path: folder.Path, Type: folder.Type, ItemCount: folder.ItemCount, LogicalBytes: folder.LogicalBytes}
}

func cloneHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	result := make(map[string]string, len(headers))
	for key, value := range headers {
		result[key] = value
	}
	return result
}

func auditDetails(link Link) map[string]string {
	return map[string]string{"target_kind": string(link.TargetKind), "folder_id": link.FolderID, "item_id": link.ItemID, "access": string(link.Access), "publish": string(link.Publish), "expires_at": link.ExpiresAt.Format(time.RFC3339), "max_uses": fmt.Sprint(link.MaxUses)}
}

func unavailable(err error) error {
	if err == nil {
		return ErrUnavailable
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func invalidInput(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, values...))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "item"
}
