// Package mcpserver exposes Veksel' authorized folder abstraction through the
// Model Context Protocol. It deliberately owns no storage access of its own.
package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/authz"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	mcpAuth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var logger = logpkg.For(logpkg.ModuleMCP)

const (
	ReadScope          = model.APIKeyScopeMCPRead
	WriteScope         = model.APIKeyScopeMCPWrite
	defaultPageSize    = 50
	maximumPageSize    = 200
	maximumInlineBytes = 1024 * 1024
)

// NewHandler creates a concurrent, authenticated remote MCP endpoint. The
// returned handler is safe to share between all configured HTTP listeners.
func NewHandler(apiKeys *model.APIKeyStore, users *model.UserStore, folders service.FolderSpace, search service.SearchReader, references *ReferenceService, auditLog AuditLogger) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "veksel", Version: "1"}, &mcp.ServerOptions{
		Instructions: "Read authorized Veksel mail, calendar, contact, file, and other typed folders. Credentials explicitly issued with mcp.write may also run the advertised item mutation tools; only do so when the user asks for the change. Prefer returned opaque references and veksel:// resource URIs over raw IDs. Use bounded pages, pass cursors unchanged, and follow next_uri metadata for large resources.",
		PageSize:     100,
	})
	h := &tools{folders: folders, search: search, references: references, audit: auditLog, mime: service.NewMIMEReader(folders)}
	mcp.AddTool(server, &mcp.Tool{Name: "veksel_list_folders", Description: "List folders visible to the authenticated user in their own or a delegated Veksel account."}, h.listFolders)
	mcp.AddTool(server, &mcp.Tool{Name: "veksel_list_items", Description: "List a bounded metadata page from an authorized Veksel folder. Bodies are not returned."}, h.listItems)
	mcp.AddTool(server, &mcp.Tool{Name: "veksel_get_item", Description: "Read one authorized item. Prefer item_ref; metadata includes a safe veksel:// resource URI. The compatibility inline projection is limited to 1 MiB."}, h.getItem)
	mcp.AddTool(server, &mcp.Tool{Name: "veksel_project_message", Description: "Project one authorized mail item into sanitized text/HTML and attachment metadata. Attachment bytes are available only through returned bounded veksel:// resources."}, h.projectMessage)
	mcp.AddTool(server, &mcp.Tool{Name: "veksel_search", Description: "Search authorized items across mail, calendar, contact, and file folders. Account search permission is separate from folder read permission."}, h.searchItems)
	registerMutationTools(server, h)
	server.AddResourceTemplate(&mcp.ResourceTemplate{
		Name: "veksel_item", Title: "Veksel item content",
		Description: "Authorized mail, calendar, contact, file, or other typed-folder item content. Follow next_uri metadata for bounded continuation chunks.",
		URITemplate: "veksel://item/{reference}{?offset}",
	}, h.readItemResource)
	server.AddResourceTemplate(&mcp.ResourceTemplate{
		Name: "veksel_attachment", Title: "Veksel message attachment",
		Description: "Authorized decoded MIME attachment content. Follow next_uri metadata for bounded continuation chunks.",
		URITemplate: "veksel://attachment/{reference}{?offset}",
	}, h.readAttachmentResource)

	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		SessionTimeout: 30 * time.Minute,
	})
	verifier := func(ctx context.Context, token string, _ *http.Request) (*mcpAuth.TokenInfo, error) {
		key, err := apiKeys.GetBySecret(ctx, token)
		if err != nil {
			logger.Error("verify bearer credential", "error", err)
			return nil, err
		}
		if key == nil {
			logger.Debug("reject unknown bearer credential")
			return nil, mcpAuth.ErrInvalidToken
		}
		user, err := users.Get(ctx, key.UserID)
		if err != nil || !user.Enabled {
			logger.Debug("reject bearer credential for unavailable account", "user", key.UserID)
			return nil, mcpAuth.ErrInvalidToken
		}
		// This assertion is intentionally short-lived. Named keys themselves are
		// revocable, and every HTTP request is verified again before it reaches
		// an existing MCP session.
		if err := apiKeys.UpdateLastUsed(ctx, key.ID); err != nil {
			logger.Warn("record credential use", "key", key.ID, "user", user.ID, "error", err)
		}
		return &mcpAuth.TokenInfo{UserID: user.ID, Scopes: slices.Clone(key.Scopes), Expiration: time.Now().Add(5 * time.Minute)}, nil
	}
	authenticated := mcpAuth.RequireBearerToken(verifier, &mcpAuth.RequireBearerTokenOptions{Scopes: []string{ReadScope}})(transport)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// MCP's optional standalone event stream is intentionally long-lived and
		// must not inherit the ordinary web listener's finite write deadline.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		authenticated.ServeHTTP(w, r)
	})
}

type tools struct {
	folders    service.FolderSpace
	search     service.SearchReader
	references *ReferenceService
	audit      AuditLogger
	mime       *service.MIMEReader
}

type accountInput struct {
	AccountID string `json:"account_id,omitempty" jsonschema:"Veksel account ID; omit for the authenticated user's own account"`
}

func sessionID(session *mcp.ServerSession) string {
	if session == nil {
		return ""
	}
	return session.ID()
}

func authenticatedActor(ctx context.Context) (string, error) {
	token := mcpAuth.TokenInfoFromContext(ctx)
	if token == nil || strings.TrimSpace(token.UserID) == "" {
		return "", errors.New("authenticated MCP principal is missing")
	}
	return strings.TrimSpace(token.UserID), nil
}

func accessFrom(ctx context.Context, accountID string) (service.AccessContext, error) {
	actorID, err := authenticatedActor(ctx)
	if err != nil {
		return service.AccessContext{}, err
	}
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: actorID}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		accountID = actor.ID
	}
	mode := authz.ActingNone
	if accountID != actor.ID {
		mode = authz.ActingDelegation
	}
	return service.AccessContext{
		Actor: actor, Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: accountID},
		Mode: mode, Protocol: "mcp", Correlation: "account:" + accountID,
	}, nil
}

func (h *tools) issueReference(session *mcp.ServerSession, kind string, access service.AccessContext, resourceID string) (string, error) {
	return h.references.Issue(kind, access.Actor.ID, access.Subject.ID, sessionID(session), resourceID)
}

func (h *tools) resolveReference(ctx context.Context, session *mcp.ServerSession, reference, kind, requestedAccount string) (service.AccessContext, string, error) {
	actorID, err := authenticatedActor(ctx)
	if err != nil {
		return service.AccessContext{}, "", err
	}
	claims, err := h.references.Resolve(reference, kind, actorID, sessionID(session))
	if err != nil {
		return service.AccessContext{}, "", err
	}
	if accountID := strings.TrimSpace(requestedAccount); accountID != "" && accountID != claims.AccountID {
		return service.AccessContext{}, "", ErrReferenceInvalid
	}
	access, err := accessFrom(ctx, claims.AccountID)
	if err != nil {
		return service.AccessContext{}, "", err
	}
	return access, claims.Resource, nil
}

type listFoldersInput struct {
	accountInput
	Type model.FolderType `json:"type,omitempty" jsonschema:"optional folder type such as mail, calendar, contact, or file"`
}

type folderView struct {
	ID           string           `json:"id"`
	Reference    string           `json:"reference"`
	Name         string           `json:"name"`
	Path         string           `json:"path"`
	ParentID     string           `json:"parent_id,omitempty"`
	ParentRef    string           `json:"parent_ref,omitempty"`
	Type         model.FolderType `json:"type"`
	SpecialUse   string           `json:"special_use,omitempty"`
	ItemCount    int64            `json:"item_count"`
	LogicalBytes int64            `json:"logical_bytes"`
	Trashed      bool             `json:"trashed,omitempty"`
}

type listFoldersOutput struct {
	AccountID string       `json:"account_id"`
	Folders   []folderView `json:"folders"`
}

func (h *tools) listFolders(ctx context.Context, request *mcp.CallToolRequest, input listFoldersInput) (*mcp.CallToolResult, listFoldersOutput, error) {
	access, err := accessFrom(ctx, input.AccountID)
	if err != nil {
		return nil, listFoldersOutput{}, err
	}
	folders, err := h.folders.ListFolders(ctx, access, service.FolderQuery{Type: input.Type})
	if err != nil {
		return nil, listFoldersOutput{}, err
	}
	out := listFoldersOutput{AccountID: access.Subject.ID, Folders: make([]folderView, 0, len(folders))}
	references := make(map[string]string, len(folders))
	for _, folder := range folders {
		reference, err := h.issueReference(request.Session, ReferenceFolder, access, folder.ID)
		if err != nil {
			return nil, listFoldersOutput{}, err
		}
		references[folder.ID] = reference
	}
	for _, folder := range folders {
		out.Folders = append(out.Folders, folderView{ID: folder.ID, Reference: references[folder.ID], Name: folder.Name, Path: folder.Path, ParentID: folder.ParentID, ParentRef: references[folder.ParentID], Type: folder.Type, SpecialUse: folder.SpecialUse, ItemCount: folder.ItemCount, LogicalBytes: folder.LogicalBytes})
	}
	return nil, out, nil
}

type listItemsInput struct {
	accountInput
	FolderRef string `json:"folder_ref,omitempty" jsonschema:"opaque folder reference returned by veksel_list_folders; preferred over folder_id"`
	FolderID  string `json:"folder_id,omitempty" jsonschema:"legacy raw folder ID returned by veksel_list_folders"`
	Cursor    string `json:"cursor,omitempty" jsonschema:"opaque cursor returned by a previous page"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size from 1 to 200; default 50"`
}

type itemMetadata struct {
	ID           string            `json:"id"`
	Reference    string            `json:"reference"`
	ResourceURI  string            `json:"resource_uri"`
	Name         string            `json:"name,omitempty"`
	FolderID     string            `json:"folder_id"`
	FolderRef    string            `json:"folder_ref"`
	Headers      map[string]string `json:"headers,omitempty"`
	Size         int64             `json:"size"`
	Flags        []string          `json:"flags,omitempty"`
	InternalDate time.Time         `json:"internal_date"`
	ModSeq       uint64            `json:"mod_seq"`
}

type listItemsOutput struct {
	Items      []itemMetadata `json:"items"`
	Total      int64          `json:"total"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

func boundedLimit(limit int) int {
	if limit <= 0 {
		return defaultPageSize
	}
	if limit > maximumPageSize {
		return maximumPageSize
	}
	return limit
}

func (h *tools) listItems(ctx context.Context, request *mcp.CallToolRequest, input listItemsInput) (*mcp.CallToolResult, listItemsOutput, error) {
	var access service.AccessContext
	folderID := strings.TrimSpace(input.FolderID)
	var err error
	if strings.TrimSpace(input.FolderRef) != "" {
		access, folderID, err = h.resolveReference(ctx, request.Session, input.FolderRef, ReferenceFolder, input.AccountID)
	} else {
		access, err = accessFrom(ctx, input.AccountID)
	}
	if err != nil {
		return nil, listItemsOutput{}, err
	}
	if folderID == "" {
		return nil, listItemsOutput{}, errors.New("folder_ref or folder_id is required")
	}
	pager, ok := h.folders.(service.FolderItemPager)
	if !ok {
		return nil, listItemsOutput{}, errors.New("bounded folder paging is unavailable")
	}
	page, err := pager.ListItemPage(ctx, access, folderID, service.ItemPageQuery{Cursor: input.Cursor, Order: service.ItemPageOrderInternalDateDescending, Limit: boundedLimit(input.Limit)})
	if err != nil {
		return nil, listItemsOutput{}, err
	}
	out := listItemsOutput{Items: make([]itemMetadata, 0, len(page.Items)), Total: page.Total, NextCursor: page.NextCursor}
	for _, item := range page.Items {
		view, err := h.metadata(request.Session, access, item)
		if err != nil {
			return nil, listItemsOutput{}, err
		}
		out.Items = append(out.Items, view)
	}
	return nil, out, nil
}

type getItemInput struct {
	accountInput
	ItemRef string `json:"item_ref,omitempty" jsonschema:"opaque item reference returned by a Veksel list or search tool; preferred over item_id"`
	ItemID  string `json:"item_id,omitempty" jsonschema:"legacy raw item ID returned by a Veksel list or search tool"`
}

type getItemOutput struct {
	Item      itemMetadata `json:"item"`
	MediaType string       `json:"media_type,omitempty"`
	Text      string       `json:"text,omitempty"`
	Base64    string       `json:"base64,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
}

func (h *tools) getItem(ctx context.Context, request *mcp.CallToolRequest, input getItemInput) (*mcp.CallToolResult, getItemOutput, error) {
	var access service.AccessContext
	itemID := strings.TrimSpace(input.ItemID)
	var err error
	if strings.TrimSpace(input.ItemRef) != "" {
		access, itemID, err = h.resolveReference(ctx, request.Session, input.ItemRef, ReferenceItem, input.AccountID)
	} else {
		access, err = accessFrom(ctx, input.AccountID)
	}
	if err != nil {
		return nil, getItemOutput{}, err
	}
	if itemID == "" {
		return nil, getItemOutput{}, errors.New("item_ref or item_id is required")
	}
	item, err := h.folders.GetItem(ctx, access, itemID)
	if err != nil {
		return nil, getItemOutput{}, err
	}
	mediaType := h.itemMediaType(ctx, access, item)
	data := item.Data
	view, err := h.metadata(request.Session, access, item)
	if err != nil {
		return nil, getItemOutput{}, err
	}
	out := getItemOutput{Item: view, MediaType: mediaType}
	if len(data) > maximumInlineBytes {
		data, out.Truncated = data[:maximumInlineBytes], true
	}
	if strings.HasPrefix(mediaType, "text/") || mediaType == "" || mediaType == "message/rfc822" || mediaType == "text/calendar" {
		out.Text = string(data)
	} else {
		out.Base64 = base64.StdEncoding.EncodeToString(data)
	}
	return nil, out, nil
}

func (h *tools) metadata(session *mcp.ServerSession, access service.AccessContext, item model.Item) (itemMetadata, error) {
	reference, err := h.issueReference(session, ReferenceItem, access, item.ID)
	if err != nil {
		return itemMetadata{}, err
	}
	folderReference, err := h.issueReference(session, ReferenceFolder, access, item.FolderID)
	if err != nil {
		return itemMetadata{}, err
	}
	headers := make(map[string]string, len(item.Headers))
	for key, value := range item.Headers {
		if !strings.EqualFold(key, service.CommandIDHeader()) {
			headers[key] = value
		}
	}
	return itemMetadata{ID: item.ID, Reference: reference, ResourceURI: itemResourceURI(reference, 0), Name: item.Name, FolderID: item.FolderID, FolderRef: folderReference, Headers: headers, Size: item.Size, Flags: slices.Clone(item.Flags), InternalDate: item.InternalDate, ModSeq: item.ModSeq}, nil
}

type attachmentTarget struct {
	ItemID string `json:"i"`
	PartID string `json:"p"`
}

type attachmentView struct {
	PartID      string `json:"part_id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Inline      bool   `json:"inline"`
	ContentID   string `json:"content_id,omitempty"`
	Reference   string `json:"reference"`
	ResourceURI string `json:"resource_uri"`
}

type projectMessageOutput struct {
	Item                 itemMetadata      `json:"item"`
	Headers              map[string]string `json:"headers"`
	Text                 string            `json:"text,omitempty"`
	HTML                 string            `json:"html,omitempty"`
	Attachments          []attachmentView  `json:"attachments"`
	BodyTruncated        bool              `json:"body_truncated"`
	UnsafeContentRemoved bool              `json:"unsafe_content_removed"`
	RemoteContentBlocked bool              `json:"remote_content_blocked"`
}

func (h *tools) projectMessage(ctx context.Context, request *mcp.CallToolRequest, input getItemInput) (*mcp.CallToolResult, projectMessageOutput, error) {
	var access service.AccessContext
	itemID := strings.TrimSpace(input.ItemID)
	var err error
	if strings.TrimSpace(input.ItemRef) != "" {
		access, itemID, err = h.resolveReference(ctx, request.Session, input.ItemRef, ReferenceItem, input.AccountID)
	} else {
		access, err = accessFrom(ctx, input.AccountID)
	}
	if err != nil {
		return nil, projectMessageOutput{}, err
	}
	if itemID == "" {
		return nil, projectMessageOutput{}, errors.New("item_ref or item_id is required")
	}
	projection, err := h.mime.Project(ctx, access, itemID)
	if err != nil {
		return nil, projectMessageOutput{}, err
	}
	item, err := h.folders.GetItem(ctx, access, itemID)
	if err != nil {
		return nil, projectMessageOutput{}, err
	}
	metadata, err := h.metadata(request.Session, access, item)
	if err != nil {
		return nil, projectMessageOutput{}, err
	}
	out := projectMessageOutput{Item: metadata, Headers: projection.Headers, Text: projection.Text, HTML: projection.HTML,
		Attachments: make([]attachmentView, 0, len(projection.Attachments)), BodyTruncated: projection.BodyTruncated,
		UnsafeContentRemoved: projection.UnsafeContentRemoved, RemoteContentBlocked: projection.RemoteContentBlocked}
	for _, attachment := range projection.Attachments {
		target, marshalErr := json.Marshal(attachmentTarget{ItemID: itemID, PartID: attachment.PartID})
		if marshalErr != nil {
			return nil, projectMessageOutput{}, marshalErr
		}
		reference, issueErr := h.issueReference(request.Session, ReferenceAttachment, access, string(target))
		if issueErr != nil {
			return nil, projectMessageOutput{}, issueErr
		}
		out.Attachments = append(out.Attachments, attachmentView{PartID: attachment.PartID, Name: attachment.Name,
			ContentType: attachment.ContentType, Size: attachment.Size, Inline: attachment.Inline, ContentID: attachment.ContentID,
			Reference: reference, ResourceURI: attachmentResourceURI(reference, 0)})
	}
	return nil, out, nil
}

type searchInput struct {
	accountInput
	Query        string             `json:"query" jsonschema:"end-user search expression"`
	FolderRefs   []string           `json:"folder_refs,omitempty" jsonschema:"optional opaque folder references to constrain the search; preferred over folder_ids"`
	FolderIDs    []string           `json:"folder_ids,omitempty" jsonschema:"optional folder IDs to constrain the search"`
	Types        []model.FolderType `json:"types,omitempty" jsonschema:"optional folder types to constrain the search"`
	IncludeTrash bool               `json:"include_trash,omitempty"`
	Sort         string             `json:"sort,omitempty" jsonschema:"supported search sort order"`
	Cursor       string             `json:"cursor,omitempty" jsonschema:"opaque cursor returned by a previous search page"`
	Limit        int                `json:"limit,omitempty" jsonschema:"page size from 1 to 200; default 50"`
}

type searchOutput struct {
	Hits       []searchHitView `json:"hits"`
	Total      uint64          `json:"total"`
	NextCursor string          `json:"next_cursor,omitempty"`
	IndexID    string          `json:"index_id"`
}

type searchHitView struct {
	service.SearchHit
	Reference   string `json:"reference"`
	ResourceURI string `json:"resource_uri"`
}

func (h *tools) searchItems(ctx context.Context, request *mcp.CallToolRequest, input searchInput) (*mcp.CallToolResult, searchOutput, error) {
	if h.search == nil {
		return nil, searchOutput{}, service.ErrSearchUnavailable
	}
	access, err := accessFrom(ctx, input.AccountID)
	if err != nil {
		return nil, searchOutput{}, err
	}
	folderIDs := slices.Clone(input.FolderIDs)
	for index, reference := range input.FolderRefs {
		resolvedAccess, folderID, resolveErr := h.resolveReference(ctx, request.Session, reference, ReferenceFolder, input.AccountID)
		if resolveErr != nil {
			return nil, searchOutput{}, resolveErr
		}
		if index == 0 && strings.TrimSpace(input.AccountID) == "" {
			access = resolvedAccess
		} else if resolvedAccess.Subject.ID != access.Subject.ID {
			return nil, searchOutput{}, ErrReferenceInvalid
		}
		folderIDs = append(folderIDs, folderID)
	}
	page, err := h.search.Search(ctx, access, service.SearchQuery{AccountID: access.Subject.ID, Expression: input.Query, FolderIDs: folderIDs, Types: input.Types, IncludeTrash: input.IncludeTrash, Sort: input.Sort, Cursor: input.Cursor, Limit: boundedLimit(input.Limit)})
	if err != nil {
		return nil, searchOutput{}, fmt.Errorf("search: %w", err)
	}
	hits := make([]searchHitView, 0, len(page.Hits))
	for _, hit := range page.Hits {
		reference, err := h.issueReference(request.Session, ReferenceItem, access, hit.ItemID)
		if err != nil {
			return nil, searchOutput{}, err
		}
		hits = append(hits, searchHitView{SearchHit: hit, Reference: reference, ResourceURI: itemResourceURI(reference, 0)})
	}
	return nil, searchOutput{Hits: hits, Total: page.Total, NextCursor: page.NextCursor, IndexID: page.IndexID}, nil
}

func itemResourceURI(reference string, offset int) string {
	uri := "veksel://item/" + reference
	if offset > 0 {
		uri += "?offset=" + strconv.Itoa(offset)
	}
	return uri
}

func attachmentResourceURI(reference string, offset int) string {
	uri := "veksel://attachment/" + reference
	if offset > 0 {
		uri += "?offset=" + strconv.Itoa(offset)
	}
	return uri
}

func detectedItemMediaType(item model.Item) string {
	value := strings.TrimSpace(item.Headers["Content-Type"])
	if value == "" {
		return http.DetectContentType(item.Data)
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil || mediaType == "" {
		return "application/octet-stream"
	}
	return strings.ToLower(mediaType)
}

func (h *tools) itemMediaType(ctx context.Context, access service.AccessContext, item model.Item) string {
	folder, err := h.folders.GetFolder(ctx, access, item.FolderID)
	if err == nil {
		switch folder.Type {
		case model.FolderTypeMail:
			return "message/rfc822"
		case model.FolderTypeCalendar, model.FolderTypeScheduleInbox, model.FolderTypeScheduleOutbox:
			return "text/calendar"
		case model.FolderTypeContacts:
			return "text/vcard"
		case model.FolderTypeNotes:
			return "text/plain"
		}
	}
	return detectedItemMediaType(item)
}

func textualMediaType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "text/") || strings.HasPrefix(mediaType, "message/") || mediaType == "application/json" || mediaType == "application/xml" || strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
}

func parseItemResourceURI(rawURI string) (string, int, error) {
	return parseResourceURI(rawURI, "item")
}

func parseAttachmentResourceURI(rawURI string) (string, int, error) {
	return parseResourceURI(rawURI, "attachment")
}

func parseResourceURI(rawURI, host string) (string, int, error) {
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme != "veksel" || parsed.Host != host || parsed.User != nil || parsed.Fragment != "" {
		return "", 0, ErrReferenceInvalid
	}
	reference := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if reference == "" || strings.Contains(reference, "/") {
		return "", 0, ErrReferenceInvalid
	}
	reference, err = url.PathUnescape(reference)
	if err != nil || strings.Contains(reference, "/") {
		return "", 0, ErrReferenceInvalid
	}
	query := parsed.Query()
	if len(query) > 1 {
		return "", 0, ErrReferenceInvalid
	}
	offset := 0
	if values, ok := query["offset"]; ok {
		if len(values) != 1 || values[0] == "" {
			return "", 0, ErrReferenceInvalid
		}
		offset, err = strconv.Atoi(values[0])
		if err != nil || offset < 0 {
			return "", 0, ErrReferenceInvalid
		}
	}
	if len(query) == 1 {
		if _, ok := query["offset"]; !ok {
			return "", 0, ErrReferenceInvalid
		}
	}
	if parsed.RawQuery != "" && len(query) == 0 {
		return "", 0, ErrReferenceInvalid
	}
	return reference, offset, nil
}

func (h *tools) readAttachmentResource(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	reference, offset, err := parseAttachmentResourceURI(request.Params.URI)
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	access, encoded, err := h.resolveReference(ctx, request.Session, reference, ReferenceAttachment, "")
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	var target attachmentTarget
	if json.Unmarshal([]byte(encoded), &target) != nil || target.ItemID == "" || target.PartID == "" {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	projection, err := h.mime.Project(ctx, access, target.ItemID)
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	partIndex := slices.IndexFunc(projection.Attachments, func(candidate service.MessageAttachment) bool { return candidate.PartID == target.PartID })
	if partIndex < 0 {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	attachment, err := h.mime.OpenAttachment(ctx, access, target.ItemID, target.PartID)
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	attachment.MessageAttachment = projection.Attachments[partIndex]
	defer attachment.Reader.Close()
	if offset < 0 || int64(offset) > attachment.Size {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	if offset > 0 {
		if _, err := io.CopyN(io.Discard, attachment.Reader, int64(offset)); err != nil {
			return nil, mcp.ResourceNotFoundError(request.Params.URI)
		}
	}
	data, err := io.ReadAll(io.LimitReader(attachment.Reader, maximumInlineBytes))
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	end := offset + len(data)
	contents := &mcp.ResourceContents{URI: request.Params.URI, MIMEType: attachment.ContentType,
		Meta: mcp.Meta{"offset": offset, "length": len(data), "total_size": attachment.Size, "complete": int64(end) == attachment.Size,
			"name": attachment.Name, "part_id": attachment.PartID, "inline": attachment.Inline}}
	if textualMediaType(attachment.ContentType) && utf8.Valid(data) {
		contents.Text = string(data)
	} else {
		contents.Blob = slices.Clone(data)
	}
	if int64(end) < attachment.Size {
		contents.Meta["next_uri"] = attachmentResourceURI(reference, end)
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{contents}}, nil
}

func (h *tools) readItemResource(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	reference, offset, err := parseItemResourceURI(request.Params.URI)
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	access, itemID, err := h.resolveReference(ctx, request.Session, reference, ReferenceItem, "")
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	item, err := h.folders.GetItem(ctx, access, itemID)
	if err != nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	if offset > len(item.Data) {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	end := min(offset+maximumInlineBytes, len(item.Data))
	mediaType := h.itemMediaType(ctx, access, item)
	data := item.Data[offset:end]
	contents := &mcp.ResourceContents{
		URI: request.Params.URI, MIMEType: mediaType,
		Meta: mcp.Meta{"offset": offset, "length": len(data), "total_size": len(item.Data), "complete": end == len(item.Data)},
	}
	if textualMediaType(mediaType) && utf8.Valid(data) {
		contents.Text = string(data)
	} else {
		contents.Blob = slices.Clone(data)
	}
	if end < len(item.Data) {
		contents.Meta["next_uri"] = itemResourceURI(reference, end)
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{contents}}, nil
}
