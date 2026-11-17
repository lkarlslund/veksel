package mcpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	mcpAuth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AuditLogger is the append-only security evidence boundary used by MCP
// mutations. The interface is intentionally owned here so the protocol layer
// does not depend on audit storage details.
type AuditLogger interface {
	Log(actor, action, target string, details map[string]string)
}

type itemMutationInput struct {
	accountInput
	ItemRef string `json:"item_ref,omitempty" jsonschema:"opaque item reference returned by a Veksel list or search tool; preferred over item_id"`
	ItemID  string `json:"item_id,omitempty" jsonschema:"legacy raw item ID returned by a Veksel list or search tool"`
}

type setItemFlagsInput struct {
	itemMutationInput
	Flags []string `json:"flags" jsonschema:"complete replacement flag set; at most 100 distinct values"`
}

type relocateItemInput struct {
	itemMutationInput
	DestinationFolderRef string `json:"destination_folder_ref,omitempty" jsonschema:"opaque destination folder reference; preferred over destination_folder_id"`
	DestinationFolderID  string `json:"destination_folder_id,omitempty" jsonschema:"legacy raw destination folder ID"`
	DestinationName      string `json:"destination_name,omitempty" jsonschema:"optional destination item name; maximum 255 bytes"`
}

type confirmedItemMutationInput struct {
	itemMutationInput
	Confirm bool `json:"confirm" jsonschema:"must be true to confirm moving this item to recoverable trash"`
}

type itemMutationOutput struct {
	Item itemMetadata `json:"item"`
}

type itemContentInput struct {
	Content  string            `json:"content" jsonschema:"UTF-8 content, or standard base64 when content_encoding is base64; maximum decoded size 8 MiB"`
	Encoding string            `json:"content_encoding,omitempty" jsonschema:"utf8 (default) or base64"`
	Headers  map[string]string `json:"headers,omitempty" jsonschema:"bounded protocol metadata; content and secrets must not be placed in headers"`
}

type createItemContentInput struct {
	accountInput
	FolderRef string `json:"folder_ref,omitempty" jsonschema:"opaque destination folder reference; preferred over folder_id"`
	FolderID  string `json:"folder_id,omitempty" jsonschema:"legacy raw destination folder ID"`
	Name      string `json:"name" jsonschema:"protocol-facing item name; required, maximum 255 bytes"`
	itemContentInput
}

type replaceItemContentInput struct {
	itemMutationInput
	itemContentInput
	ExpectedModSeq uint64 `json:"expected_mod_seq" jsonschema:"mod_seq returned by the latest Veksel item read"`
	Confirm        bool   `json:"confirm" jsonschema:"must be true because replacement discards the current content"`
}

type folderMutationInput struct {
	accountInput
	FolderRef string `json:"folder_ref,omitempty" jsonschema:"opaque folder reference; preferred over folder_id"`
	FolderID  string `json:"folder_id,omitempty" jsonschema:"legacy raw folder ID"`
}

type createFolderInput struct {
	accountInput
	Name      string           `json:"name" jsonschema:"folder display name; maximum 255 bytes"`
	Type      model.FolderType `json:"type" jsonschema:"folder item type"`
	ParentRef string           `json:"parent_ref,omitempty" jsonschema:"optional opaque parent folder reference"`
	ParentID  string           `json:"parent_id,omitempty" jsonschema:"legacy raw parent folder ID"`
}

type moveFolderInput struct {
	folderMutationInput
	Name      string `json:"name" jsonschema:"new folder display name; maximum 255 bytes"`
	ParentRef string `json:"parent_ref,omitempty" jsonschema:"optional opaque new parent reference; omit for root"`
	ParentID  string `json:"parent_id,omitempty" jsonschema:"legacy raw new parent folder ID"`
}

type confirmedFolderMutationInput struct {
	folderMutationInput
	Confirm bool `json:"confirm" jsonschema:"must be true to confirm moving this folder hierarchy to recoverable trash"`
}

type folderMutationOutput struct {
	Folder folderView `json:"folder"`
}

func registerMutationTools(server *mcp.Server, h *tools) {
	mcp.AddTool(server, mutationTool("veksel_create_item", "Create bounded content in an authorized calendar, contacts, files, or mail Drafts folder. Requires mcp.write and records content-free audit evidence.", false), h.createItemContent)
	mcp.AddTool(server, mutationTool("veksel_replace_item_content", "Atomically replace bounded content only at the supplied mod_seq. Requires mcp.write, confirm=true, and records content-free audit evidence.", true), h.replaceItemContent)
	mcp.AddTool(server, mutationTool("veksel_set_item_flags", "Replace an authorized item's complete flag set. Requires an explicitly issued mcp.write credential and records durable audit evidence.", true), h.setItemFlags)
	mcp.AddTool(server, mutationTool("veksel_copy_item", "Copy an authorized item to a same-type destination folder. Requires an explicitly issued mcp.write credential and records durable audit evidence.", false), h.copyItem)
	mcp.AddTool(server, mutationTool("veksel_move_item", "Move an authorized item to a same-type destination folder. Requires an explicitly issued mcp.write credential and records durable audit evidence.", true), h.moveItem)
	mcp.AddTool(server, mutationTool("veksel_trash_item", "Move an authorized item to recoverable trash. Requires mcp.write, confirm=true, and records durable audit evidence. This does not permanently expunge content.", true), h.trashItem)
	mcp.AddTool(server, mutationTool("veksel_restore_item", "Restore an authorized recoverably trashed item to its former folder. Requires an explicitly issued mcp.write credential and records durable audit evidence.", false), h.restoreItem)
	mcp.AddTool(server, mutationTool("veksel_create_folder", "Create an authorized typed folder at an account root or beneath a same-type parent. Requires an explicitly issued mcp.write credential and records durable audit evidence.", false), h.createFolder)
	mcp.AddTool(server, mutationTool("veksel_move_folder", "Rename or move an authorized folder while preserving its hierarchy. Requires an explicitly issued mcp.write credential and records durable audit evidence.", true), h.moveFolder)
	mcp.AddTool(server, mutationTool("veksel_trash_folder", "Move an authorized folder hierarchy to recoverable trash. Requires mcp.write, confirm=true, and records durable audit evidence. This does not permanently purge content.", true), h.trashFolder)
	mcp.AddTool(server, mutationTool("veksel_restore_folder", "Restore an authorized recoverably trashed folder hierarchy. Requires an explicitly issued mcp.write credential and records durable audit evidence.", false), h.restoreFolder)
}

const maximumMutationContentBytes = 8 << 20

func decodeMutationContent(input itemContentInput) ([]byte, map[string]string, error) {
	var data []byte
	var err error
	switch strings.ToLower(strings.TrimSpace(input.Encoding)) {
	case "", "utf8":
		if !utf8.ValidString(input.Content) {
			return nil, nil, errors.New("content is not valid UTF-8")
		}
		data = []byte(input.Content)
	case "base64":
		data, err = base64.StdEncoding.DecodeString(input.Content)
		if err != nil {
			return nil, nil, errors.New("content is not valid standard base64")
		}
	default:
		return nil, nil, errors.New("content_encoding must be utf8 or base64")
	}
	if len(data) > maximumMutationContentBytes {
		return nil, nil, errors.New("decoded content exceeds 8 MiB")
	}
	if len(input.Headers) > 100 {
		return nil, nil, errors.New("headers cannot contain more than 100 entries")
	}
	headers := make(map[string]string, len(input.Headers))
	total := 0
	for key, value := range input.Headers {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 128 || len(value) > 8192 || strings.ContainsAny(key, "\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
			return nil, nil, errors.New("header names or values exceed safe boundaries")
		}
		total += len(key) + len(value)
		if total > 64<<10 {
			return nil, nil, errors.New("headers exceed 64 KiB")
		}
		headers[key] = value
	}
	return data, headers, nil
}

func supportedMCPContentFolder(folder model.Folder) error {
	switch folder.Type {
	case model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeFiles:
		return nil
	case model.FolderTypeMail:
		if folder.SpecialUse == model.SpecialUseDrafts {
			return nil
		}
		return errors.New("MCP can create mail content only in the Drafts folder")
	default:
		return fmt.Errorf("MCP content mutation is unsupported for folder type %s", folder.Type)
	}
}

func (h *tools) createItemContent(ctx context.Context, request *mcp.CallToolRequest, input createItemContentInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	access, err := h.initialMutationAccess(ctx, input.AccountID, "create_content")
	if err != nil {
		return nil, itemMutationOutput{}, err
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 255 || strings.ContainsAny(input.Name, "\x00/\\") {
		err = errors.New("name must be non-empty, at most 255 bytes, and contain no path separators")
		h.auditMutation(access, "create_content", "unresolved", nil, err)
		return nil, itemMutationOutput{}, err
	}
	folderID, err := h.resolveMutationDestination(ctx, request, access, input.FolderRef, input.FolderID)
	if err != nil {
		h.auditMutation(access, "create_content", "unresolved", nil, err)
		return nil, itemMutationOutput{}, err
	}
	folder, err := h.folders.GetFolder(ctx, access, folderID)
	if err == nil {
		err = supportedMCPContentFolder(folder)
	}
	data, headers, contentErr := decodeMutationContent(input.itemContentInput)
	if err == nil {
		err = contentErr
	}
	if err != nil {
		h.auditMutation(access, "create_content", folderID, nil, err)
		return nil, itemMutationOutput{}, err
	}
	creator, ok := h.folders.(service.ExclusiveItemCreator)
	if !ok {
		err = errors.New("exclusive item creation is unavailable")
		h.auditMutation(access, "create_content", folderID, nil, err)
		return nil, itemMutationOutput{}, err
	}
	item, err := creator.CreateItemIfAbsent(ctx, access, folderID, service.ItemInput{Name: strings.TrimSpace(input.Name), Data: data, Headers: headers, InternalDate: time.Now().UTC()})
	if err != nil {
		h.auditMutation(access, "create_content", folderID, map[string]string{"type": string(folder.Type), "bytes": strconv.Itoa(len(data))}, err)
		return nil, itemMutationOutput{}, err
	}
	return h.mutationResult(request.Session, access, "create_content", item, map[string]string{"type": string(folder.Type), "bytes": strconv.Itoa(len(data))})
}

func (h *tools) replaceItemContent(ctx context.Context, request *mcp.CallToolRequest, input replaceItemContentInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	access, itemID, err := h.resolveMutationItem(ctx, request, input.itemMutationInput, "replace_content")
	if err != nil {
		return nil, itemMutationOutput{}, err
	}
	if !input.Confirm {
		err = errors.New("confirm must be true to replace current item content")
		h.auditMutation(access, "replace_content", itemID, map[string]string{"confirmed": "false"}, err)
		return nil, itemMutationOutput{}, err
	}
	current, err := h.folders.GetItem(ctx, access, itemID)
	if err == nil {
		var folder model.Folder
		folder, err = h.folders.GetFolder(ctx, access, current.FolderID)
		if err == nil {
			err = supportedMCPContentFolder(folder)
		}
	}
	data, headers, contentErr := decodeMutationContent(input.itemContentInput)
	if err == nil {
		err = contentErr
	}
	updater, ok := h.folders.(service.ConditionalItemUpdater)
	if err == nil && !ok {
		err = errors.New("conditional item update is unavailable")
	}
	if err != nil {
		h.auditMutation(access, "replace_content", itemID, map[string]string{"confirmed": "true"}, err)
		return nil, itemMutationOutput{}, err
	}
	item, err := updater.UpdateItemIfModSeq(ctx, access, itemID, input.ExpectedModSeq, data, headers)
	if err != nil {
		h.auditMutation(access, "replace_content", itemID, map[string]string{"confirmed": "true", "bytes": strconv.Itoa(len(data))}, err)
		return nil, itemMutationOutput{}, err
	}
	return h.mutationResult(request.Session, access, "replace_content", item, map[string]string{"confirmed": "true", "bytes": strconv.Itoa(len(data))})
}

func mutationTool(name, description string, destructive bool) *mcp.Tool {
	closedWorld := false
	return &mcp.Tool{
		Name: name, Description: description + " Only use this tool when the user explicitly requests the change.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, OpenWorldHint: &closedWorld},
	}
}

func requireWriteScope(ctx context.Context) error {
	token := mcpAuth.TokenInfoFromContext(ctx)
	if token == nil || !slices.Contains(token.Scopes, WriteScope) {
		return errors.New("mcp.write scope is required for this mutation")
	}
	return nil
}

func (h *tools) initialMutationAccess(ctx context.Context, accountID, action string) (service.AccessContext, error) {
	access, err := accessFrom(ctx, accountID)
	if err != nil {
		return service.AccessContext{}, err
	}
	if err := requireWriteScope(ctx); err != nil {
		h.auditMutation(access, action, "scope", nil, err)
		return service.AccessContext{}, err
	}
	return access, nil
}

func (h *tools) initialFolderMutationAccess(ctx context.Context, accountID, action string) (service.AccessContext, error) {
	access, err := accessFrom(ctx, accountID)
	if err != nil {
		return service.AccessContext{}, err
	}
	if err := requireWriteScope(ctx); err != nil {
		h.auditFolderMutation(access, action, "scope", nil, err)
		return service.AccessContext{}, err
	}
	return access, nil
}

func (h *tools) resolveMutationItem(ctx context.Context, request *mcp.CallToolRequest, input itemMutationInput, action string) (service.AccessContext, string, error) {
	access, err := h.initialMutationAccess(ctx, input.AccountID, action)
	if err != nil {
		return service.AccessContext{}, "", err
	}
	itemID := strings.TrimSpace(input.ItemID)
	if strings.TrimSpace(input.ItemRef) != "" {
		access, itemID, err = h.resolveReference(ctx, request.Session, input.ItemRef, ReferenceItem, input.AccountID)
	}
	if err == nil && itemID == "" {
		err = errors.New("item_ref or item_id is required")
	}
	if err != nil {
		h.auditMutation(access, action, "unresolved", nil, err)
		return service.AccessContext{}, "", err
	}
	return access, itemID, nil
}

func (h *tools) resolveMutationDestination(ctx context.Context, request *mcp.CallToolRequest, access service.AccessContext, reference, rawID string) (string, error) {
	destinationID := strings.TrimSpace(rawID)
	if strings.TrimSpace(reference) != "" {
		resolvedAccess, resolvedID, err := h.resolveReference(ctx, request.Session, reference, ReferenceFolder, access.Subject.ID)
		if err != nil {
			return "", err
		}
		if resolvedAccess.Subject.ID != access.Subject.ID {
			return "", ErrReferenceInvalid
		}
		destinationID = resolvedID
	}
	if destinationID == "" {
		return "", errors.New("destination_folder_ref or destination_folder_id is required")
	}
	return destinationID, nil
}

func (h *tools) resolveMutationFolder(ctx context.Context, request *mcp.CallToolRequest, input folderMutationInput, action string) (service.AccessContext, string, error) {
	access, err := h.initialFolderMutationAccess(ctx, input.AccountID, action)
	if err != nil {
		return service.AccessContext{}, "", err
	}
	folderID := strings.TrimSpace(input.FolderID)
	if strings.TrimSpace(input.FolderRef) != "" {
		access, folderID, err = h.resolveReference(ctx, request.Session, input.FolderRef, ReferenceFolder, input.AccountID)
	}
	if err == nil && folderID == "" {
		err = errors.New("folder_ref or folder_id is required")
	}
	if err != nil {
		h.auditFolderMutation(access, action, "unresolved", nil, err)
		return service.AccessContext{}, "", err
	}
	return access, folderID, nil
}

func (h *tools) optionalMutationParent(ctx context.Context, request *mcp.CallToolRequest, access service.AccessContext, reference, rawID string) (string, error) {
	parentID := strings.TrimSpace(rawID)
	if strings.TrimSpace(reference) == "" {
		return parentID, nil
	}
	resolvedAccess, resolvedID, err := h.resolveReference(ctx, request.Session, reference, ReferenceFolder, access.Subject.ID)
	if err != nil || resolvedAccess.Subject.ID != access.Subject.ID {
		if err == nil {
			err = ErrReferenceInvalid
		}
		return "", err
	}
	return resolvedID, nil
}

func normalizeMutationFlags(flags []string) ([]string, error) {
	if len(flags) > 100 {
		return nil, errors.New("flags cannot contain more than 100 values")
	}
	seen := make(map[string]struct{}, len(flags))
	normalized := make([]string, 0, len(flags))
	for _, flag := range flags {
		flag = strings.TrimSpace(flag)
		if flag == "" || len(flag) > 200 {
			return nil, errors.New("flags must be non-empty and at most 200 bytes")
		}
		if _, exists := seen[flag]; exists {
			continue
		}
		seen[flag] = struct{}{}
		normalized = append(normalized, flag)
	}
	return normalized, nil
}

func (h *tools) setItemFlags(ctx context.Context, request *mcp.CallToolRequest, input setItemFlagsInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	access, itemID, err := h.resolveMutationItem(ctx, request, input.itemMutationInput, "set_flags")
	if err != nil {
		return nil, itemMutationOutput{}, err
	}
	flags, err := normalizeMutationFlags(input.Flags)
	if err != nil {
		h.auditMutation(access, "set_flags", itemID, map[string]string{"flags": strconv.Itoa(len(input.Flags))}, err)
		return nil, itemMutationOutput{}, err
	}
	item, err := h.folders.SetFlags(ctx, access, itemID, flags)
	if err == nil {
		return h.mutationResult(request.Session, access, "set_flags", item, map[string]string{"flags": strconv.Itoa(len(flags))})
	}
	h.auditMutation(access, "set_flags", itemID, map[string]string{"flags": strconv.Itoa(len(input.Flags))}, err)
	return nil, itemMutationOutput{}, err
}

func (h *tools) copyItem(ctx context.Context, request *mcp.CallToolRequest, input relocateItemInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	return h.relocateItem(ctx, request, input, false)
}

func (h *tools) moveItem(ctx context.Context, request *mcp.CallToolRequest, input relocateItemInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	return h.relocateItem(ctx, request, input, true)
}

func (h *tools) relocateItem(ctx context.Context, request *mcp.CallToolRequest, input relocateItemInput, move bool) (*mcp.CallToolResult, itemMutationOutput, error) {
	action := "copy"
	if move {
		action = "move"
	}
	access, itemID, err := h.resolveMutationItem(ctx, request, input.itemMutationInput, action)
	if err != nil {
		return nil, itemMutationOutput{}, err
	}
	if len(input.DestinationName) > 255 {
		err = errors.New("destination_name cannot exceed 255 bytes")
		h.auditMutation(access, action, itemID, nil, err)
		return nil, itemMutationOutput{}, err
	}
	destinationID, err := h.resolveMutationDestination(ctx, request, access, input.DestinationFolderRef, input.DestinationFolderID)
	if err != nil {
		h.auditMutation(access, action, itemID, nil, err)
		return nil, itemMutationOutput{}, err
	}
	var item model.Item
	if move {
		item, err = h.folders.MoveItem(ctx, access, itemID, destinationID, input.DestinationName)
	} else {
		item, err = h.folders.CopyItem(ctx, access, itemID, destinationID, input.DestinationName)
	}
	if err != nil {
		h.auditMutation(access, action, itemID, map[string]string{"destination_folder": destinationID}, err)
		return nil, itemMutationOutput{}, err
	}
	return h.mutationResult(request.Session, access, action, item, map[string]string{"destination_folder": destinationID})
}

func (h *tools) trashItem(ctx context.Context, request *mcp.CallToolRequest, input confirmedItemMutationInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	access, itemID, err := h.resolveMutationItem(ctx, request, input.itemMutationInput, "trash")
	if err != nil {
		return nil, itemMutationOutput{}, err
	}
	if !input.Confirm {
		err = errors.New("confirm must be true to move an item to recoverable trash")
		h.auditMutation(access, "trash", itemID, map[string]string{"confirmed": "false"}, err)
		return nil, itemMutationOutput{}, err
	}
	recovery, ok := h.folders.(service.RecoverableFolderSpace)
	if !ok {
		err = errors.New("recoverable item trash is unavailable")
		h.auditMutation(access, "trash", itemID, map[string]string{"confirmed": "true"}, err)
		return nil, itemMutationOutput{}, err
	}
	item, err := recovery.TrashItem(ctx, access, itemID)
	if err != nil {
		h.auditMutation(access, "trash", itemID, map[string]string{"confirmed": "true"}, err)
		return nil, itemMutationOutput{}, err
	}
	return h.mutationResult(request.Session, access, "trash", item, map[string]string{"confirmed": "true"})
}

func (h *tools) restoreItem(ctx context.Context, request *mcp.CallToolRequest, input itemMutationInput) (*mcp.CallToolResult, itemMutationOutput, error) {
	access, itemID, err := h.resolveMutationItem(ctx, request, input, "restore")
	if err != nil {
		return nil, itemMutationOutput{}, err
	}
	recovery, ok := h.folders.(service.RecoverableFolderSpace)
	if !ok {
		err = errors.New("recoverable item restore is unavailable")
		h.auditMutation(access, "restore", itemID, nil, err)
		return nil, itemMutationOutput{}, err
	}
	item, err := recovery.RestoreItem(ctx, access, itemID)
	if err != nil {
		h.auditMutation(access, "restore", itemID, nil, err)
		return nil, itemMutationOutput{}, err
	}
	return h.mutationResult(request.Session, access, "restore", item, nil)
}

func (h *tools) mutationResult(session *mcp.ServerSession, access service.AccessContext, action string, item model.Item, details map[string]string) (*mcp.CallToolResult, itemMutationOutput, error) {
	view, err := h.metadata(session, access, item)
	if err != nil {
		if details == nil {
			details = make(map[string]string)
		}
		details["response_error"] = err.Error()
		// FolderSpace already committed the change. Keep the durable mutation
		// evidence truthful even if issuing the response reference fails.
		h.auditMutation(access, action, item.ID, details, nil)
		return nil, itemMutationOutput{}, fmt.Errorf("issue mutation result reference: %w", err)
	}
	h.auditMutation(access, action, item.ID, details, nil)
	return nil, itemMutationOutput{Item: view}, nil
}

func validateFolderMutationName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 255 || strings.ContainsAny(name, "\x00/\\") {
		return errors.New("folder name must be non-empty, at most 255 bytes, and contain no path separators")
	}
	return nil
}

func (h *tools) createFolder(ctx context.Context, request *mcp.CallToolRequest, input createFolderInput) (*mcp.CallToolResult, folderMutationOutput, error) {
	access, err := h.initialFolderMutationAccess(ctx, input.AccountID, "create")
	if err != nil {
		return nil, folderMutationOutput{}, err
	}
	if err = validateFolderMutationName(input.Name); err != nil {
		h.auditFolderMutation(access, "create", "unresolved", nil, err)
		return nil, folderMutationOutput{}, err
	}
	parentID, err := h.optionalMutationParent(ctx, request, access, input.ParentRef, input.ParentID)
	if err != nil {
		h.auditFolderMutation(access, "create", "unresolved", nil, err)
		return nil, folderMutationOutput{}, err
	}
	folder, err := h.folders.CreateFolder(ctx, access, strings.TrimSpace(input.Name), input.Type, parentID)
	if err != nil {
		h.auditFolderMutation(access, "create", parentID, map[string]string{"type": string(input.Type)}, err)
		return nil, folderMutationOutput{}, err
	}
	return h.folderMutationResult(request.Session, access, "create", folder, map[string]string{"type": string(input.Type), "parent_folder": parentID})
}

func (h *tools) moveFolder(ctx context.Context, request *mcp.CallToolRequest, input moveFolderInput) (*mcp.CallToolResult, folderMutationOutput, error) {
	access, folderID, err := h.resolveMutationFolder(ctx, request, input.folderMutationInput, "move")
	if err != nil {
		return nil, folderMutationOutput{}, err
	}
	if err = validateFolderMutationName(input.Name); err != nil {
		h.auditFolderMutation(access, "move", folderID, nil, err)
		return nil, folderMutationOutput{}, err
	}
	parentID, err := h.optionalMutationParent(ctx, request, access, input.ParentRef, input.ParentID)
	if err != nil {
		h.auditFolderMutation(access, "move", folderID, nil, err)
		return nil, folderMutationOutput{}, err
	}
	folder, err := h.folders.MoveFolder(ctx, access, folderID, parentID, strings.TrimSpace(input.Name))
	if err != nil {
		h.auditFolderMutation(access, "move", folderID, map[string]string{"parent_folder": parentID}, err)
		return nil, folderMutationOutput{}, err
	}
	return h.folderMutationResult(request.Session, access, "move", folder, map[string]string{"parent_folder": parentID})
}

func (h *tools) trashFolder(ctx context.Context, request *mcp.CallToolRequest, input confirmedFolderMutationInput) (*mcp.CallToolResult, folderMutationOutput, error) {
	access, folderID, err := h.resolveMutationFolder(ctx, request, input.folderMutationInput, "trash")
	if err != nil {
		return nil, folderMutationOutput{}, err
	}
	if !input.Confirm {
		err = errors.New("confirm must be true to move a folder hierarchy to recoverable trash")
		h.auditFolderMutation(access, "trash", folderID, map[string]string{"confirmed": "false"}, err)
		return nil, folderMutationOutput{}, err
	}
	folder, err := h.folders.GetFolder(ctx, access, folderID)
	if err == nil {
		err = h.folders.DeleteFolder(ctx, access, folderID)
	}
	if err != nil {
		h.auditFolderMutation(access, "trash", folderID, map[string]string{"confirmed": "true"}, err)
		return nil, folderMutationOutput{}, err
	}
	folder.TrashedAt = time.Now().UTC()
	return h.folderMutationResult(request.Session, access, "trash", folder, map[string]string{"confirmed": "true"})
}

func (h *tools) restoreFolder(ctx context.Context, request *mcp.CallToolRequest, input folderMutationInput) (*mcp.CallToolResult, folderMutationOutput, error) {
	access, folderID, err := h.resolveMutationFolder(ctx, request, input, "restore")
	if err != nil {
		return nil, folderMutationOutput{}, err
	}
	recovery, ok := h.folders.(service.RecoverableFolderSpace)
	if !ok {
		err = errors.New("recoverable folder restore is unavailable")
		h.auditFolderMutation(access, "restore", folderID, nil, err)
		return nil, folderMutationOutput{}, err
	}
	folder, err := recovery.RestoreFolder(ctx, access, folderID)
	if err != nil {
		h.auditFolderMutation(access, "restore", folderID, nil, err)
		return nil, folderMutationOutput{}, err
	}
	return h.folderMutationResult(request.Session, access, "restore", folder, nil)
}

func (h *tools) folderMutationResult(session *mcp.ServerSession, access service.AccessContext, action string, folder model.Folder, details map[string]string) (*mcp.CallToolResult, folderMutationOutput, error) {
	reference, err := h.issueReference(session, ReferenceFolder, access, folder.ID)
	if err != nil {
		h.auditFolderMutation(access, action, folder.ID, details, nil)
		return nil, folderMutationOutput{}, fmt.Errorf("issue folder mutation result reference: %w", err)
	}
	parentRef := ""
	if folder.ParentID != "" {
		parentRef, err = h.issueReference(session, ReferenceFolder, access, folder.ParentID)
		if err != nil {
			h.auditFolderMutation(access, action, folder.ID, details, nil)
			return nil, folderMutationOutput{}, fmt.Errorf("issue parent mutation result reference: %w", err)
		}
	}
	view := folderView{ID: folder.ID, Reference: reference, Name: folder.Name, Path: folder.Path, ParentID: folder.ParentID,
		ParentRef: parentRef, Type: folder.Type, SpecialUse: folder.SpecialUse, ItemCount: folder.ItemCount,
		LogicalBytes: folder.LogicalBytes, Trashed: !folder.TrashedAt.IsZero()}
	h.auditFolderMutation(access, action, folder.ID, details, nil)
	return nil, folderMutationOutput{Folder: view}, nil
}

func (h *tools) auditMutation(access service.AccessContext, action, target string, details map[string]string, mutationErr error) {
	if h.audit == nil {
		return
	}
	evidence := make(map[string]string, len(details)+4)
	for key, value := range details {
		evidence[key] = value
	}
	evidence["subject"] = access.Subject.ID
	evidence["protocol"] = "mcp"
	if mutationErr == nil {
		evidence["result"] = "succeeded"
	} else {
		evidence["result"] = "failed"
		evidence["error"] = mutationErr.Error()
	}
	h.audit.Log(access.Actor.ID, "mcp.item."+action, target, evidence)
}

func (h *tools) auditFolderMutation(access service.AccessContext, action, target string, details map[string]string, mutationErr error) {
	if h.audit == nil {
		return
	}
	evidence := make(map[string]string, len(details)+4)
	for key, value := range details {
		evidence[key] = value
	}
	evidence["subject"] = access.Subject.ID
	evidence["protocol"] = "mcp"
	if mutationErr == nil {
		evidence["result"] = "succeeded"
	} else {
		evidence["result"] = "failed"
		evidence["error"] = mutationErr.Error()
	}
	h.audit.Log(access.Actor.ID, "mcp.folder."+action, target, evidence)
}
