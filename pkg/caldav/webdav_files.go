package caldav

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- WebDAV File Storage Handlers ---
//
// These handlers implement WebDAV (RFC 4918) operations for folders of type
// FolderTypeFiles.  They reuse the existing CalDAV handler infrastructure
// (PROPFIND, PUT, GET, DELETE, MKCOL, MOVE) but treat items as arbitrary
// binary files rather than calendar or contact data.

// handleFilesPropfind handles PROPFIND for file folders.
// Lists items as WebDAV files with getcontenttype, getcontentlength, getlastmodified.
func (h *Handler) handleFilesPropfind(ctx context.Context, username, collectionPath string, pf *propfind, depth string) ([]response, error) {
	folder, err := h.store.FolderStore().GetByPath(ctx, username, collectionPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errResourceNotFound, err)
	}

	href := buildHref(username, folder.Path) + "/"
	responses := []response{folderToFileResp(folder, href)}

	if depth == "0" {
		return responses, nil
	}

	// List items in the file folder
	items, err := h.store.ItemStore().List(ctx, folder.ID)
	if err != nil {
		return nil, err
	}

	for _, itemKey := range items {
		item, err := h.store.ItemStore().Get(ctx, itemKey)
		if err != nil {
			continue
		}

		// Extract the item ID from the key
		itemID := item.Name
		if itemID == "" {
			itemID = item.ID
		}
		itemHref := buildHref(username, folder.Path, itemID)

		responses = append(responses, fileItemToPropResp(item, itemHref))
	}

	return responses, nil
}

// handleFilesGet handles GET requests for file items.
// Returns raw data with correct Content-Type and ETag headers.
func (h *Handler) handleFilesGet(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		// GET on a file collection — return a directory listing via PROPFIND
		if len(parts) == 1 && parts[0] != "" {
			h.handlePropfind(w, r, username, parts)
			return
		}
		h.respondError(w, r, http.StatusNotFound, "not-found", "resource not found")
		return
	}

	collectionPath := parts[0]
	itemID := parts[1]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "folder not found")
		return
	}

	itemKey := model.ItemKey(folder.ID, itemID)
	item, err := h.store.ItemStore().Get(r.Context(), itemKey)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "file not found")
		return
	}

	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))

	// Determine content type from stored headers or detect from data
	contentType := "application/octet-stream"
	if item.Headers != nil {
		if ct, ok := item.Headers["Content-Type"]; ok && ct != "" {
			contentType = ct
		}
	}
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = http.DetectContentType(item.Data)
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", item.Size))
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", formatHTTPTime(item.UpdatedAt))
	w.Header().Set("Cache-Control", "must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write(item.Data)
}

// handleFilesPut handles PUT requests for creating/updating files in a files folder.
// Stores raw binary data as Item with proper content-type header.
func (h *Handler) handleFilesPut(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "PUT requires a target file path")
		return
	}

	collectionPath := parts[0]
	itemID := parts[1]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "folder not found")
		return
	}

	// Check file size limit
	maxSize := h.maxFileSize.Load()
	if maxSize > 0 && r.ContentLength > maxSize {
		h.respondError(w, r, http.StatusRequestEntityTooLarge, "entity-too-large",
			fmt.Sprintf("file size %d exceeds maximum allowed %d bytes", r.ContentLength, maxSize))
		return
	}

	// Read the file data with size limit enforcement
	var data []byte
	if maxSize > 0 {
		lr := &io.LimitedReader{R: r.Body, N: maxSize + 1}
		data, err = io.ReadAll(lr)
		if err != nil {
			h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
			return
		}
		if int64(len(data)) > maxSize {
			h.respondError(w, r, http.StatusRequestEntityTooLarge, "entity-too-large",
				fmt.Sprintf("file size %d exceeds maximum allowed %d bytes", len(data), maxSize))
			return
		}
	} else {
		data, err = io.ReadAll(r.Body)
		if err != nil {
			h.respondError(w, r, http.StatusBadRequest, "bad-request", "cannot read body")
			return
		}
	}

	// Determine content type
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}

	h.putObject(w, r, username, folder, itemID, data, map[string]string{"Content-Type": contentType})
}

// handleFilesDelete handles DELETE requests for file items.
func (h *Handler) handleFilesDelete(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	if len(parts) < 2 {
		// DELETE on a file collection
		if len(parts) == 1 && parts[0] != "" {
			folder, err := h.store.FolderStore().GetByPath(r.Context(), username, parts[0])
			if err != nil {
				h.respondError(w, r, http.StatusNotFound, "no-folder", "folder not found")
				return
			}
			if folder.Type != model.FolderTypeFiles {
				h.respondError(w, r, http.StatusNotFound, "no-folder", "not a files folder")
				return
			}
			if err := h.store.FolderStore().Delete(r.Context(), folder.ID); err != nil {
				h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.respondError(w, r, http.StatusNotFound, "not-found", "resource not found")
		return
	}

	collectionPath := parts[0]

	folder, err := h.store.FolderStore().GetByPath(r.Context(), username, collectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "folder not found")
		return
	}

	itemID := parts[1]

	h.deleteObject(w, r, folder, itemID, "file not found")
}

// handleFilesMove handles MOVE requests for file items.
// Supports rename within folder or move between folders.
func (h *Handler) handleFilesMove(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	destHeader := r.Header.Get("Destination")
	if destHeader == "" {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "Destination header required for MOVE")
		return
	}

	if len(parts) < 2 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "MOVE requires a source file path")
		return
	}

	// Parse source
	srcCollectionPath := parts[0]
	srcItemID := parts[1]

	srcFolder, err := h.store.FolderStore().GetByPath(r.Context(), username, srcCollectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "source folder not found")
		return
	}

	srcItemKey := model.ItemKey(srcFolder.ID, srcItemID)
	item, err := h.store.ItemStore().Get(r.Context(), srcItemKey)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "source file not found")
		return
	}

	// Parse destination
	destPath := parseDestination(destHeader)
	destParts := parseDestinationParts(destPath)
	if len(destParts) < 3 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "invalid destination path")
		return
	}

	// destParts = [username, collectionPath, itemID]
	if destParts[0] != username {
		h.respondError(w, r, http.StatusForbidden, "forbidden", "cannot move files between users")
		return
	}

	destCollectionPath := destParts[1]
	destItemID := destParts[2]

	// Get destination folder
	destFolder, err := h.store.FolderStore().GetByPath(r.Context(), username, destCollectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "destination folder not found")
		return
	}

	// Check if destination already exists
	destItemKey := model.ItemKey(destFolder.ID, destItemID)
	if _, err := h.store.ItemStore().Get(r.Context(), destItemKey); err == nil {
		if r.Header.Get("Overwrite") != "T" {
			h.respondError(w, r, http.StatusPreconditionFailed, "precondition-failed", "destination exists and Overwrite is not T")
			return
		}
		h.store.ItemStore().Delete(r.Context(), destItemKey)
	}

	if _, err := h.store.ItemStore().Move(r.Context(), item.ID, destFolder.ID, destItemID); err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleFilesCopy handles COPY requests for file items.
func (h *Handler) handleFilesCopy(w http.ResponseWriter, r *http.Request, username string, parts []string) {
	destHeader := r.Header.Get("Destination")
	if destHeader == "" {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "Destination header required for COPY")
		return
	}

	if len(parts) < 2 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "COPY requires a source file path")
		return
	}

	// Parse source
	srcCollectionPath := parts[0]
	srcItemID := parts[1]

	srcFolder, err := h.store.FolderStore().GetByPath(r.Context(), username, srcCollectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "source folder not found")
		return
	}

	srcItemKey := model.ItemKey(srcFolder.ID, srcItemID)
	item, err := h.store.ItemStore().Get(r.Context(), srcItemKey)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "not-found", "source file not found")
		return
	}

	// Parse destination
	destPath := parseDestination(destHeader)
	destParts := parseDestinationParts(destPath)
	if len(destParts) < 3 {
		h.respondError(w, r, http.StatusBadRequest, "bad-request", "invalid destination path")
		return
	}

	// destParts = [username, collectionPath, itemID]
	if destParts[0] != username {
		h.respondError(w, r, http.StatusForbidden, "forbidden", "cannot copy files between users")
		return
	}

	destCollectionPath := destParts[1]
	destItemID := destParts[2]

	destFolder, err := h.store.FolderStore().GetByPath(r.Context(), username, destCollectionPath)
	if err != nil {
		h.respondError(w, r, http.StatusNotFound, "no-folder", "destination folder not found")
		return
	}

	// Check if destination already exists
	destItemKey := model.ItemKey(destFolder.ID, destItemID)
	if _, err := h.store.ItemStore().Get(r.Context(), destItemKey); err == nil {
		if r.Header.Get("Overwrite") != "T" {
			h.respondError(w, r, http.StatusPreconditionFailed, "precondition-failed", "destination exists and Overwrite is not T")
			return
		}
	}

	// Create a copy
	now := time.Now().UTC()
	newItem := model.Item{
		ID:           destItemKey,
		FolderID:     destFolder.ID,
		Data:         bytes.Clone(item.Data),
		Headers:      cloneHeaders(item.Headers),
		Size:         item.Size,
		UID:          0,
		Flags:        nil,
		InternalDate: now,
		ModSeq:       1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.store.ItemStore().SetItem(r.Context(), newItem); err != nil {
		h.respondError(w, r, http.StatusInternalServerError, "server-error", err.Error())
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// --- Helper functions for file responses ---

// fileItemToPropResp builds a propResp for a file Item.
func fileItemToPropResp(item model.Item, href string) response {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", item.ModSeq))
	created := formatXMLTime(item.CreatedAt)
	lastMod := formatHTTPTime(item.UpdatedAt)
	size := fmt.Sprintf("%d", item.Size)

	// Determine content type from stored headers
	contentType := "application/octet-stream"
	if item.Headers != nil {
		if ct, ok := item.Headers["Content-Type"]; ok && ct != "" {
			contentType = ct
		}
	}

	return response{
		Href:   href,
		Status: "HTTP/1.1 200 OK",
		Prop: &propResp{
			ResourceType:     &resourceType{},
			Getcontentlength: &size,
			Getcontenttype:   &contentType,
			Getetag:          &etag,
			Getlastmodified:  &lastMod,
			Creationdate:     &created,
		},
	}
}

// folderToFileResp builds a propResp for a files folder (collection).
func folderToFileResp(folder model.Folder, href string) response {
	etag := fmt.Sprintf("%q", fmt.Sprintf("%016x", 0))
	lastMod := formatHTTPTime(folder.UpdatedAt)
	created := formatXMLTime(folder.CreatedAt)
	displayName := folder.Name

	return response{
		Href:   href,
		Status: "HTTP/1.1 200 OK",
		Prop: &propResp{
			Displayname:     &displayName,
			ResourceType:    &resourceType{Collection: &empty{}},
			Getetag:         &etag,
			Getlastmodified: &lastMod,
			Creationdate:    &created,
		},
	}
}

// parseDestination extracts the decoded path from a Destination header,
// which is an absolute URL ("http://host/dav/user/folder/file.txt") or an
// absolute path ("/dav/user/folder/file.txt", RFC 4918 §10.3).
func parseDestination(destHeader string) string {
	parsed, err := url.Parse(strings.TrimSpace(destHeader))
	if err != nil {
		return ""
	}
	return parsed.Path
}

// parseDestinationParts splits a destination path into parts, skipping the /dav/ prefix.
func parseDestinationParts(path string) []string {
	path = strings.TrimPrefix(path, "/dav")
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	raw := strings.Split(path, "/")
	var parts []string
	for _, p := range raw {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// getParentPath returns the parent path of a collection path.
// e.g. "parent/child" -> "parent", "root" -> ""
func getParentPath(collectionPath string) string {
	idx := strings.LastIndex(collectionPath, "/")
	if idx < 0 {
		return ""
	}
	return collectionPath[:idx]
}

// cloneHeaders returns a copy of the headers map.
func cloneHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	c := make(map[string]string, len(headers))
	for k, v := range headers {
		c[k] = v
	}
	return c
}
