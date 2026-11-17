package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/category"
	"github.com/lkarlslund/veksel/pkg/mailindex"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// apiWorkspaceMailList serves one filtered, sorted page of a mail folder from
// its durable list projection, so rows carry previews and triage marks
// without parsing message bodies per request.
func (h *Handler) apiWorkspaceMailList(w http.ResponseWriter, r *http.Request) {
	parameters := r.URL.Query()
	query := mailindex.Query{Limit: 100, Cursor: strings.TrimSpace(parameters.Get("cursor")), AroundItemID: strings.TrimSpace(parameters.Get("around_item_id"))}
	var err error
	if query.Filter, err = mailindex.ParseFilter(parameters.Get("filter")); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if query.Sort, err = mailindex.ParseSort(parameters.Get("sort")); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch parameters.Get("dir") {
	case "", "desc":
	case "asc":
		query.Ascending = true
	default:
		jsonError(w, http.StatusBadRequest, "dir must be asc or desc")
		return
	}
	if raw := strings.TrimSpace(parameters.Get("limit")); raw != "" {
		if query.Limit, err = strconv.Atoi(raw); err != nil || query.Limit < 1 || query.Limit > service.MaxItemPageLimit {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("limit must be between 1 and %d", service.MaxItemPageLimit))
			return
		}
	}
	switch parameters.Get("view") {
	case "", "messages":
	case "conversations":
		query.Conversations = true
	default:
		jsonError(w, http.StatusBadRequest, "view must be messages or conversations")
		return
	}
	if query.Cursor != "" && query.AroundItemID != "" {
		jsonError(w, http.StatusBadRequest, "cursor cannot be combined with around_item_id")
		return
	}
	folder, err := h.workspaceFolder(r, parameters.Get("folder_id"), model.FolderTypeMail)
	if err != nil {
		apiError(w, err)
		return
	}
	// A cached projection answers without consulting authorization, so the
	// item-read boundary is checked here on every request.
	capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
	if err != nil {
		apiError(w, err)
		return
	}
	if !capabilities.ReadItems {
		apiError(w, service.ErrForbidden)
		return
	}
	if name := strings.TrimSpace(parameters.Get("category")); name != "" {
		query.Keyword = category.Keyword(name)
	}
	if query.Filter == mailindex.FilterToMe {
		if query.Addresses, err = h.mailboxAddresses(r.Context(), folder.UserID); err != nil {
			apiError(w, err)
			return
		}
	}
	if query.Conversations {
		if query.Related, err = h.conversationFolders(r, folder); err != nil {
			apiError(w, err)
			return
		}
	}
	page, err := h.mailIndex.List(r.Context(), h.folderSpace, webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), folder, query)
	if err == nil {
		err = h.annotateMailPage(r.Context(), currentSubject(r).ID, &page)
		h.annotateMailCategories(r.Context(), currentActor(r).ID, &page)
	}
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, page)
}

// conversationActionItems expands conversation IDs listed in folderID to the
// folder's member messages, checking item reads like the list does.
func (h *Handler) conversationActionItems(r *http.Request, folderID string, conversationIDs []string) ([]string, error) {
	folder, err := h.workspaceFolder(r, folderID, model.FolderTypeMail)
	if err != nil {
		return nil, err
	}
	capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
	if err != nil {
		return nil, err
	}
	if !capabilities.ReadItems {
		return nil, service.ErrForbidden
	}
	related, err := h.conversationFolders(r, folder)
	if err != nil {
		return nil, err
	}
	return h.mailIndex.ConversationItems(r.Context(), h.folderSpace, webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), folder, related, conversationIDs)
}

// conversationFolders returns the mailbox folders whose messages join the
// listed folder's conversations, as Outlook's "show messages from other
// folders" does: the owner's readable Inbox, Sent, and Archive. Junk and
// Trash list only their own messages.
func (h *Handler) conversationFolders(r *http.Request, folder model.Folder) ([]model.Folder, error) {
	if folder.SpecialUse == model.SpecialUseJunk || folder.SpecialUse == model.SpecialUseTrash {
		return nil, nil
	}
	folders, err := h.workspace.ListFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		return nil, err
	}
	var related []model.Folder
	for _, candidate := range folders {
		if candidate.ID == folder.ID || candidate.Type != model.FolderTypeMail || !strings.EqualFold(candidate.UserID, folder.UserID) || !slices.Contains([]string{model.SpecialUseInbox, model.SpecialUseSent, model.SpecialUseArchive}, candidate.SpecialUse) {
			continue
		}
		capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, candidate)
		if err != nil {
			return nil, err
		}
		if capabilities.ReadItems {
			related = append(related, candidate)
		}
	}
	return related, nil
}

// mailboxAddresses returns the lowercase addresses that make a message
// addressed "to me" for the mailbox owner.
func (h *Handler) mailboxAddresses(ctx context.Context, userID string) ([]string, error) {
	identities, err := h.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	addresses := make([]string, 0, len(identities)+1)
	if strings.Contains(userID, "@") {
		addresses = append(addresses, strings.ToLower(userID))
	}
	for _, identity := range identities {
		addresses = append(addresses, strings.ToLower(identity.ID))
	}
	return addresses, nil
}

// mailTriage applies the folder-resolving item actions (archive, junk, not
// junk, block sender) for one bulk request, caching the folder catalog.
type mailTriage struct {
	h       *Handler
	r       *http.Request
	folders []model.Folder
	trained int
	blocked []string
}

func (t *mailTriage) catalog() ([]model.Folder, error) {
	if t.folders != nil {
		return t.folders, nil
	}
	folders, err := t.h.workspace.ListFolders(t.r.Context(), currentActor(t.r), currentSubject(t.r), currentActingMode(t.r))
	t.folders = folders
	return folders, err
}

// destination returns the owner's special-use mail folder. A missing
// Archive is created on demand for the signed-in mailbox owner.
func (t *mailTriage) destination(item model.Item, specialUse string) (model.Folder, error) {
	folders, err := t.catalog()
	if err != nil {
		return model.Folder{}, err
	}
	owner := ""
	for _, folder := range folders {
		if folder.ID == item.FolderID {
			owner = folder.UserID
		}
	}
	for _, folder := range folders {
		if folder.Type == model.FolderTypeMail && folder.SpecialUse == specialUse && strings.EqualFold(folder.UserID, owner) {
			return folder, nil
		}
	}
	if specialUse != model.SpecialUseArchive || !strings.EqualFold(owner, currentSubject(t.r).ID) {
		return model.Folder{}, fmt.Errorf("%w: the mailbox has no %s folder", store.ErrNotFound, specialUse)
	}
	archive, err := service.EnsureFolderPath(t.r.Context(), t.h.folderSpace, webAccess(currentActor(t.r), currentSubject(t.r), currentActingMode(t.r)), "Archive", model.FolderTypeMail)
	if err == nil {
		t.folders = append(t.folders, archive)
	}
	return archive, err
}

func (t *mailTriage) apply(itemID, action string) (model.Item, error) {
	actor, subject, mode := currentActor(t.r), currentSubject(t.r), currentActingMode(t.r)
	item, err := t.h.workspace.GetItem(t.r.Context(), actor, subject, mode, itemID)
	if err != nil {
		return model.Item{}, err
	}
	specialUse := map[string]string{"archive": model.SpecialUseArchive, "junk": model.SpecialUseJunk, "block_sender": model.SpecialUseJunk, "not_junk": model.SpecialUseInbox}[action]
	if action == "block_sender" {
		if sender := senderListEntry(messageSender(item)); sender != "" {
			if err := t.h.users.AddSpamListEntry(t.r.Context(), subject.ID, model.SpamListBlock, sender, time.Time{}); err != nil {
				return model.Item{}, err
			}
			t.blocked = append(t.blocked, sender)
		}
	}
	destination, err := t.destination(item, specialUse)
	if err != nil {
		return model.Item{}, err
	}
	result := item
	if destination.ID != item.FolderID {
		if result, err = t.h.workspace.MoveItem(t.r.Context(), actor, subject, mode, itemID, destination.ID); err != nil {
			return model.Item{}, err
		}
	}
	// Train only after the move is authorized, so a reader of a shared
	// folder cannot feed the classifier with someone else's mail.
	if action != "archive" {
		t.learn(item, action == "junk" || action == "block_sender")
	}
	return result, nil
}

// learn feeds the configured content trainer best-effort: a missing or
// failing trainer never blocks the user's move.
func (t *mailTriage) learn(item model.Item, spam bool) {
	if !t.h.trainingAvailable() || len(item.Data) == 0 {
		return
	}
	maximum := int64(50 << 20)
	if t.h.cfg != nil && t.h.cfg.RspamdMaxBytes > 0 {
		maximum = t.h.cfg.RspamdMaxBytes
	}
	if int64(len(item.Data)) > maximum {
		return
	}
	ctx, cancel := context.WithTimeout(t.r.Context(), 30*time.Second)
	defer cancel()
	if t.h.contentTrainer.Learn(ctx, item.Data, spam) == nil {
		t.trained++
	}
}

func messageSender(item model.Item) string {
	for key, value := range item.Headers {
		if strings.EqualFold(key, "From") && strings.TrimSpace(value) != "" {
			return model.DecodeHeaderValue(value)
		}
	}
	if message, err := mail.ReadMessage(bytes.NewReader(item.Data)); err == nil {
		return model.DecodeHeaderValue(message.Header.Get("From"))
	}
	return ""
}
