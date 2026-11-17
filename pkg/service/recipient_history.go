package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

const recipientHistoryNamespace = "veksel:recent-recipient"

// RecipientHistory records successful outbound recipients through FolderSpace.
// Its data is an ordinary contacts folder, so CardDAV, search, RBAC, caches, and
// future storage backends all observe the same items without a private store.
type RecipientHistory struct {
	space FolderSpace
	mu    sync.Mutex
	now   func() time.Time
}

func NewRecipientHistory(space FolderSpace) *RecipientHistory {
	return &RecipientHistory{space: space, now: func() time.Time { return time.Now().UTC() }}
}

// Record parses one or more RFC 5322 address-list values and upserts one vCard
// per distinct email address. Invalid values are ignored when another valid
// recipient remains; a wholly invalid list is a no-op.
func (h *RecipientHistory) Record(ctx context.Context, userID string, values []string) error {
	if h == nil || h.space == nil || strings.TrimSpace(userID) == "" {
		return nil
	}
	addresses := uniqueAddresses(values)
	if len(addresses) == 0 {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	access := UserAccess(userID, "recipient-history")
	folder, err := h.space.GetFolderByPath(ctx, access, "Recent recipients")
	if errors.Is(err, store.ErrNotFound) {
		folder, err = h.space.CreateFolder(ctx, access, "Recent recipients", model.FolderTypeContacts, "")
	}
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if err := h.upsert(ctx, access, folder.ID, address); err != nil {
			return err
		}
	}
	return nil
}

// Knows reports whether userID has sent mail to address. The history is the
// account's own record of correspondents, so no second list is kept.
func (h *RecipientHistory) Knows(ctx context.Context, userID, address string) (bool, error) {
	email := strings.ToLower(strings.TrimSpace(address))
	if h == nil || h.space == nil || strings.TrimSpace(userID) == "" || email == "" {
		return false, nil
	}
	access := UserAccess(userID, "recipient-history")
	folder, err := h.space.GetFolderByPath(ctx, access, "Recent recipients")
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = h.space.GetItemByExternalID(ctx, access, folder.ID, recipientHistoryNamespace, email)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (h *RecipientHistory) upsert(ctx context.Context, access AccessContext, folderID string, address *mail.Address) error {
	email := strings.ToLower(strings.TrimSpace(address.Address))
	now := h.now().UTC()
	item, err := h.space.GetItemByExternalID(ctx, access, folderID, recipientHistoryNamespace, email)
	if err == nil {
		contact := model.ParseVCard(item.Data)
		if strings.TrimSpace(address.Name) != "" {
			contact.FN = strings.TrimSpace(address.Name)
		}
		if strings.TrimSpace(contact.FN) == "" {
			contact.FN = recipientDisplayName(email)
		}
		contact.Emails = []string{email}
		headers := cloneHeaders(item.Headers)
		headers["Email"] = email
		headers["Last-Used"] = now.Format(time.RFC3339Nano)
		uses, _ := strconv.ParseUint(headers["Use-Count"], 10, 64)
		headers["Use-Count"] = strconv.FormatUint(uses+1, 10)
		_, err = h.space.UpdateItem(ctx, access, item.ID, model.ContactToVCard(contact), headers)
		return err
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	uidHash := sha256.Sum256([]byte(email))
	name := strings.TrimSpace(address.Name)
	if name == "" {
		name = recipientDisplayName(email)
	}
	contact := model.Contact{
		UID:        "recent-" + hex.EncodeToString(uidHash[:16]),
		FN:         name,
		Emails:     []string{email},
		Categories: []string{"recent-recipient"},
	}
	_, err = h.space.CreateItem(ctx, access, folderID, ItemInput{
		Data: model.ContactToVCard(contact),
		Headers: map[string]string{
			"Email": email, "Last-Used": now.Format(time.RFC3339Nano), "Use-Count": "1",
		},
		ExternalIDs: map[string]string{recipientHistoryNamespace: email},
	})
	return err
}

func uniqueAddresses(values []string) []*mail.Address {
	seen := make(map[string]bool)
	result := make([]*mail.Address, 0, len(values))
	for _, value := range values {
		addresses, err := mail.ParseAddressList(value)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			email := strings.ToLower(strings.TrimSpace(address.Address))
			if email == "" || seen[email] {
				continue
			}
			seen[email] = true
			address.Address = email
			result = append(result, address)
		}
	}
	return result
}

func recipientDisplayName(email string) string {
	name, _, found := strings.Cut(email, "@")
	if found && name != "" {
		return name
	}
	return email
}
