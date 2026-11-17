package app

import (
	"bytes"
	"errors"
	"mime"
	"net/http"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// maxMessageSourceBytes bounds the View source dialog; Download .eml returns
// the whole message.
const maxMessageSourceBytes = 512 << 10

var emlFilenameUnsafe = regexp.MustCompile(`[^\p{L}\p{N} ._()-]+`)

// workspaceMailItem returns a readable mail item through the same folder
// authorization as the message projection.
func (h *Handler) workspaceMailItem(r *http.Request) (model.Item, error) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		return model.Item{}, err
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeMail); err != nil {
		return model.Item{}, err
	}
	return item, nil
}

// apiWorkspaceMailSource returns the raw RFC 5322 message for the View source
// dialog, truncated to maxMessageSourceBytes.
func (h *Handler) apiWorkspaceMailSource(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspaceMailItem(r)
	if err != nil {
		apiError(w, err)
		return
	}
	data, truncated := item.Data, false
	if len(data) > maxMessageSourceBytes {
		data, truncated = data[:maxMessageSourceBytes], true
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
	}
	if headerEnd < 0 {
		headerEnd = len(data)
	}
	w.Header().Set("Cache-Control", "private, no-store")
	jsonResponse(w, http.StatusOK, map[string]any{
		"size": len(item.Data), "truncated": truncated,
		"headers": strings.ToValidUTF8(string(data[:headerEnd]), "�"), "source": strings.ToValidUTF8(string(data), "�"),
	})
}

// apiWorkspaceMailEML downloads the stored message as an .eml file.
func (h *Handler) apiWorkspaceMailEML(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspaceMailItem(r)
	if err != nil {
		apiError(w, err)
		return
	}
	subject := ""
	if message, parseErr := mail.ReadMessage(bytes.NewReader(item.Data)); parseErr == nil {
		subject, _ = new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	}
	name := strings.Join(strings.Fields(emlFilenameUnsafe.ReplaceAllString(subject, " ")), " ")
	if len(name) > 80 {
		name = strings.ToValidUTF8(name[:80], "")
	}
	if name == "" {
		name = "message"
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".eml"}))
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Length", strconv.Itoa(len(item.Data)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(item.Data)
}

// apiWorkspaceMailReceipt answers a read receipt request: "send" queues an
// MDN (RFC 8098) and "dismiss" declines; both set $MDNSent so the request is
// answered once. Receipts are never sent automatically.
func (h *Handler) apiWorkspaceMailReceipt(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Action string `json:"action"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Action != "send" && request.Action != "dismiss" {
		jsonError(w, http.StatusBadRequest, "action must be send or dismiss")
		return
	}
	item, err := h.workspaceMailItem(r)
	if err != nil {
		apiError(w, err)
		return
	}
	if slices.Contains(item.Flags, model.KeywordMDNSent) {
		jsonError(w, http.StatusConflict, "this read receipt request was already answered")
		return
	}
	actor, subject := currentActor(r), currentSubject(r)
	recipient := ""
	if request.Action == "send" {
		// The message must sit in the actor's own mailbox: a reader of a
		// shared folder would otherwise send receipts in the owner's
		// place, and, unable to set $MDNSent, send them repeatedly.
		folder, err := h.folderSpace.GetFolder(r.Context(), webAccess(actor, subject, currentActingMode(r)), item.FolderID)
		if err != nil {
			apiError(w, err)
			return
		}
		if actor.ID != subject.ID || !strings.EqualFold(folder.UserID, actor.ID) {
			jsonError(w, http.StatusForbidden, "read receipts can only be sent from your own mailbox")
			return
		}
		if h.mail == nil {
			jsonError(w, http.StatusServiceUnavailable, "mail submission is unavailable")
			return
		}
		if recipient, err = h.mail.SendDispositionNotification(r.Context(), actor, item.Data); err != nil {
			if errors.Is(err, service.ErrNoReceiptRequested) {
				jsonError(w, http.StatusBadRequest, err.Error())
				return
			}
			apiError(w, err)
			return
		}
	}
	item, err = h.workspace.SetItemKeyword(r.Context(), actor, subject, currentActingMode(r), item.ID, model.KeywordMDNSent, true)
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "mail.receipt."+request.Action, item.ID, map[string]any{"folder_id": item.FolderID})
	jsonResponse(w, http.StatusOK, map[string]any{"item_id": item.ID, "flags": item.Flags, "action": request.Action, "recipient": recipient})
}

// remoteImagesAllowed reports whether the viewing user always shows remote
// images from the message's sender.
func (h *Handler) remoteImagesAllowed(r *http.Request, from string) bool {
	address, err := mail.ParseAddress(from)
	if err != nil {
		return false
	}
	user, err := h.users.Get(r.Context(), currentActor(r).ID)
	return err == nil && slices.Contains(user.RemoteImageSenders, strings.ToLower(address.Address))
}

func (h *Handler) apiRemoteImageSenders(w http.ResponseWriter, r *http.Request) {
	user, err := h.users.Get(r.Context(), currentActor(r).ID)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"senders": nonNilStrings(user.RemoteImageSenders)})
}

// apiSetRemoteImageSender adds (PUT) or removes (DELETE) one sender address.
func (h *Handler) apiSetRemoteImageSender(w http.ResponseWriter, r *http.Request) {
	address, err := mail.ParseAddress(r.PathValue("sender"))
	if err != nil || !strings.Contains(address.Address, "@") {
		jsonError(w, http.StatusBadRequest, "a valid sender address is required")
		return
	}
	userID := currentActor(r).ID
	senders, err := h.users.SetRemoteImageSender(r.Context(), userID, address.Address, r.Method == http.MethodPut)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(userID, "mail.remote_images."+map[bool]string{true: "allow", false: "remove"}[r.Method == http.MethodPut], strings.ToLower(address.Address), nil)
	jsonResponse(w, http.StatusOK, map[string]any{"senders": nonNilStrings(senders)})
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
