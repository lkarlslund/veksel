package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/virus"
)

const (
	defaultQuarantinePageSize = 25
	maxQuarantinePageSize     = 100
)

var errQuarantineQueueUnavailable = errors.New("quarantine release queue unavailable")

type quarantineView struct {
	ID                    string            `json:"id"`
	Sender                string            `json:"sender"`
	Recipient             string            `json:"recipient"`
	Subject               string            `json:"subject"`
	Date                  string            `json:"date"`
	VirusName             string            `json:"virus_name"`
	Scanner               string            `json:"scanner"`
	MessageSize           int64             `json:"message_size"`
	ReasonType            string            `json:"reason_type,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	AuthenticationResults string            `json:"authentication_results,omitempty"`
	ScanTranscript        string            `json:"scan_transcript,omitempty"`
	TrainingAvailable     bool              `json:"training_available"`
	Headers               map[string]string `json:"headers,omitempty"`
	MessageData           []byte            `json:"message_data,omitempty"`
}

type quarantinePage struct {
	Entries  []quarantineView `json:"entries"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
	Pages    int              `json:"pages"`
}

func (h *Handler) quarantineEntryView(entry virus.QuarantineEntry, detail bool) quarantineView {
	view := quarantineView{ID: entry.ID, Sender: entry.Sender, Recipient: entry.Recipient, Subject: entry.Subject, Date: entry.Date, VirusName: entry.VirusName, Scanner: entry.Scanner, MessageSize: entry.MessageSize, ReasonType: entry.ReasonType, Reason: entry.Reason, TrainingAvailable: h.trainingAvailable()}
	if detail {
		view.Headers = entry.Headers
		view.MessageData = entry.MessageData
		view.AuthenticationResults = entry.AuthenticationResults
		view.ScanTranscript = entry.ScanTranscript
	}
	return view
}

func (h *Handler) quarantineStore() *virus.QuarantineStore {
	if h.quarantine != nil {
		return h.quarantine
	}
	return virus.NewQuarantineStore(h.ts)
}

func quarantineDetectionValue(entry virus.QuarantineEntry) string {
	for _, value := range []string{entry.VirusName, entry.Reason, entry.ReasonType, "policy quarantine"} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "policy quarantine"
}

func (h *Handler) quarantineEntryAllowed(r *http.Request, entry virus.QuarantineEntry) bool {
	if h.isAdmin(r.Context(), currentActor(r).ID) && currentActingMode(r) == "" {
		return true
	}
	if entry.OwnerID != "" {
		return strings.EqualFold(entry.OwnerID, currentSubject(r).ID)
	}
	identity, err := h.mailboxForRecipient(r.Context(), entry.Recipient)
	return err == nil && strings.EqualFold(identity.UserID, currentSubject(r).ID)
}

func (h *Handler) visibleQuarantine(r *http.Request) ([]virus.QuarantineEntry, error) {
	quarantine := h.quarantineStore()
	if h.quarantine != nil && (!h.isAdmin(r.Context(), currentActor(r).ID) || currentActingMode(r) != "") {
		return quarantine.ListForOwner(r.Context(), currentSubject(r).ID)
	}
	entries, err := quarantine.List(r.Context())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return []virus.QuarantineEntry{}, nil
		}
		return nil, err
	}
	visible := entries[:0]
	for _, entry := range entries {
		if h.quarantineEntryAllowed(r, entry) {
			visible = append(visible, entry)
		}
	}
	return visible, nil
}

func quarantineInt(value string, fallback, maximum int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	if maximum > 0 && parsed > maximum {
		return maximum
	}
	return parsed
}

func (h *Handler) apiQuarantine(w http.ResponseWriter, r *http.Request) {
	entries, err := h.visibleQuarantine(r)
	if err != nil {
		apiError(w, err)
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if query != "" {
		filtered := entries[:0]
		for _, entry := range entries {
			if strings.Contains(strings.ToLower(entry.Sender+" "+entry.Recipient+" "+entry.Subject+" "+entry.VirusName+" "+entry.Scanner+" "+entry.ReasonType+" "+entry.Reason), query) {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}
	sortKey := r.URL.Query().Get("sort")
	descending := r.URL.Query().Get("direction") != "asc"
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		comparison := 0
		switch sortKey {
		case "sender":
			comparison = strings.Compare(strings.ToLower(left.Sender), strings.ToLower(right.Sender))
		case "subject":
			comparison = strings.Compare(strings.ToLower(left.Subject), strings.ToLower(right.Subject))
		case "detection":
			comparison = strings.Compare(strings.ToLower(quarantineDetectionValue(left)), strings.ToLower(quarantineDetectionValue(right)))
		case "size":
			if left.MessageSize < right.MessageSize {
				comparison = -1
			} else if left.MessageSize > right.MessageSize {
				comparison = 1
			}
		default:
			comparison = strings.Compare(left.Date, right.Date)
		}
		if descending {
			return comparison > 0
		}
		return comparison < 0
	})
	page, pageSize, total := quarantineInt(r.URL.Query().Get("page"), 1, 0), quarantineInt(r.URL.Query().Get("page_size"), defaultQuarantinePageSize, maxQuarantinePageSize), len(entries)
	pages := (total + pageSize - 1) / pageSize
	if pages == 0 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	start := (page - 1) * pageSize
	end := min(start+pageSize, total)
	views := make([]quarantineView, 0, end-start)
	for _, entry := range entries[start:end] {
		views = append(views, h.quarantineEntryView(entry, false))
	}
	jsonResponse(w, http.StatusOK, quarantinePage{Entries: views, Total: total, Page: page, PageSize: pageSize, Pages: pages})
}

func (h *Handler) quarantineEntry(w http.ResponseWriter, r *http.Request) (virus.QuarantineEntry, bool) {
	entry, err := h.quarantineStore().Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "quarantine entry not found")
		} else {
			apiError(w, err)
		}
		return virus.QuarantineEntry{}, false
	}
	if !h.quarantineEntryAllowed(r, *entry) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return virus.QuarantineEntry{}, false
	}
	return *entry, true
}

func (h *Handler) apiQuarantineDetail(w http.ResponseWriter, r *http.Request) {
	entry, ok := h.quarantineEntry(w, r)
	if ok {
		jsonResponse(w, http.StatusOK, h.quarantineEntryView(entry, true))
	}
}

func (h *Handler) apiQuarantineTrain(w http.ResponseWriter, r *http.Request) {
	entry, ok := h.quarantineEntry(w, r)
	if !ok {
		return
	}
	if !h.trainingAvailable() {
		jsonError(w, http.StatusServiceUnavailable, "content training is not configured")
		return
	}
	maximum := int64(50 * 1024 * 1024)
	if h.cfg != nil && h.cfg.RspamdMaxBytes > 0 {
		maximum = h.cfg.RspamdMaxBytes
	}
	if int64(len(entry.MessageData)) > maximum {
		jsonError(w, http.StatusRequestEntityTooLarge, "quarantined message exceeds the content training limit")
		return
	}
	var request struct {
		Classification string `json:"classification"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	classification := strings.ToLower(strings.TrimSpace(request.Classification))
	if classification != "spam" && classification != "ham" {
		jsonError(w, http.StatusBadRequest, "classification must be spam or ham")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := h.contentTrainer.Learn(ctx, entry.MessageData, classification == "spam"); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "content trainer could not accept the sample")
		return
	}
	h.audit.Log(currentActor(r).ID, "quarantine.train", entry.ID, map[string]string{"classification": classification, "recipient": entry.Recipient})
	h.events.Publish(events.Event{Type: "quarantine.trained", Resource: entry.ID, Recipients: []string{currentSubject(r).ID}})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "trained", "classification": classification})
}

func (h *Handler) apiQuarantineRelease(w http.ResponseWriter, r *http.Request) {
	entryID := r.PathValue("id")
	entry, err := h.quarantineStore().Get(r.Context(), entryID)
	if err == nil && !h.quarantineEntryAllowed(r, *entry) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	expectedOwner := currentSubject(r).ID
	if h.isAdmin(r.Context(), currentActor(r).ID) && currentActingMode(r) == "" {
		expectedOwner = ""
	}
	queueID, ownerID, recipient, err := h.releaseQuarantine(r.Context(), entryID, expectedOwner)
	if err != nil {
		if errors.Is(err, errQuarantineQueueUnavailable) {
			jsonError(w, http.StatusServiceUnavailable, "mail queue could not accept the released message")
			return
		}
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "quarantine.release", entryID, map[string]string{"recipient": recipient, "queue_id": queueID})
	h.events.Publish(events.Event{Type: "quarantine.released", Resource: entryID, Recipients: []string{ownerID}})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "released", "queue_id": queueID})
}

func (h *Handler) releaseQuarantine(ctx context.Context, entryID, expectedOwner string) (queueID, ownerID, recipient string, retErr error) {
	quarantine := h.quarantineStore()
	entry, err := quarantine.Get(ctx, entryID)
	if errors.Is(err, store.ErrNotFound) {
		receipt, receiptErr := quarantine.GetReleaseReceipt(ctx, entryID)
		if receiptErr == nil && (expectedOwner == "" || strings.EqualFold(receipt.OwnerID, expectedOwner)) {
			return receipt.QueueID, receipt.OwnerID, receipt.Recipient, nil
		}
		return "", "", "", store.ErrNotFound
	}
	if err != nil {
		return "", "", "", err
	}
	identity, err := h.mailboxForRecipient(ctx, entry.Recipient)
	if err != nil || !identity.Enabled {
		return "", "", "", errors.New("quarantined recipient is no longer available")
	}
	if expectedOwner != "" && !strings.EqualFold(identity.UserID, expectedOwner) || entry.OwnerID != "" && !strings.EqualFold(entry.OwnerID, identity.UserID) {
		return "", "", "", service.ErrForbidden
	}
	enqueuer, ok := h.systemQueue.(interface{ EnqueueBatch([]*queue.Message) error })
	if !ok {
		return "", "", "", errQuarantineQueueUnavailable
	}
	queueID = "quarantine-release-" + fmt.Sprintf("%x", sha256.Sum256([]byte(entry.ID)))
	queued := &queue.Message{ID: queueID, CorrelationID: queueID, Direction: queue.DirectionInbound, EnvelopeSender: entry.Sender, Recipient: entry.Recipient, Headers: entry.Headers, Content: entry.MessageData, TargetFolderID: model.InboxFolderID(identity.UserID), TargetOwnerID: identity.UserID}
	if err := enqueuer.EnqueueBatch([]*queue.Message{queued}); err != nil && !errors.Is(err, queue.ErrDuplicate) {
		return "", "", "", fmt.Errorf("%w: %v", errQuarantineQueueUnavailable, err)
	}
	receipt := virus.ReleaseReceipt{EntryID: entry.ID, QueueID: queueID, OwnerID: identity.UserID, Recipient: entry.Recipient, AcceptedAt: time.Now().UTC()}
	if err := quarantine.PutReleaseReceipt(ctx, receipt); err != nil {
		return "", "", "", err
	}
	if err := quarantine.Delete(ctx, entry.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", "", "", err
	}
	if h.spamReputation != nil {
		h.spamReputation.Released(entry.Headers)
	}
	return queueID, identity.UserID, entry.Recipient, nil
}

func senderListEntry(sender string) string {
	if address, err := mail.ParseAddress(sender); err == nil {
		return strings.ToLower(strings.TrimSpace(address.Address))
	}
	return strings.ToLower(strings.TrimSpace(sender))
}

func (h *Handler) apiQuarantineSpam(w http.ResponseWriter, r *http.Request) {
	entry, ok := h.quarantineEntry(w, r)
	if !ok {
		return
	}
	expectedOwner := currentSubject(r).ID
	if h.isAdmin(r.Context(), currentActor(r).ID) && currentActingMode(r) == "" {
		expectedOwner = ""
	}
	sender, ownerID, recipient, err := h.confirmQuarantineSpam(r.Context(), entry.ID, expectedOwner)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "quarantine.confirm_spam", entry.ID, map[string]string{"sender": sender, "recipient": recipient})
	h.events.Publish(events.Event{Type: "quarantine.spam_confirmed", Resource: entry.ID, Recipients: []string{ownerID}})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "spam_confirmed", "blocked_sender": sender})
}

func (h *Handler) confirmQuarantineSpam(ctx context.Context, entryID, expectedOwner string) (sender, ownerID, recipient string, retErr error) {
	quarantine := h.quarantineStore()
	entry, err := quarantine.Get(ctx, entryID)
	if errors.Is(err, store.ErrNotFound) {
		receipt, receiptErr := quarantine.GetSpamReceipt(ctx, entryID)
		if receiptErr == nil && (expectedOwner == "" || strings.EqualFold(receipt.OwnerID, expectedOwner)) {
			return receipt.Blocked, receipt.OwnerID, "", nil
		}
		return "", "", "", store.ErrNotFound
	}
	if err != nil {
		return "", "", "", err
	}
	identity, err := h.mailboxForRecipient(ctx, entry.Recipient)
	if err != nil || !identity.Enabled {
		return "", "", "", errors.New("quarantined recipient is no longer available")
	}
	if expectedOwner != "" && !strings.EqualFold(identity.UserID, expectedOwner) || entry.OwnerID != "" && !strings.EqualFold(entry.OwnerID, identity.UserID) {
		return "", "", "", service.ErrForbidden
	}
	sender = senderListEntry(entry.Sender)
	if sender != "" {
		if err := h.users.AddSpamListEntry(ctx, identity.UserID, model.SpamListBlock, sender, time.Time{}); err != nil {
			return "", "", "", err
		}
	}
	if err := quarantine.PutSpamReceipt(ctx, virus.SpamReceipt{EntryID: entry.ID, OwnerID: identity.UserID, Blocked: sender, ConfirmedAt: time.Now().UTC()}); err != nil {
		return "", "", "", err
	}
	if err := quarantine.Delete(ctx, entry.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", "", "", err
	}
	return sender, identity.UserID, entry.Recipient, nil
}

type spamListsResponse struct {
	Allow        []string                `json:"allow"`
	Block        []string                `json:"block"`
	AllowEntries []spamListEntryResponse `json:"allow_entries"`
	BlockEntries []spamListEntryResponse `json:"block_entries"`
}

type spamListEntryResponse struct {
	Value     string `json:"value"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func (h *Handler) apiSpamLists(w http.ResponseWriter, r *http.Request) {
	userID := currentSubject(r).ID
	allow, err := h.users.ReadSpamListEntries(r.Context(), userID, model.SpamListAllow)
	if err != nil {
		apiError(w, err)
		return
	}
	block, err := h.users.ReadSpamListEntries(r.Context(), userID, model.SpamListBlock)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, spamListsResponse{
		Allow: spamListResponseValues(allow), Block: spamListResponseValues(block),
		AllowEntries: projectSpamListEntries(allow), BlockEntries: projectSpamListEntries(block),
	})
}

func spamListResponseValues(entries []model.SpamListEntry) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.Value)
	}
	return values
}

func projectSpamListEntries(entries []model.SpamListEntry) []spamListEntryResponse {
	result := make([]spamListEntryResponse, 0, len(entries))
	for _, entry := range entries {
		projected := spamListEntryResponse{Value: entry.Value}
		if !entry.ExpiresAt.IsZero() {
			projected.ExpiresAt = entry.ExpiresAt.UTC().Format(time.RFC3339)
		}
		result = append(result, projected)
	}
	return result
}

func normalizeSpamListEntry(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "@")
	if value == "" || strings.ContainsAny(value, " <>\t\r\n,;") || (!strings.Contains(value, ".") && !strings.Contains(value, "@")) {
		return "", errors.New("enter an email address or domain")
	}
	return value, nil
}

func (h *Handler) mutateSpamList(w http.ResponseWriter, r *http.Request, add bool) {
	var request struct {
		Entry     string `json:"entry"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	entry, err := normalizeSpamListEntry(request.Entry)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, kindValue := currentSubject(r).ID, r.PathValue("kind")
	kind := model.SpamListKind(kindValue)
	if kind != model.SpamListAllow && kind != model.SpamListBlock {
		jsonError(w, http.StatusNotFound, "unknown sender list")
		return
	}
	var expiresAt time.Time
	if add && strings.TrimSpace(request.ExpiresAt) != "" {
		expiresAt, err = time.Parse(time.RFC3339, request.ExpiresAt)
		if err != nil || !expiresAt.After(time.Now().UTC()) {
			jsonError(w, http.StatusBadRequest, "expiry must be a future RFC3339 timestamp")
			return
		}
	}
	if add {
		err = h.users.AddSpamListEntry(r.Context(), userID, kind, entry, expiresAt)
	} else {
		err = h.users.RemoveSpamListEntry(r.Context(), userID, kind, entry)
	}
	if err != nil {
		apiError(w, err)
		return
	}
	auditFields := map[string]string{"kind": string(kind), "entry": entry, "action": map[bool]string{true: "add", false: "remove"}[add]}
	if !expiresAt.IsZero() {
		auditFields["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	h.audit.Log(currentActor(r).ID, "spam_list.update", userID, auditFields)
	h.apiSpamLists(w, r)
}

type spamConfigResponse struct {
	Enabled   bool    `json:"enabled"`
	Threshold float64 `json:"threshold"`
}

// apiAdminUserSpamConfig reads, and with PUT partially updates, whether
// local spam scoring files one account's mail and at which score.
func (h *Handler) apiAdminUserSpamConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	userID := r.PathValue("id")
	enabled, threshold, err := h.users.GetSpamConfig(r.Context(), userID)
	if err != nil {
		apiError(w, err)
		return
	}
	if r.Method == http.MethodPut {
		var request struct {
			Enabled   *bool    `json:"enabled"`
			Threshold *float64 `json:"threshold"`
		}
		if err := decodeJSON(r, &request); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if request.Threshold != nil && (*request.Threshold < 0 || *request.Threshold > 50) {
			jsonError(w, http.StatusBadRequest, "threshold must be between 0 and 50")
			return
		}
		if request.Enabled != nil {
			enabled = *request.Enabled
		}
		if request.Threshold != nil {
			threshold = *request.Threshold
		}
		if err := h.users.UpdateSpamConfig(r.Context(), userID, enabled, threshold); err != nil {
			apiError(w, err)
			return
		}
		h.audit.Log(currentActor(r).ID, "spam_config.update", userID, map[string]string{
			"enabled": strconv.FormatBool(enabled), "threshold": strconv.FormatFloat(threshold, 'f', 1, 64),
		})
	}
	jsonResponse(w, http.StatusOK, spamConfigResponse{Enabled: enabled, Threshold: threshold})
}

func (h *Handler) apiSpamListAdd(w http.ResponseWriter, r *http.Request) {
	h.mutateSpamList(w, r, true)
}

func (h *Handler) apiSpamListRemove(w http.ResponseWriter, r *http.Request) {
	h.mutateSpamList(w, r, false)
}
