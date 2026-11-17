package ews

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// EWS notification limits. Subscriptions live in memory only: MS-EWS lets a
// pull subscription lapse after its Timeout and a streaming subscription
// after 30 minutes without a connection, and clients resubscribe after a
// server restart when GetEvents answers ErrorSubscriptionNotFound.
const (
	maxSubscriptionsPerUser   = 20
	maxSubscriptionFolders    = 200
	maxPullTimeout            = 1440 * time.Minute
	streamingIdleExpiry       = 30 * time.Minute
	maxStreamingConnection    = 30 * time.Minute
	defaultStreamingKeepalive = 30 * time.Second
	eventPageSize             = 100
	// Fallback polls for open streaming connections, as for EAS Ping: with
	// commit notifications they only cover what no notification reports.
	notifiedStreamPoll   = 60 * time.Second
	unnotifiedStreamPoll = 5 * time.Second
)

var (
	errSubscriptionNotFound     = errors.New("the specified subscription was not found")
	errInvalidSubscription      = errors.New("the subscription is not valid for this request")
	errSubscriptionAccessDenied = errors.New("the subscription belongs to another user")
	errInvalidWatermark         = errors.New("the watermark is invalid")
	errInvalidSubscriptionReq   = errors.New("the subscription request is invalid")
	errSubscriptionCount        = errors.New("too many subscriptions for this user")
)

// eventTypeNames are the notification event types EWS clients subscribe to.
var eventTypeNames = []string{"CopiedEvent", "CreatedEvent", "DeletedEvent", "ModifiedEvent", "MovedEvent", "NewMailEvent", "FreeBusyChangedEvent"}

// subscription is one pull or streaming subscription. Its journal states
// are keyed by scope: "a:" for the whole account, "h:" for the folder
// hierarchy only (a subscription on msgfolderroot), and "f:<id>" per folder.
type subscription struct {
	id         string
	access     service.AccessContext
	streaming  bool
	allFolders bool
	folders    []string
	folderType map[string]model.FolderType
	eventTypes map[string]bool
	timeout    time.Duration

	// The fields below are guarded by subscriptions.mu.
	lastUsed time.Time
	// wake receives commit signals; an open streaming connection swaps in
	// its own channel. It has capacity one so commits coalesce.
	wake chan struct{}
	// conn is the streaming connection holding the subscription.
	conn *streamConn

	// read serializes journal reads, which advance states.
	read   sync.Mutex
	states map[string]string
}

func (s *subscription) userID() string { return s.access.Subject.ID }

// expired reports whether the subscription lapsed at now.
func (s *subscription) expired(now time.Time) bool {
	if s.streaming {
		return s.conn == nil && now.Sub(s.lastUsed) > streamingIdleExpiry
	}
	return now.Sub(s.lastUsed) > s.timeout
}

// subscriptions is the in-memory registry, indexed by watched folder and by
// account so a commit wakes only the affected streaming connections.
type subscriptions struct {
	mu        sync.Mutex
	byID      map[string]*subscription
	byFolder  map[string]map[*subscription]struct{}
	byAccount map[string]map[*subscription]struct{}
	now       func() time.Time
}

func newSubscriptions() *subscriptions {
	return &subscriptions{
		byID:      map[string]*subscription{},
		byFolder:  map[string]map[*subscription]struct{}{},
		byAccount: map[string]map[*subscription]struct{}{},
		now:       time.Now,
	}
}

// sweepLocked drops lapsed subscriptions.
func (r *subscriptions) sweepLocked() {
	now := r.now()
	for _, sub := range r.byID {
		if sub.expired(now) {
			r.removeLocked(sub)
		}
	}
}

func (r *subscriptions) removeLocked(sub *subscription) {
	delete(r.byID, sub.id)
	for _, folderID := range sub.folders {
		removeIndexed(r.byFolder, folderID, sub)
	}
	removeIndexed(r.byAccount, sub.userID(), sub)
	if sub.conn != nil {
		sub.conn.stop()
		sub.conn = nil
	}
}

// streamConn is one open GetStreamingEvents response.
type streamConn struct {
	wake chan struct{}
	// done closes when a newer connection takes over one of its
	// subscriptions, the subscription goes away, or the server stops.
	done chan struct{}
	once sync.Once
}

func (c *streamConn) stop() { c.once.Do(func() { close(c.done) }) }

func (r *subscriptions) add(sub *subscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	count := 0
	for _, existing := range r.byID {
		if existing.userID() == sub.userID() {
			count++
		}
	}
	if count >= maxSubscriptionsPerUser {
		return errSubscriptionCount
	}
	sub.lastUsed = r.now()
	sub.wake = make(chan struct{}, 1)
	r.byID[sub.id] = sub
	for _, folderID := range sub.folders {
		addIndexed(r.byFolder, folderID, sub)
	}
	addIndexed(r.byAccount, sub.userID(), sub)
	return nil
}

// lookup returns the caller's live subscription and marks it used.
func (r *subscriptions) lookup(access service.AccessContext, id string, streaming bool) (*subscription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	sub := r.byID[id]
	if sub == nil {
		return nil, errSubscriptionNotFound
	}
	if sub.userID() != access.Subject.ID {
		return nil, errSubscriptionAccessDenied
	}
	if sub.streaming != streaming {
		return nil, errInvalidSubscription
	}
	sub.lastUsed = r.now()
	return sub, nil
}

func (r *subscriptions) remove(access service.AccessContext, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	sub := r.byID[id]
	if sub == nil {
		return errSubscriptionNotFound
	}
	if sub.userID() != access.Subject.ID {
		return errSubscriptionAccessDenied
	}
	r.removeLocked(sub)
	return nil
}

// attach binds streaming subscriptions to conn, ending any connection
// that held one of them.
func (r *subscriptions) attach(subs []*subscription, conn *streamConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sub := range subs {
		if sub.conn != nil {
			sub.conn.stop()
		}
		sub.conn = conn
		sub.wake = conn.wake
	}
}

// release ends conn's hold on the subscriptions it still owns, which then
// lapse after streamingIdleExpiry without a new connection.
func (r *subscriptions) release(subs []*subscription, conn *streamConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for _, sub := range subs {
		if sub.conn == conn {
			sub.conn = nil
			sub.wake = make(chan struct{}, 1)
			sub.lastUsed = now
		}
	}
	conn.stop()
}

// clear drops every subscription, at shutdown.
func (r *subscriptions) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sub := range r.byID {
		r.removeLocked(sub)
	}
}

func (r *subscriptions) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

// changesCommitted is the service.FolderChangeNotifier listener. It runs on
// the committing goroutine, so it only signals the affected subscriptions.
func (r *subscriptions) changesCommitted(accountID string, folderIDs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for sub := range r.byAccount[accountID] {
		if folderIDs == nil || sub.allFolders || sub.folders == nil {
			signal(sub.wake)
		}
	}
	for _, folderID := range folderIDs {
		for sub := range r.byFolder[folderID] {
			signal(sub.wake)
		}
	}
}

func signal(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

func addIndexed(index map[string]map[*subscription]struct{}, key string, sub *subscription) {
	if index[key] == nil {
		index[key] = map[*subscription]struct{}{}
	}
	index[key][sub] = struct{}{}
}

func removeIndexed(index map[string]map[*subscription]struct{}, key string, sub *subscription) {
	delete(index[key], sub)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}

func newSubscriptionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte("s:" + hex.EncodeToString(value[:]))), nil
}

func encodeWatermark(states map[string]string) string {
	data, _ := json.Marshal(states)
	return base64.StdEncoding.EncodeToString(data)
}

func decodeWatermark(encoded string) (map[string]string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errInvalidWatermark
	}
	var states map[string]string
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, errInvalidWatermark
	}
	return states, nil
}

func scopeOf(key string) service.ChangeScope {
	switch {
	case key == "h:":
		return service.ChangeScope{Object: service.ChangeObjectFolder}
	case strings.HasPrefix(key, "f:"):
		return service.ChangeScope{FolderID: strings.TrimPrefix(key, "f:")}
	}
	return service.ChangeScope{}
}

func (h *Handler) subscribe(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	request := op.child("PullSubscriptionRequest")
	streaming := false
	if request == nil {
		request = op.child("StreamingSubscriptionRequest")
		streaming = true
	}
	if request == nil {
		return responses("Subscribe", []responseMessage{{err: errInvalidSubscriptionReq}}), nil
	}
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return "", errors.New("folder change history is unavailable")
	}
	sub := &subscription{access: access, streaming: streaming, folderType: map[string]model.FolderType{}, eventTypes: map[string]bool{}, states: map[string]string{}}
	sub.allFolders = strings.EqualFold(strings.TrimSpace(request.attr("SubscribeToAllFolders")), "true")
	if types := request.child("EventTypes"); types != nil {
		for _, child := range types.Children {
			name := strings.TrimSpace(child.Text)
			if !slices.Contains(eventTypeNames, name) {
				return responses("Subscribe", []responseMessage{{err: errInvalidSubscriptionReq}}), nil
			}
			sub.eventTypes[name] = true
		}
	}
	if len(sub.eventTypes) == 0 {
		return responses("Subscribe", []responseMessage{{err: errInvalidSubscriptionReq}}), nil
	}
	var keys []string
	if sub.allFolders {
		keys = []string{"a:"}
	} else {
		ids := folderIDs(request.child("FolderIds"))
		if len(ids) == 0 || len(ids) > maxSubscriptionFolders {
			return responses("Subscribe", []responseMessage{{err: errInvalidSubscriptionReq}}), nil
		}
		sub.folders = []string{}
		for _, id := range ids {
			folder, err := h.resolveFolder(ctx, access, id)
			if err != nil {
				return responses("Subscribe", []responseMessage{{err: err}}), nil
			}
			if folder.ID == rootFolderID {
				if !slices.Contains(keys, "h:") {
					keys = append(keys, "h:")
				}
				continue
			}
			if !slices.Contains(sub.folders, folder.ID) {
				sub.folders = append(sub.folders, folder.ID)
				sub.folderType[folder.ID] = folder.Type
				keys = append(keys, "f:"+folder.ID)
			}
		}
	}
	if !streaming {
		sub.timeout = 30 * time.Minute
		if text := strings.TrimSpace(request.descendantText("Timeout")); text != "" {
			minutes, err := strconv.Atoi(text)
			if err != nil || minutes < 1 || time.Duration(minutes)*time.Minute > maxPullTimeout {
				return responses("Subscribe", []responseMessage{{err: errInvalidSubscriptionReq}}), nil
			}
			sub.timeout = time.Duration(minutes) * time.Minute
		}
		if watermark := strings.TrimSpace(request.descendantText("Watermark")); watermark != "" {
			states, err := decodeWatermark(watermark)
			if err != nil {
				return responses("Subscribe", []responseMessage{{err: err}}), nil
			}
			for _, key := range keys {
				state, ok := states[key]
				if !ok {
					return responses("Subscribe", []responseMessage{{err: errInvalidWatermark}}), nil
				}
				if _, err := service.ChangeStateSequence(state); err != nil {
					return responses("Subscribe", []responseMessage{{err: errInvalidWatermark}}), nil
				}
				sub.states[key] = state
			}
		}
	}
	for _, key := range keys {
		if _, ok := sub.states[key]; ok {
			continue
		}
		state, err := reader.CurrentChangeState(ctx, access, scopeOf(key))
		if err != nil {
			return responses("Subscribe", []responseMessage{{err: err}}), nil
		}
		sub.states[key] = state
	}
	id, err := newSubscriptionID()
	if err != nil {
		return "", err
	}
	sub.id = id
	if err := h.subscriptions.add(sub); err != nil {
		return responses("Subscribe", []responseMessage{{err: err}}), nil
	}
	body := `<m:SubscriptionId>` + escape(id) + `</m:SubscriptionId>`
	if !streaming {
		body += `<m:Watermark>` + escape(encodeWatermark(sub.states)) + `</m:Watermark>`
	}
	return responses("Subscribe", []responseMessage{{body: body}}), nil
}

func (h *Handler) unsubscribe(_ context.Context, access service.AccessContext, op *node) (string, error) {
	id := strings.TrimSpace(op.descendantText("SubscriptionId"))
	if err := h.subscriptions.remove(access, id); err != nil {
		return responses("Unsubscribe", []responseMessage{{err: err}}), nil
	}
	return responses("Unsubscribe", []responseMessage{{}}), nil
}

func (h *Handler) getEvents(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	sub, err := h.subscriptions.lookup(access, strings.TrimSpace(op.descendantText("SubscriptionId")), false)
	if err != nil {
		return responses("GetEvents", []responseMessage{{err: err}}), nil
	}
	notification, err := h.readEvents(ctx, sub, true)
	if err != nil {
		return responses("GetEvents", []responseMessage{{err: err}}), nil
	}
	return responses("GetEvents", []responseMessage{{body: notification}}), nil
}

// readEvents reads the subscription's journal scopes from its watermark
// and renders one Notification. Only the journal names what changed: an
// item is not read by ID, since a just-committed item may not resolve yet.
// A pull notification always carries an event, a StatusEvent when nothing
// changed; a streaming one is empty when nothing changed.
func (h *Handler) readEvents(ctx context.Context, sub *subscription, pull bool) (string, error) {
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return "", errors.New("folder change history is unavailable")
	}
	sub.read.Lock()
	defer sub.read.Unlock()
	previous := encodeWatermark(sub.states)
	next := make(map[string]string, len(sub.states))
	keys := make([]string, 0, len(sub.states))
	for key, state := range sub.states {
		keys = append(keys, key)
		next[key] = state
	}
	slices.Sort(keys)
	type pending struct {
		record service.ChangeRecord
		change service.Change
	}
	var changes []pending
	seen := map[string]bool{}
	more := false
	for _, key := range keys {
		page, err := reader.ListChanges(ctx, sub.access, scopeOf(key), sub.states[key], eventPageSize)
		if errors.Is(err, service.ErrChangeStateExpired) {
			return "", errInvalidSubscription
		}
		if err != nil {
			return "", err
		}
		for _, record := range page.Records {
			for _, change := range record.Changes {
				// A move between two watched folders is in both scopes.
				dedupe := record.MutationID + "\x00" + string(change.Object) + "\x00" + change.ID + "\x00" + string(change.Operation)
				if seen[dedupe] {
					continue
				}
				seen[dedupe] = true
				changes = append(changes, pending{record: record, change: change})
			}
		}
		next[key] = page.NewState
		more = more || page.HasMoreChanges
	}
	slices.SortStableFunc(changes, func(a, b pending) int {
		switch {
		case a.record.Sequence < b.record.Sequence:
			return -1
		case a.record.Sequence > b.record.Sequence:
			return 1
		}
		return 0
	})
	watermark := encodeWatermark(next)
	var events strings.Builder
	for _, entry := range changes {
		events.WriteString(h.renderEvents(ctx, sub, entry.change, watermark, entry.record.CommittedAt))
	}
	sub.states = next
	if events.Len() == 0 {
		if !pull {
			return "", nil
		}
		events.WriteString(`<t:StatusEvent><t:Watermark>` + escape(watermark) + `</t:Watermark></t:StatusEvent>`)
	}
	notification := `<m:Notification><t:SubscriptionId>` + escape(sub.id) + `</t:SubscriptionId>`
	if pull {
		notification += `<t:PreviousWatermark>` + escape(previous) + `</t:PreviousWatermark><t:MoreEvents>` + strconv.FormatBool(more) + `</t:MoreEvents>`
	}
	return notification + events.String() + `</m:Notification>`, nil
}

// renderEvents maps one journal change to the EWS events it raises.
func (h *Handler) renderEvents(ctx context.Context, sub *subscription, change service.Change, watermark string, at time.Time) string {
	if at.IsZero() {
		at = time.Now()
	}
	head := `<t:Watermark>` + escape(watermark) + `</t:Watermark><t:TimeStamp>` + at.UTC().Format(time.RFC3339) + `</t:TimeStamp>`
	folderRef := func(tag, id string) string {
		return `<t:` + tag + ` Id="` + escape(encodeID("f:", id)) + `"/>`
	}
	var object string
	parent, previousParent := change.FolderID, change.PreviousFolderID
	if change.Object == service.ChangeObjectFolder {
		object = folderRef("FolderId", change.ID)
		parent = rootFolderID
		if folder, err := h.space.GetFolder(ctx, sub.access, change.ID); err == nil && folder.ParentID != "" {
			parent = folder.ParentID
		}
		if previousParent == "" {
			previousParent = parent
		}
	} else {
		object = `<t:ItemId Id="` + escape(encodeID("i:", change.ID)) + `" ChangeKey="` + strconv.FormatUint(change.ModSeq, 10) + `"/>`
		if parent == "" {
			parent = previousParent
		}
	}
	event := func(name, body string) string {
		if !sub.eventTypes[name] {
			return ""
		}
		return `<t:` + name + `>` + head + body + `</t:` + name + `>`
	}
	switch change.Operation {
	case service.ChangeCreate, service.ChangeRestore:
		out := ""
		if change.Object == service.ChangeObjectItem && change.Operation == service.ChangeCreate && h.isMailFolder(ctx, sub, parent) {
			out += event("NewMailEvent", object+folderRef("ParentFolderId", parent))
		}
		return out + event("CreatedEvent", object+folderRef("ParentFolderId", parent))
	case service.ChangeUpdate:
		return event("ModifiedEvent", object+folderRef("ParentFolderId", parent))
	case service.ChangeMove:
		oldObject := strings.Replace(strings.Replace(object, "<t:ItemId ", "<t:OldItemId ", 1), "<t:FolderId ", "<t:OldFolderId ", 1)
		return event("MovedEvent", object+folderRef("ParentFolderId", parent)+oldObject+folderRef("OldParentFolderId", previousParent))
	case service.ChangeDestroy, service.ChangeTrash:
		return event("DeletedEvent", object+folderRef("ParentFolderId", parent))
	}
	return ""
}

// isMailFolder reports whether a new item in folderID is new mail.
func (h *Handler) isMailFolder(ctx context.Context, sub *subscription, folderID string) bool {
	folderType, ok := sub.folderType[folderID]
	if !ok {
		folder, err := h.space.GetFolder(ctx, sub.access, folderID)
		if err != nil {
			return false
		}
		folderType = folder.Type
	}
	return folderType == model.FolderTypeMail || folderType == ""
}

// getStreamingEvents holds the response open for ConnectionTimeout
// minutes, writing one SOAP envelope per batch of notifications and a
// ConnectionStatus OK keepalive between them, and ends with Closed.
func (h *Handler) getStreamingEvents(w http.ResponseWriter, r *http.Request, access service.AccessContext, op *node) {
	writeOnce := func(body string) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Header().Set("X-EWS-Server-Version", "Exchange2016")
		_, _ = io.WriteString(w, envelope(body))
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(op.descendantText("ConnectionTimeout")))
	if err != nil || minutes < 1 || time.Duration(minutes)*time.Minute > maxStreamingConnection {
		writeOnce(responses("GetStreamingEvents", []responseMessage{{err: errInvalidSubscriptionReq}}))
		return
	}
	var subs []*subscription
	if ids := op.child("SubscriptionIds"); ids != nil {
		for _, child := range ids.Children {
			sub, err := h.subscriptions.lookup(access, strings.TrimSpace(child.Text), true)
			if err != nil {
				writeOnce(responses("GetStreamingEvents", []responseMessage{{err: err}}))
				return
			}
			if !slices.Contains(subs, sub) {
				subs = append(subs, sub)
			}
		}
	}
	if len(subs) == 0 {
		writeOnce(responses("GetStreamingEvents", []responseMessage{{err: errInvalidSubscriptionReq}}))
		return
	}
	conn := &streamConn{wake: make(chan struct{}, 1), done: make(chan struct{})}
	h.subscriptions.attach(subs, conn)
	defer h.subscriptions.release(subs, conn)

	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-EWS-Server-Version", "Exchange2016")
	w.WriteHeader(http.StatusOK)
	write := func(body string) bool {
		if _, err := io.WriteString(w, envelope(response("GetStreamingEvents", body))); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	flushEvents := func() bool {
		var notifications strings.Builder
		for _, sub := range subs {
			for range 10 {
				notification, err := h.readEvents(r.Context(), sub, false)
				if err != nil || notification == "" {
					break
				}
				notifications.WriteString(notification)
			}
		}
		if notifications.Len() == 0 {
			return true
		}
		return write(`<m:Notifications>` + notifications.String() + `</m:Notifications>`)
	}
	if !write(`<m:ConnectionStatus>OK</m:ConnectionStatus>`) || !flushEvents() {
		return
	}
	poll := unnotifiedStreamPoll
	if _, ok := h.space.(service.FolderChangeNotifier); ok {
		poll = notifiedStreamPoll
	}
	deadline := time.NewTimer(time.Duration(minutes) * h.streamingMinute)
	defer deadline.Stop()
	keepalive := time.NewTicker(h.streamingKeepalive)
	defer keepalive.Stop()
	fallback := time.NewTicker(poll)
	defer fallback.Stop()
	for {
		select {
		case <-conn.wake:
			if !flushEvents() {
				return
			}
		case <-fallback.C:
			if !flushEvents() {
				return
			}
		case <-keepalive.C:
			if !write(`<m:ConnectionStatus>OK</m:ConnectionStatus>`) {
				return
			}
		case <-deadline.C:
			write(`<m:ConnectionStatus>Closed</m:ConnectionStatus>`)
			return
		case <-conn.done:
			write(`<m:ConnectionStatus>Closed</m:ConnectionStatus>`)
			return
		case <-h.ctx.Done():
			write(`<m:ConnectionStatus>Closed</m:ConnectionStatus>`)
			return
		case <-r.Context().Done():
			return
		}
	}
}
