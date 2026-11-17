package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

// Push (RFC 8620 §7): an EventSource connection checks the account journals
// when a commit to one of them wakes it, or on the fallback poll, and emits
// a StateChange naming the data types whose state moved.

// collectionTypes maps a folder type to its collection and item data types.
var collectionTypes = map[model.FolderType][2][]string{
	model.FolderTypeMail:     {{"Mailbox"}, {"Email", "Thread"}},
	model.FolderTypeContacts: {{"AddressBook"}, {"ContactCard"}},
	model.FolderTypeCalendar: {{"Calendar"}, {"CalendarEvent"}},
}

// pushTypes lists every data type a folder type reports state for.
func pushTypes(folderType model.FolderType) []string {
	types := collectionTypes[folderType]
	return append(append([]string{}, types[0]...), types[1]...)
}

type stateChange struct {
	Type    string                       `json:"@type"`
	Changed map[string]map[string]string `json:"changed"`
}

// pushTracker remembers the journal state last reported per account.
type pushTracker struct {
	wanted map[string]bool // nil means every type
	last   map[string]string
}

func (h *Handler) eventSource(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	query := r.URL.Query()
	tracker := &pushTracker{last: map[string]string{}}
	if types := query.Get("types"); types != "" && types != "*" {
		tracker.wanted = idSet(strings.Split(types, ","))
	}
	who := actor(r)
	ctx := r.Context()
	emit := func(changed map[string]map[string]string) {
		data, _ := json.Marshal(stateChange{Type: "StateChange", Changed: changed})
		fmt.Fprintf(w, "event: state\ndata: %s\n\n", data)
		flusher.Flush()
	}
	watcher := h.newPushWatcher()
	defer watcher.close()
	emit(h.pushStates(ctx, who, tracker, true))
	if query.Get("closeafter") == "state" {
		return
	}
	watcher.follow(tracker)
	poll := time.NewTicker(h.cfg.PushInterval)
	defer poll.Stop()
	interval, _ := strconv.Atoi(query.Get("ping"))
	keepalive := time.Duration(interval) * time.Second
	if interval <= 0 {
		keepalive = 30 * time.Second
	}
	ping := time.NewTicker(keepalive)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-watcher.wake:
			if !watcher.settle(ctx) {
				return
			}
			if changed := h.pushStates(ctx, who, tracker, false); len(changed) > 0 {
				emit(changed)
			}
			watcher.follow(tracker)
		case <-poll.C:
			if changed := h.pushStates(ctx, who, tracker, false); len(changed) > 0 {
				emit(changed)
			}
			watcher.follow(tracker)
		case <-ping.C:
			if interval > 0 {
				fmt.Fprintf(w, "event: ping\ndata: {\"interval\":%d}\n\n", interval)
			} else {
				fmt.Fprint(w, ": ping\n\n")
			}
			flusher.Flush()
		}
	}
}

// pushStates returns the type states to report. The initial call reports
// every type; later calls report only types with journal changes since the
// state last reported for the account.
func (h *Handler) pushStates(ctx context.Context, who model.User, tracker *pushTracker, initial bool) map[string]map[string]string {
	accounts, err := h.accounts(ctx, who)
	if err != nil {
		return nil
	}
	changed := map[string]map[string]string{}
	for accountID := range accounts {
		access, e := h.validateAccount(ctx, who, accountID)
		if e != nil {
			continue
		}
		folders := h.jmapFolders(ctx, access)
		state, err := h.collectionState(ctx, access, folders)
		if err != nil {
			continue
		}
		previous, seen := tracker.last[accountID]
		tracker.last[accountID] = state
		var types map[string]bool
		switch {
		case initial || !seen:
			types = map[string]bool{}
			for folderType := range h.accountFolderTypes(ctx, access, accountID) {
				for _, name := range pushTypes(folderType) {
					types[name] = true
				}
			}
		case previous != state:
			types = h.changedTypes(ctx, access, folders, previous)
		}
		for name := range types {
			if tracker.wanted == nil || tracker.wanted[name] {
				if changed[accountID] == nil {
					changed[accountID] = map[string]string{}
				}
				changed[accountID][name] = state
			}
		}
	}
	return changed
}

// jmapFolders lists every JMAP-visible folder of the validated account.
func (h *Handler) jmapFolders(ctx context.Context, access service.AccessContext) []model.Folder {
	var all []model.Folder
	for _, folderType := range jmapFolderTypes {
		folders, err := h.typedFolders(ctx, access, folderType)
		if err == nil {
			all = append(all, folders...)
		}
	}
	return all
}

// changedTypes names the data types touched by journal records since state.
func (h *Handler) changedTypes(ctx context.Context, access service.AccessContext, folders []model.Folder, since string) map[string]bool {
	types := map[string]bool{}
	page, err := h.collectionChanges(ctx, access, folders, "", since, 10_000)
	if err != nil || page.HasMoreChanges {
		for _, folder := range folders {
			for _, name := range pushTypes(folder.Type) {
				types[name] = true
			}
		}
		return types
	}
	byID := folderIndex(folders)
	for _, record := range page.Records {
		for _, change := range record.Changes {
			if change.Object == service.ChangeObjectFolder {
				for _, name := range collectionTypes[change.FolderType][0] {
					types[name] = true
				}
				continue
			}
			folder, ok := byID[change.FolderID]
			if !ok {
				folder, ok = byID[change.PreviousFolderID]
			}
			if ok {
				for _, name := range collectionTypes[folder.Type][1] {
					types[name] = true
				}
			}
		}
	}
	return types
}
