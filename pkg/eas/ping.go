package eas

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

// Heartbeat bounds in seconds. Exchange defaults to the same range; the
// HTTP listeners' long-running deadline (one hour) exceeds the maximum.
const (
	minHeartbeatSeconds = 60
	maxHeartbeatSeconds = 3540
	maxPingFolders      = 300
)

// Ping status codes (MS-ASCMD 2.2.3.177.11).
const (
	pingExpired        = "1"
	pingChanges        = "2"
	pingMissingParams  = "3"
	pingSyntaxError    = "4"
	pingBadHeartbeat   = "5"
	pingTooManyFolders = "6"
	pingHierarchy      = "7"
	pingServerError    = "8"
)

// ping implements the ActiveSync long poll. The partnership lock is held
// only while the request is validated and while state is read, never while
// waiting, so the device's other commands (and a newer Ping) proceed.
func (h *Handler) ping(command *commandContext, r *http.Request) (*Node, error) {
	var folders []string
	var heartbeat int
	var baselines map[string]string
	var waiter *pingWaiter
	response, err := h.withState(command, r, func(command *commandContext) (*Node, error) {
		state := command.state
		request := command.request
		if request != nil && request.Child("HeartbeatInterval") != nil {
			value, parseErr := strconv.Atoi(childText(request, "HeartbeatInterval"))
			if parseErr != nil {
				return E(13, "Ping", T(13, "Status", pingSyntaxError)), nil
			}
			if value < h.minHeartbeat || value > h.maxHeartbeat {
				limit := h.maxHeartbeat
				if value < h.minHeartbeat {
					limit = h.minHeartbeat
				}
				return E(13, "Ping", T(13, "Status", pingBadHeartbeat), T(13, "HeartbeatInterval", strconv.Itoa(limit))), nil
			}
			state.PingHeartbeat = value
		}
		if list := request.Child("Folders"); list != nil {
			entries := list.ChildrenNamed("Folder")
			if len(entries) > maxPingFolders {
				return E(13, "Ping", T(13, "Status", pingTooManyFolders), T(13, "MaxFolders", strconv.Itoa(maxPingFolders))), nil
			}
			state.PingFolders = state.PingFolders[:0]
			for _, entry := range entries {
				state.PingFolders = append(state.PingFolders, childText(entry, "Id"))
			}
		}
		if state.PingHeartbeat == 0 || len(state.PingFolders) == 0 {
			// An empty Ping reuses the last parameters; there are none.
			return E(13, "Ping", T(13, "Status", pingMissingParams)), nil
		}
		heartbeat = state.PingHeartbeat
		folders = folders[:0]
		var accounts []string
		for _, serverID := range state.PingFolders {
			folderID, decodeErr := decodeServerID(serverID, "f:")
			if decodeErr != nil {
				return E(13, "Ping", T(13, "Status", pingHierarchy)), nil
			}
			folder, getErr := h.space.GetFolder(command.ctx, command.access, folderID)
			if getErr != nil {
				if service.IsTemporarilyUnavailable(getErr) {
					return nil, getErr
				}
				return E(13, "Ping", T(13, "Status", pingHierarchy)), nil
			}
			folders = append(folders, folderID)
			if folder.UserID != "" && !slices.Contains(accounts, folder.UserID) {
				accounts = append(accounts, folder.UserID)
			}
		}
		waiter = h.waits.register(h.waitKey(command), folders, accounts)
		baselines = map[string]string{}
		changed, changeErr := h.changedFolders(command, state, folders, baselines)
		if changeErr != nil {
			return nil, changeErr
		}
		if len(changed) > 0 {
			return pingChangedResponse(changed), nil
		}
		return nil, nil
	})
	if err != nil || response != nil || waiter == nil {
		if waiter != nil {
			h.waits.unregister(waiter)
		}
		return response, err
	}
	changed := h.waitForChanges(command, waiter, time.Duration(heartbeat)*time.Second, baselines)
	if len(changed) > 0 {
		return pingChangedResponse(changed), nil
	}
	return E(13, "Ping", T(13, "Status", pingExpired)), nil
}

func pingChangedResponse(folderIDs []string) *Node {
	list := E(13, "Folders")
	for _, folderID := range folderIDs {
		list.Children = append(list.Children, T(13, "Folder", encodeServerID("f:", folderID)))
	}
	return E(13, "Ping", T(13, "Status", pingChanges), list)
}

// waitForChanges waits until a watched folder changes, the interval ends,
// the client disconnects, the server shuts down, or a newer request from the
// same device supersedes this one, and returns the changed folders. It
// unregisters waiter, which the caller registered before its last journal
// read.
//
// Commit notifications for the watched folders wake it, so it reads nothing
// while idle; the slow fallback poll covers changes no notification
// reports. A wake reads the journal, never items by ID: the account space
// notifies before a new item's location index is written.
func (h *Handler) waitForChanges(command *commandContext, waiter *pingWaiter, interval time.Duration, baseline map[string]string) []string {
	defer h.waits.unregister(waiter)
	deadline := time.NewTimer(interval)
	defer deadline.Stop()
	fallback := time.NewTicker(h.pingPoll)
	defer fallback.Stop()
	for {
		select {
		case <-command.ctx.Done():
			return nil
		case <-h.ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case <-waiter.superseded:
			return nil
		case <-waiter.wake:
		case <-fallback.C:
		}
		state, err := h.states.Load(command.ctx, command.userID, command.line.DeviceID)
		if err != nil {
			continue
		}
		changed, err := h.changedFolders(command, &state, waiter.folders, baseline)
		if err != nil {
			continue
		}
		if len(changed) > 0 {
			return changed
		}
	}
}

func (h *Handler) waitKey(command *commandContext) string {
	return command.userID + "\x00" + command.line.DeviceID
}

// folderAccounts returns the accounts owning folders, for waits woken by
// account-wide notifications.
func (h *Handler) folderAccounts(command *commandContext, folders []string) []string {
	var accounts []string
	for _, folderID := range folders {
		folder, err := h.space.GetFolder(command.ctx, command.access, folderID)
		if err == nil && folder.UserID != "" && !slices.Contains(accounts, folder.UserID) {
			accounts = append(accounts, folder.UserID)
		}
	}
	return accounts
}

// changedFolders reports which folders hold changes the device has not
// synchronized. Folders without synchronization state are compared with
// the journal position recorded in baselines on the first call.
func (h *Handler) changedFolders(command *commandContext, state *DeviceState, folders []string, baselines map[string]string) ([]string, error) {
	reader, ok := h.space.(service.FolderChangeReader)
	if !ok {
		return nil, errors.New("folder space does not provide incremental changes")
	}
	var changed []string
	for _, folderID := range folders {
		if _, initial := state.CollectionInitialStates[folderID]; initial {
			changed = append(changed, folderID)
			continue
		}
		scope := service.ChangeScope{FolderID: folderID, Object: service.ChangeObjectItem}
		base := state.CollectionStates[folderID]
		if base == "" {
			if baselines == nil {
				continue
			}
			if base = baselines[folderID]; base == "" {
				current, err := reader.CurrentChangeState(command.ctx, command.access, scope)
				if err != nil {
					return nil, err
				}
				baselines[folderID] = current
				continue
			}
		}
		page, err := reader.ListChanges(command.ctx, command.access, scope, base, 64)
		if errors.Is(err, service.ErrChangeStateExpired) {
			changed = append(changed, folderID)
			continue
		}
		if err != nil {
			return nil, err
		}
		if page.HasMoreChanges || len(newEchoSet(state.CollectionEchoes[folderID]).pendingIDs(page, folderID)) > 0 {
			changed = append(changed, folderID)
		}
	}
	return changed, nil
}
