package eas

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

const stateNamespace = "eas_device_state"

type DeviceState struct {
	UserID                  string            `json:"user_id"`
	DeviceID                string            `json:"device_id"`
	DeviceType              string            `json:"device_type"`
	Protocol                string            `json:"protocol"`
	FolderKey               string            `json:"folder_key"`
	FolderState             string            `json:"folder_state,omitempty"`
	CollectionKeys          map[string]string `json:"collection_keys,omitempty"`
	CollectionStates        map[string]string `json:"collection_states,omitempty"`
	CollectionInitialStates map[string]string `json:"collection_initial_states,omitempty"`
	CollectionOffsets       map[string]int    `json:"collection_offsets,omitempty"`
	PolicyKey               string            `json:"policy_key,omitempty"`
	PendingPolicyKey        string            `json:"pending_policy_key,omitempty"`
	WipePending             bool              `json:"wipe_pending,omitempty"`
	WipeRequestedAt         time.Time         `json:"wipe_requested_at,omitzero"`
	WipeAcknowledgedAt      time.Time         `json:"wipe_acknowledged_at,omitzero"`
	// PreviousFolderKey and PreviousFolderState let a client that lost a
	// FolderSync response retry with the key it still holds.
	PreviousFolderKey   string `json:"previous_folder_key,omitempty"`
	PreviousFolderState string `json:"previous_folder_state,omitempty"`
	// PreviousFolderEchoes are the folder echoes the previous key saw.
	PreviousFolderEchoes []string `json:"previous_folder_echoes,omitempty"`
	FolderEchoes         []string `json:"folder_echoes,omitempty"`
	// CollectionOptions persist each collection's Sync options: clients send
	// them once and omit them from later requests.
	CollectionOptions map[string]SyncOptions `json:"collection_options,omitempty"`
	// PreviousCollections snapshot the state each collection's previous
	// SyncKey referred to, so a retried request is replayed, not reset.
	PreviousCollections map[string]CollectionSnapshot `json:"previous_collections,omitempty"`
	// CollectionClientIDs maps the ClientIds of the last request's Adds to
	// their ServerIds, so a retried Add is not created twice.
	CollectionClientIDs map[string]map[string]string `json:"collection_client_ids,omitempty"`
	// CollectionEchoes are items the device itself changed; their journal
	// entries are not sent back to it.
	CollectionEchoes map[string][]Echo `json:"collection_echoes,omitempty"`
	// SyncRequest caches the last full Sync request for empty requests.
	SyncRequest   []byte   `json:"sync_request,omitempty"`
	PingFolders   []string `json:"ping_folders,omitempty"`
	PingHeartbeat int      `json:"ping_heartbeat,omitempty"`
	// SentClientIDs are recent SendMail ClientIds, newest last.
	SentClientIDs []string `json:"sent_client_ids,omitempty"`
	// CollectionCursors position the initial enumeration of collections.
	CollectionCursors map[string]EnumerationCursor `json:"collection_cursors,omitempty"`
	// pendingCursor carries the enumeration position of the current window
	// until the window is committed.
	pendingCursor string
	UserAgent     string    `json:"user_agent,omitempty"`
	Model         string    `json:"model,omitempty"`
	FriendlyName  string    `json:"friendly_name,omitempty"`
	OS            string    `json:"os,omitempty"`
	OSLanguage    string    `json:"os_language,omitempty"`
	LastCommand   string    `json:"last_command,omitempty"`
	FirstSeenAt   time.Time `json:"first_seen_at,omitzero"`
	LastSeenAt    time.Time `json:"last_seen_at,omitzero"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CollectionSnapshot is the synchronization position one SyncKey names.
type CollectionSnapshot struct {
	Key          string            `json:"key"`
	State        string            `json:"state,omitempty"`
	InitialState string            `json:"initial_state,omitempty"`
	Initial      bool              `json:"initial,omitempty"`
	Offset       int               `json:"offset,omitempty"`
	Cursor       EnumerationCursor `json:"cursor,omitzero"`
	// Echoes are the collection's echoes when the key was issued: a
	// replayed request must suppress the same own changes again.
	Echoes []Echo `json:"echoes,omitempty"`
}

// EnumerationCursor is the last item ID sent by an initial enumeration and
// when the enumeration began.
type EnumerationCursor struct {
	After     string    `json:"after,omitempty"`
	StartedAt time.Time `json:"started_at,omitzero"`
}

func (s *DeviceState) snapshot(folderID string) CollectionSnapshot {
	initialState, initial := s.CollectionInitialStates[folderID]
	return CollectionSnapshot{
		Key: s.CollectionKeys[folderID], State: s.CollectionStates[folderID],
		InitialState: initialState, Initial: initial, Offset: s.CollectionOffsets[folderID],
		Cursor: s.CollectionCursors[folderID], Echoes: slices.Clone(s.CollectionEchoes[folderID]),
	}
}

func (s *DeviceState) restore(folderID string, snapshot CollectionSnapshot) {
	s.CollectionKeys[folderID] = snapshot.Key
	// Merge rather than replace: the echoes added by the lost request are
	// still the device's own changes, and the newer echo of an item wins.
	if len(snapshot.Echoes) > 0 {
		current := s.CollectionEchoes[folderID]
		known := newEchoSet(current)
		merged := make([]Echo, 0, len(snapshot.Echoes)+len(current))
		for _, echo := range snapshot.Echoes {
			if _, ok := known[echo.ID]; !ok {
				merged = append(merged, echo)
			}
		}
		merged = append(merged, current...)
		if excess := len(merged) - maxEchoes; excess > 0 {
			merged = merged[excess:]
		}
		s.CollectionEchoes[folderID] = merged
	}
	if snapshot.State != "" {
		s.CollectionStates[folderID] = snapshot.State
	} else {
		delete(s.CollectionStates, folderID)
	}
	if snapshot.Initial {
		s.CollectionInitialStates[folderID] = snapshot.InitialState
		s.CollectionOffsets[folderID] = snapshot.Offset
		s.setCursor(folderID, snapshot.Cursor.After, snapshot.Cursor.StartedAt)
	} else {
		delete(s.CollectionInitialStates, folderID)
		delete(s.CollectionOffsets, folderID)
		delete(s.CollectionCursors, folderID)
	}
}

// resetCollection forgets everything known about one collection.
func (s *DeviceState) resetCollection(folderID string) {
	delete(s.CollectionKeys, folderID)
	delete(s.CollectionStates, folderID)
	delete(s.CollectionInitialStates, folderID)
	delete(s.CollectionOffsets, folderID)
	delete(s.PreviousCollections, folderID)
	delete(s.CollectionClientIDs, folderID)
	delete(s.CollectionEchoes, folderID)
	delete(s.CollectionCursors, folderID)
}

// RequestWipe marks one existing partnership for remote wipe. The device is
// refused every command except Provision until it acknowledges the wipe.
func (s *StateStore) RequestWipe(ctx context.Context, userID, deviceID string) (bool, error) {
	unlock := s.lockDevice(userID, deviceID)
	defer unlock()
	if _, err := s.backend.Get(ctx, stateNamespace, userID+"/"+deviceID); errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	state, err := s.load(ctx, userID, deviceID)
	if err != nil {
		return false, err
	}
	state.WipePending = true
	state.WipeRequestedAt = time.Now().UTC()
	state.WipeAcknowledgedAt = time.Time{}
	return true, s.save(ctx, state)
}

type StateStore struct {
	backend store.Store
	locksMu sync.Mutex
	locks   map[string]*deviceStateLock
}

type deviceStateLock struct {
	mu   sync.Mutex
	refs int
}

func NewStateStore(ctx context.Context, backend store.Store) (*StateStore, error) {
	if backend == nil {
		return nil, errors.New("EAS state store is required")
	}
	exists, err := backend.NamespaceExists(ctx, stateNamespace)
	if err != nil {
		return nil, fmt.Errorf("check EAS state namespace: %w", err)
	}
	if !exists {
		if err := backend.CreateNamespace(ctx, stateNamespace); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("create EAS state namespace: %w", err)
		}
	}
	return &StateStore{backend: backend}, nil
}

func (s *StateStore) Load(ctx context.Context, userID, deviceID string) (DeviceState, error) {
	unlock := s.lockDevice(userID, deviceID)
	defer unlock()
	return s.load(ctx, userID, deviceID)
}

func (s *StateStore) load(ctx context.Context, userID, deviceID string) (DeviceState, error) {
	key := userID + "/" + deviceID
	data, err := s.backend.Get(ctx, stateNamespace, key)
	if errors.Is(err, store.ErrNotFound) {
		return newDeviceState(userID, deviceID), nil
	}
	if err != nil {
		return DeviceState{}, err
	}
	var state DeviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return DeviceState{}, fmt.Errorf("decode EAS device state: %w", err)
	}
	state.initializeMaps()
	if state.LastSeenAt.IsZero() {
		state.LastSeenAt = state.UpdatedAt
	}
	if state.FirstSeenAt.IsZero() {
		state.FirstSeenAt = state.LastSeenAt
	}
	return state, nil
}

func newDeviceState(userID, deviceID string) DeviceState {
	state := DeviceState{UserID: userID, DeviceID: deviceID}
	state.initializeMaps()
	return state
}

func (s *DeviceState) initializeMaps() {
	if s.CollectionKeys == nil {
		s.CollectionKeys = map[string]string{}
	}
	if s.CollectionStates == nil {
		s.CollectionStates = map[string]string{}
	}
	if s.CollectionInitialStates == nil {
		s.CollectionInitialStates = map[string]string{}
	}
	if s.CollectionOffsets == nil {
		s.CollectionOffsets = map[string]int{}
	}
	if s.CollectionOptions == nil {
		s.CollectionOptions = map[string]SyncOptions{}
	}
	if s.PreviousCollections == nil {
		s.PreviousCollections = map[string]CollectionSnapshot{}
	}
	if s.CollectionClientIDs == nil {
		s.CollectionClientIDs = map[string]map[string]string{}
	}
	if s.CollectionEchoes == nil {
		s.CollectionEchoes = map[string][]Echo{}
	}
}

func (s *StateStore) Save(ctx context.Context, state DeviceState) error {
	unlock := s.lockDevice(state.UserID, state.DeviceID)
	defer unlock()
	return s.save(ctx, state)
}

func (s *StateStore) save(ctx context.Context, state DeviceState) error {
	state.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, stateNamespace, state.UserID+"/"+state.DeviceID, data)
}

// Update serializes the complete request state transition for one partnership.
// EAS clients expect commands for one device partnership to be ordered, and
// keeping load/mutate/save under the same striped lock also prevents a
// concurrent removal from being undone by an older in-flight request.
func (s *StateStore) Update(ctx context.Context, userID, deviceID string, mutate func(*DeviceState) error) error {
	unlock := s.lockDevice(userID, deviceID)
	defer unlock()
	state, err := s.load(ctx, userID, deviceID)
	if err != nil {
		return err
	}
	if err := mutate(&state); err != nil {
		return err
	}
	return s.save(ctx, state)
}

// List returns only the partnerships owned by userID. Synchronization keys and
// collection state remain internal fields and are filtered by the web adapter.
func (s *StateStore) List(ctx context.Context, userID string) ([]DeviceState, error) {
	prefix := userID + "/"
	states := make([]DeviceState, 0)
	err := s.backend.Iterate(ctx, stateNamespace, prefix, func(_ string, data []byte) (bool, error) {
		var state DeviceState
		if err := json.Unmarshal(data, &state); err != nil {
			return false, fmt.Errorf("decode EAS device state: %w", err)
		}
		if state.UserID != userID || strings.TrimSpace(state.DeviceID) == "" {
			return true, nil
		}
		if state.LastSeenAt.IsZero() {
			state.LastSeenAt = state.UpdatedAt
		}
		if state.FirstSeenAt.IsZero() {
			state.FirstSeenAt = state.LastSeenAt
		}
		states = append(states, state)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].LastSeenAt.Equal(states[j].LastSeenAt) {
			return states[i].DeviceID < states[j].DeviceID
		}
		return states[i].LastSeenAt.After(states[j].LastSeenAt)
	})
	return states, nil
}

// Remove deletes one exact partnership and is idempotent. A later request from
// the same physical client creates fresh synchronization state.
func (s *StateStore) Remove(ctx context.Context, userID, deviceID string) (bool, error) {
	unlock := s.lockDevice(userID, deviceID)
	defer unlock()
	if state, err := s.load(ctx, userID, deviceID); err == nil && state.WipePending && state.WipeAcknowledgedAt.IsZero() {
		// A wipe the device has not confirmed survives removal: otherwise a
		// stolen device that had not yet connected would start afresh.
		fresh := newDeviceState(userID, deviceID)
		fresh.DeviceType, fresh.WipePending, fresh.WipeRequestedAt = state.DeviceType, true, state.WipeRequestedAt
		fresh.FirstSeenAt, fresh.LastSeenAt = state.FirstSeenAt, state.LastSeenAt
		return true, s.save(ctx, fresh)
	}
	err := s.backend.Delete(ctx, stateNamespace, userID+"/"+deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *StateStore) lockDevice(userID, deviceID string) func() {
	key := userID + "\x00" + deviceID
	s.locksMu.Lock()
	if s.locks == nil {
		s.locks = make(map[string]*deviceStateLock)
	}
	lock := s.locks[key]
	if lock == nil {
		lock = &deviceStateLock{}
		s.locks[key] = lock
	}
	lock.refs++
	s.locksMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.locksMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(s.locks, key)
		}
		s.locksMu.Unlock()
	}
}

func nextKey() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
