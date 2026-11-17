// Package eas provides an Exchange ActiveSync migration source.
package eas

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	protocol "github.com/lkarlslund/veksel/pkg/eas"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
)

type Config struct {
	Endpoint   string
	Username   string
	Password   string
	DeviceID   string
	DeviceType string
	HTTPClient *http.Client
	TLSConfig  *tls.Config
	Version    string
	// RequestTimeout is used by the default HTTP client. Exchange can take
	// several minutes to prepare large initial calendar collections.
	RequestTimeout time.Duration
	MaxAttempts    int
	RetryBackoff   time.Duration
}

type Source struct {
	endpoint     string
	username     string
	password     string
	deviceID     string
	deviceType   string
	version      string
	client       *http.Client
	folderKey    string
	maxAttempts  int
	retryBackoff time.Duration
	windowMu     sync.Mutex
	folderWindow map[string]int
	responseMax  int64
}

const easCheckpointPrefix = "eas1:"
const defaultSyncWindow = 100
const maxEASResponseBytes = 64 << 20
const maxTrailingEndClosures = 256

var errEASResponseTooLarge = errors.New("EAS response exceeds the bounded decode size")

type responseFailureKind string

const (
	responseFailureTransport responseFailureKind = "transport_short_read"
	responseFailureMalformed responseFailureKind = "malformed_wbxml"
	responseFailureOversize  responseFailureKind = "response_too_large"
)

// responseFailure retains enough in-memory evidence to classify and, only at
// Sync window one, safely inspect a structurally incomplete page. Error output
// contains only bounded metadata and a body hash; source content is never
// persisted or logged.
type responseFailure struct {
	kind          responseFailureKind
	command       string
	data          []byte
	bytes         int
	contentLength int64
	hash          string
	err           error
}

func newResponseFailure(kind responseFailureKind, command string, data []byte, contentLength int64, err error) *responseFailure {
	digest := sha256.Sum256(data)
	failure := &responseFailure{
		kind: kind, command: command, bytes: len(data), contentLength: contentLength,
		hash: hex.EncodeToString(digest[:8]), err: err,
	}
	if kind == responseFailureMalformed {
		failure.data = append([]byte(nil), data...)
	}
	return failure
}

func (e *responseFailure) Error() string {
	length := "unknown"
	if e.contentLength >= 0 {
		length = strconv.FormatInt(e.contentLength, 10)
	}
	return fmt.Sprintf("EAS %s response failure kind=%s bytes=%d content_length=%s sha256=%s: %v", e.command, e.kind, e.bytes, length, e.hash, e.err)
}

func (e *responseFailure) Unwrap() error { return e.err }

type easCheckpoint struct {
	Version                int    `json:"version"`
	Key                    string `json:"key"`
	InitialCoveragePending bool   `json:"initial_coverage_pending,omitempty"`
	InitialItemsSeen       bool   `json:"initial_items_seen,omitempty"`
	InitialEmptyResponses  uint8  `json:"initial_empty_responses,omitempty"`
}

func decodeCheckpoint(value string, folderType model.FolderType) (state easCheckpoint, initialRequest bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return easCheckpoint{Version: 1, Key: "0", InitialCoveragePending: true}, true, nil
	}
	if !strings.HasPrefix(value, easCheckpointPrefix) {
		// Older Veksel versions stored only Exchange's opaque key. They could
		// persist the priming key as if it proved initial coverage. Re-prime
		// legacy calendars once; large mail collections retain their key.
		if folderType == model.FolderTypeCalendar {
			return easCheckpoint{Version: 1, Key: "0", InitialCoveragePending: true}, true, nil
		}
		return easCheckpoint{Version: 1, Key: value}, false, nil
	}
	encoded := strings.TrimPrefix(value, easCheckpointPrefix)
	payload, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
	if decodeErr != nil || json.Unmarshal(payload, &state) != nil || state.Version != 1 || state.Key == "" || len(state.Key) > 64 {
		return easCheckpoint{}, false, errors.New("invalid EAS checkpoint")
	}
	return state, state.Key == "0", nil
}

func encodeCheckpoint(state easCheckpoint) (string, error) {
	if state.Version != 1 || state.Key == "" || len(state.Key) > 64 {
		return "", errors.New("invalid EAS checkpoint state")
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return easCheckpointPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func New(cfg Config) (*Source, error) {
	endpoint, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, errors.New("valid EAS endpoint is required")
	}
	if cfg.Username == "" {
		return nil, errors.New("EAS username is required")
	}
	if cfg.DeviceID == "" {
		var deviceID [16]byte
		if _, err := rand.Read(deviceID[:]); err != nil {
			return nil, fmt.Errorf("generate EAS device ID: %w", err)
		}
		cfg.DeviceID = strings.ToUpper(hex.EncodeToString(deviceID[:]))
	}
	if cfg.DeviceType == "" {
		cfg.DeviceType = "VekselMigration"
	}
	if cfg.Version == "" {
		cfg.Version = "16.1"
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 5 * time.Minute
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = cfg.TLSConfig
		client = &http.Client{Transport: transport, Timeout: cfg.RequestTimeout}
	}
	return &Source{
		endpoint: endpoint.String(), username: cfg.Username, password: cfg.Password,
		deviceID: cfg.DeviceID, deviceType: cfg.DeviceType, version: cfg.Version,
		client: client, maxAttempts: cfg.MaxAttempts, retryBackoff: cfg.RetryBackoff,
		folderWindow: make(map[string]int), responseMax: maxEASResponseBytes,
	}, nil
}

func (s *Source) ID() string {
	return "eas://" + s.username + "@" + strings.TrimPrefix(strings.TrimPrefix(s.endpoint, "https://"), "http://")
}
func (s *Source) Close() error { return nil }

// FolderConcurrency is deliberately one. Exchange caches Sync request state
// per device partnership, so overlapping collection requests under one
// DeviceId corrupt that cache and cause global retry-later responses. EAS
// throughput must be raised with a batched multi-collection Sync command, not
// concurrent single-collection commands.
func (s *Source) FolderConcurrency() int { return 1 }

func (s *Source) Folders(ctx context.Context) ([]migration.Folder, error) {
	response, err := s.call(ctx, "FolderSync", protocol.E(7, "FolderSync", protocol.T(7, "SyncKey", "0")))
	if err != nil {
		return nil, err
	}
	if status := nodeText(response, "Status"); status != "1" {
		return nil, fmt.Errorf("EAS FolderSync status %s", status)
	}
	s.folderKey = nodeText(response, "SyncKey")
	changes := response.Descendant("Changes")
	if changes == nil {
		return nil, nil
	}
	result := make([]migration.Folder, 0, len(changes.Children))
	for _, change := range changes.Children {
		if change.Tag != "Add" && change.Tag != "Update" {
			continue
		}
		parent := nodeText(change, "ParentId")
		if parent == "0" {
			parent = ""
		}
		folder := migration.Folder{
			ID: nodeText(change, "ServerId"), ParentID: parent, Name: nodeText(change, "DisplayName"), Type: folderType(nodeText(change, "Type")),
		}
		folder.Special = specialUse(nodeText(change, "Type"))
		result = append(result, folder)
	}
	return result, nil
}

func (s *Source) Inventory(ctx context.Context) ([]migration.Folder, error) {
	folders, err := s.Folders(ctx)
	if err != nil || len(folders) == 0 {
		return folders, err
	}

	initialCollections := make([]*protocol.Node, 0, len(folders))
	for _, folder := range folders {
		initialCollections = append(initialCollections, protocol.E(0, "Collection",
			protocol.T(0, "SyncKey", "0"), protocol.T(0, "CollectionId", folder.ID),
		))
	}
	response, err := s.call(ctx, "Sync", protocol.E(0, "Sync", protocol.E(0, "Collections", initialCollections...)))
	if err != nil {
		return nil, fmt.Errorf("initialize EAS inventory: %w", err)
	}
	keys := make(map[string]string, len(folders))
	if collections := response.Descendant("Collections"); collections != nil {
		for _, collection := range collections.ChildrenNamed("Collection") {
			if status := nodeText(collection, "Status"); status != "" && status != "1" {
				continue
			}
			id, key := nodeText(collection, "CollectionId"), nodeText(collection, "SyncKey")
			if id != "" && key != "" && key != "0" {
				keys[id] = key
			}
		}
	}

	estimateCollections := make([]*protocol.Node, 0, len(keys))
	for _, folder := range folders {
		if key := keys[folder.ID]; key != "" {
			estimateCollections = append(estimateCollections, protocol.E(6, "Collection",
				protocol.T(0, "SyncKey", key), protocol.T(6, "CollectionId", folder.ID),
			))
		}
	}
	if len(estimateCollections) == 0 {
		return folders, nil
	}
	estimates, err := s.call(ctx, "GetItemEstimate", protocol.E(6, "GetItemEstimate", protocol.E(6, "Collections", estimateCollections...)))
	if err != nil {
		return nil, fmt.Errorf("estimate EAS inventory: %w", err)
	}
	byID := itemEstimates(estimates)
	for index := range folders {
		if estimate, ok := byID[folders[index].ID]; ok {
			folders[index].Estimate = estimate
			folders[index].EstimateKnown = true
		}
	}
	return folders, nil
}

func itemEstimates(root *protocol.Node) map[string]int64 {
	result := make(map[string]int64)
	var visit func(*protocol.Node)
	visit = func(node *protocol.Node) {
		if node == nil {
			return
		}
		if node.Tag == "Collection" {
			value, err := strconv.ParseInt(nodeText(node, "Estimate"), 10, 64)
			if id := nodeText(node, "CollectionId"); id != "" && err == nil && value >= 0 {
				result[id] = value
			}
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(root)
	return result
}

func (s *Source) Items(ctx context.Context, folder migration.Folder, checkpoint string) (migration.Page, error) {
	return s.items(ctx, folder, checkpoint, true)
}

func (s *Source) items(ctx context.Context, folder migration.Folder, checkpoint string, refreshHierarchy bool) (migration.Page, error) {
	state, initialRequest, err := decodeCheckpoint(checkpoint, folder.Type)
	if err != nil {
		return migration.Page{}, err
	}
	initialCoveragePending := state.InitialCoveragePending
	var response *protocol.Node
	var itemFailures []migration.ItemFailure
	recoveredMalformedItem := false
	for {
		collectionChildren := []*protocol.Node{
			protocol.T(0, "SyncKey", state.Key),
			protocol.T(0, "CollectionId", folder.ID),
		}
		if !initialRequest {
			collectionChildren = append(collectionChildren,
				protocol.T(0, "GetChanges", "1"),
				protocol.T(0, "WindowSize", strconv.Itoa(s.syncWindow(folder.ID))),
				syncOptions(folder),
			)
		}
		request := protocol.E(0, "Sync", protocol.E(0, "Collections", protocol.E(0, "Collection", collectionChildren...)))
		response, err = s.call(ctx, "Sync", request)
		if err == nil {
			break
		}
		if initialRequest || !windowReducibleResponseError(err) {
			return migration.Page{}, err
		}
		if !s.reduceSyncWindow(folder.ID) {
			recovered, failure, ok, rejection := recoverMinimumWindowResponse(err)
			if ok {
				response = recovered
				itemFailures = []migration.ItemFailure{failure}
				recoveredMalformedItem = true
				break
			}
			return migration.Page{}, fmt.Errorf("EAS response remains truncated at minimum Sync window 1; safe structural recovery rejected (%s): %w", rejection, err)
		}
	}
	if response == nil {
		if initialRequest {
			return migration.Page{}, errors.New("EAS initial Sync returned no synchronization key")
		}
		if !initialCoveragePending {
			return migration.Page{Checkpoint: checkpoint, Done: true}, nil
		}
		// Exchange uses an empty WBXML response for a collection with no pending
		// changes. During initial coverage, require that result twice and persist
		// the observation between requests. This prevents a transient empty HTTP
		// response or interrupted priming exchange from becoming durable proof
		// that a non-empty source calendar contained zero objects.
		state.InitialEmptyResponses++
		confirmedEmpty := state.InitialItemsSeen || state.InitialEmptyResponses >= 2
		if confirmedEmpty {
			state.InitialCoveragePending = false
		}
		encodedCheckpoint, encodeErr := encodeCheckpoint(state)
		if encodeErr != nil {
			return migration.Page{}, encodeErr
		}
		return migration.Page{Checkpoint: encodedCheckpoint, Done: confirmedEmpty, InitialCoverageComplete: confirmedEmpty && initialCoveragePending, SourceExplicitlyEmpty: confirmedEmpty && initialCoveragePending && !state.InitialItemsSeen}, nil
	}
	if statusNode := response.Child("Status"); statusNode != nil && statusNode.Text != "" && statusNode.Text != "1" {
		if statusNode.Text == "12" && refreshHierarchy {
			if _, err := s.Folders(ctx); err != nil {
				return migration.Page{}, fmt.Errorf("refresh EAS folder hierarchy: %w", err)
			}
			return s.items(ctx, folder, checkpoint, false)
		}
		return migration.Page{}, syncStatusError("global", statusNode.Text)
	}
	collection := response.Descendant("Collection")
	if collection == nil {
		if state.InitialCoveragePending {
			return migration.Page{}, errors.New("EAS initial Sync response has no collection")
		}
		return migration.Page{Checkpoint: checkpoint, Done: true}, nil
	}
	if status := nodeText(collection, "Status"); status != "" && status != "1" {
		if status == "12" && refreshHierarchy {
			if _, err := s.Folders(ctx); err != nil {
				return migration.Page{}, fmt.Errorf("refresh EAS folder hierarchy: %w", err)
			}
			return s.items(ctx, folder, checkpoint, false)
		}
		return migration.Page{}, syncStatusError("collection", status)
	}
	nextKey := nodeText(collection, "SyncKey")
	if nextKey == "" {
		nextKey = state.Key
	}
	if initialRequest && nextKey == "0" {
		return migration.Page{}, errors.New("EAS initial Sync returned an invalid synchronization key")
	}
	commands := collection.Child("Commands")
	items := make([]migration.Item, 0)
	deletedIDs := make([]string, 0)
	if commands != nil {
		for _, command := range commands.Children {
			if command.Tag == "Delete" || command.Tag == "SoftDelete" {
				if serverID := nodeText(command, "ServerId"); serverID != "" {
					deletedIDs = append(deletedIDs, serverID)
				}
				continue
			}
			if command.Tag != "Add" && command.Tag != "Change" {
				continue
			}
			serverID := nodeText(command, "ServerId")
			if len(itemFailures) == 1 && itemFailures[0].ID == serverID {
				continue
			}
			applicationData := command.Child("ApplicationData")
			if applicationData == nil {
				continue
			}
			data, headers := itemContent(folder.Type, serverID, applicationData)
			flags := []string{}
			if nodeText(applicationData, "Read") == "1" {
				flags = append(flags, model.FlagSeen)
			}
			items = append(items, migration.Item{ID: serverID, Version: nextKey, Data: data, Headers: headers, Flags: flags, InternalDate: parseDate(nodeText(applicationData, "DateReceived"))})
		}
	}
	// The malformed stream ended inside its final item, before Exchange could
	// emit any collection-level MoreAvailable marker. Always follow the supplied
	// key once more; that prevents a repaired suffix from declaring incomplete
	// initial coverage complete or skipping later changes.
	moreAvailable := recoveredMalformedItem || collection.Child("MoreAvailable") != nil
	state.InitialEmptyResponses = 0
	initialCoverageComplete := !initialRequest && initialCoveragePending && !moreAvailable
	if initialCoveragePending && (len(items) > 0 || len(deletedIDs) > 0 || len(itemFailures) > 0) {
		state.InitialItemsSeen = true
	}
	if initialRequest || moreAvailable {
		state.InitialCoveragePending = true
	} else {
		state.InitialCoveragePending = false
	}
	state.Key = nextKey
	encodedCheckpoint, err := encodeCheckpoint(state)
	if err != nil {
		return migration.Page{}, err
	}
	// A SyncKey of zero only primes the synchronization relationship. Initial
	// coverage remains pending across every MoreAvailable page and restart.
	done := !state.InitialCoveragePending
	return migration.Page{Items: items, DeletedIDs: deletedIDs, ItemFailures: itemFailures, Checkpoint: encodedCheckpoint, Done: done, InitialCoverageComplete: initialCoverageComplete}, nil
}

func recoverMinimumWindowResponse(err error) (*protocol.Node, migration.ItemFailure, bool, string) {
	var responseErr *responseFailure
	var suffixErr *protocol.MissingTrailingEndError
	if !errors.As(err, &responseErr) || responseErr.kind != responseFailureMalformed || !errors.As(err, &suffixErr) {
		return nil, migration.ItemFailure{}, false, "not a complete malformed WBXML structural suffix"
	}
	var root *protocol.Node
	recoveryMode := "application_data_prefix"
	if suffixErr.Depth > 0 && suffixErr.Depth <= maxTrailingEndClosures {
		// The typed decoder depth gives the exact count; append only structural
		// END tokens once instead of repeatedly reparsing the source body.
		repaired := append(append([]byte(nil), responseErr.data...), bytes.Repeat([]byte{0x01}, suffixErr.Depth)...)
		root, _ = protocol.Decode(repaired)
		if root != nil {
			recoveryMode = "end_suffix"
		}
	}
	if root == nil {
		// An implausibly deep suffix means malformed bytes inside ApplicationData
		// are being interpreted as WBXML nodes. Parse only the valid envelope up
		// to that boundary; never interpret or manufacture the item's fields.
		var prefixErr error
		root, prefixErr = protocol.DecodePrefix(responseErr.data, 0, "ApplicationData")
		if prefixErr != nil || root == nil {
			return nil, migration.ItemFailure{}, false, fmt.Sprintf("application-data envelope projection failed at open depth %d: %T", suffixErr.Depth, prefixErr)
		}
	}
	collection := root.Descendant("Collection")
	if collection == nil {
		return nil, migration.ItemFailure{}, false, "repaired document has no Collection"
	}
	commands := collection.Child("Commands")
	if commands == nil || len(commands.Children) == 0 {
		return nil, migration.ItemFailure{}, false, "repaired Collection has no command children"
	}
	command := commands.Children[len(commands.Children)-1]
	if command.Tag != "Add" && command.Tag != "Change" {
		return nil, migration.ItemFailure{}, false, fmt.Sprintf("final command is %s across %d command(s)", command.Tag, len(commands.Children))
	}
	if recoveryMode == "end_suffix" {
		rightmost := command
		for len(rightmost.Children) > 0 {
			rightmost = rightmost.Children[len(rightmost.Children)-1]
		}
		if rightmost.Page != suffixErr.Page || rightmost.Tag != suffixErr.Tag {
			return nil, migration.ItemFailure{}, false, fmt.Sprintf("final command leaf is page %d tag %s, suffix ended at page %d tag %s", rightmost.Page, rightmost.Tag, suffixErr.Page, suffixErr.Tag)
		}
	} else if applicationData := command.Child("ApplicationData"); applicationData == nil || len(applicationData.Children) != 0 || applicationData.Text != "" || applicationData.Opaque != nil {
		return nil, migration.ItemFailure{}, false, "envelope projection did not stop at an empty ApplicationData boundary"
	}
	serverID := nodeText(command, "ServerId")
	nextKey := nodeText(collection, "SyncKey")
	if serverID == "" || nextKey == "" || nextKey == "0" {
		return nil, migration.ItemFailure{}, false, fmt.Sprintf("identity presence server_id=%t sync_key=%t nonzero_sync_key=%t", serverID != "", nextKey != "", nextKey != "0")
	}
	// END repair proves the final leaf; prefix projection proves the envelope up
	// to (but not into) ApplicationData. WindowSize=1 bounds changed item output,
	// and the caller forces another request from the supplied key before claiming
	// the collection was fully traversed.
	diagnostic := fmt.Sprintf("source item skipped after a window-one WBXML structural suffix failure repaired with %d END token(s) (%s)", suffixErr.Depth, responseErr.Error())
	if recoveryMode == "application_data_prefix" {
		diagnostic = fmt.Sprintf("source item skipped from a structurally parsed WBXML envelope without reading malformed ApplicationData; open_depth=%d (%s)", suffixErr.Depth, responseErr.Error())
	}
	return root, migration.ItemFailure{
		ID:    serverID,
		Error: diagnostic,
	}, true, ""
}

func windowReducibleResponseError(err error) bool {
	var responseErr *responseFailure
	if errors.As(err, &responseErr) {
		return responseErr.kind == responseFailureOversize || responseErr.kind == responseFailureMalformed
	}
	return errors.Is(err, errEASResponseTooLarge) || errors.Is(err, protocol.ErrMissingTrailingEnd)
}

func (s *Source) syncWindow(folderID string) int {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	if window := s.folderWindow[folderID]; window > 0 {
		return window
	}
	return defaultSyncWindow
}

func (s *Source) reduceSyncWindow(folderID string) bool {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	window := s.folderWindow[folderID]
	if window <= 0 {
		window = defaultSyncWindow
	}
	if window <= 1 {
		return false
	}
	s.folderWindow[folderID] = max(1, window/2)
	return true
}

func syncOptions(folder migration.Folder) *protocol.Node {
	if folder.ID == "RI" {
		// CollectionId RI is Exchange's recipient information cache, not an
		// ordinary contacts folder. Its Options block has dedicated semantics:
		// MaxItems selects the most frequently used recipients to retain. Sending
		// the generic contact BodyPreference makes real Exchange reject the whole
		// Sync request with protocol status 4.
		return protocol.E(0, "Options", protocol.T(0, "MaxItems", "1000"))
	}
	folderType := folder.Type
	children := []*protocol.Node{protocol.T(0, "FilterType", "0")}
	if folderType == model.FolderTypeMail {
		// MIME is an email representation. Requesting it for PIM collections is
		// semantically wrong and makes Exchange perform unnecessary MIME work for
		// every calendar or contact object.
		children = append(children,
			protocol.T(0, "MIMESupport", "2"),
			protocol.E(17, "BodyPreference", protocol.T(17, "Type", "4")),
		)
	} else {
		children = append(children, protocol.E(17, "BodyPreference", protocol.T(17, "Type", "1")))
	}
	return protocol.E(0, "Options", children...)
}

func syncStatusError(scope, status string) error {
	err := fmt.Errorf("EAS Sync %s status %s", scope, status)
	// Status 5 is a server error, 16 instructs the client to retry, and common
	// status 111 is ServerErrorRetryLater. They indicate transient source
	// pressure; protocol, key, and folder errors do not become pressure merely
	// because they make one collection unusable.
	if status == "5" || status == "16" || status == "111" {
		return migration.MarkSourcePressure(err)
	}
	return err
}

func itemContent(folderType model.FolderType, serverID string, applicationData *protocol.Node) ([]byte, map[string]string) {
	switch folderType {
	case model.FolderTypeContacts:
		return contactContent(serverID, applicationData)
	case model.FolderTypeCalendar:
		return calendarContent(serverID, applicationData)
	default:
		data := nodeBytes(applicationData.Descendant("Data"))
		headers := map[string]string{
			"Subject": nodeText(applicationData, "Subject"), "From": nodeText(applicationData, "From"), "To": nodeText(applicationData, "To"), "Cc": nodeText(applicationData, "Cc"),
		}
		if !looksLikeMIME(data) {
			data = makeMIME(headers, data)
		}
		return data, headers
	}
}

func contactContent(serverID string, data *protocol.Node) ([]byte, map[string]string) {
	contact := model.Contact{
		UID: serverID, FN: nodeText(data, "FileAs"), Prefix: nodeText(data, "Title"), GivenName: nodeText(data, "FirstName"),
		MiddleName: nodeText(data, "MiddleName"), FamilyName: nodeText(data, "LastName"), Suffix: nodeText(data, "Suffix"),
		Nickname: nodeText(data, "NickName"), Org: nodeText(data, "CompanyName"), Department: nodeText(data, "Department"),
		Title: nodeText(data, "JobTitle"), Birthday: dateOnly(nodeText(data, "Birthday")), URL: nodeText(data, "WebPage"),
		Note: nodeText(data, "Data"), Categories: nodeTexts(data, "Category"),
	}
	if contact.FN == "" {
		contact.FN = strings.TrimSpace(strings.Join([]string{contact.GivenName, contact.MiddleName, contact.FamilyName}, " "))
	}
	if contact.FN == "" {
		contact.FN = "Unnamed contact"
	}
	for _, tag := range []string{"Email1Address", "Email2Address", "Email3Address"} {
		if value := nodeText(data, tag); value != "" {
			contact.Emails = append(contact.Emails, value)
		}
	}
	for _, tag := range []string{"BusinessPhoneNumber", "Business2PhoneNumber", "HomePhoneNumber", "Home2PhoneNumber", "MobilePhoneNumber", "CarPhoneNumber", "AssistantPhoneNumber", "PagerNumber", "RadioPhoneNumber"} {
		if value := nodeText(data, tag); value != "" {
			contact.Phones = append(contact.Phones, value)
		}
	}
	for _, address := range []struct{ kind, prefix string }{{"work", "BusinessAddress"}, {"home", "HomeAddress"}, {"other", "OtherAddress"}} {
		value := model.ContactAddress{Type: address.kind, Street: nodeText(data, address.prefix+"Street"), Locality: nodeText(data, address.prefix+"City"), Region: nodeText(data, address.prefix+"State"), PostalCode: nodeText(data, address.prefix+"PostalCode"), Country: nodeText(data, address.prefix+"Country")}
		if value.Street != "" || value.Locality != "" || value.Region != "" || value.PostalCode != "" || value.Country != "" {
			contact.Addresses = append(contact.Addresses, value)
		}
	}
	if picture := nodeBytes(data.Descendant("Picture")); len(picture) > 0 {
		contact.PhotoData = picture
		if decoded, err := base64.StdEncoding.DecodeString(string(picture)); err == nil {
			contact.PhotoData = decoded
		}
		contact.PhotoType = "JPEG"
	}
	return model.ContactToVCard(contact), map[string]string{"UID": serverID, "FN": contact.FN}
}

func calendarContent(serverID string, data *protocol.Node) ([]byte, map[string]string) {
	uid := childText(data, "UID")
	if uid == "" {
		uid = serverID
	}
	summary := childText(data, "Subject")
	lines := []string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Veksel//EAS Sync//EN"}
	masterAllDay := childText(data, "AllDayEvent") == "1"
	lines = append(lines, easCalendarEvent(uid, data, "", masterAllDay)...)
	for _, exception := range calendarExceptions(data) {
		if childText(exception, "Deleted") == "1" {
			continue
		}
		recurrenceID := childText(exception, "ExceptionStartTime")
		if recurrenceID != "" {
			lines = append(lines, easCalendarEvent(uid, exception, recurrenceID, masterAllDay)...)
		}
	}
	lines = append(lines, "END:VCALENDAR", "")
	return []byte(strings.Join(lines, "\r\n")), map[string]string{"UID": uid, "SUMMARY": summary, "External-ID": serverID}
}

func easCalendarEvent(uid string, data *protocol.Node, recurrenceID string, inheritedAllDay bool) []string {
	allDay := inheritedAllDay
	if value := childText(data, "AllDayEvent"); value != "" {
		allDay = value == "1"
	}
	lines := []string{"BEGIN:VEVENT", "UID:" + escapeICal(uid)}
	if recurrenceID != "" {
		if value := icalDate(recurrenceID, allDay); value != "" {
			lines = append(lines, "RECURRENCE-ID"+value)
		}
	}
	for _, field := range []struct{ tag, property string }{{"DtStamp", "DTSTAMP"}, {"StartTime", "DTSTART"}, {"EndTime", "DTEND"}} {
		if value := icalDate(childText(data, field.tag), allDay); value != "" {
			lines = append(lines, field.property+value)
		}
	}
	if summary := childText(data, "Subject"); summary != "" {
		lines = append(lines, "SUMMARY:"+escapeICal(summary))
	}
	if location := calendarLocation(data); location != "" {
		lines = append(lines, "LOCATION:"+escapeICal(location))
	}
	if body := data.Child("Body"); body != nil {
		if description := nodeText(body, "Data"); description != "" {
			lines = append(lines, "DESCRIPTION:"+escapeICal(description))
		}
	}
	if categories := nodeTexts(data.Child("Categories"), "Category"); len(categories) > 0 {
		escaped := make([]string, 0, len(categories))
		for _, category := range categories {
			escaped = append(escaped, escapeICal(category))
		}
		lines = append(lines, "CATEGORIES:"+strings.Join(escaped, ","))
	}
	if organizer := childText(data, "OrganizerEmail"); organizer != "" {
		property := "ORGANIZER"
		if name := childText(data, "OrganizerName"); name != "" {
			property += ";CN=\"" + escapeICalParam(name) + "\""
		}
		lines = append(lines, property+":"+calendarAddress(organizer))
	}
	for _, attendee := range directChildren(data.Child("Attendees"), "Attendee") {
		email := nodeText(attendee, "Email")
		if email == "" {
			continue
		}
		property := "ATTENDEE"
		if name := nodeText(attendee, "Name"); name != "" {
			property += ";CN=\"" + escapeICalParam(name) + "\""
		}
		if partstat := easPartStat(nodeText(attendee, "AttendeeStatus")); partstat != "" {
			property += ";PARTSTAT=" + partstat
		}
		if role := easAttendeeRole(nodeText(attendee, "AttendeeType")); role != "" {
			property += ";ROLE=" + role
		}
		lines = append(lines, property+":"+calendarAddress(email))
	}
	if recurrence := data.Child("Recurrence"); recurrence != nil {
		if rule := easRecurrenceRule(recurrence); rule != "" {
			lines = append(lines, "RRULE:"+rule)
		}
	}
	var exdates []string
	for _, exception := range calendarExceptions(data) {
		if childText(exception, "Deleted") != "1" {
			continue
		}
		if value := icalDate(childText(exception, "ExceptionStartTime"), allDay); value != "" {
			exdates = append(exdates, strings.TrimPrefix(value, ":"))
		}
	}
	if len(exdates) > 0 {
		property := "EXDATE:"
		if allDay {
			property = "EXDATE;VALUE=DATE:"
			for index := range exdates {
				exdates[index] = strings.TrimPrefix(exdates[index], ";VALUE=DATE:")
			}
		}
		lines = append(lines, property+strings.Join(exdates, ","))
	}
	if timezone := nodeBytes(data.Child("TimeZone")); len(timezone) > 0 {
		lines = append(lines, "X-VEKSEL-EAS-TIMEZONE:"+base64.StdEncoding.EncodeToString(timezone))
	}
	if class := easSensitivity(childText(data, "Sensitivity")); class != "" {
		lines = append(lines, "CLASS:"+class)
	}
	if busy := childText(data, "BusyStatus"); busy != "" {
		if busy == "0" {
			lines = append(lines, "TRANSP:TRANSPARENT")
		} else {
			lines = append(lines, "TRANSP:OPAQUE")
		}
		lines = append(lines, "X-MICROSOFT-CDO-BUSYSTATUS:"+easBusyStatus(busy))
	}
	if meeting := childText(data, "MeetingStatus"); meeting != "" {
		lines = append(lines, "X-VEKSEL-EAS-MEETING-STATUS:"+escapeICal(meeting))
	}
	if reminder := positiveInt(childText(data, "Reminder")); reminder > 0 {
		lines = append(lines, "BEGIN:VALARM", "TRIGGER:-PT"+strconv.Itoa(reminder)+"M", "ACTION:DISPLAY", "DESCRIPTION:Reminder", "END:VALARM")
	}
	lines = append(lines, "END:VEVENT")
	return lines
}

func calendarLocation(data *protocol.Node) string {
	location := data.Child("Location")
	if location == nil {
		return ""
	}
	if location.Text != "" {
		return location.Text
	}
	return nodeText(location, "DisplayName")
}

func childText(root *protocol.Node, tag string) string {
	if root == nil {
		return ""
	}
	if child := root.Child(tag); child != nil {
		return child.Text
	}
	return ""
}

func calendarExceptions(data *protocol.Node) []*protocol.Node {
	return directChildren(data.Child("Exceptions"), "Exception")
}

func directChildren(root *protocol.Node, tag string) []*protocol.Node {
	if root == nil {
		return nil
	}
	return root.ChildrenNamed(tag)
}

func calendarAddress(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, ":") {
		return value
	}
	return "mailto:" + value
}

func escapeICalParam(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return strings.ReplaceAll(value, "\r", " ")
}

func easPartStat(value string) string {
	return map[string]string{"0": "NEEDS-ACTION", "2": "TENTATIVE", "3": "ACCEPTED", "4": "DECLINED", "5": "NEEDS-ACTION"}[value]
}

func easAttendeeRole(value string) string {
	return map[string]string{"1": "REQ-PARTICIPANT", "2": "OPT-PARTICIPANT", "3": "NON-PARTICIPANT"}[value]
}

func easSensitivity(value string) string {
	return map[string]string{"0": "PUBLIC", "1": "PERSONAL", "2": "PRIVATE", "3": "CONFIDENTIAL"}[value]
}

func easBusyStatus(value string) string {
	status := map[string]string{"0": "FREE", "1": "TENTATIVE", "2": "BUSY", "3": "OOF", "4": "WORKINGELSEWHERE"}[value]
	if status == "" {
		return value
	}
	return status
}

func positiveInt(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0
	}
	return parsed
}

func easRecurrenceRule(recurrence *protocol.Node) string {
	typeValue := nodeText(recurrence, "Type")
	parts := []string{}
	switch typeValue {
	case "0":
		parts = append(parts, "FREQ=DAILY")
	case "1":
		parts = append(parts, "FREQ=WEEKLY")
	case "2", "3":
		parts = append(parts, "FREQ=MONTHLY")
	case "5", "6":
		parts = append(parts, "FREQ=YEARLY")
	default:
		return ""
	}
	if interval := positiveInt(nodeText(recurrence, "Interval")); interval > 1 {
		parts = append(parts, "INTERVAL="+strconv.Itoa(interval))
	}
	if occurrences := positiveInt(nodeText(recurrence, "Occurrences")); occurrences > 0 {
		parts = append(parts, "COUNT="+strconv.Itoa(occurrences))
	} else if until := icalDate(nodeText(recurrence, "Until"), false); until != "" {
		parts = append(parts, "UNTIL="+strings.TrimPrefix(until, ":"))
	}
	if typeValue == "1" || typeValue == "2" || typeValue == "5" {
		if days := easWeekdays(nodeText(recurrence, "DayOfWeek")); len(days) > 0 {
			if typeValue == "2" || typeValue == "5" {
				week := positiveInt(nodeText(recurrence, "WeekOfMonth"))
				prefix := strconv.Itoa(week)
				if week == 5 {
					prefix = "-1"
				}
				for index := range days {
					days[index] = prefix + days[index]
				}
			}
			parts = append(parts, "BYDAY="+strings.Join(days, ","))
		}
	}
	if typeValue == "3" || typeValue == "6" {
		if day := positiveInt(nodeText(recurrence, "DayOfMonth")); day > 0 {
			parts = append(parts, "BYMONTHDAY="+strconv.Itoa(day))
		}
	}
	if typeValue == "5" || typeValue == "6" {
		if month := positiveInt(nodeText(recurrence, "MonthOfYear")); month > 0 && month <= 12 {
			parts = append(parts, "BYMONTH="+strconv.Itoa(month))
		}
	}
	return strings.Join(parts, ";")
}

func easWeekdays(value string) []string {
	mask, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	days := []struct {
		bit  int
		name string
	}{{1, "SU"}, {2, "MO"}, {4, "TU"}, {8, "WE"}, {16, "TH"}, {32, "FR"}, {64, "SA"}}
	result := make([]string, 0, 7)
	for _, day := range days {
		if mask&day.bit != 0 {
			result = append(result, day.name)
		}
	}
	return result
}

func nodeTexts(root *protocol.Node, tag string) []string {
	var result []string
	var visit func(*protocol.Node)
	visit = func(node *protocol.Node) {
		if node == nil {
			return
		}
		if node.Tag == tag && node.Text != "" {
			result = append(result, node.Text)
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(root)
	return result
}

func dateOnly(value string) string {
	if parsed := parseDate(value); !parsed.IsZero() {
		return parsed.Format("2006-01-02")
	}
	return value
}

func icalDate(value string, allDay bool) string {
	parsed := parseDate(value)
	if parsed.IsZero() {
		return ""
	}
	if allDay {
		return ";VALUE=DATE:" + parsed.UTC().Format("20060102")
	}
	return ":" + parsed.UTC().Format("20060102T150405Z")
}

func escapeICal(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\r\n", "\\n")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, ",", "\\,")
	return strings.ReplaceAll(value, ";", "\\;")
}

func (s *Source) call(ctx context.Context, command string, root *protocol.Node) (*protocol.Node, error) {
	payload, err := protocol.Encode(root)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(s.endpoint)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("Cmd", command)
	query.Set("User", s.username)
	query.Set("DeviceId", s.deviceID)
	query.Set("DeviceType", s.deviceType)
	endpoint.RawQuery = query.Encode()
	var lastErr error
	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		response, retryable, err := s.callOnce(ctx, command, endpoint.String(), payload)
		if err == nil {
			if status := topLevelStatus(response); status != "" && protocolStatusRetryable(command, status) {
				err = fmt.Errorf("EAS %s global status %s (%s)", command, status, protocolStatusMeaning(status))
				retryable = true
			} else {
				return response, nil
			}
		}
		lastErr = err
		if !retryable || attempt == s.maxAttempts || ctx.Err() != nil {
			if retryable && ctx.Err() == nil {
				var responseErr *responseFailure
				if errors.As(err, &responseErr) && responseErr.kind == responseFailureMalformed {
					// Repeating the identical page may recover a transient serializer
					// failure, but a persistently malformed collection is folder-local.
					// Do not misclassify it as global source pressure.
					return nil, err
				}
				return nil, migration.MarkSourcePressure(err)
			}
			return nil, err
		}
		timer := time.NewTimer(s.retryBackoff * time.Duration(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func topLevelStatus(response *protocol.Node) string {
	if response == nil {
		return ""
	}
	if status := response.Child("Status"); status != nil {
		return status.Text
	}
	return ""
}

func protocolStatusRetryable(command, status string) bool {
	if status == "111" { // Common status: ServerErrorRetryLater.
		return true
	}
	return command == "Sync" && (status == "5" || status == "16")
}

func protocolStatusMeaning(status string) string {
	switch status {
	case "111":
		return "server error; retry later"
	case "16":
		return "retry requested"
	case "5":
		return "server error"
	case "12":
		return "folder hierarchy changed"
	default:
		return "protocol error"
	}
}

func (s *Source) callOnce(ctx context.Context, command, endpoint string, payload []byte) (*protocol.Node, bool, error) {
	ctx, remote := migration.TraceRemote(ctx)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, false, err
	}
	request.SetBasicAuth(s.username, s.password)
	request.Header.Set("Content-Type", "application/vnd.ms-sync.wbxml")
	request.Header.Set("MS-ASProtocolVersion", s.version)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, ctx.Err() == nil, fmt.Errorf("EAS %s: %w", command, err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, s.responseMax+1))
	closeErr := response.Body.Close()
	if err != nil {
		failure := newResponseFailure(responseFailureTransport, command, data, response.ContentLength, fmt.Errorf("read HTTP body: %w", err))
		return nil, ctx.Err() == nil, failure
	}
	if closeErr != nil {
		return nil, true, fmt.Errorf("close EAS %s response: %w", command, closeErr)
	}
	if err := migration.CheckSourceResponse("ActiveSync", response, remote(), len(data), "application/vnd.ms-sync.wbxml", "application/vnd.ms-sync"); err != nil {
		retryable := response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusGatewayTimeout
		return nil, retryable, fmt.Errorf("EAS %s: %w", command, err)
	}
	if int64(len(data)) > s.responseMax {
		failure := newResponseFailure(responseFailureOversize, command, data, response.ContentLength, fmt.Errorf("response exceeds %d bytes: %w", s.responseMax, errEASResponseTooLarge))
		return nil, false, failure
	}
	if len(data) == 0 {
		return nil, false, nil
	}
	rootResponse, err := protocol.Decode(data)
	if err != nil {
		failure := newResponseFailure(responseFailureMalformed, command, data, response.ContentLength, fmt.Errorf("decode WBXML: %w", err))
		return nil, true, failure
	}
	return rootResponse, false, nil
}

func folderType(value string) model.FolderType {
	switch value {
	case "7", "10", "11", "15", "16", "17":
		return model.FolderTypeNotes
	case "8", "13":
		return model.FolderTypeCalendar
	case "9", "14", "19":
		return model.FolderTypeContacts
	default:
		return model.FolderTypeMail
	}
}

func specialUse(value string) string {
	switch value {
	case "2":
		return model.SpecialUseInbox
	case "3":
		return model.SpecialUseDrafts
	case "4":
		return model.SpecialUseTrash
	case "5":
		return model.SpecialUseSent
	default:
		return ""
	}
}

func nodeText(root *protocol.Node, tag string) string {
	if root == nil {
		return ""
	}
	node := root.Descendant(tag)
	if node == nil {
		return ""
	}
	return node.Text
}

func nodeBytes(node *protocol.Node) []byte {
	if node == nil {
		return nil
	}
	if node.Opaque != nil {
		return append([]byte(nil), node.Opaque...)
	}
	return []byte(node.Text)
}

func looksLikeMIME(data []byte) bool {
	text := strings.ToLower(string(data))
	return strings.Contains(text, "\r\n\r\n") && (strings.HasPrefix(text, "from:") || strings.HasPrefix(text, "subject:") || strings.Contains(text, "\r\nsubject:"))
}

func makeMIME(headers map[string]string, body []byte) []byte {
	var result strings.Builder
	for _, name := range []string{"From", "To", "Cc", "Subject"} {
		if value := strings.ReplaceAll(strings.ReplaceAll(headers[name], "\r", ""), "\n", ""); value != "" {
			result.WriteString(name + ": " + value + "\r\n")
		}
	}
	result.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	result.Write(body)
	return []byte(result.String())
}

func parseDate(value string) time.Time {
	for _, layout := range []string{"20060102T150405Z", "2006-01-02T15:04:05.000Z", time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
