package eas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	protocol "github.com/lkarlslund/veksel/pkg/eas"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestCheckpointUpgradesLegacyCalendarsWithoutResettingMail(t *testing.T) {
	calendar, initial, err := decodeCheckpoint("legacy-key", model.FolderTypeCalendar)
	if err != nil || !initial || calendar.Key != "0" || !calendar.InitialCoveragePending {
		t.Fatalf("calendar checkpoint=%#v initial=%v err=%v", calendar, initial, err)
	}
	mail, initial, err := decodeCheckpoint("legacy-key", model.FolderTypeMail)
	if err != nil || initial || mail.Key != "legacy-key" || mail.InitialCoveragePending {
		t.Fatalf("mail checkpoint=%#v initial=%v err=%v", mail, initial, err)
	}
	encoded, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "42", InitialCoveragePending: true})
	if err != nil {
		t.Fatal(err)
	}
	decoded, initial, err := decodeCheckpoint(encoded, model.FolderTypeCalendar)
	if err != nil || initial || decoded.Key != "42" || !decoded.InitialCoveragePending {
		t.Fatalf("round trip=%#v initial=%v err=%v", decoded, initial, err)
	}
	if _, _, err := decodeCheckpoint(easCheckpointPrefix+"not-base64", model.FolderTypeCalendar); err == nil {
		t.Fatal("malformed checkpoint succeeded")
	}
}

func TestCalendarInitialSyncIsPagedAndRestartSafe(t *testing.T) {
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		root, err := protocol.Decode(payload)
		if err != nil {
			t.Error(err)
			return
		}
		collection := root.Descendant("Collection")
		key := nodeText(collection, "SyncKey")
		getChanges := collection.Child("GetChanges") != nil
		var response *protocol.Node
		switch attempt.Add(1) {
		case 1:
			if key != "0" || getChanges {
				t.Errorf("prime request key=%q getChanges=%v", key, getChanges)
			}
			response = syncCollection("10")
		case 2:
			if key != "10" || !getChanges {
				t.Errorf("first data request key=%q getChanges=%v", key, getChanges)
			}
			response = syncCollection("11", protocol.E(0, "MoreAvailable"), calendarAdd("event-1", "First event"))
		case 3:
			if key != "11" || !getChanges {
				t.Errorf("next page request key=%q getChanges=%v", key, getChanges)
			}
			response = syncCollection("12", calendarAdd("event-2", "Second event"))
		default:
			t.Errorf("unexpected request %d", attempt.Load())
			response = syncCollection("12")
		}
		encoded, err := protocol.Encode(response)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ms-sync.wbxml")
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	folder := migration.Folder{ID: "calendar", Name: "Calendar", Type: model.FolderTypeCalendar}
	prime, err := source.Items(t.Context(), folder, "legacy-unverified-key")
	if err != nil || prime.Done || len(prime.Items) != 0 {
		t.Fatalf("prime=%#v err=%v", prime, err)
	}
	first, err := source.Items(t.Context(), folder, prime.Checkpoint)
	if err != nil || first.Done || len(first.Items) != 1 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	// Passing the persisted checkpoint to a fresh Source simulates a restart.
	restarted, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	last, err := restarted.Items(t.Context(), folder, first.Checkpoint)
	if err != nil || !last.Done || len(last.Items) != 1 {
		t.Fatalf("last=%#v err=%v", last, err)
	}
	if got := string(last.Items[0].Data); !strings.Contains(got, "SUMMARY:Second event") {
		t.Fatalf("calendar item=%s", got)
	}
}

func TestItemsReducesWindowForOversizeAndTruncatedResponses(t *testing.T) {
	var windows []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		root, err := protocol.Decode(payload)
		if err != nil {
			t.Error(err)
			return
		}
		window := nodeText(root.Descendant("Collection"), "WindowSize")
		windows = append(windows, window)
		value, _ := strconv.Atoi(window)
		if value > 50 {
			_, _ = w.Write(make([]byte, 513))
			return
		}
		if value > 25 {
			truncated, err := protocol.Encode(syncCollection("truncated", calendarAdd("event", "Truncated")))
			if err != nil {
				t.Error(err)
				return
			}
			truncated = truncated[:len(truncated)-1]
			if _, err := protocol.Decode(truncated); !errors.Is(err, protocol.ErrMissingTrailingEnd) {
				t.Errorf("fixture truncation error = %v", err)
				return
			}
			_, _ = w.Write(truncated)
			return
		}
		response, err := protocol.Encode(syncCollection("next"))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(response)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	source.responseMax = 512
	checkpoint, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "current", InitialCoveragePending: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "large", Type: model.FolderTypeMail}, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Done || !page.InitialCoverageComplete {
		t.Fatalf("page = %#v, want completed initial coverage", page)
	}
	if got, want := strings.Join(windows, ","), "100,50,25"; got != want {
		t.Fatalf("windows = %s, want %s", got, want)
	}
	if got := source.syncWindow("large"); got != 25 {
		t.Fatalf("retained window = %d, want 25", got)
	}
}

func TestItemsRetainsPreciseFailureAtMinimumWindow(t *testing.T) {
	var windows []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		root, err := protocol.Decode(payload)
		if err != nil {
			t.Error(err)
			return
		}
		windows = append(windows, nodeText(root.Descendant("Collection"), "WindowSize"))
		truncated, err := protocol.Encode(syncCollection("truncated"))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(truncated[:len(truncated)-1])
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "current", InitialCoveragePending: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Items(t.Context(), migration.Folder{ID: "always-truncated", Type: model.FolderTypeMail}, checkpoint)
	if err == nil || !strings.Contains(err.Error(), "minimum Sync window 1") || !errors.Is(err, protocol.ErrMissingTrailingEnd) {
		t.Fatalf("minimum-window error = %v", err)
	}
	if got, want := strings.Join(windows, ","), "100,50,25,12,6,3,1"; got != want {
		t.Fatalf("windows = %s, want %s", got, want)
	}
}

func TestItemsSkipsOnlyProvenWindowOneMalformedItemAndResumesCheckpoint(t *testing.T) {
	const reportedBytes = 67850
	malformed := reportedLatitudeResponse(t, reportedBytes, "damaged-next", "damaged-item")
	var windows []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		root, err := protocol.Decode(payload)
		if err != nil {
			t.Error(err)
			return
		}
		collection := root.Descendant("Collection")
		key := nodeText(collection, "SyncKey")
		windows = append(windows, nodeText(collection, "WindowSize"))
		if key == "damaged-next" {
			response, encodeErr := protocol.Encode(syncCollection("caught-up"))
			if encodeErr != nil {
				t.Error(encodeErr)
				return
			}
			_, _ = w.Write(response)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(malformed)))
		_, _ = w.Write(malformed)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "current", InitialCoveragePending: true, InitialItemsSeen: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if page.Done || page.InitialCoverageComplete || len(page.Items) != 0 || len(page.DeletedIDs) != 1 || page.DeletedIDs[0] != "complete-delete" || len(page.ItemFailures) != 1 || page.ItemFailures[0].ID != "damaged-item" {
		t.Fatalf("recovered page = %#v", page)
	}
	if failure := page.ItemFailures[0].Error; !strings.Contains(failure, "kind=malformed_wbxml") || !strings.Contains(failure, "bytes=67850") || !strings.Contains(failure, "content_length=67850") || !strings.Contains(failure, "sha256=") || strings.Contains(failure, strings.Repeat("x", 32)) {
		t.Fatalf("failure diagnostic = %q", failure)
	}
	state, initial, err := decodeCheckpoint(page.Checkpoint, model.FolderTypeCalendar)
	if err != nil || initial || state.Key != "damaged-next" || !state.InitialCoveragePending {
		t.Fatalf("checkpoint state=%#v initial=%v err=%v", state, initial, err)
	}

	// A fresh source receives the retained key after restart and asks only for
	// changes after the terminally skipped item.
	restarted, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, page.Checkpoint)
	if err != nil || !resumed.Done || !resumed.InitialCoverageComplete || len(resumed.ItemFailures) != 0 {
		t.Fatalf("resumed page=%#v err=%v", resumed, err)
	}
	if got, want := strings.Join(windows, ","), "100,50,25,12,6,3,1,100"; got != want {
		t.Fatalf("windows = %s, want %s", got, want)
	}
}

func reportedLatitudeResponse(t *testing.T, size int, key, itemID string) []byte {
	t.Helper()
	build := func(filler int) []byte {
		response := syncCollection(key, protocol.E(0, "Commands",
			protocol.E(0, "Delete", protocol.T(0, "ServerId", "complete-delete")),
			protocol.E(0, "Add",
				protocol.T(0, "ServerId", itemID),
				protocol.E(0, "ApplicationData",
					protocol.T(4, "UID", itemID),
					protocol.T(17, "Data", strings.Repeat("x", filler)),
					protocol.T(17, "Latitude", "55.6761"),
				),
			),
		))
		encoded, err := protocol.Encode(response)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	truncateAfterLatitude := func(encoded []byte) []byte {
		marker := append([]byte("55.6761"), 0)
		end := bytes.Index(encoded, marker)
		if end < 0 {
			t.Fatal("Latitude marker is missing from encoded fixture")
		}
		return encoded[:end+len(marker)]
	}
	base := truncateAfterLatitude(build(0))
	filler := size - len(base)
	if filler < 0 {
		t.Fatalf("reported response size %d is too small", size)
	}
	var malformed []byte
	for range 4 {
		malformed = truncateAfterLatitude(build(filler))
		if len(malformed) == size {
			break
		}
		filler += size - len(malformed)
	}
	if len(malformed) != size {
		t.Fatalf("malformed fixture size = %d, want %d", len(malformed), size)
	}
	if _, err := protocol.Decode(malformed); !errors.Is(err, protocol.ErrMissingTrailingEnd) || !strings.Contains(err.Error(), "page 17 tag Latitude") {
		t.Fatalf("malformed fixture error = %v", err)
	}
	return malformed
}

func TestMinimumWindowRecoveryProjectsEnvelopeBeforeMalformedApplicationData(t *testing.T) {
	var nested *protocol.Node = protocol.T(17, "Latitude", "55.6761")
	for range maxTrailingEndClosures + 1 {
		nested = protocol.E(17, "Location", nested)
	}
	document := syncCollection("projected-next", protocol.E(0, "Commands", protocol.E(0, "Change",
		protocol.T(0, "ServerId", "projected-item"),
		protocol.E(0, "ApplicationData", nested),
	)))
	encoded, err := protocol.Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	marker := append([]byte("55.6761"), 0)
	end := bytes.Index(encoded, marker)
	if end < 0 {
		t.Fatal("fixture marker is missing")
	}
	malformed := encoded[:end+len(marker)]
	_, decodeErr := protocol.Decode(malformed)
	var suffix *protocol.MissingTrailingEndError
	if !errors.As(decodeErr, &suffix) || suffix.Depth <= maxTrailingEndClosures {
		t.Fatalf("decode error = %v, suffix=%#v", decodeErr, suffix)
	}
	failure := newResponseFailure(responseFailureMalformed, "Sync", malformed, int64(len(malformed)), fmt.Errorf("decode WBXML: %w", decodeErr))
	root, itemFailure, ok, rejection := recoverMinimumWindowResponse(failure)
	if !ok || rejection != "" || itemFailure.ID != "projected-item" {
		t.Fatalf("recovery ok=%v rejection=%q failure=%#v", ok, rejection, itemFailure)
	}
	command := root.Descendant("Commands").Child("Change")
	applicationData := command.Child("ApplicationData")
	if nodeText(root.Descendant("Collection"), "SyncKey") != "projected-next" || applicationData == nil || len(applicationData.Children) != 0 || !strings.Contains(itemFailure.Error, "without reading malformed ApplicationData") || !strings.Contains(itemFailure.Error, "open_depth=") {
		t.Fatalf("projected root=%#v failure=%#v", root, itemFailure)
	}
}

func TestCalendarInitialCoverageRequiresTwoEmptyContentResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "10", InitialCoveragePending: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, checkpoint)
	if err != nil || first.Done || first.Checkpoint == checkpoint || first.InitialCoverageComplete || first.SourceExplicitlyEmpty {
		t.Fatalf("first page=%#v error=%v", first, err)
	}
	firstState, _, err := decodeCheckpoint(first.Checkpoint, model.FolderTypeCalendar)
	if err != nil || firstState.InitialEmptyResponses != 1 || !firstState.InitialCoveragePending {
		t.Fatalf("first checkpoint state=%#v error=%v", firstState, err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, first.Checkpoint)
	if err != nil || !page.Done || page.Checkpoint == first.Checkpoint || !page.InitialCoverageComplete || !page.SourceExplicitlyEmpty {
		t.Fatalf("confirmed page=%#v error=%v", page, err)
	}
	state, _, err := decodeCheckpoint(page.Checkpoint, model.FolderTypeCalendar)
	if err != nil || state.InitialCoveragePending {
		t.Fatalf("checkpoint state=%#v error=%v", state, err)
	}
}

func TestEstablishedEmptyResponseMeansNoChangesNotEmptySource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "10"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, checkpoint)
	if err != nil || !page.Done || page.InitialCoverageComplete || page.SourceExplicitlyEmpty {
		t.Fatalf("page=%#v error=%v", page, err)
	}
}

func TestEmptyResponseAfterPagedItemsCompletesCoverageWithoutClaimingEmptySource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := encodeCheckpoint(easCheckpoint{Version: 1, Key: "11", InitialCoveragePending: true, InitialItemsSeen: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, checkpoint)
	if err != nil || !page.Done || !page.InitialCoverageComplete || page.SourceExplicitlyEmpty {
		t.Fatalf("page=%#v error=%v", page, err)
	}
}

func TestCalendarPrimingStillRejectsEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Items(t.Context(), migration.Folder{ID: "calendar", Type: model.FolderTypeCalendar}, "")
	if err == nil || !strings.Contains(err.Error(), "no synchronization key") {
		t.Fatalf("error=%v", err)
	}
}

func syncCollection(key string, children ...*protocol.Node) *protocol.Node {
	collectionChildren := []*protocol.Node{protocol.T(0, "SyncKey", key), protocol.T(0, "CollectionId", "calendar"), protocol.T(0, "Status", "1")}
	collectionChildren = append(collectionChildren, children...)
	return protocol.E(0, "Sync", protocol.E(0, "Collections", protocol.E(0, "Collection", collectionChildren...)))
}

func calendarAdd(id, subject string) *protocol.Node {
	return protocol.E(0, "Commands", protocol.E(0, "Add", protocol.T(0, "ServerId", id), protocol.E(0, "ApplicationData",
		protocol.T(4, "UID", id), protocol.T(4, "Subject", subject),
		protocol.T(4, "StartTime", "2026-08-18T09:00:00.000Z"), protocol.T(4, "EndTime", "2026-08-18T10:00:00.000Z"))))
}

func TestSourceAgainstVekselEASServer(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: EAS migration\r\n\r\nbody")
	sourceItemID, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), raw, map[string]string{"Subject": "EAS migration"})
	if err != nil {
		t.Fatal(err)
	}
	space := service.NewFolderSpace(ts, authz.New(ts))
	handler, err := protocol.New(t.Context(), protocol.Config{
		Space: space, Store: backend,
		Authenticate: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", context.Canceled
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", Password: "secret", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	folders, err := source.Folders(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var inboxID string
	for _, folder := range folders {
		if folder.Name == "INBOX" {
			inboxID = folder.ID
		}
	}
	if inboxID == "" {
		t.Fatalf("INBOX missing from %#v", folders)
	}
	inventory, err := source.Inventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, folder := range inventory {
		if folder.Name == "INBOX" && (!folder.EstimateKnown || folder.Estimate != 1) {
			t.Fatalf("INBOX inventory = %#v", folder)
		}
	}
	folder := migration.Folder{ID: inboxID, Name: "INBOX", Type: model.FolderTypeMail}
	initial, err := source.Items(t.Context(), folder, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.Items) != 0 || initial.Checkpoint == "" || initial.Checkpoint == "0" || initial.Done {
		t.Fatalf("initial page=%#v", initial)
	}
	page, err := source.Items(t.Context(), folder, initial.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || string(page.Items[0].Data) != string(raw) || !page.Done || page.Checkpoint == initial.Checkpoint {
		t.Fatalf("page=%#v", page)
	}
	sourceExternalID := page.Items[0].ID
	if err := space.DeleteItem(t.Context(), service.UserAccess("alice", "test"), sourceItemID); err != nil {
		t.Fatal(err)
	}
	deleted, err := source.Items(t.Context(), folder, page.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.DeletedIDs) != 1 || deleted.DeletedIDs[0] != sourceExternalID || !deleted.Done {
		t.Fatalf("deleted page=%#v", deleted)
	}
}

func TestCallRetriesTransientHTTPFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 2, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.call(t.Context(), "Sync", protocol.E(0, "Sync")); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestCallRetriesTransientProtocolStatus(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var response *protocol.Node
		if attempts.Add(1) == 1 {
			response = protocol.E(0, "Sync", protocol.T(0, "Status", "111"))
		} else {
			response = protocol.E(0, "Sync", protocol.E(0, "Collections"))
		}
		payload, err := protocol.Encode(response)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 2, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.call(t.Context(), "Sync", protocol.E(0, "Sync")); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestCallRetriesMalformedCompleteResponseAtSameWindow(t *testing.T) {
	malformed := reportedLatitudeResponse(t, 67850, "next", "damaged-item")
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Content-Length", strconv.Itoa(len(malformed)))
			_, _ = w.Write(malformed)
			return
		}
		response, err := protocol.Encode(syncCollection("next"))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(response)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 2, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.call(t.Context(), "Sync", protocol.E(0, "Sync")); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestCallKeepsPersistentMalformedResponseFolderLocal(t *testing.T) {
	malformed := reportedLatitudeResponse(t, 67850, "next", "damaged-item")
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Length", strconv.Itoa(len(malformed)))
		_, _ = w.Write(malformed)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 2, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.call(t.Context(), "Sync", protocol.E(0, "Sync"))
	var failure *responseFailure
	var pressure *migration.SourcePressureError
	if !errors.As(err, &failure) || failure.kind != responseFailureMalformed || errors.As(err, &pressure) {
		t.Fatalf("error = %v, want folder-local malformed response", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if diagnostic := err.Error(); !strings.Contains(diagnostic, "kind=malformed_wbxml") || !strings.Contains(diagnostic, "bytes=67850") || !strings.Contains(diagnostic, "content_length=67850") || !strings.Contains(diagnostic, "sha256=") || strings.Contains(diagnostic, strings.Repeat("x", 32)) {
		t.Fatalf("diagnostic = %q", diagnostic)
	}
}

func TestCallClassifiesHTTPShortReadAsSourcePressure(t *testing.T) {
	response, err := protocol.Encode(syncCollection("next"))
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Length", strconv.Itoa(len(response)+10))
		_, _ = w.Write(response)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 2, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.call(t.Context(), "Sync", protocol.E(0, "Sync"))
	var failure *responseFailure
	var pressure *migration.SourcePressureError
	if !errors.As(err, &failure) || failure.kind != responseFailureTransport || !errors.As(err, &pressure) {
		t.Fatalf("error = %v, want retryable transport pressure", err)
	}
	if windowReducibleResponseError(err) {
		t.Fatalf("short read must not reduce Sync window: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if diagnostic := err.Error(); !strings.Contains(diagnostic, "kind=transport_short_read") || !strings.Contains(diagnostic, "unexpected EOF") || !strings.Contains(diagnostic, "sha256=") {
		t.Fatalf("diagnostic = %q", diagnostic)
	}
}

func TestCallDoesNotRetryAuthenticationFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 3, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.call(t.Context(), "Sync", protocol.E(0, "Sync")); err == nil {
		t.Fatal("authentication failure succeeded")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestCallMarksExhaustedTransientHTTPFailureAsSourcePressure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "try again", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client(), MaxAttempts: 2, RetryBackoff: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.call(t.Context(), "Sync", protocol.E(0, "Sync"))
	var pressure *migration.SourcePressureError
	if !errors.As(err, &pressure) || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("error = %v, want source pressure preserving HTTP failure", err)
	}
}

func TestItemsReportsGlobalSyncStatusWithoutReducingProtocolErrorsToMissingCollection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload, err := protocol.Encode(protocol.E(0, "Sync", protocol.T(0, "Status", "4")))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ms-sync.wbxml")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Items(t.Context(), migration.Folder{ID: "tasks", Type: model.FolderTypeNotes}, "")
	if err == nil || !strings.Contains(err.Error(), "global status 4") || strings.Contains(err.Error(), "no collection") {
		t.Fatalf("error = %v, want precise global protocol status", err)
	}
}

func TestItemsRefreshesFolderHierarchyAndRetriesStatus12(t *testing.T) {
	var commands []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		command := request.URL.Query().Get("Cmd")
		commands = append(commands, command)
		var response *protocol.Node
		switch len(commands) {
		case 1:
			if command != "Sync" {
				t.Errorf("first command = %q, want Sync", command)
			}
			response = protocol.E(0, "Sync", protocol.T(0, "Status", "12"))
		case 2:
			if command != "FolderSync" {
				t.Errorf("recovery command = %q, want FolderSync", command)
			}
			response = protocol.E(7, "FolderSync", protocol.T(7, "Status", "1"), protocol.T(7, "SyncKey", "hierarchy-2"))
		case 3:
			if command != "Sync" {
				t.Errorf("retried command = %q, want Sync", command)
			}
			response = syncCollection("calendar-1")
		default:
			t.Errorf("unexpected command sequence %v", commands)
			response = syncCollection("calendar-1")
		}
		payload, err := protocol.Encode(response)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ms-sync.wbxml")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	source, err := New(Config{Endpoint: server.URL, Username: "alice", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Items(t.Context(), migration.Folder{ID: "calendar", Name: "Calendar", Type: model.FolderTypeCalendar}, "")
	if err != nil {
		t.Fatal(err)
	}
	if page.Checkpoint == "" || page.Done || strings.Join(commands, ",") != "Sync,FolderSync,Sync" {
		t.Fatalf("page=%#v commands=%v", page, commands)
	}
}

func TestSyncServerStatusIsSourcePressure(t *testing.T) {
	for _, status := range []string{"5", "16", "111"} {
		err := syncStatusError("global", status)
		var pressure *migration.SourcePressureError
		if !errors.As(err, &pressure) {
			t.Errorf("server status %s = %v, want source pressure", status, err)
		}
	}
	var pressure *migration.SourcePressureError
	err := syncStatusError("global", "4")
	if errors.As(err, &pressure) {
		t.Fatalf("protocol error = %v, must not be source pressure", err)
	}
}

func TestDeviceIdentityIsUniqueUnlessConfigured(t *testing.T) {
	first, err := New(Config{Endpoint: "https://example.test/Microsoft-Server-ActiveSync", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{Endpoint: "https://example.test/Microsoft-Server-ActiveSync", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if first.deviceID == second.deviceID || len(first.deviceID) != 32 {
		t.Fatalf("device IDs %q %q", first.deviceID, second.deviceID)
	}
	explicit, err := New(Config{Endpoint: "https://example.test/Microsoft-Server-ActiveSync", Username: "alice", DeviceID: "AABBCC"})
	if err != nil || explicit.deviceID != "AABBCC" {
		t.Fatalf("explicit device ID=%q err=%v", explicit.deviceID, err)
	}
}

func TestSourceSerializesFolderSyncCommandsForOneDevicePartnership(t *testing.T) {
	source, err := New(Config{Endpoint: "https://example.test/Microsoft-Server-ActiveSync", Username: "alice", DeviceID: "STABLEBASEDEVICE"})
	if err != nil {
		t.Fatal(err)
	}
	if got := source.FolderConcurrency(); got != 1 {
		t.Fatalf("folder concurrency = %d, want 1", got)
	}
}

func TestSyncOptionsUseMIMEOnlyForMail(t *testing.T) {
	tests := []struct {
		name       string
		folderType model.FolderType
		bodyType   string
		mime       bool
	}{
		{name: "mail", folderType: model.FolderTypeMail, bodyType: "4", mime: true},
		{name: "calendar", folderType: model.FolderTypeCalendar, bodyType: "1"},
		{name: "contacts", folderType: model.FolderTypeContacts, bodyType: "1"},
		{name: "notes", folderType: model.FolderTypeNotes, bodyType: "1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := syncOptions(migration.Folder{ID: test.name, Type: test.folderType})
			if filter := options.Child("FilterType"); filter == nil || filter.Text != "0" {
				t.Fatalf("FilterType = %#v", filter)
			}
			if got := options.Child("MIMESupport") != nil; got != test.mime {
				t.Fatalf("MIMESupport present = %v, want %v", got, test.mime)
			}
			body := options.Child("BodyPreference")
			if body == nil || body.Child("Type") == nil || body.Child("Type").Text != test.bodyType {
				t.Fatalf("BodyPreference = %#v, want type %s", body, test.bodyType)
			}
		})
	}
}

func TestRecipientInformationCacheUsesDedicatedSyncOptions(t *testing.T) {
	options := syncOptions(migration.Folder{ID: "RI", Type: model.FolderTypeContacts})
	if got := nodeText(options, "MaxItems"); got != "1000" {
		t.Fatalf("MaxItems = %q, want 1000", got)
	}
	for _, forbidden := range []string{"FilterType", "BodyPreference", "MIMESupport"} {
		if options.Descendant(forbidden) != nil {
			t.Errorf("recipient cache options unexpectedly contain %s", forbidden)
		}
	}
}

func TestParseDateSupportsExchangeDateTimeRepresentations(t *testing.T) {
	want := time.Date(2026, time.August, 18, 9, 30, 15, 0, time.UTC)
	for _, value := range []string{"20260818T093015Z", "2026-08-18T09:30:15Z", "2026-08-18T09:30:15.000Z"} {
		if got := parseDate(value); !got.Equal(want) {
			t.Errorf("parseDate(%q) = %v, want %v", value, got, want)
		}
	}
	if got := parseDate("not-a-date"); !got.IsZero() {
		t.Fatalf("invalid date = %v, want zero", got)
	}
}

func TestItemEstimatesReadsAllResponseNodes(t *testing.T) {
	response := protocol.E(6, "GetItemEstimate",
		protocol.E(6, "Response", protocol.E(6, "Collection",
			protocol.T(6, "CollectionId", "inbox"), protocol.T(6, "Estimate", "7231"))),
		protocol.E(6, "Response", protocol.E(6, "Collection",
			protocol.T(6, "CollectionId", "archive"), protocol.T(6, "Estimate", "10"))),
	)

	got := itemEstimates(response)
	if got["inbox"] != 7231 || got["archive"] != 10 || len(got) != 2 {
		t.Fatalf("estimates=%v", got)
	}
}

func TestContactContentProducesVCard(t *testing.T) {
	data := protocol.E(0, "ApplicationData",
		protocol.T(1, "FileAs", "Doe, Jane"), protocol.T(1, "FirstName", "Jane"), protocol.T(1, "LastName", "Doe"),
		protocol.T(1, "Email1Address", "jane@example.test"), protocol.T(1, "MobilePhoneNumber", "+45 12345678"),
		protocol.T(1, "BusinessAddressStreet", "Main Street 1"), protocol.T(1, "BusinessAddressCity", "Copenhagen"),
		protocol.E(1, "Categories", protocol.T(1, "Category", "Work")),
	)

	raw, headers := contactContent("contact-1", data)
	contact := model.ParseVCard(raw)
	if headers["FN"] != "Doe, Jane" || contact.UID != "contact-1" || contact.FN != "Doe, Jane" || contact.Emails[0] != "jane@example.test" || contact.Addresses[0].Locality != "Copenhagen" {
		t.Fatalf("headers=%v contact=%#v vcard=%s", headers, contact, raw)
	}
}

func TestCalendarContentProducesICalendar(t *testing.T) {
	data := protocol.E(0, "ApplicationData",
		protocol.T(4, "UID", "event-1"), protocol.T(4, "Subject", "Planning"),
		protocol.T(4, "StartTime", "2026-08-17T09:00:00.000Z"), protocol.T(4, "EndTime", "2026-08-17T10:00:00.000Z"),
		protocol.T(4, "Location", "Studio"), protocol.E(17, "Body", protocol.T(17, "Data", "Bring notes")),
	)

	raw, headers := calendarContent("fallback-id", data)
	text := string(raw)
	for _, want := range []string{"BEGIN:VCALENDAR", "UID:event-1", "DTSTART:20260817T090000Z", "DTEND:20260817T100000Z", "SUMMARY:Planning", "LOCATION:Studio", "DESCRIPTION:Bring notes"} {
		if !strings.Contains(text, want) {
			t.Errorf("iCalendar is missing %q: %s", want, text)
		}
	}
	if headers["UID"] != "event-1" || headers["SUMMARY"] != "Planning" {
		t.Fatalf("headers=%v", headers)
	}
}

func TestCalendarContentPreservesRecurrenceAndMeetingMetadata(t *testing.T) {
	data := protocol.E(0, "ApplicationData",
		protocol.T(4, "UID", "series-1"), protocol.T(4, "Subject", "Team sync"),
		protocol.T(4, "StartTime", "2026-08-17T09:00:00.000Z"), protocol.T(4, "EndTime", "2026-08-17T10:00:00.000Z"),
		protocol.T(4, "OrganizerEmail", "owner@example.test"), protocol.T(4, "OrganizerName", "Calendar Owner"),
		protocol.E(4, "Attendees", protocol.E(4, "Attendee", protocol.T(4, "Email", "jane@example.test"), protocol.T(4, "Name", "Jane Doe"), protocol.T(4, "AttendeeStatus", "3"), protocol.T(4, "AttendeeType", "1"))),
		protocol.E(4, "Categories", protocol.T(4, "Category", "Project"), protocol.T(4, "Category", "Blue")),
		protocol.E(4, "Recurrence", protocol.T(4, "Type", "1"), protocol.T(4, "Interval", "2"), protocol.T(4, "Occurrences", "6"), protocol.T(4, "DayOfWeek", "42")),
		protocol.E(4, "Exceptions",
			protocol.E(4, "Exception", protocol.T(4, "Deleted", "1"), protocol.T(4, "ExceptionStartTime", "2026-08-19T09:00:00.000Z")),
			protocol.E(4, "Exception", protocol.T(4, "ExceptionStartTime", "2026-08-21T09:00:00.000Z"), protocol.T(4, "StartTime", "2026-08-21T11:00:00.000Z"), protocol.T(4, "EndTime", "2026-08-21T12:00:00.000Z"), protocol.T(4, "Subject", "Moved team sync"))),
		protocol.T(4, "Reminder", "15"), protocol.T(4, "Sensitivity", "2"), protocol.T(4, "BusyStatus", "2"),
		protocol.O(4, "TimeZone", []byte{1, 2, 3, 4}),
	)

	raw, headers := calendarContent("server-series-1", data)
	text := string(raw)
	for _, want := range []string{
		"RRULE:FREQ=WEEKLY;INTERVAL=2;COUNT=6;BYDAY=MO,WE,FR",
		"EXDATE:20260819T090000Z",
		"RECURRENCE-ID:20260821T090000Z",
		"SUMMARY:Moved team sync",
		"ORGANIZER;CN=\"Calendar Owner\":mailto:owner@example.test",
		"ATTENDEE;CN=\"Jane Doe\";PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:jane@example.test",
		"CATEGORIES:Project,Blue", "CLASS:PRIVATE", "TRANSP:OPAQUE", "X-MICROSOFT-CDO-BUSYSTATUS:BUSY",
		"BEGIN:VALARM", "TRIGGER:-PT15M", "X-VEKSEL-EAS-TIMEZONE:AQIDBA==",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("iCalendar is missing %q: %s", want, text)
		}
	}
	if headers["External-ID"] != "server-series-1" {
		t.Fatalf("headers=%v", headers)
	}
}

func TestCalendarExceptionInheritsMasterAllDaySemantics(t *testing.T) {
	data := protocol.E(0, "ApplicationData",
		protocol.T(4, "UID", "all-day-series"), protocol.T(4, "AllDayEvent", "1"),
		protocol.T(4, "StartTime", "2026-08-17T00:00:00.000Z"), protocol.T(4, "EndTime", "2026-08-18T00:00:00.000Z"),
		protocol.E(4, "Exceptions", protocol.E(4, "Exception",
			protocol.T(4, "ExceptionStartTime", "2026-08-19T00:00:00.000Z"),
			protocol.T(4, "StartTime", "2026-08-20T00:00:00.000Z"), protocol.T(4, "EndTime", "2026-08-21T00:00:00.000Z"))),
	)
	raw, _ := calendarContent("fallback", data)
	for _, want := range []string{"RECURRENCE-ID;VALUE=DATE:20260819", "DTSTART;VALUE=DATE:20260820", "DTEND;VALUE=DATE:20260821"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("iCalendar is missing %q: %s", want, raw)
		}
	}
}

func TestFolderTypeUsesEASFolderHierarchyValues(t *testing.T) {
	tests := map[string]model.FolderType{
		"1": model.FolderTypeMail, "12": model.FolderTypeMail, "18": model.FolderTypeMail,
		"8": model.FolderTypeCalendar, "13": model.FolderTypeCalendar,
		"9": model.FolderTypeContacts, "14": model.FolderTypeContacts, "19": model.FolderTypeContacts,
		"7": model.FolderTypeNotes, "10": model.FolderTypeNotes, "11": model.FolderTypeNotes,
		"15": model.FolderTypeNotes, "16": model.FolderTypeNotes, "17": model.FolderTypeNotes,
	}
	for wire, want := range tests {
		if got := folderType(wire); got != want {
			t.Errorf("folderType(%q) = %q, want %q", wire, got, want)
		}
	}
}

func TestSpecialUseDoesNotTreatUserMailAsJunk(t *testing.T) {
	tests := map[string]string{
		"2": model.SpecialUseInbox,
		"3": model.SpecialUseDrafts,
		"4": model.SpecialUseTrash,
		"5": model.SpecialUseSent,
		// MS-ASCMD defines 12 as a user-created mail folder. It does not
		// identify Junk Email, so ordinary folders must not collapse into the
		// destination's special-use Junk folder.
		"12": "",
		"1":  "",
		"18": "",
	}
	for wire, want := range tests {
		if got := specialUse(wire); got != want {
			t.Errorf("specialUse(%q) = %q, want %q", wire, got, want)
		}
	}
}
