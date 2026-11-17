package caldav

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type listFoldersErrorSpace struct {
	service.FolderSpace
	err error
}

func (s listFoldersErrorSpace) ListFolders(context.Context, service.AccessContext, service.FolderQuery) ([]model.Folder, error) {
	return nil, s.err
}

type createItemErrorSpace struct {
	service.FolderSpace
	err error
}

func (s createItemErrorSpace) CreateItem(context.Context, service.AccessContext, string, service.ItemInput) (model.Item, error) {
	return model.Item{}, s.err
}

// --- Test helpers ---

func testStoreSetup(t *testing.T) *model.TypedStore {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create jsonstore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()
	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %q: %v", ns, err)
		}
	}
	return ts
}

func testUser(t *testing.T, ts *model.TypedStore, username, password string) {
	t.Helper()
	ctx := context.Background()
	if err := ts.UserStore().Create(ctx, username, username, password); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	// Ensure default folders are created
	if err := ts.FolderStore().CreateForUser(ctx, username); err != nil {
		t.Fatalf("create folders for %s: %v", username, err)
	}
}

func testHandler(t *testing.T, ts *model.TypedStore) *Handler {
	t.Helper()
	return New(ts, nil)
}

func TestDAVMapsAccountMaintenanceToRetryableResponse(t *testing.T) {
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "password123")
	base := service.NewFolderSpace(ts, authz.New(ts))
	handler := NewWithFolderSpace(ts, listFoldersErrorSpace{FolderSpace: base, err: account.ErrTemporarilyUnavailable}, nil)
	response := httptest.NewRecorder()
	request := newRequest("PROPFIND", "/dav/alice/", `<propfind xmlns="DAV:"><allprop/></propfind>`)
	request.Header.Set("Depth", "1")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" || !strings.Contains(response.Body.String(), "temporarily-unavailable") {
		t.Fatalf("maintenance response: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestDAVMapsQuotaToInsufficientStorage(t *testing.T) {
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "password123")
	base := service.NewFolderSpace(ts, authz.New(ts))
	handler := NewWithFolderSpace(ts, createItemErrorSpace{FolderSpace: base, err: model.ErrQuotaExceeded}, nil)
	response := httptest.NewRecorder()
	calendar := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:quota-test\r\nDTSTART:20260817T120000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	handler.ServeHTTP(response, newRequest(http.MethodPut, "/dav/alice/Calendar/quota.ics", calendar))
	if response.Code != http.StatusInsufficientStorage || !strings.Contains(response.Body.String(), "quota-not-exceeded") {
		t.Fatalf("quota response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func newRequest(method, path string, body interface{}) *http.Request {
	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			reader = strings.NewReader(v)
		case []byte:
			reader = bytes.NewReader(v)
		default:
			data, _ := json.Marshal(v)
			reader = bytes.NewReader(data)
		}
	}
	r := httptest.NewRequest(method, path, reader)
	if body != nil {
		switch body.(type) {
		case string:
			r.Header.Set("Content-Type", "application/xml; charset=utf-8")
		}
	}
	return r
}

func TestSyncCollectionReportsIncrementalDeletion(t *testing.T) {
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "password123")
	handler := testHandler(t, ts)
	access := service.UserAccess("alice", "test")
	folder, err := handler.store.space.GetFolderByPath(t.Context(), access, "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	item, err := handler.store.space.CreateItem(t.Context(), access, folder.ID, service.ItemInput{Name: "event.ics", Data: []byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	body := `<sync-collection xmlns="DAV:"><sync-token></sync-token><prop><getetag/></prop></sync-collection>`
	initial := httptest.NewRecorder()
	handler.ServeHTTP(initial, newRequest("REPORT", "/dav/alice/Calendar/", body))
	if initial.Code != http.StatusMultiStatus || !strings.Contains(initial.Body.String(), "event.ics") {
		t.Fatalf("initial status=%d body=%s", initial.Code, initial.Body.String())
	}
	token := xmlTestElementText(initial.Body.String(), "d:sync-token")
	if token == "" {
		t.Fatalf("initial response has no sync token: %s", initial.Body.String())
	}
	if err := handler.store.space.DeleteItem(t.Context(), access, item.ID); err != nil {
		t.Fatal(err)
	}
	body = `<sync-collection xmlns="DAV:"><sync-token>` + token + `</sync-token><prop><getetag/></prop></sync-collection>`
	incremental := httptest.NewRecorder()
	handler.ServeHTTP(incremental, newRequest("REPORT", "/dav/alice/Calendar/", body))
	if incremental.Code != http.StatusMultiStatus || !strings.Contains(incremental.Body.String(), "event.ics") || !strings.Contains(incremental.Body.String(), "404 Not Found") {
		t.Fatalf("incremental status=%d body=%s", incremental.Code, incremental.Body.String())
	}
}

func xmlTestElementText(document, name string) string {
	startTag, endTag := "<"+name+">", "</"+name+">"
	start := strings.Index(document, startTag)
	if start < 0 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(document[start:], endTag)
	if end < 0 {
		return ""
	}
	return document[start : start+end]
}

func TestCanonicalAuthorizationProtectsCrossAccountDAV(t *testing.T) {
	ts := testStoreSetup(t)
	for _, namespace := range []string{model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	testUser(t, ts, "alice", "password123")
	testUser(t, ts, "bob", "password123")
	handler := New(ts, &Config{Authorizer: authz.New(ts)})

	request := WithAuthenticatedUser(newRequest("PROPFIND", "/dav/bob/Calendar", nil), "alice")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ungranted status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	_, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: model.FolderKey("bob", "Calendar")},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer,
		Inheritance: model.InheritanceSelf, GrantedBy: "bob",
	})
	if err != nil {
		t.Fatalf("create calendar grant: %v", err)
	}
	request = WithAuthenticatedUser(newRequest("PROPFIND", "/dav/bob/Calendar", nil), "alice")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code == http.StatusForbidden {
		t.Fatalf("granted request remained forbidden: %s", recorder.Body.String())
	}
}

// Sample VEVENT for testing
var sampleVEVENT = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:test-event-001@example.com
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:Test Event
END:VEVENT
END:VCALENDAR`

var sampleVEVENT2 = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:test-event-002@example.com
DTSTART:20250615T140000Z
DTEND:20250615T150000Z
SUMMARY:Summer Event
END:VEVENT
END:VCALENDAR`

// propfindBody is a standard PROPFIND XML body used in tests.
const propfindBody = `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:displayname/>
 <D:resourcetype/>
 </D:prop>
</D:propfind>`

// --- Tests ---

func TestMKCALENDAR(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// MKCALENDAR via MKCOL with calendar resource type in body
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
 <D:resourcetype>
   <C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/>
 </D:resourcetype>
</D:prop>`

	r := newRequest("MKCOL", "/dav/alice/WorkCalendar", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("MKCALENDAR: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Verify the folder was created as a calendar
	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "WorkCalendar")
	if err != nil {
		t.Fatalf("get folder: %v", err)
	}
	if folder.Type != model.FolderTypeCalendar {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeCalendar)
	}
}

func TestMKCALENDARDuplicate(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	body := `<D:prop xmlns:D="DAV:"><D:resourcetype><C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/></D:resourcetype></D:prop>`

	// First creation
	r := newRequest("MKCOL", "/dav/alice/Cal", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("first MKCALENDAR: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Second creation should fail
	r = newRequest("MKCOL", "/dav/alice/Cal", body)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate MKCALENDAR: status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestPUTAndGetEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Create a calendar first
	ctx := context.Background()
	if err := ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	// PUT an event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify ETag header
	if etag := w.Header().Get("ETag"); etag == "" {
		t.Error("PUT: missing ETag header")
	}

	// GET the event back
	r = newRequest("GET", "/dav/alice/MyCal/event1.ics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "text/calendar; charset=utf-8" {
		t.Errorf("GET: Content-Type = %q, want %q", w.Header().Get("Content-Type"), "text/calendar; charset=utf-8")
	}

	if !strings.Contains(w.Body.String(), "test-event-001@example.com") {
		t.Errorf("GET: body does not contain expected UID: %s", w.Body.String())
	}
}

func TestPUTUpdateEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT initial event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("initial PUT: status = %d", w.Code)
	}

	// PUT updated event
	updatedEvent := strings.Replace(sampleVEVENT, "Test Event", "Updated Event", 1)
	r = newRequest("PUT", "/dav/alice/MyCal/event1.ics", updatedEvent)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("update PUT: status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// GET and verify
	r = newRequest("GET", "/dav/alice/MyCal/event1.ics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "Updated Event") {
		t.Errorf("GET after update: body does not contain updated summary: %s", w.Body.String())
	}
}

func TestPUTInvalidData(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT data without VEVENT
	r := newRequest("PUT", "/dav/alice/MyCal/bad.ics", "this is not a vevent")
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT invalid: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDeleteEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an event first
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d", w.Code)
	}

	// DELETE the event
	r = newRequest("DELETE", "/dav/alice/MyCal/event1.ics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// GET should return 404
	r = newRequest("GET", "/dav/alice/MyCal/event1.ics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "TempCal", model.FolderTypeCalendar, "")

	// DELETE the calendar collection
	r := newRequest("DELETE", "/dav/alice/TempCal", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE calendar: status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify folder is gone
	_, err := ts.FolderStore().GetByPath(ctx, "alice", "TempCal")
	if err == nil {
		t.Error("expected folder to be deleted")
	}
}

func TestPROPFINDUserRoot(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
   <D:displayname/>
   <D:resourcetype/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	if !strings.Contains(w.Body.String(), "alice") {
		t.Errorf("PROPFIND: body does not contain user href: %s", w.Body.String())
	}
}

func TestPROPFINDCollection(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// PROPFIND on the collection with depth 1
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
   <D:displayname/>
   <D:resourcetype/>
   <D:getetag/>
 </D:prop>
</D:propfind>`

	r = newRequest("PROPFIND", "/dav/alice/MyCal/", body)
	r.Header.Set("Depth", "1")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND collection: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "MyCal") {
		t.Errorf("PROPFIND: body does not contain collection name: %s", respBody)
	}
}

func TestPROPFINDItem(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// PROPFIND on the item
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
   <D:getetag/>
   <D:getcontentlength/>
 </D:prop>
</D:propfind>`

	r = newRequest("PROPFIND", "/dav/alice/MyCal/event1.ics", body)
	r.Header.Set("Depth", "0")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND item: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestCalendarQuery(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT two events with different dates
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT) // Jan 1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	r = newRequest("PUT", "/dav/alice/MyCal/event2.ics", sampleVEVENT2) // Jun 15
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query for events in January 2025
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
   <calendar-data/>
 </D:prop>
 <filter>
   <comp-filter name="VCALENDAR">
     <comp-filter name="VEVENT">
       <time-range start="20250101T000000Z" end="20250131T235959Z"/>
     </comp-filter>
   </comp-filter>
 </filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain the January event
	if !strings.Contains(respBody, "Test Event") {
		t.Errorf("calendar-query: body does not contain January event: %s", respBody)
	}
	// Should NOT contain the June event
	if strings.Contains(respBody, "Summer Event") {
		t.Errorf("calendar-query: body should not contain June event: %s", respBody)
	}
}

func TestCalendarQueryNoTimeRange(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query without time range (should return all)
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
 <filter>
   <comp-filter name="VCALENDAR">
     <comp-filter name="VEVENT"/>
   </comp-filter>
 </filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query no range: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestMultiget(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT two events
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	r = newRequest("PUT", "/dav/alice/MyCal/event2.ics", sampleVEVENT2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Multiget for both events
	multigetBody := `<?xml version="1.0" encoding="utf-8"?>
<multiget xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
   <calendar-data/>
 </D:prop>
 <D:href xmlns:D="DAV:">/dav/alice/MyCal/event1.ics</D:href>
 <D:href xmlns:D="DAV:">/dav/alice/MyCal/event2.ics</D:href>
</multiget>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", multigetBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("multiget: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "Test Event") {
		t.Errorf("multiget: body does not contain event 1: %s", respBody)
	}
	if !strings.Contains(respBody, "Summer Event") {
		t.Errorf("multiget: body does not contain event 2: %s", respBody)
	}
}

func TestMultigetNotFound(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// Multiget for a non-existent event
	multigetBody := `<?xml version="1.0" encoding="utf-8"?>
<multiget xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
 <D:href xmlns:D="DAV:">/dav/alice/MyCal/nonexistent.ics</D:href>
</multiget>`

	r := newRequest("REPORT", "/dav/alice/MyCal/", multigetBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("multiget: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "404") {
		t.Errorf("multiget: expected 404 for missing event: %s", respBody)
	}
}

func TestPROPPATCH(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	patchBody := `<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:">
 <D:set>
   <D:prop>
     <D:displayname>New Calendar Name</D:displayname>
   </D:prop>
 </D:set>
</D:propertyupdate>`

	r := newRequest("PROPPATCH", "/dav/alice/MyCal/", patchBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPPATCH: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestLOCK(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("LOCK", "/dav/alice/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("LOCK: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestUNLOCK(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("UNLOCK", "/dav/alice/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("UNLOCK: status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestMOVE(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("MOVE", "/dav/alice/MyCal/event1.ics", nil)
	r.Header.Set("Destination", "http://example.com/dav/alice/MyCal/event2.ics")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// The source does not exist; MOVE used to answer 204 without acting.
	if w.Code != http.StatusNotFound {
		t.Fatalf("MOVE: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCOPY(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("COPY", "/dav/alice/MyCal/event1.ics", nil)
	r.Header.Set("Destination", "http://example.com/dav/alice/MyCal/event2.ics")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// The source does not exist; COPY used to answer 204 without acting.
	if w.Code != http.StatusNotFound {
		t.Fatalf("COPY: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestNotFoundUser(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	h := testHandler(t, ts)

	r := newRequest("PROPFIND", "/dav/nobody/", propfindBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("not found user: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDisabledUser(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Disable the user
	ctx := context.Background()
	ts.UserStore().Update(ctx, "alice", func(u *model.User) { u.Enabled = false })

	r := newRequest("PROPFIND", "/dav/alice/", propfindBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("disabled user: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestUnsupportedMethod(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := httptest.NewRequest("PATCH", "/dav/alice/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("unsupported method: status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestVEVENTParsing(t *testing.T) {
	t.Parallel()
	// Test containsVEVENT
	if !containsVEVENT([]byte(sampleVEVENT)) {
		t.Error("containsVEVENT should return true for valid VEVENT")
	}

	if containsVEVENT([]byte("just some text")) {
		t.Error("containsVEVENT should return false for non-VEVENT data")
	}

	// Test extractUID
	uid := extractUID([]byte(sampleVEVENT))
	if uid != "test-event-001@example.com" {
		t.Errorf("extractUID = %q, want %q", uid, "test-event-001@example.com")
	}

	// Test extractDTStart
	dtStart := extractDTStart([]byte(sampleVEVENT))
	expected, _ := time.Parse(time.RFC3339, "2025-01-01T10:00:00Z")
	if !dtStart.Equal(expected) {
		t.Errorf("extractDTStart = %v, want %v", dtStart, expected)
	}

	// Test extractDTEnd
	dtEnd := extractDTEnd([]byte(sampleVEVENT))
	expected, _ = time.Parse(time.RFC3339, "2025-01-01T11:00:00Z")
	if !dtEnd.Equal(expected) {
		t.Errorf("extractDTEnd = %v, want %v", dtEnd, expected)
	}
}

func TestTimeRangeMatching(t *testing.T) {
	t.Parallel()
	// Event: Jan 1, 10:00 - 11:00
	startT, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	endT, _ := time.Parse(time.RFC3339, "2025-01-31T23:59:59Z")

	if !eventMatchesTimeRange([]byte(sampleVEVENT), startT, endT) {
		t.Error("event should match January time range")
	}

	// Event should NOT match June range
	juneStart, _ := time.Parse(time.RFC3339, "2025-06-01T00:00:00Z")
	juneEnd, _ := time.Parse(time.RFC3339, "2025-06-30T23:59:59Z")

	if eventMatchesTimeRange([]byte(sampleVEVENT), juneStart, juneEnd) {
		t.Error("January event should not match June time range")
	}

	// Summer event should match June range
	if !eventMatchesTimeRange([]byte(sampleVEVENT2), juneStart, juneEnd) {
		t.Error("June event should match June time range")
	}
}

func TestCalDAVTimeParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input  string
		expect string
	}{
		{"20250101T100000Z", "2025-01-01T10:00:00Z"},
		{"20250101T100000", "2025-01-01T10:00:00Z"},
		{"20250101", "2025-01-01T00:00:00Z"},
		{"2025-01-01T10:00:00Z", "2025-01-01T10:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseCalDAVTime(tt.input)
			if err != nil {
				t.Fatalf("parseCalDAVTime(%q) error: %v", tt.input, err)
			}
			if got.UTC().Format(time.RFC3339) != tt.expect {
				t.Errorf("parseCalDAVTime(%q) = %v, want %v", tt.input, got.UTC(), tt.expect)
			}
		})
	}
}

func TestETagFormat(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("PUT: missing ETag header")
	}
	// ETag should be quoted hex
	if !strings.HasPrefix(etag, "\"") || !strings.HasSuffix(etag, "\"") {
		t.Errorf("ETag should be quoted: %s", etag)
	}

	// GET should return same ETag
	r = newRequest("GET", "/dav/alice/MyCal/event1.ics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	getEtag := w.Header().Get("ETag")
	if getEtag != etag {
		t.Errorf("GET ETag = %q, want %q", getEtag, etag)
	}
}

func TestMultipleEventsInCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT multiple events
	for i := 1; i <= 5; i++ {
		event := strings.Replace(sampleVEVENT, "test-event-001",
			"test-event-001", 1)
		event = strings.Replace(event, "Test Event",
			"Event "+string(rune('A'+i-1)), 1)
		r := newRequest("PUT", "/dav/alice/MyCal/event"+string(rune('0'+i))+".ics", event)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("PUT event %d: status = %d", i, w.Code)
		}
	}

	// PROPFIND with depth 1 should list all events
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
   <D:getetag/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/MyCal/", body)
	r.Header.Set("Depth", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d", w.Code)
	}

	// Count the number of href responses (should be 5 events + 1 collection)
	respBody := w.Body.String()
	hrefCount := strings.Count(respBody, "<d:href>")
	if hrefCount < 6 {
		t.Errorf("PROPFIND: found %d hrefs, expected at least 6 (5 events + 1 collection)", hrefCount)
	}
}

func TestItemStoreSetItem(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	ctx := context.Background()

	// Create a calendar folder
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "MyCal")

	// Create a user first (SetItem needs the user to exist for CalDAV)
	ts.UserStore().Create(ctx, "alice", "Alice", "pass")

	item := model.Item{
		ID:        model.ItemKey(folder.ID, "test-item"),
		FolderID:  folder.ID,
		Data:      []byte(sampleVEVENT),
		Headers:   map[string]string{"UID": "test@example.com"},
		Size:      int64(len(sampleVEVENT)),
		ModSeq:    1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := ts.ItemStore().SetItem(ctx, item); err != nil {
		t.Fatalf("SetItem: %v", err)
	}

	// Verify the item was stored
	retrieved, err := ts.ItemStore().Get(ctx, item.ID)
	if err != nil {
		t.Fatalf("Get after SetItem: %v", err)
	}

	if !bytes.Equal(retrieved.Data, item.Data) {
		t.Error("retrieved item data does not match")
	}

	if retrieved.Headers["UID"] != "test@example.com" {
		t.Errorf("UID header = %q, want %q", retrieved.Headers["UID"], "test@example.com")
	}
}

func TestStoreInterface(t *testing.T) {
	t.Parallel()
	// Verify that model.TypedStore implements our TypedStore interface
	var _ TypedStore = (*model.TypedStore)(nil)
}

func TestBuildHref(t *testing.T) {
	t.Parallel()
	tests := []struct {
		user   string
		parts  []string
		expect string
	}{
		{"alice", nil, "/dav/alice"},
		{"alice", []string{"MyCal"}, "/dav/alice/MyCal"},
		{"alice", []string{"MyCal", "event1.ics"}, "/dav/alice/MyCal/event1.ics"},
	}

	for _, tt := range tests {
		got := buildHref(tt.user, tt.parts...)
		if got != tt.expect {
			t.Errorf("buildHref(%q, %v) = %q, want %q", tt.user, tt.parts, got, tt.expect)
		}
	}
}

func TestMKCOLDefaultFolder(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// MKCOL without calendar body — should create a files folder
	r := newRequest("MKCOL", "/dav/alice/MyFiles", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("MKCOL: status = %d, want %d", w.Code, http.StatusCreated)
	}

	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "MyFiles")
	if err != nil {
		t.Fatalf("get folder: %v", err)
	}
	// Default type when no calendar body
	if folder.Type != model.FolderTypeFiles {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeFiles)
	}
}

func TestCalendarQueryEmptyCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "EmptyCal", model.FolderTypeCalendar, "")

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
 <filter>
   <comp-filter name="VCALENDAR">
     <comp-filter name="VEVENT">
       <time-range start="20250101T000000Z" end="20251231T235959Z"/>
     </comp-filter>
   </comp-filter>
 </filter>
</calendar-query>`

	r := newRequest("REPORT", "/dav/alice/EmptyCal/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("calendar-query empty: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestPROPFINDNonExistentCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop><D:displayname/></D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/NoCal/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// RFC 4918 §9.1: a missing target is 404, not a server error.
	if w.Code != http.StatusNotFound {
		t.Errorf("PROPFIND non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestPUTNonExistentCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("PUT", "/dav/alice/NoCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("PUT non-existent calendar: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteNonExistentEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	r := newRequest("DELETE", "/dav/alice/MyCal/nope.ics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("DELETE non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCalendarQueryNonExistentCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:"><D:getetag/></D:prop>
 <filter><comp-filter name="VCALENDAR"><comp-filter name="VEVENT"/></comp-filter></filter>
</calendar-query>`

	r := newRequest("REPORT", "/dav/alice/NoCal/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("calendar-query non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDTStartWithParameters(t *testing.T) {
	t.Parallel()
	// Test DTSTART with VALUE parameter
	event := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:test-param@example.com
DTSTART;VALUE=DATE:20250704
SUMMARY:Independence Day
END:VEVENT
END:VCALENDAR`

	dtStart := extractDTStart([]byte(event))
	expected, _ := time.Parse("20060102", "20250704")
	if !dtStart.Equal(expected) {
		t.Errorf("extractDTStart with params = %v, want %v", dtStart, expected)
	}
}

func TestEventNoTimeInfo(t *testing.T) {
	t.Parallel()
	// Event with no DTSTART/DTEND should match any time range
	event := `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:no-time@example.com
SUMMARY:All Day No Time
END:VEVENT
END:VCALENDAR`

	startT, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	endT, _ := time.Parse(time.RFC3339, "2025-12-31T23:59:59Z")

	if !eventMatchesTimeRange([]byte(event), startT, endT) {
		t.Error("event with no time info should match any range")
	}
}

func TestStoreErrNotFound(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	ctx := context.Background()

	// Verify that Get returns ErrNotFound for missing items
	_, err := ts.ItemStore().Get(ctx, "nonexistent")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// --- Free/Busy Query Tests (RFC 6638) ---

var sampleAllDayEvent = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:allday-event@example.com
DTSTART;VALUE=DATE:20250704
DTEND;VALUE=DATE:20250705
SUMMARY:Independence Day
END:VEVENT
END:VCALENDAR`

func TestFreeBusyQuery(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an event in January
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d", w.Code)
	}

	// PUT an event in June (outside query range)
	r = newRequest("PUT", "/dav/alice/MyCal/event2.ics", sampleVEVENT2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT event2: status = %d", w.Code)
	}

	// Free-busy query for January 2025
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<free-busy-query xmlns="urn:ietf:params:xml:ns:caldav">
 <time-range-start>20250101T000000Z</time-range-start>
 <time-range-end>20250131T235959Z</time-range-end>
</free-busy-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("free-busy-query: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain VCALENDAR
	if !strings.Contains(respBody, "BEGIN:VCALENDAR") {
		t.Errorf("free-busy-query: body does not contain VCALENDAR: %s", respBody)
	}
	// Should contain FREEBUSY
	if !strings.Contains(respBody, "FREEBUSY;") {
		t.Errorf("free-busy-query: body does not contain FREEBUSY: %s", respBody)
	}
	// Should contain the January event time
	if !strings.Contains(respBody, "20250101T100000Z") {
		t.Errorf("free-busy-query: body does not contain January event time: %s", respBody)
	}
	// Should NOT contain the June event time
	if strings.Contains(respBody, "20250615") {
		t.Errorf("free-busy-query: body should not contain June event: %s", respBody)
	}
}

func TestFreeBusyQueryEmptyCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "EmptyCal", model.FolderTypeCalendar, "")

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<free-busy-query xmlns="urn:ietf:params:xml:ns:caldav">
 <time-range-start>20250101T000000Z</time-range-start>
 <time-range-end>20250131T235959Z</time-range-end>
</free-busy-query>`

	r := newRequest("REPORT", "/dav/alice/EmptyCal/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("free-busy-query empty: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	respBody := w.Body.String()
	// Should still return a valid VCALENDAR
	if !strings.Contains(respBody, "BEGIN:VCALENDAR") {
		t.Errorf("free-busy-query: body does not contain VCALENDAR: %s", respBody)
	}
	// Should not contain FREEBUSY entries
	if strings.Contains(respBody, "FREEBUSY;") {
		t.Errorf("free-busy-query: empty calendar should not have FREEBUSY entries: %s", respBody)
	}
}

func TestFreeBusyQueryAllDayEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT an all-day event
	r := newRequest("PUT", "/dav/alice/MyCal/allday.ics", sampleAllDayEvent)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT all-day event: status = %d", w.Code)
	}

	// Free-busy query for July 2025
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<free-busy-query xmlns="urn:ietf:params:xml:ns:caldav">
 <time-range-start>20250701T000000Z</time-range-start>
 <time-range-end>20250731T235959Z</time-range-end>
</free-busy-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("free-busy-query all-day: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "FREEBUSY") {
		t.Errorf("free-busy-query: body does not contain FREEBUSY for all-day event: %s", respBody)
	}
}

func TestFreeBusyQueryNonExistentCalendar(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<free-busy-query xmlns="urn:ietf:params:xml:ns:caldav">
 <time-range-start>20250101T000000Z</time-range-start>
 <time-range-end>20250131T235959Z</time-range-end>
</free-busy-query>`

	r := newRequest("REPORT", "/dav/alice/NoCal/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("free-busy-query non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestExtractIsAllDay(t *testing.T) {
	t.Parallel()
	if !extractIsAllDay([]byte(sampleAllDayEvent)) {
		t.Error("all-day event should be detected as all-day")
	}
	if extractIsAllDay([]byte(sampleVEVENT)) {
		t.Error("timed event should not be detected as all-day")
	}
}

// --- Schedule Inbox/Outbox Tests (RFC 7959) ---

var sampleiTIPRequest = `BEGIN:VCALENDAR
VERSION:2.0
METHOD:REQUEST
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:meeting-001@example.com
DTSTART:20250615T140000Z
DTEND:20250615T150000Z
SUMMARY:Team Meeting
ORGANIZER:mailto:bob@example.com
ATTENDEE:mailto:alice@example.com
END:VEVENT
END:VCALENDAR`

var sampleiTIPReply = `BEGIN:VCALENDAR
VERSION:2.0
METHOD:REPLY
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:meeting-001@example.com
DTSTART:20250615T140000Z
DTEND:20250615T150000Z
SUMMARY:Team Meeting
ORGANIZER:mailto:bob@example.com
ATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@example.com
END:VEVENT
END:VCALENDAR`

func TestScheduleInboxPutAndQuery(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT an iTIP REQUEST into the schedule inbox
	r := newRequest("PUT", "/dav/alice/schedule-inbox/req1.ics", sampleiTIPRequest)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT schedule-inbox: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Query the schedule inbox
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<schedule-inbox-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
</schedule-inbox-query>`

	r = newRequest("REPORT", "/dav/alice/schedule-inbox/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("schedule-inbox-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "schedule-inbox") {
		t.Errorf("schedule-inbox-query: body does not contain schedule-inbox: %s", respBody)
	}
}

func TestScheduleOutboxPutAndQuery(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT an iTIP REPLY into the schedule outbox
	r := newRequest("PUT", "/dav/alice/schedule-outbox/reply1.ics", sampleiTIPReply)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT schedule-outbox: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Query the schedule outbox
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<schedule-outbox-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
</schedule-outbox-query>`

	r = newRequest("REPORT", "/dav/alice/schedule-outbox/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("schedule-outbox-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "schedule-outbox") {
		t.Errorf("schedule-outbox-query: body does not contain schedule-outbox: %s", respBody)
	}
}

func TestExtractMethod(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		data   string
		expect string
	}{
		{"REQUEST", sampleiTIPRequest, "REQUEST"},
		{"REPLY", sampleiTIPReply, "REPLY"},
		{"CANCEL", "BEGIN:VCALENDAR\r\nMETHOD:CANCEL\r\nEND:VCALENDAR", "CANCEL"},
		{"none", "BEGIN:VCALENDAR\r\nEND:VCALENDAR", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMethod([]byte(tt.data))
			if got != tt.expect {
				t.Errorf("extractMethod = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestScheduleInboxEmpty(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Query an empty schedule inbox
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<schedule-inbox-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
</schedule-inbox-query>`

	r := newRequest("REPORT", "/dav/alice/schedule-inbox/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("schedule-inbox-query empty: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestScheduleOutboxEmpty(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Query an empty schedule outbox
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<schedule-outbox-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
   <D:getetag/>
 </D:prop>
</schedule-outbox-query>`

	r := newRequest("REPORT", "/dav/alice/schedule-outbox/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("schedule-outbox-query empty: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestScheduleInboxInvalidData(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT invalid data (no VCALENDAR) to schedule inbox
	r := newRequest("PUT", "/dav/alice/schedule-inbox/bad.ics", "not a calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT invalid to schedule-inbox: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- Scheduling Integration Tests ---

var sampleiTIPCancel = `BEGIN:VCALENDAR
VERSION:2.0
METHOD:CANCEL
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:meeting-001@example.com
DTSTART:20250615T140000Z
DTEND:20250615T150000Z
SUMMARY:Team Meeting
ORGANIZER:mailto:bob@example.com
SEQUENCE:1
END:VEVENT
END:VCALENDAR`

var sampleiTIPCounter = `BEGIN:VCALENDAR
VERSION:2.0
METHOD:COUNTER
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:meeting-002@example.com
DTSTART:20250615T160000Z
DTEND:20250615T170000Z
SUMMARY:Team Meeting Counter
ORGANIZER:mailto:alice@example.com
ATTENDEE;PARTSTAT=TENTATIVE:mailto:alice@example.com
END:VEVENT
END:VCALENDAR`

// TestScheduleInviteCreation tests the full flow of receiving a calendar invitation
// via schedule-inbox and having it processed into the user's calendar.
func TestScheduleInviteCreation(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT an iTIP REQUEST into the schedule inbox
	r := newRequest("PUT", "/dav/alice/schedule-inbox/invite1.ics", sampleiTIPRequest)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT schedule-inbox REQUEST: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify the event was created in the user's Calendar folder
	ctx := context.Background()
	calendar, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get Calendar folder: %v", err)
	}

	items, err := ts.ItemStore().List(ctx, calendar.ID)
	if err != nil {
		t.Fatalf("list calendar items: %v", err)
	}
	if len(items) == 0 {
		t.Error("expected event to be created in Calendar after schedule-inbox REQUEST")
	}

	// Verify the auto-generated reply was stored in schedule-outbox
	outbox, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleOutboxPath)
	if err != nil {
		t.Fatalf("get schedule-outbox: %v", err)
	}
	outboxItems, err := ts.ItemStore().List(ctx, outbox.ID)
	if err != nil {
		t.Fatalf("list outbox items: %v", err)
	}
	if len(outboxItems) == 0 {
		t.Error("expected auto-generated REPLY in schedule-outbox")
	}
}

// TestScheduleInviteAcceptance tests manually sending a REPLY to the schedule-inbox.
func TestScheduleInviteAcceptance(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a REPLY into the schedule inbox (simulating an attendee response)
	r := newRequest("PUT", "/dav/alice/schedule-inbox/reply1.ics", sampleiTIPReply)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT schedule-inbox REPLY: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify the reply was forwarded to schedule-outbox
	ctx := context.Background()
	outbox, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleOutboxPath)
	if err != nil {
		t.Fatalf("get schedule-outbox: %v", err)
	}
	outboxItems, err := ts.ItemStore().List(ctx, outbox.ID)
	if err != nil {
		t.Fatalf("list outbox items: %v", err)
	}
	if len(outboxItems) == 0 {
		t.Error("expected REPLY to be forwarded to schedule-outbox")
	}
}

// TestScheduleInviteDecline tests sending a DECLINED reply.
func TestScheduleInviteDecline(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Build a DECLINED reply
	msg, err := calendar.ParseITIP([]byte(sampleiTIPRequest))
	if err != nil {
		t.Fatalf("parse iTIP request: %v", err)
	}

	declinedReply, err := calendar.BuildReply(msg, "mailto:alice@example.com", calendar.PartStatDeclined)
	if err != nil {
		t.Fatalf("build declined reply: %v", err)
	}

	// PUT the declined reply into schedule-outbox
	r := newRequest("PUT", "/dav/alice/schedule-outbox/declined1.ics", string(declinedReply))
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT declined reply: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify the reply contains DECLINED
	if !strings.Contains(string(declinedReply), "PARTSTAT=DECLINED") {
		t.Error("declined reply should contain PARTSTAT=DECLINED")
	}
}

// TestScheduleCancel tests the cancellation flow.
func TestScheduleCancel(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	calendar, err := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	if err != nil {
		t.Fatalf("get Calendar folder: %v", err)
	}

	// First, create an event in the calendar (simulating a previous invite)
	itemID := sanitizeItemID("meeting-001@example.com")
	itemKey := model.ItemKey(calendar.ID, itemID)
	item := model.Item{
		ID:        itemKey,
		FolderID:  calendar.ID,
		Data:      []byte(sampleiTIPRequest),
		Headers:   map[string]string{"UID": "meeting-001@example.com"},
		Size:      int64(len(sampleiTIPRequest)),
		ModSeq:    1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := ts.ItemStore().SetItem(ctx, item); err != nil {
		t.Fatalf("create event: %v", err)
	}

	// Verify event exists
	_, err = ts.ItemStore().Get(ctx, itemKey)
	if err != nil {
		t.Fatalf("event should exist before cancel: %v", err)
	}

	// Now send a CANCEL to the schedule-inbox
	r := newRequest("PUT", "/dav/alice/schedule-inbox/cancel1.ics", sampleiTIPCancel)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT schedule-inbox CANCEL: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify the event was removed from the calendar
	_, err = ts.ItemStore().Get(ctx, itemKey)
	if err == nil {
		t.Error("event should be deleted after CANCEL")
	}
}

// TestScheduleCounter tests the COUNTER proposal flow.
func TestScheduleCounter(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Build a counter proposal
	msg, err := calendar.ParseITIP([]byte(sampleiTIPRequest))
	if err != nil {
		t.Fatalf("parse iTIP request: %v", err)
	}

	newStart, _ := time.Parse(time.RFC3339, "2025-06-15T16:00:00Z")
	newEnd, _ := time.Parse(time.RFC3339, "2025-06-15T17:00:00Z")
	counterData, err := calendar.BuildCounter(msg, "mailto:alice@example.com", newStart, newEnd)
	if err != nil {
		t.Fatalf("build counter: %v", err)
	}

	// Verify counter contains correct method and times
	if !strings.Contains(string(counterData), "METHOD:COUNTER") {
		t.Error("counter should contain METHOD:COUNTER")
	}
	if !strings.Contains(string(counterData), "20250615T160000Z") {
		t.Error("counter should contain new start time")
	}

	// PUT counter into schedule-outbox
	r := newRequest("PUT", "/dav/alice/schedule-outbox/counter1.ics", string(counterData))
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT counter: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}
}

// TestScheduleDeclineCounter tests the DECLINECOUNTER flow.
func TestScheduleDeclineCounter(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Parse the counter message
	counterMsg, err := calendar.ParseITIP([]byte(sampleiTIPCounter))
	if err != nil {
		t.Fatalf("parse counter: %v", err)
	}

	// Build a DECLINECOUNTER response
	declineCounterData, err := calendar.BuildDeclineCounter(counterMsg, "mailto:bob@example.com")
	if err != nil {
		t.Fatalf("build decline counter: %v", err)
	}

	// Verify it contains the correct method
	if !strings.Contains(string(declineCounterData), "METHOD:DECLINECOUNTER") {
		t.Error("decline counter should contain METHOD:DECLINECOUNTER")
	}

	// PUT into schedule-outbox
	r := newRequest("PUT", "/dav/alice/schedule-outbox/decline-counter1.ics", string(declineCounterData))
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT decline counter: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}
}

// TestScheduleInboxAutoCreate tests that schedule-inbox folder is auto-created on first PUT.
func TestScheduleInboxAutoCreate(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	// Delete the schedule-inbox folder if it exists (from default folders)
	siFolder, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleInboxPath)
	if err == nil {
		ts.FolderStore().Delete(ctx, siFolder.ID)
	}

	// PUT should auto-create the folder
	r := newRequest("PUT", "/dav/alice/schedule-inbox/test1.ics", sampleiTIPRequest)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT to auto-create schedule-inbox: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify folder was created
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleInboxPath)
	if err != nil {
		t.Fatalf("schedule-inbox should be auto-created: %v", err)
	}
	if folder.Type != model.FolderTypeScheduleInbox {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeScheduleInbox)
	}
}

// TestScheduleOutboxAutoCreate tests that schedule-outbox folder is auto-created on first PUT.
func TestScheduleOutboxAutoCreate(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	// Delete the schedule-outbox folder if it exists (from default folders)
	soFolder, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleOutboxPath)
	if err == nil {
		ts.FolderStore().Delete(ctx, soFolder.ID)
	}

	// PUT should auto-create the folder
	r := newRequest("PUT", "/dav/alice/schedule-outbox/test1.ics", sampleiTIPReply)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT to auto-create schedule-outbox: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify folder was created
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleOutboxPath)
	if err != nil {
		t.Fatalf("schedule-outbox should be auto-created: %v", err)
	}
	if folder.Type != model.FolderTypeScheduleOutbox {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeScheduleOutbox)
	}
}

// TestScheduleDefaultFolders tests that schedule-inbox and schedule-outbox
// are created as default folders for new users.
func TestScheduleDefaultFolders(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")

	ctx := context.Background()

	// Verify schedule-inbox exists
	siFolder, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleInboxPath)
	if err != nil {
		t.Fatalf("schedule-inbox should exist as default folder: %v", err)
	}
	if siFolder.Type != model.FolderTypeScheduleInbox {
		t.Errorf("schedule-inbox type = %q, want %q", siFolder.Type, model.FolderTypeScheduleInbox)
	}

	// Verify schedule-outbox exists
	soFolder, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleOutboxPath)
	if err != nil {
		t.Fatalf("schedule-outbox should exist as default folder: %v", err)
	}
	if soFolder.Type != model.FolderTypeScheduleOutbox {
		t.Errorf("schedule-outbox type = %q, want %q", soFolder.Type, model.FolderTypeScheduleOutbox)
	}
}

// TestScheduleMultitargetPut tests the calendar-multitarget PUT endpoint.
func TestScheduleMultitargetPut(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Send a calendar-multitarget PUT (REPORT with text/calendar body)
	r := newRequest("REPORT", "/dav/alice/", sampleiTIPRequest)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("calendar-multitarget PUT: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Verify the message was stored in schedule-outbox
	ctx := context.Background()
	outbox, err := ts.FolderStore().GetByPath(ctx, "alice", model.ScheduleOutboxPath)
	if err != nil {
		t.Fatalf("get schedule-outbox: %v", err)
	}
	outboxItems, err := ts.ItemStore().List(ctx, outbox.ID)
	if err != nil {
		t.Fatalf("list outbox items: %v", err)
	}
	if len(outboxItems) == 0 {
		t.Error("expected message in schedule-outbox after multitarget PUT")
	}
}

// TestScheduleUpdateEvent tests that a REQUEST with an existing UID updates the event.
func TestScheduleUpdateEvent(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()

	// First invite
	r := newRequest("PUT", "/dav/alice/schedule-inbox/invite1.ics", sampleiTIPRequest)
	r.Header.Set("Content-Type", "text/calendar")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("first PUT: status = %d", w.Code)
	}

	// Get the created event
	calendar, _ := ts.FolderStore().GetByPath(ctx, "alice", "Calendar")
	items, _ := ts.ItemStore().List(ctx, calendar.ID)
	if len(items) == 0 {
		t.Fatal("no events created after first invite")
	}
	event1, _ := ts.ItemStore().Get(ctx, items[0])
	originalModSeq := event1.ModSeq

	// Updated invite (same UID, higher sequence)
	updatedInvite := strings.Replace(sampleiTIPRequest, "Team Meeting", "Updated Meeting", 1)
	r = newRequest("PUT", "/dav/alice/schedule-inbox/invite1-updated.ics", updatedInvite)
	r.Header.Set("Content-Type", "text/calendar")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("updated PUT: status = %d", w.Code)
	}

	// Verify event was updated
	event2, err := ts.ItemStore().Get(ctx, items[0])
	if err != nil {
		t.Fatalf("get updated event: %v", err)
	}
	if event2.ModSeq <= originalModSeq {
		t.Errorf("event ModSeq should increase after update: got %d, want > %d", event2.ModSeq, originalModSeq)
	}
}

// TestScheduleOutboxResourcetype tests that schedule-outbox folder has correct resourcetype.
func TestScheduleOutboxResourcetype(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PROPFIND on schedule-outbox
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:resourcetype/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/schedule-outbox/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND schedule-outbox: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "schedule-outbox") {
		t.Errorf("PROPFIND should contain schedule-outbox resourcetype: %s", respBody)
	}
}

// TestScheduleInboxResourcetype tests that schedule-inbox folder has correct resourcetype.
func TestScheduleInboxResourcetype(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PROPFIND on schedule-inbox
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:resourcetype/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/schedule-inbox/", body)
	r.Header.Set("Depth", "0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND schedule-inbox: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "schedule-inbox") {
		t.Errorf("PROPFIND should contain schedule-inbox resourcetype: %s", respBody)
	}
}
