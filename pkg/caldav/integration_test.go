package caldav

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// --- Integration test helpers ---

// integrationTestSetup creates a typed store, user, and CalDAV handler for integration tests.
func integrationTestSetup(t *testing.T) (*model.TypedStore, *Handler, func()) {
	t.Helper()
	dir := t.TempDir()
	s, err := jsonstore.New(dir)
	if err != nil {
		t.Fatalf("create jsonstore: %v", err)
	}
	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()
	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %q: %v", ns, err)
		}
	}

	h := New(ts, nil)
	return ts, h, func() { s.Close() }
}

// startTestServer starts an HTTP server serving the CalDAV handler on a random port.
// Returns the server URL base (e.g. "http://127.0.0.1:12345").
func startTestServer(t *testing.T, h *Handler) (*httptest.Server, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Production wraps the handler in HTTP authentication that supplies the
		// acting user; model that for requests that carry no username in the path.
		if user, _, ok := r.BasicAuth(); ok {
			r = WithAuthenticatedUser(r, user)
		}
		h.ServeHTTP(w, r)
	}))
	return srv, func() { srv.Close() }
}

// createTestUser creates a user and default folders.
func createTestUser(t *testing.T, ts *model.TypedStore, username, password string) {
	t.Helper()
	ctx := context.Background()
	if err := ts.UserStore().Create(ctx, username, username, password); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	if err := ts.FolderStore().CreateForUser(ctx, username); err != nil {
		t.Fatalf("create folders for %s: %v", username, err)
	}
}

// newCalDAVClient creates a CalDAV client connected to the test server's /dav/ endpoint.
func newCalDAVClient(t *testing.T, srvURL, username, password string) *caldav.Client {
	t.Helper()
	// Endpoint is /dav/{username}/ so the client resolves paths relative to the user
	endpoint := strings.TrimSuffix(srvURL, "/") + "/dav/" + username + "/"
	httpClient := webdav.HTTPClientWithBasicAuth(nil, username, password)
	client, err := caldav.NewClient(httpClient, endpoint)
	if err != nil {
		t.Fatalf("create caldav client: %v", err)
	}
	return client
}

// newWebDAVClient creates a WebDAV client for lower-level operations.
func newWebDAVClient(t *testing.T, srvURL, username, password string) *webdav.Client {
	t.Helper()
	endpoint := strings.TrimSuffix(srvURL, "/") + "/dav/" + username + "/"
	httpClient := webdav.HTTPClientWithBasicAuth(nil, username, password)
	client, err := webdav.NewClient(httpClient, endpoint)
	if err != nil {
		t.Fatalf("create webdav client: %v", err)
	}
	return client
}

// buildICalEvent creates a simple iCalendar VEVENT for testing.
func buildICalEvent(uid string, dtStart, dtEnd time.Time, summary string) *ical.Calendar {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//Test//Integration//EN")

	event := ical.NewEvent()
	event.Props.SetText(ical.PropUID, uid)
	event.Props.SetDateTime(ical.PropDateTimeStart, dtStart)
	event.Props.SetDateTime(ical.PropDateTimeEnd, dtEnd)
	event.Props.SetText(ical.PropSummary, summary)
	event.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())

	cal.Children = append(cal.Children, event.Component)
	return cal
}

// --- Integration tests using go-webdav/caldav client ---

func TestIntegration_PutAndGetCalendarObject(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// Create a calendar folder
	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// Create an iCalendar event
	dtStart := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	dtEnd := time.Date(2025, 1, 15, 11, 0, 0, 0, time.UTC)
	cal := buildICalEvent("integration-test-001@example.com", dtStart, dtEnd, "Integration Test Event")

	// PUT the calendar object
	path := "/dav/alice/TestCal/event1.ics"
	co, err := client.PutCalendarObject(ctx, path, cal)
	if err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}
	if co.Path == "" {
		t.Error("PutCalendarObject: expected non-empty Path")
	}
	if co.ETag == "" {
		t.Error("PutCalendarObject: expected non-empty ETag")
	}

	// GET the calendar object back
	co2, err := client.GetCalendarObject(ctx, path)
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}
	if co2.Data == nil {
		t.Fatal("GetCalendarObject: returned nil Data")
	}

	// Verify the event summary
	summary, err := co2.Data.Children[0].Props.Text(ical.PropSummary)
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if summary != "Integration Test Event" {
		t.Errorf("summary = %q, want %q", summary, "Integration Test Event")
	}
}

func TestIntegration_QueryCalendar(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// PUT two events with different dates
	dtStart1 := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	dtEnd1 := time.Date(2025, 1, 15, 11, 0, 0, 0, time.UTC)
	cal1 := buildICalEvent("jan-event@example.com", dtStart1, dtEnd1, "January Event")
	if _, err := client.PutCalendarObject(ctx, "/dav/alice/TestCal/jan.ics", cal1); err != nil {
		t.Fatalf("PutCalendarObject (jan): %v", err)
	}

	dtStart2 := time.Date(2025, 6, 15, 14, 0, 0, 0, time.UTC)
	dtEnd2 := time.Date(2025, 6, 15, 15, 0, 0, 0, time.UTC)
	cal2 := buildICalEvent("june-event@example.com", dtStart2, dtEnd2, "June Event")
	if _, err := client.PutCalendarObject(ctx, "/dav/alice/TestCal/june.ics", cal2); err != nil {
		t.Fatalf("PutCalendarObject (june): %v", err)
	}

	// Query for events in January 2025
	query := &caldav.CalendarQuery{
		CompFilter: caldav.CompFilter{
			Name: "VCALENDAR",
			Comps: []caldav.CompFilter{{
				Name:  "VEVENT",
				Start: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
			}},
		},
	}

	results, err := client.QueryCalendar(ctx, "/dav/alice/TestCal/", query)
	if err != nil {
		t.Fatalf("QueryCalendar: %v", err)
	}

	// Should find the January event but not the June event
	if len(results) != 1 {
		t.Fatalf("QueryCalendar: got %d results, want 1", len(results))
	}

	summary, _ := results[0].Data.Children[0].Props.Text(ical.PropSummary)
	if summary != "January Event" {
		t.Errorf("QueryCalendar: summary = %q, want %q", summary, "January Event")
	}
}

func TestIntegration_QueryCalendarNoFilter(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// PUT an event
	dtStart := time.Date(2025, 3, 10, 9, 0, 0, 0, time.UTC)
	dtEnd := time.Date(2025, 3, 10, 10, 0, 0, 0, time.UTC)
	cal := buildICalEvent("march-event@example.com", dtStart, dtEnd, "March Event")
	if _, err := client.PutCalendarObject(ctx, "/dav/alice/TestCal/march.ics", cal); err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}

	// Query without time range — should return all events
	query := &caldav.CalendarQuery{
		CompFilter: caldav.CompFilter{
			Name: "VCALENDAR",
			Comps: []caldav.CompFilter{{
				Name: "VEVENT",
			}},
		},
	}

	results, err := client.QueryCalendar(ctx, "/dav/alice/TestCal/", query)
	if err != nil {
		t.Fatalf("QueryCalendar: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("QueryCalendar: got %d results, want 1", len(results))
	}
}

func TestIntegration_WebDAVStat(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// PUT an event using the CalDAV client
	caldavClient := newCalDAVClient(t, srv.URL, "alice", "pass123")
	dtStart := time.Date(2025, 5, 1, 12, 0, 0, 0, time.UTC)
	dtEnd := time.Date(2025, 5, 1, 13, 0, 0, 0, time.UTC)
	cal := buildICalEvent("stat-test@example.com", dtStart, dtEnd, "Stat Test")
	if _, err := caldavClient.PutCalendarObject(ctx, "/dav/alice/TestCal/stat.ics", cal); err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}

	// Use WebDAV client to stat the resource
	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")
	fi, err := wdavClient.Stat(ctx, "/dav/alice/TestCal/stat.ics")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if fi.Path != "/dav/alice/TestCal/stat.ics" {
		t.Errorf("Stat: path = %q, want %q", fi.Path, "/dav/alice/TestCal/stat.ics")
	}
	if fi.IsDir {
		t.Error("Stat: expected file, got directory")
	}
}

func TestIntegration_WebDAVReadDir(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// PUT multiple events
	for i := 0; i < 3; i++ {
		dtStart := time.Date(2025, 7, 1+i, 10, 0, 0, 0, time.UTC)
		dtEnd := time.Date(2025, 7, 1+i, 11, 0, 0, 0, time.UTC)
		cal := buildICalEvent("readir-test-001@example.com", dtStart, dtEnd, "Event")
		path := "/dav/alice/TestCal/event" + string(rune('A'+i)) + ".ics"
		if _, err := client.PutCalendarObject(ctx, path, cal); err != nil {
			t.Fatalf("PutCalendarObject %d: %v", i, err)
		}
	}

	// Use WebDAV client to list directory
	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")
	entries, err := wdavClient.ReadDir(ctx, "/dav/alice/TestCal/", false)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	// Should have at least 3 entries (the events we created)
	fileCount := 0
	for _, e := range entries {
		if !e.IsDir {
			fileCount++
		}
	}
	if fileCount < 3 {
		t.Errorf("ReadDir: found %d files, expected at least 3", fileCount)
	}
}

func TestIntegration_WebDAVRemoveAll(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")
	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")

	// PUT an event
	dtStart := time.Date(2025, 8, 1, 10, 0, 0, 0, time.UTC)
	dtEnd := time.Date(2025, 8, 1, 11, 0, 0, 0, time.UTC)
	cal := buildICalEvent("delete-test@example.com", dtStart, dtEnd, "Delete Test")
	path := "/dav/alice/TestCal/delete.ics"
	if _, err := client.PutCalendarObject(ctx, path, cal); err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}

	// Delete the event
	if err := wdavClient.RemoveAll(ctx, path); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	// Verify it's gone
	_, err := client.GetCalendarObject(ctx, path)
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestIntegration_FindCalendars(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// Create additional calendars
	if err := ts.FolderStore().Create(ctx, "alice", "WorkCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}
	if err := ts.FolderStore().Create(ctx, "alice", "PersonalCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// Use WebDAV ReadDir to list calendars at the user root
	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")
	entries, err := wdavClient.ReadDir(ctx, "/dav/alice/", false)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	// Count directories (calendars)
	dirCount := 0
	dirPaths := make(map[string]bool)
	for _, e := range entries {
		dirPaths[e.Path] = true
		if e.IsDir {
			dirCount++
		}
	}

	// Should find at least the calendars we created (default Calendar + WorkCal + PersonalCal)
	if dirCount < 3 {
		t.Errorf("ReadDir: found %d directories, expected at least 3 (paths: %v)", dirCount, dirPaths)
	}

	// The client resolves paths relative to the endpoint, so check for the expected suffixes
	foundCalendar := false
	foundWorkCal := false
	foundPersonalCal := false
	for p := range dirPaths {
		if strings.HasSuffix(p, "/Calendar") || strings.HasSuffix(p, "/Calendar/") {
			foundCalendar = true
		}
		if strings.HasSuffix(p, "/WorkCal") || strings.HasSuffix(p, "/WorkCal/") {
			foundWorkCal = true
		}
		if strings.HasSuffix(p, "/PersonalCal") || strings.HasSuffix(p, "/PersonalCal/") {
			foundPersonalCal = true
		}
	}

	if !foundCalendar {
		t.Error("ReadDir: missing default Calendar")
	}
	if !foundWorkCal {
		t.Error("ReadDir: missing WorkCal")
	}
	if !foundPersonalCal {
		t.Error("ReadDir: missing PersonalCal")
	}
}

func TestIntegration_MultiGetCalendar(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// PUT two events
	dtStart1 := time.Date(2025, 9, 1, 10, 0, 0, 0, time.UTC)
	dtEnd1 := time.Date(2025, 9, 1, 11, 0, 0, 0, time.UTC)
	cal1 := buildICalEvent("multiget-001@example.com", dtStart1, dtEnd1, "MultiGet Event 1")
	if _, err := client.PutCalendarObject(ctx, "/dav/alice/TestCal/mg1.ics", cal1); err != nil {
		t.Fatalf("PutCalendarObject 1: %v", err)
	}

	dtStart2 := time.Date(2025, 9, 2, 10, 0, 0, 0, time.UTC)
	dtEnd2 := time.Date(2025, 9, 2, 11, 0, 0, 0, time.UTC)
	cal2 := buildICalEvent("multiget-002@example.com", dtStart2, dtEnd2, "MultiGet Event 2")
	if _, err := client.PutCalendarObject(ctx, "/dav/alice/TestCal/mg2.ics", cal2); err != nil {
		t.Fatalf("PutCalendarObject 2: %v", err)
	}

	// MultiGet both events
	multiGet := &caldav.CalendarMultiGet{
		Paths: []string{
			"/dav/alice/TestCal/mg1.ics",
			"/dav/alice/TestCal/mg2.ics",
		},
	}

	results, err := client.MultiGetCalendar(ctx, "/dav/alice/TestCal/", multiGet)
	if err != nil {
		t.Fatalf("MultiGetCalendar: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("MultiGetCalendar: got %d results, want 2", len(results))
	}

	// Verify both events are returned
	summaries := make(map[string]bool)
	for _, r := range results {
		if r.Data != nil && len(r.Data.Children) > 0 {
			s, _ := r.Data.Children[0].Props.Text(ical.PropSummary)
			summaries[s] = true
		}
	}
	if !summaries["MultiGet Event 1"] {
		t.Error("MultiGetCalendar: missing MultiGet Event 1")
	}
	if !summaries["MultiGet Event 2"] {
		t.Error("MultiGetCalendar: missing MultiGet Event 2")
	}
}

func TestIntegration_PutCalendarObjectUpdate(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// PUT initial event
	dtStart := time.Date(2025, 10, 1, 10, 0, 0, 0, time.UTC)
	dtEnd := time.Date(2025, 10, 1, 11, 0, 0, 0, time.UTC)
	cal := buildICalEvent("update-test@example.com", dtStart, dtEnd, "Original Summary")
	path := "/dav/alice/TestCal/update.ics"
	if _, err := client.PutCalendarObject(ctx, path, cal); err != nil {
		t.Fatalf("PutCalendarObject (initial): %v", err)
	}

	// PUT updated event (same path, different summary)
	cal2 := buildICalEvent("update-test@example.com", dtStart, dtEnd, "Updated Summary")
	if _, err := client.PutCalendarObject(ctx, path, cal2); err != nil {
		t.Fatalf("PutCalendarObject (update): %v", err)
	}

	// GET and verify the update
	co, err := client.GetCalendarObject(ctx, path)
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}

	summary, _ := co.Data.Children[0].Props.Text(ical.PropSummary)
	if summary != "Updated Summary" {
		t.Errorf("summary = %q, want %q", summary, "Updated Summary")
	}
}

func TestIntegration_WebDAVCurrentUserPrincipal(t *testing.T) {
	// The account root is the principal; discovery clients depend on
	// current-user-principal being present there.
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")

	principal, err := wdavClient.FindCurrentUserPrincipal(ctx)
	if err != nil {
		t.Fatalf("FindCurrentUserPrincipal: %v", err)
	}
	if principal != "/dav/alice/" {
		t.Errorf("principal = %q, want /dav/alice/", principal)
	}
}

func TestIntegration_CalendarObjectETag(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "TestCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// PUT an event
	dtStart := time.Date(2025, 11, 1, 10, 0, 0, 0, time.UTC)
	dtEnd := time.Date(2025, 11, 1, 11, 0, 0, 0, time.UTC)
	cal := buildICalEvent("etag-test@example.com", dtStart, dtEnd, "ETag Test")
	path := "/dav/alice/TestCal/etag.ics"

	co, err := client.PutCalendarObject(ctx, path, cal)
	if err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}

	putETag := co.ETag
	if putETag == "" {
		t.Error("PutCalendarObject: expected non-empty ETag")
	}

	// GET and compare ETag
	co2, err := client.GetCalendarObject(ctx, path)
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}

	if co2.ETag != putETag {
		t.Errorf("ETag mismatch: PUT returned %q, GET returned %q", putETag, co2.ETag)
	}
}

func TestIntegration_QueryCalendarEmpty(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "EmptyCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCalDAVClient(t, srv.URL, "alice", "pass123")

	// Query empty calendar
	query := &caldav.CalendarQuery{
		CompFilter: caldav.CompFilter{
			Name: "VCALENDAR",
			Comps: []caldav.CompFilter{{
				Name:  "VEVENT",
				Start: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			}},
		},
	}

	results, err := client.QueryCalendar(ctx, "/dav/alice/EmptyCal/", query)
	if err != nil {
		t.Fatalf("QueryCalendar: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("QueryCalendar on empty calendar: got %d results, want 0", len(results))
	}
}

func TestIntegration_UserNotFound(t *testing.T) {
	_, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// Connect as a non-existent user
	client := newCalDAVClient(t, srv.URL, "nobody", "pass")

	ctx := context.Background()

	// Any operation should fail
	_, err := client.GetCalendarObject(ctx, "/dav/nobody/Cal/event.ics")
	if err == nil {
		t.Error("expected error for non-existent user, got nil")
	}
}

func TestIntegration_WebDAVCreateCalendar(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// Create a new calendar collection using MKCOL
	// Note: WebDAV client Mkdir uses MKCOL, which creates a files folder by default
	// For a calendar, we need to use the raw HTTP request
	req, err := http.NewRequest("MKCOL",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/NewCal",
		strings.NewReader(`<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
 <D:resourcetype>
  <C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/>
 </D:resourcetype>
</D:prop>`))
	if err != nil {
		t.Fatalf("create MKCOL request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("MKCOL request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Verify the calendar was created
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "NewCal")
	if err != nil {
		t.Fatalf("GetByPath after MKCOL: %v", err)
	}
	if folder.Type != model.FolderTypeCalendar {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeCalendar)
	}
}

// --- WebDAV File Storage Integration Tests ---

func TestIntegration_WebDAVFileUploadAndDownload(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// Create a files folder
	if err := ts.FolderStore().Create(ctx, "alice", "Documents", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload a file via PUT
	fileData := []byte("Hello, WebDAV file storage!")
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/Documents/hello.txt", strings.NewReader(string(fileData)))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp.Body.Close()

	// Verify ETag header is present
	if resp.Header.Get("ETag") == "" {
		t.Error("PUT: expected ETag header")
	}

	// Download the file via GET
	req2, err := http.NewRequest("GET", baseURL+"/dav/alice/Documents/hello.txt", nil)
	if err != nil {
		t.Fatalf("create GET request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET: status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}

	// Verify content type
	contentType := resp2.Header.Get("Content-Type")
	if contentType != "text/plain" && contentType != "text/plain; charset=utf-8" {
		t.Errorf("GET Content-Type = %q, want text/plain or text/plain; charset=utf-8", contentType)
	}

	// Verify content
	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("read GET body: %v", err)
	}
	if string(body) != string(fileData) {
		t.Errorf("GET body = %q, want %q", string(body), string(fileData))
	}

	// Verify ETag header
	if resp2.Header.Get("ETag") == "" {
		t.Error("GET: expected ETag header")
	}
}

func TestIntegration_WebDAVFileUploadContentTypeDetection(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "FilesCT", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload HTML content without explicit Content-Type
	htmlData := []byte("<html><body><h1>Test</h1></body></html>")
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesCT/page.html", strings.NewReader(string(htmlData)))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	// No Content-Type header — should be detected

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Download and verify detected content type
	req2, err := http.NewRequest("GET", baseURL+"/dav/alice/FilesCT/page.html", nil)
	if err != nil {
		t.Fatalf("create GET request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET request: %v", err)
	}
	defer resp2.Body.Close()

	contentType := resp2.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("GET Content-Type = %q, expected to contain text/html", contentType)
	}
}

func TestIntegration_WebDAVFileList(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "FilesList", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload multiple files
	files := map[string]string{
		"readme.txt":  "This is a readme",
		"notes.txt":   "Some notes",
		"config.json": `{"key": "value"}`,
	}

	for name, content := range files {
		req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesList/"+name, strings.NewReader(content))
		if err != nil {
			t.Fatalf("create PUT request for %s: %v", name, err)
		}
		req.SetBasicAuth("alice", "pass123")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT %s: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT %s: status = %d, want %d", name, resp.StatusCode, http.StatusCreated)
		}
	}

	// List files via PROPFIND
	req, err := http.NewRequest("PROPFIND", baseURL+"/dav/alice/FilesList/", strings.NewReader(`<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
   <D:displayname/>
   <D:getcontentlength/>
   <D:getcontenttype/>
   <D:getlastmodified/>
   <D:resourcetype/>
 </D:prop>
</D:propfind>`))
	if err != nil {
		t.Fatalf("create PROPFIND request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PROPFIND request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d, want %d", resp.StatusCode, http.StatusMultiStatus)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read PROPFIND body: %v", err)
	}

	bodyStr := string(body)

	// Verify all files are listed
	for name := range files {
		if !strings.Contains(bodyStr, name) {
			t.Errorf("PROPFIND response missing file %q in: %s", name, bodyStr)
		}
	}

	// Verify the collection itself is listed
	if !strings.Contains(bodyStr, "Files") {
		t.Errorf("PROPFIND response missing collection in: %s", bodyStr)
	}
}

func TestIntegration_WebDAVFileDelete(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "FilesDel", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload a file
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesDel/temp.txt", strings.NewReader("temporary"))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp.Body.Close()

	// Delete the file
	req2, err := http.NewRequest("DELETE", baseURL+"/dav/alice/FilesDel/temp.txt", nil)
	if err != nil {
		t.Fatalf("create DELETE request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("DELETE request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want %d", resp2.StatusCode, http.StatusNoContent)
	}

	// Verify it's gone
	req3, err := http.NewRequest("GET", baseURL+"/dav/alice/FilesDel/temp.txt", nil)
	if err != nil {
		t.Fatalf("create GET request: %v", err)
	}
	req3.SetBasicAuth("alice", "pass123")

	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET request: %v", err)
	}
	resp3.Body.Close()

	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE: status = %d, want %d", resp3.StatusCode, http.StatusNotFound)
	}
}

func TestIntegration_WebDAVFileMove(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// Create two file folders
	if err := ts.FolderStore().Create(ctx, "alice", "FolderA", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create FolderA: %v", err)
	}
	if err := ts.FolderStore().Create(ctx, "alice", "FolderB", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create FolderB: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload a file to FolderA
	fileData := []byte("move me to folder B")
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FolderA/move.txt", strings.NewReader(string(fileData)))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Move the file from FolderA to FolderB
	req2, err := http.NewRequest("MOVE", baseURL+"/dav/alice/FolderA/move.txt", nil)
	if err != nil {
		t.Fatalf("create MOVE request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")
	req2.Header.Set("Destination", baseURL+"/dav/alice/FolderB/move.txt")
	req2.Header.Set("Overwrite", "T")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("MOVE request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("MOVE: status = %d, want %d", resp2.StatusCode, http.StatusNoContent)
	}

	// Verify file is gone from FolderA
	req3, err := http.NewRequest("GET", baseURL+"/dav/alice/FolderA/move.txt", nil)
	if err != nil {
		t.Fatalf("create GET request: %v", err)
	}
	req3.SetBasicAuth("alice", "pass123")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("GET from source after MOVE: status = %d, want %d", resp3.StatusCode, http.StatusNotFound)
	}

	// Verify file exists in FolderB with correct content
	req4, err := http.NewRequest("GET", baseURL+"/dav/alice/FolderB/move.txt", nil)
	if err != nil {
		t.Fatalf("create GET request: %v", err)
	}
	req4.SetBasicAuth("alice", "pass123")
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("GET request: %v", err)
	}
	defer resp4.Body.Close()

	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("GET from dest after MOVE: status = %d, want %d", resp4.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp4.Body)
	if err != nil {
		t.Fatalf("read GET body: %v", err)
	}
	if string(body) != string(fileData) {
		t.Errorf("GET body after MOVE = %q, want %q", string(body), string(fileData))
	}
}

func TestIntegration_WebDAVFileMoveRename(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "FilesRename", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload a file
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesRename/old-name.txt", strings.NewReader("renamed file"))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	resp, err := http.DefaultClient.Do(req)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status = %v, err = %v", resp.StatusCode, err)
	}

	// Rename within the same folder
	req2, err := http.NewRequest("MOVE", baseURL+"/dav/alice/FilesRename/old-name.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.SetBasicAuth("alice", "pass123")
	req2.Header.Set("Destination", baseURL+"/dav/alice/FilesRename/new-name.txt")
	req2.Header.Set("Overwrite", "T")

	resp2, err := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if err != nil {
		t.Fatalf("MOVE request: %v", err)
	}
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("MOVE: status = %d, want %d", resp2.StatusCode, http.StatusNoContent)
	}

	// Verify old name is gone
	req3, _ := http.NewRequest("GET", baseURL+"/dav/alice/FilesRename/old-name.txt", nil)
	req3.SetBasicAuth("alice", "pass123")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET old name: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Error("old name should be gone after rename")
	}

	// Verify new name exists
	req4, _ := http.NewRequest("GET", baseURL+"/dav/alice/FilesRename/new-name.txt", nil)
	req4.SetBasicAuth("alice", "pass123")
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("GET new name: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("new name GET: status = %d, want %d", resp4.StatusCode, http.StatusOK)
	}
}

func TestIntegration_WebDAVFileSizeLimit(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "FilesLimit", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	// Set a small file size limit for testing (100 bytes)
	h.SetMaxWebdavFileSize(100)

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload a small file — should succeed
	smallData := []byte("small file content")
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesLimit/small.txt", strings.NewReader(string(smallData)))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.ContentLength = int64(len(smallData))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT small file: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Upload a large file — should be rejected with 413
	largeData := make([]byte, 200)
	for i := range largeData {
		largeData[i] = 'X'
	}
	req2, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesLimit/large.txt", bytes.NewReader(largeData))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")
	req2.ContentLength = int64(len(largeData))

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("PUT large file: status = %d, want %d (413)", resp2.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestIntegration_WebDAVFileCreateFolder(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Create a files folder via MKCOL (no body = files folder by default)
	req, err := http.NewRequest("MKCOL", baseURL+"/dav/alice/MyFiles", nil)
	if err != nil {
		t.Fatalf("create MKCOL request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("MKCOL request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// Verify the folder was created as a files type
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "MyFiles")
	if err != nil {
		t.Fatalf("GetByPath after MKCOL: %v", err)
	}
	if folder.Type != model.FolderTypeFiles {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeFiles)
	}

	// Verify we can upload a file to the new folder
	req2, err := http.NewRequest("PUT", baseURL+"/dav/alice/MyFiles/test.txt", strings.NewReader("test content"))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")
	resp2, err := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("PUT to new folder: status = %d, want %d", resp2.StatusCode, http.StatusCreated)
	}
}

func TestIntegration_WebDAVFileUpdate(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	if err := ts.FolderStore().Create(ctx, "alice", "FilesUpdate", model.FolderTypeFiles, ""); err != nil {
		t.Fatalf("create files folder: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	baseURL := strings.TrimSuffix(srv.URL, "/")

	// Upload initial content
	req, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesUpdate/doc.txt", strings.NewReader("version 1"))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	resp, err := http.DefaultClient.Do(req)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("initial PUT: status = %v, err = %v", resp.StatusCode, err)
	}

	// Update the file
	req2, err := http.NewRequest("PUT", baseURL+"/dav/alice/FilesUpdate/doc.txt", strings.NewReader("version 2 — updated content"))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req2.SetBasicAuth("alice", "pass123")
	resp2, err := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if err != nil {
		t.Fatalf("update PUT: %v", err)
	}
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("update PUT: status = %d, want %d", resp2.StatusCode, http.StatusNoContent)
	}

	// Verify the updated content
	req3, err := http.NewRequest("GET", baseURL+"/dav/alice/FilesUpdate/doc.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req3.SetBasicAuth("alice", "pass123")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET request: %v", err)
	}
	defer resp3.Body.Close()

	body, err := io.ReadAll(resp3.Body)
	if err != nil {
		t.Fatalf("read GET body: %v", err)
	}
	if string(body) != "version 2 — updated content" {
		t.Errorf("GET body = %q, want %q", string(body), "version 2 — updated content")
	}
}
