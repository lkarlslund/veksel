package caldav

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

// Regression tests in this file replay request sequences captured from real
// DAV clients (python caldav 3.6 with caldav-server-tester 1.6, vdirsyncer
// 0.21) and from the documented sequences of Apple Calendar/Contacts,
// Thunderbird, DAVx5, and Evolution during the 2026-10 interoperability audit.

type davReply struct {
	status int
	header http.Header
	body   string
}

// interopServer starts a DAV test server with the accounts alice and bob.
func interopServer(t *testing.T) string {
	t.Helper()
	ts, h, cleanup := integrationTestSetup(t)
	t.Cleanup(cleanup)
	for _, namespace := range []string{model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	createTestUser(t, ts, "alice", "pass123")
	createTestUser(t, ts, "bob", "pass456")
	srv, srvCleanup := startTestServer(t, h)
	t.Cleanup(srvCleanup)
	return strings.TrimSuffix(srv.URL, "/")
}

// davDo sends one request as alice unless an Authorization header is given.
func davDo(t *testing.T, method, url string, headers map[string]string, body string) davReply {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", "pass123")
	if body != "" {
		req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return davReply{status: resp.StatusCode, header: resp.Header, body: string(data)}
}

const interopEvent = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261105T090000Z\r\nDTEND:20261105T100000Z\r\nSUMMARY:%s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

// DAVx5 (dav4jvm) refuses a 207 whose Content-Type is not XML unless the
// body starts with an XML declaration; the PROPFIND, REPORT, and PROPPATCH
// multistatus replies were sent as text/plain without one.
func TestInteropMultistatusIsXML(t *testing.T) {
	base := interopServer(t)
	propfind := `<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getetag/></d:prop></d:propfind>`
	for _, target := range []string{"/dav/", "/dav/alice/", "/dav/alice/Calendar/"} {
		reply := davDo(t, "PROPFIND", base+target, map[string]string{"Depth": "1"}, propfind)
		if reply.status != http.StatusMultiStatus {
			t.Fatalf("PROPFIND %s status = %d: %s", target, reply.status, reply.body)
		}
		if ct := reply.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
			t.Fatalf("PROPFIND %s Content-Type = %q, want application/xml", target, ct)
		}
		if !strings.HasPrefix(reply.body, "<?xml") {
			t.Fatalf("PROPFIND %s body lacks an XML declaration: %.80s", target, reply.body)
		}
	}
	reply := davDo(t, "REPORT", base+"/dav/alice/Calendar/", nil, `<?xml version="1.0" encoding="utf-8"?><C:calendar-query xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"/></C:comp-filter></C:filter></C:calendar-query>`)
	if reply.status != http.StatusMultiStatus || !strings.HasPrefix(reply.header.Get("Content-Type"), "application/xml") {
		t.Fatalf("calendar-query status %d Content-Type %q", reply.status, reply.header.Get("Content-Type"))
	}
}

// Thunderbird, DAVx5, Apple, and python caldav create with
// If-None-Match: * and update or delete with If-Match: "<etag>" taken from
// the PUT reply. The handler ignored both headers (overwriting on create and
// recreating on If-Match: *) and returned an ETag the store never assigned,
// so GET, PROPFIND, and the next If-Match disagreed with the PUT reply.
func TestInteropConditionalWrites(t *testing.T) {
	base := interopServer(t)
	for _, tc := range []struct {
		name, url, contentType, body, changed string
	}{
		{"calendar", base + "/dav/alice/Calendar/cond.ics", "text/calendar; charset=utf-8",
			fmt.Sprintf(interopEvent, "cond-1", "First"), fmt.Sprintf(interopEvent, "cond-1", "Second")},
		{"contacts", base + "/dav/alice/Contacts/cond.vcf", "text/vcard; charset=utf-8",
			"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:cond-card\r\nFN:First\r\nN:First;;;;\r\nEND:VCARD\r\n",
			"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:cond-card\r\nFN:Second\r\nN:Second;;;;\r\nEND:VCARD\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := map[string]string{"Content-Type": tc.contentType}
			with := func(key, value string) map[string]string {
				return map[string]string{"Content-Type": tc.contentType, key: value}
			}
			if reply := davDo(t, http.MethodPut, tc.url, with("If-Match", "*"), tc.body); reply.status != http.StatusPreconditionFailed {
				t.Fatalf("If-Match: * on a missing object = %d, want 412", reply.status)
			}
			created := davDo(t, http.MethodPut, tc.url, with("If-None-Match", "*"), tc.body)
			if created.status != http.StatusCreated {
				t.Fatalf("create = %d: %s", created.status, created.body)
			}
			etag := created.header.Get("ETag")
			if got := davDo(t, http.MethodGet, tc.url, nil, "").header.Get("ETag"); got != etag {
				t.Fatalf("GET ETag %s differs from PUT ETag %s", got, etag)
			}
			if reply := davDo(t, http.MethodPut, tc.url, with("If-None-Match", "*"), tc.changed); reply.status != http.StatusPreconditionFailed {
				t.Fatalf("If-None-Match: * on an existing object = %d, want 412", reply.status)
			}
			if reply := davDo(t, http.MethodPut, tc.url, with("If-Match", `"stale"`), tc.changed); reply.status != http.StatusPreconditionFailed {
				t.Fatalf("stale If-Match = %d, want 412", reply.status)
			}
			updated := davDo(t, http.MethodPut, tc.url, with("If-Match", etag), tc.changed)
			if updated.status != http.StatusNoContent {
				t.Fatalf("If-Match update = %d: %s", updated.status, updated.body)
			}
			newETag := updated.header.Get("ETag")
			if newETag == etag {
				t.Fatalf("update kept ETag %s", etag)
			}
			get := davDo(t, http.MethodGet, tc.url, nil, "")
			if get.header.Get("ETag") != newETag || !strings.Contains(get.body, "Second") {
				t.Fatalf("GET after update: ETag %s (PUT said %s) body %s", get.header.Get("ETag"), newETag, get.body)
			}
			if reply := davDo(t, http.MethodPut, tc.url, ct, tc.body); reply.status != http.StatusNoContent {
				t.Fatalf("unconditional update = %d", reply.status)
			}
			if reply := davDo(t, http.MethodDelete, tc.url, map[string]string{"If-Match": newETag}, ""); reply.status != http.StatusPreconditionFailed {
				t.Fatalf("DELETE with stale If-Match = %d, want 412", reply.status)
			}
			current := davDo(t, http.MethodGet, tc.url, nil, "").header.Get("ETag")
			if reply := davDo(t, http.MethodDelete, tc.url, map[string]string{"If-Match": current}, ""); reply.status != http.StatusNoContent {
				t.Fatalf("DELETE with current If-Match = %d", reply.status)
			}
		})
	}
}

// Apple Calendar's principal probe and calendar-home Depth 1 listing, the
// DAVx5 service detection, and cadaver's empty-body PROPFIND. The handler
// answered every PROPFIND with a fixed property set in one 200 propstat
// (never reporting requested-but-missing properties as 404), rejected an
// empty body with 400, had no principal-URL, getctag, supported-report-set,
// or owner, gave every collection the same constant ETag, and answered a
// missing collection with 500.
func TestInteropPropfindDiscoveryProperties(t *testing.T) {
	base := interopServer(t)

	apple := `<?xml version="1.0" encoding="UTF-8"?>
<A:propfind xmlns:A="DAV:" xmlns:B="urn:ietf:params:xml:ns:caldav" xmlns:C="http://calendarserver.org/ns/">
  <A:prop><B:calendar-home-set/><A:principal-URL/><A:principal-collection-set/><A:displayname/><C:email-address-set/></A:prop>
</A:propfind>`
	reply := davDo(t, "PROPFIND", base+"/dav/alice/", map[string]string{"Depth": "0"}, apple)
	if reply.status != http.StatusMultiStatus {
		t.Fatalf("principal PROPFIND = %d", reply.status)
	}
	ok, missing, _ := strings.Cut(reply.body, "404 Not Found")
	for _, want := range []string{"<d:principal-URL><d:href>/dav/alice/</d:href>", "<d:principal-collection-set><d:href>/dav/</d:href>", "calendar-home-set", "<d:displayname>alice"} {
		if !strings.Contains(ok, want) {
			t.Fatalf("principal PROPFIND lacks %q in the 200 propstat: %s", want, reply.body)
		}
	}
	if strings.Contains(ok, "getetag") || strings.Contains(ok, "schedule-inbox-URL") {
		t.Fatalf("principal PROPFIND returned properties that were not requested: %s", reply.body)
	}
	if !strings.Contains(reply.body, "404 Not Found") || !strings.Contains(missing+ok[strings.LastIndex(ok, "<d:propstat>"):], "email-address-set") {
		t.Fatalf("an unknown requested property must be reported in a 404 propstat: %s", reply.body)
	}

	if reply := davDo(t, "PROPFIND", base+"/dav/alice/", map[string]string{"Depth": "0"}, ""); reply.status != http.StatusMultiStatus || !strings.Contains(reply.body, "calendar-home-set") {
		t.Fatalf("empty-body PROPFIND (allprop) = %d: %s", reply.status, reply.body)
	}
	names := davDo(t, "PROPFIND", base+"/dav/alice/", map[string]string{"Depth": "0"}, `<?xml version="1.0"?><propfind xmlns="DAV:"><propname/></propfind>`)
	if names.status != http.StatusMultiStatus || !strings.Contains(names.body, "displayname") || strings.Contains(names.body, ">alice<") {
		t.Fatalf("propname must list names without values: %s", names.body)
	}

	home := `<?xml version="1.0" encoding="UTF-8"?>
<A:propfind xmlns:A="DAV:" xmlns:B="urn:ietf:params:xml:ns:caldav" xmlns:C="http://calendarserver.org/ns/">
  <A:prop><C:getctag/><A:sync-token/><A:getetag/><A:resourcetype/><A:supported-report-set/><A:current-user-privilege-set/><A:owner/><B:supported-calendar-component-set/></A:prop>
</A:propfind>`
	ctagOf := func() string {
		listing := davDo(t, "PROPFIND", base+"/dav/alice/", map[string]string{"Depth": "1"}, home)
		if listing.status != http.StatusMultiStatus {
			t.Fatalf("home Depth 1 = %d", listing.status)
		}
		_, calendarPart, found := strings.Cut(listing.body, "<d:href>/dav/alice/Calendar/</d:href>")
		if !found {
			t.Fatalf("home listing lacks the Calendar collection: %s", listing.body)
		}
		calendarPart, _, _ = strings.Cut(calendarPart, "</d:response>")
		for _, want := range []string{"<CS:getctag>", "<d:sync-token>", "sync-collection", "calendar-multiget", "<d:write>", "<d:owner><d:href>/dav/alice/</d:href>"} {
			if !strings.Contains(calendarPart, want) {
				t.Fatalf("Calendar collection lacks %q: %s", want, calendarPart)
			}
		}
		if strings.Contains(calendarPart, "0000000000000000") {
			t.Fatalf("collection ETag must change with its contents: %s", calendarPart)
		}
		_, ctag, _ := strings.Cut(calendarPart, "<CS:getctag>")
		ctag, _, _ = strings.Cut(ctag, "</CS:getctag>")
		return ctag
	}
	before := ctagOf()
	if reply := davDo(t, http.MethodPut, base+"/dav/alice/Calendar/ctag.ics", map[string]string{"Content-Type": "text/calendar"}, fmt.Sprintf(interopEvent, "ctag-1", "Ctag")); reply.status != http.StatusCreated {
		t.Fatalf("PUT = %d", reply.status)
	}
	if after := ctagOf(); after == before {
		t.Fatalf("getctag %q did not change after a PUT", after)
	}

	if reply := davDo(t, "PROPFIND", base+"/dav/alice/NoSuchCalendar/", map[string]string{"Depth": "0"}, home); reply.status != http.StatusNotFound {
		t.Fatalf("PROPFIND on a missing collection = %d, want 404", reply.status)
	}
}

const interopWeekly = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\n" +
	"BEGIN:VEVENT\r\nUID:weekly-1\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261102T090000Z\r\nDTEND:20261102T100000Z\r\n" +
	"SUMMARY:Weekly\r\nRRULE:FREQ=WEEKLY;COUNT=6\r\nEXDATE:20261116T090000Z,20261123T090000Z\r\nEND:VEVENT\r\n" +
	"BEGIN:VEVENT\r\nUID:weekly-1\r\nDTSTAMP:20261021T120000Z\r\nRECURRENCE-ID:20261109T090000Z\r\nDTSTART:20261109T140000Z\r\nDTEND:20261109T150000Z\r\n" +
	"SUMMARY:Weekly moved\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

// calendar-query as DAVx5 (getetag with a VEVENT time-range), Thunderbird
// (VTODO with calendar-data), and python caldav (VJOURNAL, expand) send it.
// The handler ignored comp-filters other than VEVENT/VTODO, dropped getetag
// whenever calendar-data was requested, and answered a time-ranged query on
// a recurring event with one response per generated occurrence under the
// same href (RFC 4918 §14.24) even without expand, so clients stored a
// single occurrence as the event. expand ignored overridden instances.
func TestInteropCalendarQueryAsSentByClients(t *testing.T) {
	base := interopServer(t)
	cal := base + "/dav/alice/Calendar/"
	put := func(url, body string) {
		t.Helper()
		if reply := davDo(t, http.MethodPut, url, map[string]string{"Content-Type": "text/calendar"}, body); reply.status != http.StatusCreated {
			t.Fatalf("PUT %s = %d: %s", url, reply.status, reply.body)
		}
	}
	put(cal+"weekly.ics", interopWeekly)
	put(cal+"single.ics", fmt.Sprintf(interopEvent, "single-1", "Single"))
	if reply := davDo(t, "MKCOL", base+"/dav/alice/todo/", nil, `<?xml version="1.0" encoding="utf-8"?><D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop><D:resourcetype><D:collection/><C:calendar/></D:resourcetype><C:supported-calendar-component-set><C:comp name="VTODO"/></C:supported-calendar-component-set></D:prop></D:set></D:mkcol>`); reply.status != http.StatusCreated {
		t.Fatalf("MKCOL task list = %d: %s", reply.status, reply.body)
	}
	put(base+"/dav/alice/todo/task.ics", "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VTODO\r\nUID:task-1\r\nDTSTAMP:20261021T120000Z\r\nSUMMARY:Task\r\nEND:VTODO\r\nEND:VCALENDAR\r\n")

	query := func(url, prop, filter string) string {
		t.Helper()
		reply := davDo(t, "REPORT", url, map[string]string{"Depth": "1"}, `<?xml version="1.0" encoding="utf-8"?><C:calendar-query xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop>`+prop+`</d:prop><C:filter><C:comp-filter name="VCALENDAR">`+filter+`</C:comp-filter></C:filter></C:calendar-query>`)
		if reply.status != http.StatusMultiStatus {
			t.Fatalf("calendar-query = %d: %s", reply.status, reply.body)
		}
		return reply.body
	}

	davx5 := query(cal, `<d:getetag/>`, `<C:comp-filter name="VEVENT"><C:time-range start="20261101T000000Z" end="20261201T000000Z"/></C:comp-filter>`)
	if n := strings.Count(davx5, "<d:response>"); n != 2 {
		t.Fatalf("DAVx5 time-range query returned %d responses for 2 objects: %s", n, davx5)
	}
	if strings.Contains(davx5, "calendar-data") {
		t.Fatalf("calendar-data was returned without being requested: %s", davx5)
	}

	full := query(cal, `<d:getetag/><C:calendar-data/>`, `<C:comp-filter name="VEVENT"><C:time-range start="20261101T000000Z" end="20261201T000000Z"/></C:comp-filter>`)
	if strings.Count(full, "<d:response>") != 2 || strings.Count(full, "<d:getetag>") != 2 {
		t.Fatalf("each object needs one response with getetag and calendar-data: %s", full)
	}
	if !strings.Contains(full, "RRULE:FREQ=WEEKLY") {
		t.Fatalf("without expand the stored recurring object must be returned: %s", full)
	}

	if journal := query(cal, `<d:getetag/>`, `<C:comp-filter name="VJOURNAL"/>`); strings.Contains(journal, "<d:response>") {
		t.Fatalf("a VJOURNAL query matched events: %s", journal)
	}
	if todos := query(cal, `<d:getetag/>`, `<C:comp-filter name="VTODO"/>`); strings.Contains(todos, "<d:response>") {
		t.Fatalf("a VTODO query matched events: %s", todos)
	}
	if tasks := query(base+"/dav/alice/todo/", `<d:getetag/><C:calendar-data/>`, `<C:comp-filter name="VTODO"/>`); !strings.Contains(tasks, "<d:getetag>") || !strings.Contains(tasks, "SUMMARY:Task") {
		t.Fatalf("Thunderbird VTODO query: %s", tasks)
	}

	expanded := query(cal, `<d:getetag/><C:calendar-data><C:expand start="20261101T000000Z" end="20261201T000000Z"/></C:calendar-data>`,
		`<C:comp-filter name="VEVENT"><C:time-range start="20261101T000000Z" end="20261201T000000Z"/></C:comp-filter>`)
	_, weekly, _ := strings.Cut(expanded, "weekly.ics</d:href>")
	weekly, _, _ = strings.Cut(weekly, "</d:response>")
	// 2, 9, 16, 23, and 30 Nov fall in the range; 16 and 23 are EXDATEs and
	// the 9 Nov instance is overridden.
	if n := strings.Count(weekly, "RECURRENCE-ID"); n != 3 {
		t.Fatalf("expand returned %d instances, want 3: %s", n, weekly)
	}
	if strings.Contains(weekly, "RRULE") || strings.Contains(weekly, "EXDATE") || !strings.Contains(weekly, "Weekly moved") || !strings.Contains(weekly, "DTSTART:20261109T140000Z") {
		t.Fatalf("expanded instances must drop the rule and carry the override: %s", weekly)
	}
	if strings.Count(weekly, "BEGIN:VCALENDAR") != 1 {
		t.Fatalf("expanded instances belong in one VCALENDAR: %s", weekly)
	}

	multiget := davDo(t, "REPORT", cal, nil, `<?xml version="1.0" encoding="utf-8"?><C:calendar-multiget xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><C:calendar-data><C:expand start="20261101T000000Z" end="20261110T000000Z"/></C:calendar-data></d:prop><d:href>/dav/alice/Calendar/weekly.ics</d:href></C:calendar-multiget>`)
	if n := strings.Count(multiget.body, "RECURRENCE-ID"); multiget.status != http.StatusMultiStatus || n != 2 {
		t.Fatalf("multiget expand returned %d instances, want 2: %s", n, multiget.body)
	}
}

// DAVx5's sync-collection sequence: initial sync, incremental sync with an
// update and a delete, and an expired token. An invalid token was answered
// with 409 instead of RFC 6578's 403 valid-sync-token (DAVx5 and python
// caldav restart the sync only on 403), a member changed twice was listed
// twice, a DAV:limit was ignored on the initial sync, the token was not a
// URI, and vCards were described as text/calendar.
func TestInteropSyncCollectionAsSentByDAVx5(t *testing.T) {
	base := interopServer(t)
	syncReport := func(url, token, limit string) davReply {
		t.Helper()
		return davDo(t, "REPORT", url, map[string]string{"Depth": "1"}, `<?xml version="1.0" encoding="UTF-8"?>
<sync-collection xmlns="DAV:"><sync-token>`+token+`</sync-token><sync-level>1</sync-level>`+limit+`<prop><getetag/><getcontenttype/></prop></sync-collection>`)
	}
	tokenOf := func(body string) string {
		_, token, _ := strings.Cut(body, "<d:sync-token>")
		token, _, _ = strings.Cut(token, "</d:sync-token>")
		return token
	}
	for _, tc := range []struct{ collection, name, contentType, body, changed, mime string }{
		{"Calendar", "a.ics", "text/calendar", fmt.Sprintf(interopEvent, "sync-a", "A"), fmt.Sprintf(interopEvent, "sync-a", "A2"), "text/calendar"},
		{"Contacts", "a.vcf", "text/vcard", "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:sync-a\r\nFN:A\r\nEND:VCARD\r\n", "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:sync-a\r\nFN:A2\r\nEND:VCARD\r\n", "text/vcard"},
	} {
		t.Run(tc.collection, func(t *testing.T) {
			url := base + "/dav/alice/" + tc.collection + "/"
			put := func(name, body string) {
				if reply := davDo(t, http.MethodPut, url+name, map[string]string{"Content-Type": tc.contentType}, body); reply.status/100 != 2 {
					t.Fatalf("PUT %s = %d", name, reply.status)
				}
			}
			put(tc.name, tc.body)
			put("b-"+tc.name, strings.ReplaceAll(tc.body, "sync-a", "sync-b"))

			initial := syncReport(url, "", "")
			token := tokenOf(initial.body)
			if initial.status != http.StatusMultiStatus || strings.Count(initial.body, "<d:response>") != 2 || !strings.HasPrefix(token, "urn:") {
				t.Fatalf("initial sync = %d token %q: %s", initial.status, token, initial.body)
			}
			if !strings.Contains(initial.body, "<d:getcontenttype>"+tc.mime) {
				t.Fatalf("members must be described as %s: %s", tc.mime, initial.body)
			}
			if limited := syncReport(url, "", "<limit><nresults>1</nresults></limit>"); limited.status != http.StatusInsufficientStorage || !strings.Contains(limited.body, "number-of-matches-within-limits") {
				t.Fatalf("initial sync beyond DAV:limit = %d: %s", limited.status, limited.body)
			}

			put(tc.name, tc.changed)
			put(tc.name, tc.body)
			if reply := davDo(t, http.MethodDelete, url+"b-"+tc.name, nil, ""); reply.status != http.StatusNoContent {
				t.Fatalf("DELETE = %d", reply.status)
			}
			incremental := syncReport(url, token, "")
			if incremental.status != http.StatusMultiStatus {
				t.Fatalf("incremental sync = %d: %s", incremental.status, incremental.body)
			}
			if n := strings.Count(incremental.body, "/"+tc.name+"</d:href>"); n != 1 {
				t.Fatalf("a member changed twice must be listed once, got %d: %s", n, incremental.body)
			}
			_, deleted, _ := strings.Cut(incremental.body, "b-"+tc.name+"</d:href>")
			if !strings.HasPrefix(strings.TrimSpace(deleted), "<d:status>HTTP/1.1 404 Not Found") {
				t.Fatalf("the deleted member must be reported 404: %s", incremental.body)
			}
			if next := tokenOf(incremental.body); next == token || next == "" {
				t.Fatalf("incremental sync must return a new token, got %q", next)
			}

			for _, invalid := range []string{"http://example.invalid/never-issued", "0000000000000000000000000000000000000000"} {
				reply := syncReport(url, invalid, "")
				if reply.status != http.StatusForbidden || !strings.Contains(reply.body, "valid-sync-token") {
					t.Fatalf("invalid token %q = %d, want 403 valid-sync-token: %s", invalid, reply.status, reply.body)
				}
			}
		})
	}
}

// Apple Calendar and Evolution create calendars with MKCALENDAR carrying a
// display name, color, order, and component set; Apple, Thunderbird, and
// DAVx5 rename and recolor with PROPPATCH. MKCALENDAR was answered 405,
// MKCOL dropped every property, and PROPPATCH replied 200 without storing
// anything, so the next PROPFIND showed the old name.
func TestInteropCollectionCreationAndProppatch(t *testing.T) {
	base := interopServer(t)
	propfind := `<?xml version="1.0" encoding="UTF-8"?><A:propfind xmlns:A="DAV:" xmlns:B="urn:ietf:params:xml:ns:caldav" xmlns:E="http://apple.com/ns/ical/"><A:prop><A:displayname/><E:calendar-color/><E:calendar-order/><B:calendar-description/><B:supported-calendar-component-set/><A:resourcetype/></A:prop></A:propfind>`
	props := func(url string) string {
		t.Helper()
		reply := davDo(t, "PROPFIND", url, map[string]string{"Depth": "0"}, propfind)
		if reply.status != http.StatusMultiStatus {
			t.Fatalf("PROPFIND %s = %d", url, reply.status)
		}
		ok, _, _ := strings.Cut(reply.body, "200 OK")
		return ok
	}

	url := base + "/dav/alice/7E1A2C34-58B0-4C3A-9A51-2C1F0C1D8E10/"
	reply := davDo(t, "MKCALENDAR", url, nil, `<?xml version="1.0" encoding="UTF-8"?>
<B:mkcalendar xmlns:A="DAV:" xmlns:B="urn:ietf:params:xml:ns:caldav" xmlns:D="http://apple.com/ns/ical/">
  <A:set><A:prop>
    <A:displayname>Work ✓</A:displayname>
    <D:calendar-color symbolic-color="custom">#63DA38FF</D:calendar-color>
    <D:calendar-order>3</D:calendar-order>
    <B:calendar-description>Shared team calendar</B:calendar-description>
    <B:supported-calendar-component-set><B:comp name="VEVENT"/></B:supported-calendar-component-set>
    <B:calendar-timezone>BEGIN:VCALENDAR&#13;
END:VCALENDAR&#13;
</B:calendar-timezone>
  </A:prop></A:set>
</B:mkcalendar>`)
	if reply.status != http.StatusCreated {
		t.Fatalf("MKCALENDAR = %d: %s", reply.status, reply.body)
	}
	created := props(url)
	for _, want := range []string{"<d:displayname>Work ✓</d:displayname>", "<IC:calendar-color>#63DA38FF</IC:calendar-color>", "<IC:calendar-order>3</IC:calendar-order>", "Shared team calendar", "<C:calendar>", `name="VEVENT"`} {
		if !strings.Contains(created, want) {
			t.Fatalf("created calendar lacks %q: %s", want, created)
		}
	}

	// Apple Reminders creates task lists the same way.
	tasks := base + "/dav/alice/reminders-1/"
	if reply := davDo(t, "MKCALENDAR", tasks, nil, `<?xml version="1.0" encoding="UTF-8"?><C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop><D:displayname>Groceries</D:displayname><C:supported-calendar-component-set><C:comp name="VTODO"/></C:supported-calendar-component-set></D:prop></D:set></C:mkcalendar>`); reply.status != http.StatusCreated {
		t.Fatalf("MKCALENDAR task list = %d: %s", reply.status, reply.body)
	}
	if list := props(tasks); !strings.Contains(list, `name="VTODO"`) || !strings.Contains(list, "Groceries") {
		t.Fatalf("task list: %s", list)
	}
	if reply := davDo(t, "MKCALENDAR", tasks, nil, ""); reply.status/100 == 2 {
		t.Fatalf("MKCALENDAR on an existing collection = %d", reply.status)
	}

	patch := davDo(t, "PROPPATCH", url, nil, `<?xml version="1.0" encoding="UTF-8"?>
<A:propertyupdate xmlns:A="DAV:" xmlns:D="http://apple.com/ns/ical/" xmlns:B="urn:ietf:params:xml:ns:caldav">
  <A:set><A:prop><A:displayname>Renamed</A:displayname><D:calendar-color>#FF2968</D:calendar-color><D:calendar-order>1</D:calendar-order></A:prop></A:set>
  <A:remove><A:prop><B:calendar-description/></A:prop></A:remove>
</A:propertyupdate>`)
	if patch.status != http.StatusMultiStatus || strings.Count(patch.body, "HTTP/1.1 200 OK") != 1 || strings.Contains(patch.body, "403") {
		t.Fatalf("PROPPATCH = %d: %s", patch.status, patch.body)
	}
	renamed := props(url)
	if !strings.Contains(renamed, "<d:displayname>Renamed</d:displayname>") || !strings.Contains(renamed, "#FF2968") || !strings.Contains(renamed, "<IC:calendar-order>1<") || strings.Contains(renamed, "Shared team calendar") {
		t.Fatalf("PROPPATCH was not persisted: %s", renamed)
	}
	if !strings.Contains(url, "7E1A2C34") || davDo(t, "PROPFIND", url, map[string]string{"Depth": "0"}, propfind).status != http.StatusMultiStatus {
		t.Fatal("renaming must keep the collection URL")
	}

	// A protected property fails the whole update (RFC 4918 §9.2).
	protected := davDo(t, "PROPPATCH", url, nil, `<?xml version="1.0" encoding="UTF-8"?><A:propertyupdate xmlns:A="DAV:" xmlns:B="urn:ietf:params:xml:ns:caldav"><A:set><A:prop><A:displayname>Nope</A:displayname><B:supported-calendar-component-set><B:comp name="VTODO"/></B:supported-calendar-component-set></A:prop></A:set></A:propertyupdate>`)
	if !strings.Contains(protected.body, "403 Forbidden") || !strings.Contains(protected.body, "424 Failed Dependency") {
		t.Fatalf("protected PROPPATCH: %s", protected.body)
	}
	if strings.Contains(props(url), "Nope") {
		t.Fatal("a failed PROPPATCH must not apply its other properties")
	}
	// caldav-server-tester sets a named color; it is refused per property
	// rather than accepted, and later requests still work.
	named := davDo(t, "PROPPATCH", url, nil, `<?xml version="1.0" encoding="UTF-8"?><A:propertyupdate xmlns:A="DAV:" xmlns:D="http://apple.com/ns/ical/"><A:set><A:prop><D:calendar-color>red</D:calendar-color></A:prop></A:set></A:propertyupdate>`)
	if named.status != http.StatusMultiStatus || !strings.Contains(named.body, "409 Conflict") {
		t.Fatalf("named color PROPPATCH: %d %s", named.status, named.body)
	}
	if !strings.Contains(props(url), "#FF2968") {
		t.Fatal("a refused color must leave the stored one")
	}

	// Thunderbird renames an address book; RFC 5689 extended MKCOL creates one.
	book := base + "/dav/alice/team-book/"
	if reply := davDo(t, "MKCOL", book, nil, `<?xml version="1.0" encoding="UTF-8"?><D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:set><D:prop><D:resourcetype><D:collection/><C:addressbook/></D:resourcetype><D:displayname>Team</D:displayname><C:addressbook-description>People</C:addressbook-description></D:prop></D:set></D:mkcol>`); reply.status != http.StatusCreated {
		t.Fatalf("extended MKCOL = %d: %s", reply.status, reply.body)
	}
	listing := davDo(t, "PROPFIND", book, map[string]string{"Depth": "0"}, `<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><D:displayname/><C:addressbook-description/><D:resourcetype/></D:prop></D:propfind>`)
	if !strings.Contains(listing.body, "<d:displayname>Team</d:displayname>") || !strings.Contains(listing.body, "People") || !strings.Contains(listing.body, "addressbook") {
		t.Fatalf("extended MKCOL properties: %s", listing.body)
	}
}

// Apple Calendar moves an event to another calendar with MOVE and an
// absolute-URL Destination; cadaver and Finder send absolute paths. MOVE
// and COPY of calendar objects and vCards answered 204 and did nothing, so
// the event stayed in the source calendar.
func TestInteropMoveAndCopyObjects(t *testing.T) {
	base := interopServer(t)
	if reply := davDo(t, "MKCALENDAR", base+"/dav/alice/work/", nil, ""); reply.status != http.StatusCreated {
		t.Fatalf("MKCALENDAR = %d", reply.status)
	}
	src := base + "/dav/alice/Calendar/move.ics"
	if reply := davDo(t, http.MethodPut, src, map[string]string{"Content-Type": "text/calendar"}, fmt.Sprintf(interopEvent, "move-1", "Move me")); reply.status != http.StatusCreated {
		t.Fatalf("PUT = %d", reply.status)
	}

	moved := davDo(t, "MOVE", src, map[string]string{"Destination": base + "/dav/alice/work/move.ics", "Overwrite": "F"}, "")
	if moved.status != http.StatusCreated {
		t.Fatalf("MOVE = %d: %s", moved.status, moved.body)
	}
	if reply := davDo(t, http.MethodGet, src, nil, ""); reply.status != http.StatusNotFound {
		t.Fatalf("the source still exists after MOVE: %d", reply.status)
	}
	got := davDo(t, http.MethodGet, base+"/dav/alice/work/move.ics", nil, "")
	if got.status != http.StatusOK || !strings.Contains(got.body, "Move me") || got.header.Get("ETag") != moved.header.Get("ETag") {
		t.Fatalf("destination after MOVE: %d ETag %s (MOVE said %s)", got.status, got.header.Get("ETag"), moved.header.Get("ETag"))
	}

	copied := davDo(t, "COPY", base+"/dav/alice/work/move.ics", map[string]string{"Destination": "/dav/alice/Calendar/copy.ics"}, "")
	if copied.status != http.StatusCreated {
		t.Fatalf("COPY with an absolute-path Destination = %d: %s", copied.status, copied.body)
	}
	for _, url := range []string{base + "/dav/alice/work/move.ics", base + "/dav/alice/Calendar/copy.ics"} {
		if reply := davDo(t, http.MethodGet, url, nil, ""); reply.status != http.StatusOK {
			t.Fatalf("GET %s after COPY = %d", url, reply.status)
		}
	}
	if reply := davDo(t, "COPY", base+"/dav/alice/work/move.ics", map[string]string{"Destination": "/dav/alice/Calendar/copy.ics", "Overwrite": "F"}, ""); reply.status != http.StatusPreconditionFailed {
		t.Fatalf("COPY onto an existing object with Overwrite: F = %d, want 412", reply.status)
	}
	if reply := davDo(t, "MOVE", base+"/dav/alice/work/move.ics", map[string]string{"Destination": "/dav/alice/Contacts/move.vcf"}, ""); reply.status != http.StatusForbidden {
		t.Fatalf("MOVE of an event into an address book = %d, want 403", reply.status)
	}
	if reply := davDo(t, "MOVE", base+"/dav/alice/work/", map[string]string{"Destination": "/dav/alice/renamed/"}, ""); reply.status/100 == 2 {
		t.Fatalf("MOVE of a collection must not claim success: %d", reply.status)
	}
}

// Collections and objects with spaces and non-ASCII names, as Apple and
// Evolution create them. Hrefs and Location were emitted with raw spaces and
// UTF-8 (not URI references, so NSURL and okhttp cannot resolve them), and
// a multiget naming the percent-encoded href the client was given found
// nothing. A byte order mark was stored and served back, and an ISO-8859-1
// body was served as UTF-8 unchanged.
func TestInteropNonASCIINamesAndCharsets(t *testing.T) {
	base := interopServer(t)
	calendar := "/dav/alice/Kalender%20%C3%A6%C3%B8%C3%A5/"
	object := calendar + "m%C3%B8de%20%C3%A9n.ics"
	if reply := davDo(t, "MKCALENDAR", base+calendar, nil, ""); reply.status != http.StatusCreated || reply.header.Get("Location") != calendar {
		t.Fatalf("MKCALENDAR = %d Location %q", reply.status, reply.header.Get("Location"))
	}
	put := davDo(t, http.MethodPut, base+object, map[string]string{"Content-Type": "text/calendar; charset=utf-8"}, "\ufeff"+fmt.Sprintf(interopEvent, "nonascii-1", "Møde på dansk"))
	if put.status != http.StatusCreated || put.header.Get("Location") != object {
		t.Fatalf("PUT = %d Location %q", put.status, put.header.Get("Location"))
	}
	if got := davDo(t, http.MethodGet, base+object, nil, ""); !strings.HasPrefix(got.body, "BEGIN:VCALENDAR") || !strings.Contains(got.body, "Møde på dansk") {
		t.Fatalf("GET must return the object without a byte order mark: %q", got.body[:20])
	}
	listing := davDo(t, "PROPFIND", base+calendar, map[string]string{"Depth": "1"}, `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:displayname/></d:prop></d:propfind>`)
	for _, want := range []string{"<d:href>" + calendar + "</d:href>", "<d:href>" + object + "</d:href>", "<d:displayname>Kalender æøå</d:displayname>"} {
		if !strings.Contains(listing.body, want) {
			t.Fatalf("listing lacks %q: %s", want, listing.body)
		}
	}
	multiget := davDo(t, "REPORT", base+calendar, nil, `<?xml version="1.0"?><C:calendar-multiget xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><C:calendar-data/></d:prop><d:href>`+object+`</d:href></C:calendar-multiget>`)
	if strings.Contains(multiget.body, "404") || !strings.Contains(multiget.body, "Møde på dansk") {
		t.Fatalf("multiget of the encoded href: %s", multiget.body)
	}

	latin1 := []byte(fmt.Sprintf(interopEvent, "latin1-1", "Caf\xe9"))
	if reply := davDo(t, http.MethodPut, base+"/dav/alice/Calendar/latin1.ics", map[string]string{"Content-Type": "text/calendar; charset=ISO-8859-1"}, string(latin1)); reply.status != http.StatusCreated {
		t.Fatalf("PUT latin-1 = %d", reply.status)
	}
	if got := davDo(t, http.MethodGet, base+"/dav/alice/Calendar/latin1.ics", nil, ""); !strings.Contains(got.body, "SUMMARY:Café") {
		t.Fatalf("an ISO-8859-1 body must be served as UTF-8: %q", got.body)
	}
}

// A calendar shared read-only with bob, added in DAVx5 by its collection
// URL: getctag and sync-token were missing and sync-collection failed with
// 500, because the change state was read as if bob were acting as alice.
func TestInteropSharedCalendarSync(t *testing.T) {
	ts := testStoreSetup(t)
	for _, namespace := range []string{model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	testUser(t, ts, "alice", "password123")
	testUser(t, ts, "bob", "password123")
	handler := New(ts, &Config{Authorizer: authz.New(ts)})
	serve := func(actor, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		request := WithAuthenticatedUser(newRequest(method, path, body), actor)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	if reply := serve("alice", http.MethodPut, "/dav/alice/Calendar/shared.ics", fmt.Sprintf(interopEvent, "shared-1", "Shared"), map[string]string{"Content-Type": "text/calendar"}); reply.Code != http.StatusCreated {
		t.Fatalf("PUT = %d", reply.Code)
	}
	if _, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceFolder, ID: model.FolderKey("alice", "Calendar")},
		Effect:    model.EffectAllow, RoleID: authz.RoleFolderViewer, Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}

	props := serve("bob", "PROPFIND", "/dav/alice/Calendar/", `<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop><cs:getctag/><d:sync-token/><d:current-user-privilege-set/></d:prop></d:propfind>`, map[string]string{"Depth": "0"})
	body := props.Body.String()
	ok, _, _ := strings.Cut(body, "404 Not Found")
	if !strings.Contains(ok, "<CS:getctag>") || !strings.Contains(ok, "<d:sync-token>") {
		t.Fatalf("a sharee needs getctag and sync-token: %s", body)
	}
	if !strings.Contains(ok, "<d:read>") || strings.Contains(ok, "<d:write>") {
		t.Fatalf("a viewer must be offered read without write: %s", body)
	}
	sync := serve("bob", "REPORT", "/dav/alice/Calendar/", `<?xml version="1.0"?><sync-collection xmlns="DAV:"><sync-token/><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>`, map[string]string{"Depth": "1"})
	if sync.Code != http.StatusMultiStatus || !strings.Contains(sync.Body.String(), "shared.ics") {
		t.Fatalf("sharee sync-collection = %d: %s", sync.Code, sync.Body.String())
	}
	if reply := serve("bob", http.MethodPut, "/dav/alice/Calendar/bob.ics", fmt.Sprintf(interopEvent, "bob-1", "Bob"), map[string]string{"Content-Type": "text/calendar"}); reply.Code != http.StatusForbidden {
		t.Fatalf("a viewer PUT = %d, want 403", reply.Code)
	}
}

// Apple Calendar's principal-property-search on the principal collection
// and python caldav's journal probe. The report was refused with 404 on
// /dav/ and 400 on a principal; a VJOURNAL calendar was silently created as
// an event calendar whose PUTs then failed with 400 instead of the
// supported-calendar-component precondition.
func TestInteropPrincipalSearchAndJournals(t *testing.T) {
	base := interopServer(t)
	search := func(match string) davReply {
		return davDo(t, "REPORT", base+"/dav/", map[string]string{"Depth": "0"}, `<?xml version="1.0" encoding="UTF-8"?>
<A:principal-property-search xmlns:A="DAV:" xmlns:B="urn:ietf:params:xml:ns:caldav" test="anyof">
  <A:property-search><A:prop><A:displayname/></A:prop><A:match>`+match+`</A:match></A:property-search>
  <A:property-search><A:prop><B:calendar-user-address-set/></A:prop><A:match>`+match+`</A:match></A:property-search>
  <A:prop><A:displayname/><B:calendar-home-set/><A:principal-URL/></A:prop>
</A:principal-property-search>`)
	}
	self := search("ali")
	if self.status != http.StatusMultiStatus || !strings.Contains(self.body, "<d:href>/dav/alice/</d:href>") || !strings.Contains(self.body, "calendar-home-set") {
		t.Fatalf("principal-property-search for self = %d: %s", self.status, self.body)
	}
	// python caldav 3.6 sends an empty DAV:prop with its properties beside it.
	pythonCaldav := davDo(t, "REPORT", base+"/dav/", nil, `<D:principal-property-search xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:property-search><D:prop><D:displayname/></D:prop><D:match>alice</D:match></D:property-search><D:prop/><C:calendar-home-set/><D:displayname/></D:principal-property-search>`)
	if !strings.Contains(pythonCaldav.body, "calendar-home-set") {
		t.Fatalf("python caldav principal search returned no properties: %s", pythonCaldav.body)
	}
	if other := search("bob"); other.status != http.StatusMultiStatus || strings.Contains(other.body, "/dav/bob/") {
		t.Fatalf("principal-property-search must not disclose other accounts: %d %s", other.status, other.body)
	}
	set := davDo(t, "REPORT", base+"/dav/alice/", nil, `<?xml version="1.0"?><principal-search-property-set xmlns="DAV:"/>`)
	if set.status != http.StatusOK || !strings.Contains(set.body, "principal-search-property") {
		t.Fatalf("principal-search-property-set = %d: %s", set.status, set.body)
	}

	journal := davDo(t, "MKCALENDAR", base+"/dav/alice/journal/", nil, `<?xml version="1.0"?><C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop><C:supported-calendar-component-set><C:comp name="VJOURNAL"/></C:supported-calendar-component-set></D:prop></D:set></C:mkcalendar>`)
	if journal.status != http.StatusForbidden || !strings.Contains(journal.body, "supported-calendar-component") {
		t.Fatalf("MKCALENDAR of a journal = %d: %s", journal.status, journal.body)
	}
	entry := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VJOURNAL\r\nUID:journal-1\r\nDTSTAMP:20261021T120000Z\r\nSUMMARY:Note\r\nEND:VJOURNAL\r\nEND:VCALENDAR\r\n"
	if reply := davDo(t, http.MethodPut, base+"/dav/alice/Calendar/journal.ics", map[string]string{"Content-Type": "text/calendar"}, entry); reply.status != http.StatusForbidden || !strings.Contains(reply.body, "supported-calendar-component") {
		t.Fatalf("VJOURNAL PUT into an event calendar = %d: %s", reply.status, reply.body)
	}
}

// Apple Calendar and macOS Finder ask the home and its collections for
// RFC 4331 quota properties; they were never returned.
func TestInteropQuotaProperties(t *testing.T) {
	base := interopServer(t)
	if reply := davDo(t, http.MethodPut, base+"/dav/alice/Calendar/q.ics", map[string]string{"Content-Type": "text/calendar"}, fmt.Sprintf(interopEvent, "quota-1", "Quota")); reply.status != http.StatusCreated {
		t.Fatalf("PUT = %d", reply.status)
	}
	reply := davDo(t, "PROPFIND", base+"/dav/alice/", map[string]string{"Depth": "1"}, `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/><d:quota-available-bytes/></d:prop></d:propfind>`)
	_, calendar, _ := strings.Cut(reply.body, "<d:href>/dav/alice/Calendar/</d:href>")
	calendar, _, _ = strings.Cut(calendar, "</d:response>")
	if !strings.Contains(calendar, "<d:quota-used-bytes>") || strings.Contains(calendar, "<d:quota-used-bytes>0<") {
		t.Fatalf("quota-used-bytes missing or zero: %s", calendar)
	}
	// Without a storage limit the space left is unknown (RFC 4331 §3).
	if !strings.Contains(calendar, "quota-available-bytes") || !strings.Contains(calendar, "404 Not Found") {
		t.Fatalf("quota-available-bytes must be reported missing without a limit: %s", calendar)
	}
	if allprop := davDo(t, "PROPFIND", base+"/dav/alice/", map[string]string{"Depth": "0"}, ""); strings.Contains(allprop.body, "quota-used-bytes") {
		t.Fatalf("allprop must not include quota properties: %s", allprop.body)
	}
}

// Evolution's and python caldav's searches use prop-filter with text-match,
// is-not-defined, and param-filter; all were ignored, so every search
// returned the whole calendar.
func TestInteropCalendarQueryPropertyFilters(t *testing.T) {
	base := interopServer(t)
	put := func(name, body string) {
		if reply := davDo(t, http.MethodPut, base+"/dav/alice/Calendar/"+name, map[string]string{"Content-Type": "text/calendar"}, body); reply.status != http.StatusCreated {
			t.Fatalf("PUT %s = %d", name, reply.status)
		}
	}
	put("lunch.ics", "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VEVENT\r\nUID:f-1\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261105T120000Z\r\nDTEND:20261105T130000Z\r\nSUMMARY:Team Lunch\r\nCATEGORIES:Food\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	put("review.ics", "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VEVENT\r\nUID:f-2\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261106T120000Z\r\nSUMMARY:Code review\r\nCLASS:PRIVATE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	query := func(filter string) string {
		t.Helper()
		reply := davDo(t, "REPORT", base+"/dav/alice/Calendar/", map[string]string{"Depth": "1"}, `<?xml version="1.0"?><C:calendar-query xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">`+filter+`</C:comp-filter></C:comp-filter></C:filter></C:calendar-query>`)
		if reply.status != http.StatusMultiStatus {
			t.Fatalf("calendar-query = %d: %s", reply.status, reply.body)
		}
		var names []string
		for _, name := range []string{"lunch.ics", "review.ics"} {
			if strings.Contains(reply.body, name) {
				names = append(names, name)
			}
		}
		return strings.Join(names, ",")
	}
	// An event with DURATION, matched by open-ended ranges (python caldav's
	// search.time-range.open probes); open ranges used to match everything
	// and DURATION was ignored.
	put("standup.ics", "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VEVENT\r\nUID:f-3\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261201T090000Z\r\nDURATION:PT2H\r\nSUMMARY:Standup\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	for _, tc := range []struct{ rangeAttrs, want string }{
		{`end="20261201T100000Z"`, "standup"},
		{`end="20261201T090000Z"`, ""},
		{`start="20261201T105959Z"`, "standup"},
		{`start="20261201T110000Z"`, ""},
	} {
		reply := davDo(t, "REPORT", base+"/dav/alice/Calendar/", map[string]string{"Depth": "1"}, `<?xml version="1.0"?><C:calendar-query xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:prop-filter name="UID"><C:text-match>f-3</C:text-match></C:prop-filter><C:time-range `+tc.rangeAttrs+`/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>`)
		if got := strings.Contains(reply.body, "standup.ics"); got != (tc.want != "") {
			t.Errorf("time-range %s matched %v, want %v", tc.rangeAttrs, got, tc.want != "")
		}
	}

	for _, tc := range []struct{ filter, want string }{
		{`<C:prop-filter name="SUMMARY"><C:text-match>lunch</C:text-match></C:prop-filter>`, "lunch.ics"},
		{`<C:prop-filter name="SUMMARY"><C:text-match collation="i;octet">lunch</C:text-match></C:prop-filter>`, ""},
		{`<C:prop-filter name="SUMMARY"><C:text-match negate-condition="yes">lunch</C:text-match></C:prop-filter>`, "review.ics"},
		{`<C:prop-filter name="DTEND"><C:is-not-defined/></C:prop-filter>`, "review.ics"},
		{`<C:prop-filter name="CATEGORIES"><C:text-match>food</C:text-match></C:prop-filter>`, "lunch.ics"},
		{`<C:prop-filter name="CLASS"><C:is-not-defined/></C:prop-filter>`, "lunch.ics"},
		{`<C:prop-filter name="ATTENDEE"><C:param-filter name="PARTSTAT"><C:text-match>ACCEPTED</C:text-match></C:param-filter></C:prop-filter>`, "lunch.ics"},
		{`<C:comp-filter name="VALARM"><C:is-not-defined/></C:comp-filter>`, "lunch.ics,review.ics"},
	} {
		if got := query(tc.filter); got != tc.want {
			t.Errorf("filter %s matched %q, want %q", tc.filter, got, tc.want)
		}
	}
}

// addressbook-query as RFC 6352 defines it and Apple Contacts, Evolution,
// and DAVx5 send it: prop-filters directly under filter, with a test,
// match-type, and limit. Only a comp-filter wrapper was understood, so these
// queries returned every contact; supported-address-data was missing.
func TestInteropAddressbookQueryAsSentByClients(t *testing.T) {
	base := interopServer(t)
	for name, card := range map[string]string{
		"ann.vcf": "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:ann\r\nFN:Ann Archer\r\nN:Archer;Ann;;;\r\nEMAIL;TYPE=WORK:ann@work.example\r\nCATEGORIES:Work,Friends\r\nEND:VCARD\r\n",
		"bo.vcf":  "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:bo\r\nFN:Bo Builder\r\nEMAIL;TYPE=home:bo@home.example\r\nEND:VCARD\r\n",
	} {
		if reply := davDo(t, http.MethodPut, base+"/dav/alice/Contacts/"+name, map[string]string{"Content-Type": "text/vcard"}, card); reply.status != http.StatusCreated {
			t.Fatalf("PUT %s = %d", name, reply.status)
		}
	}
	query := func(filter, limit string) string {
		t.Helper()
		reply := davDo(t, "REPORT", base+"/dav/alice/Contacts/", map[string]string{"Depth": "1"}, `<?xml version="1.0"?><C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/></D:prop>`+filter+limit+`</C:addressbook-query>`)
		if reply.status != http.StatusMultiStatus {
			t.Fatalf("addressbook-query = %d: %s", reply.status, reply.body)
		}
		var names []string
		for _, name := range []string{"ann.vcf", "bo.vcf"} {
			if strings.Contains(reply.body, name) {
				names = append(names, name)
			}
		}
		if strings.Contains(reply.body, "507 Insufficient Storage") {
			names = append(names, "507")
		}
		return strings.Join(names, ",")
	}
	for _, tc := range []struct{ filter, limit, want string }{
		{`<C:filter><C:prop-filter name="EMAIL"><C:text-match collation="i;unicode-casemap" match-type="contains">ANN@</C:text-match></C:prop-filter></C:filter>`, "", "ann.vcf"},
		{`<C:filter><C:prop-filter name="FN"><C:text-match match-type="starts-with">bo</C:text-match></C:prop-filter></C:filter>`, "", "bo.vcf"},
		{`<C:filter test="anyof"><C:prop-filter name="FN"><C:text-match match-type="equals">nobody</C:text-match></C:prop-filter><C:prop-filter name="EMAIL"><C:text-match match-type="ends-with">home.example</C:text-match></C:prop-filter></C:filter>`, "", "bo.vcf"},
		{`<C:filter test="allof"><C:prop-filter name="FN"><C:text-match>a</C:text-match></C:prop-filter><C:prop-filter name="CATEGORIES"><C:text-match match-type="equals">friends</C:text-match></C:prop-filter></C:filter>`, "", "ann.vcf"},
		{`<C:filter><C:prop-filter name="CATEGORIES"><C:is-not-defined/></C:prop-filter></C:filter>`, "", "bo.vcf"},
		{`<C:filter><C:prop-filter name="EMAIL"><C:param-filter name="TYPE"><C:text-match match-type="equals">work</C:text-match></C:param-filter></C:prop-filter></C:filter>`, "", "ann.vcf"},
		{`<C:filter><C:prop-filter name="FN"><C:text-match negate-condition="yes">Ann</C:text-match></C:prop-filter></C:filter>`, "", "bo.vcf"},
	} {
		if got := query(tc.filter, tc.limit); got != tc.want {
			t.Errorf("filter %s matched %q, want %q", tc.filter, got, tc.want)
		}
	}
	if got := query(`<C:filter><C:prop-filter name="FN"/></C:filter>`, `<C:limit><C:nresults>1</C:nresults></C:limit>`); strings.Count(got, ".vcf") != 1 || !strings.HasSuffix(got, "507") {
		t.Errorf("a limited query must return one card and a 507 marker, got %q", got)
	}
	props := davDo(t, "PROPFIND", base+"/dav/alice/Contacts/", map[string]string{"Depth": "0"}, `<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><C:supported-address-data/></D:prop></D:propfind>`)
	if !strings.Contains(props.body, `version="4.0"`) || !strings.Contains(props.body, `version="3.0"`) {
		t.Fatalf("supported-address-data: %s", props.body)
	}
}

// Thunderbird and Apple Calendar accept an invitation by PUTting the copy
// with the attendee's PARTSTAT changed and, since the server advertises
// calendar-auto-schedule, leave the REPLY to the server (RFC 6638
// §3.2.2). The change was stored and nothing told the organizer.
func TestInteropAttendeePartStatChangeReplies(t *testing.T) {
	ts := testStoreSetup(t)
	ctx := t.Context()
	if err := ts.DomainStore().Create(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	testUser(t, ts, "bob", "pass123")
	if err := ts.UserStore().AddEmailAddress(ctx, "bob@example.com", "bob", "example.com", true); err != nil {
		t.Fatal(err)
	}
	type reply struct{ owner, item, partStat string }
	var replies []reply
	handler := New(ts, &Config{AttendeeReply: func(_ context.Context, owner, item, partStat string) error {
		replies = append(replies, reply{owner, item, partStat})
		return nil
	}})
	invitation := func(partStat string) string {
		return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VEVENT\r\nUID:invite-1\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261210T090000Z\r\nDTEND:20261210T100000Z\r\nSUMMARY:Planning\r\n" +
			"ORGANIZER:mailto:alice@partner.test\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@partner.test\r\nATTENDEE;PARTSTAT=" + partStat + ";RSVP=TRUE:mailto:bob@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	}
	put := func(body string) *httptest.ResponseRecorder {
		request := WithAuthenticatedUser(newRequest(http.MethodPut, "/dav/bob/Calendar/invite.ics", body), "bob")
		request.Header.Set("Content-Type", "text/calendar")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code/100 != 2 {
			t.Fatalf("PUT = %d: %s", recorder.Code, recorder.Body.String())
		}
		return recorder
	}
	put(invitation("NEEDS-ACTION"))
	if len(replies) != 0 {
		t.Fatalf("storing an unanswered invitation must not reply: %+v", replies)
	}
	accepted := put(invitation("ACCEPTED"))
	if len(replies) != 1 || replies[0].owner != "bob" || replies[0].partStat != "ACCEPTED" || replies[0].item == "" {
		t.Fatalf("accepting must reply once: %+v", replies)
	}
	if accepted.Header().Get("ETag") != "" {
		t.Fatalf("the reply rewrites the object, so the PUT must not return an ETag")
	}
	put(strings.Replace(invitation("ACCEPTED"), "SUMMARY:Planning", "SUMMARY:Planning\r\nCATEGORIES:Work", 1))
	if len(replies) != 1 {
		t.Fatalf("an edit that keeps the answer must not reply again: %+v", replies)
	}
	put(invitation("DECLINED"))
	if len(replies) != 2 || replies[1].partStat != "DECLINED" {
		t.Fatalf("declining must reply: %+v", replies)
	}
	// Bob's own meetings are scheduled as organizer, not answered.
	own := strings.ReplaceAll(invitation("ACCEPTED"), "ORGANIZER:mailto:alice@partner.test", "ORGANIZER:mailto:bob@example.com")
	request := WithAuthenticatedUser(newRequest(http.MethodPut, "/dav/bob/Calendar/own.ics", own), "bob")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if len(replies) != 2 {
		t.Fatalf("an organizer's own event must not send a reply: %+v", replies)
	}
}

// python caldav's search.time-range.open.start.duration probe: a VTODO
// with DTSTART and DURATION was treated as instantaneous, so a range that
// overlaps only its later part missed it.
func TestInteropTaskDurationTimeRange(t *testing.T) {
	base := interopServer(t)
	if reply := davDo(t, "MKCALENDAR", base+"/dav/alice/chores/", nil, `<?xml version="1.0"?><C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop><C:supported-calendar-component-set><C:comp name="VTODO"/></C:supported-calendar-component-set></D:prop></D:set></C:mkcalendar>`); reply.status != http.StatusCreated {
		t.Fatalf("MKCALENDAR = %d", reply.status)
	}
	task := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VTODO\r\nUID:dur-1\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20270118T120000Z\r\nDURATION:PT2H\r\nSUMMARY:Two hours\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
	if reply := davDo(t, http.MethodPut, base+"/dav/alice/chores/dur.ics", map[string]string{"Content-Type": "text/calendar"}, task); reply.status != http.StatusCreated {
		t.Fatalf("PUT = %d", reply.status)
	}
	for _, tc := range []struct {
		start, end string
		want       bool
	}{
		{"20270118T130000Z", "20270118T150000Z", true},
		{"20270118T110000Z", "20270118T130000Z", true},
		{"20270118T150000Z", "20270118T160000Z", false},
	} {
		reply := davDo(t, "REPORT", base+"/dav/alice/chores/", map[string]string{"Depth": "1"}, `<?xml version="1.0"?><C:calendar-query xmlns:d="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VTODO"><C:time-range start="`+tc.start+`" end="`+tc.end+`"/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>`)
		if got := strings.Contains(reply.body, "dur.ics"); got != tc.want {
			t.Errorf("range %s-%s matched %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}
