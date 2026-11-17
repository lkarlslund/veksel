package caldav

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

const sampleVTODO = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VTODO\r\nUID:todo-1\r\nDTSTAMP:20250101T000000Z\r\nSUMMARY:Pay invoices\r\nDUE;VALUE=DATE:20250110\r\nCATEGORIES:Finance\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"

const sampleSubtask = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VTODO\r\nUID:todo-2\r\nDTSTAMP:20250101T000000Z\r\nSUMMARY:Collect receipts\r\nRELATED-TO;RELTYPE=PARENT:todo-1\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"

func TestTaskListsAreVTODOCollections(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)
	serve := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newRequest(method, path, body))
		return w
	}

	mkcalendar := `<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:set><D:prop>
 <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>
 <C:supported-calendar-component-set><C:comp name="VTODO"/></C:supported-calendar-component-set>
</D:prop></D:set></D:mkcol>`
	if w := serve("MKCOL", "/dav/alice/Chores", mkcalendar); w.Code != http.StatusCreated {
		t.Fatalf("MKCOL task list status=%d body=%s", w.Code, w.Body)
	}
	folder, err := ts.FolderStore().GetByPath(context.Background(), "alice", "Chores")
	if err != nil || folder.Type != model.FolderTypeTasks {
		t.Fatalf("folder=%+v err=%v", folder, err)
	}

	propfind := `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><C:supported-calendar-component-set xmlns:C="urn:ietf:params:xml:ns:caldav"/></D:prop></D:propfind>`
	request := newRequest("PROPFIND", "/dav/alice/", propfind)
	request.Header.Set("Depth", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	body := w.Body.String()
	if !strings.Contains(body, `<C:comp name="VTODO">`) || !strings.Contains(body, `<C:comp name="VEVENT">`) {
		t.Fatalf("home PROPFIND does not advertise components: %s", body)
	}

	if w := serve("PUT", "/dav/alice/Chores/event.ics", sampleVEVENT); w.Code != http.StatusForbidden {
		t.Fatalf("VEVENT into task list status=%d", w.Code)
	}
	// RFC 4791 5.3.2.1: valid iCalendar of an unsupported component type
	// fails the supported-calendar-component precondition with 403.
	if w := serve("PUT", "/dav/alice/Calendar/todo.ics", sampleVTODO); w.Code != http.StatusForbidden {
		t.Fatalf("VTODO into event calendar status=%d", w.Code)
	}
	for name, payload := range map[string]string{"todo-1.ics": sampleVTODO, "todo-2.ics": sampleSubtask} {
		if w := serve("PUT", "/dav/alice/Chores/"+name, payload); w.Code != http.StatusCreated {
			t.Fatalf("PUT %s status=%d body=%s", name, w.Code, w.Body)
		}
	}

	query := func(component, timeRange string) string {
		return `<?xml version="1.0" encoding="utf-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
 <D:prop><D:getetag/><C:calendar-data/></D:prop>
 <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="` + component + `">` + timeRange + `</C:comp-filter></C:comp-filter></C:filter>
</C:calendar-query>`
	}
	w = serve("REPORT", "/dav/alice/Chores/", query("VTODO", ""))
	if w.Code != http.StatusMultiStatus || !strings.Contains(w.Body.String(), "Pay invoices") || !strings.Contains(w.Body.String(), "RELATED-TO;RELTYPE=PARENT:todo-1") {
		t.Fatalf("VTODO query status=%d body=%s", w.Code, w.Body)
	}
	// The dated task falls outside February; the undated subtask always matches.
	w = serve("REPORT", "/dav/alice/Chores/", query("VTODO", `<C:time-range start="20250201T000000Z" end="20250301T000000Z"/>`))
	if body := w.Body.String(); strings.Contains(body, "Pay invoices") || !strings.Contains(body, "Collect receipts") {
		t.Fatalf("VTODO time-range query body=%s", body)
	}
	if w := serve("REPORT", "/dav/alice/Chores/", query("VEVENT", "")); strings.Contains(w.Body.String(), "VTODO") {
		t.Fatalf("VEVENT query returned tasks: %s", w.Body)
	}

	w = serve("GET", "/dav/alice/Chores/todo-1.ics", "")
	task, err := calendar.ProjectTask(w.Body.Bytes())
	if w.Code != http.StatusOK || err != nil || task.Due != "2025-01-10" || len(task.Categories) != 1 || task.Categories[0] != "Finance" {
		t.Fatalf("GET task status=%d task=%+v err=%v", w.Code, task, err)
	}
}
