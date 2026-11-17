package caldav

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func rawReport(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("REPORT", url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml; charset=UTF-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// vdirsyncer 0.21 (a real third-party client) sends the RFC 6352 report name
// addressbook-multiget and the RFC 4791 calendar-multiget with a default DAV:
// namespace, and refuses any response entry that lacks getetag.
func TestInteropMultigetReportsAsSentByVdirsyncer(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()
	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")
	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()
	base := strings.TrimSuffix(srv.URL, "/")

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")
	card := buildVCardWithName("interop-001@example.com", "Interop One", "One", "Interop", "one@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/one.vcf", card); err != nil {
		t.Fatal(err)
	}
	status, body := rawReport(t, base+"/dav/alice/Contacts/", `<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-multiget xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <prop><getetag/><C:address-data /></prop>
  <href>/dav/alice/Contacts/one.vcf</href>
</C:addressbook-multiget>`)
	if status != http.StatusMultiStatus {
		t.Fatalf("addressbook-multiget status = %d: %s", status, body)
	}
	if !strings.Contains(body, "Interop One") || !strings.Contains(body, "getetag") {
		t.Fatalf("addressbook-multiget must return address-data and getetag: %s", body)
	}

	ical := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//interop//EN\r\nBEGIN:VEVENT\r\nUID:interop-evt-1\r\nDTSTAMP:20261021T120000Z\r\nDTSTART:20261105T090000Z\r\nDTEND:20261105T100000Z\r\nSUMMARY:Interop event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	put, err := http.NewRequest(http.MethodPut, base+"/dav/alice/Calendar/evt.ics", strings.NewReader(ical))
	if err != nil {
		t.Fatal(err)
	}
	put.SetBasicAuth("alice", "pass123")
	put.Header.Set("Content-Type", "text/calendar")
	resp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("PUT event status = %d", resp.StatusCode)
	}
	status, body = rawReport(t, base+"/dav/alice/Calendar/", `<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-multiget xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <prop><getetag/><C:calendar-data/></prop>
  <href>/dav/alice/Calendar/evt.ics</href>
</C:calendar-multiget>`)
	if status != http.StatusMultiStatus {
		t.Fatalf("calendar-multiget status = %d: %s", status, body)
	}
	if !strings.Contains(body, "Interop event") || !strings.Contains(body, "getetag") {
		t.Fatalf("calendar-multiget must return calendar-data and getetag: %s", body)
	}
}
