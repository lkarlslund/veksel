package caldav

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- Sample vCards for testing ---

var sampleVCARD = `BEGIN:VCARD
VERSION:3.0
UID:contact-001@example.com
FN:John Doe
N:Doe;John;;;
EMAIL;TYPE=INTERNET:john@example.com
TEL;TYPE=WORK:+1-555-0101
END:VCARD`

var sampleVCARD2 = `BEGIN:VCARD
VERSION:4.0
UID:contact-002@example.com
FN:Jane Smith
N:Smith;Jane;;;
EMAIL;type=internet:jane@example.com
TEL;type=work:+1-555-0202
END:VCARD`

var sampleVCARD3 = `BEGIN:VCARD
VERSION:3.0
UID:contact-003@example.com
FN:Bob Johnson
N:Johnson;Bob;;;
EMAIL;TYPE=INTERNET:bob@example.com
TEL;TYPE=HOME:+1-555-0303
END:VCARD`

// --- Tests ---

func TestAddressbookMKCOL(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// MKCOL with addressbook resource type
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
 <D:resourcetype>
  <C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>
 </D:resourcetype>
</D:prop>`

	r := newRequest("MKCOL", "/dav/alice/MyContacts", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("MKCOL addressbook: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify the folder was created as contacts type
	ctx := context.Background()
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "MyContacts")
	if err != nil {
		t.Fatalf("get folder: %v", err)
	}
	if folder.Type != model.FolderTypeContacts {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeContacts)
	}
}

func TestAddressbookMKCOLDuplicate(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	body := `<D:prop xmlns:D="DAV:"><D:resourcetype><C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/></D:resourcetype></D:prop>`

	// First creation
	r := newRequest("MKCOL", "/dav/alice/MyContacts", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("first MKCOL: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Second creation should fail
	r = newRequest("MKCOL", "/dav/alice/MyContacts", body)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate MKCOL: status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestPUTAndGetContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// testUser creates a default "Contacts" folder

	// PUT a contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	r.Header.Set("Content-Type", "text/vcard")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// Verify ETag header
	if etag := w.Header().Get("ETag"); etag == "" {
		t.Error("PUT: missing ETag header")
	}

	// GET the contact back
	r = newRequest("GET", "/dav/alice/Contacts/john.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "text/vcard" {
		t.Errorf("GET: Content-Type = %q, want %q", w.Header().Get("Content-Type"), "text/vcard")
	}

	if !strings.Contains(w.Body.String(), "John Doe") {
		t.Errorf("GET: body does not contain expected name: %s", w.Body.String())
	}
}

func TestPUTUpdateContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// testUser creates a default "Contacts" folder

	// PUT initial contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("initial PUT: status = %d", w.Code)
	}

	// PUT updated contact
	updatedContact := strings.Replace(sampleVCARD, "John Doe", "John Q. Doe", 1)
	r = newRequest("PUT", "/dav/alice/Contacts/john.vcf", updatedContact)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("update PUT: status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// GET and verify
	r = newRequest("GET", "/dav/alice/Contacts/john.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "John Q. Doe") {
		t.Errorf("GET after update: body does not contain updated name: %s", w.Body.String())
	}
}

func TestPUTInvalidContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT data without VCARD
	r := newRequest("PUT", "/dav/alice/Contacts/bad.vcf", "this is not a vcard")
	r.Header.Set("Content-Type", "text/vcard")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT invalid: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestPUTContactNonExistentAddressbook(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("PUT", "/dav/alice/NoContacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("PUT non-existent addressbook: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact first
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d", w.Code)
	}

	// DELETE the contact
	r = newRequest("DELETE", "/dav/alice/Contacts/john.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// GET should return 404
	r = newRequest("GET", "/dav/alice/Contacts/john.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteAddressbook(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "TempContacts", model.FolderTypeContacts, "")

	// DELETE the addressbook collection
	r := newRequest("DELETE", "/dav/alice/TempContacts", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE addressbook: status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify folder is gone
	_, err := ts.FolderStore().GetByPath(ctx, "alice", "TempContacts")
	if err == nil {
		t.Error("expected addressbook to be deleted")
	}
}

func TestPROPFINDAddressbook(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// PROPFIND on the addressbook with depth 1
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
  <D:displayname/>
  <D:resourcetype/>
  <D:getetag/>
 </D:prop>
</D:propfind>`

	r = newRequest("PROPFIND", "/dav/alice/Contacts/", body)
	r.Header.Set("Depth", "1")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND addressbook: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	// Should contain the addressbook resource type
	if !strings.Contains(respBody, "addressbook") {
		t.Errorf("PROPFIND: body does not contain addressbook resource type: %s", respBody)
	}
}

func TestAddressbookQuery(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT three contacts
	for name, vcard := range map[string]string{
		"john.vcf": sampleVCARD,
		"jane.vcf": sampleVCARD2,
		"bob.vcf":  sampleVCARD3,
	} {
		r := newRequest("PUT", "/dav/alice/Contacts/"+name, vcard)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("PUT %s: status = %d", name, w.Code)
		}
	}

	// Query for contacts with "John Doe" in FN (exact full name to avoid matching "Johnson")
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD">
   <prop-filter name="FN">
     <text-match>John Doe</text-match>
   </prop-filter>
 </comp-filter>
 </filter>
</addressbook-query>`

	r := newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain John Doe
	if !strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: body does not contain John Doe: %s", respBody)
	}
	// Should NOT contain Jane Smith
	if strings.Contains(respBody, "Jane Smith") {
		t.Errorf("addressbook-query: body should not contain Jane Smith: %s", respBody)
	}
	// Should NOT contain Bob Johnson
	if strings.Contains(respBody, "Bob Johnson") {
		t.Errorf("addressbook-query: body should not contain Bob Johnson: %s", respBody)
	}
}

func TestAddressbookQueryByEmail(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT contacts
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	r = newRequest("PUT", "/dav/alice/Contacts/jane.vcf", sampleVCARD2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query for contacts with "jane" in EMAIL
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
  <D:getetag/>
  <vcard/>
 </D:prop>
 <filter>
  <comp-filter name="VCARD">
    <prop-filter name="EMAIL">
      <text-match>jane</text-match>
    </prop-filter>
  </comp-filter>
 </filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query email: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain Jane Smith
	if !strings.Contains(respBody, "Jane Smith") {
		t.Errorf("addressbook-query: body does not contain Jane Smith: %s", respBody)
	}
	// Should NOT contain John Doe
	if strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: body should not contain John Doe: %s", respBody)
	}
}

func TestAddressbookQueryNoFilter(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query without text-match filter (should return all)
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
  <D:getetag/>
 </D:prop>
 <filter>
  <comp-filter name="VCARD"/>
 </filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query no filter: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestAddressbookQueryEmptyAddressbook(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:"><D:getetag/></D:prop>
 <filter><comp-filter name="VCARD"><prop-filter name="FN"><text-match>john</text-match></prop-filter></comp-filter></filter>
</addressbook-query>`

	r := newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query empty: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
}

func TestAddressbookQueryNonExistentAddressbook(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:"><D:getetag/></D:prop>
 <filter><comp-filter name="VCARD"/></filter>
</addressbook-query>`

	r := newRequest("REPORT", "/dav/alice/NoContacts/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("addressbook-query non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCardDAVMultiget(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT two contacts
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	r = newRequest("PUT", "/dav/alice/Contacts/jane.vcf", sampleVCARD2)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Multiget for both contacts
	multigetBody := `<?xml version="1.0" encoding="utf-8"?>
<multiget xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
  <D:getetag/>
  <vcard/>
 </D:prop>
 <D:href xmlns:D="DAV:">/dav/alice/Contacts/john.vcf</D:href>
 <D:href xmlns:D="DAV:">/dav/alice/Contacts/jane.vcf</D:href>
</multiget>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", multigetBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("multiget: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "John Doe") {
		t.Errorf("multiget: body does not contain John Doe: %s", respBody)
	}
	if !strings.Contains(respBody, "Jane Smith") {
		t.Errorf("multiget: body does not contain Jane Smith: %s", respBody)
	}
}

func TestCardDAVMultigetNotFound(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// Multiget for a non-existent contact
	multigetBody := `<?xml version="1.0" encoding="utf-8"?>
<multiget xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
  <D:getetag/>
 </D:prop>
 <D:href xmlns:D="DAV:">/dav/alice/Contacts/nonexistent.vcf</D:href>
</multiget>`

	r := newRequest("REPORT", "/dav/alice/Contacts/", multigetBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("multiget: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "404") {
		t.Errorf("multiget: expected 404 for missing contact: %s", respBody)
	}
}

func TestVCARDParsing(t *testing.T) {
	t.Parallel()
	// Test containsVCARD
	if !containsVCARD([]byte(sampleVCARD)) {
		t.Error("containsVCARD should return true for valid vCard")
	}

	if containsVCARD([]byte("just some text")) {
		t.Error("containsVCARD should return false for non-vCard data")
	}

	// Test extractVCARDUID
	uid := extractVCARDUID([]byte(sampleVCARD))
	if uid != "contact-001@example.com" {
		t.Errorf("extractVCARDUID = %q, want %q", uid, "contact-001@example.com")
	}

	// Test vCard 4.0 UID extraction
	uid = extractVCARDUID([]byte(sampleVCARD2))
	if uid != "contact-002@example.com" {
		t.Errorf("extractVCARDUID v4 = %q, want %q", uid, "contact-002@example.com")
	}
}

func TestVCARDPropertyMatching(t *testing.T) {
	t.Parallel()
	// Test FN matching
	if !vCardPropertyMatches([]byte(sampleVCARD), "FN", "John") {
		t.Error("vCardPropertyMatches should match FN=John")
	}

	if vCardPropertyMatches([]byte(sampleVCARD), "FN", "Jane") {
		t.Error("vCardPropertyMatches should not match FN=Jane for John's card")
	}

	// Test EMAIL matching
	if !vCardPropertyMatches([]byte(sampleVCARD), "EMAIL", "john@example.com") {
		t.Error("vCardPropertyMatches should match EMAIL=john@example.com")
	}

	// Test case-insensitive matching
	if !vCardPropertyMatches([]byte(sampleVCARD), "FN", "john") {
		t.Error("vCardPropertyMatches should be case-insensitive")
	}

	// Test TEL matching
	if !vCardPropertyMatches([]byte(sampleVCARD), "TEL", "555-0101") {
		t.Error("vCardPropertyMatches should match TEL containing 555-0101")
	}
}

func TestETagFormatContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
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
	r = newRequest("GET", "/dav/alice/Contacts/john.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	getEtag := w.Header().Get("ETag")
	if getEtag != etag {
		t.Errorf("GET ETag = %q, want %q", getEtag, etag)
	}
}

func TestMultipleContactsInAddressbook(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT multiple contacts
	contacts := map[string]string{
		"john.vcf": sampleVCARD,
		"jane.vcf": sampleVCARD2,
		"bob.vcf":  sampleVCARD3,
	}

	for name, vcard := range contacts {
		r := newRequest("PUT", "/dav/alice/Contacts/"+name, vcard)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("PUT %s: status = %d", name, w.Code)
		}
	}

	// PROPFIND with depth 1 should list all contacts
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
  <D:getetag/>
 </D:prop>
</D:propfind>`

	r := newRequest("PROPFIND", "/dav/alice/Contacts/", body)
	r.Header.Set("Depth", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d", w.Code)
	}

	// Count the number of href responses (should be 3 contacts + 1 addressbook)
	respBody := w.Body.String()
	hrefCount := strings.Count(respBody, "<d:href>")
	if hrefCount < 4 {
		t.Errorf("PROPFIND: found %d hrefs, expected at least 4 (3 contacts + 1 addressbook)", hrefCount)
	}
}

func TestCardDAVReportOnCalendar(t *testing.T) {
	t.Parallel()
	// CardDAV query on a calendar folder should return "not an address book"
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:"><D:getetag/></D:prop>
 <filter><comp-filter name="VCARD"/></filter>
</addressbook-query>`

	r := newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("CardDAV query on calendar: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCalDAVStillWorks(t *testing.T) {
	t.Parallel()
	// Ensure CalDAV operations still work alongside CardDAV
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")

	// PUT a calendar event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("CalDAV PUT: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// GET the event back
	r = newRequest("GET", "/dav/alice/MyCal/event1.ics", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("CalDAV GET: status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Header().Get("Content-Type") != "text/calendar; charset=utf-8" {
		t.Errorf("CalDAV GET: Content-Type = %q, want %q", w.Header().Get("Content-Type"), "text/calendar; charset=utf-8")
	}
}

func TestMixedCalDAVAndCardDAV(t *testing.T) {
	t.Parallel()
	// Test that both CalDAV and CardDAV work for the same user
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	ctx := context.Background()
	ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, "")
	// Contacts folder already created by testUser

	// PUT a calendar event
	r := newRequest("PUT", "/dav/alice/MyCal/event1.ics", sampleVEVENT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("CalDAV PUT: status = %d", w.Code)
	}

	// PUT a contact
	r = newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("CardDAV PUT: status = %d", w.Code)
	}

	// CalDAV calendar-query
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:"><D:getetag/></D:prop>
 <filter><comp-filter name="VCALENDAR"><comp-filter name="VEVENT"/></comp-filter></filter>
</calendar-query>`

	r = newRequest("REPORT", "/dav/alice/MyCal/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMultiStatus {
		t.Fatalf("CalDAV calendar-query: status = %d", w.Code)
	}

	// CardDAV addressbook-query
	cardQueryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:"><D:getetag/></D:prop>
 <filter><comp-filter name="VCARD"/></filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", cardQueryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMultiStatus {
		t.Fatalf("CardDAV addressbook-query: status = %d", w.Code)
	}
}

func TestVCARD4PutAndGet(t *testing.T) {
	t.Parallel()
	// Test vCard 4.0 specifically
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a vCard 4.0
	r := newRequest("PUT", "/dav/alice/Contacts/jane.vcf", sampleVCARD2)
	r.Header.Set("Content-Type", "text/vcard")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT vCard 4.0: status = %d, want %d", w.Code, http.StatusCreated)
	}

	// GET it back
	r = newRequest("GET", "/dav/alice/Contacts/jane.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET vCard 4.0: status = %d, want %d", w.Code, http.StatusOK)
	}

	if !strings.Contains(w.Body.String(), "Jane Smith") {
		t.Errorf("GET vCard 4.0: body does not contain expected name: %s", w.Body.String())
	}
}

func TestDeleteNonExistentContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("DELETE", "/dav/alice/Contacts/nope.vcf", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("DELETE non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestGETNonExistentContact(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	r := newRequest("GET", "/dav/alice/Contacts/nope.vcf", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("GET non-existent: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestAddressbookQueryCaseInsensitive(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query with uppercase "JOHN" — should still match
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
  <D:getetag/>
  <vcard/>
 </D:prop>
 <filter>
  <comp-filter name="VCARD">
    <prop-filter name="FN">
      <text-match>JOHN</text-match>
    </prop-filter>
  </comp-filter>
 </filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query case insensitive: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: case-insensitive search should match John Doe: %s", respBody)
	}
}

func TestAddressbookQueryNonExistentMatch(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact
	r := newRequest("PUT", "/dav/alice/Contacts/john.vcf", sampleVCARD)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query for a name that doesn't exist
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
  <D:getetag/>
  <vcard/>
 </D:prop>
 <filter>
  <comp-filter name="VCARD">
    <prop-filter name="FN">
      <text-match>nonexistent</text-match>
    </prop-filter>
  </comp-filter>
 </filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query no match: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	// Should not contain any vCard data
	respBody := w.Body.String()
	if strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: should not return any results for non-matching query: %s", respBody)
	}
}

// --- CATEGORIES / Group tests ---

var sampleVCARDWithCategories = `BEGIN:VCARD
VERSION:3.0
UID:contact-cat-001@example.com
FN:Alice Work
N:Work;Alice;;;
EMAIL;TYPE=INTERNET:alice-work@example.com
CATEGORIES:work,engineering
END:VCARD`

var sampleVCARDWithCategories2 = `BEGIN:VCARD
VERSION:3.0
UID:contact-cat-002@example.com
FN:Bob Personal
N:Personal;Bob;;;
EMAIL;TYPE=INTERNET:bob-personal@example.com
CATEGORIES:friends,family
END:VCARD`

var sampleVCARDWithPhoto = `BEGIN:VCARD
VERSION:3.0
UID:contact-photo-001@example.com
FN:Photo Person
N:Person;Photo;;;
EMAIL;TYPE=INTERNET:photo@example.com
PHOTO;TYPE=JPEG;VALUE=binary:/9j/4AAQSkZJRg==
END:VCARD`

func TestAddressbookQueryByCategories(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT contacts with categories
	for name, vcard := range map[string]string{
		"alice.vcf": sampleVCARDWithCategories,
		"bob.vcf":   sampleVCARDWithCategories2,
	} {
		r := newRequest("PUT", "/dav/alice/Contacts/"+name, vcard)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("PUT %s: status = %d", name, w.Code)
		}
	}

	// Query for contacts in "work" category
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD">
  <prop-filter name="CATEGORIES">
   <text-match>work</text-match>
  </prop-filter>
 </comp-filter>
 </filter>
</addressbook-query>`

	r := newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query categories: status = %d, want %d, body = %s", w.Code, http.StatusMultiStatus, w.Body.String())
	}

	respBody := w.Body.String()
	// Should contain Alice Work (in "work" category)
	if !strings.Contains(respBody, "Alice Work") {
		t.Errorf("addressbook-query: body does not contain Alice Work: %s", respBody)
	}
	// Should NOT contain Bob Personal (not in "work" category)
	if strings.Contains(respBody, "Bob Personal") {
		t.Errorf("addressbook-query: body should not contain Bob Personal: %s", respBody)
	}
}

func TestAddressbookQueryByCategoriesNoMatch(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact with categories
	r := newRequest("PUT", "/dav/alice/Contacts/alice.vcf", sampleVCARDWithCategories)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query for a category that doesn't exist
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD">
  <prop-filter name="CATEGORIES">
   <text-match>sales</text-match>
  </prop-filter>
 </comp-filter>
 </filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query categories no match: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if strings.Contains(respBody, "Alice Work") {
		t.Errorf("addressbook-query: should not return results for non-matching category: %s", respBody)
	}
}

func TestAddressbookQueryByCategoriesCaseInsensitive(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact with categories
	r := newRequest("PUT", "/dav/alice/Contacts/alice.vcf", sampleVCARDWithCategories)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Query with uppercase "WORK" — should still match
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD">
  <prop-filter name="CATEGORIES">
   <text-match>WORK</text-match>
  </prop-filter>
 </comp-filter>
 </filter>
</addressbook-query>`

	r = newRequest("REPORT", "/dav/alice/Contacts/", queryBody)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMultiStatus {
		t.Fatalf("addressbook-query categories case insensitive: status = %d, want %d", w.Code, http.StatusMultiStatus)
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, "Alice Work") {
		t.Errorf("addressbook-query: case-insensitive category search should match: %s", respBody)
	}
}

func TestPUTAndGetContactWithPhoto(t *testing.T) {
	t.Parallel()
	ts := testStoreSetup(t)
	testUser(t, ts, "alice", "pass123")
	h := testHandler(t, ts)

	// PUT a contact with photo
	r := newRequest("PUT", "/dav/alice/Contacts/photo.vcf", sampleVCARDWithPhoto)
	r.Header.Set("Content-Type", "text/vcard")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("PUT: status = %d, want %d, body = %s", w.Code, http.StatusCreated, w.Body.String())
	}

	// GET the contact back
	r = newRequest("GET", "/dav/alice/Contacts/photo.vcf", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want %d, body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "Photo Person") {
		t.Errorf("GET: body does not contain expected name: %s", body)
	}
	if !strings.Contains(body, "PHOTO") {
		t.Errorf("GET: body does not contain PHOTO property: %s", body)
	}
}

func TestVCardMatchesFiltersWithCategories(t *testing.T) {
	t.Parallel()
	// Test the vCardMatchesFilters function directly with CATEGORIES
	filters := []cardDAVFilter{
		{PropName: "CATEGORIES", TextMatch: "work"},
	}
	if !vCardMatchesFilters([]byte(sampleVCARDWithCategories), filters) {
		t.Error("vCardMatchesFilters should match 'work' category")
	}
	if vCardMatchesFilters([]byte(sampleVCARDWithCategories2), filters) {
		t.Error("vCardMatchesFilters should not match 'work' category for Bob")
	}
}

func TestVCardMatchesFiltersCategoriesAndFN(t *testing.T) {
	t.Parallel()
	// Test AND logic: both CATEGORIES and FN must match
	filters := []cardDAVFilter{
		{PropName: "CATEGORIES", TextMatch: "work"},
		{PropName: "FN", TextMatch: "Alice"},
	}
	if !vCardMatchesFilters([]byte(sampleVCARDWithCategories), filters) {
		t.Error("vCardMatchesFilters should match both work category and Alice")
	}
	// Bob has neither work nor Alice
	if vCardMatchesFilters([]byte(sampleVCARDWithCategories2), filters) {
		t.Error("vCardMatchesFilters should not match Bob for work+Alice filter")
	}
}
