package caldav

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/carddav"

	"github.com/lkarlslund/veksel/pkg/model"
)

// --- CardDAV client integration test helpers ---

// newCardDAVClient creates a CardDAV client connected to the test server's /dav/ endpoint.
func newCardDAVClient(t *testing.T, srvURL, username, password string) *carddav.Client {
	t.Helper()
	endpoint := strings.TrimSuffix(srvURL, "/") + "/dav/" + username + "/"
	httpClient := webdav.HTTPClientWithBasicAuth(nil, username, password)
	client, err := carddav.NewClient(httpClient, endpoint)
	if err != nil {
		t.Fatalf("create carddav client: %v", err)
	}
	return client
}

// buildVCard creates a simple vCard for testing.
func buildVCard(uid, fn, email string) vcard.Card {
	card := make(vcard.Card)
	card.SetValue(vcard.FieldUID, uid)
	card.SetValue(vcard.FieldFormattedName, fn)
	card.SetValue(vcard.FieldVersion, "4.0")
	card.AddValue(vcard.FieldEmail, email)
	return card
}

// buildVCardWithName creates a vCard with a structured name.
func buildVCardWithName(uid, fn, familyName, givenName, email string) vcard.Card {
	card := buildVCard(uid, fn, email)
	card.SetName(&vcard.Name{
		FamilyName: familyName,
		GivenName:  givenName,
	})
	return card
}

// --- Integration tests using go-webdav/carddav client ---

func TestIntegration_CardDAV_PutAndGetAddressObject(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// testUser creates a default "Contacts" folder

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// Create a vCard
	card := buildVCardWithName("test-contact-001@example.com", "Alice Test", "Test", "Alice", "alice@example.com")

	// PUT the address object
	path := "/dav/alice/Contacts/alice.vcf"
	ao, err := client.PutAddressObject(ctx, path, card)
	if err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}
	if ao.Path == "" {
		t.Error("PutAddressObject: expected non-empty Path")
	}
	if ao.ETag == "" {
		t.Error("PutAddressObject: expected non-empty ETag")
	}

	// GET the address object back
	ao2, err := client.GetAddressObject(ctx, path)
	if err != nil {
		t.Fatalf("GetAddressObject: %v", err)
	}
	if ao2.Card == nil {
		t.Fatal("GetAddressObject: returned nil Card")
	}

	// Verify the formatted name
	fn := ao2.Card.Value(vcard.FieldFormattedName)
	if fn != "Alice Test" {
		t.Errorf("formatted name = %q, want %q", fn, "Alice Test")
	}

	// Verify the email
	email := ao2.Card.Value(vcard.FieldEmail)
	if email != "alice@example.com" {
		t.Errorf("email = %q, want %q", email, "alice@example.com")
	}
}

func TestIntegration_CardDAV_ContactGroupRoundTrip(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()
	createTestUser(t, ts, "alice", "pass123")
	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	card := make(vcard.Card)
	card.SetValue(vcard.FieldVersion, "4.0")
	card.SetValue(vcard.FieldUID, "urn:uuid:group-1")
	card.SetValue(vcard.FieldFormattedName, "Project team")
	card.SetKind(vcard.KindGroup)
	card.AddValue(vcard.FieldMember, "mailto:ada@example.test")
	card.AddValue(vcard.FieldMember, "urn:uuid:member-2")
	client := newCardDAVClient(t, srv.URL, "alice", "pass123")
	path := "/dav/alice/Contacts/project-team.vcf"
	if _, err := client.PutAddressObject(t.Context(), path, card); err != nil {
		t.Fatalf("PutAddressObject(group): %v", err)
	}
	object, err := client.GetAddressObject(t.Context(), path)
	if err != nil {
		t.Fatalf("GetAddressObject(group): %v", err)
	}
	if object.Card.Kind() != vcard.KindGroup || object.Card.Value(vcard.FieldFormattedName) != "Project team" {
		t.Fatalf("group card projection = %#v", object.Card)
	}
	members := object.Card.Values(vcard.FieldMember)
	if len(members) != 2 || members[0] != "mailto:ada@example.test" || members[1] != "urn:uuid:member-2" {
		t.Fatalf("group members = %#v", members)
	}
}

func TestIntegration_CardDAV_PutAddressObjectUpdate(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT initial contact
	card := buildVCardWithName("update-contact@example.com", "Original Name", "Original", "Name", "orig@example.com")
	path := "/dav/alice/Contacts/update.vcf"
	if _, err := client.PutAddressObject(ctx, path, card); err != nil {
		t.Fatalf("PutAddressObject (initial): %v", err)
	}

	// PUT updated contact (same path, different name)
	card2 := buildVCardWithName("update-contact@example.com", "Updated Name", "Updated", "Name", "updated@example.com")
	if _, err := client.PutAddressObject(ctx, path, card2); err != nil {
		t.Fatalf("PutAddressObject (update): %v", err)
	}

	// GET and verify the update
	ao, err := client.GetAddressObject(ctx, path)
	if err != nil {
		t.Fatalf("GetAddressObject: %v", err)
	}

	fn := ao.Card.Value(vcard.FieldFormattedName)
	if fn != "Updated Name" {
		t.Errorf("formatted name = %q, want %q", fn, "Updated Name")
	}

	email := ao.Card.Value(vcard.FieldEmail)
	if email != "updated@example.com" {
		t.Errorf("email = %q, want %q", email, "updated@example.com")
	}
}

func TestIntegration_CardDAV_QueryAddressBook(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT three contacts
	contacts := []struct {
		uid   string
		fn    string
		email string
		path  string
	}{
		{"contact-001@example.com", "John Doe", "john@example.com", "/dav/alice/Contacts/john.vcf"},
		{"contact-002@example.com", "Jane Smith", "jane@example.com", "/dav/alice/Contacts/jane.vcf"},
		{"contact-003@example.com", "Bob Johnson", "bob@example.com", "/dav/alice/Contacts/bob.vcf"},
	}

	for _, c := range contacts {
		card := buildVCardWithName(c.uid, c.fn, strings.Split(c.fn, " ")[1], strings.Split(c.fn, " ")[0], c.email)
		if _, err := client.PutAddressObject(ctx, c.path, card); err != nil {
			t.Fatalf("PutAddressObject %s: %v", c.path, err)
		}
	}

	// Query for contacts with "John" in FN using a raw HTTP REPORT so the
	// filtering request and response body are both asserted explicitly.
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD">
 <prop-filter name="FN">
  <text-match>John</text-match>
 </prop-filter>
 </comp-filter>
 </filter>
</addressbook-query>`

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	respBody := string(body)
	// Should contain John Doe and Bob Johnson
	if !strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: body does not contain John Doe: %s", respBody)
	}
	if !strings.Contains(respBody, "Bob Johnson") {
		t.Errorf("addressbook-query: body does not contain Bob Johnson: %s", respBody)
	}
	// Should NOT contain Jane Smith
	if strings.Contains(respBody, "Jane Smith") {
		t.Errorf("addressbook-query: body should not contain Jane Smith: %s", respBody)
	}
}

func TestIntegration_CardDAV_QueryAddressBookByEmail(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT two contacts
	card1 := buildVCardWithName("email-001@example.com", "John Doe", "Doe", "John", "john@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/john.vcf", card1); err != nil {
		t.Fatalf("PutAddressObject (john): %v", err)
	}

	card2 := buildVCardWithName("email-002@example.com", "Jane Smith", "Smith", "Jane", "jane@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/jane.vcf", card2); err != nil {
		t.Fatalf("PutAddressObject (jane): %v", err)
	}

	// Query for contacts with "jane" in EMAIL using raw HTTP REPORT
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

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	respBody := string(body)
	// Should contain Jane Smith
	if !strings.Contains(respBody, "Jane Smith") {
		t.Errorf("addressbook-query: body does not contain Jane Smith: %s", respBody)
	}
	// Should NOT contain John Doe
	if strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: body should not contain John Doe: %s", respBody)
	}
}

func TestIntegration_CardDAV_QueryAddressBookNoFilter(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT two contacts
	card1 := buildVCardWithName("nofilter-001@example.com", "Alice A", "A", "Alice", "alice@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/alice.vcf", card1); err != nil {
		t.Fatalf("PutAddressObject (alice): %v", err)
	}

	card2 := buildVCardWithName("nofilter-002@example.com", "Bob B", "B", "Bob", "bob@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/bob.vcf", card2); err != nil {
		t.Fatalf("PutAddressObject (bob): %v", err)
	}

	// Query without text-match filter using raw HTTP REPORT
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD"/>
 </filter>
</addressbook-query>`

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	// Count the number of href responses (should be 2 contacts)
	respBody := string(body)
	hrefCount := strings.Count(respBody, "<d:href>")
	if hrefCount != 2 {
		t.Errorf("addressbook-query: found %d hrefs, expected 2", hrefCount)
	}
}

func TestIntegration_CardDAV_QueryAddressBookEmpty(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// Query empty addressbook
	query := &carddav.AddressBookQuery{}

	results, err := client.QueryAddressBook(ctx, "/dav/alice/Contacts/", query)
	if err != nil {
		t.Fatalf("QueryAddressBook: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("QueryAddressBook on empty addressbook: got %d results, want 0", len(results))
	}
}

func TestIntegration_CardDAV_MultiGetAddressBook(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT two contacts
	card1 := buildVCardWithName("multiget-001@example.com", "MultiGet One", "One", "MultiGet", "one@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/one.vcf", card1); err != nil {
		t.Fatalf("PutAddressObject (one): %v", err)
	}

	card2 := buildVCardWithName("multiget-002@example.com", "MultiGet Two", "Two", "MultiGet", "two@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/two.vcf", card2); err != nil {
		t.Fatalf("PutAddressObject (two): %v", err)
	}

	// Use CardDAV multiget REPORT via raw HTTP (client library uses addressbook-multiget which server doesn't support)
	multigetBody := `<?xml version="1.0" encoding="utf-8"?>
<multiget xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <D:href xmlns:D="DAV:">/dav/alice/Contacts/one.vcf</D:href>
 <D:href xmlns:D="DAV:">/dav/alice/Contacts/two.vcf</D:href>
</multiget>`

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(multigetBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Depth", "1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("multiget: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	respBody := string(body)
	if !strings.Contains(respBody, "MultiGet One") {
		t.Errorf("multiget: body does not contain MultiGet One: %s", respBody)
	}
	if !strings.Contains(respBody, "MultiGet Two") {
		t.Errorf("multiget: body does not contain MultiGet Two: %s", respBody)
	}
}

func TestIntegration_CardDAV_PROPFINDAddressbookContents(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT multiple contacts
	for i := 0; i < 3; i++ {
		card := buildVCardWithName(
			"propfind-001@example.com",
			"Contact",
			"Contact",
			strings.Repeat(string(rune('A'+i)), 1),
			"test@example.com",
		)
		path := "/dav/alice/Contacts/contact" + string(rune('A'+i)) + ".vcf"
		if _, err := client.PutAddressObject(ctx, path, card); err != nil {
			t.Fatalf("PutAddressObject %d: %v", i, err)
		}
	}

	// Use raw PROPFIND to list addressbook contents
	propfindBody := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
 <D:prop>
 <D:getetag/>
 </D:prop>
</D:propfind>`

	req, err := http.NewRequest("PROPFIND",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(propfindBody))
	if err != nil {
		t.Fatalf("create PROPFIND request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Depth", "1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PROPFIND request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	// Count href responses (should be 3 contacts + 1 addressbook)
	respBody := string(body)
	hrefCount := strings.Count(respBody, "<d:href>")
	if hrefCount < 4 {
		t.Errorf("PROPFIND: found %d hrefs, expected at least 4 (3 contacts + 1 addressbook)", hrefCount)
	}
}

func TestIntegration_CardDAV_WebDAVStat(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("stat-contact@example.com", "Stat Test", "Test", "Stat", "stat@example.com")
	path := "/dav/alice/Contacts/stat.vcf"
	if _, err := client.PutAddressObject(ctx, path, card); err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// Use WebDAV client to stat the resource
	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")
	fi, err := wdavClient.Stat(ctx, path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if fi.Path != path {
		t.Errorf("Stat: path = %q, want %q", fi.Path, path)
	}
	if fi.IsDir {
		t.Error("Stat: expected file, got directory")
	}
}

func TestIntegration_CardDAV_WebDAVRemoveAll(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")
	wdavClient := newWebDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("delete-contact@example.com", "Delete Test", "Test", "Delete", "delete@example.com")
	path := "/dav/alice/Contacts/delete.vcf"
	if _, err := client.PutAddressObject(ctx, path, card); err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// Delete the contact
	if err := wdavClient.RemoveAll(ctx, path); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	// Verify it's gone
	_, err := client.GetAddressObject(ctx, path)
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestIntegration_CardDAV_AddressObjectETag(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("etag-contact@example.com", "ETag Test", "Test", "ETag", "etag@example.com")
	path := "/dav/alice/Contacts/etag.vcf"

	ao, err := client.PutAddressObject(ctx, path, card)
	if err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	putETag := ao.ETag
	if putETag == "" {
		t.Error("PutAddressObject: expected non-empty ETag")
	}

	// GET and compare ETag
	ao2, err := client.GetAddressObject(ctx, path)
	if err != nil {
		t.Fatalf("GetAddressObject: %v", err)
	}

	if ao2.ETag != putETag {
		t.Errorf("ETag mismatch: PUT returned %q, GET returned %q", putETag, ao2.ETag)
	}
}

func TestIntegration_CardDAV_CreateAddressbookMKCOL(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// Create a new addressbook collection using MKCOL
	req, err := http.NewRequest("MKCOL",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/WorkContacts",
		strings.NewReader(`<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
 <D:resourcetype>
 <C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>
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

	// Verify the addressbook was created
	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "WorkContacts")
	if err != nil {
		t.Fatalf("GetByPath after MKCOL: %v", err)
	}
	if folder.Type != model.FolderTypeContacts {
		t.Errorf("folder type = %q, want %q", folder.Type, model.FolderTypeContacts)
	}

	// Now use the CardDAV client to PUT a contact in the new addressbook
	client := newCardDAVClient(t, srv.URL, "alice", "pass123")
	card := buildVCardWithName("mkcol-contact@example.com", "Work Contact", "Contact", "Work", "work@example.com")
	ao, err := client.PutAddressObject(ctx, "/dav/alice/WorkContacts/work.vcf", card)
	if err != nil {
		t.Fatalf("PutAddressObject in new addressbook: %v", err)
	}
	if ao.Path == "" {
		t.Error("PutAddressObject: expected non-empty Path")
	}
}

func TestIntegration_CardDAV_MultipleAddressbooks(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// Create additional addressbooks
	if err := ts.FolderStore().Create(ctx, "alice", "WorkContacts", model.FolderTypeContacts, ""); err != nil {
		t.Fatalf("create addressbook: %v", err)
	}
	if err := ts.FolderStore().Create(ctx, "alice", "FamilyContacts", model.FolderTypeContacts, ""); err != nil {
		t.Fatalf("create addressbook: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT contacts in different addressbooks
	card1 := buildVCardWithName("multi-ab-001@example.com", "Personal Contact", "Contact", "Personal", "personal@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/personal.vcf", card1); err != nil {
		t.Fatalf("PutAddressObject (personal): %v", err)
	}

	card2 := buildVCardWithName("multi-ab-002@example.com", "Work Contact", "Contact", "Work", "work@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/WorkContacts/work.vcf", card2); err != nil {
		t.Fatalf("PutAddressObject (work): %v", err)
	}

	// Query personal addressbook using raw HTTP — should only find personal contact
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:"><D:getetag/><address-data/></D:prop>
 <filter><comp-filter name="VCARD"/></filter>
</addressbook-query>`

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query (personal): status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}
	respBody := string(body)
	hrefCount := strings.Count(respBody, "<d:href>")
	if hrefCount != 1 {
		t.Errorf("addressbook-query (personal): found %d hrefs, expected 1", hrefCount)
	}
	if !strings.Contains(respBody, "Personal Contact") {
		t.Errorf("addressbook-query (personal): body does not contain Personal Contact: %s", respBody)
	}
	if strings.Contains(respBody, "Work Contact") {
		t.Errorf("addressbook-query (personal): body should not contain Work Contact: %s", respBody)
	}

	// Query work addressbook using raw HTTP — should only find work contact
	req, err = http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/WorkContacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query (work): status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}
	respBody = string(body)
	hrefCount = strings.Count(respBody, "<d:href>")
	if hrefCount != 1 {
		t.Errorf("addressbook-query (work): found %d hrefs, expected 1", hrefCount)
	}
	if !strings.Contains(respBody, "Work Contact") {
		t.Errorf("addressbook-query (work): body does not contain Work Contact: %s", respBody)
	}
	if strings.Contains(respBody, "Personal Contact") {
		t.Errorf("addressbook-query (work): body should not contain Personal Contact: %s", respBody)
	}
}

func TestIntegration_CardDAV_UserNotFound(t *testing.T) {
	_, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// Connect as a non-existent user
	client := newCardDAVClient(t, srv.URL, "nobody", "pass")

	ctx := context.Background()

	// Any operation should fail
	_, err := client.GetAddressObject(ctx, "/dav/nobody/Contacts/test.vcf")
	if err == nil {
		t.Error("expected error for non-existent user, got nil")
	}
}

func TestIntegration_CardDAV_vCard3And4(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// The go-vcard library produces vCard 4.0 by default
	// Test that we can also handle vCard 3.0 via raw PUT

	// vCard 3.0
	vcard3 := `BEGIN:VCARD
VERSION:3.0
UID:vcard3-test@example.com
FN:VCARD 3.0 Test
N:Test;VCARD 3.0;;;
EMAIL;TYPE=INTERNET:vcard3@example.com
END:VCARD`

	// PUT vCard 3.0 via raw HTTP
	req, err := http.NewRequest("PUT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/vcard3.vcf",
		strings.NewReader(vcard3))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "text/vcard")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT vCard 3.0: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	// GET it back via the client
	ao, err := client.GetAddressObject(ctx, "/dav/alice/Contacts/vcard3.vcf")
	if err != nil {
		t.Fatalf("GetAddressObject (vCard 3.0): %v", err)
	}

	fn := ao.Card.Value(vcard.FieldFormattedName)
	if fn != "VCARD 3.0 Test" {
		t.Errorf("formatted name = %q, want %q", fn, "VCARD 3.0 Test")
	}

	// vCard 4.0 via client
	card4 := buildVCardWithName("vcard4-test@example.com", "VCARD 4.0 Test", "Test", "VCARD 4.0", "vcard4@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/vcard4.vcf", card4); err != nil {
		t.Fatalf("PutAddressObject (vCard 4.0): %v", err)
	}

	ao2, err := client.GetAddressObject(ctx, "/dav/alice/Contacts/vcard4.vcf")
	if err != nil {
		t.Fatalf("GetAddressObject (vCard 4.0): %v", err)
	}

	fn2 := ao2.Card.Value(vcard.FieldFormattedName)
	if fn2 != "VCARD 4.0 Test" {
		t.Errorf("formatted name = %q, want %q", fn2, "VCARD 4.0 Test")
	}
}

func TestIntegration_CardDAV_AddressbookQueryCaseInsensitive(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("case-contact@example.com", "John Doe", "Doe", "John", "john@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/john.vcf", card); err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// Query with uppercase "JOHN" using raw HTTP — should still match
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

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	respBody := string(body)
	if !strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: case-insensitive search should match John Doe: %s", respBody)
	}
}

func TestIntegration_CardDAV_QueryNonExistentMatch(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("nomatch-contact@example.com", "John Doe", "Doe", "John", "john@example.com")
	if _, err := client.PutAddressObject(ctx, "/dav/alice/Contacts/john.vcf", card); err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// Query for a name that doesn't exist using raw HTTP
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

	req, err := http.NewRequest("REPORT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/",
		strings.NewReader(queryBody))
	if err != nil {
		t.Fatalf("create REPORT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REPORT request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status = %d, want %d, body = %s", resp.StatusCode, http.StatusMultiStatus, body)
	}

	// Should not contain any vCard data
	respBody := string(body)
	if strings.Contains(respBody, "John Doe") {
		t.Errorf("addressbook-query: should not return any results for non-matching query: %s", respBody)
	}
}

func TestIntegration_CardDAV_MixedWithCalDAV(t *testing.T) {
	// Test that both CalDAV and CardDAV work for the same user
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	// Create a calendar
	if err := ts.FolderStore().Create(ctx, "alice", "MyCal", model.FolderTypeCalendar, ""); err != nil {
		t.Fatalf("create calendar: %v", err)
	}

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// PUT a contact via CardDAV client
	cardClient := newCardDAVClient(t, srv.URL, "alice", "pass123")
	card := buildVCardWithName("mixed-contact@example.com", "Mixed Test", "Test", "Mixed", "mixed@example.com")
	if _, err := cardClient.PutAddressObject(ctx, "/dav/alice/Contacts/mixed.vcf", card); err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// GET the contact back
	ao, err := cardClient.GetAddressObject(ctx, "/dav/alice/Contacts/mixed.vcf")
	if err != nil {
		t.Fatalf("GetAddressObject: %v", err)
	}
	if ao.Card.Value(vcard.FieldFormattedName) != "Mixed Test" {
		t.Errorf("formatted name = %q, want %q", ao.Card.Value(vcard.FieldFormattedName), "Mixed Test")
	}

	// PUT a calendar event via CalDAV client
	calClient := newCalDAVClient(t, srv.URL, "alice", "pass123")
	cal := buildICalEvent("mixed-event@example.com",
		time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC),
		time.Date(2025, 12, 1, 11, 0, 0, 0, time.UTC),
		"Mixed CalDAV Event")
	if _, err := calClient.PutCalendarObject(ctx, "/dav/alice/MyCal/mixed.ics", cal); err != nil {
		t.Fatalf("PutCalendarObject: %v", err)
	}

	// GET the event back
	co, err := calClient.GetCalendarObject(ctx, "/dav/alice/MyCal/mixed.ics")
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}
	summary, _ := co.Data.Children[0].Props.Text(ical.PropSummary)
	if summary != "Mixed CalDAV Event" {
		t.Errorf("summary = %q, want %q", summary, "Mixed CalDAV Event")
	}
}

func TestIntegration_CardDAV_AddressbookQueryNonExistentAddressbook(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// Query a non-existent addressbook
	query := &carddav.AddressBookQuery{}

	_, err := client.QueryAddressBook(ctx, "/dav/alice/NoContacts/", query)
	if err == nil {
		t.Error("expected error for non-existent addressbook, got nil")
	}
}

func TestIntegration_CardDAV_PutInvalidVCard(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	// PUT invalid data (not a vCard) via raw HTTP
	req, err := http.NewRequest("PUT",
		strings.TrimSuffix(srv.URL, "/")+"/dav/alice/Contacts/bad.vcf",
		strings.NewReader("this is not a vcard"))
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "text/vcard")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT invalid: status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestIntegration_CardDAV_PutInNonExistentAddressbook(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// Try to PUT in a non-existent addressbook
	card := buildVCardWithName("bad-ab-contact@example.com", "Bad AB", "AB", "Bad", "bad@example.com")
	_, err := client.PutAddressObject(ctx, "/dav/alice/NoContacts/bad.vcf", card)
	if err == nil {
		t.Error("expected error for non-existent addressbook, got nil")
	}
}

func TestIntegration_CardDAV_AddressObjectPath(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("path-contact@example.com", "Path Test", "Test", "Path", "path@example.com")
	path := "/dav/alice/Contacts/path.vcf"
	ao, err := client.PutAddressObject(ctx, path, card)
	if err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// Verify the path is set correctly
	if ao.Path == "" {
		t.Error("PutAddressObject: expected non-empty Path")
	}

	// GET and verify path
	ao2, err := client.GetAddressObject(ctx, path)
	if err != nil {
		t.Fatalf("GetAddressObject: %v", err)
	}

	if ao2.Path != path {
		t.Errorf("GetAddressObject: path = %q, want %q", ao2.Path, path)
	}
}

func TestIntegration_CardDAV_AddressObjectContentLength(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	createTestUser(t, ts, "alice", "pass123")

	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()

	client := newCardDAVClient(t, srv.URL, "alice", "pass123")

	// PUT a contact
	card := buildVCardWithName("cl-contact@example.com", "Content Length Test", "Test", "Content Length", "cl@example.com")
	path := "/dav/alice/Contacts/cl.vcf"
	_, err := client.PutAddressObject(ctx, path, card)
	if err != nil {
		t.Fatalf("PutAddressObject: %v", err)
	}

	// GET and verify content length
	ao2, err := client.GetAddressObject(ctx, path)
	if err != nil {
		t.Fatalf("GetAddressObject: %v", err)
	}

	if ao2.ContentLength <= 0 {
		t.Errorf("GetAddressObject: ContentLength = %d, expected > 0", ao2.ContentLength)
	}

	// Verify the content matches
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(ao2.Card); err != nil {
		t.Fatalf("encode card: %v", err)
	}
	if !strings.Contains(buf.String(), "Content Length Test") {
		t.Error("encoded card does not contain expected name")
	}
}
