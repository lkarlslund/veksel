package caldav

import (
	"net/http"
	"strings"
	"testing"
)

func rawPropfind(t *testing.T, url, depth, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("PROPFIND", url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("alice", "pass123")
	req.Header.Set("Content-Type", "application/xml; charset=UTF-8")
	req.Header.Set("Depth", depth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

// Walk the discovery chain a standards-following client uses after the
// /.well-known redirect: service root -> current-user-principal -> home sets.
func TestInteropClientDiscoveryChain(t *testing.T) {
	ts, h, cleanup := integrationTestSetup(t)
	defer cleanup()
	createTestUser(t, ts, "alice", "pass123")
	srv, srvCleanup := startTestServer(t, h)
	defer srvCleanup()
	base := strings.TrimSuffix(srv.URL, "/")

	status, body := rawPropfind(t, base+"/dav/", "0", `<propfind xmlns="DAV:"><prop><current-user-principal /></prop></propfind>`)
	if status != http.StatusMultiStatus || !strings.Contains(body, "current-user-principal") || !strings.Contains(body, "/dav/alice/") {
		t.Fatalf("service root PROPFIND: status %d body %s", status, body)
	}

	status, body = rawPropfind(t, base+"/dav/alice/", "0", `<propfind xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CR="urn:ietf:params:xml:ns:carddav"><prop><C:calendar-home-set /><CR:addressbook-home-set /></prop></propfind>`)
	if status != http.StatusMultiStatus {
		t.Fatalf("principal PROPFIND: status %d body %s", status, body)
	}
	for _, want := range []string{"calendar-home-set", "addressbook-home-set", "/dav/alice/"} {
		if !strings.Contains(body, want) {
			t.Fatalf("principal PROPFIND is missing %q: %s", want, body)
		}
	}
}
