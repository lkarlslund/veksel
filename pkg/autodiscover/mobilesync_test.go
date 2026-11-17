package autodiscover

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mobileSyncRequest is the POX body iOS, Android and Windows Mail send.
const mobileSyncRequest = `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006">
  <Request>
    <EMailAddress>alice@example.com</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006</AcceptableResponseSchema>
  </Request>
</Autodiscover>`

// TestMobileSyncAutodiscover replays the ActiveSync client request: it is
// challenged without credentials and then answered in the mobilesync
// schema with the MobileSync server URL. The Outlook schema answer was
// once returned, which ActiveSync clients cannot parse.
func TestMobileSyncAutodiscover(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	handler := testHandler(t, ts)
	handler.cfg.EasEnabled = true

	request := httptest.NewRequest(http.MethodPost, "/Autodiscover/Autodiscover.xml", strings.NewReader(mobileSyncRequest))
	response := httptest.NewRecorder()
	handler.Handle(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("anonymous mobilesync status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/Autodiscover/Autodiscover.xml", strings.NewReader(mobileSyncRequest))
	request.SetBasicAuth("alice@example.com", "pass123")
	response = httptest.NewRecorder()
	handler.Handle(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, body)
	}
	for _, want := range []string{
		`<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">`,
		`<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006">`,
		`<EMailAddress>alice@example.com</EMailAddress>`,
		`<Type>MobileSync</Type><Url>https://mail.example.com/Microsoft-Server-ActiveSync</Url>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response lacks %q:\n%s", want, body)
		}
	}

	request = httptest.NewRequest(http.MethodPost, "/Autodiscover/Autodiscover.xml", strings.NewReader(mobileSyncRequest))
	request.SetBasicAuth("alice", "wrong")
	response = httptest.NewRecorder()
	handler.Handle(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bad password status = %d", response.Code)
	}

	handler.cfg.EasEnabled = false
	request = httptest.NewRequest(http.MethodPost, "/Autodiscover/Autodiscover.xml", strings.NewReader(mobileSyncRequest))
	request.SetBasicAuth("alice", "pass123")
	response = httptest.NewRecorder()
	handler.Handle(response, request)
	if !strings.Contains(response.Body.String(), "<ErrorCode>600</ErrorCode>") {
		t.Fatalf("EAS disabled response = %s", response.Body.String())
	}
}

// TestAutodiscoverJSON replays the Autodiscover v2 lookups of Outlook for
// iOS/Android and Windows.
func TestAutodiscoverJSON(t *testing.T) {
	ts := testStoreSetup(t)
	handler := testHandler(t, ts)
	handler.cfg.EasEnabled = true
	for _, test := range []struct {
		target, protocol, url string
		status                int
	}{
		{"/autodiscover/autodiscover.json/v1.0/alice@example.com?Protocol=ActiveSync", "ActiveSync", "https://mail.example.com/Microsoft-Server-ActiveSync", 200},
		{"/autodiscover/autodiscover.json?Email=alice%40example.com&Protocol=Ews", "EWS", "https://mail.example.com/EWS/Exchange.asmx", 200},
		{"/Autodiscover/Autodiscover.json/v1.0/alice@example.com?Protocol=AutodiscoverV1", "AutodiscoverV1", "https://mail.example.com/autodiscover/autodiscover.xml", 200},
		{"/autodiscover/autodiscover.json/v1.0/alice@example.com?Protocol=Rest", "", "", 400},
		{"/autodiscover/autodiscover.json?Protocol=ActiveSync", "", "", 400},
	} {
		response := httptest.NewRecorder()
		handler.Handle(response, httptest.NewRequest(http.MethodGet, test.target, nil))
		var body map[string]string
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		if response.Code != test.status || body["Protocol"] != test.protocol || body["Url"] != test.url {
			t.Errorf("%s: status %d body %v", test.target, response.Code, body)
		}
		if test.status == 400 && body["ErrorCode"] == "" {
			t.Errorf("%s: error body %v", test.target, body)
		}
	}
}
