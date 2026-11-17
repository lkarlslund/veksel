package autodiscover

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func soap11Request(namespace string, mailboxes, settings []string) string {
	var body strings.Builder
	body.WriteString(`<s:Envelope xmlns:s="` + soap11Namespace + `" xmlns:a="` + namespace + `" xmlns:wsa="` + wsa2005Namespace + `"><s:Header><wsa:Action s:mustUnderstand="1">`)
	body.WriteString(namespace + `/Autodiscover/GetUserSettings`)
	body.WriteString(`</wsa:Action></s:Header><s:Body><a:GetUserSettingsRequestMessage><a:Request><a:Users>`)
	for _, mailbox := range mailboxes {
		body.WriteString(`<a:User><a:Mailbox>`)
		_ = xml.EscapeText(&body, []byte(mailbox))
		body.WriteString(`</a:Mailbox></a:User>`)
	}
	body.WriteString(`</a:Users><a:RequestedSettings>`)
	for _, setting := range settings {
		body.WriteString(`<a:Setting>`)
		_ = xml.EscapeText(&body, []byte(setting))
		body.WriteString(`</a:Setting>`)
	}
	body.WriteString(`</a:RequestedSettings></a:Request></a:GetUserSettingsRequestMessage></s:Body></s:Envelope>`)
	return body.String()
}

func serveSOAP(t *testing.T, h *Handler, path, contentType, action, username, password, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	if action != "" {
		r.Header.Set("SOAPAction", `"`+action+`"`)
	}
	if username != "" || password != "" {
		r.SetBasicAuth(username, password)
	}
	w := httptest.NewRecorder()
	h.Handle(w, r)
	return w
}

func childNamed(node *soapNode, space, local string) *soapNode {
	if node == nil {
		return nil
	}
	for _, child := range node.children {
		if child.name == (xml.Name{Space: space, Local: local}) {
			return child
		}
	}
	return nil
}

func descendantsNamed(node *soapNode, space, local string) []*soapNode {
	var result []*soapNode
	var walk func(*soapNode)
	walk = func(current *soapNode) {
		for _, child := range current.children {
			if child.name == (xml.Name{Space: space, Local: local}) {
				result = append(result, child)
			}
			walk(child)
		}
	}
	walk(node)
	return result
}

func TestSOAPGetUserSettingsReturnsRequestedManagedSettings(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alias@example.com", "alice", "example.com", false); err != nil {
		t.Fatal(err)
	}
	h := testHandler(t, ts)
	h.cfg.ImapServerName = "imap.example.com"
	h.cfg.Pop3ServerName = "pop.example.com"
	settings := []string{"UserDisplayName", "AutoDiscoverSMTPAddress", "ExternalEwsUrl", "ExternalImap4Connections", "ExternalPop3Connections", "ExternalSmtpConnections"}
	body := soap11Request(autodiscoverHTTPSNamespace, []string{"alias@example.com"}, settings)
	w := serveSOAP(t, h, "/AUTODISCOVER/AUTODISCOVER.SVC", "text/xml; charset=utf-8", autodiscoverHTTPSNamespace+"/Autodiscover/GetUserSettings", "alice", "pass123", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	root, err := parseSOAPTree(w.Body.Bytes())
	if err != nil {
		t.Fatalf("response XML: %v\n%s", err, w.Body.String())
	}
	if root.name != (xml.Name{Space: soap11Namespace, Local: "Envelope"}) {
		t.Fatalf("envelope = %#v", root.name)
	}
	names := descendantsNamed(root, autodiscoverHTTPSNamespace, "Name")
	if len(names) != len(settings) {
		t.Fatalf("setting names = %d, want %d: %s", len(names), len(settings), w.Body.String())
	}
	for i := range settings {
		if got := strings.TrimSpace(names[i].text.String()); got != settings[i] {
			t.Fatalf("setting %d = %q, want %q", i, got, settings[i])
		}
	}
	values := descendantsNamed(root, autodiscoverHTTPSNamespace, "Value")
	if len(values) < 3 || strings.TrimSpace(values[1].text.String()) != "alice@example.com" || strings.TrimSpace(values[2].text.String()) != "https://mail.example.com/EWS/Exchange.asmx" {
		t.Fatalf("string values are incomplete: %s", w.Body.String())
	}
	hosts := descendantsNamed(root, autodiscoverHTTPSNamespace, "Hostname")
	gotHosts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		gotHosts = append(gotHosts, strings.TrimSpace(host.text.String()))
	}
	joined := strings.Join(gotHosts, ",")
	for _, want := range []string{"imap.example.com", "pop.example.com", "mail.example.com"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("connections %q do not include %q", joined, want)
		}
	}
	for _, encryption := range []string{"SSL", "TLS"} {
		if !strings.Contains(w.Body.String(), ">"+encryption+"<") {
			t.Fatalf("response does not contain %s connection: %s", encryption, w.Body.String())
		}
	}
}

func TestSOAPGetUserSettingsSOAP12AndHTTPNamespace(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)
	action := autodiscoverHTTPNamespace + "/Autodiscover/GetUserSettings"
	body := strings.ReplaceAll(soap11Request(autodiscoverHTTPNamespace, []string{"alice@example.com"}, []string{"UserDN"}), soap11Namespace, soap12Namespace)
	w := serveSOAP(t, h, "/autodiscover/autodiscover.svc", `application/soap+xml; charset=utf-8; action="`+action+`"`, "", "alice@example.com", "pass123", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/soap+xml") {
		t.Fatalf("content type = %q", got)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "GetUserSettingsResponse") {
		t.Fatalf("SOAP 1.2 response action is missing: %q", w.Header().Get("Content-Type"))
	}
	root, err := parseSOAPTree(w.Body.Bytes())
	if err != nil || root.name.Space != soap12Namespace {
		t.Fatalf("SOAP 1.2 response: root=%#v err=%v body=%s", root, err, w.Body.String())
	}
}

func TestSOAPGetUserSettingsMirrorsLegacyAddressingNamespace(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)
	body := strings.ReplaceAll(soap11Request(autodiscoverHTTPNamespace, []string{"alice@example.com"}, []string{"UserDN"}), wsa2005Namespace, wsa2004Namespace)
	w := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass123", body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `xmlns:a="`+wsa2004Namespace+`"`) {
		t.Fatalf("legacy addressing response = %d %s", w.Code, w.Body.String())
	}
}

func TestSOAPGetUserSettingsUsesCommonApplicationPassword(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "primary-password", "alice@example.com")
	_, secret, err := model.NewAppPasswordStore(ts).Create(t.Context(), "alice", "EWS client", []string{model.AppProtocolEWS})
	if err != nil {
		t.Fatal(err)
	}
	h := testHandler(t, ts)
	body := soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"ExternalEwsUrl"})
	w := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", secret, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	_, wrongScope, err := model.NewAppPasswordStore(ts).Create(t.Context(), "alice", "IMAP client", []string{model.AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	w = serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", wrongScope, body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-scope app password status = %d, want 401", w.Code)
	}
}

func TestSOAPGetUserSettingsIsolatesAccountsAndPreservesOrder(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	testUserWithEmail(t, ts, "bob", "pass456", "bob@example.com")
	if err := ts.UserStore().AddEmailAddress(t.Context(), "alias@example.com", "alice", "example.com", false); err != nil {
		t.Fatal(err)
	}
	h := testHandler(t, ts)
	body := soap11Request(autodiscoverHTTPSNamespace, []string{"alias@example.com", "bob@example.com", "missing@example.com", "alice@example.com"}, []string{"UserDisplayName"})
	w := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass123", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	root, err := parseSOAPTree(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	responses := descendantsNamed(root, autodiscoverHTTPSNamespace, "UserResponse")
	if len(responses) != 4 {
		t.Fatalf("responses = %d, want 4", len(responses))
	}
	want := []string{"NoError", "InvalidUser", "InvalidUser", "NoError"}
	for i, response := range responses {
		code := childNamed(response, autodiscoverHTTPSNamespace, "ErrorCode")
		if code == nil || strings.TrimSpace(code.text.String()) != want[i] {
			t.Fatalf("response %d code = %#v, want %q", i, code, want[i])
		}
	}
	foreign := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass123", soap11Request(autodiscoverHTTPSNamespace, []string{"bob@example.com"}, []string{"UserDisplayName"}))
	missing := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass123", soap11Request(autodiscoverHTTPSNamespace, []string{"missing@example.com"}, []string{"UserDisplayName"}))
	if foreign.Body.String() != missing.Body.String() {
		t.Fatalf("foreign and unknown identity responses differ\nforeign=%s\nmissing=%s", foreign.Body.String(), missing.Body.String())
	}
}

func TestSOAPGetUserSettingsReportsSettingErrors(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)
	h.cfg.EwsEnabled = false
	h.cfg.Pop3Enabled = false
	h.cfg.Pop3TlsEnabled = false
	body := soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"ExternalEwsUrl", "ExternalPop3Connections", "InternalOABUrl", "DefinitelyNotASetting", "UserDisplayName"})
	w := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass123", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if strings.Count(w.Body.String(), "SettingIsNotAvailable") != 3 || strings.Count(w.Body.String(), "InvalidSetting") != 1 {
		t.Fatalf("setting errors are incorrect: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "UserDisplayName") {
		t.Fatalf("available setting was omitted: %s", w.Body.String())
	}
}

func TestSOAPGetUserSettingsAuthenticationFailuresAreIndistinguishable(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)
	body := soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"UserDisplayName"})
	missing := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "", "", body)
	wrong := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "wrong", body)
	unknown := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "unknown", "wrong", body)
	for name, response := range map[string]*httptest.ResponseRecorder{"missing": missing, "wrong": wrong, "unknown": unknown} {
		if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != `Basic realm="Autodiscover"` || response.Body.Len() != 0 {
			t.Fatalf("%s auth response = status %d headers %#v body %q", name, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestSOAPGetUserSettingsRejectsInvalidRequestsBeforeAuthentication(t *testing.T) {
	ts := testStoreSetup(t)
	authCalls := 0
	h := New(ts.UserStore(), Config{}, func(_ context.Context, _, _ string) (string, error) {
		authCalls++
		return "alice", nil
	})
	body := soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"UserDisplayName"})
	w := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", autodiscoverHTTPSNamespace+"/Autodiscover/Wrong", "alice", "pass", body)
	if w.Code != http.StatusBadRequest || authCalls != 0 {
		t.Fatalf("invalid request status = %d, auth calls = %d, body = %s", w.Code, authCalls, w.Body.String())
	}
}

func TestParseSOAPRequestRejectsMalformedAndUnboundedInput(t *testing.T) {
	action := autodiscoverHTTPSNamespace + "/Autodiscover/GetUserSettings"
	valid := soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"UserDisplayName"})
	manyUsers := make([]string, maxSOAPUsers+1)
	for i := range manyUsers {
		manyUsers[i] = fmt.Sprintf("user%d@example.com", i)
	}
	manySettings := make([]string, maxSOAPSettings+1)
	for i := range manySettings {
		manySettings[i] = fmt.Sprintf("Setting%d", i)
	}
	tests := map[string]string{
		"directive":         strings.Replace(valid, `<s:Envelope`, `<!DOCTYPE x><s:Envelope`, 1),
		"trailing document": valid + valid,
		"wrong operation":   strings.Replace(valid, "GetUserSettingsRequestMessage", "GetDomainSettingsRequestMessage", 2),
		"wrong namespace":   strings.ReplaceAll(valid, autodiscoverHTTPSNamespace, "https://example.invalid/Autodiscover"),
		"unexpected child":  strings.Replace(valid, `</a:Request>`, `<a:Extra/></a:Request>`, 1),
		"header after body": strings.Replace(valid, `<s:Header><wsa:Action s:mustUnderstand="1">`+action+`</wsa:Action></s:Header><s:Body>`, `<s:Body>`, 1) + `<s:Header/>`,
		"too many users":    soap11Request(autodiscoverHTTPSNamespace, manyUsers, []string{"UserDisplayName"}),
		"too many settings": soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, manySettings),
		"long mailbox":      soap11Request(autodiscoverHTTPSNamespace, []string{strings.Repeat("a", 321)}, []string{"UserDisplayName"}),
		"long setting":      soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{strings.Repeat("a", 129)}),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSOAPRequest(strings.NewReader(body), soap11Namespace, action); err == nil {
				t.Fatal("expected malformed request to fail")
			}
		})
	}
	oversized := bytes.Repeat([]byte("x"), maxSOAPBodyBytes+1)
	if _, err := parseSOAPRequest(bytes.NewReader(oversized), soap11Namespace, action); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized request error = %v", err)
	}
	if _, err := parseSOAPRequest(strings.NewReader(valid), soap11Namespace, action+"Wrong"); err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("mismatched action error = %v", err)
	}
	if _, err := parseSOAPRequest(strings.NewReader(strings.Replace(valid, `<wsa:Action s:mustUnderstand="1">`+action+`</wsa:Action>`, "", 1)), soap11Namespace, ""); err == nil || !strings.Contains(err.Error(), "action is required") {
		t.Fatalf("missing action error = %v", err)
	}
	deep := `<s:Envelope xmlns:s="` + soap11Namespace + `"><s:Header>` + strings.Repeat(`<x>`, maxSOAPDepth) + strings.Repeat(`</x>`, maxSOAPDepth) + `</s:Header><s:Body/></s:Envelope>`
	if _, err := parseSOAPRequest(strings.NewReader(deep), soap11Namespace, action); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep request error = %v", err)
	}
	manyNodes := `<s:Envelope xmlns:s="` + soap11Namespace + `"><s:Header>` + strings.Repeat(`<x/>`, maxSOAPNodes) + `</s:Header><s:Body/></s:Envelope>`
	if _, err := parseSOAPRequest(strings.NewReader(manyNodes), soap11Namespace, action); err == nil || !strings.Contains(err.Error(), "element count") {
		t.Fatalf("node-count request error = %v", err)
	}
}

func TestSOAPGetUserSettingsHTTPFailures(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)
	get := httptest.NewRequest(http.MethodGet, "/autodiscover/autodiscover.svc", nil)
	getResponse := httptest.NewRecorder()
	h.Handle(getResponse, get)
	if getResponse.Code != http.StatusMethodNotAllowed || getResponse.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET response = %d %#v", getResponse.Code, getResponse.Header())
	}
	invalidType := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "application/json", "", "alice", "pass", `{}`)
	if invalidType.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("invalid content type = %d", invalidType.Code)
	}
	malformed := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass", `<broken>`)
	if malformed.Code != http.StatusBadRequest || !strings.Contains(malformed.Body.String(), "s:Fault") {
		t.Fatalf("malformed response = %d %s", malformed.Code, malformed.Body.String())
	}
	soap12Malformed := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "application/soap+xml", "", "alice", "pass", `<broken>`)
	if soap12Malformed.Code != http.StatusBadRequest || !strings.Contains(soap12Malformed.Body.String(), "s:Sender") {
		t.Fatalf("SOAP 1.2 malformed response = %d %s", soap12Malformed.Code, soap12Malformed.Body.String())
	}
	wrongPath := serveSOAP(t, h, "/prefix/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass", `<broken>`)
	if wrongPath.Code != http.StatusNotFound {
		t.Fatalf("noncanonical SOAP path = %d, want 404", wrongPath.Code)
	}
}
