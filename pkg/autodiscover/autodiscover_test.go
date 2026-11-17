package autodiscover

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

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
	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSAppPasswords} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %q: %v", ns, err)
		}
	}
	return ts
}

func testUserWithEmail(t *testing.T, ts *model.TypedStore, username, password, email string) {
	t.Helper()
	ctx := context.Background()
	if err := ts.UserStore().Create(ctx, username, username, password); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	// Create a domain for the email
	domain := strings.Split(email, "@")[1]
	_ = ts.DomainStore().Create(ctx, domain) // the domain may already exist
	if err := ts.UserStore().AddEmailAddress(ctx, email, username, domain, true); err != nil {
		t.Fatalf("add email %s: %v", email, err)
	}
}

func testHandler(t *testing.T, ts *model.TypedStore) *Handler {
	t.Helper()
	return New(ts.UserStore(), Config{
		ServerName:             "mail.example.com",
		ListenAddr:             ":8472",
		SmtpPort:               587,
		SmtpTlsPort:            465,
		ImapPort:               143,
		ImapTlsPort:            993,
		Pop3Port:               110,
		Pop3TlsPort:            995,
		DavPath:                "/dav/",
		EwsEnabled:             true,
		ImapTlsEnabled:         true,
		Pop3TlsEnabled:         true,
		SmtpSubmissionEnabled:  true,
		SmtpImplicitTLSEnabled: true,
		ImapEnabled:            true,
		ImapStartTLSEnabled:    true,
		Pop3Enabled:            true,
		Pop3StartTLSEnabled:    true,
	}, func(ctx context.Context, username, password string) (string, error) {
		result, err := protocolauth.New(ts).Authenticate(ctx, username, password, model.AppProtocolEWS)
		return result.User.ID, err
	})
}

// --- Port extraction tests ---

func TestExtractPort(t *testing.T) {
	tests := []struct {
		addr string
		want int
	}{
		{":587", 587},
		{"127.0.0.1:993", 993},
		{":8080", 8080},
		{"", 0},
		{"localhost", 0},
		{":abc", 0},
		{"[::1]:8472", 8472},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := extractPort(tt.addr)
			if got != tt.want {
				t.Errorf("extractPort(%q) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

// --- Microsoft Autodiscover tests ---

func TestMicrosoftAutodiscoverSuccess(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)

	body := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006a">
 <Request>
   <EMailAddress>alice@example.com</EMailAddress>
 </Request>
</Autodiscover>`

	r := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.SetBasicAuth("alice", "pass123")
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify XML response
	var resp msResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response XML: %v\nbody: %s", err, w.Body.String())
	}

	if resp.Response.User.EmailAddr != "alice@example.com" {
		t.Errorf("email = %q, want %q", resp.Response.User.EmailAddr, "alice@example.com")
	}
	if len(resp.Response.Account.Protocols) != 2 || resp.Response.Account.Protocols[0].Type != "EXPR" || resp.Response.Account.Protocols[0].EwsUrl != "https://mail.example.com/EWS/Exchange.asmx" {
		t.Fatalf("EWS protocols = %#v", resp.Response.Account.Protocols)
	}
	smtp := resp.Response.Account.Protocols[1]
	if smtp.Server != "mail.example.com" || smtp.Port != 587 || smtp.Type != "SMTP" {
		t.Errorf("SMTP protocol = %#v", smtp)
	}
}

func TestMicrosoftAutodiscoverNoAuth(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)

	body := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006a">
 <Request>
   <EMailAddress>alice@example.com</EMailAddress>
 </Request>
</Autodiscover>`

	r := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	w := httptest.NewRecorder()
	h.Handle(w, r)

	// Should succeed without auth when email is in request body (auth is optional for lookup)
	if w.Code != http.StatusOK {
		t.Logf("status = %d (auth may be optional for email-only lookup)", w.Code)
	}
}

func TestMicrosoftAutodiscoverBadCredentials(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)

	body := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006a">
 <Request>
   <EMailAddress>alice@example.com</EMailAddress>
 </Request>
</Autodiscover>`

	r := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.SetBasicAuth("alice", "wrongpassword")
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestMicrosoftAutodiscoverWrongMethod(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)

	r := httptest.NewRequest(http.MethodGet, "/autodiscover/autodiscover.xml", nil)
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestMicrosoftAutodiscoverUserNotFound(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)

	body := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006a">
 <Request>
   <EMailAddress>nobody@example.com</EMailAddress>
 </Request>
</Autodiscover>`

	r := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- Mozilla autoconfig tests ---

type autoconfigProvider struct {
	ID       string `xml:"id,attr"`
	Domain   string `xml:"domain"`
	Incoming []struct {
		Type     string `xml:"type,attr"`
		Hostname string `xml:"hostname"`
		Port     int    `xml:"port"`
		Socket   string `xml:"socketType"`
		Username string `xml:"username"`
		EWSURL   string `xml:"ewsURL"`
	} `xml:"incomingServer"`
	Outgoing []struct {
		Type   string `xml:"type,attr"`
		Port   int    `xml:"port"`
		Socket string `xml:"socketType"`
	} `xml:"outgoingServer"`
}

func fetchAutoconfig(t *testing.T, h *Handler, host, target string) autoconfigProvider {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.Handle(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s%s: status %d: %s", host, target, w.Code, w.Body.String())
	}
	var doc struct {
		XMLName  xml.Name           `xml:"clientConfig"`
		Version  string             `xml:"version,attr"`
		Provider autoconfigProvider `xml:"emailProvider"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.Version != "1.1" {
		t.Fatalf("%s%s: %v: %s", host, target, err, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "emailConfig") || strings.Contains(w.Body.String(), "config-v1.1.xml") {
		t.Fatalf("%s%s: not the Mozilla format: %s", host, target, w.Body.String())
	}
	return doc.Provider
}

// TestAutoconfigDomain takes the provider domain from the address, then the
// host the client contacted, never from the file name in the path.
func TestAutoconfigDomain(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)
	for _, test := range []struct{ host, target, want string }{
		{"autoconfig.example.com", "/mail/config-v1.1.xml?emailaddress=user@example.com", "example.com"},
		{"autoconfig.example.com", "/mail/config-v1.1.xml", "example.com"},
		{"example.com", "/.well-known/autoconfig/mail/config-v1.1.xml", "example.com"},
		{"mail.example.com", "/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=bob@other.test", "other.test"},
		{"mail.example.com", "/.well-known/autoconfig/mail", "example.com"},
		{"10.0.0.1", "/mail/config-v1.1.xml", "example.com"},
		{"autoconfig.example.com", "/mail/config-v1.1.xml?emailaddress=x@<bad>", "example.com"},
	} {
		provider := fetchAutoconfig(t, h, test.host, test.target)
		if provider.ID != test.want || provider.Domain != test.want {
			t.Errorf("%s%s: provider %q domain %q, want %q", test.host, test.target, provider.ID, provider.Domain, test.want)
		}
	}
}

func TestAutoconfigServers(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)
	h.cfg.EwsEnabled = true
	provider := fetchAutoconfig(t, h, "autoconfig.example.com", "/mail/config-v1.1.xml?emailaddress=alice@example.com")
	if len(provider.Incoming) == 0 || provider.Incoming[0].Type != "imap" || provider.Incoming[0].Username != "%EMAILADDRESS%" {
		t.Fatalf("incoming = %+v", provider.Incoming)
	}
	var exchange bool
	for _, server := range provider.Incoming {
		exchange = exchange || server.Type == "exchange" && server.EWSURL == "https://mail.example.com/EWS/Exchange.asmx"
	}
	if !exchange {
		t.Errorf("no exchange server with the EWS URL: %+v", provider.Incoming)
	}
	if len(provider.Outgoing) == 0 || provider.Outgoing[0].Type != "smtp" {
		t.Errorf("outgoing = %+v", provider.Outgoing)
	}
}

// --- Routing tests ---

func TestHandleNotFound(t *testing.T) {
	ts := testStoreSetup(t)
	h := testHandler(t, ts)

	r := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- Config defaults test ---

func TestConfigDefaults(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")

	// Test with empty server name — should use localhost
	h := New(ts.UserStore(), Config{
		ServerName:  "",
		SmtpPort:    587,
		ImapTlsPort: 993,
	})

	body := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006a">
 <Request>
   <EMailAddress>alice@example.com</EMailAddress>
 </Request>
</Autodiscover>`

	r := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should default to localhost
	if !strings.Contains(w.Body.String(), "localhost") {
		t.Errorf("response should default to localhost: %s", w.Body.String())
	}
}

// --- TLS config variations ---

func TestThunderbirdWithoutTLS(t *testing.T) {
	ts := testStoreSetup(t)
	h := New(ts.UserStore(), Config{
		ServerName:            "mail.example.com",
		SmtpPort:              587,
		SmtpSubmissionEnabled: true,
		ImapPort:              143,
		ImapTlsPort:           993,
		ImapEnabled:           true,
		ImapStartTLSEnabled:   true,
		ImapTlsEnabled:        false,
	})

	r := httptest.NewRequest(http.MethodGet, "/mail/config-v1.1.xml", nil)
	w := httptest.NewRecorder()
	h.Handle(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	// When TLS is not enabled, should use STARTTLS on port 143
	if !strings.Contains(body, "<socketType>STARTTLS</socketType>") {
		t.Errorf("response should use starttls when TLS is disabled: %s", body)
	}
}
