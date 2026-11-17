package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/autodiscover"
	"github.com/lkarlslund/veksel/pkg/model"
)

func mobileConfigGet(t *testing.T, client *http.Client, url, csrf string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func TestUserMobileConfigDownload(t *testing.T) {
	handler, typed := testHandler(t)
	signed := false
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "mail.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	handler.ConfigureMobileConfig(func() autodiscover.Config {
		return autodiscover.Config{ServerName: "mail.example.test", ImapEnabled: true, ImapStartTLSEnabled: true, ImapPort: 143, SmtpSubmissionEnabled: true, SmtpPort: 587, DavPort: 443, DavTLS: true}
	}, func(context.Context) ([]*x509.Certificate, crypto.Signer, error) {
		if !signed {
			return nil, nil, nil
		}
		return []*x509.Certificate{certificate}, key, nil
	})
	mux := http.NewServeMux()
	handler.Register(mux)
	server := serveTestApp(t, handler, mux)
	t.Cleanup(server.Close)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "alice")
	users := typed.UserStore()
	if err := typed.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := users.AddEmailAddress(t.Context(), "alice@example.test", "alice", "example.test", true); err != nil {
		t.Fatal(err)
	}
	if err := users.Create(t.Context(), "bob", "Bob", "password123"); err != nil {
		t.Fatal(err)
	}
	if err := users.AddEmailAddress(t.Context(), "bob@example.test", "bob", "example.test", true); err != nil {
		t.Fatal(err)
	}

	base := server.URL + "/api/v1/user/mobileconfig"
	response, body := mobileConfigGet(t, client, base+"?identity=alice@example.test&app_password=0", "")
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.Contains(response.Header.Get("Content-Disposition"), "alice@example.test.mobileconfig") || response.Header.Get("X-Profile-Signed") != "false" {
		t.Fatalf("status=%d headers=%v", response.StatusCode, response.Header)
	}
	if !strings.Contains(string(body), "<string>alice@example.test</string>") || strings.Contains(string(body), "<key>IncomingPassword</key>") {
		t.Fatalf("unsigned profile = %s", body)
	}
	passwords, _ := model.NewAppPasswordStore(typed).ListByUser(t.Context(), "alice")
	if len(passwords) != 0 {
		t.Fatalf("plain download created %d credentials", len(passwords))
	}

	response, body = mobileConfigGet(t, client, base+"?identity=bob@example.test", "")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign identity status = %d body=%s", response.StatusCode, body)
	}

	response, _ = mobileConfigGet(t, client, base+"?app_password=1", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("app password without CSRF status = %d", response.StatusCode)
	}

	signed = true
	response, body = mobileConfigGet(t, client, base+"?app_password=1", csrf)
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Profile-Signed") != "true" || len(body) == 0 || body[0] != 0x30 || !bytes.Contains(body, []byte("com.apple.mail.managed")) {
		t.Fatalf("signed profile status=%d headers=%v", response.StatusCode, response.Header)
	}
	passwords, _ = model.NewAppPasswordStore(typed).ListByUser(t.Context(), "alice")
	if len(passwords) != 1 || len(passwords[0].Protocols) != 3 || slices.Contains(passwords[0].Protocols, model.AppProtocolPOP3) {
		t.Fatalf("credentials = %#v", passwords)
	}
	entries, err := audit.New(typed).Query(t.Context(), time.Time{}, "mobileconfig.download", "alice", 10)
	if err != nil || len(entries) != 2 || entries[1].Details["app_password"] != "true" || entries[1].Details["signed"] != "true" {
		t.Fatalf("audit = %#v, %v", entries, err)
	}
}
