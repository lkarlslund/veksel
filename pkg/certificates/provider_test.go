package certificates

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
	"golang.org/x/crypto/acme/autocert"
)

func testCertificate(t *testing.T, name string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func testProviderStore(t *testing.T) *model.TypedStore {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSCerts, model.NSACMECache} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	return ts
}

func TestProviderResolvesStoredCertificateAndReplacement(t *testing.T) {
	ts := testProviderStore(t)
	certPEM, keyPEM := testCertificate(t, "mail.example.test")
	if _, err := ts.TLSCertStore().Create(t.Context(), "MAIL.EXAMPLE.TEST", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.TLSCertStore().Create(t.Context(), "mail.example.test", certPEM, keyPEM); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	provider, err := New(ts, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := provider.TLSConfig(t.Context(), "stored:mail.example.test", "", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || first == nil || tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config: %#v", tlsConfig)
	}

	replacementCert, replacementKey := testCertificate(t, "replacement.example.test")
	replaced, err := ts.TLSCertStore().Replace(t.Context(), "mail.example.test", replacementCert, replacementKey)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Domain != "mail.example.test" || replaced.Subject != "replacement.example.test" {
		t.Fatalf("replacement: %#v", replaced)
	}
	second, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || second == nil || string(first.Certificate[0]) == string(second.Certificate[0]) {
		t.Fatal("live TLS callback did not load the replacement certificate")
	}
	if _, err := ts.TLSCertStore().Replace(t.Context(), "missing.example.test", replacementCert, replacementKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replace missing: %v", err)
	}
	if _, err := ts.TLSCertStore().Replace(t.Context(), "mail.example.test", replacementCert, keyPEM); err == nil {
		t.Fatal("mismatched private key was accepted")
	}
}

func TestProviderACMEValidationAndGenericCache(t *testing.T) {
	ts := testProviderStore(t)
	cfg := &config.Config{AcmeEnabled: true, AcmeDomains: "mail.example.test"}
	if _, err := New(ts, cfg); err == nil {
		t.Fatal("ACME started without TOS acceptance")
	}
	cfg.AcmeAcceptTOS = true
	provider, err := New(ts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.TLSConfig(t.Context(), "acme:other.example.test", "", ""); err == nil {
		t.Fatal("unapproved ACME hostname was accepted")
	}
	if _, err := provider.TLSConfig(t.Context(), "acme:mail.example.test", "", ""); err != nil {
		t.Fatalf("approved ACME assignment: %v", err)
	}

	cache := StoreCache{Store: ts.Store()}
	if _, err := cache.Get(t.Context(), "missing"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("cache miss: %v", err)
	}
	if err := cache.Put(context.Background(), "account", []byte("opaque ACME state")); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get(t.Context(), "account")
	if err != nil || string(got) != "opaque ACME state" {
		t.Fatalf("cache get=%q err=%v", got, err)
	}
	if err := cache.Delete(t.Context(), "account"); err != nil {
		t.Fatal(err)
	}
}

func TestProviderReconfiguresACMELive(t *testing.T) {
	ts := testProviderStore(t)
	provider, err := New(ts, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.StartHTTPChallenge(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	if addr := provider.ChallengeAddr(); addr != "" {
		t.Fatalf("disabled ACME bound %s", addr)
	}
	if _, err := provider.TLSConfig(t.Context(), "acme:mail.example.test", "", ""); err == nil {
		t.Fatal("ACME assignment accepted while ACME is disabled")
	}

	// No ACME server is contacted: issuance only starts on a handshake.
	enabled := &config.Config{AcmeEnabled: true, AcmeAcceptTOS: true, AcmeDomains: "mail.example.test", AcmeHTTPListen: "127.0.0.1:0", AcmeDirectoryURL: "https://acme.invalid/directory"}
	if err := provider.Reconfigure(enabled); err != nil {
		t.Fatal(err)
	}
	challengeAddr := provider.ChallengeAddr()
	if challengeAddr == "" {
		t.Fatal("enabling ACME did not start the HTTP-01 listener")
	}
	// The responder applies the host policy: an allowed host without a
	// pending token gets 404, any other host 403.
	challengeStatus := func(host string) int {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, "http://"+challengeAddr+"/.well-known/acme-challenge/unknown-token", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = host
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	if status := challengeStatus("mail.example.test"); status != http.StatusNotFound {
		t.Fatalf("allowed host challenge status %d", status)
	}
	if status := challengeStatus("other.example.test"); status != http.StatusForbidden {
		t.Fatalf("unknown host challenge status %d", status)
	}
	manager := provider.acme.Load().manager
	if manager.Client == nil || manager.Client.DirectoryURL != enabled.AcmeDirectoryURL {
		t.Fatalf("directory not applied: %#v", manager.Client)
	}
	if err := manager.HostPolicy(t.Context(), "mail.example.test"); err != nil {
		t.Fatalf("configured host refused: %v", err)
	}
	tlsConfig, err := provider.TLSConfig(t.Context(), "acme:mail.example.test", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// New domains replace the host policy, and a TLS config handed out
	// earlier follows on its next handshake.
	changed := *enabled
	changed.AcmeDomains = "other.example.test"
	if err := provider.Reconfigure(&changed); err != nil {
		t.Fatal(err)
	}
	manager = provider.acme.Load().manager
	if err := manager.HostPolicy(t.Context(), "mail.example.test"); err == nil {
		t.Fatal("removed host still allowed")
	}
	if err := manager.HostPolicy(t.Context(), "other.example.test"); err != nil {
		t.Fatalf("added host refused: %v", err)
	}
	if provider.ChallengeAddr() != challengeAddr {
		t.Fatal("an unchanged HTTP-01 address was rebound")
	}
	if status := challengeStatus("mail.example.test"); status != http.StatusForbidden {
		t.Fatalf("removed host challenge status %d", status)
	}
	if status := challengeStatus("other.example.test"); status != http.StatusNotFound {
		t.Fatalf("added host challenge status %d", status)
	}
	if _, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "mail.example.test"}); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("handshake for a removed ACME domain: %v", err)
	}

	// Invalid configuration leaves the running state unchanged.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	for name, invalid := range map[string]config.Config{
		"no TOS":      {AcmeEnabled: true, AcmeDomains: "x.example.test", AcmeHTTPListen: "127.0.0.1:0"},
		"no domains":  {AcmeEnabled: true, AcmeAcceptTOS: true, AcmeHTTPListen: "127.0.0.1:0"},
		"bad URL":     {AcmeEnabled: true, AcmeAcceptTOS: true, AcmeDomains: "x.example.test", AcmeDirectoryURL: "not a url"},
		"busy listen": {AcmeEnabled: true, AcmeAcceptTOS: true, AcmeDomains: "x.example.test", AcmeHTTPListen: occupied.Addr().String()},
	} {
		before, beforeAddr := provider.acme.Load(), provider.ChallengeAddr()
		if err := provider.Reconfigure(&invalid); err == nil {
			t.Fatalf("%s: reconfigure succeeded", name)
		}
		if provider.acme.Load() != before || provider.ChallengeAddr() != beforeAddr {
			t.Fatalf("%s: failed reconfigure changed the running state", name)
		}
	}

	if err := provider.Reconfigure(&config.Config{}); err != nil {
		t.Fatal(err)
	}
	if addr := provider.ChallengeAddr(); addr != "" {
		t.Fatalf("disabling ACME left the HTTP-01 listener on %s", addr)
	}
	if _, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.test"}); err == nil {
		t.Fatal("ACME handshake succeeded after ACME was disabled")
	}
}
