package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"golang.org/x/crypto/acme"
)

// fakeChallenger stands in for the DNS provider.
type fakeChallenger struct {
	mu        sync.Mutex
	records   map[string][]string
	presented []string
}

func (f *fakeChallenger) Available(name string) bool {
	return name == "example.test" || strings.HasSuffix(name, ".example.test")
}

func (f *fakeChallenger) PresentTXT(_ context.Context, name, value string, wait time.Duration) (func(context.Context) error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if wait != 30*time.Second {
		return nil, fmt.Errorf("propagation timeout %s does not follow configuration", wait)
	}
	f.records[name] = append(f.records[name], value)
	f.presented = append(f.presented, name)
	return func(context.Context) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.records[name] = slices.DeleteFunc(f.records[name], func(v string) bool { return v == value })
		return nil
	}, nil
}

func (f *fakeChallenger) has(name, value string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.records[name], value)
}

// fakeACME is a minimal RFC 8555 server: it trusts JWS signatures, but
// validates dns-01 challenges against the fake DNS provider using the
// account key thumbprint, and issues certificates from a test CA.
type fakeACME struct {
	*httptest.Server
	t          *testing.T
	dns        *fakeChallenger
	mu         sync.Mutex
	thumbprint string
	authzValid bool
	identifier string
	wildcard   bool
	orders     int
	chain      []byte
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
}

func newFakeACME(t *testing.T, dns *fakeChallenger) *fakeACME {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	f := &fakeACME{t: t, dns: dns, caKey: caKey, caCert: caCert}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeACME) payload(r *http.Request) (map[string]any, []byte) {
	var jws struct{ Protected, Payload string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		f.t.Errorf("JWS: %v", err)
	}
	protected, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	var header map[string]any
	_ = json.Unmarshal(protected, &header)
	return header, payload
}

func (f *fakeACME) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	base := f.URL
	write := func(status int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	order := func() map[string]any {
		status := "pending"
		if f.authzValid {
			status = "ready"
		}
		value := map[string]any{"status": status, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1",
			"identifiers": []map[string]string{{"type": "dns", "value": f.identifier}}}
		if f.chain != nil {
			value["status"], value["certificate"] = "valid", base+"/cert/1"
		}
		w.Header().Set("Location", base+"/order/1")
		return value
	}
	switch r.URL.Path {
	case "/directory":
		write(200, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order", "revokeCert": base + "/revoke", "keyChange": base + "/key"})
	case "/nonce":
		w.WriteHeader(http.StatusOK)
	case "/account":
		header, _ := f.payload(r)
		raw, _ := json.Marshal(header["jwk"])
		var jwk struct{ X, Y string }
		_ = json.Unmarshal(raw, &jwk)
		x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
		y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
		point := make([]byte, 65)
		point[0] = 4
		copy(point[33-len(x):33], x)
		copy(point[65-len(y):], y)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			f.t.Fatalf("account key: %v", err)
		}
		thumb, err := acme.JWKThumbprint(key)
		if err != nil {
			f.t.Errorf("thumbprint: %v", err)
		}
		f.thumbprint = thumb
		w.Header().Set("Location", base+"/account/1")
		write(201, map[string]any{"status": "valid"})
	case "/order":
		_, payload := f.payload(r)
		var request struct {
			Identifiers []struct{ Value string }
		}
		_ = json.Unmarshal(payload, &request)
		f.orders++
		f.identifier = strings.TrimPrefix(request.Identifiers[0].Value, "*.")
		f.wildcard = strings.HasPrefix(request.Identifiers[0].Value, "*.")
		f.authzValid, f.chain = false, nil
		write(201, order())
	case "/order/1":
		write(200, order())
	case "/authz/1":
		status := "pending"
		if f.authzValid {
			status = "valid"
		}
		write(200, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": f.identifier}, "wildcard": f.wildcard,
			"challenges": []map[string]string{{"type": "http-01", "url": base + "/chall/http", "token": "unused", "status": "pending"}, {"type": "dns-01", "url": base + "/chall/1", "token": "tok-1", "status": "pending"}}})
	case "/chall/1":
		digest := sha256.Sum256([]byte("tok-1." + f.thumbprint))
		expected := base64.RawURLEncoding.EncodeToString(digest[:])
		f.authzValid = f.dns.has("_acme-challenge."+f.identifier, expected)
		status := "invalid"
		if f.authzValid {
			status = "valid"
		}
		write(200, map[string]string{"type": "dns-01", "url": base + "/chall/1", "token": "tok-1", "status": status})
	case "/finalize/1":
		_, payload := f.payload(r)
		var request struct{ CSR string }
		_ = json.Unmarshal(payload, &request)
		der, _ := base64.RawURLEncoding.DecodeString(request.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || !f.authzValid {
			write(403, map[string]string{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "not authorized"})
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, csr.PublicKey, f.caKey)
		if err != nil {
			f.t.Errorf("issue: %v", err)
		}
		f.chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})...)
		write(200, order())
	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(f.chain)
	default:
		write(404, map[string]string{"type": "urn:ietf:params:acme:error:malformed"})
	}
}

func TestDNS01IssuesWildcardThroughDNSProviderAndCachesIt(t *testing.T) {
	ts := testProviderStore(t)
	challenger := &fakeChallenger{records: map[string][]string{}}
	ca := newFakeACME(t, challenger)
	cfg := &config.Config{AcmeEnabled: true, AcmeAcceptTOS: true, AcmeEmail: "admin@example.test", AcmeDomains: "*.example.test, mail.example.test",
		AcmeDirectoryURL: ca.URL + "/directory", AcmeChallenge: "auto, mail.example.test=http-01", AcmeDNSPropagationSeconds: 30}
	provider, err := New(ts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	state := provider.acme.Load()
	if state.usesDNS01("*.example.test", nil) != true || state.usesDNS01("mail.example.test", challenger) {
		t.Fatal("wildcards must use DNS-01 and the http-01 override must win")
	}
	tlsConfig, err := provider.TLSConfig(t.Context(), "acme:*.example.test", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "imap.example.test"}); err == nil {
		t.Fatal("certificate served before any DNS provider was connected")
	}
	provider.SetDNSChallenger(challenger)
	var cert *tls.Certificate
	deadline := time.Now().Add(10 * time.Second)
	for cert == nil && time.Now().Before(deadline) {
		cert, _ = tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "imap.example.test"})
		time.Sleep(10 * time.Millisecond)
	}
	if cert == nil {
		t.Fatal("DNS-01 issuance did not complete")
	}
	if !slices.Equal(cert.Leaf.DNSNames, []string{"*.example.test"}) || cert.Leaf.VerifyHostname("imap.example.test") != nil {
		t.Fatalf("issued names: %v", cert.Leaf.DNSNames)
	}
	if challenger.presented[0] != "_acme-challenge.example.test" || len(challenger.records["_acme-challenge.example.test"]) != 0 {
		t.Fatalf("challenge record not published at the base name or not cleaned up: %v %v", challenger.presented, challenger.records)
	}

	// After a restart the cached certificate is served without a new order.
	orders := ca.orders
	restarted, err := New(ts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetDNSChallenger(challenger)
	tlsConfig, _ = restarted.TLSConfig(t.Context(), "acme:*.example.test", "", "")
	if again, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{}); err != nil || !again.Leaf.Equal(cert.Leaf) {
		t.Fatalf("cached certificate: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if ca.orders != orders {
		t.Fatal("a valid cached certificate triggered a new order")
	}
}

func TestACMEChallengeConfigurationValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		challenge, domains string
		ok                 bool
	}{
		"default auto":           {"", "*.example.test", true},
		"override":               {"http-01, *.example.test=dns-01", "*.example.test, mail.example.test", true},
		"wildcard over http":     {"http-01", "*.example.test", false},
		"bad mode":               {"tls-alpn-01", "mail.example.test", false},
		"two defaults":           {"auto, dns-01", "mail.example.test", false},
		"inner wildcard":         {"auto", "mail.*.example.test", false},
		"wildcard http override": {"auto, *.example.test=http-01", "*.example.test", false},
	} {
		cfg := config.Default()
		cfg.AcmeChallenge, cfg.AcmeDomains = tc.challenge, tc.domains
		if err := config.Validate(cfg); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}
