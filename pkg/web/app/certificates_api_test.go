package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func appTestCertificate(t *testing.T, commonName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func TestCertificateAPICreateReplaceAssignAndDelete(t *testing.T) {
	server, _, _, _, _ := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")
	certPEM, keyPEM := appTestCertificate(t, "mail.example.test")
	request := map[string]string{"name": "MAIL.EXAMPLE.TEST", "cert_pem": certPEM, "key_pem": keyPEM}
	var created certificateView
	lifecycleRequest(t, client, http.MethodPost, server.URL+"/api/v1/admin/certificates", csrf, request, http.StatusCreated, &created)
	if created.Name != "mail.example.test" || created.Subject != "mail.example.test" || created.Expired {
		t.Fatalf("created certificate: %#v", created)
	}
	lifecycleRequest(t, client, http.MethodPost, server.URL+"/api/v1/admin/certificates", csrf, request, http.StatusConflict, nil)

	var listed []map[string]any
	lifecycleRequest(t, client, http.MethodGet, server.URL+"/api/v1/admin/certificates", "", nil, http.StatusOK, &listed)
	if len(listed) != 1 {
		t.Fatalf("certificate list: %#v", listed)
	}
	if _, exposed := listed[0]["key_pem"]; exposed {
		t.Fatal("certificate list exposed the private key")
	}
	if _, exposed := listed[0]["cert_pem"]; exposed {
		t.Fatal("certificate list exposed certificate payload")
	}

	replacementPEM, replacementKey := appTestCertificate(t, "new.example.test")
	lifecycleRequest(t, client, http.MethodPut, server.URL+"/api/v1/admin/certificates/mail.example.test", csrf,
		map[string]string{"cert_pem": replacementPEM, "key_pem": keyPEM}, http.StatusBadRequest, nil)
	var replaced certificateView
	lifecycleRequest(t, client, http.MethodPut, server.URL+"/api/v1/admin/certificates/mail.example.test", csrf,
		map[string]string{"cert_pem": replacementPEM, "key_pem": replacementKey}, http.StatusOK, &replaced)
	if replaced.Name != "mail.example.test" || replaced.Subject != "new.example.test" {
		t.Fatalf("replaced certificate: %#v", replaced)
	}

	lifecycleRequest(t, client, http.MethodPatch, server.URL+"/api/v1/admin/settings", csrf,
		map[string]any{"settings": map[string]string{"smtp_certificate": "stored:mail.example.test"}}, http.StatusOK, nil)
	lifecycleRequest(t, client, http.MethodDelete, server.URL+"/api/v1/admin/certificates/mail.example.test", csrf, nil, http.StatusConflict, nil)
	lifecycleRequest(t, client, http.MethodPatch, server.URL+"/api/v1/admin/settings", csrf,
		map[string]any{"settings": map[string]string{"smtp_certificate": ""}}, http.StatusOK, nil)
	lifecycleRequest(t, client, http.MethodDelete, server.URL+"/api/v1/admin/certificates/mail.example.test", csrf, nil, http.StatusNoContent, nil)
	lifecycleRequest(t, client, http.MethodGet, server.URL+"/api/v1/admin/certificates", "", nil, http.StatusOK, &listed)
	if len(listed) != 0 {
		t.Fatalf("deleted certificate remains listed: %#v", listed)
	}
	lifecycleRequest(t, client, http.MethodPatch, server.URL+"/api/v1/admin/settings", csrf,
		map[string]any{"settings": map[string]any{"acme_enabled": true, "acme_accept_tos": true, "acme_domains": "mail.example.test", "smtp_certificate": "acme:mail.example.test"}}, http.StatusOK, nil)
	lifecycleRequest(t, client, http.MethodPatch, server.URL+"/api/v1/admin/settings", csrf,
		map[string]any{"settings": map[string]string{"smtp_certificate": "acme:not-managed.example.test"}}, http.StatusBadRequest, nil)
}
