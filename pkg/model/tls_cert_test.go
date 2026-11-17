package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTLSCertificateMetadataListDoesNotExposePEMOrKey(t *testing.T) {
	ts := testStore(t)
	if err := ts.EnsureNamespace(t.Context(), NSCerts); err != nil {
		t.Fatal(err)
	}
	wantExpiry := time.Now().UTC().Add(30 * 24 * time.Hour).Round(time.Second)
	stored := TLSCert{Domain: "mail", CertPEM: "SECRET CERTIFICATE", KeyPEM: "SECRET PRIVATE KEY", NotAfter: wantExpiry, Subject: "mail.example.test", SANs: []string{"mail.example.test"}}
	if err := ts.Set(t.Context(), NSCerts, stored.Domain, stored); err != nil {
		t.Fatal(err)
	}
	metadata, err := ts.TLSCertStore().ListMetadata(t.Context())
	if err != nil || len(metadata) != 1 || metadata[0].Domain != "mail" || !metadata[0].NotAfter.Equal(wantExpiry) {
		t.Fatalf("metadata=%#v err=%v", metadata, err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "pem") || strings.Contains(string(encoded), "key") {
		t.Fatalf("metadata exposed certificate secret fields: %s", encoded)
	}
}
