package model

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// TLSCertStore provides CRUD operations for TLS certificates.
type TLSCertStore struct {
	certs    collection[TLSCert]
	metadata collection[TLSCertMetadata]
}

// TLSCertMetadata is the secret-free certificate projection used by health
// evaluation and administration inventory.
type TLSCertMetadata struct {
	Domain    string    `json:"domain"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Uploaded  time.Time `json:"uploaded"`
	Subject   string    `json:"subject"`
	Signer    string    `json:"signer"`
	SANs      []string  `json:"sans"`
}

// NewTLSCertStore creates a new TLSCertStore.
func NewTLSCertStore(ts *TypedStore) *TLSCertStore {
	return &TLSCertStore{
		certs:    newCollection[TLSCert](ts, NSCerts),
		metadata: newCollection[TLSCertMetadata](ts, NSCerts),
	}
}

// Create stores a new TLS certificate for a domain.
func (s *TLSCertStore) Create(ctx context.Context, domain string, certPEM, keyPEM string) (*TLSCert, error) {
	tlsCert, err := parseTLSCert(domain, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := s.certs.put(ctx, tlsCert.Domain, *tlsCert); err != nil {
		return nil, err
	}
	return tlsCert, nil
}

// Replace validates and replaces an existing certificate without changing its
// stable domain identifier. It returns store.ErrNotFound when none is assigned.
func (s *TLSCertStore) Replace(ctx context.Context, domain, certPEM, keyPEM string) (*TLSCert, error) {
	domain = normalizeID(domain)
	if _, err := s.Get(ctx, domain); err != nil {
		return nil, err
	}
	tlsCert, err := parseTLSCert(domain, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := s.certs.set(ctx, domain, *tlsCert); err != nil {
		return nil, err
	}
	return tlsCert, nil
}

func parseTLSCert(domain, certPEM, keyPEM string) (*TLSCert, error) {
	domain = normalizeID(domain)
	if domain == "" || strings.ContainsAny(domain, "@:/\\ ") {
		return nil, errors.New("valid certificate name required")
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return nil, errors.New("invalid or mismatched certificate and private key: " + err.Error())
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid certificate: " + err.Error())
	}

	tlsCert := &TLSCert{
		Domain:    domain,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Uploaded:  time.Now().UTC(),
		Subject:   cert.Subject.CommonName,
		Signer:    cert.Issuer.CommonName,
		SANs:      cert.DNSNames,
	}
	if len(tlsCert.SANs) == 0 {
		tlsCert.SANs = []string{}
	}

	return tlsCert, nil
}

// Get retrieves a TLS certificate by domain.
func (s *TLSCertStore) Get(ctx context.Context, domain string) (*TLSCert, error) {
	cert, err := s.certs.get(ctx, normalizeID(domain))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// Delete removes a TLS certificate for a domain.
func (s *TLSCertStore) Delete(ctx context.Context, domain string) error {
	return s.certs.delete(ctx, normalizeID(domain))
}

// List returns all stored TLS certificates.
func (s *TLSCertStore) List(ctx context.Context) ([]TLSCert, error) {
	return s.certs.list(ctx)
}

// ListMetadata reads only public certificate fields. The JSON decoder skips
// PEM and private-key values instead of retaining them in memory.
func (s *TLSCertStore) ListMetadata(ctx context.Context) ([]TLSCertMetadata, error) {
	return s.metadata.list(ctx)
}
