package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// DNSChallenger publishes ACME DNS-01 challenge records through a DNS
// provider; dnsprovider.Zones implements it.
type DNSChallenger interface {
	Available(name string) bool
	PresentTXT(ctx context.Context, name, value string, wait time.Duration) (func(context.Context) error, error)
}

const (
	// accountKeyCache is autocert's account key entry, shared so HTTP-01
	// and DNS-01 issuance use one ACME account.
	accountKeyCache  = "acme_account+key"
	dns01CachePrefix = "dns-01+"
	renewBefore      = 30 * 24 * time.Hour
	issueTimeout     = 15 * time.Minute
	retryAfter       = 10 * time.Minute
)

var errNoDNSProvider = errors.New("no DNS provider covers the name")

// dnsIssuer obtains and renews certificates with DNS-01, which works for
// wildcard names and without a public port 80. Issuance runs in the
// background; handshakes are served from the cached certificate.
type dnsIssuer struct {
	cache       StoreCache
	directory   string
	email       string
	propagation time.Duration
	challenger  func() DNSChallenger

	mu       sync.Mutex
	certs    map[string]*tls.Certificate
	issuing  map[string]bool
	failedAt map[string]time.Time
}

func newDNSIssuer(cache StoreCache, directory, email string, propagation time.Duration, challenger func() DNSChallenger) *dnsIssuer {
	return &dnsIssuer{cache: cache, directory: directory, email: email, propagation: propagation, challenger: challenger,
		certs: map[string]*tls.Certificate{}, issuing: map[string]bool{}, failedAt: map[string]time.Time{}}
}

// certificate returns the current certificate for domain and starts a
// background issuance when none is cached or renewal is due.
func (d *dnsIssuer) certificate(domain string) (*tls.Certificate, error) {
	d.mu.Lock()
	cert := d.certs[domain]
	d.mu.Unlock()
	if cert == nil {
		if loaded, err := d.load(domain); err == nil {
			cert = loaded
			d.mu.Lock()
			d.certs[domain] = cert
			d.mu.Unlock()
		}
	}
	if cert == nil || time.Until(cert.Leaf.NotAfter) < renewBefore {
		d.start(domain)
	}
	if cert == nil || time.Now().After(cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("ACME DNS-01 certificate for %s is being issued", domain)
	}
	return cert, nil
}

func (d *dnsIssuer) start(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.issuing[domain] || time.Since(d.failedAt[domain]) < retryAfter {
		return
	}
	d.issuing[domain] = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
		defer cancel()
		cert, err := d.issue(ctx, domain)
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.issuing, domain)
		if errors.Is(err, errNoDNSProvider) {
			// Nothing was sent to the CA; retry as soon as a provider exists.
			return
		}
		if err != nil {
			d.failedAt[domain] = time.Now()
			log.Error("ACME DNS-01 issuance failed", "domain", domain, "error", err)
			return
		}
		delete(d.failedAt, domain)
		d.certs[domain] = cert
		log.Info("ACME DNS-01 certificate issued", "domain", domain, "not_after", cert.Leaf.NotAfter)
	}()
}

func (d *dnsIssuer) load(domain string) (*tls.Certificate, error) {
	data, err := d.cache.Get(context.Background(), dns01CachePrefix+domain)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

// issue runs one RFC 8555 order: authorize each identifier with a DNS-01
// TXT record (published, propagated, and removed through the challenger),
// finalize with a fresh key, and cache the key and chain.
func (d *dnsIssuer) issue(ctx context.Context, domain string) (*tls.Certificate, error) {
	challenger := d.challenger()
	if challenger == nil || !challenger.Available(domain) {
		return nil, fmt.Errorf("%w: %s", errNoDNSProvider, domain)
	}
	accountKey, err := d.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: d.directory}
	account := &acme.Account{}
	if d.email != "" {
		account.Contact = []string{"mailto:" + d.email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := d.authorize(ctx, client, challenger, authzURL); err != nil {
			return nil, err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("wait for ACME order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize ACME order: %w", err)
	}
	var encoded bytes.Buffer
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	_ = pem.Encode(&encoded, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for _, der := range chain {
		_ = pem.Encode(&encoded, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	pair, err := tls.X509KeyPair(encoded.Bytes(), encoded.Bytes())
	if err != nil {
		return nil, fmt.Errorf("issued certificate: %w", err)
	}
	if err := pair.Leaf.VerifyHostname(strings.Replace(domain, "*", "wildcard-check", 1)); err != nil {
		return nil, fmt.Errorf("issued certificate does not cover %s: %w", domain, err)
	}
	if err := d.cache.Put(ctx, dns01CachePrefix+domain, encoded.Bytes()); err != nil {
		return nil, err
	}
	return &pair, nil
}

func (d *dnsIssuer) authorize(ctx context.Context, client *acme.Client, challenger DNSChallenger, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("read ACME authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	var challenge *acme.Challenge
	for _, candidate := range authz.Challenges {
		if candidate.Type == "dns-01" {
			challenge = candidate
		}
	}
	if challenge == nil {
		return fmt.Errorf("ACME server offered no dns-01 challenge for %s", authz.Identifier.Value)
	}
	value, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return err
	}
	cleanup, err := challenger.PresentTXT(ctx, "_acme-challenge."+authz.Identifier.Value, value, d.propagation)
	if err != nil {
		return fmt.Errorf("publish DNS-01 record: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := cleanup(cleanupCtx); err != nil {
			log.Warn("remove ACME DNS-01 record", "name", authz.Identifier.Value, "error", err)
		}
	}()
	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept DNS-01 challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("DNS-01 authorization for %s: %w", authz.Identifier.Value, err)
	}
	return nil
}

// accountKey loads autocert's ACME account key, creating it in the same
// format when absent.
func (d *dnsIssuer) accountKey(ctx context.Context) (crypto.Signer, error) {
	data, err := d.cache.Get(ctx, accountKeyCache)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid cached ACME account key")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !errors.Is(err, autocert.ErrCacheMiss) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := d.cache.Put(ctx, accountKeyCache, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}
