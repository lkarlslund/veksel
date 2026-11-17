// Package certificates resolves administrator-managed TLS certificates for
// protocol listeners and provides a generic-store-backed ACME cache.
package certificates

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/httpservice"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	StoredPrefix = "stored:"
	ACMEPrefix   = "acme:"
)

const challengeListenerID = "acme-http-01"

// Provider owns certificate resolution and optional Let's Encrypt issuance.
// Reconfigure swaps the ACME settings and the HTTP-01 responder at runtime.
type Provider struct {
	ts         *model.TypedStore
	acme       atomic.Pointer[acmeState]
	challenge  *httpservice.ListenerSet
	dnsSolver  atomic.Pointer[DNSChallenger]
	renewStop  chan struct{}
	renewEvery time.Duration

	mu      sync.Mutex // serializes Reconfigure, StartHTTPChallenge and Close
	started bool
}

// acmeState is one validated ACME configuration; a disabled one has no
// manager. HTTP-01 issuance goes through the autocert manager and DNS-01
// issuance through the DNS issuer; challenges picks one per certificate.
type acmeState struct {
	manager    *autocert.Manager
	dns        *dnsIssuer
	challenges config.ACMEChallenges
	domains    map[string]struct{}
	listen     string
}

// New configures a provider. ACME refuses to start unless the administrator
// explicitly accepts the subscriber agreement and supplies hostnames.
func New(ts *model.TypedStore, cfg *config.Config) (*Provider, error) {
	p := &Provider{ts: ts, renewEvery: 12 * time.Hour}
	state, err := p.newACMEState(cfg)
	if err != nil {
		return nil, err
	}
	p.acme.Store(state)
	p.challenge = httpservice.NewListenerSet(func(config.HTTPListener) http.Handler {
		return http.HandlerFunc(p.serveChallenge)
	}, nil, httpservice.Timeouts{ReadHeader: 10 * time.Second, Idle: time.Minute, Request: time.Minute, MaxHeaderBytes: 16 << 10})
	return p, nil
}

func (p *Provider) newACMEState(cfg *config.Config) (*acmeState, error) {
	if cfg == nil || !cfg.AcmeEnabled {
		return &acmeState{}, nil
	}
	if !cfg.AcmeAcceptTOS {
		return nil, errors.New("ACME is enabled but the subscriber agreement has not been accepted")
	}
	domains := splitDomains(cfg.AcmeDomains)
	if len(domains) == 0 {
		return nil, errors.New("ACME is enabled but no domains are configured")
	}
	challenges, err := config.ParseACMEChallenge(cfg.AcmeChallenge)
	if err != nil {
		return nil, err
	}
	state := &acmeState{domains: make(map[string]struct{}, len(domains)), listen: strings.TrimSpace(cfg.AcmeHTTPListen), challenges: challenges}
	var httpNames []string
	for _, domain := range domains {
		state.domains[domain] = struct{}{}
		if !strings.HasPrefix(domain, "*.") {
			httpNames = append(httpNames, domain)
		}
	}
	cache := StoreCache{Store: p.ts.Store()}
	state.manager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.AcmeEmail,
		Cache:      cache,
		HostPolicy: autocert.HostWhitelist(httpNames...),
	}
	directory := strings.TrimSpace(cfg.AcmeDirectoryURL)
	if directory != "" && directory != acme.LetsEncryptURL {
		parsed, err := url.Parse(directory)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			return nil, fmt.Errorf("ACME directory URL %q must be an absolute http(s) URL", directory)
		}
		state.manager.Client = &acme.Client{DirectoryURL: directory}
	}
	if directory == "" {
		directory = acme.LetsEncryptURL
	}
	propagation := time.Duration(cfg.AcmeDNSPropagationSeconds) * time.Second
	if propagation <= 0 {
		propagation = 2 * time.Minute
	}
	state.dns = newDNSIssuer(cache, directory, cfg.AcmeEmail, propagation, p.dnsChallenger)
	return state, nil
}

// SetDNSChallenger connects the DNS provider used for DNS-01 and starts
// issuing the DNS-01 certificates it now makes possible.
func (p *Provider) SetDNSChallenger(challenger DNSChallenger) {
	p.dnsSolver.Store(&challenger)
	go p.ensureDNSCertificates()
}

func (p *Provider) dnsChallenger() DNSChallenger {
	if challenger := p.dnsSolver.Load(); challenger != nil {
		return *challenger
	}
	return nil
}

// usesDNS01 reports whether the certificate for domain is issued with
// DNS-01: when configured so, for wildcards, or in auto mode when a DNS
// provider covers the name.
func (s *acmeState) usesDNS01(domain string, challenger DNSChallenger) bool {
	switch s.challenges.For(domain) {
	case config.ACMEChallengeDNS:
		return true
	case config.ACMEChallengeAuto:
		return challenger != nil && challenger.Available(domain)
	}
	return false
}

// ensureDNSCertificates starts issuance or renewal of every DNS-01
// certificate that is missing or due.
func (p *Provider) ensureDNSCertificates() {
	state, challenger := p.acme.Load(), p.dnsChallenger()
	if state.dns == nil || challenger == nil {
		return
	}
	for domain := range state.domains {
		if state.usesDNS01(domain, challenger) {
			_, _ = state.dns.certificate(domain)
		}
	}
}

// Reconfigure validates cfg and swaps the ACME settings in place: new
// handshakes follow the new domains, account email and directory, and a
// started HTTP-01 responder starts, stops, or rebinds to follow
// acme_http_listen. On error the previous configuration stays in effect.
func (p *Provider) Reconfigure(cfg *config.Config) error {
	state, err := p.newACMEState(cfg)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		if err := p.challenge.Apply(challengeListeners(state)); err != nil {
			return fmt.Errorf("ACME HTTP-01 listener: %w", err)
		}
	}
	p.acme.Store(state)
	go p.ensureDNSCertificates()
	return nil
}

// TLSConfig resolves a stored/ACME assignment, falling back to legacy PEM
// file paths when assignment is empty. Stored and ACME certificates are
// resolved per handshake, so a replaced certificate or an ACME
// reconfiguration needs no listener restart.
func (p *Provider) TLSConfig(ctx context.Context, assignment, certFile, keyFile string) (*tls.Config, error) {
	assignment = strings.TrimSpace(assignment)
	switch {
	case strings.HasPrefix(assignment, StoredPrefix):
		name := strings.TrimSpace(strings.TrimPrefix(assignment, StoredPrefix))
		load := func() (*tls.Certificate, error) {
			stored, err := p.ts.TLSCertStore().Get(context.Background(), name)
			if err != nil {
				return nil, fmt.Errorf("load stored certificate %q: %w", name, err)
			}
			pair, err := tls.X509KeyPair([]byte(stored.CertPEM), []byte(stored.KeyPEM))
			if err != nil {
				return nil, fmt.Errorf("parse stored certificate %q: %w", name, err)
			}
			return &pair, nil
		}
		if _, err := load(); err != nil {
			return nil, err
		}
		return &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return load() }, MinVersion: tls.VersionTLS12}, nil
	case strings.HasPrefix(assignment, ACMEPrefix):
		domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(assignment, ACMEPrefix)))
		if _, err := p.acmeState(domain); err != nil {
			return nil, err
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				state, err := p.acmeState(domain)
				if err != nil {
					return nil, err
				}
				if state.usesDNS01(domain, p.dnsChallenger()) {
					return state.dns.certificate(domain)
				}
				copyHello := *hello
				if copyHello.ServerName == "" {
					copyHello.ServerName = domain
				}
				return state.manager.GetCertificate(&copyHello)
			},
		}, nil
	case assignment != "":
		return nil, fmt.Errorf("unknown certificate assignment %q", assignment)
	case certFile != "" && keyFile != "":
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
	default:
		return nil, nil
	}
}

// acmeState returns the current ACME configuration when it may issue for
// domain.
func (p *Provider) acmeState(domain string) (*acmeState, error) {
	state := p.acme.Load()
	if state.manager == nil {
		return nil, errors.New("ACME certificate selected but ACME is not enabled")
	}
	if _, ok := state.domains[domain]; !ok {
		return nil, fmt.Errorf("ACME domain %q is not allowed", domain)
	}
	return state, nil
}

// StartHTTPChallenge starts the ACME HTTP-01 responder when ACME and
// acme_http_listen are configured, and the periodic DNS-01 renewal check;
// later Reconfigure calls keep them in step until Close.
func (p *Provider) StartHTTPChallenge() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		p.renewStop = make(chan struct{})
		go func(stop <-chan struct{}) {
			ticker := time.NewTicker(p.renewEvery)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					p.ensureDNSCertificates()
				}
			}
		}(p.renewStop)
	}
	p.started = true
	p.challenge.Serve()
	if err := p.challenge.Apply(challengeListeners(p.acme.Load())); err != nil {
		return fmt.Errorf("ACME HTTP-01 listener: %w", err)
	}
	return nil
}

// ChallengeAddr returns the bound HTTP-01 responder address, or "" when it
// is not running.
func (p *Provider) ChallengeAddr() string {
	return p.challenge.Addrs()[challengeListenerID]
}

// Close stops the HTTP-01 responder.
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		close(p.renewStop)
	}
	p.started = false
	p.challenge.Close()
}

func challengeListeners(state *acmeState) []config.HTTPListener {
	if state.manager == nil || state.listen == "" {
		return nil
	}
	return []config.HTTPListener{{ID: challengeListenerID, Enabled: true, Transport: config.HTTPTransport, Address: state.listen}}
}

// serveChallenge answers HTTP-01 challenges with the current ACME manager.
func (p *Provider) serveChallenge(w http.ResponseWriter, r *http.Request) {
	state := p.acme.Load()
	if state.manager == nil {
		http.NotFound(w, r)
		return
	}
	state.manager.HTTPHandler(nil).ServeHTTP(w, r)
}

func splitDomains(value string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, part := range strings.Split(value, ",") {
		domain := strings.ToLower(strings.TrimSpace(part))
		if domain == "" {
			continue
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

// StoreCache implements autocert.Cache using the configured generic backend.
type StoreCache struct{ Store store.Store }

func (c StoreCache) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := c.Store.Get(ctx, model.NSACMECache, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	return value, err
}
func (c StoreCache) Put(ctx context.Context, key string, data []byte) error {
	return c.Store.Set(ctx, model.NSACMECache, key, data)
}
func (c StoreCache) Delete(ctx context.Context, key string) error {
	err := c.Store.Delete(ctx, model.NSACMECache, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}
