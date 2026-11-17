// Package dnsserver is Veksel' optional authoritative-only DNS server. It
// serves the zones dnsprovider.Hosted stores (the "builtin" DNS provider)
// over UDP and TCP with synthesized SOA and NS records, optional online
// DNSSEC signing with compact denial of existence, and amplification
// safeguards: no recursion, per-network response rate limiting, minimal ANY
// answers, EDNS(0) size limits with truncation, and TSIG-only zone transfers.
package dnsserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/dnsprovider"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/miekg/dns"
)

// TSIGKey authenticates zone transfers. Algorithm is a dns.Hmac* name and
// Secret the base64 key.
type TSIGKey struct {
	Name      string
	Algorithm string
	Secret    string
}

// Settings configure the server. Nameservers are the NS names published at
// every zone apex; the first is the SOA primary. A nil AXFR key disables
// zone transfers.
type Settings struct {
	Enabled     bool
	Listen      string
	Nameservers []string
	DNSSEC      bool
	AXFR        *TSIGKey
}

// DefaultRateLimit is the UDP responses per second allowed per client
// network (IPv4 /24, IPv6 /56) before responses are dropped or slipped.
const DefaultRateLimit = 20

// Server answers authoritative queries for the hosted zones.
type Server struct {
	hosted *dnsprovider.Hosted
	// RateLimit overrides DefaultRateLimit; a negative value disables rate
	// limiting. Set it before the first Apply.
	RateLimit int
	// DefaultNameserver names the NS published when Settings.Nameservers
	// is empty; without one, zones publish ns1 within themselves.
	DefaultNameserver func() string

	settings atomic.Pointer[Settings]
	mu       sync.Mutex // serializes Apply and Close
	running  *listeners
	lastErr  error

	snapMu sync.Mutex
	snap   atomic.Pointer[snapshot]
	rrl    *limiter
	once   sync.Once
}

// New returns a stopped server for hosted.
func New(hosted *dnsprovider.Hosted) *Server {
	s := &Server{hosted: hosted}
	s.settings.Store(&Settings{})
	return s
}

func (s *Server) limiter() *limiter {
	s.once.Do(func() {
		rate := s.RateLimit
		if rate == 0 {
			rate = DefaultRateLimit
		}
		s.rrl = newLimiter(rate)
	})
	return s.rrl
}

// listeners is one bound UDP and TCP address pair.
type listeners struct {
	listen string
	udp    *dns.Server
	tcp    *dns.Server
	addr   string
}

// Apply makes the server match settings. Changing only the zone settings
// (nameservers, DNSSEC, transfers) keeps the sockets; a new address is bound
// before the old one closes, and a failed bind leaves the running server
// and its settings untouched.
func (s *Server) Apply(settings Settings) error {
	settings.Nameservers = slices.Clone(settings.Nameservers)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !settings.Enabled {
		s.settings.Store(&settings)
		s.stopLocked()
		s.lastErr = nil
		return nil
	}
	if s.running != nil && s.running.listen == settings.Listen {
		s.settings.Store(&settings)
		s.lastErr = nil
		return nil
	}
	bound, err := s.bind(settings.Listen)
	if err != nil {
		if s.running == nil {
			s.lastErr = err
		}
		return err
	}
	s.settings.Store(&settings)
	old := s.running
	s.running, s.lastErr = bound, nil
	if old != nil {
		old.shutdown()
	}
	log.Info("dns: listening", "addr", bound.addr)
	return nil
}

// Close stops the server.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *Server) stopLocked() {
	if s.running != nil {
		s.running.shutdown()
		s.running = nil
	}
}

// Addr returns the bound host:port, empty while stopped.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		return ""
	}
	return s.running.addr
}

// Status describes the running server.
type Status struct {
	Enabled     bool     `json:"enabled"`
	Listen      string   `json:"listen"`
	Running     bool     `json:"running"`
	Address     string   `json:"address,omitempty"`
	Error       string   `json:"error,omitempty"`
	Nameservers []string `json:"nameservers"`
	DNSSEC      bool     `json:"dnssec"`
	AXFR        bool     `json:"axfr"`
}

// Status reports the effective settings and listener state.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := s.settings.Load()
	status := Status{Enabled: settings.Enabled, Listen: settings.Listen, Running: s.running != nil, Nameservers: nameservers(settings.Nameservers, s.defaultNameserver()),
		DNSSEC: settings.DNSSEC, AXFR: settings.AXFR != nil}
	if status.Nameservers == nil {
		status.Nameservers = []string{}
	}
	if s.running != nil {
		status.Address = s.running.addr
	}
	if s.lastErr != nil {
		status.Error = s.lastErr.Error()
	}
	return status
}

// Observation reports the server's health for the runtime health registry.
func (s *Server) Observation() health.Observation {
	status := s.Status()
	observation := health.Observation{ID: "dns-server", Label: "Built-in DNS server", Kind: "listener", Desired: status.Enabled, State: health.StateDisabled}
	if !status.Enabled {
		return observation
	}
	observation.Details = map[string]string{"listen": status.Listen, "zones": strconv.Itoa(len(s.hosted.Zones()))}
	if status.Running {
		observation.State = health.StateHealthy
		return observation
	}
	observation.State, observation.Severity, observation.Reason = health.StateUnavailable, health.SeverityWarning, status.Error
	if observation.Reason == "" {
		observation.Reason = "the DNS listener is not running"
	}
	return observation
}

// bind opens UDP and TCP sockets on the same address. A zero port takes a
// free UDP port and binds TCP to it, retrying on collisions.
func (s *Server) bind(listen string) (*listeners, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("DNS listener %q: %w", listen, err)
	}
	var lastErr error
	for range 5 {
		pc, err := net.ListenPacket("udp", listen)
		if err != nil {
			return nil, fmt.Errorf("DNS listener udp %s: %w", listen, err)
		}
		bound := net.JoinHostPort(host, strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port))
		ln, err := net.Listen("tcp", bound)
		if err != nil {
			_ = pc.Close()
			lastErr = fmt.Errorf("DNS listener tcp %s: %w", bound, err)
			if port == "0" {
				continue
			}
			return nil, lastErr
		}
		l := &listeners{listen: listen, addr: bound,
			udp: &dns.Server{PacketConn: pc, Handler: s, TsigProvider: tsigProvider{s}, UDPSize: dns.DefaultMsgSize},
			tcp: &dns.Server{Listener: ln, Handler: s, TsigProvider: tsigProvider{s}, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}}
		l.start()
		return l, nil
	}
	return nil, lastErr
}

func (l *listeners) start() {
	var started sync.WaitGroup
	for _, server := range []*dns.Server{l.udp, l.tcp} {
		started.Add(1)
		server.NotifyStartedFunc = started.Done
		go func() {
			if err := server.ActivateAndServe(); err != nil {
				log.Warn("dns: server stopped", "error", err)
			}
		}()
	}
	started.Wait()
}

func (l *listeners) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range []*dns.Server{l.udp, l.tcp} {
		if err := server.ShutdownContext(ctx); err != nil {
			log.Warn("dns: shutdown incomplete", "error", err)
		}
	}
}

// tsigProvider verifies and signs transfer messages with the live AXFR key.
type tsigProvider struct{ s *Server }

func (p tsigProvider) mac(msg []byte, t *dns.TSIG) ([]byte, error) {
	key := p.s.settings.Load().AXFR
	if key == nil || !strings.EqualFold(dns.Fqdn(key.Name), t.Hdr.Name) {
		return nil, dns.ErrSecret
	}
	if dns.CanonicalName(t.Algorithm) != dns.CanonicalName(key.Algorithm) {
		return nil, dns.ErrKeyAlg
	}
	secret, err := base64.StdEncoding.DecodeString(key.Secret)
	if err != nil {
		return nil, dns.ErrSecret
	}
	hashes := map[string]func() hash.Hash{dns.HmacSHA1: sha1.New, dns.HmacSHA224: sha256.New224, dns.HmacSHA256: sha256.New,
		dns.HmacSHA384: sha512.New384, dns.HmacSHA512: sha512.New}
	newHash, ok := hashes[dns.CanonicalName(key.Algorithm)]
	if !ok {
		return nil, dns.ErrKeyAlg
	}
	h := hmac.New(newHash, secret)
	h.Write(msg)
	return h.Sum(nil), nil
}

func (p tsigProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) { return p.mac(msg, t) }

func (p tsigProvider) Verify(msg []byte, t *dns.TSIG) error {
	want, err := p.mac(msg, t)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(t.MAC)
	if err != nil || !hmac.Equal(want, got) {
		return dns.ErrSig
	}
	return nil
}
