package dane

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Resolver sources reported in Status.
const (
	SourceConfigured = "configured"
	SourceSystem     = "system"
)

// Validation probe verdicts reported in Status.
const (
	ValidatingUnknown = "unknown"
	ValidatingYes     = "yes"
	ValidatingNo      = "no"
	ValidatingError   = "error"
)

// Default probe names: a long-standing signed zone and a deliberately
// broken one. A validating resolver authenticates the first and refuses
// the second with SERVFAIL.
const (
	DefaultProbeSigned = "isc.org"
	DefaultProbeBogus  = "dnssec-failed.org"
)

// Config selects DANE enablement and the resolvers whose AD bit is trusted.
type Config struct {
	Enabled bool
	// Resolvers are operator-trusted validating resolvers (host:port). When
	// empty, the system resolvers are used, but only loopback ones are
	// trusted: the AD bit is meaningless across an untrusted network path.
	Resolvers []string
}

// Options controls resolver discovery and probing. Zero values select
// production defaults.
type Options struct {
	ResolvConf   string                           // default /etc/resolv.conf
	NewExchanger func(servers []string) Exchanger // default *Client
	ProbeSigned  string
	ProbeBogus   string
}

// Status is the operator-visible DANE state.
type Status struct {
	Enabled bool `json:"enabled"`
	// Active means outbound delivery currently consults DANE: it is enabled,
	// a trusted resolver exists, and the probe has not shown it to be
	// non-validating.
	Active     bool      `json:"active"`
	Source     string    `json:"resolver_source"`
	Resolvers  []string  `json:"resolvers"`
	Untrusted  []string  `json:"untrusted_resolvers,omitempty"`
	Validating string    `json:"validating"`
	CheckedAt  time.Time `json:"checked_at,omitzero"`
	Detail     string    `json:"detail,omitempty"`
}

type serviceState struct {
	resolver *Resolver // nil without a trusted resolver
	status   Status
}

// Service owns the live DANE configuration consumed by outbound SMTP.
// Configuration swaps are atomic; a lookup finishes on the state it began.
type Service struct {
	opts  Options
	state atomic.Pointer[serviceState]
}

// New returns a disabled service.
func New(opts Options) *Service {
	if opts.ResolvConf == "" {
		opts.ResolvConf = "/etc/resolv.conf"
	}
	if opts.NewExchanger == nil {
		opts.NewExchanger = func(servers []string) Exchanger { return &Client{Servers: servers} }
	}
	if opts.ProbeSigned == "" {
		opts.ProbeSigned = DefaultProbeSigned
	}
	if opts.ProbeBogus == "" {
		opts.ProbeBogus = DefaultProbeBogus
	}
	service := &Service{opts: opts}
	service.Configure(Config{})
	return service
}

// Configure installs cfg. The validation verdict resets to unknown until
// the next Probe.
func (s *Service) Configure(cfg Config) {
	status := Status{Enabled: cfg.Enabled, Validating: ValidatingUnknown, Source: SourceConfigured, Resolvers: append([]string{}, cfg.Resolvers...)}
	if len(cfg.Resolvers) == 0 {
		status.Source = SourceSystem
		status.Resolvers, status.Untrusted = s.systemResolvers()
	}
	state := &serviceState{status: status}
	switch {
	case !cfg.Enabled:
		state.status.Detail = "DANE is disabled"
	case len(status.Resolvers) == 0:
		state.status.Detail = "no trusted validating resolver: configure dane_resolvers or run a local DNSSEC-validating resolver on loopback"
	default:
		state.resolver = NewResolver(s.opts.NewExchanger(status.Resolvers))
		state.status.Active = true
	}
	s.state.Store(state)
}

func (s *Service) systemResolvers() (trusted, untrusted []string) {
	conf, err := dns.ClientConfigFromFile(s.opts.ResolvConf)
	if err != nil {
		return nil, nil
	}
	for _, server := range conf.Servers {
		address := net.JoinHostPort(server, conf.Port)
		if ip, parseErr := netip.ParseAddr(server); parseErr == nil && ip.IsLoopback() {
			trusted = append(trusted, address)
		} else {
			untrusted = append(untrusted, address)
		}
	}
	return trusted, untrusted
}

// Status returns the current DANE state.
func (s *Service) Status() Status {
	status := s.state.Load().status
	status.Resolvers = append([]string{}, status.Resolvers...)
	status.Untrusted = append([]string(nil), status.Untrusted...)
	return status
}

// Active reports whether outbound delivery should consult DANE.
func (s *Service) Active() bool { return s.state.Load().status.Active }

// Probe checks that the trusted resolver validates DNSSEC: it must
// authenticate a signed name and refuse a bogus one. A resolver shown not
// to validate deactivates DANE, since its AD bit cannot be trusted; a probe
// that cannot reach the resolver leaves DANE active, because then every
// lookup fails closed as a temporary error anyway.
func (s *Service) Probe(ctx context.Context) Status {
	current := s.state.Load()
	if current.resolver == nil {
		return s.Status()
	}
	next := *current
	next.status.CheckedAt = time.Now().UTC()
	_, signed, signedErr := current.resolver.lookup(ctx, s.opts.ProbeSigned, dns.TypeSOA)
	_, bogus, _ := current.resolver.lookup(ctx, s.opts.ProbeBogus, dns.TypeSOA)
	switch {
	case signed == Bogus:
		next.status.Validating, next.status.Detail = ValidatingError, "validation probe failed: "+signedErr.Error()
	case signed != Secure:
		next.status.Validating, next.status.Detail = ValidatingNo, "resolver did not authenticate "+s.opts.ProbeSigned+" (no AD bit); it is not validating DNSSEC"
		next.status.Active = false
	case bogus != Bogus:
		next.status.Validating, next.status.Detail = ValidatingNo, "resolver answered the deliberately broken "+s.opts.ProbeBogus+"; its AD bit is not trustworthy"
		next.status.Active = false
	default:
		next.status.Validating, next.status.Detail = ValidatingYes, "validating resolver detected"
	}
	if !next.status.Active {
		next.resolver = nil
	}
	s.state.CompareAndSwap(current, &next)
	return s.Status()
}

// MX looks up domain's MX RRset. Without an active DANE configuration the
// result is Insecure, so no DANE applies.
func (s *Service) MX(ctx context.Context, domain string) MXResult {
	resolver := s.state.Load().resolver
	if resolver == nil {
		return MXResult{Security: Insecure}
	}
	return resolver.MX(ctx, domain)
}

// HostPolicy returns host's DANE policy, or StateNone while inactive.
func (s *Service) HostPolicy(ctx context.Context, host string, port int) HostPolicy {
	resolver := s.state.Load().resolver
	if resolver == nil {
		return HostPolicy{Host: canonicalName(host), State: StateNone, Reason: "DANE is inactive"}
	}
	return resolver.HostPolicy(ctx, host, port)
}
