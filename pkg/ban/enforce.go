package ban

import (
	"net"
	"net/http"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
)

// Listener wraps a mail protocol listener so connections from banned clients
// are closed before any protocol bytes are exchanged. It belongs above a
// PROXY protocol listener, so the relayed client address is checked, and
// below implicit TLS, so banned clients never cost a handshake. surface
// labels refusals in the ban_refused_total metric. A nil Service returns ln.
func (s *Service) Listener(ln net.Listener, surface string) net.Listener {
	if s == nil {
		return ln
	}
	return &listener{Listener: ln, bans: s, surface: surface}
}

type listener struct {
	net.Listener
	bans    *Service
	surface string
}

// Accept returns the next connection from a client that is not banned.
func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.bans.Banned(ratelimit.AddrIP(conn.RemoteAddr().String()), l.surface) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// Handler refuses requests from banned clients with a bare 403. It must run
// inside httpservice.TrustedProxies.Handler so the effective client IP is
// checked. A nil Service returns next.
func (s *Service) Handler(next http.Handler) http.Handler {
	if s == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ratelimit.ClientIP(r.Context())
		if ip == "" {
			ip = ratelimit.AddrIP(r.RemoteAddr)
		}
		if s.Banned(ip, "http") {
			w.Header().Set("Connection", "close")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ObserveAuth is a ratelimit.AuthObserver: failed password attempts strike
// TriggerAuth, failed second-factor attempts strike TriggerSecondFactor, and
// any success clears the client network's strikes.
func (s *Service) ObserveAuth(ip, account string, success bool) {
	switch {
	case success:
		s.Success(ip)
	case ratelimit.IsSecondFactorAccount(account):
		s.Strike(ip, TriggerSecondFactor)
	default:
		s.Strike(ip, TriggerAuth)
	}
}

// Observation reports the ban table for runtime health. It stays healthy
// under ordinary background abuse and warns only when the table grows
// abnormally large.
func (s *Service) Observation() health.Observation {
	observation := health.Observation{ID: "abuse-bans", Label: "Abuse bans", Kind: "security", State: health.StateHealthy}
	if s == nil || !s.Policy().Enabled {
		observation.State = health.StateDisabled
		return observation
	}
	observation.Desired = true
	active := s.Active()
	observation.Details = map[string]string{"active": strconv.Itoa(active)}
	switch {
	case active >= MaxActive:
		observation.State, observation.Severity = health.StateDegraded, health.SeverityWarning
		observation.Reason = "the ban table is full; new automatic bans are skipped"
	case active >= AbnormalActive:
		observation.State, observation.Severity = health.StateDegraded, health.SeverityWarning
		observation.Reason = strconv.Itoa(active) + " active bans is abnormally many; check for a distributed attack or a misconfigured exemption"
	}
	return observation
}
