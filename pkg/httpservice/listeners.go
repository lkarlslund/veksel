package httpservice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lkarlslund/veksel/pkg/config"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

// RetireTimeout bounds how long a removed or rebound listener may finish
// its in-flight requests before its remaining connections are closed.
const RetireTimeout = 20 * time.Second

// ListenerSet runs one server per enabled HTTP(S) listener and reconciles
// the running servers against a changed listener list without a restart:
// new listeners start, removed ones drain gracefully, a changed address or
// transport rebinds, and every other change — services, HSTS, logging, the
// assigned certificate — is swapped into the running server in place.
type ListenerSet struct {
	handler   func(config.HTTPListener) http.Handler
	tlsConfig func(config.HTTPListener) (*tls.Config, error)
	timeouts  Timeouts

	mu      sync.Mutex
	serving bool
	running []*runningListener
}

type runningListener struct {
	config   config.HTTPListener
	server   *http.Server
	listener net.Listener
	handler  atomic.Pointer[http.Handler]
	tls      atomic.Pointer[tls.Config]
}

// NewListenerSet returns an empty set. handler builds the request handler
// of one listener; tlsConfig resolves the certificate of an HTTPS listener
// and may be nil when the set only runs plain HTTP listeners.
func NewListenerSet(handler func(config.HTTPListener) http.Handler, tlsConfig func(config.HTTPListener) (*tls.Config, error), timeouts Timeouts) *ListenerSet {
	return &ListenerSet{handler: handler, tlsConfig: tlsConfig, timeouts: timeouts}
}

// Serve starts serving every bound listener; listeners bound by a later
// Apply start serving immediately.
func (s *ListenerSet) Serve() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serving {
		return
	}
	s.serving = true
	for _, running := range s.running {
		s.serve(running)
	}
}

// Apply reconciles the running listeners with listeners. It validates and
// binds everything before it changes anything, so on error the previous
// listeners keep running unchanged.
func (s *ListenerSet) Apply(listeners []config.HTTPListener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := make(map[string]*runningListener, len(s.running))
	for _, running := range s.running {
		current[running.config.ID] = running
	}
	type update struct {
		running *runningListener
		next    *runningListener
	}
	var (
		next     []*runningListener
		inPlace  []update
		fresh    []*runningListener
		retiring []*runningListener
	)
	kept := make(map[string]bool)
	for _, configured := range listeners {
		if !configured.Enabled {
			continue
		}
		prepared, err := s.prepare(configured)
		if err != nil {
			return err
		}
		if old := current[configured.ID]; old != nil && old.config.Address == configured.Address && old.config.Transport == configured.Transport {
			inPlace = append(inPlace, update{running: old, next: prepared})
			next = append(next, old)
			kept[configured.ID] = true
			continue
		}
		fresh = append(fresh, prepared)
		next = append(next, prepared)
	}
	for _, running := range s.running {
		if !kept[running.config.ID] {
			retiring = append(retiring, running)
		}
	}

	// A new binding may need the port of a retiring listener: stop that
	// listener accepting first, and resume it if the change is abandoned.
	var paused []*runningListener
	for _, old := range retiring {
		if slices.ContainsFunc(fresh, func(r *runningListener) bool { return samePort(r.config.Address, old.config.Address) }) {
			_ = old.listener.Close()
			paused = append(paused, old)
		}
	}
	for i, prepared := range fresh {
		if err := s.bind(prepared); err != nil {
			for _, bound := range fresh[:i] {
				_ = bound.listener.Close()
			}
			for _, old := range paused {
				if resumeErr := s.bind(old); resumeErr != nil {
					err = errors.Join(err, fmt.Errorf("resume listener %s: %w", old.config.ID, resumeErr))
					continue
				}
				if s.serving {
					s.serve(old)
				}
			}
			return err
		}
	}

	for _, change := range inPlace {
		change.running.config = change.next.config
		change.running.handler.Store(change.next.handler.Load())
		change.running.tls.Store(change.next.tls.Load())
	}
	s.running = next
	if s.serving {
		for _, prepared := range fresh {
			s.serve(prepared)
		}
	}
	for _, old := range retiring {
		go retire(old)
	}
	return nil
}

// Servers returns the running servers, for a graceful process shutdown.
func (s *ListenerSet) Servers() []*http.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers := make([]*http.Server, 0, len(s.running))
	for _, running := range s.running {
		servers = append(servers, running.server)
	}
	return servers
}

// Addrs maps each running listener ID to its bound address.
func (s *ListenerSet) Addrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	addrs := make(map[string]string, len(s.running))
	for _, running := range s.running {
		addrs[running.config.ID] = running.listener.Addr().String()
	}
	return addrs
}

// Close immediately closes every running server and its connections.
func (s *ListenerSet) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, running := range s.running {
		_ = running.listener.Close()
		_ = running.server.Close()
	}
	s.running = nil
}

// prepare resolves the handler and certificate of configured without
// binding it.
func (s *ListenerSet) prepare(configured config.HTTPListener) (*runningListener, error) {
	prepared := &runningListener{config: configured}
	handler := s.handler(configured)
	prepared.handler.Store(&handler)
	if configured.Transport == config.HTTPSTransport {
		var tlsConfig *tls.Config
		err := errors.New("no certificate is assigned")
		if s.tlsConfig != nil {
			tlsConfig, err = s.tlsConfig(configured)
			if err == nil && tlsConfig == nil {
				err = errors.New("no certificate is assigned")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("HTTPS listener %s: load certificate: %w", configured.ID, err)
		}
		prepared.tls.Store(tlsConfig)
	}
	prepared.server = NewServer(configured.Address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*prepared.handler.Load()).ServeHTTP(w, r)
	}), s.timeouts)
	return prepared, nil
}

// bind opens the socket of running. An HTTPS listener resolves its TLS
// configuration per handshake, so certificate changes need no rebind.
func (s *ListenerSet) bind(running *runningListener) error {
	listener, err := net.Listen("tcp", running.config.Address)
	if err != nil {
		return fmt.Errorf("HTTP listener %s: bind %s: %w", running.config.ID, running.config.Address, err)
	}
	if running.config.Transport == config.HTTPSTransport {
		listener = tls.NewListener(listener, &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return running.tls.Load(), nil
			},
		})
	}
	running.listener = listener
	return nil
}

func (s *ListenerSet) serve(running *runningListener) {
	server, listener, configured := running.server, running.listener, running.config
	logger := logpkg.For(logpkg.ModuleWeb)
	go func() {
		logger.Info("HTTP service listener started", "listener", configured.ID, "transport", configured.Transport, "addr", listener.Addr().String(), "services", configured.Services)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			logger.Error("HTTP service listener stopped", "listener", configured.ID, "error", err)
		}
	}()
}

// retire stops a removed or rebound listener, letting in-flight requests
// finish within RetireTimeout.
func retire(running *runningListener) {
	_ = running.listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), RetireTimeout)
	defer cancel()
	if err := running.server.Shutdown(ctx); err != nil {
		_ = running.server.Close()
	}
	logpkg.For(logpkg.ModuleWeb).Info("HTTP service listener stopped", "listener", running.config.ID, "addr", running.config.Address)
}

// samePort reports whether two listen addresses use the same fixed port and
// so may conflict; ephemeral ports never do.
func samePort(a, b string) bool {
	_, portA, errA := net.SplitHostPort(a)
	_, portB, errB := net.SplitHostPort(b)
	return errA == nil && errB == nil && portA == portB && portA != "0" && portA != ""
}
