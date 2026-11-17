package proto

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Sessions tracks the listeners and active connections of a protocol server
// so it can stop accepting and drain sessions on shutdown. The zero value is
// ready to use.
//
// Sessions mark themselves idle while waiting for the next client command.
// Once shutdown begins, idle connections are closed immediately and busy
// connections are closed as soon as they become idle, so in-flight commands
// complete while waiting clients do not hold shutdown open.
type Sessions struct {
	mu           sync.Mutex
	wg           sync.WaitGroup
	listeners    []net.Listener
	active       map[*Session]struct{}
	shuttingDown bool
}

// Session is the shutdown handle for one tracked connection. A nil *Session
// is valid and ignores all calls, so sessions created outside an accept loop
// need no special casing.
type Session struct {
	owner *Sessions
	conn  net.Conn
	idle  bool
}

// AddListener registers ln to be closed by CloseListeners and Shutdown.
func (s *Sessions) AddListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, ln)
}

// CloseListeners closes every registered listener without affecting active
// sessions. Listeners that are already closed, such as those the caller closed
// first to stop accepting, are not an error.
func (s *Sessions) CloseListeners() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for _, ln := range s.listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Track registers conn as an active session. It returns nil and closes conn
// when shutdown has already begun. The caller must call Done on the returned
// handle when the session ends.
func (s *Sessions) Track(conn net.Conn) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shuttingDown {
		_ = conn.Close()
		return nil
	}
	if s.active == nil {
		s.active = make(map[*Session]struct{})
	}
	session := &Session{owner: s, conn: conn}
	s.active[session] = struct{}{}
	s.wg.Add(1)
	return session
}

// Active reports how many tracked sessions have not yet finished.
func (s *Sessions) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// Shutdown closes all listeners, closes idle sessions, and waits for busy
// sessions to finish. When ctx ends first, the remaining connections are
// closed and ctx.Err() is returned without waiting further.
func (s *Sessions) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.shuttingDown = true
	s.mu.Unlock()
	err := s.CloseListeners()
	s.closeSessions(true)

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return err
	case <-ctx.Done():
		s.closeSessions(false)
		return ctx.Err()
	}
}

func (s *Sessions) closeSessions(idleOnly bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for session := range s.active {
		if !idleOnly || session.idle {
			_ = session.conn.Close()
		}
	}
}

// SetIdle records whether the session is waiting for the next client
// command. Marking a session idle during shutdown closes its connection.
func (t *Session) SetIdle(idle bool) {
	if t == nil {
		return
	}
	t.owner.mu.Lock()
	defer t.owner.mu.Unlock()
	t.idle = idle
	if idle && t.owner.shuttingDown {
		_ = t.conn.Close()
	}
}

// Done unregisters the session.
func (t *Session) Done() {
	if t == nil {
		return
	}
	t.owner.mu.Lock()
	delete(t.owner.active, t)
	t.owner.mu.Unlock()
	t.owner.wg.Done()
}

// refuseWriteTimeout bounds the refusal written to a connection that is not
// admitted.
const refuseWriteTimeout = time.Second

// Refuse writes line, the protocol's refusal response, to a connection that
// was not admitted and closes it. The write runs in its own goroutine with a
// short deadline so a client that does not read cannot stall the accept loop.
func Refuse(conn net.Conn, line string) {
	go func() {
		_ = conn.SetWriteDeadline(time.Now().Add(refuseWriteTimeout))
		_, _ = io.WriteString(conn, line+"\r\n")
		_ = conn.Close()
	}()
}
