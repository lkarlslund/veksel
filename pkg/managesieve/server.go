// Package managesieve implements the RFC 5804 Sieve management protocol.
package managesieve

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/proto"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/sieve"
	"github.com/lkarlslund/veksel/pkg/store"
)

const minimumAuthenticatedIdleTimeout = 30 * time.Minute

// sieveCapabilities advertises exactly the extensions the interpreter
// implements (RFC 5804 section 1.7), with the redirect limit and the
// enotify methods.
var sieveCapabilities = []string{
	`"SIEVE" "` + sieve.Capabilities + `"`,
	`"NOTIFY" "` + strings.Join(sieve.NotifyMethods, " ") + `"`,
	`"MAXREDIRECTS" "` + strconv.Itoa(sieve.MaxRedirects) + `"`,
}

type Server struct {
	Repository        *service.SieveRepository
	Authenticate      protocolauth.AuthenticateFunc
	TLSConfig         *tls.Config
	RequireTLSForAuth bool
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration

	// policy, once set by Reconfigure, overrides TLSConfig and
	// RequireTLSForAuth for connections accepted afterwards.
	policy   atomic.Pointer[connectionPolicy]
	sessions proto.Sessions
}

type connectionPolicy struct {
	tlsConfig         *tls.Config
	requireTLSForAuth bool
}

// Reconfigure replaces the TLS configuration and authentication policy for
// connections accepted afterwards; established connections keep theirs.
func (s *Server) Reconfigure(tlsConfig *tls.Config, requireTLSForAuth bool) {
	s.policy.Store(&connectionPolicy{tlsConfig: tlsConfig, requireTLSForAuth: requireTLSForAuth})
}

func (s *Server) currentPolicy() connectionPolicy {
	if policy := s.policy.Load(); policy != nil {
		return *policy
	}
	return connectionPolicy{tlsConfig: s.TLSConfig, requireTLSForAuth: s.RequireTLSForAuth}
}

// ActiveSessions reports how many accepted connections are still running.
func (s *Server) ActiveSessions() int {
	return s.sessions.Active()
}

func (s *Server) Serve(listener net.Listener) error {
	s.sessions.AddListener(listener)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		tracked := s.sessions.Track(conn)
		if tracked == nil {
			continue
		}
		go func() {
			defer tracked.Done()
			_ = s.serveConn(context.Background(), conn, tracked)
		}()
	}
}

// Close closes the listeners passed to Serve. Active sessions keep running.
func (s *Server) Close() error {
	return s.sessions.CloseListeners()
}

// Shutdown closes the listeners and waits for active sessions to finish,
// closing idle sessions immediately and the rest when ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.sessions.Shutdown(ctx)
}

func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	return s.serveConn(ctx, conn, nil)
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn, tracked *proto.Session) error {
	defer conn.Close()
	if s.Repository == nil || s.Authenticate == nil {
		return errors.New("ManageSieve server is not configured")
	}
	ctx = ratelimit.WithClientIP(ctx, ratelimit.AddrIP(conn.RemoteAddr().String()))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	_, secure := conn.(*tls.Conn)
	policy := s.currentPolicy()
	userID := ""
	capability := func() error {
		lines := append(append([]string{`"IMPLEMENTATION" "Veksel"`}, sieveCapabilities...), `"VERSION" "1.0"`, `"UNAUTHENTICATE"`)
		// RFC 5804 1.7: SASL is always listed; it is empty only while
		// STARTTLS must come first.
		if secure || !policy.requireTLSForAuth {
			lines = append(lines, `"SASL" "PLAIN"`)
		} else {
			lines = append(lines, `"SASL" ""`)
		}
		if policy.tlsConfig != nil && !secure {
			lines = append(lines, `"STARTTLS"`)
		}
		for _, line := range lines {
			if _, err := fmt.Fprintf(writer, "%s\r\n", line); err != nil {
				return err
			}
		}
		_, err := writer.WriteString("OK\r\n")
		if err == nil {
			err = writer.Flush()
		}
		return err
	}
	if err := capability(); err != nil {
		return err
	}
	for {
		if timeout := effectiveReadTimeout(s.ReadTimeout, userID != ""); timeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
		}
		if s.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}
		tracked.SetIdle(true)
		line, err := readProtocolLine(reader)
		tracked.SetIdle(false)
		if err != nil {
			return err
		}
		args, err := parseLine(line)
		if err != nil || len(args) == 0 {
			writeStatus(writer, "NO", "", "invalid command")
			continue
		}
		command := strings.ToUpper(args[0])
		if allowed, message := commandAllowed(command, userID != ""); !allowed {
			writeStatus(writer, "NO", "", message)
			continue
		}
		switch command {
		case "CAPABILITY":
			if err := capability(); err != nil {
				return err
			}
		case "NOOP":
			switch len(args) {
			case 1:
				writeStatus(writer, "OK", "", "NOOP completed")
			case 2:
				writeStatus(writer, "OK", "TAG "+quote(args[1]), "NOOP completed")
			default:
				writeStatus(writer, "NO", "", "invalid arguments")
			}
		case "LOGOUT":
			writeStatus(writer, "OK", "", "logout")
			return nil
		case "UNAUTHENTICATE":
			userID = ""
			writeStatus(writer, "OK", "", "")
		case "STARTTLS":
			if policy.tlsConfig == nil || secure {
				writeStatus(writer, "NO", "", "TLS unavailable")
				continue
			}
			// Bytes sent before the response were read in cleartext and
			// must not run as if they had arrived under TLS.
			if reader.Buffered() > 0 {
				writeStatus(writer, "BYE", "", "data received after STARTTLS before TLS negotiation")
				return errors.New("managesieve: data pipelined after STARTTLS")
			}
			writeStatus(writer, "OK", "", "begin TLS negotiation")
			tlsConn := tls.Server(conn, policy.tlsConfig.Clone())
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return err
			}
			conn, reader, writer, secure = tlsConn, bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn), true
			userID = ""
			if err := capability(); err != nil {
				return err
			}
		case "AUTHENTICATE":
			if policy.requireTLSForAuth && !secure {
				writeStatus(writer, "NO", "ENCRYPT-NEEDED", "TLS is required for authentication")
				continue
			}
			if (len(args) != 2 && len(args) != 3) || strings.ToUpper(args[1]) != "PLAIN" {
				writeStatus(writer, "NO", "", "unsupported authentication")
				continue
			}
			initial := ""
			if len(args) == 3 {
				initial = cmp.Or(args[2], "=") // an empty string is an empty initial response
			}
			var connErr error
			username, password, saslErr := auth.RunPasswordExchange(auth.SASLPlain, initial, func(challenge string) (string, error) {
				if connErr = writeChallenge(writer, challenge); connErr != nil {
					return "", connErr
				}
				line, err := readProtocolLine(reader)
				if connErr = err; err != nil {
					return "", err
				}
				responseArgs, parseErr := parseLine(line)
				if parseErr != nil || len(responseArgs) != 1 {
					return "", auth.ErrSASLMalformed
				}
				return responseArgs[0], nil
			})
			if connErr != nil {
				return connErr
			}
			switch {
			case errors.Is(saslErr, auth.ErrSASLCanceled):
				writeStatus(writer, "NO", "", "authentication cancelled")
				continue
			case errors.Is(saslErr, auth.ErrSASLAuthzid):
				writeStatus(writer, "NO", "", "authentication failed")
				continue
			case saslErr != nil:
				writeStatus(writer, "NO", "", "invalid credentials")
				continue
			}
			id, authErr := s.Authenticate(ctx, username, password)
			if authErr != nil || id == "" {
				writeStatus(writer, "NO", "", "authentication failed")
				continue
			}
			userID = id
			writeStatus(writer, "OK", "", "authenticated")
		case "HAVESPACE":
			if len(args) != 3 {
				writeStatus(writer, "NO", "", "invalid arguments")
				continue
			}
			if _, sizeErr := parseNumber(args[2], service.MaxScriptBytes); sizeErr != nil {
				writeStatus(writer, "NO", "QUOTA/MAXSIZE", "script too large")
				continue
			}
			writeStatus(writer, "OK", "", "")
		case "CHECKSCRIPT", "PUTSCRIPT":
			name := ""
			literalArg := 1
			if command == "PUTSCRIPT" {
				if len(args) != 3 {
					writeStatus(writer, "NO", "", "invalid arguments")
					continue
				}
				name, literalArg = args[1], 2
			} else if len(args) != 2 {
				writeStatus(writer, "NO", "", "invalid arguments")
				continue
			}
			script, literalErr := readLiteral(reader, args[literalArg])
			if literalErr != nil {
				writeStatus(writer, "NO", "", literalErr.Error())
				continue
			}
			if checkErr := s.Repository.Check(script); checkErr != nil {
				writeStatus(writer, "NO", "", checkErr.Error())
				continue
			}
			if command == "PUTSCRIPT" {
				if putErr := s.Repository.Put(ctx, userID, name, script); putErr != nil {
					writeRepositoryError(writer, putErr)
					continue
				}
			}
			writeStatus(writer, "OK", "", "")
		case "LISTSCRIPTS":
			infos, listErr := s.Repository.List(ctx, userID)
			if listErr != nil {
				writeRepositoryError(writer, listErr)
				continue
			}
			for _, info := range infos {
				suffix := ""
				if info.Active {
					suffix = " ACTIVE"
				}
				fmt.Fprintf(writer, "%s%s\r\n", quote(info.Name), suffix)
			}
			writeStatus(writer, "OK", "", "")
		case "GETSCRIPT":
			if len(args) != 2 {
				writeStatus(writer, "NO", "", "invalid arguments")
				continue
			}
			script, getErr := s.Repository.Get(ctx, userID, args[1])
			if getErr != nil {
				writeRepositoryError(writer, getErr)
				continue
			}
			fmt.Fprintf(writer, "{%d}\r\n%s\r\n", len(script), script)
			writeStatus(writer, "OK", "", "")
		case "SETACTIVE":
			if len(args) != 2 {
				writeStatus(writer, "NO", "", "invalid arguments")
			} else if err := s.Repository.SetActive(ctx, userID, args[1]); err != nil {
				writeRepositoryError(writer, err)
			} else {
				writeStatus(writer, "OK", "", "")
			}
		case "DELETESCRIPT":
			if len(args) != 2 {
				writeStatus(writer, "NO", "", "invalid arguments")
			} else if err := s.Repository.Delete(ctx, userID, args[1]); err != nil {
				writeRepositoryError(writer, err)
			} else {
				writeStatus(writer, "OK", "", "")
			}
		case "RENAMESCRIPT":
			if len(args) != 3 {
				writeStatus(writer, "NO", "", "invalid arguments")
			} else if err := s.Repository.Rename(ctx, userID, args[1], args[2]); err != nil {
				writeRepositoryError(writer, err)
			} else {
				writeStatus(writer, "OK", "", "")
			}
		default:
			writeStatus(writer, "NO", "", "unknown command")
		}
	}
}

func readLiteral(reader *bufio.Reader, token string) (string, error) {
	n, err := clientLiteralSize(token)
	if err != nil {
		return "", err
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", errors.New("script is not UTF-8")
	}
	if tail, err := proto.ReadBoundedLine(reader, len("\r\n")); err != nil || tail != "\r\n" {
		return "", errors.New("literal is not terminated")
	}
	return string(data), nil
}

// maxProtocolLineLength caps one command line. Scripts travel as literals,
// so command lines stay short; the cap keeps a client, authenticated or
// not, from streaming an endless line into memory.
const maxProtocolLineLength = 64 << 10

func readProtocolLine(reader *bufio.Reader) (string, error) {
	line, err := proto.ReadBoundedLine(reader, maxProtocolLineLength)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("protocol line is not terminated with CRLF")
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}

func clientLiteralSize(token string) (int, error) {
	if !strings.HasPrefix(token, "{") || !strings.HasSuffix(token, "+}") {
		return 0, errors.New("invalid literal size")
	}
	trimmed := strings.TrimPrefix(token, "{")
	trimmed = strings.TrimSuffix(trimmed, "+}")
	n, err := parseNumber(trimmed, service.MaxScriptBytes)
	if err != nil {
		return 0, errors.New("invalid literal size")
	}
	return n, nil
}

func parseNumber(value string, maximum int) (int, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("invalid number")
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n > uint64(maximum) {
		return 0, errors.New("invalid number")
	}
	return int(n), nil
}

func effectiveReadTimeout(configured time.Duration, authenticated bool) time.Duration {
	if authenticated && configured > 0 && configured < minimumAuthenticatedIdleTimeout {
		return minimumAuthenticatedIdleTimeout
	}
	return configured
}

func commandAllowed(command string, authenticated bool) (bool, string) {
	switch command {
	case "CAPABILITY", "NOOP", "LOGOUT":
		return true, ""
	case "AUTHENTICATE", "STARTTLS":
		if authenticated {
			return false, "command requires non-authenticated state"
		}
		return true, ""
	default:
		if !authenticated {
			return false, "authenticate first"
		}
		return true, ""
	}
}

func parseLine(line string) ([]string, error) {
	var out []string
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) {
			break
		}
		if line[i] != '"' {
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			out = append(out, line[start:i])
			continue
		}
		i++
		var b strings.Builder
		closed := false
		for i < len(line) {
			c := line[i]
			i++
			if c == '"' {
				closed = true
				break
			}
			if c == '\\' {
				if i == len(line) || (line[i] != '\\' && line[i] != '"') {
					return nil, errors.New("invalid quoted escape")
				}
				c = line[i]
				i++
			}
			b.WriteByte(c)
		}
		if !closed {
			return nil, errors.New("unterminated string")
		}
		if i < len(line) && line[i] != ' ' && line[i] != '\t' {
			return nil, errors.New("missing argument separator")
		}
		out = append(out, b.String())
	}
	return out, nil
}

func quote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}
func writeStatus(w *bufio.Writer, status, code, message string) {
	if code != "" {
		fmt.Fprintf(w, "%s (%s) %s\r\n", status, code, quote(message))
	} else if message != "" {
		fmt.Fprintf(w, "%s %s\r\n", status, quote(message))
	} else {
		fmt.Fprintf(w, "%s\r\n", status)
	}
	_ = w.Flush()
}

// writeChallenge sends a base64 SASL challenge as a quoted string (RFC 5804
// section 2.1).
func writeChallenge(w *bufio.Writer, challenge string) error {
	if _, err := w.WriteString(quote(challenge) + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writeRepositoryError(w *bufio.Writer, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeStatus(w, "NO", "NONEXISTENT", "script does not exist")
	case errors.Is(err, service.ErrActive):
		writeStatus(w, "NO", "ACTIVE", "script is active")
	case errors.Is(err, service.ErrExists):
		writeStatus(w, "NO", "ALREADYEXISTS", "script already exists")
	default:
		writeStatus(w, "NO", "TRYLATER", err.Error())
	}
}
