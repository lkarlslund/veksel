package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/ratelimit"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestMaintenanceUsesTemporarySystemResponse(t *testing.T) {
	if got := pop3StorageError(account.ErrTemporarilyUnavailable); got != "-ERR [SYS/TEMP] account temporarily unavailable; retry later" {
		t.Fatalf("response = %q", got)
	}
}

// setupTestStore creates a TypedStore with a user and default folders.
func setupTestStore(t *testing.T) *model.TypedStore {
	t.Helper()
	tmpDir := t.TempDir()
	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()

	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %s: %v", ns, err)
		}
	}

	if err := ts.UserStore().Create(ctx, "alice", "Alice Test", "secret"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatalf("create folders: %v", err)
	}

	return ts
}

// makeTestServer creates a POP3 server on a random port.
func makeTestServer(t *testing.T, ts *model.TypedStore) (string, *Server, func()) {
	return makeTestServerWithConfig(t, ts, nil)
}

func makeTestServerWithConfig(t *testing.T, ts *model.TypedStore, configure func(*Config)) (string, *Server, func()) {
	t.Helper()
	cfg := &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore: ts,
	}
	if configure != nil {
		configure(cfg)
	}
	srv := New(cfg)

	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go srv.Accept(ctx, ln)

	return ln.Addr().String(), srv, func() {
		cancel()
		srv.Close()
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	return &tls.Config{Certificates: tlsServer.TLS.Certificates, MinVersion: tls.VersionTLS12}
}

// pop3Client wraps a TCP connection with POP3 protocol helpers.
type pop3Client struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func newPop3Client(t *testing.T, addr string) *pop3Client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	c := &pop3Client{
		conn: conn,
		r:    bufio.NewReader(conn),
		w:    bufio.NewWriter(conn),
	}
	// Read greeting
	line, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		t.Fatalf("unexpected greeting: %s", line)
	}
	return c
}

func (c *pop3Client) close() {
	c.conn.Close()
}

func (c *pop3Client) cmd(cmd string) (string, error) {
	fmt.Fprintln(c.w, cmd)
	c.w.Flush()
	return c.readLine()
}

func (c *pop3Client) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	return strings.TrimSpace(line), err
}

func (c *pop3Client) readUntilDot() (string, error) {
	var buf strings.Builder
	for {
		line, err := c.readLine()
		if err != nil {
			return buf.String(), err
		}
		if line == "." {
			break
		}
		buf.WriteString(line + "\n")
	}
	return buf.String(), nil
}

// --- Unit Tests ---

// --- Integration Tests ---

func TestIntegration_Greeting(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	c.close()
}

func TestIntegration_UserPass(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	resp, _ := c.cmd("USER alice")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER response: %s", resp)
	}
	resp, _ = c.cmd("PASS secret")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS response: %s", resp)
	}
}

func TestIntegration_UserPassInvalid(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	resp, _ := c.cmd("PASS wrong")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("PASS should fail, got: %s", resp)
	}
}

func TestIntegration_Stat(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("STAT")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT response: %s", resp)
	}
	if !strings.Contains(resp, "0") {
		t.Fatalf("STAT should show 0 messages: %s", resp)
	}
}

func TestIntegration_List(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\n\r\nHello World\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("LIST")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("LIST response: %s", resp)
	}
}

func TestIntegration_Retr(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\n\r\nHello World\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("RETR 1")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("RETR response: %s", resp)
	}
	body, _ := c.readUntilDot()
	if !strings.Contains(body, "Hello World") {
		t.Fatalf("message body missing 'Hello World': %s", body)
	}
	c.close()
}

func TestIntegration_Dele(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Delete Me\r\n\r\nBody\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	c.cmd("DELE 1")
	c.cmd("QUIT")
	c.close()

	// Verify message is gone
	c2 := newPop3Client(t, addr)
	c2.cmd("USER alice")
	c2.cmd("PASS secret")
	resp, _ := c2.cmd("STAT")
	if !strings.Contains(resp, "0") {
		t.Fatalf("STAT should show 0 messages after DELE+QUIT: %s", resp)
	}
}

func TestIntegration_Rset(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Keep Me\r\n\r\nBody\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	c.cmd("DELE 1")
	c.cmd("RSET")
	c.cmd("QUIT")
	c.close()

	c2 := newPop3Client(t, addr)
	c2.cmd("USER alice")
	c2.cmd("PASS secret")
	resp, _ := c2.cmd("STAT")
	if !strings.Contains(resp, "1") {
		t.Fatalf("STAT should show 1 message after RSET: %s", resp)
	}
}

func TestIntegration_Top(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Top Test\r\n\r\nThis is the body of the message which is quite long.\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("TOP 1 20")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("TOP response: %s", resp)
	}
	body, _ := c.readUntilDot()
	if !strings.Contains(body, "Subject: Top Test") {
		t.Fatalf("TOP should include headers: %s", body)
	}
	if !strings.Contains(body, "This is the body") {
		t.Fatalf("TOP should include first 20 bytes of body: %s", body)
	}
}

func TestIntegration_Uidl(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UIDL Test\r\n\r\nBody\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("UIDL")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("UIDL response: %s", resp)
	}
	body, _ := c.readUntilDot()
	if !strings.Contains(body, "1") {
		t.Fatalf("UIDL list missing message 1: %s", body)
	}
}

func TestIntegration_UidlSpecific(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UIDL\r\n\r\nBody\r\n"
	ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("UIDL 1")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("UIDL 1 response: %s", resp)
	}
	parts := strings.SplitN(resp, " ", 3)
	if len(parts) < 3 || parts[1] != "1" {
		t.Fatalf("UIDL 1 format wrong: %s", resp)
	}
}

func TestIntegration_AuthPlain(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	resp, _ := c.cmd("AUTH PLAIN")
	if resp != "+" {
		t.Fatalf("AUTH PLAIN challenge: %s", resp)
	}
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	resp, _ = c.cmd(creds)
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("AUTH PLAIN should succeed: %s", resp)
	}
}

func TestIntegration_AuthPlainInitialResponseAndCancellation(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	defer c.close()
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	resp, _ := c.cmd("AUTH PLAIN " + creds)
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("AUTH PLAIN initial response = %q", resp)
	}

	c2 := newPop3Client(t, addr)
	defer c2.close()
	resp, _ = c2.cmd("AUTH PLAIN")
	if resp != "+" {
		t.Fatalf("AUTH PLAIN challenge = %q", resp)
	}
	resp, _ = c2.cmd("*")
	if resp != "-ERR [AUTH] authentication canceled" {
		t.Fatalf("AUTH cancellation = %q", resp)
	}
	resp, _ = c2.cmd("USER alice")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("session did not recover after cancellation: %q", resp)
	}
	proxy := base64.StdEncoding.EncodeToString([]byte("bob\x00alice\x00secret"))
	if resp, _ = c2.cmd("AUTH PLAIN " + proxy); resp != "-ERR [AUTH] authorization identity is not supported" {
		t.Fatalf("AUTH PLAIN with foreign authzid = %q", resp)
	}
}

func TestIntegration_AuthLogin(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	resp, _ := c.cmd("AUTH LOGIN")
	if resp != "+ VXNlcm5hbWU6" { // base64 "Username:" (RFC 5034)
		t.Fatalf("AUTH LOGIN challenge: %s", resp)
	}
	username := base64.StdEncoding.EncodeToString([]byte("alice"))
	resp, _ = c.cmd(username)
	if resp != "+ UGFzc3dvcmQ6" { // base64 "Password:"
		t.Fatalf("AUTH LOGIN username challenge: %s", resp)
	}
	password := base64.StdEncoding.EncodeToString([]byte("secret"))
	resp, _ = c.cmd(password)
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("AUTH LOGIN should succeed: %s", resp)
	}
}

func TestIntegration_Capa(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	resp, _ := c.cmd("CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA response: %s", resp)
	}
	body, _ := c.readUntilDot()
	if !strings.Contains(body, "TOP") {
		t.Fatalf("CAPA missing TOP: %s", body)
	}
	if !strings.Contains(body, "UIDL") {
		t.Fatalf("CAPA missing UIDL: %s", body)
	}
	for _, capability := range []string{"RESP-CODES", "PIPELINING", "EXPIRE NEVER", "IMPLEMENTATION Veksel", "USER", "SASL PLAIN LOGIN"} {
		if !strings.Contains(body, capability+"\n") {
			t.Errorf("CAPA missing %q: %s", capability, body)
		}
	}
	if strings.Contains(body, "LOGINDISABLED") || strings.Contains(body, "STLS") {
		t.Fatalf("CAPA advertised an unavailable or invalid capability: %s", body)
	}
}

func TestIntegration_RequireTLSForAuthentication(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServerWithConfig(t, ts, func(cfg *Config) {
		cfg.RequireTLSForAuth = true
	})
	defer cleanup()

	c := newPop3Client(t, addr)
	defer c.close()
	resp, _ := c.cmd("CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA response = %q", resp)
	}
	body, _ := c.readUntilDot()
	if strings.Contains(body, "USER\n") || strings.Contains(body, "SASL ") || strings.Contains(body, "STLS\n") {
		t.Fatalf("CAPA advertised unusable authentication: %s", body)
	}
	resp, _ = c.cmd("USER alice")
	if resp != "-ERR [AUTH] TLS required before authentication" {
		t.Fatalf("cleartext USER = %q", resp)
	}
	resp, _ = c.cmd("AUTH PLAIN")
	if resp != "-ERR [AUTH] TLS required before authentication" {
		t.Fatalf("cleartext AUTH = %q", resp)
	}
}

func TestIntegration_STLSCapabilitiesAndAuthentication(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServerWithConfig(t, ts, func(cfg *Config) {
		cfg.TLSConfig = testTLSConfig(t)
		cfg.RequireTLSForAuth = true
	})
	defer cleanup()

	c := newPop3Client(t, addr)
	defer c.close()
	resp, _ := c.cmd("CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA response = %q", resp)
	}
	body, _ := c.readUntilDot()
	if !strings.Contains(body, "STLS\n") || strings.Contains(body, "USER\n") {
		t.Fatalf("pre-TLS CAPA = %s", body)
	}
	resp, _ = c.cmd("STLS extra")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("STLS with argument = %q", resp)
	}
	resp, _ = c.cmd("STLS")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STLS response = %q", resp)
	}
	tlsConn := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // test certificate
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.conn = tlsConn
	c.r = bufio.NewReader(tlsConn)
	c.w = bufio.NewWriter(tlsConn)
	resp, _ = c.cmd("CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("post-TLS CAPA response = %q", resp)
	}
	body, _ = c.readUntilDot()
	if strings.Contains(body, "STLS\n") || !strings.Contains(body, "USER\n") || !strings.Contains(body, "SASL PLAIN LOGIN\n") {
		t.Fatalf("post-TLS CAPA = %s", body)
	}
	resp, _ = c.cmd("STLS")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("repeated STLS = %q", resp)
	}
	resp, _ = c.cmd("USER alice")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("post-TLS USER = %q", resp)
	}
	resp, _ = c.cmd("PASS secret")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("post-TLS PASS = %q", resp)
	}
	resp, _ = c.cmd("STLS")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("transaction-state STLS = %q", resp)
	}
}

func TestIntegration_ImplicitTLSAuthentication(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServerWithConfig(t, ts, func(cfg *Config) {
		cfg.TLSConfig = testTLSConfig(t)
		cfg.ImplicitTLS = true
		cfg.RequireTLSForAuth = true
	})
	defer cleanup()

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // test certificate
	if err != nil {
		t.Fatalf("dial implicit TLS: %v", err)
	}
	c := &pop3Client{conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn)}
	defer c.close()
	if greeting, err := c.readLine(); err != nil || !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("implicit TLS greeting = %q, %v", greeting, err)
	}
	resp, _ := c.cmd("USER alice")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("implicit TLS USER = %q", resp)
	}
}

func TestIntegration_PipeliningPreservesCommandOrder(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	defer c.close()
	if _, err := fmt.Fprint(c.w, "USER alice\r\nPASS secret\r\nSTAT\r\n"); err != nil {
		t.Fatalf("write pipeline: %v", err)
	}
	if err := c.w.Flush(); err != nil {
		t.Fatalf("flush pipeline: %v", err)
	}
	for i, prefix := range []string{"+OK OK", "+OK signed in", "+OK 0 0"} {
		line, err := c.readLine()
		if err != nil || line != prefix {
			t.Fatalf("response %d = %q, %v; want %q", i, line, err, prefix)
		}
	}
}

func TestIntegration_Quit(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	c.cmd("QUIT")
}

func TestIntegration_FullFlow(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	ctx := context.Background()
	folder, _ := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	ts.ItemStore().Append(ctx, folder.ID, []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg1\r\n\r\nBody1\r\n"), nil)
	ts.ItemStore().Append(ctx, folder.ID, []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg2\r\n\r\nBody2\r\n"), nil)

	c := newPop3Client(t, addr)
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ := c.cmd("STAT")
	if !strings.Contains(resp, "2") {
		t.Fatalf("STAT should show 2 messages: %s", resp)
	}
	resp, _ = c.cmd("RETR 1")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("RETR 1 response: %s", resp)
	}
	c.readUntilDot()
	resp, _ = c.cmd("DELE 1")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("DELE 1 response: %s", resp)
	}
	c.cmd("QUIT")
}

func TestIntegration_StateMachine(t *testing.T) {
	ts := setupTestStore(t)
	addr, _, cleanup := makeTestServer(t, ts)
	defer cleanup()

	c := newPop3Client(t, addr)
	resp, _ := c.cmd("STAT")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("STAT in auth state should fail: %s", resp)
	}
	c.cmd("USER alice")
	c.cmd("PASS secret")
	resp, _ = c.cmd("STAT")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT in transaction state should succeed: %s", resp)
	}
}

func TestIntegration_AuthFailuresAreThrottledPerClient(t *testing.T) {
	ts := setupTestStore(t)
	throttle := ratelimit.NewAuthThrottleWithLimits(50, 2, time.Hour)
	var mu sync.Mutex
	verified := 0
	addr, _, cleanup := makeTestServerWithConfig(t, ts, func(cfg *Config) {
		cfg.AuthValidator = func(ctx context.Context, username, password string) (userID string, err error) {
			ip := ratelimit.ClientIP(ctx)
			if ip != "127.0.0.1" {
				t.Errorf("client IP = %q", ip)
			}
			if err := throttle.Begin(ip, username); err != nil {
				return "", err
			}
			defer func() { throttle.End(ip, username, err == nil) }()
			mu.Lock()
			verified++
			mu.Unlock()
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		}
	})
	defer cleanup()

	c := newPop3Client(t, addr)
	defer c.close()
	c.cmd("USER alice")
	for range 2 {
		if resp, _ := c.cmd("PASS wrong"); resp != "-ERR [AUTH] authentication failed" {
			t.Fatalf("failed PASS = %q", resp)
		}
	}
	const throttled = "-ERR [SYS/TEMP] too many failed authentication attempts; retry later"
	if resp, _ := c.cmd("PASS secret"); resp != throttled {
		t.Fatalf("throttled PASS = %q", resp)
	}
	c.cmd("AUTH PLAIN")
	if resp, _ := c.cmd(base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))); resp != throttled {
		t.Fatalf("throttled AUTH PLAIN = %q", resp)
	}
	c.cmd("AUTH LOGIN")
	c.cmd(base64.StdEncoding.EncodeToString([]byte("alice")))
	if resp, _ := c.cmd(base64.StdEncoding.EncodeToString([]byte("secret"))); resp != throttled {
		t.Fatalf("throttled AUTH LOGIN = %q", resp)
	}
	mu.Lock()
	defer mu.Unlock()
	if verified != 2 {
		t.Fatalf("credentials verified %d times; throttled attempts must not reach verification", verified)
	}
}

// TestIntegration_STLSRefusesPipelinedCommands checks that a command sent in
// the same cleartext write as STLS is not executed after the TLS upgrade.
func TestIntegration_STLSRefusesPipelinedCommands(t *testing.T) {
	addr, _, cleanup := makeTestServerWithConfig(t, setupTestStore(t), func(cfg *Config) {
		cfg.TLSConfig = testTLSConfig(t)
	})
	defer cleanup()
	c := newPop3Client(t, addr)
	defer c.close()
	_ = c.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if resp, _ := c.cmd("STLS\r\nUSER alice"); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("pipelined STLS = %q, want -ERR", resp)
	}
	if line, err := c.readLine(); err == nil {
		t.Fatalf("session continued after refused STLS: %q", line)
	}
}
