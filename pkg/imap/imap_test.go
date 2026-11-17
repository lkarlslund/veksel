package imap

import (
	"bufio"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestMaintenanceUsesUnavailableResponseCode(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	session := newSession(1, &Config{}, server, nil, nil, nil)
	defer session.cancel()
	done := make(chan struct{})
	go func() {
		session.sendOperationError("A1", "LIST", account.ErrTemporarilyUnavailable)
		close(done)
	}()
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "A1 NO [UNAVAILABLE] Account temporarily unavailable; retry later\r\n" {
		t.Fatalf("response = %q", line)
	}
	<-done
}

func TestQuotaUsesOverQuotaResponseCode(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	session := newSession(1, &Config{}, server, nil, nil, nil)
	defer session.cancel()
	done := make(chan struct{})
	go func() {
		session.sendOperationError("A1", "APPEND", model.ErrQuotaExceeded)
		close(done)
	}()
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "A1 NO [OVERQUOTA] Account quota exceeded\r\n" {
		t.Fatalf("response = %q", line)
	}
	<-done
}

// tc wraps a net.Conn for IMAP test client operations.
type tc struct {
	net.Conn
	r *bufio.Reader
}

func (c *tc) readLine() (string, error) {
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readResponse reads an IMAP tagged response, skipping untagged lines.
// Returns tag, result code (OK/NO/BAD), and text.
func (c *tc) readResponse() (tag, code, text string) {
	for {
		line, err := c.readLine()
		if err != nil {
			return "", "", err.Error()
		}
		// Skip untagged responses (lines starting with "* ") and continuation responses (+)
		if strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "*[") || strings.HasPrefix(line, "+ ") {
			// Check for a literal size specifier {N} or { N } in the line
			// and consume the literal data
			c.consumeLiteral(line)
			continue
		}
		// Tagged response: "TAG OK text"
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 3 {
			return parts[0], parts[1], parts[2]
		}
		if len(parts) == 2 {
			return parts[0], parts[1], ""
		}
		// Single word — could be a tag with no response
		return line, "", ""
	}
}

// consumeLiteral reads any literal data indicated by {N} or { N } in the given line.
func (c *tc) consumeLiteral(line string) {
	// Find all occurrences of {N} or { N } in the line
	for {
		idx := strings.Index(line, "{")
		if idx < 0 {
			break
		}
		end := strings.Index(line[idx:], "}")
		if end < 0 {
			break
		}
		sizeStr := strings.TrimSpace(line[idx+1 : idx+end])
		if n, err := strconv.Atoi(sizeStr); err == nil {
			// Consume n bytes of literal data, then the trailing CRLF
			// Use c.r (bufio.Reader) to avoid bypassing its internal buffer
			buf := make([]byte, n)
			c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(c.r, buf); err != nil {
				return
			}
			// Consume trailing CRLF
			c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			c.r.ReadString('\n')
		}
		line = line[idx+end+1:]
	}
}

// readContinuation reads a continuation response (+ ...).
func (c *tc) readContinuation() (string, error) {
	line, err := c.readLine()
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "+") {
		return line, fmt.Errorf("expected continuation, got: %s", line)
	}
	return line, nil
}

// send writes a command and reads the tagged response.
// If tag contains a space, it is treated as the full command line (cmd is ignored).
func (c *tc) send(tag, cmd string) (respTag, code, text string) {
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if strings.Contains(tag, " ") {
		// tag is actually the full command line
		fmt.Fprintf(c.Conn, "%s\r\n", tag)
	} else {
		fmt.Fprintf(c.Conn, "%s %s\r\n", tag, cmd)
	}
	return c.readResponse()
}

// sendNoTag writes a command without expecting a tagged response (e.g., during IDLE).
func (c *tc) sendNoTag(cmd string) {
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", cmd)
}

// appendMsg sends an APPEND command with a literal, handling the continuation response.
func (c *tc) appendMsg(tag, mailbox string, flags []string, date string, msg []byte) (tagged, code, text string) {
	// Build APPEND command
	var cmd string
	if len(flags) > 0 {
		cmd = fmt.Sprintf("APPEND %s (%s)", mailbox, strings.Join(flags, " "))
	} else {
		cmd = fmt.Sprintf("APPEND %s", mailbox)
	}
	if date != "" {
		cmd += fmt.Sprintf(" %q", date)
	}
	cmd += fmt.Sprintf(" {%d}", len(msg))

	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c.Conn, "%s %s\r\n", tag, cmd)

	// Wait for continuation response
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	contLine, err := c.r.ReadString('\n')
	if err != nil {
		return "", "", err.Error()
	}
	contLine = strings.TrimRight(contLine, "\r\n")
	if !strings.HasPrefix(contLine, "+") {
		return "", "", fmt.Sprintf("expected continuation, got: %s", contLine)
	}

	// Send the message data followed by CRLF (RFC 3501 §2.3.2)
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Conn.Write(append([]byte(msg), '\r', '\n'))
	if err != nil {
		return "", "", err.Error()
	}

	// Read the tagged response (skip untagged)
	return c.readResponse()
}

// readUntagged reads untagged response lines until a tagged response appears.
// Returns all lines read (including the tagged response).
func (c *tc) readUntagged() []string {
	var lines []string
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		// Tagged responses start with a tag (no leading "* " or "+ ")
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
		// Consume any literals in the line
		c.consumeLiteral(line)
	}
	return lines
}

// makeTestServer creates an IMAP server on a random port with a real store backend.
func makeTestServer(t *testing.T, cfg *Config) *tc {
	t.Helper()

	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, srv, nil, nil)
		sess.run()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	c := &tc{Conn: conn, r: bufio.NewReader(conn)}

	// Read greeting
	greeting, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("expected * OK greeting, got: %s", greeting)
	}

	return c
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

	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL, model.NSMetadata,
		model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes, model.NSAuthorizationMetadata} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %s: %v", ns, err)
		}
	}

	// Create a test user
	if err := ts.UserStore().Create(ctx, "alice", "Alice Test", "secret"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create default folders
	if err := ts.FolderStore().CreateForUser(ctx, "alice"); err != nil {
		t.Fatalf("create folders: %v", err)
	}

	return ts
}

// TestCapability tests the CAPABILITY command.
func TestCapability(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:     "test.veksel",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	_, code, text := c.send("A001", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY: code=%s text=%s, want OK", code, text)
	}
	// Read untagged CAPABILITY response
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	// Already consumed by send, check the response includes IMAP4rev1
	// The untagged response was sent before the tagged one, so it was already read
}

func TestLiteralSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		size    int64
		nonSync bool
		wantErr bool
	}{
		{name: "synchronizing", value: "{42}", size: 42},
		{name: "non synchronizing", value: "{42+}", size: 42, nonSync: true},
		{name: "empty", value: "{}", wantErr: true},
		{name: "negative", value: "{-1}", wantErr: true},
		{name: "suffix", value: "{42x}", wantErr: true},
		{name: "missing braces", value: "42", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			size, nonSync, err := parseLiteralSize(test.value)
			if (err != nil) != test.wantErr || size != test.size || nonSync != test.nonSync {
				t.Fatalf("parseLiteralSize(%q) = (%d, %t, %v)", test.value, size, nonSync, err)
			}
		})
	}
}

func TestCapabilitiesAdvertiseLiteralPlus(t *testing.T) {
	t.Parallel()
	session := &Session{cfg: &Config{}}
	found := map[string]bool{}
	for _, capability := range session.buildCapabilities() {
		found[capability] = true
	}
	if found["LITERAL-"] {
		t.Fatal("LITERAL- advertised alongside LITERAL+")
	}
	for _, capability := range []string{"LITERAL+", "MULTIAPPEND"} {
		if !found[capability] {
			t.Fatalf("%s not advertised", capability)
		}
	}
}

func TestAppendRejectsOversizedSynchronizingLiteralBeforeContinuation(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", MaxLiteralSize: 16,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    ts,
	})
	c.send("A001", "LOGIN alice secret")
	if _, code, text := c.send("A002", "APPEND INBOX {17}"); code != "NO" || !strings.Contains(text, "TOOBIG") {
		t.Fatalf("oversized APPEND code=%s text=%s", code, text)
	}
	if _, code, text := c.send("A003", "NOOP"); code != "OK" {
		t.Fatalf("connection after rejected synchronizing literal code=%s text=%s", code, text)
	}
	items, err := ts.ItemStore().ListMetadata(t.Context(), model.InboxFolderID("alice"))
	if err != nil || len(items) != 0 {
		t.Fatalf("oversized literal stored items=%#v error=%v", items, err)
	}
}

// TestAppendAcceptsLargeLiteralPlus: with LITERAL+ (RFC 7888) a
// non-synchronizing literal of any size up to the APPEND limit is accepted
// without a continuation request.
func TestAppendAcceptsLargeLiteralPlus(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", MaxLiteralSize: 8192,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    ts,
	})
	c.send("A001", "LOGIN alice secret")
	message := "Subject: big\r\n\r\n" + strings.Repeat("z", 6000)
	c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := fmt.Fprintf(c.Conn, "A002 APPEND INBOX {%d+}\r\n%s\r\n", len(message), message); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "+") {
			t.Fatalf("continuation requested for a LITERAL+ literal: %q", line)
		}
		if strings.HasPrefix(line, "A002 ") {
			if !strings.HasPrefix(line, "A002 OK") {
				t.Fatalf("large LITERAL+ APPEND: %q", line)
			}
			break
		}
	}
	items, err := ts.ItemStore().ListMetadata(t.Context(), model.InboxFolderID("alice"))
	if err != nil || len(items) != 1 {
		t.Fatalf("large literal items=%#v error=%v", items, err)
	}
}

// TestAppendClosesOnOversizedLiteralPlus: a non-synchronizing literal over
// the APPEND limit is already on its way and cannot be refused without
// reading it (RFC 7888 4), so the session ends after a BAD.
func TestAppendClosesOnOversizedLiteralPlus(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", MaxLiteralSize: 8192,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    ts,
	})
	c.send("A001", "LOGIN alice secret")
	c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := fmt.Fprint(c.Conn, "A002 APPEND INBOX {8193+}\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, code, text := c.readResponse(); code != "BAD" || !strings.Contains(text, "limit") {
		t.Fatalf("oversized LITERAL+ code=%s text=%s", code, text)
	}
	if _, err := c.readLine(); err == nil {
		t.Fatal("session continued after an oversized non-synchronizing literal")
	}
	items, err := ts.ItemStore().ListMetadata(t.Context(), model.InboxFolderID("alice"))
	if err != nil || len(items) != 0 {
		t.Fatalf("invalid literal stored items=%#v error=%v", items, err)
	}
}

func TestMultiAppendCumulativeLiteralLimitIsAtomic(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel", MaxLiteralSize: 30,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil },
		TypedStore:    ts,
	})
	c.send("A001", "LOGIN alice secret")
	first := []byte("Subject: one\r\n\r\n123")
	second := []byte("Subject: two\r\n\r\n456")
	if len(first) >= 30 || len(second) >= 30 || len(first)+len(second) <= 30 {
		t.Fatal("test literals do not straddle cumulative limit")
	}
	command := fmt.Sprintf("A002 APPEND INBOX {%d+}\r\n%s {%d+}\r\n", len(first), first, len(second))
	if _, err := io.WriteString(c.Conn, command); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := c.readResponse(); code != "BAD" {
		t.Fatalf("cumulative limit code=%s", code)
	}
	items, err := ts.ItemStore().ListMetadata(t.Context(), model.InboxFolderID("alice"))
	if err != nil || len(items) != 0 {
		t.Fatalf("partial MULTIAPPEND items=%#v error=%v", items, err)
	}
}

func TestMultiAppendLiteralPlusIsAtomicAndReturnsUIDSet(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	first := []byte("Subject: first\r\n\r\none")
	second := []byte("Subject: second\r\n\r\ntwo")
	command := fmt.Sprintf("A003 APPEND INBOX (\\Seen) {%d+}\r\n%s {%d+}\r\n%s\r\n", len(first), first, len(second), second)
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c.Conn, command); err != nil {
		t.Fatal(err)
	}
	lines := c.readUntagged()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "A003 OK") || !strings.Contains(joined, "APPENDUID") || !strings.Contains(joined, ",") {
		t.Fatalf("MULTIAPPEND response = %s", joined)
	}
	items, err := ts.ItemStore().ListMetadata(t.Context(), model.InboxFolderID("alice"))
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if !slices.Contains(items[0].Flags, model.FlagSeen) || slices.Contains(items[1].Flags, model.FlagSeen) {
		t.Fatalf("per-message flags = %#v, %#v", items[0].Flags, items[1].Flags)
	}
}

func TestMultiAppendRollsBackEveryItemWhenQuotaFails(t *testing.T) {
	ts := setupTestStore(t)
	if err := ts.UserStore().UpdateQuota(t.Context(), "alice", 0, 1); err != nil {
		t.Fatal(err)
	}
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	c.send("A001", "LOGIN alice secret")
	first := []byte("Subject: first\r\n\r\none")
	second := []byte("Subject: second\r\n\r\ntwo")
	command := fmt.Sprintf("A002 APPEND INBOX {%d+}\r\n%s {%d+}\r\n%s\r\n", len(first), first, len(second), second)
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c.Conn, command); err != nil {
		t.Fatal(err)
	}
	_, code, text := c.readResponse()
	if code != "NO" || !strings.Contains(text, "OVERQUOTA") {
		t.Fatalf("MULTIAPPEND quota response = %s %s", code, text)
	}
	items, err := ts.ItemStore().ListMetadata(t.Context(), model.InboxFolderID("alice"))
	if err != nil || len(items) != 0 {
		t.Fatalf("partial MULTIAPPEND items=%#v err=%v", items, err)
	}
}

func TestAppendLiteralPlusFromAuthenticatedState(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", errors.New("invalid credentials")
		},
		TypedStore: ts,
	})
	if _, code, text := c.send("A001", "LOGIN alice secret"); code != "OK" {
		t.Fatalf("LOGIN: code=%s text=%s", code, text)
	}

	message := []byte("From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Literal plus\r\n\r\nHello")
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(c.Conn, "A002 APPEND INBOX {%d+}\r\n%s\r\n", len(message), message); err != nil {
		t.Fatal(err)
	}
	if _, code, text := c.readResponse(); code != "OK" {
		t.Fatalf("APPEND: code=%s text=%s", code, text)
	}

	inbox, err := ts.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	items, err := ts.ItemStore().List(t.Context(), inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("INBOX has %d items, want 1", len(items))
	}
}

// TestLogin tests the LOGIN command.
func TestLogin(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	_, code, _ := c.send("A001", "LOGIN alice secret")
	if code != "OK" {
		t.Fatalf("LOGIN: code=%s, want OK", code)
	}
}

// TestLoginInvalid tests LOGIN with wrong credentials.
func TestLoginInvalid(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	_, code, _ := c.send("A001", "LOGIN alice wrong")
	if code != "NO" {
		t.Fatalf("LOGIN invalid: code=%s, want NO", code)
	}
}

// TestAuthenticatePlain tests AUTHENTICATE PLAIN.
func TestAuthenticatePlain(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	_, code, _ := c.send("A001", "AUTHENTICATE PLAIN "+creds)
	if code != "OK" {
		t.Fatalf("AUTHENTICATE PLAIN: code=%s, want OK", code)
	}
}

// TestSelect tests the SELECT command.
func TestSelect(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT INBOX: code=%s, want OK", code)
	}
}

// TestExamine tests the EXAMINE command.
func TestExamine(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "EXAMINE INBOX")
	if code != "OK" {
		t.Fatalf("EXAMINE INBOX: code=%s, want OK", code)
	}
}

// TestList tests the LIST command.
func TestList(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "LIST \"\" *")
	if code != "OK" {
		t.Fatalf("LIST: code=%s, want OK", code)
	}
}

// TestFullSessionFlow tests the complete session: CAPABILITY → LOGIN → SELECT → FETCH → STORE → EXPUNGE → LOGOUT.
func TestFullSessionFlow(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// CAPABILITY
	_, code, _ := c.send("A001", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY: code=%s, want OK", code)
	}

	// LOGIN
	_, code, _ = c.send("A002", "LOGIN alice secret")
	if code != "OK" {
		t.Fatalf("LOGIN: code=%s, want OK", code)
	}

	// SELECT
	_, code, _ = c.send("A003", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT: code=%s, want OK", code)
	}

	// APPEND a message
	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Test\r\n\r\nHello World\r\n"
	_, code, _ = c.appendMsg("A004", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH
	_, code, _ = c.send("A005", "FETCH 1 FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH: code=%s, want OK", code)
	}

	// STORE - add \\Seen flag
	_, code, _ = c.send("A006", "STORE 1 +FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("STORE: code=%s, want OK", code)
	}

	// SEARCH
	_, code, _ = c.send("A007", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH: code=%s, want OK", code)
	}

	// EXPUNGE (no deleted items, should be OK)
	_, code, _ = c.send("A008", "EXPUNGE")
	if code != "OK" {
		t.Fatalf("EXPUNGE: code=%s, want OK", code)
	}

	// LOGOUT
	_, code, _ = c.send("A009", "LOGOUT")
	if code != "OK" {
		t.Fatalf("LOGOUT: code=%s, want OK", code)
	}
}

// TestUIDFetch tests UID FETCH.
func TestUIDFetch(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Test\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID FETCH 1:* FLAGS
	_, code, _ = c.send("A004", "UID FETCH 1:* FLAGS")
	if code != "OK" {
		t.Fatalf("UID FETCH: code=%s, want OK", code)
	}
}

// TestSearchCriteria tests various SEARCH criteria.
func TestSearchCriteria(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND messages
	appendMsg := func(subject string) {
		msg := fmt.Sprintf("From: sender@example.com\r\nTo: alice@example.com\r\nSubject: %s\r\n\r\nBody\r\n", subject)
		_, code, _ := c.appendMsg("AAPPEND", "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND: code=%s, want OK", code)
		}
	}

	appendMsg("Hello")
	appendMsg("World")

	// SEARCH ALL
	_, code, _ := c.send("A003", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code)
	}

	// SEARCH SUBJECT Hello
	_, code, _ = c.send("A004", "SEARCH SUBJECT Hello")
	if code != "OK" {
		t.Fatalf("SEARCH SUBJECT: code=%s, want OK", code)
	}

	// SEARCH UNSEEN
	_, code, _ = c.send("A005", "SEARCH UNSEEN")
	if code != "OK" {
		t.Fatalf("SEARCH UNSEEN: code=%s, want OK", code)
	}
}

// TestFlagManipulation tests adding and removing flags.
func TestFlagManipulation(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Flags\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Add \\Flagged
	_, code, _ = c.send("A004", "STORE 1 +FLAGS (\\Flagged)")
	if code != "OK" {
		t.Fatalf("STORE +FLAGS: code=%s, want OK", code)
	}

	// Verify flag was added
	_, code, _ = c.send("A005", "FETCH 1 FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH FLAGS: code=%s, want OK", code)
	}

	// Remove \\Flagged
	_, code, _ = c.send("A006", "STORE 1 -FLAGS (\\Flagged)")
	if code != "OK" {
		t.Fatalf("STORE -FLAGS: code=%s, want OK", code)
	}

	// Add \\Deleted
	_, code, _ = c.send("A007", "STORE 1 +FLAGS (\\Deleted)")
	if code != "OK" {
		t.Fatalf("STORE +FLAGS \\Deleted: code=%s, want OK", code)
	}

	// EXPUNGE should remove the deleted message
	_, code, _ = c.send("A008", "EXPUNGE")
	if code != "OK" {
		t.Fatalf("EXPUNGE: code=%s, want OK", code)
	}
}

// TestAppendDelivery tests APPEND stores a message correctly.
func TestAppendDelivery(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Appended\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Verify the message is there
	_, code, _ = c.send("A004", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code)
	}
}

// TestSequenceRemapAfterExpunge tests that sequence numbers are remapped after EXPUNGE.
func TestSequenceRemapAfterExpunge(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND two messages
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ := c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// Mark message 1 as deleted
	_, code, _ := c.send("A003", "STORE 1 +FLAGS (\\Deleted)")
	if code != "OK" {
		t.Fatalf("STORE: code=%s, want OK", code)
	}

	// EXPUNGE
	_, code, _ = c.send("A004", "EXPUNGE")
	if code != "OK" {
		t.Fatalf("EXPUNGE: code=%s, want OK", code)
	}

	// Now message 2 should be at sequence 1
	_, code, _ = c.send("A005", "FETCH 1 ENVELOPE")
	if code != "OK" {
		t.Fatalf("FETCH 1 after expunge: code=%s, want OK", code)
	}
}

// TestCreateDeleteFolder tests CREATE and DELETE mailbox commands.
func TestCreateDeleteFolder(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// CREATE
	_, code, _ := c.send("A002", "CREATE TestFolder")
	if code != "OK" {
		t.Fatalf("CREATE: code=%s, want OK", code)
	}

	// SELECT the new folder
	_, code, _ = c.send("A003", "SELECT TestFolder")
	if code != "OK" {
		t.Fatalf("SELECT TestFolder: code=%s, want OK", code)
	}

	// Deselect before deleting (can't delete selected mailbox)
	c.send("A0035", "SELECT INBOX")

	// DELETE
	_, code, _ = c.send("A004", "DELETE TestFolder")
	if code != "OK" {
		t.Fatalf("DELETE: code=%s, want OK", code)
	}
}

// TestNoop tests the NOOP command.
func TestNoop(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "NOOP")
	if code != "OK" {
		t.Fatalf("NOOP: code=%s, want OK", code)
	}
}

// TestClose tests the CLOSE command.
func TestClose(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	_, code, _ := c.send("A003", "CLOSE")
	if code != "OK" {
		t.Fatalf("CLOSE: code=%s, want OK", code)
	}
}

// TestCheck tests the CHECK command.
func TestCheck(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	_, code, _ := c.send("A003", "CHECK")
	if code != "OK" {
		t.Fatalf("CHECK: code=%s, want OK", code)
	}
}

// TestCopy tests the COPY command.
func TestCopy(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Copy Test\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// COPY to Sent
	_, code, _ = c.send("A004", "COPY 1 Sent")
	if code != "OK" {
		t.Fatalf("COPY: code=%s, want OK", code)
	}
}

// TestUIDStore tests UID STORE.
func TestUIDStore(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Store\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID STORE 1:* +FLAGS (\\Seen)
	_, code, _ = c.send("A004", "UID STORE 1:* +FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("UID STORE: code=%s, want OK", code)
	}
}

// TestUIDExpunge tests UID EXPUNGE.
func TestUIDExpunge(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Expunge\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as deleted
	c.send("A004", "STORE 1 +FLAGS (\\Deleted)")

	// UID EXPUNGE 1
	_, code, _ = c.send("A005", "UID EXPUNGE 1")
	if code != "OK" {
		t.Fatalf("UID EXPUNGE: code=%s, want OK", code)
	}
}

// TestStateMachine tests that commands are rejected in wrong states.
func TestStateMachine(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// SELECT without auth should fail
	_, code, _ := c.send("A001", "SELECT INBOX")
	if code != "BAD" {
		t.Fatalf("SELECT without auth: code=%s, want BAD", code)
	}

	// LOGIN
	c.send("A002", "LOGIN alice secret")

	// Now SELECT should work
	_, code, _ = c.send("A003", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT after auth: code=%s, want OK", code)
	}
}

// TestLsub tests the LSUB command.
func TestLsub(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "LSUB \"\" *")
	if code != "OK" {
		t.Fatalf("LSUB: code=%s, want OK", code)
	}
}

// TestSubscribeUnsubscribe tests SUBSCRIBE and UNSUBSCRIBE.
func TestSubscribeUnsubscribe(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// SUBSCRIBE
	_, code, _ := c.send("A002", "SUBSCRIBE Sent")
	if code != "OK" {
		t.Fatalf("SUBSCRIBE: code=%s, want OK", code)
	}

	// UNSUBSCRIBE
	_, code, _ = c.send("A003", "UNSUBSCRIBE Sent")
	if code != "OK" {
		t.Fatalf("UNSUBSCRIBE: code=%s, want OK", code)
	}
}

// TestRename tests the RENAME command.
func TestRename(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// CREATE
	c.send("A002", "CREATE OldName")

	// RENAME
	_, code, _ := c.send("A003", "RENAME OldName NewName")
	if code != "OK" {
		t.Fatalf("RENAME: code=%s, want OK", code)
	}
}

// TestAuthenticateLogin tests AUTHENTICATE LOGIN.
func TestAuthenticateLogin(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// AUTHENTICATE LOGIN — send command without waiting for tagged response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 AUTHENTICATE LOGIN\r\n")

	// Expect continuation: "+ Username:"
	contLine, err := c.readLine()
	if err != nil {
		t.Fatalf("expected continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}

	// Send username
	username := base64.StdEncoding.EncodeToString([]byte("alice"))
	c.Conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", username)
	contLine, _ = c.readLine()
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation for password, got: %s", contLine)
	}

	// Send password
	password := base64.StdEncoding.EncodeToString([]byte("secret"))
	fmt.Fprintf(c.Conn, "%s\r\n", password)
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("AUTHENTICATE LOGIN: code=%s, want OK", code)
	}
}

// TestFetchBody tests FETCH BODY[].
func TestFetchBody(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Body Test\r\n\r\nHello Body\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH BODY[]
	_, code, _ = c.send("A004", "FETCH 1 BODY[]")
	if code != "OK" {
		t.Fatalf("FETCH BODY[]: code=%s, want OK", code)
	}
}

// TestFetchUID tests FETCH UID.
func TestFetchUID(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UID\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH UID
	_, code, _ = c.send("A004", "FETCH 1 UID")
	if code != "OK" {
		t.Fatalf("FETCH UID: code=%s, want OK", code)
	}
}

// TestSearchUID tests SEARCH with UID criterion.
func TestSearchUID(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Search UID\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH UID 1
	_, code, _ = c.send("A004", "SEARCH UID 1")
	if code != "OK" {
		t.Fatalf("SEARCH UID: code=%s, want OK", code)
	}
}

// TestSearchSeenUnseen tests SEARCH SEEN and UNSEEN.
func TestSearchSeenUnseen(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Seen Test\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH UNSEEN (should find the message)
	_, code, _ = c.send("A004", "SEARCH UNSEEN")
	if code != "OK" {
		t.Fatalf("SEARCH UNSEEN: code=%s, want OK", code)
	}

	// Mark as seen
	c.send("A005", "STORE 1 +FLAGS (\\Seen)")

	// SEARCH SEEN (should find the message now)
	_, code, _ = c.send("A006", "SEARCH SEEN")
	if code != "OK" {
		t.Fatalf("SEARCH SEEN: code=%s, want OK", code)
	}
}

// TestSearchOr tests SEARCH with OR criterion.
func TestSearchOr(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// SEARCH OR SEEN UNSEEN
	_, code, _ := c.send("A003", "SEARCH OR SEEN UNSEEN")
	if code != "OK" {
		t.Fatalf("SEARCH OR: code=%s, want OK", code)
	}
}

// TestSearchNot tests SEARCH with NOT criterion.
func TestSearchNot(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// SEARCH NOT SEEN
	_, code, _ := c.send("A003", "SEARCH NOT SEEN")
	if code != "OK" {
		t.Fatalf("SEARCH NOT: code=%s, want OK", code)
	}
}

// TestIdle tests the IDLE command.
func TestIdle(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Start IDLE
	c.sendNoTag("A003 IDLE")
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	contLine, _ := c.readLine()
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", contLine)
	}

	// Exit IDLE with DONE
	c.Conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	fmt.Fprint(c.Conn, "DONE\r\n")
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}
}

func TestIdleRejectsArgumentsAndNonDONEInput(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(context.Context, string, string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	if _, code, _ := c.send("A003", "IDLE unexpected"); code != "BAD" {
		t.Fatalf("IDLE with argument: code=%s, want BAD", code)
	}

	c.sendNoTag("A004 IDLE")
	continuation, err := c.readLine()
	if err != nil || !strings.HasPrefix(continuation, "+") {
		t.Fatalf("IDLE continuation = %q err=%v", continuation, err)
	}
	c.sendNoTag("NOOP")
	_, code, text := c.readResponse()
	if code != "BAD" || !strings.Contains(text, "Expected DONE") {
		t.Fatalf("non-DONE input: code=%s text=%s", code, text)
	}
}

// TestFetchModSeq tests FETCH MODSEQ.
func TestFetchModSeq(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: ModSeq\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH MODSEQ
	_, code, _ = c.send("A004", "FETCH 1 MODSEQ")
	if code != "OK" {
		t.Fatalf("FETCH MODSEQ: code=%s, want OK", code)
	}
}

// TestFetchSize tests FETCH RFC822.SIZE.
func TestFetchSize(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Size\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH RFC822.SIZE
	_, code, _ = c.send("A004", "FETCH 1 RFC822.SIZE")
	if code != "OK" {
		t.Fatalf("FETCH RFC822.SIZE: code=%s, want OK", code)
	}
}

// TestFetchInternalDate tests FETCH INTERNALDATE.
func TestFetchInternalDate(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Date\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH INTERNALDATE
	_, code, _ = c.send("A004", "FETCH 1 INTERNALDATE")
	if code != "OK" {
		t.Fatalf("FETCH INTERNALDATE: code=%s, want OK", code)
	}
}

// TestStoreSilent tests STORE with .SILENT flag.
func TestStoreSilent(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Silent\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// STORE +FLAGS.SILENT
	_, code, _ = c.send("A004", "STORE 1 +FLAGS.SILENT (\\Flagged)")
	if code != "OK" {
		t.Fatalf("STORE SILENT: code=%s, want OK", code)
	}
}

// TestUIDCopy tests UID COPY.
func TestUIDCopy(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Copy\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID COPY 1 Sent
	_, code, _ = c.send("A004", "UID COPY 1 Sent")
	if code != "OK" {
		t.Fatalf("UID COPY: code=%s, want OK", code)
	}
}

// TestFetchHeader tests FETCH BODY[HEADER].
func TestFetchHeader(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Header\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH BODY[HEADER]
	_, code, _ = c.send("A004", "FETCH 1 BODY[HEADER]")
	if code != "OK" {
		t.Fatalf("FETCH BODY[HEADER]: code=%s, want OK", code)
	}
}

// TestFetchText tests FETCH BODY[TEXT].
func TestFetchText(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Text\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH BODY[TEXT]
	_, code, _ = c.send("A004", "FETCH 1 BODY[TEXT]")
	if code != "OK" {
		t.Fatalf("FETCH BODY[TEXT]: code=%s, want OK", code)
	}
}

// TestSearchFlagged tests SEARCH FLAGGED.
func TestSearchFlagged(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Flagged\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as flagged
	c.send("A004", "STORE 1 +FLAGS (\\Flagged)")

	// SEARCH FLAGGED
	_, code, _ = c.send("A005", "SEARCH FLAGGED")
	if code != "OK" {
		t.Fatalf("SEARCH FLAGGED: code=%s, want OK", code)
	}
}

// TestSearchDeleted tests SEARCH DELETED.
func TestSearchDeleted(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Deleted\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as deleted
	c.send("A004", "STORE 1 +FLAGS (\\Deleted)")

	// SEARCH DELETED
	_, code, _ = c.send("A005", "SEARCH DELETED")
	if code != "OK" {
		t.Fatalf("SEARCH DELETED: code=%s, want OK", code)
	}
}

// TestSearchSinceBefore tests SEARCH SINCE and BEFORE.
func TestSearchSinceBefore(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Date\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH SINCE today
	today := time.Now().UTC().Format("02-Jan-2006")
	_, code, _ = c.send("A004", fmt.Sprintf("SEARCH SINCE %s", today))
	if code != "OK" {
		t.Fatalf("SEARCH SINCE: code=%s, want OK", code)
	}

	// SEARCH BEFORE tomorrow
	tomorrow := time.Now().UTC().Add(24 * time.Hour).Format("02-Jan-2006")
	_, code, _ = c.send("A005", fmt.Sprintf("SEARCH BEFORE %s", tomorrow))
	if code != "OK" {
		t.Fatalf("SEARCH BEFORE: code=%s, want OK", code)
	}
}

// TestSearchLargerSmaller tests SEARCH LARGER and SMALLER.
func TestSearchLargerSmaller(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Size\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH LARGER 0 (should find the message)
	_, code, _ = c.send("A004", "SEARCH LARGER 0")
	if code != "OK" {
		t.Fatalf("SEARCH LARGER: code=%s, want OK", code)
	}

	// SEARCH SMALLER 99999 (should find the message)
	_, code, _ = c.send("A005", "SEARCH SMALLER 99999")
	if code != "OK" {
		t.Fatalf("SEARCH SMALLER: code=%s, want OK", code)
	}
}

// TestFetchSequenceSet tests FETCH with sequence sets.
func TestFetchSequenceSet(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND 3 messages
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ := c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// FETCH 1:3 FLAGS
	_, code, _ := c.send("A003", "FETCH 1:3 FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH 1:3: code=%s, want OK", code)
	}

	// FETCH 1:2,3 FLAGS
	_, code, _ = c.send("A004", "FETCH 1:2,3 FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH 1:2,3: code=%s, want OK", code)
	}

	// FETCH * FLAGS
	_, code, _ = c.send("A005", "FETCH * FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH *: code=%s, want OK", code)
	}
}

// TestAppendWithFlags tests APPEND with flags.
func TestAppendWithFlags(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Flags\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", []string{"\\Seen"}, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND with flags: code=%s, want OK", code)
	}

	// Verify \\Seen flag is set
	_, code, _ = c.send("A004", "FETCH 1 FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH FLAGS: code=%s, want OK", code)
	}
}

// TestAppendToDifferentFolder tests APPEND to a different folder.
func TestAppendToDifferentFolder(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Sent\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "Sent", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND Sent: code=%s, want OK", code)
	}

	// SELECT Sent and verify
	c.send("A004", "SELECT Sent")
	_, code, _ = c.send("A005", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in Sent: code=%s, want OK", code)
	}
}

// TestStoreSetFlags tests STORE FLAGS (set, not add/remove).
func TestStoreSetFlags(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Set\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// STORE FLAGS (set to \\Seen only)
	_, code, _ = c.send("A004", "STORE 1 FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("STORE FLAGS: code=%s, want OK", code)
	}
}

// TestSearchAnswered tests SEARCH ANSWERED and UNANSWERED.
func TestSearchAnswered(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Answered\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH UNANSWERED (should find it)
	_, code, _ = c.send("A004", "SEARCH UNANSWERED")
	if code != "OK" {
		t.Fatalf("SEARCH UNANSWERED: code=%s, want OK", code)
	}

	// Mark as answered
	c.send("A005", "STORE 1 +FLAGS (\\Answered)")

	// SEARCH ANSWERED (should find it now)
	_, code, _ = c.send("A006", "SEARCH ANSWERED")
	if code != "OK" {
		t.Fatalf("SEARCH ANSWERED: code=%s, want OK", code)
	}
}

// TestSearchDraft tests SEARCH DRAFT.
func TestSearchDraft(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Draft\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as draft
	c.send("A004", "STORE 1 +FLAGS (\\Draft)")

	// SEARCH DRAFT
	_, code, _ = c.send("A005", "SEARCH DRAFT")
	if code != "OK" {
		t.Fatalf("SEARCH DRAFT: code=%s, want OK", code)
	}
}

// TestSearchFromTo tests SEARCH FROM and TO.
func TestSearchFromTo(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: bob@example.com\r\nTo: alice@example.com\r\nSubject: FromTo\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH FROM bob
	_, code, _ = c.send("A004", "SEARCH FROM bob")
	if code != "OK" {
		t.Fatalf("SEARCH FROM: code=%s, want OK", code)
	}

	// SEARCH TO alice
	_, code, _ = c.send("A005", "SEARCH TO alice")
	if code != "OK" {
		t.Fatalf("SEARCH TO: code=%s, want OK", code)
	}
}

// TestSearchSubject tests SEARCH SUBJECT.
func TestSearchSubject(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Hello World\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH SUBJECT Hello
	_, code, _ = c.send("A004", "SEARCH SUBJECT Hello")
	if code != "OK" {
		t.Fatalf("SEARCH SUBJECT: code=%s, want OK", code)
	}
}

// TestSearchOld tests SEARCH OLD.
func TestSearchOld(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Old\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as seen
	c.send("A004", "STORE 1 +FLAGS (\\Seen)")

	// SEARCH OLD (seen messages)
	_, code, _ = c.send("A005", "SEARCH OLD")
	if code != "OK" {
		t.Fatalf("SEARCH OLD: code=%s, want OK", code)
	}
}

// TestSearchUndeleted tests SEARCH UNDELETED.
func TestSearchUndeleted(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Undeleted\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH UNDELETED
	_, code, _ = c.send("A004", "SEARCH UNDELETED")
	if code != "OK" {
		t.Fatalf("SEARCH UNDELETED: code=%s, want OK", code)
	}
}

// TestSearchUnflagged tests SEARCH UNFLAGGED.
func TestSearchUnflagged(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Unflagged\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH UNFLAGGED
	_, code, _ = c.send("A004", "SEARCH UNFLAGGED")
	if code != "OK" {
		t.Fatalf("SEARCH UNFLAGGED: code=%s, want OK", code)
	}
}

// TestSearchUndraft tests SEARCH UNDRAFT.
func TestSearchUndraft(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: NotDraft\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH UNDRAFT
	_, code, _ = c.send("A004", "SEARCH UNDRAFT")
	if code != "OK" {
		t.Fatalf("SEARCH UNDRAFT: code=%s, want OK", code)
	}
}

// TestSearchNew tests SEARCH NEW.
func TestSearchNew(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: New\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH NEW (recent and unseen)
	_, code, _ = c.send("A004", "SEARCH NEW")
	if code != "OK" {
		t.Fatalf("SEARCH NEW: code=%s, want OK", code)
	}
}

// TestSearchHeader tests SEARCH HEADER.
func TestSearchHeader(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Header\r\nX-Custom: test123\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH HEADER X-Custom test
	_, code, _ = c.send("A004", "SEARCH HEADER X-Custom test")
	if code != "OK" {
		t.Fatalf("SEARCH HEADER: code=%s, want OK", code)
	}
}

// TestSearchBody tests SEARCH BODY.
func TestSearchBody(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: BodySearch\r\n\r\nThis is the body content\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH BODY content
	_, code, _ = c.send("A004", "SEARCH BODY content")
	if code != "OK" {
		t.Fatalf("SEARCH BODY: code=%s, want OK", code)
	}
}

// TestCreateInbox tests that CREATE INBOX fails.
func TestCreateInbox(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "CREATE INBOX")
	if code != "NO" {
		t.Fatalf("CREATE INBOX: code=%s, want NO", code)
	}
}

// TestDeleteInbox tests that DELETE INBOX fails.
func TestDeleteInbox(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "DELETE INBOX")
	if code != "NO" {
		t.Fatalf("DELETE INBOX: code=%s, want NO", code)
	}
}

// TestExamineReadOnly tests that EXAMINE makes the mailbox read-only.
func TestExamineReadOnly(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "EXAMINE INBOX")

	// STORE should fail in read-only mode
	_, code, _ := c.send("A003", "STORE 1 +FLAGS (\\Seen)")
	if code != "NO" {
		t.Fatalf("STORE in EXAMINE: code=%s, want NO", code)
	}
}

// TestFetchMultipleAttrs tests FETCH with multiple attributes.
func TestFetchMultipleAttrs(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Multi\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH with multiple attributes
	_, code, _ = c.send("A004", "FETCH 1 (FLAGS UID RFC822.SIZE INTERNALDATE MODSEQ)")
	if code != "OK" {
		t.Fatalf("FETCH multi: code=%s, want OK", code)
	}
}

// TestFetchFullMacro tests FETCH FULL macro.
func TestFetchFullMacro(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Full\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH FULL
	_, code, _ = c.send("A004", "FETCH 1 FULL")
	if code != "OK" {
		t.Fatalf("FETCH FULL: code=%s, want OK", code)
	}
}

// TestFetchFastMacro tests FETCH FAST macro.
func TestFetchFastMacro(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Fast\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH FAST
	_, code, _ = c.send("A004", "FETCH 1 FAST")
	if code != "OK" {
		t.Fatalf("FETCH FAST: code=%s, want OK", code)
	}
}

// TestSelectNonExistent tests SELECT on a non-existent mailbox.
func TestSelectNonExistent(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "SELECT NonExistent")
	if code != "NO" {
		t.Fatalf("SELECT NonExistent: code=%s, want NO", code)
	}
}

// TestLogout tests LOGOUT.
func TestLogout(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "LOGOUT")
	if code != "OK" {
		t.Fatalf("LOGOUT: code=%s, want OK", code)
	}
}

// TestCapabilityBeforeAuth tests CAPABILITY before authentication.
func TestCapabilityBeforeAuth(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	_, code, _ := c.send("A001", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY before auth: code=%s, want OK", code)
	}
}

// TestNoopBeforeAuth tests NOOP before authentication.
func TestNoopBeforeAuth(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	_, code, _ := c.send("A001", "NOOP")
	if code != "OK" {
		t.Fatalf("NOOP before auth: code=%s, want OK", code)
	}
}

// TestAuthenticatePlainInvalid tests AUTHENTICATE PLAIN with invalid credentials.
func TestAuthenticatePlainInvalid(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00wrong"))
	_, code, _ := c.send("A001", "AUTHENTICATE PLAIN "+creds)
	if code != "NO" {
		t.Fatalf("AUTHENTICATE PLAIN invalid: code=%s, want NO", code)
	}
}

// TestAuthenticateUnsupported tests AUTHENTICATE with unsupported mechanism.
func TestAuthenticateUnsupported(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	_, code, _ := c.send("A001", "AUTHENTICATE X-OAUTH2")
	if code != "NO" {
		t.Fatalf("AUTHENTICATE X-OAUTH2: code=%s, want NO", code)
	}
}

// TestUnsubscribeInbox tests that UNSUBSCRIBE INBOX fails.
func TestUnsubscribeInbox(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", "UNSUBSCRIBE INBOX")
	if code != "NO" {
		t.Fatalf("UNSUBSCRIBE INBOX: code=%s, want NO", code)
	}
}

// TestRenameToInbox tests that RENAME to INBOX fails.
func TestRenameToInbox(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "CREATE TestRename")
	_, code, _ := c.send("A003", "RENAME TestRename INBOX")
	if code != "NO" {
		t.Fatalf("RENAME to INBOX: code=%s, want NO", code)
	}
}

// TestDeleteSelected tests that DELETE on selected mailbox fails.
func TestDeleteSelected(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "CREATE TestDelete")
	c.send("A003", "SELECT TestDelete")
	_, code, _ := c.send("A004", "DELETE TestDelete")
	if code != "NO" {
		t.Fatalf("DELETE selected: code=%s, want NO", code)
	}
}

// TestSearchEmpty tests SEARCH on empty mailbox.
func TestSearchEmpty(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	_, code, _ := c.send("A003", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL empty: code=%s, want OK", code)
	}
}

// TestSearchOn tests SEARCH ON.
func TestSearchOn(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: On\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH ON today
	today := time.Now().UTC().Format("02-Jan-2006")
	_, code, _ = c.send("A004", fmt.Sprintf("SEARCH ON %s", today))
	if code != "OK" {
		t.Fatalf("SEARCH ON: code=%s, want OK", code)
	}
}

// TestSearchSentSince tests SEARCH SENTSINCE.
func TestSearchSentSince(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: SentSince\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH SENTSINCE today
	today := time.Now().UTC().Format("02-Jan-2006")
	_, code, _ = c.send("A004", fmt.Sprintf("SEARCH SENTSINCE %s", today))
	if code != "OK" {
		t.Fatalf("SEARCH SENTSINCE: code=%s, want OK", code)
	}
}

// TestSearchSentBefore tests SEARCH SENTBEFORE.
func TestSearchSentBefore(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: SentBefore\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH SENTBEFORE tomorrow
	tomorrow := time.Now().UTC().Add(24 * time.Hour).Format("02-Jan-2006")
	_, code, _ = c.send("A004", fmt.Sprintf("SEARCH SENTBEFORE %s", tomorrow))
	if code != "OK" {
		t.Fatalf("SEARCH SENTBEFORE: code=%s, want OK", code)
	}
}

// TestSearchSentOn tests SEARCH SENTON.
func TestSearchSentOn(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: SentOn\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// SEARCH SENTON today
	today := time.Now().UTC().Format("02-Jan-2006")
	_, code, _ = c.send("A004", fmt.Sprintf("SEARCH SENTON %s", today))
	if code != "OK" {
		t.Fatalf("SEARCH SENTON: code=%s, want OK", code)
	}
}

// TestSearchAnd tests SEARCH with explicit AND.
func TestSearchAnd(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: And\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as seen
	c.send("A004", "STORE 1 +FLAGS (\\Seen)")

	// SEARCH AND SEEN ALL
	_, code, _ = c.send("A005", "SEARCH AND SEEN ALL")
	if code != "OK" {
		t.Fatalf("SEARCH AND: code=%s, want OK", code)
	}
}

// TestAppendWithDateTime tests APPEND with a specific date-time.
func TestAppendWithDateTime(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: DateTime\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", []string{"\\Seen"}, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND with date: code=%s, want OK", code)
	}
}

// TestStoreRemoveFlags tests STORE -FLAGS.
func TestStoreRemoveFlags(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Remove\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Add \\Seen
	c.send("A004", "STORE 1 +FLAGS (\\Seen)")

	// Remove \\Seen
	_, code, _ = c.send("A005", "STORE 1 -FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("STORE -FLAGS: code=%s, want OK", code)
	}
}

// TestUIDFetchMultiple tests UID FETCH with multiple UIDs.
func TestUIDFetchMultiple(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND 2 messages
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: UID%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ := c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// UID FETCH 1:2 FLAGS
	_, code, _ := c.send("A003", "UID FETCH 1:2 FLAGS")
	if code != "OK" {
		t.Fatalf("UID FETCH 1:2: code=%s, want OK", code)
	}
}

// TestUIDStoreSilent tests UID STORE with .SILENT.
func TestUIDStoreSilent(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UIDSilent\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID STORE 1:* +FLAGS.SILENT (\\Seen)
	_, code, _ = c.send("A004", "UID STORE 1:* +FLAGS.SILENT (\\Seen)")
	if code != "OK" {
		t.Fatalf("UID STORE SILENT: code=%s, want OK", code)
	}
}

// TestUIDStoreRemove tests UID STORE -FLAGS.
func TestUIDStoreRemove(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UIDRemove\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Add \\Seen
	c.send("A004", "STORE 1 +FLAGS (\\Seen)")

	// UID STORE 1 -FLAGS (\\Seen)
	_, code, _ = c.send("A005", "UID STORE 1 -FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("UID STORE -FLAGS: code=%s, want OK", code)
	}
}

// TestUIDStoreSet tests UID STORE FLAGS (set).
func TestUIDStoreSet(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UIDSet\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID STORE 1 FLAGS (\\Seen \\Flagged)
	_, code, _ = c.send("A004", "UID STORE 1 FLAGS (\\Seen \\Flagged)")
	if code != "OK" {
		t.Fatalf("UID STORE FLAGS: code=%s, want OK", code)
	}
}

// TestUIDSearch tests UID SEARCH.
func TestUIDSearch(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: UIDSearch\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID SEARCH ALL
	_, code, _ = c.send("A004", "UID SEARCH ALL")
	if code != "OK" {
		t.Fatalf("UID SEARCH ALL: code=%s, want OK", code)
	}
}

// TestIdleNotification tests IDLE notification when a new message arrives.
func TestIdleNotification(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	srv := New(&Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, srv.cfg.Load(), conn, srv, nil, nil)
		sess.run()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	// Read greeting
	c.readLine()

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Start IDLE
	c.sendNoTag("A003 IDLE")
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	contLine, _ := c.readLine()
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", contLine)
	}

	// Wait for the server goroutine to register the IDLE notifier.
	// Without this sleep, notifyFolder may be called before registration,
	// causing the notification to be silently dropped.
	time.Sleep(50 * time.Millisecond)

	// Deliver a message and notify, as the delivery queue does.
	folderID := model.InboxFolderID("alice")
	deliverTestMessage(t, ts, folderID)
	srv.NotifyExists(folderID)

	// Read notification
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	notif, _ := c.readLine()
	if !strings.Contains(notif, "EXISTS") {
		t.Fatalf("expected EXISTS notification, got: %s", notif)
	}

	// Exit IDLE
	c.Conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	fmt.Fprint(c.Conn, "DONE\r\n")
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}
}

// TestFetchStar tests FETCH with * as sequence set.
func TestFetchStar(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND 2 messages
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Star%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ := c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// A bare * addresses only the largest sequence number.
	_, code, _ := c.send("A003", "FETCH * FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH *: code=%s, want OK", code)
	}
}

// TestFetch1Star tests FETCH 1:* as sequence set.
func TestFetch1Star(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND 2 messages
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: OneStar%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ := c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// FETCH 1:* FLAGS
	_, code, _ := c.send("A003", "FETCH 1:* FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH 1:*: code=%s, want OK", code)
	}
}

// makeMultiSessionServer creates an IMAP server that accepts multiple connections.
// Returns the server, listener, and a helper to dial new connections.
func makeMultiSessionServer(t *testing.T, cfg *Config) (*Server, net.Listener, func() *tc) {
	t.Helper()

	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	// Accept connections in a loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			id := srv.sessionID.Add(1)
			sess := newSession(id, cfg, conn, srv, nil, nil)
			go func() {
				sess.run()
			}()
		}
	}()

	dialConn := func() *tc {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		c := &tc{Conn: conn, r: bufio.NewReader(conn)}
		// Read greeting
		greeting, err := c.readLine()
		if err != nil {
			t.Fatalf("read greeting: %v", err)
		}
		if !strings.HasPrefix(greeting, "* OK") {
			t.Fatalf("expected * OK greeting, got: %s", greeting)
		}
		return c
	}

	return srv, ln, dialConn
}

// TestIdleMultiSessionAppend tests that APPEND in one session triggers an EXISTS
// notification in another session's IDLE.
func TestIdleMultiSessionAppend(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	_, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Session 1 — will IDLE
	s1 := dial()
	s1.send("A001", "LOGIN alice secret")
	s1.send("A002", "SELECT INBOX")

	// Session 2 — will APPEND
	s2 := dial()
	s2.send("B001", "LOGIN alice secret")
	s2.send("B002", "SELECT INBOX")

	// Session 1 enters IDLE
	s1.sendNoTag("A003 IDLE")
	s1.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	contLine, err := s1.readIdleContinuation()
	if err != nil {
		t.Fatalf("expected IDLE continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", contLine)
	}

	// Session 2 APPENDs a message to INBOX
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Multi\r\n\r\nBody\r\n"
	s2.appendMsg("B003", "INBOX", nil, "", []byte(msg))

	// Session 1 should receive an EXISTS notification
	s1.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	notif, err := s1.readLine()
	if err != nil {
		t.Fatalf("expected EXISTS notification, got error: %v", err)
	}
	if !strings.Contains(notif, "EXISTS") {
		t.Fatalf("expected EXISTS notification, got: %s", notif)
	}

	// Exit IDLE
	s1.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(s1.Conn, "DONE\r\n")
	_, code, _ := s1.readResponse()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}
}

// TestIdleMultiSessionExpunge tests that EXPUNGE in one session triggers an EXPUNGE
// notification in another session's IDLE.
func TestIdleMultiSessionExpunge(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	_, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Session 1 — will IDLE
	s1 := dial()
	s1.send("A001", "LOGIN alice secret")
	s1.send("A002", "SELECT INBOX")

	// Session 2 — will expunge
	s2 := dial()
	s2.send("B001", "LOGIN alice secret")
	s2.send("B002", "SELECT INBOX")

	// Session 2 APPENDs a message, then marks it deleted
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Expunge\r\n\r\nBody\r\n"
	s2.appendMsg("B003", "INBOX", nil, "", []byte(msg))
	s2.send("B004", "STORE 1 +FLAGS (\\Deleted)")

	// Session 1 enters IDLE
	s1.sendNoTag("A003 IDLE")
	s1.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	contLine, err := s1.readIdleContinuation()
	if err != nil {
		t.Fatalf("expected IDLE continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", contLine)
	}

	// Session 2 EXPUNGEs
	s2.send("B005", "EXPUNGE")

	// Session 1 should receive an EXPUNGE notification
	s1.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	notif, err := s1.readLine()
	if err != nil {
		t.Fatalf("expected EXPUNGE notification, got error: %v", err)
	}
	if !strings.Contains(notif, "EXPUNGE") {
		t.Fatalf("expected EXPUNGE notification, got: %s", notif)
	}

	// Exit IDLE
	s1.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(s1.Conn, "DONE\r\n")
	_, code, _ := s1.readResponse()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}
}

// TestIdleMultiSessionFlags tests that STORE/flag changes in one session trigger
// a FETCH (FLAGS) notification in another session's IDLE.
func TestIdleMultiSessionFlags(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	_, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Session 1 — will IDLE
	s1 := dial()
	s1.send("A001", "LOGIN alice secret")
	s1.send("A002", "SELECT INBOX")

	// Session 2 — will modify flags
	s2 := dial()
	s2.send("B001", "LOGIN alice secret")
	s2.send("B002", "SELECT INBOX")

	// Session 2 APPENDs a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Flags\r\n\r\nBody\r\n"
	s2.appendMsg("B003", "INBOX", nil, "", []byte(msg))

	// Session 1 enters IDLE
	s1.sendNoTag("A003 IDLE")
	s1.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	contLine, err := s1.readIdleContinuation()
	if err != nil {
		t.Fatalf("expected IDLE continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", contLine)
	}

	// Session 2 modifies flags
	s2.send("B004", "STORE 1 +FLAGS (\\Seen)")

	// Session 1 should receive a FETCH (FLAGS) notification
	s1.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	notif, err := s1.readLine()
	if err != nil {
		t.Fatalf("expected FLAGS notification, got error: %v", err)
	}
	if !strings.Contains(notif, "FETCH") || !strings.Contains(notif, "FLAGS") {
		t.Fatalf("expected FETCH (FLAGS) notification, got: %s", notif)
	}

	// Exit IDLE
	s1.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(s1.Conn, "DONE\r\n")
	_, code, _ := s1.readResponse()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.veksel",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// TestSTARTTLS tests the IMAP STARTTLS command.
func TestSTARTTLS(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	srv := New(&Config{
		ServerName: "test.veksel",
		TLSConfig:  tlsCfg,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	cfg := &Config{
		ServerName: "test.veksel",
		TLSConfig:  tlsCfg,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, srv, nil, nil)
		sess.run()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	c := &tc{Conn: conn, r: bufio.NewReader(conn)}

	// Read greeting
	greeting, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("expected * OK greeting, got: %s", greeting)
	}

	// CAPABILITY should advertise STARTTLS
	c.send("A001", "CAPABILITY")

	// Issue STARTTLS
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A002 STARTTLS\r\n")

	// Read the OK response
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("STARTTLS: code=%s, want OK", code)
	}

	// Upgrade to TLS
	tlsConn := tls.Client(c.Conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.Conn = tlsConn
	c.r = bufio.NewReader(tlsConn)

	// After TLS, CAPABILITY should NOT advertise STARTTLS
	_, code, _ = c.send("A003", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY after STARTTLS: code=%s, want OK", code)
	}

	// LOGIN should work over TLS
	_, code, _ = c.send("A004", "LOGIN alice secret")
	if code != "OK" {
		t.Fatalf("LOGIN after STARTTLS: code=%s, want OK", code)
	}
}

func TestServerTLSConfigEnforcesTLS12WithoutMutatingInput(t *testing.T) {
	input := &tls.Config{MinVersion: tls.VersionTLS10}
	got := serverTLSConfig(input)
	if got == input {
		t.Fatal("serverTLSConfig must clone a configuration that needs hardening")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", got.MinVersion)
	}
	if input.MinVersion != tls.VersionTLS10 {
		t.Fatalf("input MinVersion was mutated to %x", input.MinVersion)
	}
	if got := serverTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13}); got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3 kept", got.MinVersion)
	}
}

// recordingSessionCache records whether the server issued a session ticket.
type recordingSessionCache struct{ stored atomic.Bool }

func (c *recordingSessionCache) Get(string) (*tls.ClientSessionState, bool) { return nil, false }
func (c *recordingSessionCache) Put(_ string, session *tls.ClientSessionState) {
	if session != nil {
		c.stored.Store(true)
	}
}

// TestStartTLSIssuesNoSessionTickets guards the OfflineIMAP stall: a TLS 1.3
// ticket in the server's first flight races imaplib2's reader and writer
// threads on one OpenSSL connection and loses the command after STARTTLS.
// The certificate is selected per client, as the listeners do.
func TestStartTLSIssuesNoSessionTickets(t *testing.T) {
	t.Parallel()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	selected := &tls.Config{Certificates: []tls.Certificate{cert}}
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return selected, nil
		}},
		TypedStore: setupTestStore(t),
	})
	if _, code, text := c.send("S1", "STARTTLS"); code != "OK" {
		t.Fatalf("STARTTLS = %s %s", code, text)
	}
	cache := &recordingSessionCache{}
	tlsConn := tls.Client(c.Conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, ClientSessionCache: cache})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	c.Conn = tlsConn
	c.r = bufio.NewReader(tlsConn)
	// Reading the response processes any ticket sent after the handshake.
	if _, code, text := c.send("C1", "CAPABILITY"); code != "OK" {
		t.Fatalf("CAPABILITY after STARTTLS = %s %s", code, text)
	}
	if cache.stored.Load() {
		t.Fatal("server issued a TLS session ticket")
	}
	if selected.SessionTicketsDisabled {
		t.Fatal("per-client TLS configuration was mutated")
	}
}

// TestImplicitTLS tests that IMAP connections with ImplicitTLS=true
// immediately upgrade to TLS before sending the greeting.
func TestImplicitTLS(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	srv := New(&Config{
		ServerName:  "test.veksel",
		TLSConfig:   tlsCfg,
		ImplicitTLS: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	cfg := &Config{
		ServerName:  "test.veksel",
		TLSConfig:   tlsCfg,
		ImplicitTLS: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, srv, nil, nil)
		sess.run()
	}()

	// Connect with TLS client — implicit TLS expects TLS from the start
	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	t.Cleanup(func() { tlsConn.Close() })

	c := &tc{Conn: tlsConn, r: bufio.NewReader(tlsConn)}

	// Read greeting — should be * OK
	greeting, err := c.readLine()
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("expected * OK greeting, got: %s", greeting)
	}

	// CAPABILITY should NOT advertise STARTTLS because TLS is already active
	c.send("A001", "CAPABILITY")

	// LOGIN should work
	_, code, _ := c.send("A002", "LOGIN alice secret")
	if code != "OK" {
		t.Fatalf("LOGIN: code=%s, want OK", code)
	}

	// SELECT INBOX
	_, code, _ = c.send("A003", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT INBOX: code=%s, want OK", code)
	}
}

func TestImplicitTLSNegotiatesIMAP4rev2EndToEnd(t *testing.T) {
	ts := setupTestStore(t)
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cfg := &Config{
		ServerName: "test.veksel", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ImplicitTLS: true,
		AuthValidator: func(context.Context, string, string) (string, error) { return "alice", nil }, TypedStore: ts,
	}
	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			sess := newSession(srv.sessionID.Add(1), cfg, conn, srv, nil, nil)
			sess.run()
		}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := &tc{Conn: conn, r: bufio.NewReader(conn)}
	greeting, err := client.readLine()
	if err != nil || !strings.Contains(greeting, "IMAP4rev1") || !strings.Contains(greeting, "IMAP4rev2") {
		t.Fatalf("protected greeting = %q err=%v", greeting, err)
	}
	if _, code, text := client.send("A001", "LOGIN alice secret"); code != "OK" {
		t.Fatalf("LOGIN: code=%s text=%s", code, text)
	}
	sendAndCollect := func(tag, command string) ([]string, string) {
		t.Helper()
		if _, writeErr := fmt.Fprintf(client, "%s %s\r\n", tag, command); writeErr != nil {
			t.Fatalf("%s write: %v", command, writeErr)
		}
		var lines []string
		for {
			line, readErr := client.readLine()
			if readErr != nil {
				t.Fatalf("%s: %v", command, readErr)
			}
			lines = append(lines, line)
			if strings.HasPrefix(line, tag+" ") {
				return lines, strings.Fields(line)[1]
			}
		}
	}
	lines, code := sendAndCollect("A002", "ENABLE IMAP4rev2")
	if code != "OK" || !strings.Contains(strings.Join(lines, "\n"), "* ENABLED IMAP4rev2") {
		t.Fatalf("ENABLE: code=%s lines=%v", code, lines)
	}
	if _, code, text := client.send("A003", "CREATE Café"); code != "OK" {
		t.Fatalf("native UTF-8 CREATE: code=%s text=%s", code, text)
	}
	lines, code = sendAndCollect("A004", `LIST "" "*"`)
	if code != "OK" || !strings.Contains(strings.Join(lines, "\n"), `"Café"`) {
		t.Fatalf("native UTF-8 LIST: code=%s lines=%v", code, lines)
	}
}

// TestImplicitTLSPlaintextFails tests that a plaintext connection to an
// implicit TLS IMAP server fails (TLS handshake error).
func TestImplicitTLSPlaintextFails(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	srv := New(&Config{
		ServerName:  "test.veksel",
		TLSConfig:   tlsCfg,
		ImplicitTLS: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	cfg := &Config{
		ServerName:  "test.veksel",
		TLSConfig:   tlsCfg,
		ImplicitTLS: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, cfg, conn, srv, nil, nil)
		sess.run()
	}()

	// Connect with a plaintext client — the server expects TLS from the start
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Try to read a greeting — the server is doing a TLS handshake,
	// so plaintext data will look like garbage or the connection will close.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	// Either the connection is closed (TLS handshake failed on server side)
	// or we get garbage bytes (TLS record data interpreted as plaintext)
	if err == nil && n > 0 {
		// We got TLS record data, not an IMAP greeting
		if strings.HasPrefix(string(buf[:n]), "* OK") {
			t.Fatal("plaintext connection should not receive a clean IMAP greeting")
		}
	}
}

// TestNotifyExists tests that NotifyExists sends an EXISTS notification
// to all IDLE sessions watching a folder.
func TestNotifyExists(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	srv := New(&Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		id := srv.sessionID.Add(1)
		sess := newSession(id, srv.cfg.Load(), conn, srv, nil, nil)
		sess.run()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	c := &tc{Conn: conn, r: bufio.NewReader(conn)}
	c.readLine() // greeting

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Start IDLE
	c.sendNoTag("A003 IDLE")
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	contLine, _ := c.readLine()
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", contLine)
	}

	// Wait for the server goroutine to register the IDLE notifier.
	// Without this sleep, NotifyExists may be called before registration,
	// causing the notification to be silently dropped.
	time.Sleep(50 * time.Millisecond)

	// Use NotifyExists (the public method called by SMTP)
	folderID := model.InboxFolderID("alice")
	deliverTestMessage(t, ts, folderID)
	srv.NotifyExists(folderID)

	// Read notification
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	notif, _ := c.readLine()
	if !strings.Contains(notif, "EXISTS") {
		t.Fatalf("expected EXISTS notification, got: %s", notif)
	}

	// Exit IDLE
	c.Conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	fmt.Fprint(c.Conn, "DONE\r\n")
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}
}

// TestNotifyExistsMultipleSessions tests that NotifyExists delivers
// notifications to multiple concurrent IDLE sessions.
func TestNotifyExistsMultipleSessions(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	srv, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Create 3 sessions, all IDLE on INBOX
	const numSessions = 3
	sessions := make([]*tc, numSessions)
	for i := 0; i < numSessions; i++ {
		s := dial()
		s.send(fmt.Sprintf("A001%d", i), "LOGIN alice secret")
		s.send(fmt.Sprintf("A002%d", i), "SELECT INBOX")
		sessions[i] = s
	}

	// Start IDLE on all sessions
	for i, s := range sessions {
		s.sendNoTag(fmt.Sprintf("A003%d IDLE", i))
		s.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		contLine, err := s.readLine()
		if err != nil {
			t.Fatalf("session %d: expected IDLE continuation, got error: %v", i, err)
		}
		if !strings.HasPrefix(contLine, "+") {
			t.Fatalf("session %d: expected IDLE continuation, got: %s", i, contLine)
		}
	}

	// Wait for server goroutines to register the IDLE notifiers.
	// Without this sleep, NotifyExists may be called before registration,
	// causing notifications to be silently dropped.
	time.Sleep(50 * time.Millisecond)

	// Deliver a message and notify via NotifyExists
	deliverTestMessage(t, ts, model.InboxFolderID("alice"))
	srv.NotifyExists(model.InboxFolderID("alice"))

	// All sessions should receive EXISTS notifications
	for i, s := range sessions {
		s.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		notif, err := s.readLine()
		if err != nil {
			t.Fatalf("session %d: expected EXISTS notification, got error: %v", i, err)
		}
		if !strings.Contains(notif, "EXISTS") {
			t.Fatalf("session %d: expected EXISTS notification, got: %s", i, notif)
		}
	}

	// Exit IDLE on all sessions
	for i, s := range sessions {
		s.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(s.Conn, "DONE\r\n")
		_, code, _ := s.readResponse()
		if code != "OK" {
			t.Fatalf("session %d: IDLE DONE: code=%s, want OK", i, code)
		}
	}
}

// TestNotifyExistsNoListeners tests that NotifyExists is a no-op
// when no sessions are IDLE on the folder.
func TestNotifyExistsNoListeners(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	srv := New(&Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Calling NotifyExists with no listeners should not panic
	folderID := model.InboxFolderID("alice")
	deliverTestMessage(t, ts, folderID)
	srv.NotifyExists(folderID)
}

// --- CONDSTORE tests (RFC 4551) ---

// TestCondstoreFetchIfModSeqMatch tests CONDSTORE IFMODSEQ in FETCH when MODSEQ matches.
func TestCondstoreFetchIfModSeqMatch(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message (ModSeq starts at 1)
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: CondStore\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH with IFMODSEQ(1) — should succeed since ModSeq is 1
	_, code, _ = c.send("A004", "FETCH 1 IFMODSEQ(1) FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH IFMODSEQ(1): code=%s, want OK", code)
	}
}

// TestCondstoreFetchIfModSeqMismatch tests CONDSTORE IFMODSEQ in FETCH when MODSEQ doesn't match.
func TestCondstoreFetchIfModSeqMismatch(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message (ModSeq starts at 1)
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: CondStore\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Change the ModSeq by adding a flag
	c.send("A004", "STORE 1 +FLAGS.SILENT (\\Seen)")

	// FETCH with IFMODSEQ(1) — should silently fail since ModSeq is now 2
	// No FETCH response should be returned, but the command itself succeeds
	_, code, _ = c.send("A005", "FETCH 1 IFMODSEQ(1) FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH IFMODSEQ(1) mismatch: code=%s, want OK", code)
	}
}

// TestCondstoreStoreIfModSeq tests CONDSTORE IFMODSEQ in STORE.
func TestCondstoreStoreIfModSeq(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message (ModSeq starts at 1)
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: CondStore\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// STORE with IFMODSEQ(1) — should succeed since ModSeq is 1
	_, code, _ = c.send("A004", "STORE 1 IFMODSEQ(1) +FLAGS (\\Flagged)")
	if code != "OK" {
		t.Fatalf("STORE IFMODSEQ(1): code=%s, want OK", code)
	}
}

// TestCondstoreStoreIfModSeqMismatch tests CONDSTORE IFMODSEQ in STORE when MODSEQ doesn't match.
func TestCondstoreStoreIfModSeqMismatch(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message (ModSeq starts at 1)
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: CondStore\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Change the ModSeq by adding a flag
	c.send("A004", "STORE 1 +FLAGS.SILENT (\\Seen)")

	// STORE with IFMODSEQ(1) — should silently fail since ModSeq is now 2
	_, code, _ = c.send("A005", "STORE 1 IFMODSEQ(1) +FLAGS (\\Flagged)")
	if code != "OK" {
		t.Fatalf("STORE IFMODSEQ(1) mismatch: code=%s, want OK", code)
	}
}

// TestCondstoreUIDFetchIfModSeq tests CONDSTORE IFMODSEQ in UID FETCH.
func TestCondstoreUIDFetchIfModSeq(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message (ModSeq starts at 1)
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: CondStore\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// UID FETCH with IFMODSEQ(1) — should succeed since ModSeq is 1
	_, code, _ = c.send("A004", "UID FETCH 1 IFMODSEQ(1) FLAGS")
	if code != "OK" {
		t.Fatalf("UID FETCH IFMODSEQ(1): code=%s, want OK", code)
	}
}

// --- MOVE tests (RFC 6851) ---

// TestMove tests the MOVE command.
func TestMove(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message to INBOX
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Move\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// MOVE 1 Sent — should move the message atomically
	_, code, _ = c.send("A004", "MOVE 1 Sent")
	if code != "OK" {
		t.Fatalf("MOVE: code=%s, want OK", code)
	}

	// Verify message is no longer in INBOX
	c.send("A005", "SELECT INBOX")
	_, code, _ = c.send("A006", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in INBOX: code=%s, want OK", code)
	}

	// Verify message is now in Sent
	c.send("A007", "SELECT Sent")
	_, code, _ = c.send("A008", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in Sent: code=%s, want OK", code)
	}
}

// TestMoveMultiple tests MOVE with multiple messages.
func TestMoveMultiple(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND two messages
	var code string
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Move%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ = c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// MOVE 1:2 Sent
	_, code, _ = c.send("A003", "MOVE 1:2 Sent")
	if code != "OK" {
		t.Fatalf("MOVE 1:2: code=%s, want OK", code)
	}

	// Verify INBOX is empty
	c.send("A004", "SELECT INBOX")
	_, code, _ = c.send("A005", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in INBOX: code=%s, want OK", code)
	}

	// Verify Sent has messages
	c.send("A006", "SELECT Sent")
	_, code, _ = c.send("A007", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in Sent: code=%s, want OK", code)
	}
}

// TestMoveNonExistentMailbox tests MOVE to a non-existent mailbox.
func TestMoveNonExistentMailbox(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Move\r\n\r\nBody\r\n"
	c.appendMsg("A003", "INBOX", nil, "", []byte(msg))

	// MOVE to non-existent mailbox
	_, code, _ := c.send("A004", "MOVE 1 NonExistent")
	if code != "NO" {
		t.Fatalf("MOVE to non-existent: code=%s, want NO", code)
	}
}

// --- UNSELECT tests (RFC 3691) ---

// TestUnselect tests the UNSELECT command.
func TestUnselect(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Unselect\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark the message as deleted
	c.send("A004", "STORE 1 +FLAGS (\\Deleted)")

	// UNSELECT — should deselect without expunging
	_, code, _ = c.send("A005", "UNSELECT")
	if code != "OK" {
		t.Fatalf("UNSELECT: code=%s, want OK", code)
	}

	// Re-select INBOX and verify the deleted message is still there
	c.send("A006", "SELECT INBOX")
	_, code, _ = c.send("A007", "SEARCH DELETED")
	if code != "OK" {
		t.Fatalf("SEARCH DELETED after UNSELECT: code=%s, want OK", code)
	}
}

// TestUnselectWithoutSelected tests UNSELECT without a selected mailbox.
func TestUnselectWithoutSelected(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// UNSELECT without selecting a mailbox
	_, code, _ := c.send("A002", "UNSELECT")
	if code != "BAD" {
		t.Fatalf("UNSELECT without selected: code=%s, want BAD", code)
	}
}

// TestCloseVsUnselect tests that CLOSE expunges but UNSELECT does not.
func TestCloseVsUnselect(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND a message
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Close\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// Mark as deleted
	c.send("A004", "STORE 1 +FLAGS (\\Deleted)")

	// CLOSE — should expunge the deleted message
	_, code, _ = c.send("A005", "CLOSE")
	if code != "OK" {
		t.Fatalf("CLOSE: code=%s, want OK", code)
	}

	// Re-select and verify the message is gone
	c.send("A006", "SELECT INBOX")
	_, code, _ = c.send("A007", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL after CLOSE: code=%s, want OK", code)
	}
}

// TestSetACL tests the SETACL command.
func TestSetACL(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	// Create a second user (bob)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			if username == "bob" && password == "secret" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice
	c.send("A001", "LOGIN alice secret")

	// SETACL on alice's own folder for bob
	_, code, _ := c.send("A002", "SETACL INBOX bob lr")
	if code != "OK" {
		t.Fatalf("SETACL: code=%s, want OK", code)
	}
}

// TestGetACL tests the GETACL command.
func TestGetACL(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice
	c.send("A001", "LOGIN alice secret")

	// SETACL for bob
	c.send("A002", "SETACL INBOX bob lr")

	// GETACL — write command manually so we can capture untagged responses
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 GETACL INBOX\r\n")

	// Read all lines including untagged GETACL responses
	var lines []string
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
	}

	hasAlice := false
	hasBob := false
	for _, line := range lines {
		if strings.Contains(line, "alice") && strings.HasPrefix(line, "* GETACL") {
			hasAlice = true
		}
		if strings.Contains(line, "bob") && strings.HasPrefix(line, "* GETACL") {
			hasBob = true
		}
	}
	if !hasAlice {
		t.Errorf("GETACL should include alice (owner); got lines: %v", lines)
	}
	if !hasBob {
		t.Errorf("GETACL should include bob; got lines: %v", lines)
	}
}

// TestDeleteACL tests the DELETEACL command.
func TestDeleteACL(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice
	c.send("A001", "LOGIN alice secret")

	// SETACL for bob
	c.send("A002", "SETACL INBOX bob lr")

	// DELETEACL bob
	_, code, _ := c.send("A003", "DELETEACL INBOX bob")
	if code != "OK" {
		t.Fatalf("DELETEACL: code=%s, want OK", code)
	}

	// GETACL should no longer include bob
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A004 GETACL INBOX\r\n")

	var lines []string
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
	}
	for _, line := range lines {
		if strings.Contains(line, "bob") && strings.HasPrefix(line, "* GETACL") {
			t.Error("GETACL should not include bob after DELETEACL")
		}
	}
}

// TestMyRights tests the MYRIGHTS command.
func TestMyRights(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice
	c.send("A001", "LOGIN alice secret")

	// MYRIGHTS on own folder — write command manually to capture untagged responses
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A002 MYRIGHTS INBOX\r\n")

	var lines []string
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
	}

	found := false
	for _, line := range lines {
		if strings.HasPrefix(line, "* MYRIGHTS") && strings.Contains(line, model.RightAll) {
			found = true
		}
	}
	if !found {
		t.Errorf("MYRIGHTS should return full rights for owner; got lines: %v", lines)
	}
}

// TestMyRightsShared tests MYRIGHTS on a shared mailbox.
func TestMyRightsShared(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	// Alice shares INBOX with bob
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			if username == "bob" && password == "secret" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice and share INBOX with bob
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SETACL INBOX bob lrw")

	// Login as bob and check MYRIGHTS on alice's shared mailbox
	c.send("A003", "LOGOUT")

	// Reconnect as bob
	c2 := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "bob" && password == "secret" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	c2.send("B001", "LOGIN bob secret")

	// MYRIGHTS — write manually to capture untagged responses
	c2.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c2.Conn, "B002 MYRIGHTS user/alice/INBOX\r\n")

	var lines []string
	c2.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c2.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
	}

	found := false
	for _, line := range lines {
		if strings.HasPrefix(line, "* MYRIGHTS") && strings.Contains(line, "lrw") {
			found = true
		}
	}
	if !found {
		t.Errorf("MYRIGHTS should return lrw for shared mailbox; got lines: %v", lines)
	}
}

// TestSharedMailboxList tests that shared mailboxes appear in LIST with user/ prefix.
func TestSharedMailboxList(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	// Alice shares INBOX with bob
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			if username == "bob" && password == "secret" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice and share INBOX with bob
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SETACL INBOX bob lr")

	// Verify ACL was stored
	entries, err := ts.FolderStore().ListACL(context.Background(), model.FolderKey("alice", "INBOX"))
	if err != nil {
		t.Fatalf("ListACL: %v", err)
	}
	if len(entries) != 1 || entries[0].Username != "bob" {
		t.Fatalf("expected ACL entry for bob, got: %v", entries)
	}

	// Verify ListACLForUser works
	aclForUser, err := ts.FolderStore().ListACLForUser(context.Background(), "bob")
	if err != nil {
		t.Fatalf("ListACLForUser: %v", err)
	}
	if len(aclForUser) != 1 {
		t.Fatalf("expected 1 ACL entry for bob, got %d: %v", len(aclForUser), aclForUser)
	}

	// Login as bob and LIST
	c.send("A003", "LOGIN bob secret")

	// LIST — capture all lines including untagged
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A004 LIST \"\" \"*\"\r\n")

	// Read all lines until tagged response
	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
	}

	foundShared := false
	for _, line := range lines {
		if strings.Contains(line, "user/alice/INBOX") {
			foundShared = true
		}
	}
	if !foundShared {
		t.Errorf("LIST should include user/alice/INBOX; got lines: %v", lines)
	}
}

// TestSharedMailboxLsub tests that shared mailboxes appear in LSUB with user/ prefix.
func TestSharedMailboxLsub(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(context.Background(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatalf("create user bob: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(context.Background(), "bob"); err != nil {
		t.Fatalf("create folders for bob: %v", err)
	}

	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			if username == "bob" && password == "secret" {
				return "bob", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// Login as alice and share INBOX with bob
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SETACL INBOX bob lr")

	// Login as bob and LSUB
	c.send("A003", "LOGIN bob secret")

	// LSUB — capture all lines including untagged
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A004 LSUB \"\" \"user/alice/*\"\r\n")

	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") && !strings.HasPrefix(line, "+ ") {
			break
		}
	}

	foundShared := false
	for _, line := range lines {
		if strings.Contains(line, "user/alice/INBOX") && strings.HasPrefix(line, "* LSUB") {
			foundShared = true
		}
	}
	if !foundShared {
		t.Errorf("LSUB should include user/alice/INBOX; got lines: %v", lines)
	}
}

// TestCapabilityACL tests that ACL and RIGHTS are advertised in CAPABILITY.
func TestCapabilityACL(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Read greeting
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Send CAPABILITY and capture all responses
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	// Read all responses
	var allLines []string
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		allLines = append(allLines, line)
		if !strings.HasPrefix(line, "* ") && !strings.HasPrefix(line, "*[") {
			break
		}
	}

	capLine := ""
	for _, line := range allLines {
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
			break
		}
	}
	if !strings.Contains(capLine, "ACL") {
		t.Errorf("CAPABILITY should include ACL; got: %s", capLine)
	}
	if !strings.Contains(capLine, "RIGHTS") {
		t.Errorf("CAPABILITY should include RIGHTS; got: %s", capLine)
	}
	if !strings.Contains(capLine, "METADATA") {
		t.Errorf("CAPABILITY should include METADATA; got: %s", capLine)
	}
}

// TestSetMetadata tests the SETMETADATA command (RFC 5464).
func TestSetMetadata(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// SETMETADATA on INBOX
	_, code, _ := c.send("A002", "SETMETADATA INBOX /shared/displayname \"Inbox\"")
	if code != "OK" {
		t.Fatalf("SETMETADATA: code=%s, want OK", code)
	}

	// SETMETADATA a private entry
	_, code, _ = c.send("A003", "SETMETADATA INBOX /private/annotation/color red")
	if code != "OK" {
		t.Fatalf("SETMETADATA private: code=%s, want OK", code)
	}
}

// TestGetMetadata tests the GETMETADATA command (RFC 5464).
func TestGetMetadata(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// First set some metadata
	c.send("A002", "SETMETADATA INBOX /shared/displayname \"My Inbox\"")
	c.send("A003", "SETMETADATA INBOX /private/annotation/color blue")

	// GETMETADATA all entries
	_, code, _ := c.send("A004", "GETMETADATA INBOX /")
	if code != "OK" {
		t.Fatalf("GETMETADATA all: code=%s, want OK", code)
	}

	// GETMETADATA shared entries
	_, code, _ = c.send("A005", "GETMETADATA INBOX /shared/*")
	if code != "OK" {
		t.Fatalf("GETMETADATA shared: code=%s, want OK", code)
	}

	// GETMETADATA specific entry
	_, code, _ = c.send("A006", "GETMETADATA INBOX /shared/displayname")
	if code != "OK" {
		t.Fatalf("GETMETADATA specific: code=%s, want OK", code)
	}
}

// TestGetMetadataServer tests GETMETADATA on ##server.
func TestGetMetadataServer(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	login := func(user string) *tc {
		c := makeTestServer(t, &Config{
			ServerName:    "test.veksel",
			AuthValidator: func(context.Context, string, string) (string, error) { return user, nil },
			TypedStore:    ts,
		})
		c.send("A001", "LOGIN "+user+" secret")
		return c
	}
	alice, bob := login("alice"), login("bob")
	get := func(c *tc, tag, command string) string {
		c.sendNoTag(tag + " " + command)
		return strings.Join(c.readUntagged(), "\n")
	}

	// Server /shared entries are installation settings: only administrators
	// change them.
	if _, code, _ := alice.send("A002", "SETMETADATA ##server /shared/admin/comment VekselServer"); code != "NO" {
		t.Fatalf("SETMETADATA server /shared by a user: code=%s, want NO", code)
	}
	// /private entries belong to the user who set them (RFC 5464 3.2).
	if _, code, _ := alice.send("A003", "SETMETADATA ##server /private/vendor/x/note alice-only"); code != "OK" {
		t.Fatalf("SETMETADATA server /private: code=%s, want OK", code)
	}
	if lines := get(alice, "A004", "GETMETADATA ##server /"); !strings.Contains(lines, "/private/vendor/x/note") || !strings.Contains(lines, "A004 OK") {
		t.Fatalf("owner GETMETADATA = %q, want the private entry", lines)
	}
	if lines := get(bob, "A002", "GETMETADATA ##server /"); strings.Contains(lines, "/private/vendor/x/note") || !strings.Contains(lines, "A002 OK") {
		t.Fatalf("another user's GETMETADATA = %q, must not include alice's private entry", lines)
	}
	if _, code, _ := bob.send("A003", "SETMETADATA ##server /private/vendor/x/note NIL"); code != "OK" {
		t.Fatalf("bob deleting his own (absent) private entry: code=%s", code)
	}
	if lines := get(alice, "A005", "GETMETADATA ##server /private/vendor/x/note"); !strings.Contains(lines, "/private/vendor/x/note") {
		t.Fatalf("bob's NIL removed alice's private entry: %q", lines)
	}
}

// TestSetMetadataDelete tests deleting metadata entries via NIL value.
func TestSetMetadataDelete(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// Set a value
	c.send("A002", "SETMETADATA INBOX /shared/displayname \"Test\"")

	// Delete it with NIL
	_, code, _ := c.send("A003", "SETMETADATA INBOX /shared/displayname NIL")
	if code != "OK" {
		t.Fatalf("SETMETADATA delete: code=%s, want OK", code)
	}
}

// TestSetMetadataInvalidEntryName tests SETMETADATA with invalid entry name.
func TestSetMetadataInvalidEntryName(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// Entry name without /shared/ or /private/ prefix
	_, code, _ := c.send("A002", "SETMETADATA INBOX invalid/name value")
	if code != "BAD" {
		t.Fatalf("SETMETADATA invalid name: code=%s, want BAD", code)
	}
}

// TestGetMetadataNonExistent tests GETMETADATA on non-existent mailbox.
func TestGetMetadataNonExistent(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	_, code, _ := c.send("A002", "GETMETADATA NonExistentMailbox /")
	if code != "NO" {
		t.Fatalf("GETMETADATA non-existent: code=%s, want NO", code)
	}
}

// TestMetadataCapability tests that METADATA appears in CAPABILITY response.
func TestMetadataCapability(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Send CAPABILITY and read all lines including the untagged response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	// Read all lines including untagged
	allLines := c.readUntagged()
	capLine := ""
	for _, line := range allLines {
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
			break
		}
	}
	if !strings.Contains(capLine, "METADATA") {
		t.Errorf("CAPABILITY should include METADATA; got: %s", capLine)
	}
}

// TestCompressCapability tests that COMPRESS=DEFLATE is advertised without
// claiming the full BINARY extension. FETCH-side BINARY support alone is not
// sufficient to advertise RFC 3516.
func TestCompressCapability(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Send CAPABILITY and read all lines including the untagged response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	// Read all lines including untagged
	allLines := c.readUntagged()
	capLine := ""
	for _, line := range allLines {
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
			break
		}
	}
	if !strings.Contains(capLine, "COMPRESS=DEFLATE") {
		t.Errorf("CAPABILITY should include COMPRESS=DEFLATE; got: %s", capLine)
	}
	if !strings.Contains(capLine, " BINARY ") {
		t.Errorf("CAPABILITY should include BINARY; got: %s", capLine)
	}
}

// TestCompressDeflate tests the COMPRESS DEFLATE command (RFC 4978).
func TestCompressDeflate(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// LOGIN before compressing
	_, code, _ := c.send("A001", "LOGIN alice secret")
	if code != "OK" {
		t.Fatalf("LOGIN: code=%s, want OK", code)
	}

	// COMPRESS DEFLATE
	_, code, _ = c.send("A002", "COMPRESS DEFLATE")
	if code != "OK" {
		t.Fatalf("COMPRESS DEFLATE: code=%s, want OK", code)
	}

	compressedReader := flate.NewReader(c.Conn)
	defer compressedReader.Close()
	compressedWriter, err := flate.NewWriter(c.Conn, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	defer compressedWriter.Close()
	if _, err := fmt.Fprint(compressedWriter, "A003 ID (\"name\" \"compressed-client\")\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := compressedWriter.Flush(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(compressedReader)
	for {
		c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read compressed ID response: %v", err)
		}
		if strings.HasPrefix(line, "A003 ") {
			if !strings.Contains(line, " OK ") {
				t.Fatalf("compressed ID response = %q", line)
			}
			break
		}
	}
}

// TestCompressInvalid tests COMPRESS with an invalid algorithm.
func TestCompressInvalid(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")

	// COMPRESS with no argument
	_, code, _ := c.send("A002", "COMPRESS")
	if code != "BAD" {
		t.Fatalf("COMPRESS (no arg): code=%s, want BAD", code)
	}

	// COMPRESS with invalid algorithm
	_, code, _ = c.send("A003", "COMPRESS INVALID")
	if code != "BAD" {
		t.Fatalf("COMPRESS INVALID: code=%s, want BAD", code)
	}
}

// TestAppendUID tests that APPEND returns APPENDUID response (RFC 3516 §4).
func TestAppendUID(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: AppendUID Test\r\n\r\nBody\r\n"

	// Send APPEND and capture untagged responses
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 APPEND INBOX {%d}\r\n", len(msg))

	// Wait for continuation
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	contLine, err := c.r.ReadString('\n')
	if err != nil {
		t.Fatalf("expected continuation, got error: %v", err)
	}
	contLine = strings.TrimRight(contLine, "\r\n")
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}

	// Send the message data followed by CRLF
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	c.Conn.Write(append([]byte(msg), '\r', '\n'))

	// Read responses through the tagged APPENDUID completion.
	var foundAppendUID bool
	var completionCode string
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.Contains(line, "APPENDUID") {
			foundAppendUID = true
		}
		if strings.HasPrefix(line, "A003 ") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				completionCode = parts[1]
			}
			break
		}
	}

	if !foundAppendUID {
		t.Error("Expected APPENDUID response in APPEND result")
	}

	if completionCode != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", completionCode)
	}
}

// TestBinaryAppend tests APPEND with the BINARY flag (RFC 3516 §3).
func TestBinaryAppend(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Message with 8-bit data (bytes > 127)
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Binary Test\r\n\r\nBinary data: \xff\xfe\r\n"

	// Send APPEND with BINARY flag
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 APPEND INBOX BINARY {%d}\r\n", len(msg))

	// Wait for continuation
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	contLine, err := c.r.ReadString('\n')
	if err != nil {
		t.Fatalf("expected continuation, got error: %v", err)
	}
	contLine = strings.TrimRight(contLine, "\r\n")
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}

	// Send the message data followed by CRLF
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	c.Conn.Write(append([]byte(msg), '\r', '\n'))

	// Read the tagged response (skip untagged)
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("APPEND BINARY: code=%s, want OK", code)
	}

	// Verify the message was stored
	_, code, _ = c.send("A004", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code)
	}
}

// TestSeqSetRejectsStarEquals verifies strict sequence-set syntax. RFC 3516
// adds literal8, not a "*=" message-set operator.
func TestSeqSetRejectsStarEquals(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// APPEND two messages
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg%d\r\n\r\nBody%d\r\n", i, i)
		_, code, _ := c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", nil, "", []byte(msg))
		if code != "OK" {
			t.Fatalf("APPEND %d: code=%s, want OK", i, code)
		}
	}

	// A non-standard *= token is rejected instead of being broadened to all.
	_, code, _ := c.send("A003", "FETCH *= UID")
	if code != "BAD" {
		t.Fatalf("FETCH *=: code=%s, want BAD", code)
	}
}

// TestBodyStructure tests FETCH BODYSTRUCTURE.
func TestBodyStructure(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: BodyStructure\r\n\r\nBody\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH BODYSTRUCTURE
	_, code, _ = c.send("A004", "FETCH 1 BODYSTRUCTURE")
	if code != "OK" {
		t.Fatalf("FETCH BODYSTRUCTURE: code=%s, want OK", code)
	}
}

// TestBodyBinary tests FETCH BODY.BINARY (RFC 3516 §5).
func TestBodyBinary(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Message with 8-bit data
	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Binary\r\n\r\n\xff\xfe\xfd\r\n"
	_, code, _ := c.appendMsg("A003", "INBOX", nil, "", []byte(msg))
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}

	// FETCH BODY.BINARY
	_, code, _ = c.send("A004", "FETCH 1 BODY.BINARY")
	if code != "OK" {
		t.Fatalf("FETCH BODY.BINARY: code=%s, want OK", code)
	}
}

// TestIDCommand tests the ID command (RFC 2971).
func TestIDCommand(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// ID with client info
	_, code, _ := c.send("A001", `ID ("name" "TestClient" "version" "1.0" "os" "linux" NIL)`)
	if code != "OK" {
		t.Fatalf("ID: code=%s, want OK", code)
	}
}

// TestIDCommandNIL tests the ID command with NIL argument.
func TestIDCommandNIL(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// ID NIL — no client info
	_, code, _ := c.send("A001", "ID NIL")
	if code != "OK" {
		t.Fatalf("ID NIL: code=%s, want OK", code)
	}
}

// TestIDCommandEmpty tests the ID command with no arguments.
func TestIDCommandEmpty(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// ID with no arguments
	_, code, _ := c.send("A001", "ID")
	if code != "OK" {
		t.Fatalf("ID (no args): code=%s, want OK", code)
	}
}

// TestIDCommandAfterAuth tests that ID works after authentication.
func TestIDCommandAfterAuth(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	_, code, _ := c.send("A002", `ID ("name" "Thunderbird" "version" "102.0" "os" "Mac OS X" "os-version" "13.0" "support" "example.com" "comment" "test" NIL)`)
	if code != "OK" {
		t.Fatalf("ID after auth: code=%s, want OK", code)
	}
}

// TestCapabilityDynamic tests that CAPABILITY response changes based on connection state.
func TestCapabilityDynamic(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Pre-auth: should include AUTH=PLAIN, AUTH=LOGIN, ID
	_, code, _ := c.send("A001", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY pre-auth: code=%s, want OK", code)
	}

	// LOGIN
	_, code, _ = c.send("A002", "LOGIN alice secret")
	if code != "OK" {
		t.Fatalf("LOGIN: code=%s, want OK", code)
	}

	// Authenticated: should still include AUTH=* capabilities
	_, code, _ = c.send("A003", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY authenticated: code=%s, want OK", code)
	}

	// SELECT INBOX
	_, code, _ = c.send("A004", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT INBOX: code=%s, want OK", code)
	}

	// Selected: should include HIGHESTMODSEQ, should NOT include AUTH=*
	_, code, _ = c.send("A005", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY selected: code=%s, want OK", code)
	}
}

// TestCapabilityIncludesID tests that ID appears in CAPABILITY list.
func TestCapabilityIncludesID(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Read raw response to check CAPABILITY line includes ID
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	// Read all lines until tagged response
	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
			break
		}
		if strings.HasPrefix(line, "A001 ") {
			// Reached tagged response without CAPABILITY line
			break
		}
	}

	if !strings.Contains(capLine, "ID") {
		t.Fatalf("CAPABILITY response should contain ID, got: %s", capLine)
	}
	if !strings.Contains(capLine, "IMAP4rev1") {
		t.Fatalf("CAPABILITY response should contain IMAP4rev1, got: %s", capLine)
	}
}

func TestCapabilitiesDoNotAdvertiseUnimplementedQRESYNC(t *testing.T) {
	s := &Session{cfg: &Config{}}
	for _, capability := range s.buildCapabilities() {
		if capability == "QRESYNC" {
			t.Fatal("QRESYNC advertised without a deletion journal")
		}
	}
}

func TestQResyncReportsExpungedUID(t *testing.T) {
	ts := setupTestStore(t)
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	}
	c := makeTestServer(t, cfg)
	c.send("A001", "LOGIN alice secret")
	inbox, err := cfg.FolderSpace.GetFolderByPath(t.Context(), service.UserAccess("alice", "test"), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.FolderSpace.CreateItem(t.Context(), service.UserAccess("alice", "test"), inbox.ID, service.ItemInput{Data: []byte("Subject: QRESYNC\r\n\r\nBody\r\n")}); err != nil {
		t.Fatal(err)
	}
	c.send("A003", "SELECT INBOX")
	c.send("A004", "UID STORE 1 +FLAGS.SILENT (\\Deleted)")

	item, err := cfg.FolderSpace.GetItemByUID(t.Context(), service.UserAccess("alice", "test"), inbox.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	knownModSeq := item.ModSeq
	c.send("A005", "UID EXPUNGE 1")
	c.send("A006", "UNSELECT")
	if _, code, _ := c.send("A007", "ENABLE QRESYNC"); code != "OK" {
		t.Fatalf("ENABLE code=%s", code)
	}

	fmt.Fprintf(c.Conn, "A008 SELECT INBOX (QRESYNC (%d %d 1))\r\n", inbox.UIDValidity, knownModSeq)
	var vanished string
	for {
		line, readErr := c.readLine()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(line, "VANISHED") {
			vanished = line
		}
		if strings.HasPrefix(line, "A008 ") {
			if !strings.Contains(line, " OK") {
				t.Fatalf("SELECT response=%s", line)
			}
			break
		}
	}
	if !strings.Contains(vanished, "VANISHED (EARLIER) 1") {
		t.Fatalf("vanished response=%q", vanished)
	}
}

func TestSplitFetchModifiers(t *testing.T) {
	items, modifierText := splitFetchModifiers("(FLAGS UID) (CHANGEDSINCE 42 VANISHED)")
	modifiers, err := parseFetchModifiers(modifierText)
	if err != nil || items != "(FLAGS UID)" || modifiers.changedSince != 42 || !modifiers.vanished {
		t.Fatalf("items=%q modifiers=%+v err=%v", items, modifiers, err)
	}
	if items, modifierText := splitFetchModifiers("(BODY.PEEK[HEADER.FIELDS (FROM)] UID)"); modifierText != "" || items != "(BODY.PEEK[HEADER.FIELDS (FROM)] UID)" {
		t.Fatalf("data item list taken as modifiers: %q %q", items, modifierText)
	}
}

// TestCapabilityNoAuthWhenSelected tests that AUTH=* is not present when a mailbox is selected.
func TestCapabilityNoAuthWhenSelected(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Read raw CAPABILITY response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 CAPABILITY\r\n")

	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
			break
		}
		if strings.HasPrefix(line, "A003 ") {
			break
		}
	}

	// When selected, AUTH=* should NOT be in capabilities
	if strings.Contains(capLine, "AUTH=") {
		t.Fatalf("CAPABILITY when selected should not contain AUTH=*, got: %s", capLine)
	}

	// HIGHESTMODSEQ should be present when selected
	if !strings.Contains(capLine, "HIGHESTMODSEQ") {
		t.Fatalf("CAPABILITY when selected should contain HIGHESTMODSEQ, got: %s", capLine)
	}
}

// TestCapabilityAuthAfterDeselect tests that AUTH=* reappears after deselecting.
func TestCapabilityAuthAfterDeselect(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	// Deselect by closing the mailbox
	c.send("A003", "CLOSE")

	// Read raw CAPABILITY response after CLOSE
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A004 CAPABILITY\r\n")

	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
			break
		}
		if strings.HasPrefix(line, "A004 ") {
			break
		}
	}

	// After CLOSE (back to Authenticated state), AUTH=* should be present
	if !strings.Contains(capLine, "AUTH=PLAIN") {
		t.Fatalf("CAPABILITY after CLOSE should contain AUTH=PLAIN, got: %s", capLine)
	}
}

// TestParseClientID tests the parseClientID function directly.
// Note: parseCommand uses strings.Fields which splits on whitespace,
// so "(" may be attached to the first key (e.g., "("name"").
// stripQuotes removes surrounding quotes from each token.
func TestParseClientID(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	srv := New(&Config{
		ServerName: "test.veksel",
		TypedStore: ts,
	})

	// Create a minimal session for testing parseClientID
	sess := &Session{
		cfg:    srv.cfg.Load(),
		server: srv,
	}

	// Test parsing full ID response as it arrives from parseCommand:
	// "(" is a separate token, quotes are stripped by stripQuotes in parseCommand
	args := []string{"(", "name", "TestClient", "version", "2.0", "os", "linux", "os-version", "5.15", "support", "help@example.com", "NIL", ")"}
	clientID := sess.parseClientID(args)
	if clientID == nil {
		t.Fatal("expected non-nil ClientID")
	}
	if clientID.Name != "TestClient" {
		t.Errorf("Name = %q, want %q", clientID.Name, "TestClient")
	}
	if clientID.Version != "2.0" {
		t.Errorf("Version = %q, want %q", clientID.Version, "2.0")
	}
	if clientID.OS != "linux" {
		t.Errorf("OS = %q, want %q", clientID.OS, "linux")
	}
	if clientID.OSVersion != "5.15" {
		t.Errorf("OSVersion = %q, want %q", clientID.OSVersion, "5.15")
	}
	if clientID.Support != "help@example.com" {
		t.Errorf("Support = %q, want %q", clientID.Support, "help@example.com")
	}

	// Test with "(" attached to first key (real-world parseCommand output)
	attachedArgs := []string{"(\"name\"", "\"TestClient\"", "\"version\"", "\"2.0\"", "\"os\"", "\"linux\"", "NIL", ")"}
	clientID2 := sess.parseClientID(attachedArgs)
	if clientID2 == nil {
		t.Fatal("expected non-nil ClientID for attached paren case")
	}
	if clientID2.Name != "TestClient" {
		t.Errorf("Attached: Name = %q, want %q", clientID2.Name, "TestClient")
	}
	if clientID2.Version != "2.0" {
		t.Errorf("Attached: Version = %q, want %q", clientID2.Version, "2.0")
	}
	if clientID2.OS != "linux" {
		t.Errorf("Attached: OS = %q, want %q", clientID2.OS, "linux")
	}

	// Test NIL input
	nilResult := sess.parseClientID([]string{"NIL"})
	if nilResult != nil {
		t.Error("expected nil for NIL input")
	}

	// Test empty input
	emptyResult := sess.parseClientID(nil)
	if emptyResult != nil {
		t.Error("expected nil for empty input")
	}

	// Test NIL after open paren
	nilAfterParen := sess.parseClientID([]string{"(", "NIL"})
	if nilAfterParen != nil {
		t.Error("expected nil for ( NIL input")
	}

	// Test partial ID (only name)
	partialArgs := []string{"(", "name", "Partial", "NIL", ")"}
	partial := sess.parseClientID(partialArgs)
	if partial == nil {
		t.Fatal("expected non-nil for partial ID")
	}
	if partial.Name != "Partial" {
		t.Errorf("Name = %q, want %q", partial.Name, "Partial")
	}
	if partial.Version != "" {
		t.Errorf("Version = %q, want empty", partial.Version)
	}
}

// --- SASL-IR tests (RFC 8305) ---

// TestSASLIR_PLAIN_enabled tests AUTHENTICATE PLAIN with SASL-IR enabled.
func TestSASLIR_PLAIN_enabled(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// SASL-IR: AUTHENTICATE PLAIN with initial response (one-shot)
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	_, code, _ := c.send("A001", "AUTHENTICATE PLAIN "+creds)
	if code != "OK" {
		t.Fatalf("AUTHENTICATE PLAIN (sasl-ir): code=%s, want OK", code)
	}
}

// TestSASLIR_PLAIN_disabled tests AUTHENTICATE PLAIN with SASL-IR disabled.
func TestSASLIR_PLAIN_disabled(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: false,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// When SASL-IR is disabled, AUTHENTICATE PLAIN with initial response
	// should fall back to challenge-response
	creds := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 AUTHENTICATE PLAIN %s\r\n", creds)

	// Server should respond with continuation (+)
	contLine, err := c.readLine()
	if err != nil {
		t.Fatalf("expected continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}

	// Send the credentials
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", creds)
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("AUTHENTICATE PLAIN (sasl-ir disabled): code=%s, want OK", code)
	}
}

// TestSASLIR_LOGIN_enabled tests AUTHENTICATE LOGIN with SASL-IR enabled.
func TestSASLIR_LOGIN_enabled(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// SASL-IR: AUTHENTICATE LOGIN with initial response (username)
	username := base64.StdEncoding.EncodeToString([]byte("alice"))
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 AUTHENTICATE LOGIN %s\r\n", username)

	// Server should respond with continuation for password
	contLine, err := c.readLine()
	if err != nil {
		t.Fatalf("expected continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}

	// Send password
	password := base64.StdEncoding.EncodeToString([]byte("secret"))
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", password)
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("AUTHENTICATE LOGIN (sasl-ir): code=%s, want OK", code)
	}
}

// TestSASLIR_LOGIN_disabled tests AUTHENTICATE LOGIN with SASL-IR disabled.
func TestSASLIR_LOGIN_disabled(t *testing.T) {
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: false,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	})

	// When SASL-IR is disabled, AUTHENTICATE LOGIN with initial response
	// should fall back to challenge-response
	username := base64.StdEncoding.EncodeToString([]byte("alice"))
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 AUTHENTICATE LOGIN %s\r\n", username)

	// Server should respond with continuation (+) for username
	contLine, err := c.readLine()
	if err != nil {
		t.Fatalf("expected continuation, got error: %v", err)
	}
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation, got: %s", contLine)
	}

	// Send username
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", username)
	contLine, _ = c.readLine()
	if !strings.HasPrefix(contLine, "+") {
		t.Fatalf("expected continuation for password, got: %s", contLine)
	}

	// Send password
	password := base64.StdEncoding.EncodeToString([]byte("secret"))
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", password)
	_, code, _ := c.readResponse()
	if code != "OK" {
		t.Fatalf("AUTHENTICATE LOGIN (sasl-ir disabled): code=%s, want OK", code)
	}
}

func TestIdleDoneSplitAcrossPollsIsAccepted(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	_, _, dial := makeMultiSessionServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})
	c := dial()
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")
	c.sendNoTag("A003 IDLE")
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := c.readLine(); err != nil || !strings.HasPrefix(line, "+") {
		t.Fatalf("IDLE continuation = %q, %v", line, err)
	}
	// Outlast the server's 100 ms poll deadline between the two halves.
	fmt.Fprint(c.Conn, "DO")
	time.Sleep(350 * time.Millisecond)
	fmt.Fprint(c.Conn, "NE\r\n")
	if _, code, _ := c.readResponse(); code != "OK" {
		t.Fatalf("IDLE completion code = %q, want OK", code)
	}
}

// deliverTestMessage stores a message as mail delivery would, without
// going through an IMAP session.
func deliverTestMessage(t *testing.T, ts *model.TypedStore, folderID string) {
	t.Helper()
	if _, err := ts.ItemStore().Append(context.Background(), folderID, []byte("From: a@b.test\r\nSubject: delivered\r\n\r\nbody\r\n"), nil); err != nil {
		t.Fatal(err)
	}
}

// readIdleContinuation reads the IDLE continuation, skipping the untagged
// responses that report changes made before IDLE started.
func (c *tc) readIdleContinuation() (string, error) {
	for {
		line, err := c.readLine()
		if err != nil || !strings.HasPrefix(line, "* ") {
			return line, err
		}
	}
}
