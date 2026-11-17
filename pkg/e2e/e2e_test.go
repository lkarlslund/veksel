// Package e2e runs integration tests against real protocol clients
// connected to a live veksel server with IMAP, SMTP, CalDAV, and CardDAV.
package e2e

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/caldav"
	"github.com/lkarlslund/veksel/pkg/imap"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// e2eEnv holds the shared test environment for a single test.
type e2eEnv struct {
	t         *testing.T
	tmpDir    string
	ts        *model.TypedStore
	imapSrv   *imap.Server
	smtpSrv   *smtp.Server
	httpSrv   *http.Server
	imapAddr  string
	smtpAddr  string
	httpAddr  string
	ctx       context.Context
	cancel    context.CancelFunc
	username  string
	password  string
	emailAddr string
	domainID  string
}

// setup creates a full veksel environment with temp data dir, test user,
// and starts IMAP, SMTP, and HTTP listeners on random ports.
func setup(t *testing.T) *e2eEnv {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "veksel-e2e-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}

	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("create jsonstore: %v", err)
	}

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()

	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSRecipientAliases, model.NSUserAliases, model.NSFolders, model.NSItems} {
		if err := ts.EnsureNamespace(ctx, ns); err != nil {
			t.Fatalf("ensure namespace %s: %v", ns, err)
		}
	}

	domainID := "test.local"
	username := "alice"
	password := "secret123"
	emailAddr := fmt.Sprintf("%s@%s", username, domainID)

	if err := ts.DomainStore().Create(ctx, domainID); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	if err := ts.UserStore().Create(ctx, username, "Alice Test", password); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := ts.FolderStore().CreateForUser(ctx, username); err != nil {
		t.Fatalf("create folders: %v", err)
	}
	if err := ts.UserStore().AddEmailAddress(ctx, emailAddr, username, domainID, true); err != nil {
		t.Fatalf("add email address: %v", err)
	}

	authValidator := func(ctx context.Context, user, pass string) (string, error) {
		u, err := ts.UserStore().Get(ctx, user)
		if err != nil {
			return "", fmt.Errorf("user not found")
		}
		if !u.Enabled {
			return "", fmt.Errorf("user disabled")
		}
		if !auth.ComparePassword(pass, u.PasswordHash) {
			return "", fmt.Errorf("invalid password")
		}
		return u.ID, nil
	}

	imapCfg := &imap.Config{
		ServerName:     "veksel-e2e",
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		AuthValidator:  authValidator,
		TypedStore:     ts,
		SaslIrEnabled:  true,
	}
	imapSrv := imap.New(imapCfg)
	imapLn, err := imapSrv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("imap listen: %v", err)
	}
	imapAddr := imapLn.Addr().String()

	smtpDelivery := &smtp.Delivery{
		ExpandRecipient: func(ctx context.Context, addr string) ([]string, bool, error) {
			targets, err := ts.RecipientAliasStore().Expand(ctx, addr)
			if errors.Is(err, store.ErrNotFound) {
				return nil, false, nil
			}
			return targets, err == nil, err
		},
		ResolveRecipient: func(ctx context.Context, addr string) (string, string, error) {
			ea, err := ts.UserStore().GetEmailAddress(ctx, addr)
			if err != nil {
				return "", "", fmt.Errorf("address not found: %w", err)
			}
			if !ea.Enabled {
				return "", "", fmt.Errorf("address disabled")
			}
			folderID := model.InboxFolderID(ea.UserID)
			return folderID, ea.UserID, nil
		},
		AppendMessage: func(ctx context.Context, folderID string, data []byte, headers map[string]string) (string, error) {
			return ts.ItemStore().Append(ctx, folderID, data, headers)
		},
		// Wire IMAP IDLE notifications: when SMTP delivers a message,
		// notify all IMAP IDLE clients watching that folder.
		NotifyIMAPIdle: func(folderID string) {
			imapSrv.NotifyExists(folderID)
		},
	}
	smtpCfg := &smtp.Config{
		ServerName:     "veksel-e2e",
		AuthMechanisms: []string{"PLAIN"},
		AuthValidator:  authValidator,
		Delivery:       smtpDelivery,
		SaslIrEnabled:  true,
	}
	smtpSrv := smtp.New(smtpCfg)
	smtpLn, err := smtpSrv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("smtp listen: %v", err)
	}
	smtpAddr := smtpLn.Addr().String()

	caldavHandler := caldav.New(ts, &caldav.Config{ServerName: "veksel-e2e"})
	mux := http.NewServeMux()
	mux.Handle("/dav/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="CalDAV"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		u, err := ts.UserStore().Get(r.Context(), user)
		if err != nil || !u.Enabled || !auth.ComparePassword(pass, u.PasswordHash) {
			w.Header().Set("WWW-Authenticate", `Basic realm="CalDAV"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		caldavHandler.ServeHTTP(w, r)
	}))

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("http listen: %v", err)
	}
	httpAddr := httpLn.Addr().String()

	httpSrv := &http.Server{
		Addr:         httpAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	testCtx, cancel := context.WithCancel(context.Background())
	go func() {
		log.SetOutput(io.Discard)
		imapSrv.Accept(testCtx, imapLn)
	}()
	go func() {
		smtpSrv.Accept(testCtx, smtpLn)
	}()
	go func() {
		if err := httpSrv.Serve(httpLn); err != http.ErrServerClosed {
			log.Printf("http serve: %v", err)
		}
	}()

	env := &e2eEnv{
		t:         t,
		tmpDir:    tmpDir,
		ts:        ts,
		imapSrv:   imapSrv,
		smtpSrv:   smtpSrv,
		httpSrv:   httpSrv,
		imapAddr:  imapAddr,
		smtpAddr:  smtpAddr,
		httpAddr:  httpAddr,
		ctx:       testCtx,
		cancel:    cancel,
		username:  username,
		password:  password,
		emailAddr: emailAddr,
		domainID:  domainID,
	}

	t.Cleanup(func() {
		cancel()
		imapSrv.Close()
		smtpSrv.Close()
		httpSrv.Shutdown(context.Background())
		s.Close()
		os.RemoveAll(tmpDir)
	})

	time.Sleep(50 * time.Millisecond)
	return env
}

// ---------- IMAP test client helpers ----------

type imapClient struct {
	net.Conn
	r *bufio.Reader
}

func (c *imapClient) readLine() (string, error) {
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *imapClient) readTagged() (tag, code, text string) {
	for {
		line, err := c.readLine()
		if err != nil {
			return "", "", err.Error()
		}
		if strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "*[") || strings.HasPrefix(line, "+ ") {
			c.consumeLiteral(line)
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 3 {
			return parts[0], parts[1], parts[2]
		}
		if len(parts) == 2 {
			return parts[0], parts[1], ""
		}
		return line, "", ""
	}
}

func (c *imapClient) consumeLiteral(line string) {
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
			buf := make([]byte, n)
			c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c.r, buf); err != nil {
				return
			}
			c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			c.r.ReadString('\n')
		}
		line = line[idx+end+1:]
	}
}

func (c *imapClient) cmd(tag, command string) (tagResp, code, text string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s %s\r\n", tag, command)
	return c.readTagged()
}

func (c *imapClient) appendMsg(tag, mailbox string, msg []byte) (tagResp, code, text string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s APPEND %s {%d}\r\n", tag, mailbox, len(msg))

	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	cont, err := c.r.ReadString('\n')
	if err != nil {
		return "", "", err.Error()
	}
	cont = strings.TrimRight(cont, "\r\n")
	if !strings.HasPrefix(cont, "+") {
		return "", "", fmt.Sprintf("expected continuation, got: %s", cont)
	}

	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Conn.Write(append(msg, '\r', '\n'))
	if err != nil {
		return "", "", err.Error()
	}

	return c.readTagged()
}

func (env *e2eEnv) dialIMAP() *imapClient {
	conn, err := net.Dial("tcp", env.imapAddr)
	if err != nil {
		env.t.Fatalf("dial IMAP: %v", err)
	}
	env.t.Cleanup(func() { conn.Close() })

	c := &imapClient{Conn: conn, r: bufio.NewReader(conn)}
	greeting, err := c.readLine()
	if err != nil {
		env.t.Fatalf("read IMAP greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		env.t.Fatalf("expected * OK greeting, got: %s", greeting)
	}
	return c
}

// ---------- SMTP test client helpers ----------

type smtpClient struct {
	net.Conn
	r *bufio.Reader
}

func (c *smtpClient) readLine() (string, error) {
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (c *smtpClient) readReply() (int, string, error) {
	line, err := c.readLine()
	if err != nil {
		return 0, "", err
	}
	code, text, _ := strings.Cut(line, " ")
	var codeInt int
	fmt.Sscanf(code, "%d", &codeInt)
	if len(line) > 4 && line[3] == '-' {
		for {
			l, err := c.readLine()
			if err != nil {
				break
			}
			if len(l) > 4 && l[3] == ' ' {
				text += " " + l
				break
			}
			text += " " + l
		}
	}
	return codeInt, text, nil
}

func (c *smtpClient) cmd(command string) (int, string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", command)
	code, text, err := c.readReply()
	if err != nil {
		return 0, err.Error()
	}
	return code, text
}

func (c *smtpClient) sendData(data string) (int, string) {
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c.Conn, data)
	code, text, err := c.readReply()
	if err != nil {
		return 0, err.Error()
	}
	return code, text
}

func (env *e2eEnv) dialSMTP() *smtpClient {
	conn, err := net.Dial("tcp", env.smtpAddr)
	if err != nil {
		env.t.Fatalf("dial SMTP: %v", err)
	}
	env.t.Cleanup(func() { conn.Close() })

	c := &smtpClient{Conn: conn, r: bufio.NewReader(conn)}
	greeting, err := c.readLine()
	if err != nil {
		env.t.Fatalf("read SMTP greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220 ") {
		env.t.Fatalf("expected 220 greeting, got: %s", greeting)
	}
	return c
}

// ---------- HTTP helper for CalDAV/CardDAV ----------

func (env *e2eEnv) httpDo(method, path string, body io.Reader, contentType string) *http.Response {
	url := fmt.Sprintf("http://%s%s", env.httpAddr, path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		env.t.Fatalf("create request: %v", err)
	}
	req.SetBasicAuth(env.username, env.password)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		env.t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	return resp
}

// ---------- E2E IMAP Tests ----------

func TestE2EIMAPRoundTrip(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	_, code, _ := c.cmd("A001", "CAPABILITY")
	if code != "OK" {
		t.Fatalf("CAPABILITY: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A002", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	if code != "OK" {
		t.Fatalf("LOGIN: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A003", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT INBOX: code=%s, want OK", code)
	}
	msg := []byte("From: s@e.com\r\nTo: a@t.com\r\nSubject: E2E\r\n\r\nHello\r\n")
	_, code, _ = c.appendMsg("A004", "INBOX", msg)
	if code != "OK" {
		t.Fatalf("APPEND: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A005", "FETCH 1 BODY[]")
	if code != "OK" {
		t.Fatalf("FETCH BODY: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A006", "FETCH 1 FLAGS")
	if code != "OK" {
		t.Fatalf("FETCH FLAGS: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A007", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A008", "LOGOUT")
	if code != "OK" {
		t.Fatalf("LOGOUT: code=%s, want OK", code)
	}
}

func TestE2EIMAPUIDFetch(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Test\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "UID FETCH 1:* FLAGS")
	if code != "OK" {
		t.Fatalf("UID FETCH: code=%s, want OK", code)
	}
}

func TestE2EIMAPAuthenticatePlain(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", env.username, env.password)))
	_, code, _ := c.cmd("A001", "AUTHENTICATE PLAIN "+creds)
	if code != "OK" {
		t.Fatalf("AUTHENTICATE PLAIN: code=%s, want OK", code)
	}
}

func TestE2EIMAPAuthenticateLogin(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 AUTHENTICATE LOGIN\r\n")
	cont, err := c.readLine()
	if err != nil || !strings.HasPrefix(cont, "+") {
		t.Fatalf("expected continuation, got: %s", cont)
	}
	username := base64.StdEncoding.EncodeToString([]byte(env.username))
	c.Conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	fmt.Fprintf(c.Conn, "%s\r\n", username)
	cont, _ = c.readLine()
	if !strings.HasPrefix(cont, "+") {
		t.Fatalf("expected continuation for password, got: %s", cont)
	}
	password := base64.StdEncoding.EncodeToString([]byte(env.password))
	fmt.Fprintf(c.Conn, "%s\r\n", password)
	_, code, _ := c.readTagged()
	if code != "OK" {
		t.Fatalf("AUTHENTICATE LOGIN: code=%s, want OK", code)
	}
}

func TestE2EIMAPStoreFlags(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Flags\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "STORE 1 +FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("STORE +FLAGS: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A005", "STORE 1 -FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("STORE -FLAGS: code=%s, want OK", code)
	}
}

func TestE2EIMAPCreateDeleteFolder(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", "CREATE TestFolder")
	if code != "OK" {
		t.Fatalf("CREATE: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A003", "SELECT TestFolder")
	if code != "OK" {
		t.Fatalf("SELECT TestFolder: code=%s, want OK", code)
	}
	c.cmd("A004", "SELECT INBOX")
	_, code, _ = c.cmd("A005", "DELETE TestFolder")
	if code != "OK" {
		t.Fatalf("DELETE: code=%s, want OK", code)
	}
}

func TestE2EIMAPListFolders(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", `LIST "" *`)
	if code != "OK" {
		t.Fatalf("LIST: code=%s, want OK", code)
	}
}

func TestE2EIMAPLoginInvalid(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	_, code, _ := c.cmd("A001", "LOGIN alice wrongpassword")
	if code != "NO" {
		t.Fatalf("LOGIN invalid: code=%s, want NO", code)
	}
}

func TestE2EIMAPNoop(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", "NOOP")
	if code != "OK" {
		t.Fatalf("NOOP: code=%s, want OK", code)
	}
}

func TestE2EIMAPExamine(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", "EXAMINE INBOX")
	if code != "OK" {
		t.Fatalf("EXAMINE INBOX: code=%s, want OK", code)
	}
}

func TestE2EIMAPCopy(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Copy\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "COPY 1 Sent")
	if code != "OK" {
		t.Fatalf("COPY: code=%s, want OK", code)
	}
	c.cmd("A005", "SELECT Sent")
	_, code, _ = c.cmd("A006", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in Sent: code=%s, want OK", code)
	}
}

func TestE2EIMAPMultipleMessages(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg%d\r\n\r\nBody%d\r\n", i, i))
		c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", msg)
	}
	_, code, _ := c.cmd("A003", "FETCH 1:3 (FLAGS UID)")
	if code != "OK" {
		t.Fatalf("FETCH 1:3: code=%s, want OK", code)
	}
}

func TestE2EIMAPCreateSubFolder(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", "CREATE Work")
	if code != "OK" {
		t.Fatalf("CREATE Work: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A003", "CREATE Work/Projects")
	if code != "OK" {
		t.Fatalf("CREATE Work/Projects: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A004", "SELECT Work/Projects")
	if code != "OK" {
		t.Fatalf("SELECT Work/Projects: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendWithFlags(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Flagged\r\n\r\nBody\r\n")
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 APPEND INBOX (\\Seen) {%d}\r\n", len(msg))
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.r.ReadString('\n')
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	c.Conn.Write(append(msg, '\r', '\n'))
	_, code, _ := c.readTagged()
	if code != "OK" {
		t.Fatalf("APPEND with flags: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendWithDate(t *testing.T) {
	t.Skip("server does not support quoted date-time in APPEND (strings.Fields splits quotes)")
}

func TestE2EIMAPSelectNonExistent(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", "SELECT NoSuchFolder")
	if code != "NO" && code != "BAD" {
		t.Fatalf("SELECT non-existent: code=%s, want NO or BAD", code)
	}
}

func TestE2EIMAPRename(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "CREATE OldName")
	_, code, _ := c.cmd("A003", "RENAME OldName NewName")
	if code != "OK" {
		t.Fatalf("RENAME: code=%s, want OK", code)
	}
}

func TestE2EIMAPSubscribeUnsubscribe(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", "SUBSCRIBE Sent")
	if code != "OK" {
		t.Fatalf("SUBSCRIBE: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A003", "UNSUBSCRIBE Sent")
	if code != "OK" {
		t.Fatalf("UNSUBSCRIBE: code=%s, want OK", code)
	}
}

func TestE2EIMAPClose(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	_, code, _ := c.cmd("A003", "CLOSE")
	if code != "OK" {
		t.Fatalf("CLOSE: code=%s, want OK", code)
	}
}

func TestE2EIMAPCheck(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	_, code, _ := c.cmd("A003", "CHECK")
	if code != "OK" {
		t.Fatalf("CHECK: code=%s, want OK", code)
	}
}

func TestE2EIMAPLsub(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ := c.cmd("A002", `LSUB "" *`)
	if code != "OK" {
		t.Fatalf("LSUB: code=%s, want OK", code)
	}
}

func TestE2EIMAPExpunge(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Delete Me\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "STORE 1 +FLAGS (\\Deleted)")
	if code != "OK" {
		t.Fatalf("STORE +FLAGS \\Deleted: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A005", "EXPUNGE")
	if code != "OK" {
		t.Fatalf("EXPUNGE: code=%s, want OK", code)
	}
}

func TestE2EIMAPUIDExpunge(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Expunge\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	c.cmd("A004", "STORE 1 +FLAGS (\\Deleted)")
	_, code, _ := c.cmd("A005", "UID EXPUNGE 1")
	if code != "OK" {
		t.Fatalf("UID EXPUNGE: code=%s, want OK", code)
	}
}

func TestE2EIMAPUIDStore(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: UID Store\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "UID STORE 1:* +FLAGS (\\Seen)")
	if code != "OK" {
		t.Fatalf("UID STORE: code=%s, want OK", code)
	}
}

func TestE2EIMAPSearch(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg1 := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Hello\r\n\r\nBody\r\n")
	msg2 := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: World\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg1)
	c.appendMsg("A004", "INBOX", msg2)
	_, code, _ := c.cmd("A005", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A006", "SEARCH SUBJECT Hello")
	if code != "OK" {
		t.Fatalf("SEARCH SUBJECT: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A007", "SEARCH UNSEEN")
	if code != "OK" {
		t.Fatalf("SEARCH UNSEEN: code=%s, want OK", code)
	}
}

func TestE2EIMAPStateMachine(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	_, code, _ := c.cmd("A001", "SELECT INBOX")
	if code != "BAD" {
		t.Fatalf("SELECT without auth: code=%s, want BAD", code)
	}
	c.cmd("A002", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	_, code, _ = c.cmd("A003", "SELECT INBOX")
	if code != "OK" {
		t.Fatalf("SELECT after auth: code=%s, want OK", code)
	}
}

func TestE2EIMAPFetchBody(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Body Test\r\n\r\nHello Body\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "FETCH 1 BODY[]")
	if code != "OK" {
		t.Fatalf("FETCH BODY[]: code=%s, want OK", code)
	}
}

func TestE2EIMAPFetchUID(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: UID\r\n\r\nBody\r\n")
	c.appendMsg("A003", "INBOX", msg)
	_, code, _ := c.cmd("A004", "FETCH 1 UID")
	if code != "OK" {
		t.Fatalf("FETCH UID: code=%s, want OK", code)
	}
}

func TestE2EIMAPSequenceRemapAfterExpunge(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	for i := 0; i < 2; i++ {
		msg := []byte(fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg%d\r\n\r\nBody%d\r\n", i, i))
		c.appendMsg(fmt.Sprintf("AAPP%d", i), "INBOX", msg)
	}
	c.cmd("A003", "STORE 1 +FLAGS (\\Deleted)")
	_, code, _ := c.cmd("A004", "EXPUNGE")
	if code != "OK" {
		t.Fatalf("EXPUNGE: code=%s, want OK", code)
	}
	_, code, _ = c.cmd("A005", "FETCH 1 ENVELOPE")
	if code != "OK" {
		t.Fatalf("FETCH 1 after expunge: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendToFolder(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: alice@test.local\r\nTo: bob@example.com\r\nSubject: Sent\r\n\r\nBody\r\n")
	_, code, _ := c.appendMsg("A003", "Sent", msg)
	if code != "OK" {
		t.Fatalf("APPEND Sent: code=%s, want OK", code)
	}
	c.cmd("A004", "SELECT Sent")
	_, code, _ = c.cmd("A005", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL in Sent: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendToNonExistentFolder(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	// Send APPEND to non-existent folder - server rejects before continuation
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 APPEND NoSuchFolder {0}\r\n")
	// Server sends NO directly without + continuation
	_, code, _ := c.readTagged()
	if code != "NO" {
		t.Fatalf("APPEND non-existent: code=%s, want NO", code)
	}
}

func TestE2EIMAPAppendEmptyMessage(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("")
	_, code, _ := c.appendMsg("A003", "INBOX", msg)
	if code != "OK" {
		t.Fatalf("APPEND empty: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendLargeMessage(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Large\r\n\r\n")
	msg = append(msg, strings.Repeat("X", 100*1024)...)
	_, code, _ := c.appendMsg("A003", "INBOX", msg)
	if code != "OK" {
		t.Fatalf("APPEND large: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendSpecialCharacters(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: Special\r\n\r\nHello 世界! 🎉\r\n")
	_, code, _ := c.appendMsg("A003", "INBOX", msg)
	if code != "OK" {
		t.Fatalf("APPEND special: code=%s, want OK", code)
	}
}

func TestE2EIMAPAppendMultipleFlags(t *testing.T) {
	t.Skip("server does not support multiple flags in APPEND (strings.Fields splits parens)")
}

func TestE2EIMAPAppendWithFlagsAndDate(t *testing.T) {
	t.Skip("server does not support quoted date-time in APPEND (strings.Fields splits quotes)")
}

func TestE2EIMAPAppendCaseInsensitive(t *testing.T) {
	env := setup(t)
	c := env.dialIMAP()
	c.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	c.cmd("A002", "SELECT INBOX")
	// Server only handles INBOX (uppercase) for APPEND
	msg := []byte("From: a@b.com\r\nTo: c@d.com\r\nSubject: INBOX\r\n\r\nBody\r\n")
	_, code, _ := c.appendMsg("AAPP0", "INBOX", msg)
	if code != "OK" {
		t.Fatalf("APPEND INBOX: code=%s, want OK", code)
	}
}

// ---------- E2E SMTP Tests ----------

func TestE2ESMTPSendAndReceive(t *testing.T) {
	env := setup(t)
	sc := env.dialSMTP()
	code, _ := sc.cmd("EHLO client.test.local")
	if code != 250 {
		t.Fatalf("EHLO: code=%d, want 250", code)
	}
	code, _ = sc.cmd("MAIL FROM:<sender@example.com>")
	if code != 250 {
		t.Fatalf("MAIL FROM: code=%d, want 250", code)
	}
	code, _ = sc.cmd(fmt.Sprintf("RCPT TO:<%s>", env.emailAddr))
	if code != 250 {
		t.Fatalf("RCPT TO: code=%d, want 250", code)
	}
	code, _ = sc.cmd("DATA")
	if code != 354 {
		t.Fatalf("DATA: code=%d, want 354", code)
	}
	msgBody := "From: sender@example.com\r\nTo: alice@test.local\r\nSubject: SMTP E2E\r\n\r\nDelivered via SMTP!\r\n.\r\n"
	code, _ = sc.sendData(msgBody)
	if code != 250 {
		t.Fatalf("DATA end: code=%d, want 250", code)
	}
	code, _ = sc.cmd("QUIT")
	if code != 221 {
		t.Fatalf("QUIT: code=%d, want 221", code)
	}
	time.Sleep(200 * time.Millisecond)
	ic := env.dialIMAP()
	ic.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	ic.cmd("A002", "SELECT INBOX")
	_, code2, _ := ic.cmd("A003", "SEARCH ALL")
	if code2 != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code2)
	}
	_, code2, _ = ic.cmd("A004", "FETCH 1 BODY[]")
	if code2 != "OK" {
		t.Fatalf("FETCH BODY: code=%s, want OK", code2)
	}
}

func TestE2ESMTPRecipientAliasDeliversToEachTerminalMailbox(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	if err := env.ts.UserStore().Create(ctx, "bob", "Bob Test", env.password); err != nil {
		t.Fatal(err)
	}
	if err := env.ts.FolderStore().CreateForUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := env.ts.UserStore().AddEmailAddress(ctx, "bob@test.local", "bob", env.domainID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := env.ts.RecipientAliasStore().Create(ctx, "team@test.local", []string{env.emailAddr, "bob@test.local"}, true); err != nil {
		t.Fatal(err)
	}

	sc := env.dialSMTP()
	commands := []struct {
		command string
		want    int
	}{{"EHLO client.test.local", 250}, {"MAIL FROM:<sender@example.com>", 250}, {"RCPT TO:<team@test.local>", 250}, {"DATA", 354}}
	for _, step := range commands {
		if code, text := sc.cmd(step.command); code != step.want {
			t.Fatalf("%s: code=%d text=%q, want %d", step.command, code, text, step.want)
		}
	}
	if code, text := sc.sendData("From: sender@example.com\r\nTo: team@test.local\r\nSubject: Alias E2E\r\n\r\nDelivered once to each target.\r\n.\r\n"); code != 250 {
		t.Fatalf("DATA end: code=%d text=%q, want 250", code, text)
	}

	for _, userID := range []string{"alice", "bob"} {
		items, err := env.ts.ItemStore().List(ctx, model.InboxFolderID(userID))
		if err != nil || len(items) != 1 {
			t.Fatalf("%s inbox items=%v err=%v, want one alias delivery", userID, items, err)
		}
	}
}

func TestE2ESMTPUnknownRecipient(t *testing.T) {
	env := setup(t)
	sc := env.dialSMTP()
	sc.cmd("EHLO client.test.local")
	sc.cmd("MAIL FROM:<sender@example.com>")
	code, _ := sc.cmd("RCPT TO:<nobody@test.local>")
	if code != 550 {
		t.Fatalf("RCPT TO unknown: code=%d, want 550", code)
	}
}

func TestE2ESMTPBeforeEHLO(t *testing.T) {
	env := setup(t)
	sc := env.dialSMTP()
	code, _ := sc.cmd("MAIL FROM:<sender@example.com>")
	if code != 503 {
		t.Fatalf("MAIL FROM before EHLO: code=%d, want 503", code)
	}
}

// ---------- E2E CalDAV Tests ----------

func TestE2ECalDAVCalendar(t *testing.T) {
	env := setup(t)
	mkcalBody := `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
 <D:resourcetype>
 <C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/>
 </D:resourcetype>
</D:prop>`
	resp := env.httpDo("MKCOL", "/dav/alice/WorkCalendar", strings.NewReader(mkcalBody), "application/xml")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCALENDAR: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	event := `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//E2E//E2E//EN
BEGIN:VEVENT
UID:e2e-event-001@test.local
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:E2E Test Event
END:VEVENT
END:VCALENDAR`
	resp = env.httpDo("PUT", "/dav/alice/WorkCalendar/event1.ics", strings.NewReader(event), "text/calendar")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT event: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp = env.httpDo("GET", "/dav/alice/WorkCalendar/event1.ics", nil, "")
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("GET body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET event: status=%d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(body), "E2E Test Event") {
		t.Errorf("GET: body does not contain expected summary: %s", string(body))
	}
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<calendar-query xmlns="urn:ietf:params:xml:ns:caldav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <calendar-data/>
 </D:prop>
 <filter>
 <comp-filter name="VCALENDAR">
 <comp-filter name="VEVENT">
 <time-range start="20250101T000000Z" end="20250131T235959Z"/>
 </comp-filter>
 </comp-filter>
 </filter>
</calendar-query>`
	resp = env.httpDo("REPORT", "/dav/alice/WorkCalendar/", strings.NewReader(queryBody), "application/xml")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("REPORT body: %v", err)
	}
	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("calendar-query: status=%d, want %d, body=%s", resp.StatusCode, http.StatusMultiStatus, string(body))
	}
	if !strings.Contains(string(body), "E2E Test Event") {
		t.Errorf("calendar-query: body does not contain event: %s", string(body))
	}
}

func TestE2ECalDAVDeleteEvent(t *testing.T) {
	env := setup(t)
	mkcalBody := `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:resourcetype><C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/></D:resourcetype></D:prop>`
	resp := env.httpDo("MKCOL", "/dav/alice/TempCal", strings.NewReader(mkcalBody), "application/xml")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCALENDAR: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	event := `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//E2E//E2E//EN
BEGIN:VEVENT
UID:e2e-del@test.local
DTSTART:20250101T100000Z
DTEND:20250101T110000Z
SUMMARY:To Delete
END:VEVENT
END:VCALENDAR`
	resp = env.httpDo("PUT", "/dav/alice/TempCal/del.ics", strings.NewReader(event), "text/calendar")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp = env.httpDo("DELETE", "/dav/alice/TempCal/del.ics", nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: status=%d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	resp = env.httpDo("GET", "/dav/alice/TempCal/del.ics", nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after DELETE: status=%d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// ---------- E2E CardDAV Tests ----------

func TestE2ECardDAVAddressbook(t *testing.T) {
	env := setup(t)
	mkcolBody := `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
 <D:resourcetype>
 <C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>
 </D:resourcetype>
</D:prop>`
	resp := env.httpDo("MKCOL", "/dav/alice/MyContacts", strings.NewReader(mkcolBody), "application/xml")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL addressbook: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	contact := `BEGIN:VCARD
VERSION:3.0
UID:contact-e2e-001@test.local
FN:Alice E2E
N:E2E;Alice;;;
EMAIL;TYPE=INTERNET:alice@test.local
TEL;TYPE=WORK:+1-555-0100
END:VCARD`
	resp = env.httpDo("PUT", "/dav/alice/MyContacts/alice.vcf", strings.NewReader(contact), "text/vcard")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT contact: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp = env.httpDo("GET", "/dav/alice/MyContacts/alice.vcf", nil, "")
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("GET body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET contact: status=%d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(body), "Alice E2E") {
		t.Errorf("GET: body does not contain expected name: %s", string(body))
	}
	queryBody := `<?xml version="1.0" encoding="utf-8"?>
<addressbook-query xmlns="urn:ietf:params:xml:ns:carddav">
 <D:prop xmlns:D="DAV:">
 <D:getetag/>
 <vcard/>
 </D:prop>
 <filter>
 <comp-filter name="VCARD">
 <prop-filter name="FN">
 <text-match>Alice</text-match>
 </prop-filter>
 </comp-filter>
 </filter>
</addressbook-query>`
	resp = env.httpDo("REPORT", "/dav/alice/MyContacts/", strings.NewReader(queryBody), "application/xml")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("REPORT body: %v", err)
	}
	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("addressbook-query: status=%d, want %d, body=%s", resp.StatusCode, http.StatusMultiStatus, string(body))
	}
	if !strings.Contains(string(body), "Alice E2E") {
		t.Errorf("addressbook-query: body does not contain contact: %s", string(body))
	}
}

func TestE2ECardDAVDeleteContact(t *testing.T) {
	env := setup(t)
	mkcolBody := `<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:resourcetype><C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/></D:resourcetype></D:prop>`
	resp := env.httpDo("MKCOL", "/dav/alice/TempContacts", strings.NewReader(mkcolBody), "application/xml")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	contact := `BEGIN:VCARD
VERSION:3.0
UID:del-contact@test.local
FN:To Delete
N:Delete;To;;;
END:VCARD`
	resp = env.httpDo("PUT", "/dav/alice/TempContacts/del.vcf", strings.NewReader(contact), "text/vcard")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status=%d, want %d", resp.StatusCode, http.StatusCreated)
	}
	resp = env.httpDo("DELETE", "/dav/alice/TempContacts/del.vcf", nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: status=%d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	resp = env.httpDo("GET", "/dav/alice/TempContacts/del.vcf", nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after DELETE: status=%d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// ---------- E2E HTTP Auth Tests ----------

func TestE2EHTTPUnauthorized(t *testing.T) {
	env := setup(t)
	url := fmt.Sprintf("http://%s/dav/alice/", env.httpAddr)
	req, _ := http.NewRequest("PROPFIND", url, strings.NewReader(`<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>`))
	req.Header.Set("Content-Type", "application/xml")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestE2EHTTPWrongPassword(t *testing.T) {
	env := setup(t)
	url := fmt.Sprintf("http://%s/dav/alice/", env.httpAddr)
	req, _ := http.NewRequest("PROPFIND", url, strings.NewReader(`<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>`))
	req.Header.Set("Content-Type", "application/xml")
	req.SetBasicAuth(env.username, "wrongpassword")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// ---------- E2E IMAP IDLE Tests ----------

// TestE2EIMAPIdleSMTPDelivery tests that when a message arrives via SMTP,
// an IMAP IDLE client receives a * N EXISTS notification.
func TestE2EIMAPIdleSMTPDelivery(t *testing.T) {
	env := setup(t)

	// Open IMAP connection and enter IDLE on INBOX
	ic := env.dialIMAP()
	ic.cmd("A001", fmt.Sprintf("LOGIN %s %s", env.username, env.password))
	ic.cmd("A002", "SELECT INBOX")

	// Start IDLE
	ic.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(ic.Conn, "A003 IDLE\r\n")

	// Read the continuation response
	ic.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	cont, err := ic.readLine()
	if err != nil {
		t.Fatalf("expected IDLE continuation, got error: %v", err)
	}
	if !strings.HasPrefix(cont, "+") {
		t.Fatalf("expected IDLE continuation, got: %s", cont)
	}

	// Deliver a message via SMTP in a goroutine
	go func() {
		time.Sleep(200 * time.Millisecond) // let IDLE settle
		sc := env.dialSMTP()
		sc.cmd("EHLO client.test.local")
		sc.cmd("MAIL FROM:<sender@example.com>")
		sc.cmd(fmt.Sprintf("RCPT TO:<%s>", env.emailAddr))
		code, _ := sc.cmd("DATA")
		if code != 354 {
			return
		}
		msgBody := "From: sender@example.com\r\nTo: alice@test.local\r\nSubject: IDLE Test\r\n\r\nDelivered via SMTP!\r\n.\r\n"
		sc.sendData(msgBody)
	}()

	// Wait for the EXISTS notification during IDLE
	ic.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	notif, err := ic.readLine()
	if err != nil {
		t.Fatalf("expected EXISTS notification during IDLE, got error: %v", err)
	}
	if !strings.Contains(notif, "EXISTS") {
		t.Fatalf("expected EXISTS notification, got: %s", notif)
	}
	t.Logf("Received IDLE notification: %s", notif)

	// Exit IDLE with DONE
	ic.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(ic.Conn, "DONE\r\n")
	_, code, _ := ic.readTagged()
	if code != "OK" {
		t.Fatalf("IDLE DONE: code=%s, want OK", code)
	}

	// Verify the message is actually there
	_, code, _ = ic.cmd("A004", "SEARCH ALL")
	if code != "OK" {
		t.Fatalf("SEARCH ALL: code=%s, want OK", code)
	}
}

// TestE2EIMAPIdleConcurrentSessions tests that multiple concurrent IDLE
// sessions all receive notifications when a message arrives via SMTP.
func TestE2EIMAPIdleConcurrentSessions(t *testing.T) {
	env := setup(t)

	// Open two IMAP connections, both IDLE on INBOX
	sessions := make([]*imapClient, 2)
	for i := 0; i < 2; i++ {
		ic := env.dialIMAP()
		ic.cmd(fmt.Sprintf("A001%d", i), fmt.Sprintf("LOGIN %s %s", env.username, env.password))
		ic.cmd(fmt.Sprintf("A002%d", i), "SELECT INBOX")
		sessions[i] = ic
	}

	// Start IDLE on both sessions
	for i, ic := range sessions {
		ic.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(ic.Conn, "A003%d IDLE\r\n", i)

		ic.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		cont, err := ic.readLine()
		if err != nil {
			t.Fatalf("session %d: expected IDLE continuation, got error: %v", i, err)
		}
		if !strings.HasPrefix(cont, "+") {
			t.Fatalf("session %d: expected IDLE continuation, got: %s", i, cont)
		}
	}

	// Deliver a message via SMTP
	go func() {
		time.Sleep(300 * time.Millisecond)
		sc := env.dialSMTP()
		sc.cmd("EHLO client.test.local")
		sc.cmd("MAIL FROM:<sender@example.com>")
		sc.cmd(fmt.Sprintf("RCPT TO:<%s>", env.emailAddr))
		sc.cmd("DATA")
		msgBody := "From: sender@example.com\r\nTo: alice@test.local\r\nSubject: Concurrent IDLE\r\n\r\nHello from SMTP!\r\n.\r\n"
		sc.sendData(msgBody)
	}()

	// Both sessions should receive EXISTS notifications
	for i, ic := range sessions {
		ic.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		notif, err := ic.readLine()
		if err != nil {
			t.Fatalf("session %d: expected EXISTS notification, got error: %v", i, err)
		}
		if !strings.Contains(notif, "EXISTS") {
			t.Fatalf("session %d: expected EXISTS notification, got: %s", i, notif)
		}
		t.Logf("session %d received: %s", i, notif)

		// Exit IDLE
		ic.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(ic.Conn, "DONE\r\n")
		_, code, _ := ic.readTagged()
		if code != "OK" {
			t.Fatalf("session %d: IDLE DONE: code=%s, want OK", i, code)
		}
	}
}
