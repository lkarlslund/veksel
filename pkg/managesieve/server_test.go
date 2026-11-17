package managesieve

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
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/sieve"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestParseLineQuotedEscapesAndAtoms(t *testing.T) {
	got, err := parseLine(`RENAMESCRIPT "old name" "new\\\"name"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"RENAMESCRIPT", "old name", `new\"name`}
	if len(got) != len(want) {
		t.Fatalf("parseLine() = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseLine()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := parseLine(`GETSCRIPT "broken`); err == nil {
		t.Fatal("unterminated quoted string accepted")
	}
	for _, input := range []string{`GETSCRIPT "bad\qescape"`, `GETSCRIPT "joined"atom`} {
		if _, err := parseLine(input); err == nil {
			t.Errorf("malformed command %q accepted", input)
		}
	}
}

func TestServerAuthenticatedNamedScriptRoundTrip(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "secret123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.UserStore().Create(t.Context(), "bob", "Bob", "secret123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	repository := service.NewSieveRepository(service.NewFolderSpace(typed, authz.New(typed)))
	server := &Server{Repository: repository, Authenticate: func(_ context.Context, username, password string) (string, error) {
		if (username == "alice" || username == "bob") && password == "secret123" {
			return username, nil
		}
		return "", store.ErrNotFound
	}, ReadTimeout: time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = server.Serve(listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	var greeting strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		greeting.WriteString(line)
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	if !strings.Contains(greeting.String(), `"SIEVE" "`+sieve.Capabilities+`"`+"\r\n") || !strings.Contains(greeting.String(), `"NOTIFY" "mailto"`+"\r\n") || !strings.Contains(greeting.String(), `"MAXREDIRECTS" "32"`+"\r\n") {
		t.Fatalf("greeting = %q", greeting.String())
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret123"))
	command(t, writer, `AUTHENTICATE "PLAIN" "`+credentials+`"`)
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("AUTH = %q", line)
	}
	// A Roundcube managesieve-style filter set using RFC 5490 :create.
	roundcube := "require [\"fileinto\",\"mailbox\"];\r\n# rule:[Lists]\r\nif header :contains \"list-id\" \"acme\"\r\n{\r\n\tfileinto :create \"Lists/Acme\";\r\n\tstop;\r\n}\r\n"
	command(t, writer, fmt.Sprintf("CHECKSCRIPT {%d+}\r\n%s", len(roundcube), roundcube))
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("CHECKSCRIPT roundcube = %q", line)
	}
	for _, invalid := range []string{`require "imap4flags"; keep;`, `fileinto "A";`, `keep`, `require "fileinto"; fileinto :create "A";`} {
		command(t, writer, fmt.Sprintf("CHECKSCRIPT {%d+}\r\n%s", len(invalid), invalid))
		if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "NO") {
			t.Fatalf("CHECKSCRIPT %q = %q", invalid, line)
		}
	}
	command(t, writer, "PUTSCRIPT \"primary\" {5+}\r\nkeep;")
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("PUTSCRIPT = %q", line)
	}
	command(t, writer, `SETACTIVE "primary"`)
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("SETACTIVE = %q", line)
	}
	command(t, writer, "LISTSCRIPTS")
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("LISTSCRIPTS = %q", line)
	}
	if script, active, err := repository.Active(t.Context(), "alice"); err != nil || !active || script != "keep;" {
		t.Fatalf("active = (%q, %t, %v)", script, active, err)
	}
	command(t, writer, "UNAUTHENTICATE")
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("UNAUTHENTICATE = %q", line)
	}
	bobCredentials := base64.StdEncoding.EncodeToString([]byte("\x00bob\x00secret123"))
	command(t, writer, `AUTHENTICATE "PLAIN" "`+bobCredentials+`"`)
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("Bob AUTH = %q", line)
	}
	command(t, writer, `GETSCRIPT "primary"`)
	if line := readUntilStatus(t, reader); !strings.Contains(line, "NONEXISTENT") {
		t.Fatalf("cross-account GETSCRIPT = %q", line)
	}
}

func TestServerSASLPlainChallengeStateAndNOOPTag(t *testing.T) {
	_, listener := testProtocolServer(t, nil, false)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	greeting := readResponseLines(t, reader)
	if !containsLine(greeting, `"UNAUTHENTICATE"`) || !containsLine(greeting, `"SASL" "PLAIN"`) {
		t.Fatalf("greeting = %#v", greeting)
	}

	command(t, writer, `AUTHENTICATE "PLAIN"`)
	challenge, err := reader.ReadString('\n')
	if err != nil || challenge != "\"\"\r\n" {
		t.Fatalf("PLAIN challenge = %q, %v", challenge, err)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret123"))
	command(t, writer, quote(credentials))
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("challenge AUTH = %q", line)
	}
	command(t, writer, `NOOP "sync-42"`)
	if line := readUntilStatus(t, reader); line != `OK (TAG "sync-42") "NOOP completed"` {
		t.Fatalf("tagged NOOP = %q", line)
	}
	command(t, writer, `AUTHENTICATE "PLAIN" "`+credentials+`"`)
	if line := readUntilStatus(t, reader); !strings.Contains(line, "command requires non-authenticated state") {
		t.Fatalf("authenticated AUTHENTICATE = %q", line)
	}
	command(t, writer, "UNAUTHENTICATE")
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("UNAUTHENTICATE = %q", line)
	}
	command(t, writer, `AUTHENTICATE "PLAIN"`)
	if challenge, err = reader.ReadString('\n'); err != nil || challenge != "\"\"\r\n" {
		t.Fatalf("cancel challenge = %q, %v", challenge, err)
	}
	command(t, writer, `"*"`)
	if line := readUntilStatus(t, reader); !strings.Contains(line, "authentication cancelled") {
		t.Fatalf("cancel AUTH = %q", line)
	}
	command(t, writer, `GETSCRIPT "primary"`)
	if line := readUntilStatus(t, reader); !strings.Contains(line, "authenticate first") {
		t.Fatalf("unauthenticated GETSCRIPT = %q", line)
	}
	command(t, writer, "UNAUTHENTICATE")
	if line := readUntilStatus(t, reader); !strings.Contains(line, "authenticate first") {
		t.Fatalf("unauthenticated UNAUTHENTICATE = %q", line)
	}
	differentAuthz := base64.StdEncoding.EncodeToString([]byte("bob\x00alice\x00secret123"))
	command(t, writer, `AUTHENTICATE "PLAIN" "`+differentAuthz+`"`)
	mismatch := readUntilStatus(t, reader)
	unknown := base64.StdEncoding.EncodeToString([]byte("\x00unknown\x00secret123"))
	command(t, writer, `AUTHENTICATE "PLAIN" "`+unknown+`"`)
	if line := readUntilStatus(t, reader); line != mismatch || line != `NO "authentication failed"` {
		t.Fatalf("generic authentication failures = mismatch %q, unknown %q", mismatch, line)
	}
}

func TestServerSTARTTLSReplaysCapabilitiesAndPreservesStateRules(t *testing.T) {
	tlsConfig := testManageSieveTLSConfig(t)
	_, listener := testProtocolServer(t, tlsConfig, true)
	plain, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	reader, writer := bufio.NewReader(plain), bufio.NewWriter(plain)
	greeting := readResponseLines(t, reader)
	// RFC 5804 1.7 lists SASL even before STARTTLS, empty.
	if containsLine(greeting, `"SASL" "PLAIN"`) || !containsLine(greeting, `"SASL" ""`) || !containsLine(greeting, `"STARTTLS"`) {
		t.Fatalf("pre-TLS greeting = %#v", greeting)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret123"))
	command(t, writer, `AUTHENTICATE "PLAIN" "`+credentials+`"`)
	if line := readUntilStatus(t, reader); !strings.Contains(line, "ENCRYPT-NEEDED") {
		t.Fatalf("cleartext AUTH = %q", line)
	}
	command(t, writer, "STARTTLS")
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("STARTTLS = %q", line)
	}

	secured := tls.Client(plain, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // test certificate
	if err := secured.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader, writer = bufio.NewReader(secured), bufio.NewWriter(secured)
	afterTLS := readResponseLines(t, reader)
	if !containsLine(afterTLS, `"SASL" "PLAIN"`) || containsLine(afterTLS, `"STARTTLS"`) {
		t.Fatalf("post-TLS capabilities = %#v", afterTLS)
	}
	command(t, writer, `AUTHENTICATE "PLAIN" "`+credentials+`"`)
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "OK") {
		t.Fatalf("TLS AUTH = %q", line)
	}
	command(t, writer, "STARTTLS")
	if line := readUntilStatus(t, reader); !strings.Contains(line, "command requires non-authenticated state") {
		t.Fatalf("authenticated STARTTLS = %q", line)
	}
}

func command(t *testing.T, writer *bufio.Writer, value string) {
	t.Helper()
	if _, err := writer.WriteString(value + "\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
}

func readUntilStatus(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			return line
		}
	}
}

func TestReadLiteralRequiresBoundedNonSynchronizingUTF8(t *testing.T) {
	for name, test := range map[string]struct {
		token string
		input string
		want  string
	}{
		"content": {token: "{4+}", input: "keep\r\nNEXT\r\n", want: "keep"},
		"empty":   {token: "{0+}", input: "\r\n", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readLiteral(bufio.NewReader(strings.NewReader(test.input)), test.token)
			if err != nil || got != test.want {
				t.Fatalf("readLiteral(%q) = (%q, %v), want %q", test.token, got, err, test.want)
			}
		})
	}
	for _, token := range []string{"{4}", "{04+}", "{-1+}", "{1048577+}", "{4294967296+}", "4"} {
		if _, err := readLiteral(bufio.NewReader(strings.NewReader("keep\r\n")), token); err == nil {
			t.Errorf("invalid literal %q accepted", token)
		}
	}
	if _, err := readLiteral(bufio.NewReader(strings.NewReader("keep\n")), "{4+}"); err == nil {
		t.Fatal("LF-only literal termination accepted")
	}
	if _, err := readLiteral(bufio.NewReader(strings.NewReader("\xff\r\n")), "{1+}"); err == nil {
		t.Fatal("non-UTF-8 literal accepted")
	}
}

func TestParseNumberUsesRFCUnsignedCanonicalFormAndBounds(t *testing.T) {
	for input, want := range map[string]int{"0": 0, "1": 1, "1048576": service.MaxScriptBytes} {
		got, err := parseNumber(input, service.MaxScriptBytes)
		if err != nil || got != want {
			t.Errorf("parseNumber(%q) = (%d, %v), want %d", input, got, err, want)
		}
	}
	for _, input := range []string{"", "00", "01", "-1", "+1", "1048577", "4294967296", "1.0"} {
		if _, err := parseNumber(input, service.MaxScriptBytes); err == nil {
			t.Errorf("parseNumber(%q) accepted", input)
		}
	}
}

func TestEffectiveReadTimeoutHonorsAuthenticatedMinimum(t *testing.T) {
	if got := effectiveReadTimeout(5*time.Minute, false); got != 5*time.Minute {
		t.Fatalf("pre-auth timeout = %s", got)
	}
	if got := effectiveReadTimeout(5*time.Minute, true); got != minimumAuthenticatedIdleTimeout {
		t.Fatalf("authenticated timeout = %s", got)
	}
	if got := effectiveReadTimeout(time.Hour, true); got != time.Hour {
		t.Fatalf("long authenticated timeout = %s", got)
	}
	if got := effectiveReadTimeout(0, true); got != 0 {
		t.Fatalf("disabled timeout = %s", got)
	}
}

func TestReadProtocolLineRequiresCRLF(t *testing.T) {
	if line, err := readProtocolLine(bufio.NewReader(strings.NewReader("NOOP\r\nnext"))); err != nil || line != "NOOP" {
		t.Fatalf("CRLF line = %q, %v", line, err)
	}
	if _, err := readProtocolLine(bufio.NewReader(strings.NewReader("NOOP\n"))); err == nil {
		t.Fatal("LF-only protocol line accepted")
	}
}

func testProtocolServer(t *testing.T, tlsConfig *tls.Config, requireTLS bool) (*Server, net.Listener) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{model.NSUsers, model.NSFolders, model.NSItems, model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes} {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "secret123"); err != nil {
		t.Fatal(err)
	}
	if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	repository := service.NewSieveRepository(service.NewFolderSpace(typed, authz.New(typed)))
	server := &Server{Repository: repository, TLSConfig: tlsConfig, RequireTLSForAuth: requireTLS, ReadTimeout: time.Second, WriteTimeout: time.Second,
		Authenticate: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret123" {
				return "alice", nil
			}
			return "", store.ErrNotFound
		}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = server.Serve(listener) }()
	return server, listener
}

func testManageSieveTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	return &tls.Config{Certificates: tlsServer.TLS.Certificates, MinVersion: tls.VersionTLS12}
}

func readResponseLines(t *testing.T, reader *bufio.Reader) []string {
	t.Helper()
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		lines = append(lines, line)
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			return lines
		}
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

// TestServerSTARTTLSRefusesPipelinedCommands checks that a command sent in
// the same cleartext write as STARTTLS is not executed after the upgrade.
func TestServerSTARTTLSRefusesPipelinedCommands(t *testing.T) {
	_, listener := testProtocolServer(t, testManageSieveTLSConfig(t), true)
	plain, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_ = plain.SetDeadline(time.Now().Add(2 * time.Second))
	reader, writer := bufio.NewReader(plain), bufio.NewWriter(plain)
	readResponseLines(t, reader)
	command(t, writer, "STARTTLS\r\nLOGOUT")
	if line := readUntilStatus(t, reader); !strings.HasPrefix(line, "BYE") {
		t.Fatalf("pipelined STARTTLS = %q, want BYE", line)
	}
	if line, err := reader.ReadString('\n'); err == nil {
		t.Fatalf("session continued after BYE: %q", line)
	}
}
