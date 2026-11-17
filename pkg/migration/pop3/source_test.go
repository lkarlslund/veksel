package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	pop3server "github.com/lkarlslund/veksel/pkg/pop3"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type fakeMailbox struct {
	uidls      []string
	messages   []string
	commands   []string
	rejectPass bool
	rejectUIDL bool
	mu         sync.Mutex
}

func TestSourcePagesByUIDLAndRerunsIncrementallyWithoutDeleting(t *testing.T) {
	mailbox := &fakeMailbox{
		uidls: []string{"stable-a", "stable-b"},
		messages: []string{
			"Subject: First\r\nDate: Thu, 27 Aug 2026 08:00:00 +0000\r\n\r\n.literal\r\n",
			"Subject: Second\r\n\r\nbody\r\n",
		},
	}
	address := startFakeMailbox(t, mailbox, "plain")
	source, err := Dial(t.Context(), Config{Address: address, Username: "alice", Password: "secret", TLSMode: migration.MailSecurityPlain, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	folders, err := source.Folders(t.Context())
	if err != nil || len(folders) != 1 || folders[0].Estimate != 2 || !folders[0].EstimateKnown || folders[0].Special != model.SpecialUseInbox {
		t.Fatalf("folders=%+v err=%v", folders, err)
	}
	first, err := source.Items(t.Context(), folders[0], "")
	if err != nil || first.Done || len(first.Items) != 1 || first.Items[0].ID != "stable-a" || first.Items[0].Headers["Subject"] != "First" || first.Items[0].Name != "" || !strings.Contains(string(first.Items[0].Data), ".literal\r\n") {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := source.Items(t.Context(), folders[0], first.Checkpoint)
	if err != nil || !second.Done || len(second.Items) != 1 || second.Items[0].ID != "stable-b" {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	_ = source.Close()

	replayMailbox := &fakeMailbox{uidls: mailbox.uidls, messages: mailbox.messages}
	replay := dialFake(t, replayMailbox, 10)
	unchanged, err := replay.Items(t.Context(), folders[0], second.Checkpoint)
	if err != nil || !unchanged.Done || len(unchanged.Items) != 0 {
		t.Fatalf("unchanged=%+v err=%v", unchanged, err)
	}
	_ = replay.Close()
	commands := append(mailbox.commandLog(), replayMailbox.commandLog()...)
	if strings.Contains(strings.Join(commands, "\n"), "DELE") || countCommand(commands, "RETR") != 2 {
		t.Fatalf("commands=%v", commands)
	}
}

func TestSourceResetsInterruptedContinuationWhenMailboxNumberingChanges(t *testing.T) {
	initial := &fakeMailbox{uidls: []string{"a", "b"}, messages: []string{"Subject: A\r\n\r\na", "Subject: B\r\n\r\nb"}}
	source := dialFake(t, initial, 1)
	folder := migration.Folder{ID: "INBOX", Type: model.FolderTypeMail}
	page, err := source.Items(t.Context(), folder, "")
	if err != nil || page.Done || page.Items[0].ID != "a" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	_ = source.Close()

	changed := &fakeMailbox{uidls: []string{"x", "a", "b"}, messages: []string{"Subject: X\r\n\r\nx", "Subject: A\r\n\r\na", "Subject: B\r\n\r\nb"}}
	resumed := dialFake(t, changed, 1)
	restarted, err := resumed.Items(t.Context(), folder, page.Checkpoint)
	if err != nil || len(restarted.Items) != 1 || restarted.Items[0].ID != "x" {
		t.Fatalf("restarted=%+v err=%v", restarted, err)
	}
	_ = resumed.Close()
}

func TestSourceFetchesOnlyNewUIDLsAfterCompletedCheckpoint(t *testing.T) {
	initial := &fakeMailbox{uidls: []string{"a"}, messages: []string{"Subject: A\r\n\r\na"}}
	source := dialFake(t, initial, 10)
	folder := migration.Folder{ID: "INBOX", Type: model.FolderTypeMail}
	complete, err := source.Items(t.Context(), folder, "")
	if err != nil || !complete.Done {
		t.Fatalf("complete=%+v err=%v", complete, err)
	}
	_ = source.Close()
	updated := &fakeMailbox{uidls: []string{"a", "b"}, messages: []string{"Subject: A\r\n\r\na", "Subject: B\r\n\r\nb"}}
	next := dialFake(t, updated, 10)
	page, err := next.Items(t.Context(), folder, complete.Checkpoint)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "b" || countCommand(updated.commandLog(), "RETR") != 1 {
		t.Fatalf("page=%+v commands=%v err=%v", page, updated.commandLog(), err)
	}
	_ = next.Close()
}

func TestSourceRejectsUnsafeUIDLsCredentialsAndLeaksNoPassword(t *testing.T) {
	for name, uidls := range map[string][]string{
		"duplicate": {"same", "same"}, "space": {"not valid"}, "too long": {strings.Repeat("x", 71)},
	} {
		t.Run(name, func(t *testing.T) {
			mailbox := &fakeMailbox{uidls: uidls, messages: make([]string, len(uidls))}
			source := dialFake(t, mailbox, 10)
			_, err := source.Items(t.Context(), migration.Folder{ID: "INBOX", Type: model.FolderTypeMail}, "")
			if err == nil {
				t.Fatal("unsafe UIDL response was accepted")
			}
			_ = source.Close()
		})
	}
	missing := dialFake(t, &fakeMailbox{rejectUIDL: true}, 10)
	if _, err := missing.Items(t.Context(), migration.Folder{ID: "INBOX", Type: model.FolderTypeMail}, ""); err == nil || !strings.Contains(err.Error(), "UIDL") {
		t.Fatalf("missing UIDL error=%v", err)
	}
	_ = missing.Close()
	checkpointSource := dialFake(t, &fakeMailbox{}, 10)
	for _, token := range []string{`{"version":2}`, `{"version":1,"scan_digest":"not-a-digest"}`, `{"version":1,"last_uidl":"not valid"}`, strings.Repeat("x", maxCheckpointSize+1)} {
		if _, err := checkpointSource.Items(t.Context(), migration.Folder{ID: "INBOX", Type: model.FolderTypeMail}, token); err == nil {
			t.Fatalf("invalid checkpoint %q was accepted", token[:min(len(token), 80)])
		}
	}
	_ = checkpointSource.Close()
	if _, err := Dial(t.Context(), Config{Address: "127.0.0.1:1", Username: "bad\r\nDELE 1", Password: "secret", TLSMode: migration.MailSecurityPlain}); err == nil {
		t.Fatal("command injection in credentials was accepted")
	}
	mailbox := &fakeMailbox{rejectPass: true}
	address := startFakeMailbox(t, mailbox, "plain")
	_, err := Dial(t.Context(), Config{Address: address, Username: "alice", Password: "password-must-stay-private", TLSMode: migration.MailSecurityPlain})
	if err == nil || strings.Contains(err.Error(), "password-must-stay-private") {
		t.Fatalf("password rejection error=%v", err)
	}
}

func TestSourceSupportsImplicitTLSAndSTLS(t *testing.T) {
	for _, mode := range []migration.MailSecurityMode{migration.MailSecurityImplicit, migration.MailSecurityStartTLS} {
		t.Run(string(mode), func(t *testing.T) {
			mailbox := &fakeMailbox{}
			address := startFakeMailbox(t, mailbox, string(mode))
			source, err := Dial(t.Context(), Config{Address: address, Username: "alice", Password: "secret", TLSMode: mode, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}) //nolint:gosec -- isolated test listener
			if err != nil {
				t.Fatal(err)
			}
			_ = source.Close()
			if mode == migration.MailSecurityStartTLS && !strings.Contains(strings.Join(mailbox.commandLog(), "\n"), "STLS") {
				t.Fatalf("commands=%v", mailbox.commandLog())
			}
		})
	}
}

func TestImplicitTLSDialFailureIsReported(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	source, err := Dial(t.Context(), Config{Address: address, Username: "alice", Password: "secret", TLSMode: migration.MailSecurityImplicit, Timeout: time.Second})
	if err == nil || source != nil {
		t.Fatalf("Dial to closed port = %v, %v; want error", source, err)
	}
}

func TestSourceHonorsContextCancellationAndLineBound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = fmt.Fprint(conn, "+OK ready\r\n")
			time.Sleep(time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, err = Dial(ctx, Config{Address: listener.Addr().String(), Username: "alice", Password: "secret", TLSMode: migration.MailSecurityPlain, Timeout: time.Second})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error=%v", err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	source := &Source{conn: client, reader: bufio.NewReaderSize(client, 64<<10), timeout: time.Second}
	go func() { _, _ = fmt.Fprintf(server, "%s\r\n", strings.Repeat("x", maxLineBytes+1)) }()
	if _, err := source.readLine(); err == nil || !strings.Contains(err.Error(), "line") {
		t.Fatalf("oversized line error=%v", err)
	}
	server2, client2 := net.Pipe()
	t.Cleanup(func() { _ = server2.Close(); _ = client2.Close() })
	bounded := &Source{conn: client2, reader: bufio.NewReader(client2), timeout: time.Second}
	go func() { _, _ = fmt.Fprint(server2, "1234\r\n.\r\n") }()
	if _, err := bounded.readMultiline(t.Context(), 3); err == nil || !strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized multiline error=%v", err)
	}
}

func TestVekselPOP3SourceImportsThroughGenericFolderSpace(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	typed := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range model.Namespaces() {
		if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	for _, user := range []string{"source", "destination"} {
		if err := typed.UserStore().Create(t.Context(), user, strings.ToUpper(user), "password123"); err != nil {
			t.Fatal(err)
		}
		if err := typed.FolderStore().CreateForUser(t.Context(), user); err != nil {
			t.Fatal(err)
		}
	}
	space := service.NewFolderSpace(typed, authz.New(typed))
	sourceInbox, err := space.GetFolderByPath(t.Context(), service.UserAccess("source", "test"), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.test\r\nTo: destination@example.test\r\nSubject: Dot test\r\n\r\n.hidden line\r\n")
	if _, err := space.CreateItem(t.Context(), service.UserAccess("source", "test"), sourceInbox.ID, service.ItemInput{Name: "Dot test", Data: raw, Headers: map[string]string{"Subject": "Dot test"}}); err != nil {
		t.Fatal(err)
	}
	server := pop3server.New(&pop3server.Config{TypedStore: typed, AuthValidator: func(_ context.Context, username, password string) (string, error) {
		if username == "source" && password == "password123" {
			return "source", nil
		}
		return "", errors.New("invalid credentials")
	}})
	listener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stop := context.WithCancel(t.Context())
	go server.Accept(serverCtx, listener)
	t.Cleanup(func() { stop(); server.Close() })
	client, err := Dial(t.Context(), Config{Address: listener.Addr().String(), Username: "source", Password: "password123", TLSMode: migration.MailSecurityPlain})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := migration.NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	job, err := jobs.Create(t.Context(), migration.Job{OwnerID: "destination", DestinationID: "destination", SourceType: "pop3", SourceIdentity: client.ID(), SelectedFolderIDs: []string{"INBOX"}, SourceDeletionPolicy: migration.SourceDeletionRetain, ConflictPolicy: migration.ConflictSourceWins, Schedule: migration.ScheduleManual})
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.NewRunner(jobs, space).Run(t.Context(), job.ID, client); err != nil {
		t.Fatal(err)
	}
	destinationInbox, err := space.GetFolderByPath(t.Context(), service.UserAccess("destination", "test"), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	items, err := space.ListItems(t.Context(), service.UserAccess("destination", "test"), destinationInbox.ID, service.ItemQuery{})
	if err != nil || len(items) != 1 || !strings.Contains(string(items[0].Data), ".hidden line") {
		t.Fatalf("destination items=%+v err=%v", items, err)
	}
}

func dialFake(t *testing.T, mailbox *fakeMailbox, pageSize int) *Source {
	t.Helper()
	address := startFakeMailbox(t, mailbox, "plain")
	source, err := Dial(t.Context(), Config{Address: address, Username: "alice", Password: "secret", TLSMode: migration.MailSecurityPlain, PageSize: pageSize})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func startFakeMailbox(t *testing.T, mailbox *fakeMailbox, security string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t)
	if security == string(migration.MailSecurityImplicit) {
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
		writeLine(writer, "+OK fake ready")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.TrimSpace(line)
			mailbox.record(command)
			verb := strings.ToUpper(strings.Fields(command)[0])
			switch verb {
			case "STLS":
				writeLine(writer, "+OK begin TLS")
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if tlsConn.Handshake() != nil {
					return
				}
				conn, reader, writer = tlsConn, bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn)
			case "USER":
				writeLine(writer, "+OK user")
			case "PASS":
				if mailbox.rejectPass {
					writeLine(writer, "-ERR rejected password detail")
					return
				}
				writeLine(writer, "+OK signed in")
			case "STAT":
				writeLine(writer, fmt.Sprintf("+OK %d %d", len(mailbox.uidls), mailboxSize(mailbox.messages)))
			case "UIDL":
				if mailbox.rejectUIDL {
					writeLine(writer, "-ERR UIDL unavailable")
					continue
				}
				writeLine(writer, "+OK list")
				for index, uidl := range mailbox.uidls {
					writeLine(writer, fmt.Sprintf("%d %s", index+1, uidl))
				}
				writeLine(writer, ".")
			case "RETR":
				fields := strings.Fields(command)
				number, _ := strconvAtoi(fields, 1)
				if number < 1 || number > len(mailbox.messages) {
					writeLine(writer, "-ERR missing")
					continue
				}
				writeLine(writer, "+OK message")
				messageLines := strings.Split(strings.ReplaceAll(mailbox.messages[number-1], "\r\n", "\n"), "\n")
				if len(messageLines) > 0 && messageLines[len(messageLines)-1] == "" {
					messageLines = messageLines[:len(messageLines)-1]
				}
				for _, messageLine := range messageLines {
					if strings.HasPrefix(messageLine, ".") {
						messageLine = "." + messageLine
					}
					writeLine(writer, messageLine)
				}
				writeLine(writer, ".")
			case "QUIT":
				writeLine(writer, "+OK bye")
				return
			default:
				writeLine(writer, "-ERR unsupported")
			}
		}
	}()
	return listener.Addr().String()
}

func (m *fakeMailbox) record(command string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, command)
}
func (m *fakeMailbox) commandLog() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.commands...)
}

func countCommand(commands []string, verb string) int {
	count := 0
	for _, command := range commands {
		if strings.HasPrefix(command, verb+" ") || command == verb {
			count++
		}
	}
	return count
}

func writeLine(writer *bufio.Writer, value string) {
	_, _ = writer.WriteString(value + "\r\n")
	_ = writer.Flush()
}

func mailboxSize(messages []string) int {
	total := 0
	for _, message := range messages {
		total += len(message)
	}
	return total
}

func strconvAtoi(fields []string, index int) (int, error) {
	if index >= len(fields) {
		return 0, errors.New("missing")
	}
	var value int
	_, err := fmt.Sscanf(fields[index], "%d", &value)
	return value, err
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := server.TLS.Certificates[0]
	server.Close()
	return certificate
}
