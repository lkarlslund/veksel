package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/imap"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

func TestIMAPStateSurvivesRepeatedServerAndStoreRestarts(t *testing.T) {
	for _, engine := range []store.Backend{store.BackendPebble, store.BackendBadger} {
		t.Run(string(engine), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mailbox")
			var uidValidity uint64
			var highestModSeq uint64
			for cycle := range 5 {
				backend := openRestartStore(t, engine, path)
				typed := model.NewTypedStore(backend, engine)
				if cycle == 0 {
					for _, namespace := range model.Namespaces() {
						if err := typed.EnsureNamespace(t.Context(), namespace); err != nil {
							t.Fatal(err)
						}
					}
					if err := typed.UserStore().Create(t.Context(), "alice", "Alice", "secret"); err != nil {
						t.Fatal(err)
					}
					if err := typed.FolderStore().CreateForUser(t.Context(), "alice"); err != nil {
						t.Fatal(err)
					}
				}
				server := imap.New(&imap.Config{
					ServerName: "restart-test", TypedStore: typed,
					AuthValidator: func(ctx context.Context, username, password string) (string, error) {
						user, err := typed.UserStore().Get(ctx, username)
						if err != nil || !auth.ComparePassword(password, user.PasswordHash) {
							return "", fmt.Errorf("invalid credentials")
						}
						return user.ID, nil
					},
				})
				listener, err := server.Listen("127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				serverCtx, cancel := context.WithCancel(t.Context())
				go server.Accept(serverCtx, listener)
				client := dialRestartIMAP(t, listener.Addr().String())
				if _, code, text := client.cmd("A1", "LOGIN alice secret"); code != "OK" {
					t.Fatalf("cycle %d LOGIN = %s %s", cycle, code, text)
				}
				lines := selectRestartInbox(t, client, "A2")
				gotUIDValidity := responseNumber(lines, "UIDVALIDITY")
				gotModSeq := responseNumber(lines, "HIGHESTMODSEQ")
				gotExists := existsCount(lines)
				if cycle == 0 {
					uidValidity = gotUIDValidity
				} else if gotUIDValidity != uidValidity {
					t.Fatalf("cycle %d UIDVALIDITY = %d, want %d", cycle, gotUIDValidity, uidValidity)
				}
				if gotModSeq < highestModSeq {
					t.Fatalf("cycle %d HIGHESTMODSEQ regressed from %d to %d", cycle, highestModSeq, gotModSeq)
				}
				highestModSeq = gotModSeq
				if gotExists != cycle {
					t.Fatalf("cycle %d EXISTS = %d", cycle, gotExists)
				}
				message := []byte(fmt.Sprintf("Subject: restart %d\r\n\r\nbody\r\n", cycle))
				appendLines := appendRestartMessage(t, client, "A3", message)
				if !containsResponse(appendLines, fmt.Sprintf("APPENDUID %d %d", uidValidity, cycle+1)) {
					t.Fatalf("cycle %d APPEND responses = %q, expected UIDVALIDITY=%d UID=%d; SELECT=%q", cycle, appendLines, uidValidity, cycle+1, lines)
				}
				_ = client.Close()
				cancel()
				_ = server.Close()
				if err := backend.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func appendRestartMessage(t *testing.T, client *imapClient, tag string, message []byte) []string {
	t.Helper()
	if _, err := fmt.Fprintf(client.Conn, "%s APPEND INBOX {%d}\r\n", tag, len(message)); err != nil {
		t.Fatal(err)
	}
	continuation, err := client.readLine()
	if err != nil || !strings.HasPrefix(continuation, "+") {
		t.Fatalf("APPEND continuation = %q, %v", continuation, err)
	}
	if _, err := client.Write(append(message, '\r', '\n')); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for {
		line, err := client.readLine()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, tag+" ") {
			if !strings.Contains(line, " OK") {
				t.Fatalf("APPEND = %q", line)
			}
			return lines
		}
	}
}

func containsResponse(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func openRestartStore(t *testing.T, engine store.Backend, path string) store.Store {
	t.Helper()
	var (
		backend store.Store
		err     error
	)
	if engine == store.BackendPebble {
		backend, err = pebblestore.New(path)
	} else {
		backend, err = badgerstore.New(path)
	}
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func dialRestartIMAP(t *testing.T, address string) *imapClient {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := &imapClient{Conn: connection, r: bufio.NewReader(connection)}
	if greeting, err := client.readLine(); err != nil || !strings.HasPrefix(greeting, "* OK") {
		_ = connection.Close()
		t.Fatalf("greeting = %q, %v", greeting, err)
	}
	return client
}

func selectRestartInbox(t *testing.T, client *imapClient, tag string) []string {
	t.Helper()
	if _, err := fmt.Fprintf(client.Conn, "%s SELECT INBOX\r\n", tag); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for {
		line, err := client.readLine()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, tag+" ") {
			if !strings.Contains(line, " OK") {
				t.Fatalf("SELECT = %q", line)
			}
			return lines
		}
	}
}

func responseNumber(lines []string, name string) uint64 {
	needle := name + " "
	for _, line := range lines {
		index := strings.Index(line, needle)
		if index < 0 {
			continue
		}
		value := strings.Fields(line[index+len(needle):])[0]
		value = strings.TrimRight(value, "])")
		number, _ := strconv.ParseUint(value, 10, 64)
		return number
	}
	return 0
}

func existsCount(lines []string) int {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "*" && fields[2] == "EXISTS" {
			count, _ := strconv.Atoi(fields[1])
			return count
		}
	}
	return -1
}
