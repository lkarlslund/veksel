package compatibility

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestIMAPFixtureRecordsOnlyCommandMetadata(t *testing.T) {
	fixture, err := StartIMAPFixture(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	})

	connection, err := net.DialTimeout("tcp", fixture.Address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	if greeting, err := reader.ReadString('\n'); err != nil || !strings.Contains(greeting, "* OK") {
		t.Fatalf("greeting=%q err=%v", greeting, err)
	}
	commands := []string{
		"A1 CAPABILITY",
		fmt.Sprintf("A2 LOGIN %s %s", fixture.Username, fixture.Password),
		`A3 ID ("name" "compatibility-test")`,
		`A4 LIST "" "*"`,
		`A5 SELECT "INBOX"`,
		`A6 UID FETCH 1:* (UID FLAGS RFC822.SIZE)`,
		"A7 LOGOUT",
	}
	for _, command := range commands {
		if _, err := fmt.Fprintf(connection, "%s\r\n", command); err != nil {
			t.Fatal(err)
		}
		readTaggedResponse(t, reader, strings.Fields(command)[0])
	}

	required := []string{"CAPABILITY", "LOGIN", "ID", "LIST", "SELECT", "UID FETCH", "LOGOUT"}
	waitCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	recorded, err := fixture.WaitFor(waitCtx, required)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range required {
		if !slices.Contains(recorded, command) {
			t.Errorf("missing command %q in %v", command, recorded)
		}
	}
	joined := strings.Join(recorded, " ")
	if strings.Contains(joined, fixture.Username) || strings.Contains(joined, fixture.Password) {
		t.Fatalf("credentials leaked into evidence: %q", joined)
	}
}

func readTaggedResponse(t *testing.T, reader *bufio.Reader, tag string) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read %s response: %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.Contains(line, " OK") {
				t.Fatalf("%s response: %s", tag, line)
			}
			return
		}
	}
}
