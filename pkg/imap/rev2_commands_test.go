package imap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func authenticatedTestClient(t *testing.T) *tc {
	t.Helper()
	store := setupTestStore(t)
	client := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore: store,
	})
	if _, code, text := client.send("A001", "LOGIN alice secret"); code != "OK" {
		t.Fatalf("LOGIN: code=%s text=%s", code, text)
	}
	return client
}

func TestNamespaceWireResponse(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, err := fmt.Fprint(client.Conn, "A002 NAMESPACE\r\n"); err != nil {
		t.Fatal(err)
	}
	lines := client.readUntagged()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `* NAMESPACE (("" "/")) NIL (("user/" "/"))`) {
		t.Fatalf("NAMESPACE response:\n%s", joined)
	}
	if !strings.Contains(joined, "A002 OK NAMESPACE completed") {
		t.Fatalf("NAMESPACE completion:\n%s", joined)
	}
}

func TestStatusUsesFolderAccountingAndMetadataFlags(t *testing.T) {
	client := authenticatedTestClient(t)
	first := []byte("Subject: first\r\n\r\none")
	second := []byte("Subject: second\r\n\r\ntwo")
	if _, code, text := client.appendMsg("A002", "INBOX", []string{"\\Seen"}, "", first); code != "OK" {
		t.Fatalf("first APPEND: code=%s text=%s", code, text)
	}
	if _, code, text := client.appendMsg("A003", "INBOX", []string{"\\Deleted"}, "", second); code != "OK" {
		t.Fatalf("second APPEND: code=%s text=%s", code, text)
	}

	if _, err := fmt.Fprint(client.Conn, "A004 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN DELETED SIZE)\r\n"); err != nil {
		t.Fatal(err)
	}
	lines := client.readUntagged()
	var status string
	for _, line := range lines {
		if strings.HasPrefix(line, "* STATUS ") {
			status = line
			break
		}
	}
	if status == "" {
		t.Fatalf("missing STATUS response: %v", lines)
	}
	for _, fragment := range []string{
		`* STATUS "INBOX" (`,
		"MESSAGES 2",
		"UIDNEXT 3",
		"UIDVALIDITY ",
		"UNSEEN 1",
		"DELETED 1",
		fmt.Sprintf("SIZE %d", len(first)+len(second)),
	} {
		if !strings.Contains(status, fragment) {
			t.Errorf("STATUS %q does not contain %q", status, fragment)
		}
	}
}

func TestStatusRejectsMalformedAndUnknownDataItems(t *testing.T) {
	client := authenticatedTestClient(t)
	for index, command := range []string{
		"STATUS INBOX MESSAGES",
		"STATUS INBOX ()",
		"STATUS INBOX (NOPE)",
	} {
		tag := fmt.Sprintf("A%03d", index+2)
		if _, code, _ := client.send(tag, command); code != "BAD" {
			t.Fatalf("%s: code=%s, want BAD", command, code)
		}
	}
}

func TestESearchReturnOptionsAndSavedResult(t *testing.T) {
	client := authenticatedTestClient(t)
	for index := 0; index < 3; index++ {
		message := []byte(fmt.Sprintf("Subject: message %d\r\n\r\nbody", index+1))
		tag := fmt.Sprintf("A%03d", index+2)
		if _, code, text := client.appendMsg(tag, "INBOX", nil, "", message); code != "OK" {
			t.Fatalf("APPEND %d: code=%s text=%s", index, code, text)
		}
	}
	if _, code, text := client.send("A005", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	if _, err := fmt.Fprint(client.Conn, "A006 SEARCH RETURN (MIN MAX ALL COUNT SAVE) ALL\r\n"); err != nil {
		t.Fatal(err)
	}
	lines := client.readUntagged()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `* ESEARCH (TAG "A006") MIN 1 MAX 3 ALL 1:3 COUNT 3`) {
		t.Fatalf("ESEARCH response:\n%s", joined)
	}

	if _, err := fmt.Fprint(client.Conn, "A007 FETCH $ (UID)\r\n"); err != nil {
		t.Fatal(err)
	}
	lines = client.readUntagged()
	joined = strings.Join(lines, "\n")
	for _, sequence := range []string{"* 1 FETCH", "* 2 FETCH", "* 3 FETCH"} {
		if !strings.Contains(joined, sequence) {
			t.Errorf("saved SEARCH result FETCH missing %s:\n%s", sequence, joined)
		}
	}
}

func TestSearchRejectsUnsupportedCharsetWithResponseCode(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, code, text := client.send("A002", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	_, code, text := client.send("A003", "SEARCH CHARSET ISO-8859-1 ALL")
	if code != "NO" || !strings.Contains(text, "[BADCHARSET (UTF-8 US-ASCII)]") {
		t.Fatalf("unsupported charset: code=%s text=%s", code, text)
	}
}

func TestSearchSaveOnlySuppressesResponseAndEmptyResultIsReusable(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, code, text := client.send("A002", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	if _, err := fmt.Fprint(client.Conn, "A003 SEARCH RETURN (SAVE) SUBJECT missing\r\n"); err != nil {
		t.Fatal(err)
	}
	lines := client.readUntagged()
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "* ESEARCH") || strings.Contains(joined, "* SEARCH") {
		t.Fatalf("SAVE-only SEARCH must suppress search data response:\n%s", joined)
	}
	if !strings.Contains(joined, "A003 OK SEARCH completed") {
		t.Fatalf("SAVE-only completion missing:\n%s", joined)
	}
	if _, err := fmt.Fprint(client.Conn, "A004 FETCH $ (UID)\r\n"); err != nil {
		t.Fatal(err)
	}
	lines = client.readUntagged()
	joined = strings.Join(lines, "\n")
	if strings.Contains(joined, "* ") || !strings.Contains(joined, "A004 OK FETCH completed") {
		t.Fatalf("empty saved result must be a valid non-matching set:\n%s", joined)
	}
}

func TestSavedSearchTranslatesBetweenSequenceAndUIDContexts(t *testing.T) {
	client := authenticatedTestClient(t)
	for index := 0; index < 3; index++ {
		message := []byte(fmt.Sprintf("Subject: message %d\r\n\r\nbody", index+1))
		if _, code, text := client.appendMsg(fmt.Sprintf("A%03d", index+2), "INBOX", nil, "", message); code != "OK" {
			t.Fatalf("APPEND: code=%s text=%s", code, text)
		}
	}
	if _, code, text := client.send("A005", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	if _, code, text := client.send("A006", "STORE 2 +FLAGS (\\Deleted)"); code != "OK" {
		t.Fatalf("STORE: code=%s text=%s", code, text)
	}
	if _, code, text := client.send("A007", "EXPUNGE"); code != "OK" {
		t.Fatalf("EXPUNGE: code=%s text=%s", code, text)
	}
	if _, code, text := client.send("A008", "SEARCH RETURN (SAVE) ALL"); code != "OK" {
		t.Fatalf("SEARCH SAVE: code=%s text=%s", code, text)
	}
	if _, err := fmt.Fprint(client.Conn, "A009 UID FETCH $ (UID)\r\n"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(client.readUntagged(), "\n")
	if !strings.Contains(joined, "UID 1") || !strings.Contains(joined, "UID 3") || strings.Contains(joined, "UID 2") {
		t.Fatalf("sequence SEARCH result did not translate to UID set:\n%s", joined)
	}

	if _, code, text := client.send("A010", "UID SEARCH RETURN (SAVE) ALL"); code != "OK" {
		t.Fatalf("UID SEARCH SAVE: code=%s text=%s", code, text)
	}
	if _, err := fmt.Fprint(client.Conn, "A011 FETCH $ (UID)\r\n"); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(client.readUntagged(), "\n")
	if !strings.Contains(joined, "* 1 FETCH") || !strings.Contains(joined, "* 2 FETCH") {
		t.Fatalf("UID SEARCH result did not translate to sequence set:\n%s", joined)
	}
}

func TestSortSavePopulatesSearchResultWithoutSortResponse(t *testing.T) {
	client := authenticatedTestClient(t)
	for index, subject := range []string{"Charlie", "Alpha", "Bravo"} {
		message := []byte(fmt.Sprintf("Subject: %s\r\n\r\nbody", subject))
		if _, code, text := client.appendMsg(fmt.Sprintf("A%03d", index+2), "INBOX", nil, "", message); code != "OK" {
			t.Fatalf("APPEND: code=%s text=%s", code, text)
		}
	}
	if _, code, text := client.send("A005", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	if _, err := fmt.Fprint(client.Conn, "A006 SORT RETURN (SAVE) (SUBJECT) UTF-8 ALL\r\n"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(client.readUntagged(), "\n")
	if strings.Contains(joined, "* SORT") || !strings.Contains(joined, "A006 OK SORT completed") {
		t.Fatalf("SORT SAVE response:\n%s", joined)
	}
	if _, err := fmt.Fprint(client.Conn, "A007 UID FETCH $ (UID)\r\n"); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(client.readUntagged(), "\n")
	for _, uid := range []string{"UID 1", "UID 2", "UID 3"} {
		if !strings.Contains(joined, uid) {
			t.Errorf("saved SORT result missing %s:\n%s", uid, joined)
		}
	}
}

func TestRev2SearchUsesESearchByDefault(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	session := newSession(1, &Config{}, server, nil, nil, nil)
	defer session.cancel()
	session.rev2Enabled = true
	done := make(chan struct{})
	go func() {
		session.sendSearchResults("A001", []int{1, 2, 3}, searchReturnOptions{}, false)
		close(done)
	}()
	reader := bufio.NewReader(client)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	second, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if first != "* ESEARCH (TAG \"A001\") ALL 1:3\r\n" || second != "A001 OK SEARCH completed\r\n" {
		t.Fatalf("rev2 SEARCH response = %q %q", first, second)
	}
}

func TestRev2SelectResponsesAndReplacementSemantics(t *testing.T) {
	typedStore := setupTestStore(t)
	config := &Config{TypedStore: typedStore}
	serverSide, clientSide := net.Pipe()
	defer func() { _ = serverSide.Close() }()
	defer func() { _ = clientSide.Close() }()
	server := New(config)
	session := newSession(1, config, serverSide, server, nil, nil)
	defer session.cancel()
	session.userID = "alice"
	session.authenticated = true
	session.curState = stateAuthenticated
	session.rev2Enabled = true
	reader := bufio.NewReader(clientSide)

	selectAndRead := func(tag, mailbox string) string {
		t.Helper()
		done := make(chan struct{})
		go func() {
			session.selectMailbox(tag, mailbox, false, nil)
			close(done)
		}()
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, strings.TrimRight(line, "\r\n"))
			if strings.HasPrefix(line, tag+" ") {
				break
			}
		}
		<-done
		return strings.Join(lines, "\n")
	}

	first := selectAndRead("A001", "INBOX")
	for _, required := range []string{"* FLAGS (", "* OK [PERMANENTFLAGS (", `* LIST (\HasNoChildren \Subscribed \Inbox) "/" "INBOX"`, "A001 OK [READ-WRITE]"} {
		if !strings.Contains(first, required) {
			t.Errorf("initial rev2 SELECT missing %q:\n%s", required, first)
		}
	}
	if strings.Contains(first, " RECENT") {
		t.Errorf("rev2 SELECT emitted deprecated RECENT:\n%s", first)
	}

	second := selectAndRead("A002", "Archive")
	if !strings.Contains(second, "* OK [CLOSED] Previous mailbox closed") {
		t.Fatalf("replacement SELECT missing CLOSED:\n%s", second)
	}
	selectedID := session.selectedFolderID
	failed := selectAndRead("A003", "Missing")
	if !strings.Contains(failed, "A003 NO ") {
		t.Fatalf("missing mailbox SELECT response:\n%s", failed)
	}
	if session.selectedFolderID != selectedID || session.selectedFolder.Path != "Archive" {
		t.Fatalf("failed SELECT changed selection to %#v", session.selectedFolder)
	}
}

func TestCopyAndMoveUseTaggedCopyUIDAndTryCreate(t *testing.T) {
	client := authenticatedTestClient(t)
	message := []byte("Subject: copy me\r\n\r\nbody")
	if _, code, text := client.appendMsg("A002", "INBOX", nil, "", message); code != "OK" {
		t.Fatalf("APPEND: code=%s text=%s", code, text)
	}
	if _, code, text := client.send("A003", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	for tag, command := range map[string]string{
		"A004": "COPY 1 Missing",
		"A005": "UID COPY 1 Missing",
		"A006": "MOVE 1 Missing",
		"A007": "UID MOVE 1 Missing",
	} {
		_, code, text := client.send(tag, command)
		if code != "NO" || !strings.Contains(text, "[TRYCREATE]") {
			t.Errorf("%s: code=%s text=%s", command, code, text)
		}
	}

	_, code, text := client.send("A008", "COPY 1 Archive")
	if code != "OK" || !strings.Contains(text, "[COPYUID ") {
		t.Fatalf("COPY tagged result: code=%s text=%s", code, text)
	}
	_, code, text = client.send("A009", "UID COPY 1 Archive")
	if code != "OK" || !strings.Contains(text, "[COPYUID ") {
		t.Fatalf("UID COPY tagged result: code=%s text=%s", code, text)
	}
	// RFC 6851 4.3: MOVE reports COPYUID in an untagged OK before the
	// expunge, which precedes the tagged completion.
	lines := client.exchange(t, "A010", "MOVE 1 Archive")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "* OK [COPYUID ") || lines[1] != "* 1 EXPUNGE" || !strings.HasPrefix(lines[2], "A010 OK") {
		t.Fatalf("MOVE result: %q", lines)
	}
}

func TestEnableSyntaxAndState(t *testing.T) {
	client := authenticatedTestClient(t)
	if _, code, _ := client.send("A002", "ENABLE"); code != "BAD" {
		t.Fatalf("argument-free ENABLE code=%s, want BAD", code)
	}
	if _, code, _ := client.send("A003", "ENABLE (CONDSTORE)"); code != "BAD" {
		t.Fatalf("invalid ENABLE atom code=%s, want BAD", code)
	}
	if _, code, text := client.send("A004", "ENABLE UNKNOWN"); code != "OK" {
		t.Fatalf("unknown ENABLE capability: code=%s text=%s", code, text)
	}
	if _, code, text := client.send("A005", "SELECT INBOX"); code != "OK" {
		t.Fatalf("SELECT: code=%s text=%s", code, text)
	}
	if _, code, _ := client.send("A006", "ENABLE CONDSTORE"); code != "BAD" {
		t.Fatalf("selected-state ENABLE code=%s, want BAD", code)
	}
}
