package imap

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
)

func TestQuotaCapabilitiesAreReadOnlyAndMessageScoped(t *testing.T) {
	session := &Session{cfg: &Config{}}
	capabilities := strings.Join(session.buildCapabilities(), " ")
	for _, want := range []string{"QUOTA", "QUOTA=RES-MESSAGE"} {
		if !strings.Contains(" "+capabilities+" ", " "+want+" ") {
			t.Fatalf("capabilities %q do not include %s", capabilities, want)
		}
	}
	for _, forbidden := range []string{"QUOTASET", "QUOTA=RES-STORAGE"} {
		if strings.Contains(" "+capabilities+" ", " "+forbidden+" ") {
			t.Fatalf("capabilities %q unexpectedly include %s", capabilities, forbidden)
		}
	}
}

func TestGetQuotaReportsEffectiveMailMessageLimit(t *testing.T) {
	ts := setupTestStore(t)
	if err := ts.UserStore().UpdateQuota(t.Context(), "alice", 0, 10); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := ts.ItemStore().Append(t.Context(), model.InboxFolderID("alice"), []byte("mail"), nil); err != nil {
			t.Fatal(err)
		}
	}
	calendar, err := ts.FolderStore().GetByPath(t.Context(), "alice", "Calendar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.ItemStore().Append(t.Context(), calendar.ID, []byte("event"), nil); err != nil {
		t.Fatal(err)
	}

	observed := make(chan string, 4)
	client := makeQuotaTestClient(t, ts, "alice", func(command string) { observed <- command })
	client.send("A001", "LOGIN alice secret")
	<-observed
	lines := sendQuotaCommand(t, client, `A002 GETQUOTA "#user/alice"`)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `* QUOTA "#user/alice" (MESSAGE 2 9)`) || !strings.Contains(joined, "A002 OK GETQUOTA completed") {
		t.Fatalf("GETQUOTA response = %s", joined)
	}
	if got := <-observed; got != "GETQUOTA" {
		t.Fatalf("observed command = %q", got)
	}
}

func TestGetQuotaRootUsesOwnedMailboxAndWireEncoding(t *testing.T) {
	ts := setupTestStore(t)
	if err := ts.UserStore().UpdateQuota(t.Context(), "alice", 0, 25); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().Create(t.Context(), "alice", "日本語", model.FolderTypeMail, ""); err != nil {
		t.Fatal(err)
	}
	client := makeQuotaTestClient(t, ts, "alice", nil)
	client.send("A001", "LOGIN alice secret")
	lines := sendQuotaCommand(t, client, "A002 GETQUOTAROOT &ZeVnLIqe-")
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `* QUOTAROOT "&ZeVnLIqe-" "#user/alice"`) {
		t.Fatalf("GETQUOTAROOT mailbox response = %s", joined)
	}
	if !strings.Contains(joined, `* QUOTA "#user/alice" (MESSAGE 0 25)`) {
		t.Fatalf("GETQUOTAROOT quota response = %s", joined)
	}
}

func TestQuotaUnlimitedAndForeignRootDoNotMisreportOrDisclose(t *testing.T) {
	ts := setupTestStore(t)
	client := makeQuotaTestClient(t, ts, "alice", nil)
	if _, code, _ := client.send("A000", `GETQUOTA "#user/alice"`); code != "BAD" {
		t.Fatalf("unauthenticated GETQUOTA code = %s, want BAD", code)
	}
	client.send("A001", "LOGIN alice secret")
	lines := sendQuotaCommand(t, client, `A002 GETQUOTA "#user/alice"`)
	if joined := strings.Join(lines, "\n"); !strings.Contains(joined, `* QUOTA "#user/alice" ()`) {
		t.Fatalf("unlimited GETQUOTA response = %s", joined)
	}
	if _, code, text := client.send("A003", `GETQUOTA "#user/bob"`); code != "NO" || strings.Contains(strings.ToLower(text), "bob") {
		t.Fatalf("foreign root response = %s %q", code, text)
	}
	for _, command := range []string{"GETQUOTA", "GETQUOTAROOT INBOX extra"} {
		if _, code, _ := client.send("A004", command); code != "BAD" {
			t.Fatalf("malformed %q code = %s, want BAD", command, code)
		}
	}
}

func TestGetQuotaRootDoesNotExposeSharedOwnerAccount(t *testing.T) {
	ts := setupTestStore(t)
	if err := ts.UserStore().Create(t.Context(), "bob", "Bob Test", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().CreateForUser(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	aliceInbox, err := ts.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().SetACL(t.Context(), aliceInbox.ID, "bob", "lr"); err != nil {
		t.Fatal(err)
	}
	if err := authz.SetIMAPACLBinding(t.Context(), ts, aliceInbox.ID, "bob", "lr", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().UpdateQuota(t.Context(), "alice", 0, 1234); err != nil {
		t.Fatal(err)
	}

	client := makeQuotaTestClient(t, ts, "bob", nil)
	client.send("A001", "LOGIN bob secret")
	lines := sendQuotaCommand(t, client, "A002 GETQUOTAROOT user/alice/INBOX")
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `* QUOTAROOT "user/alice/INBOX"`) || !strings.Contains(joined, "A002 OK") {
		t.Fatalf("shared GETQUOTAROOT response = %s", joined)
	}
	if strings.Contains(joined, "#user/alice") || strings.Contains(joined, "QUOTA ") || strings.Contains(joined, "1234") {
		t.Fatalf("shared GETQUOTAROOT disclosed owner quota: %s", joined)
	}
}

func makeQuotaTestClient(t *testing.T, ts *model.TypedStore, userID string, observer func(string)) *tc {
	t.Helper()
	return makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(_ context.Context, username, password string) (string, error) {
			if username == userID && password == "secret" {
				return userID, nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore:      ts,
		CommandObserver: observer,
	})
}

func sendQuotaCommand(t *testing.T, client *tc, command string) []string {
	t.Helper()
	if _, err := fmt.Fprintf(client.Conn, "%s\r\n", command); err != nil {
		t.Fatal(err)
	}
	return client.readUntagged()
}
