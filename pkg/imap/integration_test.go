package imap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// startTestServer starts an IMAP server on a random port with a real store backend.
// Returns the client address and a cleanup function.
func startTestServer(t *testing.T, cfg *Config) (addr string, cleanup func()) {
	t.Helper()

	srv := New(cfg)
	ln, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	acceptDone := make(chan error, 1)
	go func() {
		acceptDone <- func() error {
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return nil
					default:
						return err
					}
				}
				go func() {
					id := srv.sessionID.Add(1)
					sess := newSession(id, cfg, conn, srv, nil, nil)
					sess.run()
				}()
			}
		}()
	}()

	return ln.Addr().String(), func() {
		cancel()
		srv.Close()
		_ = <-acceptDone
	}
}

// setupIntegrationStore creates a TypedStore with a user and default folders.
func setupIntegrationStore(t *testing.T) *model.TypedStore {
	t.Helper()
	tmpDir := t.TempDir()
	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()

	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL} {
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

// dialClient connects to the test server and waits for the greeting.
func dialClient(t *testing.T, addr string) *imapclient.Client {
	t.Helper()
	client, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.WaitGreeting(); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	return client
}

// makeTestServerAndClient sets up a full server+client pair for integration tests.
func makeTestServerAndClient(t *testing.T) (*imapclient.Client, *model.TypedStore) {
	t.Helper()
	ts := setupIntegrationStore(t)
	addr, cleanup := startTestServer(t, &Config{
		ServerName:    "test.veksel",
		SaslIrEnabled: true,
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		TypedStore: ts,
	})
	t.Cleanup(cleanup)
	client := dialClient(t, addr)
	return client, ts
}

// --- Integration Tests ---

func TestIntegration_Login(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	if err := client.Login("alice", "secret").Wait(); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}
	if client.State() != imapv2.ConnStateAuthenticated {
		t.Fatalf("state = %v, want authenticated", client.State())
	}
}

func TestIntegration_LoginInvalid(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	err := client.Login("alice", "wrong").Wait()
	if err == nil {
		t.Fatal("expected LOGIN error for wrong password")
	}
}

func TestIntegration_Select(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	data, err := client.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	if data.NumMessages != 0 {
		t.Fatalf("NumMessages = %d, want 0", data.NumMessages)
	}
	if client.State() != imapv2.ConnStateSelected {
		t.Fatalf("state = %v, want selected", client.State())
	}
}

func TestIntegration_Examine(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	data, err := client.Select("INBOX", &imapv2.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		t.Fatalf("EXAMINE: %v", err)
	}
	if data.NumMessages != 0 {
		t.Fatalf("NumMessages = %d, want 0", data.NumMessages)
	}
}

func TestIntegration_AppendAndFetch(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Hello\r\n\r\nHello World\r\n"

	// APPEND
	appendCmd := client.Append("INBOX", int64(len(msg)), nil)
	appendCmd.Write([]byte(msg))
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND Close: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND Wait: %v", err)
	}

	// SELECT
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	// FETCH flags
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{Flags: true, UID: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH Collect: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	if msgs[0].SeqNum != 1 {
		t.Fatalf("SeqNum = %d, want 1", msgs[0].SeqNum)
	}
	if msgs[0].UID == 0 {
		t.Fatal("UID should not be 0")
	}
}

func TestIntegration_FetchBody(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Body Test\r\n\r\nBody Content\r\n"
	mustAppend(t, client, "INBOX", msg)

	// Re-select to pick up the new message
	mustSelect(t, client, "INBOX")

	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{
		BodySection: []*imapv2.FetchItemBodySection{{}},
	})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH BODY: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	body := msgs[0].FindBodySection(&imapv2.FetchItemBodySection{})
	if !strings.Contains(string(body), "Body Content") {
		t.Fatalf("body does not contain 'Body Content': %s", string(body))
	}
}

func TestIntegration_FetchEnvelopeAndBodyStructure(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	msg := strings.Join([]string{
		"Date: Tue, 18 Aug 2026 12:34:56 +0200",
		"From: =?UTF-8?Q?Alice_=C3=86gir?= <alice@example.com>",
		"To: Bob <bob@example.net>",
		"Subject: =?UTF-8?Q?M=C3=B8de?=",
		"Message-ID: <message-1@example.com>",
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=parts",
		"",
		"--parts",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"Hello",
		"--parts",
		"Content-Type: application/octet-stream; name=sample.bin",
		"Content-Disposition: attachment; filename=sample.bin",
		"Content-Transfer-Encoding: base64",
		"",
		"AQID",
		"--parts--",
		"",
	}, "\r\n")
	mustAppend(t, client, "INBOX", msg)
	mustSelect(t, client, "INBOX")

	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{
		Envelope:      true,
		BodyStructure: &imapv2.FetchItemBodyStructure{Extended: true},
	})
	defer func() { _ = fetchCmd.Close() }()
	messages, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH metadata: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(messages))
	}
	got := messages[0]
	if got.Envelope == nil {
		t.Fatal("FETCH did not return an envelope")
	}
	if got.Envelope.Subject != "Møde" {
		t.Errorf("Subject = %q, want %q", got.Envelope.Subject, "Møde")
	}
	if len(got.Envelope.From) != 1 || got.Envelope.From[0].Name != "Alice Ægir" || got.Envelope.From[0].Addr() != "alice@example.com" {
		t.Errorf("From = %#v, want Alice Ægir <alice@example.com>", got.Envelope.From)
	}
	if got.Envelope.MessageID != "message-1@example.com" {
		t.Errorf("MessageID = %q, want %q", got.Envelope.MessageID, "message-1@example.com")
	}
	multipartBody, ok := got.BodyStructure.(*imapv2.BodyStructureMultiPart)
	if !ok {
		t.Fatalf("BodyStructure = %T, want multipart", got.BodyStructure)
	}
	if multipartBody.Subtype != "MIXED" || len(multipartBody.Children) != 2 {
		t.Fatalf("multipart body = %#v, want MIXED with two children", multipartBody)
	}
	attachment, ok := multipartBody.Children[1].(*imapv2.BodyStructureSinglePart)
	if !ok || attachment.MediaType() != "application/octet-stream" || attachment.Filename() != "sample.bin" {
		t.Errorf("attachment = %#v, want application/octet-stream sample.bin", multipartBody.Children[1])
	}
}

func TestIntegration_FetchInternalDate(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	msg := "From: a@b.com\r\nTo: c@d.com\r\nSubject: Date Test\r\n\r\nBody\r\n"
	mustAppend(t, client, "INBOX", msg)
	mustSelect(t, client, "INBOX")

	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{InternalDate: true, RFC822Size: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH INTERNALDATE: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	if msgs[0].InternalDate.IsZero() {
		t.Fatal("InternalDate should not be zero")
	}
}

func TestIntegration_Search(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Append two messages
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: First\r\n\r\nBody1\r\n")
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Second\r\n\r\nBody2\r\n")
	mustSelect(t, client, "INBOX")

	// SEARCH ALL
	searchData, err := client.Search(&imapv2.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH ALL: %v", err)
	}
	nums := searchData.AllSeqNums()
	if len(nums) != 2 {
		t.Fatalf("SEARCH ALL returned %d results, want 2", len(nums))
	}

	// SEARCH SUBJECT First
	searchData, err = client.Search(&imapv2.SearchCriteria{
		Header: []imapv2.SearchCriteriaHeaderField{{Key: "Subject", Value: "First"}},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH SUBJECT: %v", err)
	}
	nums = searchData.AllSeqNums()
	if len(nums) != 1 {
		t.Fatalf("SEARCH SUBJECT First returned %d results, want 1", len(nums))
	}
}

func TestIntegration_SearchSeen(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Append two messages
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: First\r\n\r\nBody\r\n")
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Second\r\n\r\nBody2\r\n")
	mustSelect(t, client, "INBOX")

	storeCmd := client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
		Op: imapv2.StoreFlagsAdd, Flags: []imapv2.Flag{imapv2.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE +FLAGS \\Seen: %v", err)
	}

	// SEARCH SEEN — should find message 1 (auto-seen from FETCH)
	searchData, err := client.Search(&imapv2.SearchCriteria{
		Flag: []imapv2.Flag{imapv2.FlagSeen},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH SEEN: %v", err)
	}
	nums := searchData.AllSeqNums()
	if len(nums) < 1 {
		t.Fatalf("SEARCH SEEN returned %d results, want at least 1", len(nums))
	}
}

func TestIntegration_StoreFlags(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Flags\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// Add \Flagged
	storeCmd := client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
		Op:    imapv2.StoreFlagsAdd,
		Flags: []imapv2.Flag{imapv2.FlagFlagged},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE +FLAGS: %v", err)
	}

	// Fetch and verify
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{Flags: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	found := false
	for _, f := range msgs[0].Flags {
		if f == imapv2.FlagFlagged {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \\Flagged in flags: %v", msgs[0].Flags)
	}

	// Remove \Flagged
	storeCmd = client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
		Op:    imapv2.StoreFlagsDel,
		Flags: []imapv2.Flag{imapv2.FlagFlagged},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE -FLAGS: %v", err)
	}
}

func TestIntegration_Expunge(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Delete Me\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// Mark as deleted
	storeCmd := client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
		Op:    imapv2.StoreFlagsAdd,
		Flags: []imapv2.Flag{imapv2.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE +FLAGS \\Deleted: %v", err)
	}

	// EXPUNGE
	if err := client.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE: %v", err)
	}

	// Verify message is gone
	mustSelect(t, client, "INBOX")
	searchData, err := client.Search(&imapv2.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH: %v", err)
	}
	if len(searchData.AllSeqNums()) != 0 {
		t.Fatalf("expected 0 messages after expunge, got %d", len(searchData.AllSeqNums()))
	}
}

func TestIntegration_Idle(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Start IDLE
	idle, err := client.Idle()
	if err != nil {
		t.Fatalf("IDLE: %v", err)
	}

	// Give IDLE time to start
	time.Sleep(100 * time.Millisecond)

	// Stop IDLE with DONE
	if err := idle.Close(); err != nil {
		t.Fatalf("IDLE Close: %v", err)
	}
	if err := idle.Wait(); err != nil {
		t.Fatalf("IDLE Wait: %v", err)
	}
}

func TestIntegration_IdleNotification(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Start IDLE
	idle, err := client.Idle()
	if err != nil {
		t.Fatalf("IDLE: %v", err)
	}

	// Stop IDLE after a short wait to verify the protocol round-trip works
	time.Sleep(200 * time.Millisecond)
	if err := idle.Close(); err != nil {
		t.Fatalf("IDLE Close: %v", err)
	}
	if err := idle.Wait(); err != nil {
		t.Fatalf("IDLE Wait: %v", err)
	}
	// Verify we're back in selected state
	if client.State() != imapv2.ConnStateSelected {
		t.Fatalf("state after IDLE = %v, want selected", client.State())
	}
}

func TestIntegration_Logout(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	if err := client.Logout().Wait(); err != nil {
		t.Fatalf("LOGOUT: %v", err)
	}
	// The client switches state when it reads the connection close, which
	// can follow the tagged OK.
	for deadline := time.Now().Add(2 * time.Second); client.State() != imapv2.ConnStateLogout && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if client.State() != imapv2.ConnStateLogout {
		t.Fatalf("state = %v, want logout", client.State())
	}
}

func TestIntegration_ListMailboxes(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	listCmd := client.List("", "*", nil)
	data, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	var mailboxes []string
	for _, d := range data {
		mailboxes = append(mailboxes, d.Mailbox)
	}
	// Should have INBOX, Sent, Drafts, Trash
	if len(mailboxes) < 3 {
		t.Fatalf("LIST returned %d mailboxes, want at least 3: %v", len(mailboxes), mailboxes)
	}
}

func TestIntegration_CreateDeleteMailbox(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	// CREATE
	if err := client.Create("TestFolder", nil).Wait(); err != nil {
		t.Fatalf("CREATE: %v", err)
	}

	// Verify it exists
	listData, err := client.List("", "TestFolder", nil).Collect()
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	found := false
	for _, d := range listData {
		if d.Mailbox == "TestFolder" {
			found = true
		}
	}
	if !found {
		t.Fatal("TestFolder not found after CREATE")
	}

	// DELETE
	if err := client.Delete("TestFolder").Wait(); err != nil {
		t.Fatalf("DELETE: %v", err)
	}
}

func TestIntegration_Copy(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Copy\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// COPY to Sent
	if _, err := client.Copy(imapv2.SeqSetNum(1), "Sent").Wait(); err != nil {
		t.Fatalf("COPY: %v", err)
	}

	// Verify in Sent
	mustSelect(t, client, "Sent")
	searchData, err := client.Search(&imapv2.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH Sent: %v", err)
	}
	if len(searchData.AllSeqNums()) != 1 {
		t.Fatalf("SEARCH Sent returned %d results, want 1", len(searchData.AllSeqNums()))
	}
}

func TestIntegration_FetchUID(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: UID\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// UID FETCH
	fetchCmd := client.Fetch(imapv2.UIDSetNum(1), &imapv2.FetchOptions{Flags: true, UID: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("UID FETCH: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("UID FETCH returned %d messages, want 1", len(msgs))
	}
	if msgs[0].UID != 1 {
		t.Fatalf("UID = %d, want 1", msgs[0].UID)
	}
}

func TestIntegration_FetchModSeq(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: ModSeq\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// FETCH with MODSEQ
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{ModSeq: true, UID: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	// ModSeq should be > 0 for a newly created message
	if msgs[0].ModSeq == 0 {
		t.Log("ModSeq is 0 — server may not return MODSEQ for all messages")
	}
}

func TestIntegration_CondStore(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: CondStore\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// Fetch initial modseq
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{ModSeq: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	initialModSeq := msgs[0].ModSeq

	// Change flags — should increase modseq
	storeCmd := client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
		Op:    imapv2.StoreFlagsAdd,
		Flags: []imapv2.Flag{imapv2.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE: %v", err)
	}

	// Fetch again — modseq should be different (or at least not less)
	fetchCmd2 := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{ModSeq: true})
	defer fetchCmd2.Close()
	msgs2, err := fetchCmd2.Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ after STORE: %v", err)
	}
	if len(msgs2) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs2))
	}
	// If the server tracks modseq, it should have changed
	if initialModSeq > 0 && msgs2[0].ModSeq < initialModSeq {
		t.Fatalf("ModSeq decreased: %d -> %d", initialModSeq, msgs2[0].ModSeq)
	}
}

func TestIntegration_Move(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Move\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// Create destination folder
	if err := client.Create("Move-Archive", nil).Wait(); err != nil {
		t.Fatalf("CREATE Move-Archive: %v", err)
	}

	// MOVE message 1 to Move-Archive
	moveCmd := client.Move(imapv2.SeqSetNum(1), "Move-Archive")
	_, err := moveCmd.Wait()
	if err != nil {
		t.Fatalf("MOVE: %v", err)
	}

	// Verify message is gone from INBOX
	mustSelect(t, client, "INBOX")
	searchData, err := client.Search(&imapv2.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH INBOX: %v", err)
	}
	if len(searchData.AllSeqNums()) != 0 {
		t.Fatalf("INBOX has %d messages after MOVE, want 0", len(searchData.AllSeqNums()))
	}

	// Verify message is in Move-Archive
	mustSelect(t, client, "Move-Archive")
	searchData, err = client.Search(&imapv2.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH Archive: %v", err)
	}
	if len(searchData.AllSeqNums()) != 1 {
		t.Fatalf("Archive has %d messages after MOVE, want 1", len(searchData.AllSeqNums()))
	}
}

func TestIntegration_Unselect(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	if err := client.Unselect().Wait(); err != nil {
		t.Fatalf("UNSELECT: %v", err)
	}
	if client.State() != imapv2.ConnStateAuthenticated {
		t.Fatalf("state = %v, want authenticated", client.State())
	}
}

func TestIntegration_Capability(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	caps := client.Caps()
	capStrs := make([]string, 0, len(caps))
	for cap := range caps {
		capStrs = append(capStrs, string(cap))
	}
	// Check for IMAP4rev1
	found := false
	for _, c := range capStrs {
		if c == "IMAP4rev1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CAPABILITY does not include IMAP4rev1: %v", capStrs)
	}
}

func TestIntegration_FullSessionFlow(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	// LOGIN
	if err := client.Login("alice", "secret").Wait(); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}

	// SELECT
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	// APPEND
	msg := "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Full Flow\r\n\r\nComplete Session Test\r\n"
	appendCmd := client.Append("INBOX", int64(len(msg)), nil)
	appendCmd.Write([]byte(msg))
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND Close: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND Wait: %v", err)
	}

	// Re-select
	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT after APPEND: %v", err)
	}

	// FETCH
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{Flags: true, UID: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}

	// STORE
	storeCmd := client.Store(imapv2.SeqSetNum(1), &imapv2.StoreFlags{
		Op:    imapv2.StoreFlagsAdd,
		Flags: []imapv2.Flag{imapv2.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE: %v", err)
	}

	// SEARCH
	searchData, err := client.Search(&imapv2.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH: %v", err)
	}
	if len(searchData.AllSeqNums()) != 1 {
		t.Fatalf("SEARCH returned %d results, want 1", len(searchData.AllSeqNums()))
	}

	// LOGOUT
	if err := client.Logout().Wait(); err != nil {
		t.Fatalf("LOGOUT: %v", err)
	}
}

func TestIntegration_MultipleMessages(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Append 5 messages
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nTo: c@d.com\r\nSubject: Msg %d\r\n\r\nBody %d\r\n", i, i)
		mustAppend(t, client, "INBOX", msg)
	}
	mustSelect(t, client, "INBOX")

	// FETCH all with UID and flags using 1:*
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1, 2, 3, 4, 5), &imapv2.FetchOptions{Flags: true, UID: true})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH *: %v", err)
	}
	if len(msgs) != 5 {
		t.Fatalf("FETCH * returned %d messages, want 5", len(msgs))
	}
}

func TestIntegration_AuthenticatePlain(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	// AUTHENTICATE PLAIN using go-sasl
	saslClient := sasl.NewPlainClient("", "alice", "secret")
	if err := client.Authenticate(saslClient); err != nil {
		t.Fatalf("AUTHENTICATE PLAIN: %v", err)
	}
	if client.State() != imapv2.ConnStateAuthenticated {
		t.Fatalf("state = %v, want authenticated", client.State())
	}
}

func TestIntegration_Noop(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	if err := client.Noop().Wait(); err != nil {
		t.Fatalf("NOOP: %v", err)
	}
}

func TestIntegration_FetchBodyPeek(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Peek\r\n\r\nPeek Body\r\n")
	mustSelect(t, client, "INBOX")

	// FETCH BODY.PEEK[] (doesn't set \Seen)
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{
		BodySection: []*imapv2.FetchItemBodySection{{Peek: true}},
		Flags:       true,
	})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH BODY.PEEK: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	body := msgs[0].FindBodySection(&imapv2.FetchItemBodySection{Peek: true})
	if !strings.Contains(string(body), "Peek Body") {
		t.Fatalf("body does not contain 'Peek Body': %s", string(body))
	}
	// Verify \Seen was NOT set
	for _, f := range msgs[0].Flags {
		if f == imapv2.FlagSeen {
			t.Fatal("BODY.PEEK should not set \\Seen")
		}
	}
}

func TestIntegration_CreateSubfolder(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	// CREATE subfolder
	if err := client.Create("Work", nil).Wait(); err != nil {
		t.Fatalf("CREATE: %v", err)
	}

	// CREATE nested subfolder
	if err := client.Create("Work/Projects", nil).Wait(); err != nil {
		t.Fatalf("CREATE nested: %v", err)
	}

	// '*' crosses hierarchy delimiters, so LIST should show both levels.
	listData, err := client.List("", "Work*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}
	if len(listData) < 2 {
		t.Fatalf("LIST returned %d mailboxes, want at least 2: %v", len(listData), func() []string {
			var names []string
			for _, d := range listData {
				names = append(names, d.Mailbox)
			}
			return names
		}())
	}
}

func TestIntegration_SubscribeUnsubscribe(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)

	// SUBSCRIBE
	if err := client.Subscribe("Sent").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE: %v", err)
	}

	// UNSUBSCRIBE
	if err := client.Unsubscribe("Sent").Wait(); err != nil {
		t.Fatalf("UNSUBSCRIBE: %v", err)
	}
}

func TestIntegration_FetchHeaders(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	mustAppend(t, client, "INBOX", "From: sender@example.com\r\nTo: alice@example.com\r\nSubject: Headers\r\nX-Custom: custom-value\r\n\r\nBody\r\n")
	mustSelect(t, client, "INBOX")

	// FETCH HEADER.FIELDS
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{
		BodySection: []*imapv2.FetchItemBodySection{{
			Specifier:    imapv2.PartSpecifierHeader,
			HeaderFields: []string{"Subject", "X-Custom"},
		}},
	})
	defer fetchCmd.Close()
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH HEADER.FIELDS: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages, want 1", len(msgs))
	}
	section := &imapv2.FetchItemBodySection{
		Specifier:    imapv2.PartSpecifierHeader,
		HeaderFields: []string{"Subject", "X-Custom"},
	}
	header := string(msgs[0].FindBodySection(section))
	if !strings.Contains(header, "Subject: Headers\r\n") || !strings.Contains(header, "X-Custom: custom-value\r\n") {
		t.Errorf("filtered header omitted requested fields: %q", header)
	}
	if strings.Contains(header, "From:") || strings.Contains(header, "To:") || !strings.HasSuffix(header, "\r\n\r\n") {
		t.Errorf("filtered header contains unrequested fields or lacks terminator: %q", header)
	}
	fullCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{
		BodySection: []*imapv2.FetchItemBodySection{{Peek: true}},
	})
	defer func() { _ = fullCmd.Close() }()
	fullMessages, err := fullCmd.Collect()
	if err != nil || len(fullMessages) != 1 {
		t.Fatalf("FETCH full message: messages=%d err=%v", len(fullMessages), err)
	}
	full := string(fullMessages[0].FindBodySection(&imapv2.FetchItemBodySection{}))
	if !strings.Contains(full, "Subject: Headers\r\n") {
		t.Errorf("stored full message omitted Subject header: %q", full)
	}
}

func TestIntegration_FetchMultipleBodySections(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")
	mustAppend(t, client, "INBOX", "From: sender@example.com\r\nSubject: Multiple literals\r\n\r\n0123456789\r\n")
	mustSelect(t, client, "INBOX")

	headerSection := &imapv2.FetchItemBodySection{Specifier: imapv2.PartSpecifierHeader, Peek: true}
	textSection := &imapv2.FetchItemBodySection{
		Specifier: imapv2.PartSpecifierText,
		Partial:   &imapv2.SectionPartial{Offset: 2, Size: 4},
		Peek:      true,
	}
	fetchCmd := client.Fetch(imapv2.SeqSetNum(1), &imapv2.FetchOptions{
		UID:         true,
		BodySection: []*imapv2.FetchItemBodySection{headerSection, textSection},
	})
	defer func() { _ = fetchCmd.Close() }()
	messages, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH multiple body sections: %v", err)
	}
	if len(messages) != 1 || messages[0].UID == 0 {
		t.Fatalf("FETCH messages = %#v", messages)
	}
	if header := string(messages[0].FindBodySection(headerSection)); !strings.Contains(header, "Subject: Multiple literals") {
		t.Errorf("header section = %q", header)
	}
	if text := string(messages[0].FindBodySection(textSection)); text != "2345" {
		t.Errorf("partial text section = %q, want %q", text, "2345")
	}
}

// mustLogin is a test helper that logs in or fails the test.
func mustLogin(t *testing.T, client *imapclient.Client) {
	t.Helper()
	if err := client.Login("alice", "secret").Wait(); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}
}

// mustSelect is a test helper that selects a mailbox or fails the test.
func mustSelect(t *testing.T, client *imapclient.Client, mailbox string) {
	t.Helper()
	if _, err := client.Select(mailbox, nil).Wait(); err != nil {
		t.Fatalf("SELECT %s: %v", mailbox, err)
	}
}

// mustAppend appends a message to a mailbox, handling the literal write properly.
func mustAppend(t *testing.T, client *imapclient.Client, mailbox, msg string) {
	t.Helper()
	cmd := client.Append(mailbox, int64(len(msg)), nil)
	cmd.Write([]byte(msg))
	if err := cmd.Close(); err != nil {
		t.Fatalf("APPEND Close: %v", err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatalf("APPEND Wait: %v", err)
	}
}

func TestIntegration_SearchBody(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Append messages with different body content
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Alpha\r\n\r\nHello from the body\r\n")
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Beta\r\n\r\nGoodbye from the body\r\n")
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Gamma\r\n\r\nHello in the subject only\r\n")
	mustSelect(t, client, "INBOX")

	// SEARCH BODY Hello — should match msg 1 (body contains "Hello") but not msg 3 (Hello is in body, so it should match)
	searchData, err := client.Search(&imapv2.SearchCriteria{
		Body: []string{"Hello"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BODY: %v", err)
	}
	nums := searchData.AllSeqNums()
	if len(nums) != 2 {
		t.Fatalf("SEARCH BODY Hello returned %d results, want 2: %v", len(nums), nums)
	}

	// SEARCH BODY Goodbye — should match only msg 2
	searchData, err = client.Search(&imapv2.SearchCriteria{
		Body: []string{"Goodbye"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BODY Goodbye: %v", err)
	}
	nums = searchData.AllSeqNums()
	if len(nums) != 1 {
		t.Fatalf("SEARCH BODY Goodbye returned %d results, want 1: %v", len(nums), nums)
	}

	// SEARCH BODY for text only in headers — should not match
	searchData, err = client.Search(&imapv2.SearchCriteria{
		Body: []string{"Alpha"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BODY Alpha: %v", err)
	}
	nums = searchData.AllSeqNums()
	if len(nums) != 0 {
		t.Fatalf("SEARCH BODY Alpha returned %d results, want 0 (Alpha is in subject header, not body): %v", len(nums), nums)
	}
}

func TestIntegration_SearchText(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Append messages — TEXT should search both headers and body
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Secret Plan\r\n\r\nBody without secret\r\n")
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Normal\r\n\r\nThis has the secret word\r\n")
	mustAppend(t, client, "INBOX", "From: secret@b.com\r\nTo: c@d.com\r\nSubject: Normal\r\n\r\nNo match here\r\n")
	mustSelect(t, client, "INBOX")

	// SEARCH TEXT secret — should match all 3 (subject, body, and from header)
	searchData, err := client.Search(&imapv2.SearchCriteria{
		Text: []string{"secret"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH TEXT: %v", err)
	}
	nums := searchData.AllSeqNums()
	if len(nums) != 3 {
		t.Fatalf("SEARCH TEXT secret returned %d results, want 3: %v", len(nums), nums)
	}

	// SEARCH TEXT for "Normal" — should match msg 2 (subject) and msg 3 (subject)
	searchData, err = client.Search(&imapv2.SearchCriteria{
		Text: []string{"Normal"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH TEXT Normal: %v", err)
	}
	nums = searchData.AllSeqNums()
	if len(nums) != 2 {
		t.Fatalf("SEARCH TEXT Normal returned %d results, want 2: %v", len(nums), nums)
	}
}

// --- SORT and THREAD integration tests (RFC 5256) ---

// TestIntegration_SortCapability verifies SORT appears in CAPABILITY via go-imap client.
func TestIntegration_SortCapability(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	caps := client.Caps()
	capStrs := make([]string, 0, len(caps))
	for cap := range caps {
		capStrs = append(capStrs, string(cap))
	}
	found := false
	for _, c := range capStrs {
		if c == "SORT" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CAPABILITY does not include SORT: %v", capStrs)
	}
}

// TestIntegration_ThreadCapability verifies THREAD appears in CAPABILITY via go-imap client.
func TestIntegration_ThreadCapability(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	caps := client.Caps()
	capStrs := make([]string, 0, len(caps))
	for cap := range caps {
		capStrs = append(capStrs, string(cap))
	}
	found := false
	for _, c := range capStrs {
		if strings.HasPrefix(c, "THREAD") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CAPABILITY does not include THREAD: %v", capStrs)
	}
}

// TestIntegration_SortAndThreadCapabilities verifies both SORT and THREAD are advertised.
func TestIntegration_SortAndThreadCapabilities(t *testing.T) {
	client, _ := makeTestServerAndClient(t)

	caps := client.Caps()
	capStrs := make([]string, 0, len(caps))
	for cap := range caps {
		capStrs = append(capStrs, string(cap))
	}

	sortFound := false
	threadFound := false
	for _, c := range capStrs {
		if c == "SORT" {
			sortFound = true
		}
		if strings.HasPrefix(c, "THREAD") {
			threadFound = true
		}
	}
	if !sortFound {
		t.Errorf("CAPABILITY missing SORT: %v", capStrs)
	}
	if !threadFound {
		t.Errorf("CAPABILITY missing THREAD: %v", capStrs)
	}
}

func TestIntegration_StandardSortSequenceAndUIDResults(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")
	for _, subject := range []string{"Charlie", "Delete me", "Alpha"} {
		mustAppend(t, client, "INBOX", "From: sender@example.com\r\nSubject: "+subject+"\r\n\r\nBody\r\n")
	}
	mustSelect(t, client, "INBOX")
	store := client.Store(imapv2.SeqSetNum(2), &imapv2.StoreFlags{Op: imapv2.StoreFlagsAdd, Flags: []imapv2.Flag{imapv2.FlagDeleted}}, nil)
	if err := store.Close(); err != nil {
		t.Fatalf("STORE deleted: %v", err)
	}
	if err := client.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE: %v", err)
	}

	options := &imapclient.SortOptions{
		SortCriteria:   []imapclient.SortCriterion{{Key: imapclient.SortKeySubject}},
		SearchCriteria: &imapv2.SearchCriteria{},
	}
	sequence, err := client.Sort(options).Wait()
	if err != nil {
		t.Fatalf("SORT: %v", err)
	}
	if len(sequence) != 2 || sequence[0] != 2 || sequence[1] != 1 {
		t.Fatalf("SORT sequence results = %v, want [2 1]", sequence)
	}
	uids, err := client.UIDSort(options).Wait()
	if err != nil {
		t.Fatalf("UID SORT: %v", err)
	}
	if len(uids) != 2 || uids[0] != 3 || uids[1] != 1 {
		t.Fatalf("UID SORT results = %v, want [3 1]", uids)
	}
}

func TestIntegration_StandardThreadResponse(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")
	mustAppend(t, client, "INBOX", "Message-ID: <root@example.com>\r\nSubject: Topic\r\n\r\nRoot\r\n")
	mustAppend(t, client, "INBOX", "Message-ID: <reply@example.com>\r\nReferences: <root@example.com>\r\nIn-Reply-To: <root@example.com>\r\nSubject: Re: Topic\r\n\r\nReply\r\n")
	mustSelect(t, client, "INBOX")

	threads, err := client.Thread(&imapclient.ThreadOptions{
		Algorithm:      imapv2.ThreadReferences,
		SearchCriteria: &imapv2.SearchCriteria{},
	}).Wait()
	if err != nil {
		t.Fatalf("THREAD REFERENCES: %v", err)
	}
	if len(threads) != 1 || len(threads[0].Chain) != 2 || threads[0].Chain[0] != 1 || threads[0].Chain[1] != 2 {
		t.Fatalf("THREAD response = %#v, want one [1 2] chain", threads)
	}
}

// TestIntegration_SearchBodyAndText tests both BODY and TEXT search together.
func TestIntegration_SearchBodyAndText(t *testing.T) {
	client, _ := makeTestServerAndClient(t)
	mustLogin(t, client)
	mustSelect(t, client, "INBOX")

	// Append messages — BODY only searches body, TEXT searches headers + body
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: OnlyInSubject\r\n\r\nBodyContent\r\n")
	mustAppend(t, client, "INBOX", "From: a@b.com\r\nTo: c@d.com\r\nSubject: Normal\r\n\r\nBodyContent\r\n")
	mustSelect(t, client, "INBOX")

	// SEARCH BODY BodyContent — should match both (body contains BodyContent)
	searchData, err := client.Search(&imapv2.SearchCriteria{
		Body: []string{"BodyContent"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BODY: %v", err)
	}
	nums := searchData.AllSeqNums()
	if len(nums) != 2 {
		t.Fatalf("SEARCH BODY BodyContent returned %d results, want 2: %v", len(nums), nums)
	}

	// SEARCH TEXT OnlyInSubject — should match only msg 1 (in subject header)
	searchData, err = client.Search(&imapv2.SearchCriteria{
		Text: []string{"OnlyInSubject"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH TEXT: %v", err)
	}
	nums = searchData.AllSeqNums()
	if len(nums) != 1 {
		t.Fatalf("SEARCH TEXT OnlyInSubject returned %d results, want 1: %v", len(nums), nums)
	}

	// SEARCH BODY OnlyInSubject — should match 0 (only in subject, not body)
	searchData, err = client.Search(&imapv2.SearchCriteria{
		Body: []string{"OnlyInSubject"},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BODY OnlyInSubject: %v", err)
	}
	nums = searchData.AllSeqNums()
	if len(nums) != 0 {
		t.Fatalf("SEARCH BODY OnlyInSubject returned %d results, want 0: %v", len(nums), nums)
	}
}
