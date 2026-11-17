package imap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// --- Unit tests for sort logic ---

// TestSortItemsByFrom tests sorting by FROM header.
func TestSortItemsByFrom(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "charlie@example.com"}},
		{UID: 2, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 3, Headers: map[string]string{"From": "bob@example.com"}},
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Should be sorted alphabetically: alice, bob, charlie
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (alice) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (bob) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (charlie) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsByFromReverse tests sorting by FROM header in reverse order.
func TestSortItemsByFromReverse(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "charlie@example.com"}},
		{UID: 2, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 3, Headers: map[string]string{"From": "bob@example.com"}},
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{true}
	sortItems(items, criteria, reverses)

	// Should be sorted reverse: charlie, bob, alice
	if items[0].UID != 1 {
		t.Errorf("expected UID 1 (charlie) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (bob) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 2 {
		t.Errorf("expected UID 2 (alice) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsBySubject tests sorting by SUBJECT header.
func TestSortItemsBySubject(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"Subject": "Zebra"}},
		{UID: 2, Headers: map[string]string{"Subject": "apple"}},
		{UID: 3, Headers: map[string]string{"Subject": "Banana"}},
	}

	criteria := []sortCriterion{sortSubject}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Case-insensitive: apple, Banana, Zebra
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (apple) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (Banana) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (Zebra) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsByDate tests sorting by DATE header.
func TestSortItemsByDate(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"Date": "Wed, 15 Jan 2025 10:00:00 +0000"}},
		{UID: 2, Headers: map[string]string{"Date": "Mon, 13 Jan 2025 10:00:00 +0000"}},
		{UID: 3, Headers: map[string]string{"Date": "Tue, 14 Jan 2025 10:00:00 +0000"}},
	}

	criteria := []sortCriterion{sortDate}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Sorted by Date header string (lexicographic): Jan 13, Jan 14, Jan 15
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (Jan 13) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (Jan 14) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (Jan 15) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsByArrival tests sorting by InternalDate (arrival time).
func TestSortItemsByArrival(t *testing.T) {
	t.Parallel()
	base := time.Date(2025, 1, 13, 10, 0, 0, 0, time.UTC)
	items := []model.Item{
		{UID: 1, InternalDate: base.Add(2 * time.Hour)},
		{UID: 2, InternalDate: base},
		{UID: 3, InternalDate: base.Add(1 * time.Hour)},
	}

	criteria := []sortCriterion{sortArrival}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Sorted by arrival: UID 2 (base), UID 3 (+1h), UID 1 (+2h)
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 third, got UID %d", items[2].UID)
	}
}

// TestSortItemsBySize tests sorting by message size.
func TestSortItemsBySize(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Size: 5000},
		{UID: 2, Size: 1000},
		{UID: 3, Size: 3000},
	}

	criteria := []sortCriterion{sortSize}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Sorted by size: 1000, 3000, 5000
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (1000) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (3000) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (5000) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsByCC tests sorting by CC header.
func TestSortItemsByCC(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"Cc": "zara@example.com"}},
		{UID: 2, Headers: map[string]string{"Cc": "amy@example.com"}},
		{UID: 3, Headers: map[string]string{"Cc": "bob@example.com"}},
	}

	criteria := []sortCriterion{sortCc}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Sorted: amy, bob, zara
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (amy) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (bob) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (zara) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsByTo tests sorting by TO header.
func TestSortItemsByTo(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"To": "zara@example.com"}},
		{UID: 2, Headers: map[string]string{"To": "amy@example.com"}},
		{UID: 3, Headers: map[string]string{"To": "bob@example.com"}},
	}

	criteria := []sortCriterion{sortTo}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Sorted: amy, bob, zara
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (amy) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (bob) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (zara) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsMultiCriteria tests multi-criteria sorting (FROM, then SUBJECT).
func TestSortItemsMultiCriteria(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "alice@example.com", "Subject": "Zebra"}},
		{UID: 2, Headers: map[string]string{"From": "alice@example.com", "Subject": "apple"}},
		{UID: 3, Headers: map[string]string{"From": "bob@example.com", "Subject": "Banana"}},
	}

	criteria := []sortCriterion{sortFrom, sortSubject}
	reverses := []bool{false, false}
	sortItems(items, criteria, reverses)

	// alice comes before bob; within alice, apple before Zebra
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (alice, apple) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 1 {
		t.Errorf("expected UID 1 (alice, Zebra) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 3 {
		t.Errorf("expected UID 3 (bob, Banana) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsEmpty tests sorting with no items.
func TestSortItemsEmpty(t *testing.T) {
	t.Parallel()
	var items []model.Item
	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)
	if len(items) != 0 {
		t.Errorf("expected empty result, got %d items", len(items))
	}
}

// TestSortItemsCaseInsensitive tests that header comparison is case-insensitive.
func TestSortItemsCaseInsensitive(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "ALICE@example.com"}},
		{UID: 2, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 3, Headers: map[string]string{"From": "Alice@Example.com"}},
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// All have the same from (case-insensitive), so order should be by UID tiebreaker
	if items[0].UID != 1 || items[1].UID != 2 || items[2].UID != 3 {
		t.Errorf("expected UID order [1 2 3] for equal keys, got [%d %d %d]",
			items[0].UID, items[1].UID, items[2].UID)
	}
}

// TestParseSortCriteria tests the criterion parser.
func TestParseSortCriteria(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		args      []string
		wantCount int
		wantErr   bool
	}{
		{"single", []string{"FROM"}, 1, false},
		{"multiple", []string{"FROM", "TO", "SUBJECT"}, 3, false},
		{"all", []string{"FROM", "TO", "SUBJECT", "DATE", "ARRIVAL", "CC", "SIZE"}, 7, false},
		{"lowercase", []string{"from", "to"}, 2, false},
		{"mixed_case", []string{"From", "TO", "subject"}, 3, false},
		{"empty", []string{}, 0, true},
		{"invalid", []string{"FROM", "INVALID"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria, reverses, err := parseSortCriteria(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(criteria) != tt.wantCount {
				t.Errorf("expected %d criteria, got %d", tt.wantCount, len(criteria))
			}
			if len(reverses) != tt.wantCount {
				t.Errorf("expected %d reverses, got %d", tt.wantCount, len(reverses))
			}
		})
	}
}

// TestCompareItem tests the sort keys for each criterion.
func TestCompareItem(t *testing.T) {
	t.Parallel()
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)

	a := model.Item{
		UID:  1,
		Size: 1000,
		Headers: map[string]string{
			"From":    "alice@example.com",
			"To":      "bob@example.com",
			"Subject": "Hello",
			"Date":    "Mon, 1 Jan 2025 10:00:00 +0000",
			"Cc":      "carol@example.com",
		},
		InternalDate: base,
	}

	b := model.Item{
		UID:  2,
		Size: 2000,
		Headers: map[string]string{
			"From":    "bob@example.com",
			"To":      "alice@example.com",
			"Subject": "World",
			"Date":    "Tue, 2 Jan 2025 10:00:00 +0000",
			"Cc":      "dave@example.com",
		},
		InternalDate: base.Add(time.Hour),
	}

	tests := []struct {
		criterion sortCriterion
		want      bool // true if a < b
	}{
		{sortFrom, true},    // alice < bob
		{sortTo, false},     // bob > alice
		{sortSubject, true}, // Hello < World
		{sortDate, true},    // Jan 1 < Jan 2
		{sortArrival, true}, // base < base+1h
		{sortCc, true},      // carol < dave
		{sortSize, true},    // 1000 < 2000
	}

	for _, tt := range tests {
		got := makeSortKey(a, tt.criterion).compare(makeSortKey(b, tt.criterion)) < 0
		if got != tt.want {
			t.Errorf("sort key(a) < sort key(b) for %v = %v, want %v", tt.criterion, got, tt.want)
		}
	}
}

// TestGetHeaderValue tests header value extraction.
func TestGetHeaderValue(t *testing.T) {
	t.Parallel()
	item := model.Item{
		Headers: map[string]string{
			"From":    "alice@example.com",
			"Subject": "Test",
		},
		Data: []byte("From: fallback@example.com\r\nSubject: Fallback\r\n\r\nBody"),
	}

	// From stored headers
	if v := getHeaderValue(item, "From"); v != "alice@example.com" {
		t.Errorf("getHeaderValue(item, From) = %q, want alice@example.com", v)
	}

	// Case-insensitive lookup
	if v := getHeaderValue(item, "from"); v != "alice@example.com" {
		t.Errorf("getHeaderValue(item, from) = %q, want alice@example.com", v)
	}

	// Missing header returns empty
	if v := getHeaderValue(item, "Missing"); v != "" {
		t.Errorf("getHeaderValue(item, Missing) = %q, want empty", v)
	}
}

// --- Integration tests ---

// setupSortTest creates a TypedStore with messages for SORT integration tests.
func setupSortTest(t *testing.T) (*model.TypedStore, *tc) {
	t.Helper()
	tmpDir := t.TempDir()
	s, err := jsonstore.New(tmpDir)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := model.NewTypedStore(s, store.BackendJSON)
	ctx := context.Background()

	for _, ns := range []string{model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems, model.NSACL, model.NSMetadata} {
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

	// Create an IMAP server
	cfg := &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			if username == "alice" && password == "secret" {
				return "alice", nil
			}
			return "", fmt.Errorf("invalid")
		},
		TypedStore: ts,
	}

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

	// Login
	c.send("A001", "LOGIN alice secret")
	c.send("A002", "SELECT INBOX")

	return ts, c
}

// TestSortIntegrationFrom tests SORT FROM ALL end-to-end.
func TestSortIntegrationFrom(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Append messages with different From addresses
	msgs := []string{
		"From: charlie@example.com\r\nMessage-Id: <s1@example.com>\r\nSubject: C\r\n\r\nC\r\n",
		"From: alice@example.com\r\nMessage-Id: <s2@example.com>\r\nSubject: A\r\n\r\nA\r\n",
		"From: bob@example.com\r\nMessage-Id: <s3@example.com>\r\nSubject: B\r\n\r\nB\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Re-select to pick up the messages
	c.send("A003", "SELECT INBOX")

	// SORT FROM UTF-8 ALL
	_, code, _ := c.send("A004", "SORT FROM UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT FROM: code=%s, want OK", code)
	}
}

// TestSortIntegrationSubject tests SORT SUBJECT ALL end-to-end.
func TestSortIntegrationSubject(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: a@b.com\r\nMessage-Id: <s1@example.com>\r\nSubject: Zebra\r\n\r\nZ\r\n",
		"From: a@b.com\r\nMessage-Id: <s2@example.com>\r\nSubject: apple\r\n\r\nA\r\n",
		"From: a@b.com\r\nMessage-Id: <s3@example.com>\r\nSubject: Banana\r\n\r\nB\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT SUBJECT UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT SUBJECT: code=%s, want OK", code)
	}
}

// TestSortIntegrationSize tests SORT SIZE ALL end-to-end.
func TestSortIntegrationSize(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: a@b.com\r\nMessage-Id: <s1@example.com>\r\nSubject: Big\r\n\r\nThis is a longer message body\r\n",
		"From: a@b.com\r\nMessage-Id: <s2@example.com>\r\nSubject: Tiny\r\n\r\nHi\r\n",
		"From: a@b.com\r\nMessage-Id: <s3@example.com>\r\nSubject: Med\r\n\r\nMedium body\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT SIZE UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT SIZE: code=%s, want OK", code)
	}
}

// TestSortIntegrationArrival tests SORT ARRIVAL UTF-8 ALL end-to-end.
func TestSortIntegrationArrival(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Messages are appended in order, so arrival order is 1, 2, 3
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nMessage-Id: <a%d@example.com>\r\nSubject: Msg %d\r\n\r\nBody %d\r\n", i, i, i)
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT ARRIVAL UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT ARRIVAL: code=%s, want OK", code)
	}
}

// TestSortIntegrationMultiCriteria tests SORT with multiple criteria.
func TestSortIntegrationMultiCriteria(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: alice@example.com\r\nMessage-Id: <m1@example.com>\r\nSubject: Z\r\n\r\nZ\r\n",
		"From: alice@example.com\r\nMessage-Id: <m2@example.com>\r\nSubject: A\r\n\r\nA\r\n",
		"From: bob@example.com\r\nMessage-Id: <m3@example.com>\r\nSubject: M\r\n\r\nM\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT FROM SUBJECT UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT FROM SUBJECT: code=%s, want OK", code)
	}
}

// TestSortIntegrationEmptyFolder tests SORT on an empty folder.
func TestSortIntegrationEmptyFolder(t *testing.T) {
	t.Parallel()
	_, c := setupSortTest(t)

	_, code, _ := c.send("A003", "SORT FROM UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT on empty folder: code=%s, want OK", code)
	}
}

// TestSortNoMailbox tests SORT without a selected mailbox.
func TestSortNoMailbox(t *testing.T) {
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
	// SORT without SELECT should fail
	_, code, _ := c.send("A002", "SORT FROM UTF-8 ALL")
	if code != "BAD" {
		t.Fatalf("SORT without SELECT: code=%s, want BAD", code)
	}
}

// TestSortBadCriteria tests SORT with invalid criteria.
func TestSortBadCriteria(t *testing.T) {
	t.Parallel()
	_, c := setupSortTest(t)

	_, code, _ := c.send("A003", "SORT INVALID UTF-8 ALL")
	if code != "BAD" {
		t.Fatalf("SORT INVALID: code=%s, want BAD", code)
	}
}

// TestSortCapability tests that SORT appears in CAPABILITY response.
func TestSortCapability(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Send CAPABILITY and read all responses
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	// Read all lines until tagged response
	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
		}
		if !strings.HasPrefix(line, "*") {
			break
		}
	}

	if !strings.Contains(capLine, "SORT") {
		t.Fatalf("CAPABILITY response does not contain SORT: %s", capLine)
	}
}

// TestSortWithSearchFilter tests SORT with a search filter (e.g., SORT FROM UTF-8 FROM alice).
func TestSortWithSearchFilter(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: alice@example.com\r\nMessage-Id: <f1@example.com>\r\nSubject: Z\r\n\r\nZ\r\n",
		"From: alice@example.com\r\nMessage-Id: <f2@example.com>\r\nSubject: A\r\n\r\nA\r\n",
		"From: bob@example.com\r\nMessage-Id: <f3@example.com>\r\nSubject: M\r\n\r\nM\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	// SORT SUBJECT but only for messages from alice
	_, code, _ := c.send("A004", "SORT SUBJECT UTF-8 FROM alice")
	if code != "OK" {
		t.Fatalf("SORT SUBJECT FROM alice: code=%s, want OK", code)
	}
}

// TestSortIntegrationDate tests SORT DATE end-to-end.
func TestSortIntegrationDate(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: a@b.com\r\nMessage-Id: <d1@example.com>\r\nDate: Wed, 15 Jan 2025 10:00:00 +0000\r\nSubject: C\r\n\r\nC\r\n",
		"From: a@b.com\r\nMessage-Id: <d2@example.com>\r\nDate: Mon, 13 Jan 2025 10:00:00 +0000\r\nSubject: A\r\n\r\nA\r\n",
		"From: a@b.com\r\nMessage-Id: <d3@example.com>\r\nDate: Tue, 14 Jan 2025 10:00:00 +0000\r\nSubject: B\r\n\r\nB\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT DATE UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT DATE: code=%s, want OK", code)
	}
}

// TestSortIntegrationCC tests SORT CC end-to-end.
func TestSortIntegrationCC(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: a@b.com\r\nMessage-Id: <c1@example.com>\r\nCc: zara@example.com\r\nSubject: Z\r\n\r\nZ\r\n",
		"From: a@b.com\r\nMessage-Id: <c2@example.com>\r\nCc: amy@example.com\r\nSubject: A\r\n\r\nA\r\n",
		"From: a@b.com\r\nMessage-Id: <c3@example.com>\r\nCc: bob@example.com\r\nSubject: B\r\n\r\nB\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT CC UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT CC: code=%s, want OK", code)
	}
}

// TestSortIntegrationTO tests SORT TO end-to-end.
func TestSortIntegrationTO(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: a@b.com\r\nMessage-Id: <t1@example.com>\r\nTo: zara@example.com\r\nSubject: Z\r\n\r\nZ\r\n",
		"From: a@b.com\r\nMessage-Id: <t2@example.com>\r\nTo: amy@example.com\r\nSubject: A\r\n\r\nA\r\n",
		"From: a@b.com\r\nMessage-Id: <t3@example.com>\r\nTo: bob@example.com\r\nSubject: B\r\n\r\nB\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT TO UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("SORT TO: code=%s, want OK", code)
	}
}

// TestSortReverse tests SORT with REVERSE keyword.
func TestSortReverse(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 2, Headers: map[string]string{"From": "charlie@example.com"}},
		{UID: 3, Headers: map[string]string{"From": "bob@example.com"}},
	}

	// RFC 5256 "REVERSE FROM" reverses FROM.
	criteria, reverses, err := parseSortCriteria([]string{"REVERSE", "FROM"})
	if err != nil || len(criteria) != 1 || criteria[0] != sortFrom || !reverses[0] {
		t.Fatalf("REVERSE FROM = %v %v, %v", criteria, reverses, err)
	}

	// The legacy trailing form "FROM REVERSE" is still accepted.
	criteria, reverses, err = parseSortCriteria([]string{"FROM", "REVERSE"})
	if err != nil {
		t.Fatalf("parseSortCriteria: %v", err)
	}

	if len(criteria) != 1 {
		t.Fatalf("expected 1 criterion, got %d", len(criteria))
	}
	if criteria[0] != sortFrom {
		t.Fatalf("expected sortFrom, got %v", criteria[0])
	}
	if !reverses[0] {
		t.Error("expected FROM to be reversed")
	}

	sortItems(items, criteria, reverses)

	// Should be reverse: charlie, bob, alice
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (charlie) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 3 {
		t.Errorf("expected UID 3 (bob) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 1 {
		t.Errorf("expected UID 1 (alice) third, got UID %d", items[2].UID)
	}
}

// TestSortItemsStable tests that the sort is stable (equal items preserve original order).
func TestSortItemsStable(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 2, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 3, Headers: map[string]string{"From": "alice@example.com"}},
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// All have the same From, so order should be preserved (by UID tiebreaker)
	expectedUIDs := []uint32{1, 2, 3}
	for i, expected := range expectedUIDs {
		if items[i].UID != expected {
			t.Errorf("items[%d].UID = %d, want %d", i, items[i].UID, expected)
		}
	}
}

// TestSortHeaderFallback tests that header extraction falls back to raw data
// when the header is not in the stored Headers map.
func TestSortHeaderFallback(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		// Headers map doesn't have "From", but raw data does
		{UID: 1, Headers: map[string]string{}, Data: []byte("From: zara@example.com\r\n\r\nBody")},
		{UID: 2, Headers: map[string]string{}, Data: []byte("From: amy@example.com\r\n\r\nBody")},
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Should sort by the From parsed from raw data: amy, zara
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (amy) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 1 {
		t.Errorf("expected UID 1 (zara) second, got UID %d", items[1].UID)
	}
}

// TestSortVerifySortResponseFormat verifies the SORT response format.
func TestSortVerifySortResponseFormat(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Append 3 messages
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: a@b.com\r\nMessage-Id: <r%d@example.com>\r\nSubject: Msg %d\r\n\r\nBody %d\r\n", i, i, i)
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")

	// Send SORT and capture the untagged response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A004 SORT ARRIVAL UTF-8 ALL\r\n")

	// Read all lines
	var sortLine string
	var code string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* SORT") {
			sortLine = line
		}
		if !strings.HasPrefix(line, "*") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				code = parts[1]
			}
			break
		}
	}

	if code != "OK" {
		t.Fatalf("SORT: code=%s, want OK", code)
	}
	if sortLine == "" {
		t.Fatal("expected * SORT response line")
	}
	// Verify format: * SORT uid1 uid2 uid3
	if !strings.HasPrefix(sortLine, "* SORT") {
		t.Fatalf("expected * SORT prefix, got: %s", sortLine)
	}
}

// TestSortVerifyEmptyResponseFormat verifies the SORT response for empty results.
func TestSortVerifyEmptyResponseFormat(t *testing.T) {
	t.Parallel()
	_, c := setupSortTest(t)

	// Send SORT and capture the untagged response
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A003 SORT FROM UTF-8 ALL\r\n")

	// Read all lines
	var sortLine string
	var code string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* SORT") {
			sortLine = line
		}
		if !strings.HasPrefix(line, "*") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				code = parts[1]
			}
			break
		}
	}

	if code != "OK" {
		t.Fatalf("SORT: code=%s, want OK", code)
	}
	if sortLine == "" {
		t.Fatal("expected * SORT response line")
	}
	// Empty result should be "* SORT" with no UIDs
	if sortLine != "* SORT" {
		t.Fatalf("expected '* SORT' for empty result, got: %s", sortLine)
	}
}

// TestSortVerifyThreadCapabilityFormat verifies THREAD capability format.
func TestSortVerifyThreadCapabilityFormat(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	// Send CAPABILITY
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
		}
		if !strings.HasPrefix(line, "*") {
			break
		}
	}

	// THREAD should include the supported algorithms
	if !strings.Contains(capLine, "THREAD=REFERENCES") {
		t.Fatalf("CAPABILITY should contain THREAD=REFERENCES: %s", capLine)
	}
}

// TestSortVerifySortAndThreadCapabilities verifies both SORT and THREAD are advertised.
func TestSortVerifySortAndThreadCapabilities(t *testing.T) {
	t.Parallel()
	ts := setupTestStore(t)
	c := makeTestServer(t, &Config{
		ServerName: "test.veksel",
		AuthValidator: func(ctx context.Context, username, password string) (string, error) {
			return "alice", nil
		},
		TypedStore: ts,
	})

	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c.Conn, "A001 CAPABILITY\r\n")

	var capLine string
	for {
		line, err := c.readLine()
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "* CAPABILITY") {
			capLine = line
		}
		if !strings.HasPrefix(line, "*") {
			break
		}
	}

	if !strings.Contains(capLine, "SORT") {
		t.Errorf("CAPABILITY missing SORT: %s", capLine)
	}
	if !strings.Contains(capLine, "THREAD") {
		t.Errorf("CAPABILITY missing THREAD: %s", capLine)
	}
}

// TestSortVerifySortByDateHeader tests SORT DATE sorts by the Date header, not InternalDate.
func TestSortVerifySortByDateHeader(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"Date": "Wed, 15 Jan 2025 10:00:00 +0000"}},
		{UID: 2, Headers: map[string]string{"Date": "Mon, 13 Jan 2025 10:00:00 +0000"}},
		{UID: 3, Headers: map[string]string{"Date": "Tue, 14 Jan 2025 10:00:00 +0000"}},
	}

	criteria := []sortCriterion{sortDate}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Sorted by Date header string: Mon 13, Tue 14, Wed 15
	expectedUIDs := []uint32{2, 3, 1}
	for i, expected := range expectedUIDs {
		if items[i].UID != expected {
			t.Errorf("items[%d].UID = %d, want %d (Date header sort)", i, items[i].UID, expected)
		}
	}
}

// TestSortVerifyArrivalVsDate tests that ARRIVAL and DATE are different sort criteria.
func TestSortVerifyArrivalVsDate(t *testing.T) {
	t.Parallel()
	base := time.Date(2025, 1, 13, 10, 0, 0, 0, time.UTC)

	// Item 1: arrived first, but has a later Date header
	// Item 2: arrived second, but has an earlier Date header
	items := []model.Item{
		{
			UID:          1,
			InternalDate: base,                                                         // arrived first
			Headers:      map[string]string{"Date": "Wed, 15 Jan 2025 10:00:00 +0000"}, // later date
		},
		{
			UID:          2,
			InternalDate: base.Add(time.Hour),                                          // arrived second
			Headers:      map[string]string{"Date": "Mon, 13 Jan 2025 10:00:00 +0000"}, // earlier date
		},
	}

	// ARRIVAL sort: item 1 first (arrived first)
	arrivalCriteria := []sortCriterion{sortArrival}
	arrivalReverses := []bool{false}
	sortItems(items, arrivalCriteria, arrivalReverses)
	if items[0].UID != 1 {
		t.Errorf("ARRIVAL sort: expected UID 1 first, got UID %d", items[0].UID)
	}

	// DATE sort: item 2 first (earlier Date header)
	dateCriteria := []sortCriterion{sortDate}
	dateReverses := []bool{false}
	sortItems(items, dateCriteria, dateReverses)
	if items[0].UID != 2 {
		t.Errorf("DATE sort: expected UID 2 first, got UID %d", items[0].UID)
	}
}

// TestSortVerifySizeReverse tests SORT SIZE in reverse order.
func TestSortVerifySizeReverse(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Size: 1000},
		{UID: 2, Size: 5000},
		{UID: 3, Size: 3000},
	}

	criteria := []sortCriterion{sortSize}
	reverses := []bool{true}
	sortItems(items, criteria, reverses)

	// Reverse size: 5000, 3000, 1000
	expectedUIDs := []uint32{2, 3, 1}
	for i, expected := range expectedUIDs {
		if items[i].UID != expected {
			t.Errorf("items[%d].UID = %d, want %d", i, items[i].UID, expected)
		}
	}
}

// TestSortVerifyMultiCriteriaWithReverse tests multi-criteria with mixed reverse flags.
func TestSortVerifyMultiCriteriaWithReverse(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "alice@example.com", "Subject": "Z"}},
		{UID: 2, Headers: map[string]string{"From": "alice@example.com", "Subject": "A"}},
		{UID: 3, Headers: map[string]string{"From": "bob@example.com", "Subject": "M"}},
	}

	// Sort by FROM ascending, then SUBJECT descending
	criteria := []sortCriterion{sortFrom, sortSubject}
	reverses := []bool{false, true}
	sortItems(items, criteria, reverses)

	// alice before bob for FROM ascending
	// Within alice: Z before A for SUBJECT descending
	if items[0].UID != 1 {
		t.Errorf("expected UID 1 (alice, Z) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 2 {
		t.Errorf("expected UID 2 (alice, A) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 3 {
		t.Errorf("expected UID 3 (bob, M) third, got UID %d", items[2].UID)
	}
}

// TestSortVerifyParseSortCriteriaAll tests parsing all sort criteria.
func TestSortVerifyParseSortCriteriaAll(t *testing.T) {
	t.Parallel()
	args := []string{"FROM", "TO", "SUBJECT", "DATE", "ARRIVAL", "CC", "SIZE"}
	criteria, reverses, err := parseSortCriteria(args)
	if err != nil {
		t.Fatalf("parseSortCriteria: %v", err)
	}

	expected := []sortCriterion{
		sortFrom, sortTo, sortSubject, sortDate, sortArrival, sortCc, sortSize,
	}

	if len(criteria) != len(expected) {
		t.Fatalf("expected %d criteria, got %d", len(expected), len(criteria))
	}

	for i, want := range expected {
		if criteria[i] != want {
			t.Errorf("criteria[%d] = %v, want %v", i, criteria[i], want)
		}
	}

	// None should be reversed
	for i, rev := range reverses {
		if rev {
			t.Errorf("reverses[%d] = true, want false", i)
		}
	}
}

// TestSortVerifyIntegrationAllCriteria runs SORT with each criterion end-to-end.
func TestSortVerifyIntegrationAllCriteria(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Create messages with varied headers for all criteria
	msgs := []string{
		"From: alice@example.com\r\nTo: bob@example.com\r\nCc: carol@example.com\r\nMessage-Id: <all1@example.com>\r\nDate: Mon, 13 Jan 2025 10:00:00 +0000\r\nSubject: Hello\r\n\r\nHello World\r\n",
		"From: charlie@example.com\r\nTo: alice@example.com\r\nCc: dave@example.com\r\nMessage-Id: <all2@example.com>\r\nDate: Tue, 14 Jan 2025 10:00:00 +0000\r\nSubject: World\r\n\r\nShort\r\n",
		"From: bob@example.com\r\nTo: carol@example.com\r\nCc: alice@example.com\r\nMessage-Id: <all3@example.com>\r\nDate: Wed, 15 Jan 2025 10:00:00 +0000\r\nSubject: Alpha\r\n\r\nMedium length message\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")

	// Test each criterion
	criteria := []string{"FROM", "TO", "SUBJECT", "DATE", "ARRIVAL", "CC", "SIZE"}
	for _, crit := range criteria {
		_, code, _ := c.send(fmt.Sprintf("A%03d", 10+len(criteria)), fmt.Sprintf("SORT %s UTF-8 ALL", crit))
		if code != "OK" {
			t.Errorf("SORT %s: code=%s, want OK", crit, code)
		}
	}
}

// TestSortVerifyParseSortCriteriaInvalid tests error handling for invalid criteria.
func TestSortVerifyParseSortCriteriaInvalid(t *testing.T) {
	t.Parallel()
	_, _, err := parseSortCriteria([]string{"INVALID"})
	if err == nil {
		t.Error("expected error for invalid criterion, got nil")
	}

	_, _, err = parseSortCriteria([]string{})
	if err == nil {
		t.Error("expected error for empty criteria, got nil")
	}
}

// TestSortVerifySortNoArgs tests SORT command with insufficient arguments.
func TestSortVerifySortNoArgs(t *testing.T) {
	t.Parallel()
	_, c := setupSortTest(t)

	_, code, _ := c.send("A003", "SORT")
	if code != "BAD" {
		t.Fatalf("SORT with no args: code=%s, want BAD", code)
	}
}

// TestSortVerifySortMissingCharset tests SORT command without charset.
func TestSortVerifySortMissingCharset(t *testing.T) {
	t.Parallel()
	_, c := setupSortTest(t)

	_, code, _ := c.send("A003", "SORT FROM")
	if code != "BAD" {
		t.Fatalf("SORT FROM (no charset): code=%s, want BAD", code)
	}
}

// TestSortVerifySortMissingSelector tests SORT command without selector.
// When no selector is given, all messages are sorted (equivalent to ALL).
func TestSortVerifySortMissingSelector(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	// Add a message so the sort has something to return
	msg := "From: a@b.com\r\nMessage-Id: <ms@example.com>\r\nSubject: Test\r\n\r\nBody\r\n"
	if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "SORT FROM UTF-8")
	if code != "OK" {
		t.Fatalf("SORT FROM UTF-8 (no selector): code=%s, want OK", code)
	}
}

// TestSortVerifySortWithUIDPrefix tests UID SORT command.
func TestSortVerifySortWithUIDPrefix(t *testing.T) {
	t.Parallel()
	ts, c := setupSortTest(t)
	ctx := context.Background()

	folder, err := ts.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}

	msgs := []string{
		"From: charlie@example.com\r\nMessage-Id: <u1@example.com>\r\nSubject: C\r\n\r\nC\r\n",
		"From: alice@example.com\r\nMessage-Id: <u2@example.com>\r\nSubject: A\r\n\r\nA\r\n",
		"From: bob@example.com\r\nMessage-Id: <u3@example.com>\r\nSubject: B\r\n\r\nB\r\n",
	}

	for _, msg := range msgs {
		if _, err := ts.ItemStore().Append(ctx, folder.ID, []byte(msg), nil); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	c.send("A003", "SELECT INBOX")
	_, code, _ := c.send("A004", "UID SORT FROM UTF-8 ALL")
	if code != "OK" {
		t.Fatalf("UID SORT FROM: code=%s, want OK", code)
	}
}

// TestSortVerifySortSubjectWithRePrefix tests sorting subjects with Re: prefixes.
func TestSortVerifySortSubjectWithRePrefix(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"Subject": "Re: Hello"}},
		{UID: 2, Headers: map[string]string{"Subject": "Hello"}},
		{UID: 3, Headers: map[string]string{"Subject": "Re: Re: Hello"}},
	}

	criteria := []sortCriterion{sortSubject}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// RFC 5256 sorts by base subject: all three are "hello", so the tie is
	// broken by sequence number.
	expectedUIDs := []uint32{1, 2, 3}
	for i, expected := range expectedUIDs {
		if items[i].UID != expected {
			t.Errorf("items[%d].UID = %d, want %d", i, items[i].UID, expected)
		}
	}
}

// TestSortVerifySortWithMissingHeaders tests sorting when some messages lack the sort header.
func TestSortVerifySortWithMissingHeaders(t *testing.T) {
	t.Parallel()
	items := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "alice@example.com"}},
		{UID: 2, Headers: map[string]string{}}, // No From header
		{UID: 3, Headers: map[string]string{"From": "bob@example.com"}},
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Empty string sorts first: (empty), alice, bob
	if items[0].UID != 2 {
		t.Errorf("expected UID 2 (no From) first, got UID %d", items[0].UID)
	}
	if items[1].UID != 1 {
		t.Errorf("expected UID 1 (alice) second, got UID %d", items[1].UID)
	}
	if items[2].UID != 3 {
		t.Errorf("expected UID 3 (bob) third, got UID %d", items[2].UID)
	}
}

// TestSortVerifySortLargeSet tests sorting with a larger set of items.
func TestSortVerifySortLargeSet(t *testing.T) {
	t.Parallel()
	var items []model.Item
	letters := "zyxwvutsrqponmlkjihgfedcba"
	for i, r := range letters {
		items = append(items, model.Item{
			UID:     uint32(i + 1),
			Headers: map[string]string{"From": string(r) + "@example.com"},
		})
	}

	criteria := []sortCriterion{sortFrom}
	reverses := []bool{false}
	sortItems(items, criteria, reverses)

	// Verify sorted order
	for i := 0; i < len(items)-1; i++ {
		a := strings.ToLower(getHeaderValue(items[i], "From"))
		b := strings.ToLower(getHeaderValue(items[i+1], "From"))
		if a > b {
			t.Errorf("items[%d].From (%s) > items[%d].From (%s) — not sorted", i, a, i+1, b)
		}
	}
}

// TestSortVerifySortDeterministic tests that sorting is deterministic.
func TestSortVerifySortDeterministic(t *testing.T) {
	t.Parallel()
	baseItems := []model.Item{
		{UID: 1, Headers: map[string]string{"From": "alice@example.com", "Subject": "Z"}},
		{UID: 2, Headers: map[string]string{"From": "bob@example.com", "Subject": "A"}},
		{UID: 3, Headers: map[string]string{"From": "alice@example.com", "Subject": "M"}},
	}

	criteria := []sortCriterion{sortFrom, sortSubject}
	reverses := []bool{false, false}

	// Run sort multiple times and verify same result
	var firstResult []uint32
	for i := 0; i < 5; i++ {
		// Deep copy items
		items := make([]model.Item, len(baseItems))
		copy(items, baseItems)
		for j := range items {
			items[j].Headers = make(map[string]string)
			for k, v := range baseItems[j].Headers {
				items[j].Headers[k] = v
			}
		}

		sortItems(items, criteria, reverses)
		uids := make([]uint32, len(items))
		for j, item := range items {
			uids[j] = item.UID
		}

		if i == 0 {
			firstResult = uids
		} else {
			for j := range uids {
				if uids[j] != firstResult[j] {
					t.Errorf("sort not deterministic: run %d UID[%d] = %d, first run = %d", i, j, uids[j], firstResult[j])
				}
			}
		}
	}
}

// TestSortFollowsRFC5256Keys replays Roundcube's "UID SORT (REVERSE DATE)
// UTF-8 ALL" and FROM/SUBJECT sorts. DATE compared the raw header text, so
// "Wed, 8 Jan" sorted after "Thu, 2 Jan" only by luck of the weekday names,
// a message without a Date header did not fall back to its arrival time,
// FROM compared display names, and SUBJECT did not strip reply prefixes.
func TestSortFollowsRFC5256Keys(t *testing.T) {
	t.Parallel()
	base := time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC)
	items := []model.Item{
		{UID: 1, InternalDate: base, Headers: map[string]string{"Date": "Wed, 8 Jan 2025 10:00:00 +0000", "From": `"Zed" <alice@example.com>`, "Subject": "Re: banana"}},
		{UID: 2, InternalDate: base, Headers: map[string]string{"Date": "Thu, 2 Jan 2025 10:00:00 +0000", "From": `"Amy" <carol@example.com>`, "Subject": "apple"}},
		{UID: 3, InternalDate: base.Add(time.Hour), Headers: map[string]string{"From": "bob@example.com", "Subject": "Fwd: cherry"}},
		{UID: 4, InternalDate: base, Headers: map[string]string{"Date": "Sat, 4 Jan 2025 23:30:00 -0500", "From": "dave@example.com", "Subject": "apple"}},
	}
	order := func(criteria []sortCriterion, reverses []bool) []uint32 {
		sorted := append([]model.Item(nil), items...)
		sortItems(sorted, criteria, reverses)
		uids := make([]uint32, len(sorted))
		for index, item := range sorted {
			uids[index] = item.UID
		}
		return uids
	}
	for _, test := range []struct {
		name     string
		criteria []sortCriterion
		reverses []bool
		want     []uint32
	}{
		{"DATE", []sortCriterion{sortDate}, []bool{false}, []uint32{2, 4, 1, 3}},
		{"REVERSE DATE", []sortCriterion{sortDate}, []bool{true}, []uint32{3, 1, 4, 2}},
		{"FROM", []sortCriterion{sortFrom}, []bool{false}, []uint32{1, 3, 2, 4}},
		{"SUBJECT", []sortCriterion{sortSubject}, []bool{false}, []uint32{2, 4, 1, 3}},
		{"SUBJECT REVERSE ARRIVAL", []sortCriterion{sortSubject, sortArrival}, []bool{false, true}, []uint32{2, 4, 1, 3}},
	} {
		if got := order(test.criteria, test.reverses); !slices.Equal(got, test.want) {
			t.Errorf("%s order = %v, want %v", test.name, got, test.want)
		}
	}
}
