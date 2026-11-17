package smtp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestSieveFileintoFailureIsNotSwallowed: when a fileinto append fails after
// the script ran, the failure must defer the transaction rather than be
// treated as a script error that falls back to the default mailbox, which
// accepted the message with 250 and silently lost the failed copy.
func TestSieveFileintoFailureIsNotSwallowed(t *testing.T) {
	var mu sync.Mutex
	var appended []string
	addr, cleanup := startSMTPServer(t, &Config{
		ServerName: "test.veksel",
		Delivery: &Delivery{
			ResolveRecipient: func(context.Context, string) (string, string, error) {
				return "INBOX", "alice", nil
			},
			GetSieveScript: func(context.Context, string) (string, bool, error) {
				return "require \"fileinto\"; fileinto \"A\"; fileinto \"B\";", true, nil
			},
			AppendMessage: func(_ context.Context, folderID string, _ []byte, _ map[string]string) (string, error) {
				if folderID == "B" {
					return "", errors.New("store unavailable")
				}
				mu.Lock()
				defer mu.Unlock()
				appended = append(appended, folderID)
				return "item-" + folderID, nil
			},
		},
	})
	t.Cleanup(cleanup)
	err := dialClient(t, addr).SendMail("bob@remote.example", []string{"alice@example.test"}, strings.NewReader("Subject: x\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("transaction accepted although a fileinto copy failed")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, folder := range appended {
		if folder == "INBOX" {
			t.Fatalf("failed fileinto fell back to the default mailbox: %v", appended)
		}
	}
}
