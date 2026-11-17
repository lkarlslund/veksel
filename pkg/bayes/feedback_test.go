package bayes

import (
	"math"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/spam"
)

func TestJunkMovesFeedSenderReputationEvenWithoutTheClassifier(t *testing.T) {
	reputation := &spam.Reputation{}
	reputation.SetSettings(true, 1)
	// The classifier is disabled: reputation still follows users' moves.
	f := newFixtureWith(t, Settings{}, func(config *Config) { config.Feedback = spam.MoveFeedback{Reputation: reputation} })
	access := service.UserAccess("alice", "imap")
	inbox, junk := f.folder(t, "alice", "INBOX"), f.folder(t, "alice", "Junk")
	keys := spam.ReputationKeys{Domain: "bulk.example", Network: "203.0.113.0/24"}
	item, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{
		Data:    []byte("Message-ID: <r1@example.net>\r\nSubject: offer\r\n\r\nbuy\r\n"),
		Headers: map[string]string{spam.ReputationHeader: keys.Header()},
	})
	if err != nil {
		t.Fatal(err)
	}
	counts := func() spam.ReputationCounts {
		t.Helper()
		report := reputation.Report(5)
		entries := append(report.BadDomains, report.GoodDomains...)
		if len(entries) == 0 {
			return spam.ReputationCounts{}
		}
		counts := entries[0].ReputationCounts
		// Real-clock decay between moves is negligible.
		counts.UserJunk, counts.UserHam = math.Round(counts.UserJunk), math.Round(counts.UserHam)
		return counts
	}
	if got := counts(); got != (spam.ReputationCounts{}) {
		t.Fatalf("delivery fed reputation: %+v", got)
	}
	moved, err := f.space.MoveItem(t.Context(), access, item.ID, junk.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := counts(); got.UserJunk != 1 || got.UserHam != 0 {
		t.Fatalf("after Junk move = %+v", got)
	}
	if _, err := f.space.MoveItem(t.Context(), access, moved.ID, inbox.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got := counts(); got.UserJunk != 1 || got.UserHam != 1 {
		t.Fatalf("after Not-junk move = %+v", got)
	}
	// Server-internal filing is not a user's judgement.
	internal, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{
		Data: []byte("Subject: queue\r\n\r\nx\r\n"), Headers: map[string]string{spam.ReputationHeader: keys.Header()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.space.MoveItem(t.Context(), service.UserAccess("alice", "system-queue"), internal.ID, junk.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got := counts(); got.UserJunk != 1 {
		t.Fatalf("internal move fed reputation: %+v", got)
	}
}

func TestJunkMovesFeedFuzzySignatures(t *testing.T) {
	fuzzy := &spam.Fuzzy{}
	fuzzy.SetSettings(true, 80, 5)
	f := newFixtureWith(t, Settings{}, func(config *Config) { config.Feedback = spam.MoveFeedback{Fuzzy: fuzzy} })
	access := service.UserAccess("alice", "imap")
	inbox, junk := f.folder(t, "alice", "INBOX"), f.folder(t, "alice", "Junk")
	body := strings.Repeat("limited offer claim your free prize today before midnight ", 6)
	item, err := f.space.CreateItem(t.Context(), access, inbox.ID, service.ItemInput{
		Data: []byte("Message-ID: <f1@example.net>\r\nSubject: prize\r\n\r\n" + body + "\r\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	moved, err := f.space.MoveItem(t.Context(), access, item.ID, junk.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := fuzzy.Report().Signatures; got != 1 {
		t.Fatalf("signatures after Junk move = %d", got)
	}
	if _, err := f.space.MoveItem(t.Context(), access, moved.ID, inbox.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got := fuzzy.Report().Signatures; got != 0 {
		t.Fatalf("signatures after Not-junk move = %d", got)
	}
}
