package sendguard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

var _ smtp.TemporaryRejection = (*QuotaError)(nil)

type testClock struct{ now time.Time }

func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func testStore(t *testing.T) *model.TypedStore {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{
		model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems,
		model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes, model.NSQueue,
	} {
		if err := ts.EnsureNamespace(t.Context(), namespace); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"alice", "bob"} {
		if err := ts.UserStore().Create(t.Context(), userID, userID, "password123"); err != nil {
			t.Fatal(err)
		}
		if err := ts.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatal(err)
		}
		if err := ts.UserStore().AddEmailAddress(t.Context(), userID+"@example.test", userID, "example.test", true); err != nil {
			t.Fatal(err)
		}
	}
	return ts
}

func testGuard(t *testing.T, ts *model.TypedStore, cfg Config) (*Guard, *testClock) {
	t.Helper()
	guard, err := New(t.Context(), ts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	guard.now = func() time.Time { return clock.now }
	t.Cleanup(guard.Wait)
	return guard, clock
}

// testQueue never delivers: every attempt is a temporary failure retried an
// hour later, so admitted messages stay queued for inspection.
func testQueue(t *testing.T, guard *Guard) *queue.Queue {
	t.Helper()
	return testQueueWith(t, guard, nil)
}

// testQueueWith is testQueue with a hook that runs at the start of every
// delivery attempt, before it fails temporarily.
func testQueueWith(t *testing.T, guard *Guard, attempt func(*queue.Message)) *queue.Queue {
	t.Helper()
	q := queue.New(&queue.Config{Screen: guard.Screen, DeliveryHold: guard.DeliveryHold, Delivery: func(_ context.Context, message *queue.Message) error {
		if attempt != nil {
			attempt(message)
		}
		return &queue.DeliveryError{Class: queue.DeliveryTemporary, RetryAfter: time.Hour, Response: "try later"}
	}})
	t.Cleanup(q.Close)
	guard.AttachQueue(q)
	return q
}

// waitHeld waits until the account has want held messages: holds placed
// while a delivery attempt is in progress apply when the attempt ends.
func waitHeld(t *testing.T, guard *Guard, account string, want int) []HeldMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		held := guard.HeldMessages(account)
		if len(held) == want {
			return held
		}
		if time.Now().After(deadline) {
			t.Fatalf("held messages of %s = %+v, want %d", account, held, want)
		}
		time.Sleep(time.Millisecond)
	}
}

var batchSequence atomic.Int64

func batch(account string, recipients ...string) []*queue.Message {
	id := batchSequence.Add(1)
	messages := make([]*queue.Message, 0, len(recipients))
	for index, recipient := range recipients {
		messages = append(messages, &queue.Message{ID: fmt.Sprintf("b%d-%d", id, index), Direction: queue.DirectionOutbound, AuthenticatedActor: account,
			EnvelopeSender: account + "@example.test", Recipient: recipient, Headers: map[string]string{"Subject": "hello"}, Body: []byte("body")})
	}
	return messages
}

func recipients(n int, domain string) []string {
	result := make([]string, n)
	for index := range result {
		result[index] = fmt.Sprintf("user%d@%s", index, domain)
	}
	return result
}

func screen(t *testing.T, guard *Guard, messages []*queue.Message) error {
	t.Helper()
	_, err := guard.Screen(t.Context(), messages)
	return err
}

func TestQuotaCountsSMTPAndAPISubmissionsTogether(t *testing.T) {
	ts := testStore(t)
	guard, _ := testGuard(t, ts, Config{Defaults: Limits{MessagesPerHour: 10, RecipientsPerHour: 3}})
	q := testQueue(t, guard)
	mail := service.NewMail(ts, authz.New(ts), q)
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	if _, err := mail.Submit(t.Context(), alice, service.Submission{From: "alice@example.test", To: []string{"bob@example.test", "x@remote.test"}, Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("API submission: %v", err)
	}
	adapter := queue.NewSMTPAdapter(q)
	smtpBatch := func(recipients ...string) error {
		messages := make([]*smtp.MailMessage, 0, len(recipients))
		for _, recipient := range recipients {
			messages = append(messages, &smtp.MailMessage{EnvelopeSender: "alice@example.test", Recipient: recipient, Outbound: true,
				AuthenticatedActor: "alice", Headers: map[string]string{"Subject": "smtp"}, Content: []byte("Subject: smtp\r\n\r\nbody\r\n")})
		}
		return adapter.EnqueueBatch(messages)
	}
	err := smtpBatch("a@remote.test", "b@remote.test")
	var quota *QuotaError
	if !errors.As(err, &quota) || quota.Limit != LimitRecipientsPerHour || quota.Max != 3 {
		t.Fatalf("SMTP submission over the shared limit = %v, want recipients_per_hour quota error", err)
	}
	var temporary smtp.TemporaryRejection
	if !errors.As(err, &temporary) {
		t.Fatal("quota error is not an SMTP temporary rejection")
	}
	if code, reason := temporary.TemporaryRejection(); code != "4.7.0" || !strings.Contains(reason, "at most 3 recipients per hour") {
		t.Fatalf("SMTP rejection = %s %s", code, reason)
	}
	if err := smtpBatch("a@remote.test"); err != nil {
		t.Fatalf("SMTP submission within the limit: %v", err)
	}
	_, err = mail.Submit(t.Context(), alice, service.Submission{From: "alice@example.test", To: []string{"y@remote.test"}, Subject: "s", Body: "b"})
	if !IsQuota(err) {
		t.Fatalf("API submission over the limit = %v, want quota error", err)
	}
	if got := q.Size(); got != 3 {
		t.Fatalf("queued messages = %d, want 3 (rejected batches are never queued)", got)
	}
	if status, err := guard.Status(t.Context(), "alice"); err != nil || status.Usage != (Usage{MessagesHour: 2, RecipientsHour: 3, RecipientsDay: 3}) {
		t.Fatalf("alice usage = %+v, %v", status.Usage, err)
	}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	if _, err := mail.Submit(t.Context(), bob, service.Submission{From: "bob@example.test", To: []string{"x@remote.test", "y@remote.test", "z@remote.test"}, Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("another account shares no counter: %v", err)
	}
}

func TestServerGeneratedMailIsNotCounted(t *testing.T) {
	guard, _ := testGuard(t, testStore(t), Config{Defaults: Limits{MessagesPerHour: 1}})
	derived := batch("alice", "x@remote.test")
	derived[0].Kind = "dsn"
	for range 3 {
		if err := screen(t, guard, batch("", "x@remote.test")); err != nil {
			t.Fatal(err)
		}
		if err := screen(t, guard, derived); err != nil {
			t.Fatal(err)
		}
	}
	if err := screen(t, guard, batch("alice", "x@remote.test")); err != nil {
		t.Fatalf("first submission: %v", err)
	}
}

func TestQuotaWindowsRollOver(t *testing.T) {
	guard, clock := testGuard(t, testStore(t), Config{Defaults: Limits{MessagesPerHour: 2, RecipientsPerDay: 5}})
	for range 2 {
		if err := screen(t, guard, batch("alice", "x@remote.test")); err != nil {
			t.Fatal(err)
		}
		clock.advance(10 * time.Minute)
	}
	err := screen(t, guard, batch("alice", "x@remote.test"))
	var quota *QuotaError
	if !errors.As(err, &quota) || quota.Limit != LimitMessagesPerHour {
		t.Fatalf("third message = %v", err)
	}
	if quota.RetryAfter != 40*time.Minute {
		t.Fatalf("retry after = %s, want 40m (when the oldest message leaves the hour)", quota.RetryAfter)
	}
	clock.advance(41 * time.Minute)
	if err := screen(t, guard, batch("alice", "x@remote.test")); err != nil {
		t.Fatalf("after the hour rolled over: %v", err)
	}
	// Three recipients used so far; the day window allows two more.
	if err := screen(t, guard, batch("alice", "a@remote.test", "b@remote.test", "c@remote.test")); !IsQuota(err) {
		t.Fatalf("day limit = %v", err)
	}
	clock.advance(22 * time.Hour)
	if err := screen(t, guard, batch("alice", "a@remote.test", "b@remote.test", "c@remote.test")); !IsQuota(err) {
		t.Fatalf("day limit 23h later = %v", err)
	}
	clock.advance(2 * time.Hour)
	if err := screen(t, guard, batch("alice", "a@remote.test", "b@remote.test", "c@remote.test")); err != nil {
		t.Fatalf("after the day rolled over: %v", err)
	}
}

func TestUndoReversesUncommittedSubmission(t *testing.T) {
	guard, _ := testGuard(t, testStore(t), Config{Defaults: Limits{MessagesPerHour: 1}})
	undo, err := guard.Screen(t.Context(), batch("alice", "x@remote.test"))
	if err != nil {
		t.Fatal(err)
	}
	undo()
	if err := screen(t, guard, batch("alice", "x@remote.test")); err != nil {
		t.Fatalf("submission after an undone batch: %v", err)
	}
}

func TestPerAccountOverride(t *testing.T) {
	ts := testStore(t)
	guard, _ := testGuard(t, ts, Config{Defaults: Limits{RecipientsPerHour: 2}})
	five, zero := 5, 0
	if err := guard.SetLimits(t.Context(), "admin", "alice", &model.SendLimits{RecipientsPerHour: &five}); err != nil {
		t.Fatal(err)
	}
	if err := screen(t, guard, batch("alice", recipients(5, "remote.test")...)); err != nil {
		t.Fatalf("override allows five: %v", err)
	}
	if err := screen(t, guard, batch("alice", "extra@remote.test")); !IsQuota(err) {
		t.Fatalf("override exceeded = %v", err)
	}
	if err := screen(t, guard, batch("bob", recipients(3, "remote.test")...)); !IsQuota(err) {
		t.Fatalf("default still applies to bob = %v", err)
	}
	if err := guard.SetLimits(t.Context(), "admin", "alice", &model.SendLimits{RecipientsPerHour: &zero}); err != nil {
		t.Fatal(err)
	}
	if err := screen(t, guard, batch("alice", recipients(50, "remote.test")...)); err != nil {
		t.Fatalf("zero override is unlimited: %v", err)
	}
	if err := guard.SetLimits(t.Context(), "admin", "alice", &model.SendLimits{}); err != nil {
		t.Fatal(err)
	}
	if user, _ := ts.UserStore().Get(t.Context(), "alice"); user.SendLimits != nil {
		t.Fatalf("empty override stored = %+v", user.SendLimits)
	}
	if err := screen(t, guard, batch("alice", "again@remote.test")); !IsQuota(err) {
		t.Fatalf("cleared override restores the default = %v", err)
	}
	negative := -1
	if err := guard.SetLimits(t.Context(), "admin", "alice", &model.SendLimits{MessagesPerHour: &negative}); err == nil {
		t.Fatal("negative override accepted")
	}
}

func TestDomainDefaultLimitsApplyBeneathAccountOverrides(t *testing.T) {
	ts := testStore(t)
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	four, one := 4, 1
	if err := ts.DomainStore().SetLimits(t.Context(), "example.test", model.DomainLimits{DefaultSendLimits: &model.SendLimits{RecipientsPerHour: &four}}); err != nil {
		t.Fatal(err)
	}
	guard, _ := testGuard(t, ts, Config{Defaults: Limits{RecipientsPerHour: 2, MessagesPerHour: 100}})
	if err := screen(t, guard, batch("bob", recipients(4, "remote.test")...)); err != nil {
		t.Fatalf("domain default allows four: %v", err)
	}
	if err := screen(t, guard, batch("bob", "extra@remote.test")); !IsQuota(err) {
		t.Fatalf("domain default exceeded = %v", err)
	}
	status, err := guard.Status(t.Context(), "bob")
	if err != nil || status.Defaults.RecipientsPerHour != 4 || status.Defaults.MessagesPerHour != 100 || status.Effective.RecipientsPerHour != 4 {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if err := guard.SetLimits(t.Context(), "admin", "alice", &model.SendLimits{RecipientsPerHour: &one}); err != nil {
		t.Fatal(err)
	}
	if err := screen(t, guard, batch("alice", recipients(2, "remote.test")...)); !IsQuota(err) {
		t.Fatalf("account override wins over the domain default = %v", err)
	}
}

func TestParseLimits(t *testing.T) {
	limits, err := ParseLimits(DefaultLimits().Entries())
	if err != nil || limits != DefaultLimits() {
		t.Fatalf("round trip = %+v, %v", limits, err)
	}
	if limits, err := ParseLimits([]string{"recipients_per_day = 7"}); err != nil || limits != (Limits{RecipientsPerDay: 7}) {
		t.Fatalf("partial = %+v, %v", limits, err)
	}
	for _, invalid := range [][]string{{"messages_per_minute=1"}, {"messages_per_hour"}, {"messages_per_hour=-1"}, {"messages_per_hour=1", "messages_per_hour=2"}} {
		if _, err := ParseLimits(invalid); err == nil {
			t.Errorf("%q accepted", invalid)
		}
	}
}

func signalPoints(assessment Assessment, name string) float64 {
	for _, signal := range assessment.Signals {
		if signal.Name == name {
			return signal.Points
		}
	}
	return 0
}

func TestHeuristicsEachContribute(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	t.Run("volume spike against baseline", func(t *testing.T) {
		state := newAccountState(start.Add(-48 * time.Hour))
		for hour := 48; hour >= 2; hour-- {
			state.record(start.Add(-time.Duration(hour)*time.Hour), 2, nil)
		}
		state.record(start, 49, nil)
		if points := signalPoints(state.assess(start, 80), SignalVolumeSpike); points != 0 {
			t.Fatalf("49 recipients scored %v", points)
		}
		state.record(start, 1, nil)
		if points := signalPoints(state.assess(start, 80), SignalVolumeSpike); points != pointsSpike {
			t.Fatalf("50 recipients against a baseline of ~2 scored %v", points)
		}
		state.record(start, 50, nil)
		if points := signalPoints(state.assess(start, 80), SignalVolumeSpike); points != pointsSpikeStrong {
			t.Fatalf("100 recipients scored %v", points)
		}
	})
	t.Run("new recipient domains", func(t *testing.T) {
		warm := newAccountState(start.Add(-48 * time.Hour))
		cold := newAccountState(start)
		var domains []string
		for index := range newDomainsModerate {
			domains = append(domains, fmt.Sprintf("d%d.test", index))
		}
		warm.record(start, len(domains), domains)
		cold.record(start, len(domains), domains)
		if points := signalPoints(warm.assess(start, 80), SignalNewDomains); points != pointsModerate {
			t.Fatalf("warm profile scored %v", points)
		}
		if points := signalPoints(cold.assess(start, 80), SignalNewDomains); points != 0 {
			t.Fatalf("cold profile scored %v for ten domains", points)
		}
		warm.record(start.Add(time.Minute), len(domains), domains)
		if points := signalPoints(warm.assess(start.Add(time.Minute), 80), SignalNewDomains); points != pointsModerate {
			t.Fatalf("known domains counted again: %v", points)
		}
		if points := signalPoints(warm.assess(start.Add(61*time.Minute), 80), SignalNewDomains); points != 0 {
			t.Fatalf("new domains older than an hour scored %v", points)
		}
	})
	t.Run("bounce rate", func(t *testing.T) {
		state := newAccountState(start)
		for index := range 10 {
			state.recordOutcome(start, index < 3)
		}
		if points := signalPoints(state.assess(start, 80), SignalBounceRate); points != pointsModerate {
			t.Fatalf("30%% failures scored %v", points)
		}
		for range 10 {
			state.recordOutcome(start, true)
		}
		if points := signalPoints(state.assess(start, 80), SignalBounceRate); points != pointsStrong {
			t.Fatalf("65%% failures scored %v", points)
		}
		if points := signalPoints(state.assess(start.Add(25*time.Hour), 80), SignalBounceRate); points != 0 {
			t.Fatalf("outcomes older than a day scored %v", points)
		}
	})
	t.Run("queue outcomes feed the bounce rate", func(t *testing.T) {
		guard, _ := testGuard(t, testStore(t), Config{CompromiseThreshold: 1000})
		submitted := queue.Message{Direction: queue.DirectionOutbound, AuthenticatedActor: "alice"}
		inbound := queue.Message{Direction: queue.DirectionInbound, AuthenticatedActor: "alice"}
		for index := range 10 {
			guard.RecordOutcome(t.Context(), submitted, map[bool]queue.Status{true: queue.StatusFailed, false: queue.StatusDelivered}[index < 6])
			guard.RecordOutcome(t.Context(), submitted, queue.StatusRetrying)
			guard.RecordOutcome(t.Context(), inbound, queue.StatusFailed)
		}
		status, _ := guard.Status(t.Context(), "alice")
		if points := signalPoints(status.Assessment, SignalBounceRate); points != pointsStrong || !strings.Contains(status.Assessment.Signals[0].Detail, "6 of 10") {
			t.Fatalf("bounce signal = %+v", status.Assessment)
		}
	})
	t.Run("login spread counts networks", func(t *testing.T) {
		state := newAccountState(start)
		for host := range 20 {
			state.recordLogin(start, networkPrefix(fmt.Sprintf("192.0.2.%d", host)))
		}
		state.recordLogin(start, networkPrefix("2001:db8:1:1::1"))
		state.recordLogin(start, networkPrefix("2001:db8:1:2::1"))
		if points := signalPoints(state.assess(start, 80), SignalLoginSpread); points != 0 {
			t.Fatalf("two networks scored %v", points)
		}
		for network := range 3 {
			state.recordLogin(start, networkPrefix(fmt.Sprintf("198.51.%d.7", network)))
		}
		if points := signalPoints(state.assess(start, 80), SignalLoginSpread); points != pointsModerate {
			t.Fatalf("five networks scored %v", points)
		}
	})
	t.Run("spam content through the scorer", func(t *testing.T) {
		guard, _ := testGuard(t, testStore(t), Config{CompromiseThreshold: 1000})
		guard.SetContentScorer(func(_ context.Context, message *queue.Message) (float64, bool) {
			return 9, strings.Contains(string(message.Body), "viagra")
		})
		spammy := batch("alice", "x@remote.test")
		spammy[0].Body = []byte("cheap viagra")
		if err := screen(t, guard, spammy); err != nil {
			t.Fatal(err)
		}
		status, _ := guard.Status(t.Context(), "alice")
		if points := signalPoints(status.Assessment, SignalSpamContent); points != pointsModerate {
			t.Fatalf("spam submission scored %v: %+v", points, status.Assessment)
		}
	})
}

func TestHoldReleaseAndPurgeFlow(t *testing.T) {
	ts := testStore(t)
	guard, clock := testGuard(t, ts, Config{CompromiseThreshold: 50, HoldEnabled: true})
	// The first attempt of alice's first message is still in progress when
	// the guard trips: the hold must apply when the attempt ends rather than
	// let the message retry and escape.
	attempting, finishAttempt := make(chan struct{}), make(chan struct{})
	var gated atomic.Bool
	var gatedID string
	q := testQueueWith(t, guard, func(message *queue.Message) {
		if message.Recipient == "before@remote.test" && gated.CompareAndSwap(false, true) {
			gatedID = message.ID
			close(attempting)
			<-finishAttempt
		}
	})
	finish := sync.OnceFunc(func() { close(finishAttempt) })
	t.Cleanup(finish) // runs before the queue closes, even on failure
	var notified atomic.Int32
	guard.SetHoldNotifier(func(_ context.Context, account string, hold model.OutboundHold) {
		if account == "alice" && hold.Score >= 50 {
			notified.Add(1)
		}
	})
	if err := q.EnqueueBatch(batch("alice", "before@remote.test")); err != nil {
		t.Fatal(err)
	}
	<-attempting
	if err := q.EnqueueBatch(batch("bob", "bob@remote.test")); err != nil {
		t.Fatal(err)
	}
	trip := func() {
		for network := range loginPrefixStrong {
			guard.RecordLogin(t.Context(), "alice", fmt.Sprintf("203.0.%d.1", network))
		}
		guard.Wait()
	}
	trip()
	if message := q.Get(gatedID); message.Status != queue.StatusProcessing || message.PendingHoldReason != HoldReason {
		t.Fatalf("in-progress message after the hold = %+v", message)
	}
	finish()
	waitHeld(t, guard, "alice", 1)
	user, _ := ts.UserStore().Get(t.Context(), "alice")
	if user.OutboundHold == nil || user.OutboundHold.Signals[0] != SignalLoginSpread {
		t.Fatalf("persisted hold = %+v", user.OutboundHold)
	}
	if notified.Load() != 1 {
		t.Fatalf("owner notifications = %d, want 1", notified.Load())
	}
	if err := q.EnqueueBatch(batch("alice", "after@remote.test")); err != nil {
		t.Fatalf("held account submission is accepted, not rejected: %v", err)
	}
	held := waitHeld(t, guard, "alice", 2)
	if len(held) != 2 || held[0].Recipient != "before@remote.test" || held[1].Recipient != "after@remote.test" || held[0].Subject != "hello" {
		t.Fatalf("held messages = %+v", held)
	}
	for _, message := range q.List("") {
		if wantHeld := message.AuthenticatedActor == "alice"; (message.Status == queue.StatusPaused) != wantHeld {
			t.Fatalf("%s from %s status = %s", message.ID, message.AuthenticatedActor, message.Status)
		}
	}
	// More evidence while held neither re-holds nor re-notifies.
	clock.advance(time.Minute)
	trip()
	if notified.Load() != 1 {
		t.Fatalf("owner notifications after more evidence = %d", notified.Load())
	}
	restarted, err := New(t.Context(), ts, guard.Config())
	if err != nil {
		t.Fatal(err)
	}
	if accounts := restarted.HeldAccounts(); len(accounts) != 1 || accounts[0].Account != "alice" || !accounts[0].Held {
		t.Fatalf("held accounts after restart = %+v", accounts)
	}

	released, err := guard.Release(t.Context(), "admin", "alice")
	if err != nil || released != 2 {
		t.Fatalf("release = %d, %v", released, err)
	}
	for _, message := range q.List(queue.StatusPaused) {
		t.Fatalf("message %s still paused after release", message.ID)
	}
	if user, _ := ts.UserStore().Get(t.Context(), "alice"); user.OutboundHold != nil {
		t.Fatal("hold not cleared")
	}
	// Evidence from before the release cannot trip the guard again.
	guard.RecordLogin(t.Context(), "alice", "203.0.1.1")
	if accounts := guard.HeldAccounts(); len(accounts) != 0 {
		t.Fatalf("released account re-held by old evidence: %+v", accounts)
	}

	clock.advance(time.Minute)
	trip()
	if notified.Load() != 2 {
		t.Fatalf("owner notifications after the second hold = %d", notified.Load())
	}
	if err := q.EnqueueBatch(batch("alice", "spam@remote.test")); err != nil {
		t.Fatal(err)
	}
	// The second hold also re-held the two released messages still queued,
	// including any whose resumed attempt was in progress.
	waitHeld(t, guard, "alice", 3)
	purged, err := guard.Purge(t.Context(), "admin", "alice")
	if err != nil || purged != 3 {
		t.Fatalf("purge = %d, %v", purged, err)
	}
	if len(guard.HeldMessages("alice")) != 0 || len(q.List(queue.StatusCancelled)) != 3 {
		t.Fatal("purge did not cancel the held message")
	}
	if accounts := guard.HeldAccounts(); len(accounts) != 1 || !accounts[0].Held {
		t.Fatalf("purge must keep the hold until release: %+v", accounts)
	}
}

func TestHoldDisabledOnlyFlagsTheAccount(t *testing.T) {
	guard, _ := testGuard(t, testStore(t), Config{CompromiseThreshold: 50})
	q := testQueue(t, guard)
	for network := range loginPrefixStrong {
		guard.RecordLogin(t.Context(), "alice", fmt.Sprintf("203.0.%d.1", network))
	}
	if err := q.EnqueueBatch(batch("alice", "x@remote.test")); err != nil {
		t.Fatal(err)
	}
	if paused := q.List(queue.StatusPaused); len(paused) != 0 {
		t.Fatalf("mail held while holding is disabled: %d", len(paused))
	}
	observations := guard.Observations()
	if len(observations) != 1 || observations[0].Severity != health.SeverityWarning {
		t.Fatalf("observations = %+v", observations)
	}
	if status, _ := guard.Status(t.Context(), "alice"); !status.Suspected || status.Hold != nil {
		t.Fatalf("status = %+v", status)
	}
}

func TestHeldAccountRaisesOneAlert(t *testing.T) {
	ts := testStore(t)
	guard, clock := testGuard(t, ts, Config{CompromiseThreshold: 50, HoldEnabled: true})
	testQueue(t, guard)
	alerts, err := health.NewAlertStore(t.Context(), ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	registry := health.New()
	evaluate := func() []health.Transition {
		t.Helper()
		if err := registry.Replace(clock.now, guard.Observations()); err != nil {
			t.Fatal(err)
		}
		transitions, err := alerts.Evaluate(t.Context(), registry.Snapshot(clock.now))
		if err != nil {
			t.Fatal(err)
		}
		return transitions
	}
	trip := func() {
		for network := range loginPrefixStrong {
			guard.RecordLogin(t.Context(), "alice", fmt.Sprintf("203.0.%d.1", network))
		}
		guard.Wait()
	}
	trip()
	transitions := evaluate()
	if len(transitions) != 1 || transitions[0].Type != health.TransitionOpened || transitions[0].Alert.ComponentID != "outbound-hold:alice" || transitions[0].Alert.Severity != health.SeverityCritical {
		t.Fatalf("first evaluation = %+v", transitions)
	}
	clock.advance(time.Minute)
	trip()
	if transitions := evaluate(); len(transitions) != 0 {
		t.Fatalf("repeated evaluation raised %+v", transitions)
	}
	if _, err := guard.Release(t.Context(), "admin", "alice"); err != nil {
		t.Fatal(err)
	}
	if transitions := evaluate(); len(transitions) != 1 || transitions[0].Type != health.TransitionResolved {
		t.Fatalf("after release = %+v", transitions)
	}
}
