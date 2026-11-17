package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dkim/dkimtest"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
)

// mailFlowQueue is a system queue with the production admission and copy
// hooks whose deliveries stay pending.
func mailFlowQueue(t *testing.T, s *server) *queue.Queue {
	t.Helper()
	mailQueue := queue.New(&queue.Config{Admission: s.queueAdmission(), Copies: s.mailFlowCopies, Signer: dkim.NewSigner(s.ts.DomainStore()),
		Delivery: func(context.Context, *queue.Message) error {
			return &queue.DeliveryError{Class: queue.DeliveryDeferred, EnhancedCode: "4.0.0", Response: "held for the test"}
		}})
	t.Cleanup(mailQueue.Close)
	return mailQueue
}

func TestOutboundRewritingIsSignedAfterRewriteAndAppliesLive(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	rule, err := s.ts.AddressRewriteStore().Create(ctx, model.AddressRewrite{MailFlowRule: model.MailFlowRule{Enabled: true}, Direction: model.RewriteOutbound,
		Pattern: "@internal.example", Replacement: "@example.test", EnvelopeSender: true, HeaderFrom: true})
	if err != nil {
		t.Fatal(err)
	}
	mailQueue := mailFlowQueue(t, s)
	content := []byte("From: Alice Example <Alice@Internal.Example>\r\nTo: carol@remote.test\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nHi Carol.\r\n")
	submit := func(id string, actor string, request *dkim.Request) *queue.Message {
		t.Helper()
		headers, _ := model.ParseMessageHeaders(content)
		if err := mailQueue.Enqueue(&queue.Message{ID: id, EnvelopeSender: "alice@internal.example", Recipient: "carol@remote.test",
			Headers: headers, Content: content, AuthenticatedActor: actor, DKIM: request}); err != nil {
			t.Fatal(err)
		}
		return mailQueue.Get(id)
	}

	submitted := submit("submitted", "alice", &dkim.Request{})
	if submitted.EnvelopeSender != "alice@example.test" || submitted.Headers["From"] != "Alice Example <Alice@example.test>" ||
		!bytes.Contains(submitted.Content, []byte("\r\nFrom: Alice Example <Alice@example.test>\r\n")) || bytes.Contains(submitted.Content, []byte("Internal.Example")) {
		t.Fatalf("rewritten submission: sender=%q from=%q\n%s", submitted.EnvelopeSender, submitted.Headers["From"], submitted.Content)
	}
	if submitted.Attributes[attributeAddressRewrite] == "" {
		t.Fatalf("rewrite not recorded: %v", submitted.Attributes)
	}
	// The DKIM signature is made after the rewrite, for the rewritten domain.
	if result := verifier.Verify(ctx, submitted.Content); !result.Pass || result.Domain != "example.test" {
		t.Fatalf("verification after rewrite = %+v", result)
	}
	// Relayed mail is not locally originated and keeps its addresses.
	if relayed := submit("relayed", "", nil); relayed.EnvelopeSender != "alice@internal.example" || relayed.Attributes[attributeAddressRewrite] != "" {
		t.Fatalf("relayed mail rewritten: %+v", relayed)
	}
	// Rule changes apply to the next message.
	if err := s.ts.AddressRewriteStore().Delete(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if after := submit("after-delete", "alice", &dkim.Request{}); after.EnvelopeSender != "alice@internal.example" {
		t.Fatalf("deleted rule still applied: %q", after.EnvelopeSender)
	}
}

func TestInboundRecipientRewritingAtResolution(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	if folder, _, err := s.resolveLocalAddress(ctx, "alice@legacy.test"); err == nil {
		t.Fatalf("unrewritten legacy address resolved to %q", folder)
	}
	if _, err := s.ts.AddressRewriteStore().Create(ctx, model.AddressRewrite{MailFlowRule: model.MailFlowRule{Enabled: true}, Direction: model.RewriteInbound,
		Pattern: "legacy.test", Replacement: "@example.test"}); err != nil {
		t.Fatal(err)
	}
	folder, owner, err := s.resolveLocalAddress(ctx, "alice@legacy.test")
	if err != nil || owner != "alice" || folder != model.InboxFolderID("alice") {
		t.Fatalf("rewritten recipient = %q, %q, %v", folder, owner, err)
	}
	if rewritten, err := s.smtpDelivery().RewriteRecipient(ctx, "bob@legacy.test"); err != nil || rewritten != "bob@example.test" {
		t.Fatalf("RCPT rewrite = %q, %v", rewritten, err)
	}
}

func TestSenderRoutePrecedenceSealedCredentialsAndTLSPolicy(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	sealer, err := migration.NewStore(ctx, s.ts.Store())
	if err != nil {
		t.Fatal(err)
	}
	s.routeSecrets = sealer
	global, domainRelay, senderRelay, pairRelay := startFakeRelay(t), startFakeRelay(t), startFakeRelay(t), startFakeRelay(t)
	relayCfg := config.Default()
	relayCfg.RelayHost, relayCfg.RelayPort = "127.0.0.1", global.port
	if err := applierFor(t, s, "relay_host")(relayCfg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ts.OutboundRouteStore().Create(ctx, model.OutboundRoute{Domain: "partner.test", Transport: model.OutboundTransportRelay, RelayHost: "127.0.0.1", RelayPort: domainRelay.port, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	senderRoute, err := s.ts.SenderRouteStore().Create(ctx, model.SenderRoute{MailFlowRule: model.MailFlowRule{Enabled: true}, Sender: "example.test",
		Transport: model.OutboundTransportRelay, RelayHost: "127.0.0.1", RelayPort: senderRelay.port, Username: "smarthost"})
	if err != nil {
		t.Fatal(err)
	}
	if senderRoute.SealedPassword, err = sealer.SealSecret(model.SenderRouteSecretPurpose, senderRoute.ID, []byte("s3cret")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(senderRoute.SealedPassword, []byte("s3cret")) {
		t.Fatal("relay password is stored in clear")
	}
	if senderRoute, err = s.ts.SenderRouteStore().Set(ctx, senderRoute.ID, senderRoute); err != nil {
		t.Fatal(err)
	}
	pairRoute, err := s.ts.SenderRouteStore().Create(ctx, model.SenderRoute{MailFlowRule: model.MailFlowRule{Enabled: true}, Sender: "example.test", Destination: "partner.test",
		Transport: model.OutboundTransportRelay, RelayHost: "127.0.0.1", RelayPort: pairRelay.port})
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(sender, recipient string) error {
		return s.deliver(ctx, &queue.Message{ID: "m-" + sender + "-" + recipient, EnvelopeSender: sender, Recipient: recipient,
			Headers: map[string]string{"From": sender, "Subject": "route"}, Body: []byte("body")})
	}
	counts := func() [4]int32 {
		return [4]int32{global.accepted.Load(), domainRelay.accepted.Load(), senderRelay.accepted.Load(), pairRelay.accepted.Load()}
	}
	for _, step := range []struct {
		sender, recipient string
		want              [4]int32
	}{
		{"bob@example.test", "carol@remote.test", [4]int32{0, 0, 1, 0}}, // sender route
		{"bob@example.test", "x@partner.test", [4]int32{0, 0, 1, 1}},    // sender+destination beats sender and destination
		{"z@other.test", "x@partner.test", [4]int32{0, 1, 1, 1}},        // destination route
		{"z@other.test", "carol@remote.test", [4]int32{1, 1, 1, 1}},     // default smart host
	} {
		if err := deliver(step.sender, step.recipient); err != nil {
			t.Fatalf("deliver %s -> %s: %v", step.sender, step.recipient, err)
		}
		if got := counts(); got != step.want {
			t.Fatalf("deliver %s -> %s: relay counts %v, want %v", step.sender, step.recipient, got, step.want)
		}
	}
	if auth := senderRelay.auth.Load(); auth == nil || *auth != "\x00smarthost\x00s3cret" {
		t.Fatalf("sender relay AUTH = %v", auth)
	}
	if pairRelay.auth.Load() != nil {
		t.Fatal("route without credentials authenticated")
	}

	// TLS policy: a route that requires TLS refuses a relay without STARTTLS.
	pairRoute.RequireTLS = true
	if _, err := s.ts.SenderRouteStore().Set(ctx, pairRoute.ID, pairRoute); err != nil {
		t.Fatal(err)
	}
	if err := deliver("bob@example.test", "y@partner.test"); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("delivery over a route requiring TLS = %v", err)
	}
	if got := pairRelay.accepted.Load(); got != 1 {
		t.Fatalf("route requiring TLS delivered in clear: %d", got)
	}
	// Removing the sender routes applies to the next delivery.
	for _, id := range []string{senderRoute.ID, pairRoute.ID} {
		if err := s.ts.SenderRouteStore().Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := deliver("bob@example.test", "carol@remote.test"); err != nil || global.accepted.Load() != 2 {
		t.Fatalf("delivery after removing sender routes: %v, global %d", err, global.accepted.Load())
	}
}

func TestJournalAndAlwaysBCCCopies(t *testing.T) {
	s := liveAddressingServer(t)
	ctx := s.ctx
	journal, err := s.ts.JournalRuleStore().Create(ctx, model.JournalRule{MailFlowRule: model.MailFlowRule{Enabled: true}, Inbound: true, Outbound: true, Address: "journal@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []model.BCCRule{
		{Match: model.BCCSender, Pattern: "example.test", Address: "archive@remote.test"},
		{Match: model.BCCRecipient, Pattern: "bob@example.test", Address: "audit@example.test"},
	} {
		rule.Enabled = true
		if _, err := s.ts.BCCRuleStore().Create(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}
	mailQueue := mailFlowQueue(t, s)
	content := []byte("From: alice@example.test\r\nTo: carol@remote.test\r\nCc: dave@remote.test\r\nSubject: Plans\r\nMessage-ID: <plans@example.test>\r\n\r\nSecret plans.\r\n")
	headers, _ := model.ParseMessageHeaders(content)
	message := func(id, correlation, sender, recipient, actor string) *queue.Message {
		return &queue.Message{ID: id, CorrelationID: correlation, EnvelopeSender: sender, Recipient: recipient, Headers: headers, Content: content, AuthenticatedActor: actor}
	}

	// An outbound submission to To, Cc, and Bcc recipients.
	if err := mailQueue.EnqueueBatch([]*queue.Message{
		message("out-1", "submission", "alice@example.test", "carol@remote.test", "alice"),
		message("out-2", "submission", "alice@example.test", "dave@remote.test", "alice"),
		message("out-3", "submission", "alice@example.test", "erin@remote.test", "alice"),
	}); err != nil {
		t.Fatal(err)
	}
	bcc := mailQueue.Get("out-1.bcc1")
	if bcc == nil || bcc.Kind != mailKindBCC || bcc.Recipient != "archive@remote.test" || bcc.EnvelopeSender != "alice@example.test" || bcc.ParentID != "out-1" ||
		bcc.Attributes["dsn_notify"] != "never" || !bytes.Equal(bcc.Content, content) {
		t.Fatalf("sender BCC copy = %+v", bcc)
	}
	copied := mailQueue.Get("out-1.journal1")
	if copied == nil || copied.Kind != mailKindJournal || copied.Recipient != journal.Address || copied.EnvelopeSender != "" || copied.CorrelationID != "submission" {
		t.Fatalf("outbound journal copy = %+v", copied)
	}
	for _, want := range []string{"Direction: outbound", "To: carol@remote.test", "Cc: dave@remote.test", "Bcc: erin@remote.test", "Bcc: archive@remote.test", "Secret plans."} {
		if !bytes.Contains(copied.Content, []byte(want)) {
			t.Fatalf("journal report lacks %q:\n%s", want, copied.Content)
		}
	}
	if got := len(mailQueue.List("")); got != 5 {
		t.Fatalf("queued %d messages after the submission, want 3 originals and 2 copies", got)
	}

	// Inbound mail to a local recipient.
	inbound := message("in-1", "smtp-transaction", "x@remote.test", "bob@example.test", "")
	inbound.Direction, inbound.TargetOwnerID, inbound.TargetFolderID = queue.DirectionInbound, "bob", model.InboxFolderID("bob")
	if err := mailQueue.Enqueue(inbound); err != nil {
		t.Fatal(err)
	}
	if bcc := mailQueue.Get("in-1.bcc1"); bcc == nil || bcc.Recipient != "audit@example.test" || bcc.TargetFolderID != "" {
		t.Fatalf("recipient BCC copy = %+v", bcc)
	}
	if copied := mailQueue.Get("in-1.journal1"); copied == nil || !bytes.Contains(copied.Content, []byte("Direction: inbound")) || !bytes.Contains(copied.Content, []byte("Bcc: bob@example.test")) {
		t.Fatalf("inbound journal copy = %+v", copied)
	}

	// Journal copies are never journaled again: neither a queued copy nor
	// one that returns addressed only to the journal address.
	before := len(mailQueue.List(""))
	again := message("again", "again", "", journal.Address, "")
	again.Kind = mailKindJournal
	returned := message("returned", "returned", "x@remote.test", journal.Address, "")
	if err := mailQueue.EnqueueBatch([]*queue.Message{again, returned}); err != nil {
		t.Fatal(err)
	}
	if got := len(mailQueue.List("")); got != before+2 {
		t.Fatalf("journal copies were copied: %d messages, want %d", got, before+2)
	}

	// Rule changes apply to the next message.
	journal.Enabled = false
	if _, err := s.ts.JournalRuleStore().Set(ctx, journal.ID, journal); err != nil {
		t.Fatal(err)
	}
	if err := mailQueue.Enqueue(message("late", "late", "x@remote.test", "carol@remote.test", "")); err != nil {
		t.Fatal(err)
	}
	if mailQueue.Get("late.journal1") != nil {
		t.Fatal("disabled journal rule still copied")
	}
}
