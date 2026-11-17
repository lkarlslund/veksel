package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/queue"
	"github.com/lkarlslund/veksel/pkg/smtp"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

type recordingMailQueue struct {
	messages []*queue.Message
	err      error
	accepted map[string]bool
}

func (q *recordingMailQueue) EnqueueBatch(messages []*queue.Message) error {
	if q.err != nil {
		return q.err
	}
	q.messages = append(q.messages, messages...)
	return nil
}

func (q *recordingMailQueue) EnqueueBatchIdempotent(key string, messages []*queue.Message) error {
	if q.err != nil {
		return q.err
	}
	if q.accepted == nil {
		q.accepted = make(map[string]bool)
	}
	if q.accepted[key] {
		return nil
	}
	q.accepted[key] = true
	q.messages = append(q.messages, messages...)
	return nil
}

func testMailService(t testing.TB) (*Mail, *model.TypedStore, *recordingMailQueue) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	for _, namespace := range []string{
		model.NSDomains, model.NSUsers, model.NSEmails, model.NSFolders, model.NSItems,
		model.NSRoles, model.NSGroups, model.NSPolicyBindings, model.NSPolicyIndexes,
	} {
		if err := ts.EnsureNamespace(context.Background(), namespace); err != nil {
			t.Fatalf("ensure namespace %q: %v", namespace, err)
		}
	}
	for _, userID := range []string{"alice", "bob"} {
		if err := ts.UserStore().Create(t.Context(), userID, strings.ToUpper(userID), "password123"); err != nil {
			t.Fatalf("create user %q: %v", userID, err)
		}
		if err := ts.FolderStore().CreateForUser(t.Context(), userID); err != nil {
			t.Fatalf("create folders for %q: %v", userID, err)
		}
		if err := ts.UserStore().AddEmailAddress(t.Context(), userID+"@example.test", userID, "example.test", true); err != nil {
			t.Fatalf("create identity for %q: %v", userID, err)
		}
	}
	recorder := &recordingMailQueue{}
	return NewMail(ts, authz.New(ts), recorder), ts, recorder
}

func TestMailSubmitNormal(t *testing.T) {
	mailService, ts, recorder := testMailService(t)

	result, err := mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, Submission{
		From: "ALICE@example.test", To: []string{"Bob <bob@example.test>", "bob@example.test"},
		CC: []string{"outside@example.net"}, BCC: []string{"hidden@example.net"},
		Subject: "Hello\r\nBcc: injected@example.net", Body: "Hello from Veksel.",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(recorder.messages) != 3 {
		t.Fatalf("queued messages = %d, want 3", len(recorder.messages))
	}
	if recorder.messages[0].ID == recorder.messages[1].ID {
		t.Fatal("recipient queue IDs are not unique")
	}
	if got := recorder.messages[0].EnvelopeSender; got != "alice@example.test" {
		t.Fatalf("envelope sender = %q", got)
	}
	for _, message := range recorder.messages {
		if message.Attributes != nil {
			t.Fatalf("ordinary submission attributes = %#v, want nil", message.Attributes)
		}
		if _, present := message.Headers["Bcc"]; present {
			t.Fatal("Bcc leaked into message headers")
		}
		if strings.ContainsAny(message.Headers["Subject"], "\r\n") {
			t.Fatalf("subject contains line break: %q", message.Headers["Subject"])
		}
	}
	item, err := ts.ItemStore().Get(t.Context(), result.SentItemID)
	if err != nil {
		t.Fatalf("read Sent copy: %v", err)
	}
	if item.FolderID != model.SentFolderID("alice") || !strings.Contains(string(item.Data), "Hello from Veksel.") {
		t.Fatalf("unexpected Sent copy: folder=%q data=%q", item.FolderID, item.Data)
	}
	recent, err := ts.ItemStore().GetByExternalID(t.Context(), model.RecentRecipientsFolderID("alice"), recipientHistoryNamespace, "bob@example.test")
	if err != nil {
		t.Fatalf("read recent recipient: %v", err)
	}
	if contact := model.ParseVCard(recent.Data); contact.FN != "Bob" {
		t.Fatalf("recent recipient = %#v", contact)
	}
}

func TestMailSubmitRequireTLSReachesEveryRecipientWithoutMessageHeader(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	result, err := mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, Submission{
		From: "alice@example.test", To: []string{"bob@example.test", "outside@example.net"}, Subject: "Private", Body: "Encrypt transport.", RequireTLS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.messages) != 2 {
		t.Fatalf("queued messages = %d, want 2", len(recorder.messages))
	}
	for _, message := range recorder.messages {
		if message.Attributes[smtp.AttributeRequireTLS] != "true" {
			t.Fatalf("queue attributes = %#v", message.Attributes)
		}
		for _, name := range []string{"TLS-Required", "X-Veksel-Require-TLS"} {
			if _, present := message.Headers[name]; present {
				t.Fatalf("delivery policy leaked as message header %q", name)
			}
		}
	}
	sent, err := ts.ItemStore().Get(t.Context(), result.SentItemID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sent.Data), "X-Veksel-Require-TLS") || strings.Contains(string(sent.Data), "TLS-Required") {
		t.Fatalf("delivery policy leaked into Sent copy: %q", sent.Data)
	}
}

func TestMailSubmitImportanceReachesQueueAndSentCopy(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	result, err := mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, Submission{
		From: "alice@example.test", To: []string{"bob@example.test", "outside@example.net"}, Subject: "Important", Body: "Please read.", Importance: MailImportanceHigh,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.messages) != 2 {
		t.Fatalf("queued messages = %d, want 2", len(recorder.messages))
	}
	for _, message := range recorder.messages {
		if got := MessageImportance(message.Headers); got != MailImportanceHigh || message.Headers["Importance"] != "high" || message.Headers["X-Priority"] != "1" || message.Headers["Priority"] != "urgent" {
			t.Fatalf("queued importance = %q, headers=%#v", got, message.Headers)
		}
	}
	sent, err := ts.ItemStore().Get(t.Context(), result.SentItemID)
	if err != nil {
		t.Fatal(err)
	}
	if got := MessageImportance(sent.Headers); got != MailImportanceHigh || !strings.Contains(string(sent.Data), "Importance: high\r\n") || !strings.Contains(string(sent.Data), "X-Priority: 1\r\n") {
		t.Fatalf("Sent importance = %q, headers=%#v data=%q", got, sent.Headers, sent.Data)
	}
}

func TestMailSubmitRejectsInvalidImportanceWithoutDurableEffects(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	_, err := mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, Submission{
		From: "alice@example.test", To: []string{"bob@example.test"}, Subject: "Invalid", Body: "No", Importance: "critical",
	})
	if err == nil || !strings.Contains(err.Error(), "importance") {
		t.Fatalf("invalid importance error = %v", err)
	}
	if len(recorder.messages) != 0 {
		t.Fatalf("invalid importance queued %d messages", len(recorder.messages))
	}
	items, listErr := ts.ItemStore().List(t.Context(), model.SentFolderID("alice"))
	if listErr != nil || len(items) != 0 {
		t.Fatalf("invalid importance Sent items=%d err=%v", len(items), listErr)
	}
}

func TestMailSubmitIdempotentReusesSentCopyAndDeliveryBatch(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	request := Submission{From: "alice@example.test", To: []string{"bob@example.test"}, Subject: "Later", Body: "Stable body", RequireTLS: true}
	first, err := mailService.SubmitIdempotent(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, request, "scheduled:alice:job-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := mailService.SubmitIdempotent(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, request, "scheduled:alice:job-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.SentItemID != second.SentItemID || len(recorder.messages) != 1 {
		t.Fatalf("idempotent results first=%+v second=%+v queued=%d", first, second, len(recorder.messages))
	}
	sent, err := ts.ItemStore().GetByExternalID(t.Context(), model.SentFolderID("alice"), "veksel.mail-submission", "scheduled:alice:job-1")
	if err != nil || sent.ID != first.SentItemID {
		t.Fatalf("stable Sent item = %+v, %v", sent, err)
	}
	if recorder.messages[0].AuthenticatedActor != "alice" || recorder.messages[0].CorrelationID != first.ID {
		t.Fatalf("queue submission evidence = %+v", recorder.messages[0])
	}
	if recorder.messages[0].Attributes[smtp.AttributeRequireTLS] != "true" {
		t.Fatalf("idempotent queue attributes = %#v", recorder.messages[0].Attributes)
	}
}

func TestMailSubmitBuildsAttachmentMIMEForQueueAndSentCopy(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	result, err := mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, Submission{
		From: "alice@example.test", To: []string{"bob@example.test"}, Subject: "Attached", Body: "See file.",
		Attachments: []SubmissionAttachment{{Name: "hello.txt", ContentType: "text/plain", Data: []byte("attachment data")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.messages) != 1 || !strings.HasPrefix(recorder.messages[0].Headers["Content-Type"], "multipart/mixed") || !strings.Contains(string(recorder.messages[0].Body), "YXR0YWNobWVudCBkYXRh") {
		t.Fatalf("queued MIME = %#v", recorder.messages)
	}
	sent, err := ts.ItemStore().Get(t.Context(), result.SentItemID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSubmissionMIME(sent.Data)
	if err != nil || len(parsed.Attachments) != 1 || string(parsed.Attachments[0].Data) != "attachment data" {
		t.Fatalf("sent MIME parsed=%+v err=%v", parsed, err)
	}
}

func TestMailSubmitDelegatedModes(t *testing.T) {
	for _, test := range []struct {
		name       string
		mode       SendMode
		permission authz.Action
		wantSender bool
	}{
		{name: "send as", mode: SendAs, permission: authz.IdentitySendAs},
		{name: "send on behalf", mode: SendOnBehalf, permission: authz.IdentitySendOnBehalf, wantSender: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mailService, ts, recorder := testMailService(t)
			_, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
				Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
				Resource:  model.ResourceRef{Kind: model.ResourceIdentity, ID: "alice@example.test"},
				Effect:    model.EffectAllow, Permissions: []string{string(test.permission)},
				Inheritance: model.InheritanceSelf, GrantedBy: "alice",
			})
			if err != nil {
				t.Fatalf("create identity grant: %v", err)
			}
			_, err = mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Submission{
				From: "alice@example.test", Mode: test.mode, To: []string{"recipient@example.net"},
				Subject: "Delegated", Body: "Body",
			})
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			_, senderPresent := recorder.messages[0].Headers["Sender"]
			if senderPresent != test.wantSender {
				t.Fatalf("Sender presence = %v, want %v", senderPresent, test.wantSender)
			}
			// From and Sender carry each identity owner's display name.
			if test.wantSender && recorder.messages[0].Headers["Sender"] != `"BOB" <bob@example.test>` {
				t.Fatalf("Sender = %q", recorder.messages[0].Headers["Sender"])
			}
			if from := recorder.messages[0].Headers["From"]; from != `"ALICE" <alice@example.test>` {
				t.Fatalf("From = %q", from)
			}
			if id := recorder.messages[0].Headers["Message-ID"]; !strings.HasSuffix(id, "@example.test>") {
				t.Fatalf("Message-ID = %q, want the sender's domain", id)
			}
		})
	}
}

func TestMailSubmitRejectsUnauthorizedDelegation(t *testing.T) {
	mailService, ts, _ := testMailService(t)
	_, err := model.NewPolicyStore(ts).Create(t.Context(), model.PolicyBinding{
		Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"},
		Resource:  model.ResourceRef{Kind: model.ResourceAccount, ID: "alice"},
		Effect:    model.EffectAllow, RoleID: authz.RoleAccountDelegate,
		Inheritance: model.InheritanceSelf, GrantedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create account delegation: %v", err)
	}

	_, err = mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Submission{
		From: "alice@example.test", Mode: SendAs, To: []string{"recipient@example.net"}, Subject: "No", Body: "Body",
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("submit error = %v, want forbidden", err)
	}
}

func TestAuthorizeSMTPSubmissionIdentityModes(t *testing.T) {
	mailService, ts, _ := testMailService(t)
	for _, binding := range []model.PolicyBinding{
		{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: "alice@example.test"}, Effect: model.EffectAllow, Permissions: []string{string(authz.IdentitySendAs)}, Inheritance: model.InheritanceSelf, GrantedBy: "alice"},
		{Principal: model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}, Resource: model.ResourceRef{Kind: model.ResourceIdentity, ID: "alice@example.test"}, Effect: model.EffectAllow, Permissions: []string{string(authz.IdentitySendOnBehalf)}, Inheritance: model.InheritanceSelf, GrantedBy: "alice"},
	} {
		if _, err := model.NewPolicyStore(ts).Create(t.Context(), binding); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name, envelope, from, sender string
		wantErr                      bool
	}{
		{name: "own identity", envelope: "bob@example.test", from: "Bob <bob@example.test>"},
		{name: "send as", envelope: "alice@example.test", from: "Alice <alice@example.test>"},
		{name: "send on behalf", envelope: "bob@example.test", from: "Alice <alice@example.test>", sender: "Bob <bob@example.test>"},
		{name: "spoofed sender", envelope: "alice@example.test", from: "Alice <alice@example.test>", sender: "mallory@example.test", wantErr: true},
		{name: "unmanaged envelope", envelope: "forged@example.net", from: "Bob <bob@example.test>", wantErr: true},
		{name: "missing from", envelope: "bob@example.test", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := mailService.AuthorizeSMTPSubmission(t.Context(), "bob", test.envelope, test.from, test.sender)
			if (err != nil) != test.wantErr {
				t.Fatalf("AuthorizeSMTPSubmission() error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestMailSubmitRollsBackSentCopyWhenQueueRejectsBatch(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	recorder.err = errors.New("queue full")
	_, err := mailService.Submit(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, Submission{
		From: "alice@example.test", To: []string{"one@example.net", "two@example.net"}, Subject: "Atomic", Body: "Body",
	})
	if err == nil {
		t.Fatal("submission unexpectedly succeeded")
	}
	items, listErr := ts.ItemStore().List(t.Context(), model.SentFolderID("alice"))
	if listErr != nil {
		t.Fatalf("list Sent: %v", listErr)
	}
	if len(items) != 0 || len(recorder.messages) != 0 {
		t.Fatalf("partial submission: sent=%v queued=%d", items, len(recorder.messages))
	}
}

func TestMailSubmitRawPreservesMIME(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	raw := []byte("From: Alice <alice@example.test>\r\nTo: bob@example.test\r\nSubject: MIME\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n--x--\r\n")
	result, err := mailService.SubmitRaw(t.Context(), model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}, raw)
	if err != nil {
		t.Fatalf("submit raw: %v", err)
	}
	if len(recorder.messages) != 1 || !strings.Contains(string(recorder.messages[0].Body), "--x--") {
		t.Fatalf("queued MIME changed: %#v", recorder.messages)
	}
	stored, err := ts.ItemStore().Get(t.Context(), result.SentItemID)
	if err != nil || string(stored.Data) != string(raw) {
		t.Fatalf("Sent MIME changed: item=%#v err=%v", stored, err)
	}
}

func TestMailSubmissionsRequestDKIMSigningAtQueueAdmission(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	actor := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	result, err := mailService.Submit(t.Context(), actor, Submission{
		From: "alice@example.test", To: []string{"carol@remote.test", "dave@remote.test"}, Subject: "Signed", Body: "Hello from webmail.",
	})
	if err != nil {
		t.Fatal(err)
	}
	// SubmitRaw carries EWS, EAS, and JMAP EmailSubmission.
	raw := []byte("From: Alice <alice@example.test>\r\nTo: carol@remote.test\r\nSubject: MIME\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nhello\r\n")
	if _, err := mailService.SubmitRaw(t.Context(), actor, raw); err != nil {
		t.Fatal(err)
	}
	if len(recorder.messages) != 3 {
		t.Fatalf("queued messages = %d, want 3", len(recorder.messages))
	}
	// The queue signs each copy after mail policy has applied its header
	// actions, so the submission only marks them.
	for _, message := range recorder.messages {
		if message.DKIM == nil || message.Headers["DKIM-Signature"] != "" {
			t.Fatalf("queued %s DKIM request = %+v, headers = %v", message.ID, message.DKIM, message.Headers)
		}
	}
	sent, err := ts.ItemStore().Get(t.Context(), result.SentItemID)
	if err != nil || strings.Contains(string(sent.Data), "DKIM-Signature") {
		t.Fatalf("Sent copy carries the transport signature: err=%v", err)
	}
}

func TestMailSendsAsTemporaryAliasOnlyForItsOwner(t *testing.T) {
	mailService, ts, recorder := testMailService(t)
	if err := ts.EnsureNamespace(t.Context(), model.NSUserAliases); err != nil {
		t.Fatal(err)
	}
	if err := ts.EnsureNamespace(t.Context(), model.NSRecipientAliases); err != nil {
		t.Fatal(err)
	}
	if err := ts.DomainStore().Create(t.Context(), "example.test"); err != nil {
		t.Fatal(err)
	}
	alias, err := ts.UserAliasStore().Create(t.Context(), model.UserAliasRequest{UserID: "alice", DomainID: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	alice := model.PrincipalRef{Kind: model.PrincipalUser, ID: "alice"}
	if _, err := mailService.Submit(t.Context(), alice, Submission{
		From: alias.Address, To: []string{"recipient@example.net"}, Subject: "Reply", Body: "Body",
	}); err != nil {
		t.Fatalf("owner send as alias: %v", err)
	}
	if len(recorder.messages) != 1 || recorder.messages[0].EnvelopeSender != alias.Address {
		t.Fatalf("queued = %#v", recorder.messages)
	}
	bob := model.PrincipalRef{Kind: model.PrincipalUser, ID: "bob"}
	for _, mode := range []SendMode{SendNormal, SendAs} {
		if _, err := mailService.Submit(t.Context(), bob, Submission{
			From: alias.Address, Mode: mode, To: []string{"recipient@example.net"}, Subject: "No", Body: "Body",
		}); err == nil {
			t.Fatalf("another account sent as the alias in mode %q", mode)
		}
	}
	if err := mailService.AuthorizeSMTPSubmission(t.Context(), "alice", alias.Address, "Shop <"+alias.Address+">", ""); err != nil {
		t.Fatalf("SMTP submission as alias: %v", err)
	}
	if err := mailService.AuthorizeSMTPSubmission(t.Context(), "bob", alias.Address, alias.Address, ""); err == nil {
		t.Fatal("another account authorized as the alias over SMTP")
	}
	off := false
	if _, err := ts.UserAliasStore().Update(t.Context(), alias.Address, "alice", model.UserAliasUpdate{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := mailService.Submit(t.Context(), alice, Submission{
		From: alias.Address, To: []string{"recipient@example.net"}, Subject: "Reply", Body: "Body",
	}); err == nil {
		t.Fatal("disabled alias still sends")
	}
}
