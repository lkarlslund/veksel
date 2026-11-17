package queue

import (
	"context"
	"errors"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dkim/dkimtest"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

// signingDomains returns a domain store where example.test signs with an
// active key, and a Verifier for that key.
func signingDomains(t *testing.T) (*model.DomainStore, dkim.Verifier) {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ts := model.NewTypedStore(backend, store.BackendJSON)
	if err := ts.EnsureNamespace(t.Context(), model.NSDomains); err != nil {
		t.Fatal(err)
	}
	return ts.DomainStore(), dkimtest.ActivateKey(t, ts.DomainStore(), "example.test", "s1")
}

func TestAdmissionSignsAfterPolicyHeaderActions(t *testing.T) {
	domains, verifier := signingDomains(t)
	q := New(&Config{
		Signer: dkim.NewSigner(domains),
		Admission: func(_ context.Context, message *Message) error {
			message.Headers["Subject"] = "[policy] " + message.Headers["Subject"]
			return nil
		},
	})
	t.Cleanup(q.Close)
	message := func(id string, request *dkim.Request) *Message {
		return &Message{ID: id, Recipient: "carol@remote.test", DKIM: request, Body: []byte("body\r\n"),
			Headers: map[string]string{"From": "alice@example.test", "To": "carol@remote.test", "Subject": "Hello", "Date": "Mon, 1 Jan 2024 00:00:00 +0000"}}
	}
	if err := q.Enqueue(message("signed", &dkim.Request{})); err != nil {
		t.Fatal(err)
	}
	// The queue ID was fixed before signing, so a replay is still a duplicate.
	if err := q.Enqueue(message("signed", &dkim.Request{})); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay error = %v, want duplicate", err)
	}
	if err := q.Enqueue(message("relayed", nil)); err != nil {
		t.Fatal(err)
	}
	signed := q.Get("signed")
	if signed.Headers["Subject"] != "[policy] Hello" || signed.DKIM != nil {
		t.Fatalf("admitted message = %+v", signed)
	}
	if result := verifier.Verify(t.Context(), BuildMessage(signed.Headers, signed.Body)); !result.Pass || result.Domain != "example.test" {
		t.Fatalf("verification over the rewritten message = %+v", result)
	}
	if relayed := q.Get("relayed"); relayed.Headers["DKIM-Signature"] != "" {
		t.Fatalf("message without a DKIM request was signed: %+v", relayed)
	}
}

func TestAdmissionRefusesUnsignableRequiredMessage(t *testing.T) {
	domains, _ := signingDomains(t)
	q := New(&Config{Signer: dkim.NewSigner(domains)})
	t.Cleanup(q.Close)
	report := &Message{ID: "report", Recipient: "reports@remote.test", DKIM: &dkim.Request{Required: true},
		Headers: map[string]string{"From": "dmarc@unhosted.test"}, Body: []byte("report")}
	if err := q.Enqueue(report); err == nil || q.Get("report") != nil {
		t.Fatalf("unsignable required message admitted: err=%v", err)
	}
	report.Headers["From"] = "dmarc@example.test"
	if err := q.Enqueue(report); err != nil || q.Get("report").Headers["DKIM-Signature"] == "" {
		t.Fatalf("signable required message: err=%v message=%+v", err, q.Get("report"))
	}
}
