package dkim_test

import (
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dkim/dkimtest"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func signerDomains(t *testing.T) *model.DomainStore {
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
	return ts.DomainStore()
}

func submission(from string) map[string]string {
	return map[string]string{"From": from, "To": "bob@remote.test", "Subject": "Hello",
		"Date": "Mon, 1 Jan 2024 00:00:00 +0000", "Message-ID": "<1@example.test>"}
}

func TestSignerSignsForFromDomainWithActiveKey(t *testing.T) {
	domains := signerDomains(t)
	verifier := dkimtest.ActivateKey(t, domains, "example.test", "s1")
	signer := dkim.NewSigner(domains)
	headers, body := submission(`"Alice" <Alice@Example.TEST>`), []byte("Hello world.\r\n")

	signed, err := signer.SignHeaders(t.Context(), headers, body)
	if err != nil || !signed {
		t.Fatalf("signed=%t err=%v", signed, err)
	}
	result := verifier.Verify(t.Context(), model.BuildMessage(headers, body))
	if !result.Pass || result.Domain != "example.test" || result.Selector != "s1" {
		t.Fatalf("verification = %+v", result)
	}
	// Signing again is a no-op: one signature per From domain.
	before := headers["DKIM-Signature"]
	if signed, err := signer.SignHeaders(t.Context(), headers, body); err != nil || !signed || headers["DKIM-Signature"] != before {
		t.Fatalf("re-sign signed=%t err=%v changed=%t", signed, err, headers["DKIM-Signature"] != before)
	}
}

func TestSignerUsesOnlyTheActiveKey(t *testing.T) {
	domains := signerDomains(t)
	verifier := dkimtest.ActivateKey(t, domains, "example.test", "current")
	domain, err := domains.Get(t.Context(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	private, public, err := dkim.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := domains.StageDKIMKey(t.Context(), "example.test", domain.DKIMRevision, model.DKIMKey{Selector: "next", PrivateKey: string(private), PublicKey: string(public)}); err != nil {
		t.Fatal(err)
	}
	headers, body := submission("alice@example.test"), []byte("Hello.\r\n")
	if signed, err := dkim.NewSigner(domains).SignHeaders(t.Context(), headers, body); err != nil || !signed {
		t.Fatalf("signed=%t err=%v", signed, err)
	}
	if result := verifier.Verify(t.Context(), model.BuildMessage(headers, body)); !result.Pass || result.Selector != "current" {
		t.Fatalf("verification = %+v", result)
	}
}

func TestSignerLeavesUnsignableMailUnchanged(t *testing.T) {
	domains := signerDomains(t)
	dkimtest.ActivateKey(t, domains, "example.test", "s1")
	if err := domains.Create(t.Context(), "nokey.test"); err != nil {
		t.Fatal(err)
	}
	dkimtest.ActivateKey(t, domains, "disabled.test", "s1")
	if err := domains.Update(t.Context(), "disabled.test", func(domain *model.Domain) { domain.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	foreign := submission("alice@example.test")
	foreign["DKIM-Signature"] = "v=1; a=rsa-sha256; d=other.test; s=x; h=from; bh=x; b=x"
	for name, headers := range map[string]map[string]string{
		"external From":      submission("someone@external.test"),
		"domain without key": submission("alice@nokey.test"),
		"disabled domain":    submission("alice@disabled.test"),
		"mixed From domains": submission("alice@example.test, eve@external.test"),
		"missing From":       {"Subject": "x"},
		"foreign signature":  foreign,
	} {
		before := len(headers)
		signed, err := dkim.NewSigner(domains).SignHeaders(t.Context(), headers, []byte("x\r\n"))
		if err != nil || signed || len(headers) != before {
			t.Errorf("%s: signed=%t err=%v headers=%v", name, signed, err, headers)
		}
		if name == "foreign signature" && !strings.Contains(headers["DKIM-Signature"], "d=other.test") {
			t.Errorf("foreign signature was replaced: %q", headers["DKIM-Signature"])
		}
	}
	var nilSigner *dkim.Signer
	if signed, err := nilSigner.SignHeaders(t.Context(), submission("alice@example.test"), nil); signed || err != nil {
		t.Fatalf("nil signer signed=%t err=%v", signed, err)
	}
}

func TestSignerSignsExactMessageBytes(t *testing.T) {
	domains := signerDomains(t)
	verifier := dkimtest.ActivateKey(t, domains, "example.test", "s1")
	message := []byte("Received: from b by c; Mon, 1 Jan 2024 00:00:01 +0000\r\n" +
		"Received: from a by b; Mon, 1 Jan 2024 00:00:00 +0000\r\n" +
		"From: alice@example.test\r\nTo: bob@remote.test\r\nSubject: Hello\r\n\r\nHello world.\r\n")
	headers, _ := model.ParseMessageHeaders(message)
	signedMessage, signed, err := dkim.NewSigner(domains).SignMessage(t.Context(), headers, message)
	if err != nil || !signed {
		t.Fatalf("signed=%t err=%v", signed, err)
	}
	if !strings.HasPrefix(string(signedMessage), "DKIM-Signature: ") || !strings.HasSuffix(string(signedMessage), string(message)) {
		t.Fatalf("signature not prepended to the exact bytes:\n%s", signedMessage)
	}
	if result := verifier.Verify(t.Context(), signedMessage); !result.Pass {
		t.Fatalf("verification = %+v", result)
	}
	if headers["DKIM-Signature"] == "" {
		t.Fatal("header view lacks the signature")
	}
	if again, signed, err := dkim.NewSigner(domains).SignMessage(t.Context(), headers, signedMessage); err != nil || !signed || len(again) != len(signedMessage) {
		t.Fatalf("re-sign signed=%t err=%v grew=%t", signed, err, len(again) != len(signedMessage))
	}
}

func TestSignerSealsForwardsWithActiveKey(t *testing.T) {
	domains := signerDomains(t)
	verifier := dkimtest.ActivateKey(t, domains, "forward.test", "s1")
	signer := dkim.NewSigner(domains)
	message := []byte("From: bob@remote.test\r\nTo: alice@forward.test\r\nSubject: Hi\r\n\r\nHello\r\n")

	sealed, ok, err := signer.Seal(t.Context(), "Forward.TEST", message, "mx.forward.test; dmarc=pass header.from=remote.test", dkim.ARCNone)
	if err != nil || !ok {
		t.Fatalf("Seal = %v, %v", ok, err)
	}
	result := verifier.VerifyARC(t.Context(), sealed)
	if result.Status != dkim.ARCPass || result.Sealer != "forward.test" || result.SealerResults["dmarc"] != "pass" {
		t.Fatalf("own seal = %+v, want pass", result)
	}
	if unchanged, ok, err := signer.Seal(t.Context(), "other.test", message, "mx; none", dkim.ARCNone); err != nil || ok || string(unchanged) != string(message) {
		t.Fatalf("unhosted domain sealed: ok=%v err=%v", ok, err)
	}
}
