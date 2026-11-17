package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/lkarlslund/veksel/pkg/dkim"
	"github.com/lkarlslund/veksel/pkg/dkim/dkimtest"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/pgpkey"
	"github.com/lkarlslund/veksel/pkg/queue"
)

func openpgpServer(t *testing.T) *server {
	t.Helper()
	s := liveAddressingServer(t)
	if err := s.registerOpenPGP(); err != nil {
		t.Fatal(err)
	}
	return s
}

// publishKey stores a freshly generated key for address.
func publishKey(t *testing.T, s *server, address, userID string, autocrypt bool) pgpkey.Key {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "", address, nil)
	if err != nil {
		t.Fatal(err)
	}
	var binary bytes.Buffer
	if err := entity.Serialize(&binary); err != nil {
		t.Fatal(err)
	}
	key, err := pgpkey.Parse(binary.Bytes(), address, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ts.PGPKeyStore().Set(s.ctx, model.PGPKey{Address: address, UserID: userID, Fingerprint: key.Fingerprint, Created: key.Created,
		Expires: key.Expires, Binary: key.Binary, Autocrypt: autocrypt}); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestOpenPGPSettingsApplyLive(t *testing.T) {
	s := openpgpServer(t)
	if !s.openpgp.wkd.Load() || s.openpgp.autocrypt.Load() {
		t.Fatalf("defaults: wkd=%t autocrypt=%t", s.openpgp.wkd.Load(), s.openpgp.autocrypt.Load())
	}
	patchAndApply(t, s, map[string]any{"wkd_enabled": false, "autocrypt_enabled": true})
	if s.openpgp.wkd.Load() || !s.openpgp.autocrypt.Load() {
		t.Fatalf("after patch: wkd=%t autocrypt=%t", s.openpgp.wkd.Load(), s.openpgp.autocrypt.Load())
	}
	for _, key := range []string{"wkd_enabled", "autocrypt_enabled"} {
		if state := applyState(t, s, key); state.RestartRequired {
			t.Fatalf("%s requires restart", key)
		}
	}
}

func TestKeyDirectoryServesOnlyHostedEnabledIdentities(t *testing.T) {
	s := openpgpServer(t)
	ctx := s.ctx
	key := publishKey(t, s, "alice@example.test", "alice", false)
	handler := s.keyDirectory()
	get := func(host, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = host
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	hash := pgpkey.WKDHash("alice")
	direct := "/.well-known/openpgpkey/hu/" + hash + "?l=alice"
	advanced := "/.well-known/openpgpkey/example.test/hu/" + hash + "?l=alice"
	for name, response := range map[string]*httptest.ResponseRecorder{
		"direct":   get("example.test", direct),
		"advanced": get("openpgpkey.example.test", advanced),
	} {
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), key.Binary) || response.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s = %d, %d bytes", name, response.Code, response.Body.Len())
		}
	}
	if response := get("example.test", "/.well-known/openpgpkey/policy"); response.Code != http.StatusOK {
		t.Fatalf("policy = %d", response.Code)
	}
	// A key stored for a domain that is not hosted is never served.
	if err := s.ts.PGPKeyStore().Set(ctx, model.PGPKey{Address: "alice@elsewhere.test", UserID: "alice", Binary: key.Binary}); err != nil {
		t.Fatal(err)
	}
	if response := get("elsewhere.test", direct); response.Code != http.StatusNotFound {
		t.Fatalf("non-hosted domain = %d", response.Code)
	}
	// A disabled identity stops being published.
	identity, err := s.ts.UserStore().GetEmailAddress(ctx, "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity.Enabled = false
	if err := s.ts.Set(ctx, model.NSEmails, model.EmailAddrKey(identity.ID), identity); err != nil {
		t.Fatal(err)
	}
	if response := get("example.test", direct); response.Code != http.StatusNotFound {
		t.Fatalf("disabled identity = %d", response.Code)
	}
	identity.Enabled = true
	if err := s.ts.Set(ctx, model.NSEmails, model.EmailAddrKey(identity.ID), identity); err != nil {
		t.Fatal(err)
	}
	patchAndApply(t, s, map[string]any{"wkd_enabled": false})
	if response := get("example.test", direct); response.Code != http.StatusNotFound {
		t.Fatalf("wkd_enabled=false = %d", response.Code)
	}
}

func TestAutocryptHeaderIsAddedBeforeDKIMSigning(t *testing.T) {
	s := openpgpServer(t)
	ctx := s.ctx
	verifier := dkimtest.ActivateKey(t, s.ts.DomainStore(), "example.test", "s1")
	publishKey(t, s, "alice@example.test", "alice", true)
	publishKey(t, s, "bob@example.test", "bob", false)
	mailQueue := mailFlowQueue(t, s)
	submit := func(id, from, actor string) *queue.Message {
		t.Helper()
		content := []byte("From: " + from + "\r\nTo: carol@remote.test\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nHi Carol.\r\n")
		headers, _ := model.ParseMessageHeaders(content)
		if err := mailQueue.Enqueue(&queue.Message{ID: id, EnvelopeSender: from, Recipient: "carol@remote.test", Headers: headers, Content: content,
			AuthenticatedActor: actor, DKIM: &dkim.Request{}}); err != nil {
			t.Fatal(err)
		}
		return mailQueue.Get(id)
	}

	// Off by default.
	if message := submit("off", "alice@example.test", "alice"); bytes.Contains(message.Content, []byte("Autocrypt:")) {
		t.Fatal("Autocrypt header added while autocrypt_enabled is off")
	}
	patchAndApply(t, s, map[string]any{"autocrypt_enabled": true})
	message := submit("on", "alice@example.test", "alice")
	if !bytes.Contains(message.Content, []byte("Autocrypt: addr=alice@example.test; prefer-encrypt=nopreference; keydata=\r\n ")) {
		t.Fatalf("no Autocrypt header:\n%s", message.Content)
	}
	if strings.Count(string(message.Content), "Autocrypt:") != 1 {
		t.Fatalf("expected exactly one Autocrypt header:\n%s", message.Content)
	}
	if message.Headers["Autocrypt"] == "" {
		t.Fatal("header lookup view lacks Autocrypt")
	}
	// The signature made after insertion still verifies, with the header in place.
	if result := verifier.Verify(ctx, message.Content); !result.Pass || result.Domain != "example.test" {
		t.Fatalf("DKIM after Autocrypt = %+v", result)
	}
	// An identity without the toggle, another account, relayed mail, and a
	// message that already carries the header are left alone.
	for name, other := range map[string]*queue.Message{
		"toggle off":    submit("bob", "bob@example.test", "bob"),
		"other account": submit("other", "alice@example.test", "bob"),
		"relayed":       submit("relayed", "alice@example.test", ""),
	} {
		if bytes.Contains(other.Content, []byte("Autocrypt:")) {
			t.Fatalf("%s: Autocrypt header added", name)
		}
	}
	// Disabling the toggle on the key stops the header for the next message.
	stored, err := s.ts.PGPKeyStore().Get(ctx, "alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	stored.Autocrypt = false
	if err := s.ts.PGPKeyStore().Set(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if message := submit("toggled-off", "alice@example.test", "alice"); bytes.Contains(message.Content, []byte("Autocrypt:")) {
		t.Fatal("Autocrypt header added after the toggle was turned off")
	}
}

func TestAutocryptSkipsOversizedKeys(t *testing.T) {
	s := openpgpServer(t)
	patchAndApply(t, s, map[string]any{"autocrypt_enabled": true})
	if err := s.ts.PGPKeyStore().Set(s.ctx, model.PGPKey{Address: "alice@example.test", UserID: "alice", Autocrypt: true,
		Binary: make([]byte, pgpkey.MaxAutocryptKeyBytes+1)}); err != nil {
		t.Fatal(err)
	}
	content := []byte("From: alice@example.test\r\nTo: carol@remote.test\r\n\r\nHi.\r\n")
	headers, _ := model.ParseMessageHeaders(content)
	message := &queue.Message{ID: "big", Headers: headers, Content: content, AuthenticatedActor: "alice"}
	if err := s.addAutocrypt(s.ctx, message); err != nil || bytes.Contains(message.Content, []byte("Autocrypt:")) {
		t.Fatalf("oversized key advertised: %v", err)
	}
}
