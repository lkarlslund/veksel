package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/lkarlslund/veksel/pkg/model"
)

type pgpKeyList struct {
	Keys             []pgpKeyView `json:"keys"`
	WKDEnabled       bool         `json:"wkd_enabled"`
	AutocryptEnabled bool         `json:"autocrypt_enabled"`
}

func armoredKey(t *testing.T, email string, private bool) (armored string, binary []byte) {
	t.Helper()
	entity, err := openpgp.NewEntity("Test User", "", email, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	kind := openpgp.PublicKeyType
	if private {
		kind = openpgp.PrivateKeyType
	}
	writer, err := armor.Encode(&out, kind, nil)
	if err != nil {
		t.Fatal(err)
	}
	if private {
		err = entity.SerializePrivate(writer, nil)
	} else {
		err = entity.Serialize(writer)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	var raw bytes.Buffer
	if err := entity.Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	return out.String(), raw.Bytes()
}

func keyBody(t *testing.T, key string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"key": key})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestUserPGPKeyUploadValidationAndLifecycle(t *testing.T) {
	f := newDomainAdminFixture(t)
	alice, aliceTok := loginAs(t, f.server, "alice")
	bob, bobTok := loginAs(t, f.server, "bob")
	const path = "/api/v1/user/pgp-keys/alice@a.test"

	list := decodeInto[pgpKeyList](t, f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/user/pgp-keys", "", http.StatusOK))
	if len(list.Keys) != 1 || list.Keys[0].Address != "alice@a.test" || list.Keys[0].Fingerprint != "" || !list.WKDEnabled || list.AutocryptEnabled {
		t.Fatalf("initial list = %+v", list)
	}

	// Garbage, a private key, and a key for another address are refused.
	f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, "not a key"), http.StatusBadRequest)
	f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, ""), http.StatusBadRequest)
	private, _ := armoredKey(t, "alice@a.test", true)
	if body := f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, private), http.StatusBadRequest); !strings.Contains(string(body), "private key") {
		t.Fatal("private key refusal does not say so")
	}
	wrong, _ := armoredKey(t, "someone@a.test", false)
	f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, wrong), http.StatusBadRequest)
	if stored, err := f.ts.PGPKeyStore().Get(t.Context(), "alice@a.test"); err == nil {
		t.Fatalf("rejected upload stored a key: %+v", stored)
	}

	// Another account cannot publish for alice's identity.
	public, _ := armoredKey(t, "alice@a.test", false)
	f.expect(t, bob, bobTok, http.MethodPut, path, keyBody(t, public), http.StatusNotFound)

	// An armored key is accepted, and so is the base64 of a binary one.
	view := decodeInto[pgpKeyView](t, f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, public), http.StatusOK))
	if view.Address != "alice@a.test" || len(view.Fingerprint) != 40 || view.Expires != "" || view.Expired || view.Autocrypt {
		t.Fatalf("view = %+v", view)
	}
	_, other := armoredKey(t, "alice@a.test", false)
	replaced := decodeInto[pgpKeyView](t, f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, base64.StdEncoding.EncodeToString(other)), http.StatusOK))
	if replaced.Fingerprint == view.Fingerprint {
		t.Fatal("replacement kept the old key")
	}

	// Autocrypt is a per-identity toggle that survives replacing the key.
	f.expect(t, bob, bobTok, http.MethodPatch, path, `{"autocrypt":true}`, http.StatusNotFound)
	if toggled := decodeInto[pgpKeyView](t, f.expect(t, alice, aliceTok, http.MethodPatch, path, `{"autocrypt":true}`, http.StatusOK)); !toggled.Autocrypt {
		t.Fatalf("toggled = %+v", toggled)
	}
	again := decodeInto[pgpKeyView](t, f.expect(t, alice, aliceTok, http.MethodPut, path, keyBody(t, public), http.StatusOK))
	if !again.Autocrypt {
		t.Fatal("replacing the key reset the Autocrypt toggle")
	}
	stored, err := f.ts.PGPKeyStore().Get(t.Context(), "alice@a.test")
	if err != nil || stored.UserID != "alice" || len(stored.Binary) == 0 {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	f.expect(t, bob, bobTok, http.MethodDelete, path, "", http.StatusNotFound)
	f.expect(t, alice, aliceTok, http.MethodDelete, path, "", http.StatusNoContent)
	f.expect(t, alice, aliceTok, http.MethodDelete, path, "", http.StatusNotFound)
	if _, err := f.ts.PGPKeyStore().Get(t.Context(), "alice@a.test"); err == nil {
		t.Fatal("key survived deletion")
	}
}

func TestPGPKeySettingsAreLiveInTheList(t *testing.T) {
	f := newDomainAdminFixture(t)
	alice, aliceTok := loginAs(t, f.server, "alice")
	f.patchConfig(t, `{"wkd_enabled":false,"autocrypt_enabled":true}`)
	list := decodeInto[pgpKeyList](t, f.expect(t, alice, aliceTok, http.MethodGet, "/api/v1/user/pgp-keys", "", http.StatusOK))
	if list.WKDEnabled || !list.AutocryptEnabled {
		t.Fatalf("list after patch = %+v", list)
	}
}

func TestDNSExpectationsAddOpenPGPKeyHostWhenWKDIsEnabled(t *testing.T) {
	domain := model.Domain{ID: "example.test"}
	find := func(wkd bool) *dnsExpectation {
		for _, want := range dnsExpectations(domain, "mail.example.test", dnsOptions{WKD: wkd}) {
			if want.Kind == "WKD" {
				return &want
			}
		}
		return nil
	}
	if find(false) != nil {
		t.Fatal("WKD record expected while WKD is off")
	}
	want := find(true)
	if want == nil || want.Type != "CNAME" || want.Name != "openpgpkey.example.test" || want.Value != "mail.example.test." || !want.Accept("MAIL.example.test.") || want.Accept("other.test.") {
		t.Fatalf("WKD expectation = %+v", want)
	}

	// The check passes for a CNAME or A record that reaches the server's addresses.
	resolver := fakeDNSResolver{host: map[string][]string{"mail.example.test": {"192.0.2.10"}, "openpgpkey.example.test": {"192.0.2.10"}}}
	if rec := checkWKDHost(t.Context(), resolver, *want, "mail.example.test"); rec.Status != dnsOK || rec.Type != "CNAME" {
		t.Fatalf("matching host = %+v", rec)
	}
	resolver.host["openpgpkey.example.test"] = []string{"198.51.100.1"}
	if rec := checkWKDHost(t.Context(), resolver, *want, "mail.example.test"); rec.Status != dnsMismatch {
		t.Fatalf("other host = %+v", rec)
	}
	delete(resolver.host, "openpgpkey.example.test")
	if rec := checkWKDHost(t.Context(), resolver, *want, "mail.example.test"); rec.Status != dnsMissing {
		t.Fatalf("absent host = %+v", rec)
	}

	// Guidance lists the record only when WKD is on.
	has := func(wkd bool) bool {
		for _, rec := range buildDNSGuidance(t.Context(), fakeDNSResolver{host: map[string][]string{}, addr: map[string][]string{}}, domain, "mail.example.test", "", dnsOptions{WKD: wkd}).Records {
			if rec.Name == "openpgpkey.example.test" {
				return true
			}
		}
		return false
	}
	if has(false) || !has(true) {
		t.Fatalf("guidance records: wkd off %t, wkd on %t", has(false), has(true))
	}
}
