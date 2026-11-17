package pgpkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func newEntity(t *testing.T, email string) *openpgp.Entity {
	t.Helper()
	entity, err := openpgp.NewEntity("Alice", "", email, nil)
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func armoredPublic(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestZBase32AndWKDHashVectors(t *testing.T) {
	// The example of draft-koch-openpgp-webkey-service.
	if got := WKDHash("Joe.Doe"); got != "iy9q119eutrkn8s1mk4r39qejnbu3n5q" {
		t.Fatalf("WKDHash(Joe.Doe) = %q", got)
	}
	if WKDHash("joe.doe") != WKDHash("JOE.DOE") {
		t.Fatal("the local part is not lower-cased")
	}
	if got := ZBase32([]byte{0, 0}); got != "yyyy" {
		t.Fatalf("ZBase32(0000) = %q", got)
	}
	if got := ZBase32([]byte{0xff, 0xff, 0xff, 0xff, 0xff}); got != "99999999" {
		t.Fatalf("ZBase32(ff*5) = %q", got)
	}
}

func TestParseAcceptsArmoredBinaryAndBase64(t *testing.T) {
	entity := newEntity(t, "Alice@Example.test")
	var binary bytes.Buffer
	if err := entity.Serialize(&binary); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"armored": armoredPublic(t, entity),
		"binary":  binary.Bytes(),
		"base64":  []byte(base64.StdEncoding.EncodeToString(binary.Bytes())),
	} {
		key, err := Parse(data, "alice@example.test", time.Now())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint); key.Fingerprint != want {
			t.Fatalf("%s: fingerprint %s, want %s", name, key.Fingerprint, want)
		}
		if !key.Expires.IsZero() || len(key.Binary) == 0 {
			t.Fatalf("%s: key = %+v", name, key)
		}
		// The stored form is itself a valid key for the address.
		if _, err := Parse(key.Binary, "alice@example.test", time.Now()); err != nil {
			t.Fatalf("%s: minimal key: %v", name, err)
		}
	}
}

func TestParseRejections(t *testing.T) {
	entity := newEntity(t, "alice@example.test")
	public := armoredPublic(t, entity)
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, nil); err != nil {
		t.Fatal(err)
	}
	var armoredPrivate bytes.Buffer
	writer, err := armor.Encode(&armoredPrivate, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(writer, nil); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	second := newEntity(t, "bob@example.test")
	var pair bytes.Buffer
	_ = entity.Serialize(&pair)
	_ = second.Serialize(&pair)
	now := time.Now()
	for name, test := range map[string]struct {
		data []byte
		want string
	}{
		"wrong user id":  {public, "no valid user ID for bob@example.test"},
		"armored secret": {armoredPrivate.Bytes(), "private key"},
		"binary secret":  {private.Bytes(), "private key"},
		"garbage":        {[]byte("this is not a key"), "neither armored"},
		"bad armor":      {[]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!\n-----END PGP PUBLIC KEY BLOCK-----"), "armored"},
		"bad packets":    {[]byte{0x99, 0x00, 0x05, 1, 2, 3, 4, 5}, "not a valid OpenPGP key"},
		"empty":          {[]byte("  \n"), "empty"},
		"two keys":       {pair.Bytes(), "found 2"},
		"too large":      {bytes.Repeat([]byte{0x99}, MaxInputBytes+1), "larger than"},
	} {
		address := "alice@example.test"
		if name == "wrong user id" {
			address = "bob@example.test"
		}
		if _, err := Parse(test.data, address, now); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestParseRejectsExpiredAndRevokedKeys(t *testing.T) {
	entity := newEntity(t, "alice@example.test")
	var binary bytes.Buffer
	if err := entity.Serialize(&binary); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(binary.Bytes(), "alice@example.test", time.Now().Add(100*365*24*time.Hour)); err != nil {
		t.Fatalf("a key without an expiry must not expire: %v", err)
	}
	lifetime := uint32(3600)
	for _, identity := range entity.Identities {
		identity.SelfSignature.KeyLifetimeSecs = &lifetime
		if err := identity.SelfSignature.SignUserId(identity.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil); err != nil {
			t.Fatal(err)
		}
		identity.Signatures = identity.Signatures[:0]
		identity.Signatures = append(identity.Signatures, identity.SelfSignature)
	}
	binary.Reset()
	if err := entity.Serialize(&binary); err != nil {
		t.Fatal(err)
	}
	key, err := Parse(binary.Bytes(), "alice@example.test", time.Now())
	if err != nil || key.Expires.IsZero() {
		t.Fatalf("expiring key = %+v, %v", key, err)
	}
	if _, err := Parse(binary.Bytes(), "alice@example.test", time.Now().Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired key error = %v", err)
	}
}

func TestMinimalKeyDropsOtherUserIDsAndCertifications(t *testing.T) {
	entity := newEntity(t, "alice@example.test")
	other := newEntity(t, "certifier@example.test")
	if err := entity.AddUserId("Alice Work", "", "alice@work.test", nil); err != nil {
		t.Fatal(err)
	}
	if err := entity.SignIdentity("Alice <alice@example.test>", other, nil); err != nil {
		t.Fatal(err)
	}
	key, err := Parse(armoredPublic(t, entity), "alice@example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ring, err := openpgp.ReadKeyRing(bytes.NewReader(key.Binary))
	if err != nil || len(ring) != 1 {
		t.Fatalf("ring = %v, %v", ring, err)
	}
	if len(ring[0].Identities) != 1 || len(ring[0].Subkeys) != 1 {
		t.Fatalf("identities=%d subkeys=%d", len(ring[0].Identities), len(ring[0].Subkeys))
	}
	for _, identity := range ring[0].Identities {
		if identity.UserId.Email != "alice@example.test" || len(identity.Signatures) != 1 {
			t.Fatalf("identity %q has %d signatures", identity.Name, len(identity.Signatures))
		}
	}
	if len(key.Binary) > MaxAutocryptKeyBytes {
		t.Fatalf("minimal key is %d bytes", len(key.Binary))
	}
}

func TestAutocryptHeader(t *testing.T) {
	binary := bytes.Repeat([]byte{7}, 300)
	header, err := AutocryptHeader("Alice@Example.test", binary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, "Autocrypt: addr=alice@example.test; prefer-encrypt=nopreference; keydata=\r\n ") {
		t.Fatalf("header = %q", header)
	}
	var encoded strings.Builder
	for _, line := range strings.Split(header, "\r\n")[1:] {
		if len(line) > 73 || line[0] != ' ' {
			t.Fatalf("badly folded line %q", line)
		}
		encoded.WriteString(line[1:])
	}
	if decoded, err := base64.StdEncoding.DecodeString(encoded.String()); err != nil || !bytes.Equal(decoded, binary) {
		t.Fatalf("keydata does not round-trip: %v", err)
	}
	if _, err := AutocryptHeader("alice@example.test", make([]byte, MaxAutocryptKeyBytes+1)); err == nil {
		t.Fatal("oversized key accepted")
	}
}

func testDirectory(enabled *bool) *Directory {
	hash := WKDHash("alice")
	return &Directory{
		Enabled: func() bool { return *enabled },
		Hosted:  func(_ context.Context, domain string) (bool, error) { return domain == "example.test", nil },
		Key: func(_ context.Context, domain, h string) ([]byte, bool, error) {
			return []byte("KEY"), domain == "example.test" && h == hash, nil
		},
	}
}

func TestDirectoryRoutes(t *testing.T) {
	enabled := true
	directory := testDirectory(&enabled)
	hash := WKDHash("alice")
	for _, test := range []struct {
		name, host, path string
		status           int
	}{
		{"direct key", "example.test", "/.well-known/openpgpkey/hu/" + hash + "?l=alice", http.StatusOK},
		{"advanced key", "openpgpkey.example.test", "/.well-known/openpgpkey/example.test/hu/" + hash + "?l=alice", http.StatusOK},
		{"advanced with port", "openpgpkey.example.test:443", "/.well-known/openpgpkey/example.test/hu/" + hash, http.StatusOK},
		{"direct policy", "example.test", "/.well-known/openpgpkey/policy", http.StatusOK},
		{"advanced policy", "openpgpkey.example.test", "/.well-known/openpgpkey/example.test/policy", http.StatusOK},
		{"unknown hash", "example.test", "/.well-known/openpgpkey/hu/" + WKDHash("bob"), http.StatusNotFound},
		{"malformed hash", "example.test", "/.well-known/openpgpkey/hu/short", http.StatusNotFound},
		{"non-hosted direct", "other.test", "/.well-known/openpgpkey/hu/" + hash, http.StatusNotFound},
		{"non-hosted direct policy", "other.test", "/.well-known/openpgpkey/policy", http.StatusNotFound},
		{"non-hosted advanced", "openpgpkey.other.test", "/.well-known/openpgpkey/other.test/hu/" + hash, http.StatusNotFound},
		{"advanced domain and host disagree", "openpgpkey.other.test", "/.well-known/openpgpkey/example.test/hu/" + hash, http.StatusNotFound},
		{"advanced path on the bare domain", "example.test", "/.well-known/openpgpkey/example.test/hu/" + hash, http.StatusNotFound},
		{"extra segments", "example.test", "/.well-known/openpgpkey/hu/" + hash + "/x", http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Host = test.host
		response := httptest.NewRecorder()
		directory.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Errorf("%s: status %d, want %d", test.name, response.Code, test.status)
		}
		if response.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: CORS header missing", test.name)
		}
		if test.status == http.StatusOK && strings.Contains(test.path, "/hu/") {
			if response.Body.String() != "KEY" || response.Header().Get("Content-Type") != "application/octet-stream" {
				t.Errorf("%s: body %q type %q", test.name, response.Body, response.Header().Get("Content-Type"))
			}
		}
		if test.status == http.StatusOK && strings.HasSuffix(test.path, "policy") && response.Body.Len() != 0 {
			t.Errorf("%s: policy file is not empty", test.name)
		}
	}
}

func TestDirectoryMethodsAndDisabled(t *testing.T) {
	enabled := true
	directory := testDirectory(&enabled)
	hash := WKDHash("alice")
	do := func(method string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "/.well-known/openpgpkey/hu/"+hash, nil)
		request.Host = "example.test"
		response := httptest.NewRecorder()
		directory.ServeHTTP(response, request)
		return response
	}
	if response := do(http.MethodHead); response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("HEAD = %d %q", response.Code, response.Body)
	}
	if response := do(http.MethodOptions); response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("OPTIONS = %d", response.Code)
	}
	if response := do(http.MethodPost); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", response.Code)
	}
	enabled = false
	if response := do(http.MethodGet); response.Code != http.StatusNotFound {
		t.Fatalf("disabled WKD served a key: %d", response.Code)
	}
}
