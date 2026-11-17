package migration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func TestStoredCredentialsUseAuthenticatedVersionedEnvelopes(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	jobs, err := NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	const password = "source-password-that-must-not-be-plaintext"
	if err := jobs.SaveCredential(t.Context(), "job-a", password); err != nil {
		t.Fatal(err)
	}
	raw, err := backend.Get(t.Context(), credentialNamespace, "job-a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(password)) {
		t.Fatalf("stored credential contains plaintext: %s", raw)
	}
	var envelope credentialEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != credentialEnvelopeType || envelope.Version != credentialEnvelopeV1 || envelope.KeyID == "" {
		t.Fatalf("credential envelope = %#v", envelope)
	}
	if got, err := jobs.Credential(t.Context(), "job-a"); err != nil || got != password {
		t.Fatalf("credential = %q, err = %v", got, err)
	}
	if err := backend.Put(t.Context(), credentialNamespace, "job-b", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Credential(t.Context(), "job-b"); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("credential copied to another job error = %v", err)
	}
}

func TestCredentialKeyRotationRewrapsAndSurvivesRestart(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	jobs, err := NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.SaveCredential(t.Context(), "job-a", "secret-a"); err != nil {
		t.Fatal(err)
	}
	before := jobs.CredentialKeyStatus()
	after, err := jobs.RotateCredentialKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveKeyID == before.ActiveKeyID || after.KeyCount != before.KeyCount+1 {
		t.Fatalf("rotation before=%#v after=%#v", before, after)
	}
	raw, err := backend.Get(t.Context(), credentialNamespace, "job-a")
	if err != nil {
		t.Fatal(err)
	}
	var envelope credentialEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.KeyID != after.ActiveKeyID {
		t.Fatalf("rotated envelope=%#v err=%v", envelope, err)
	}
	reopened, err := NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Credential(t.Context(), "job-a"); err != nil || got != "secret-a" {
		t.Fatalf("reopened credential=%q err=%v", got, err)
	}
}

func TestLegacyPlaintextCredentialIsUpgradedOnRead(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	jobs, err := NewStore(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(t.Context(), credentialNamespace, "legacy-job", []byte("legacy-secret")); err != nil {
		t.Fatal(err)
	}
	if got, err := jobs.Credential(t.Context(), "legacy-job"); err != nil || got != "legacy-secret" {
		t.Fatalf("legacy credential=%q err=%v", got, err)
	}
	raw, err := backend.Get(t.Context(), credentialNamespace, "legacy-job")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, []byte("legacy-secret")) || !json.Valid(raw) {
		t.Fatalf("legacy credential was not upgraded: %q", raw)
	}
}
