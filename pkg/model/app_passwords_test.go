package model

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/faultstore"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

func appPasswordTestStore(t *testing.T) *AppPasswordStore {
	t.Helper()
	ts := newTestSetup(t)
	if err := ts.EnsureNamespace(t.Context(), NSAppPasswords); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	return NewAppPasswordStore(ts)
}

func TestAppPasswordLifecycleAndScopeIsolation(t *testing.T) {
	passwords := appPasswordTestStore(t)
	created, secret, err := passwords.Create(t.Context(), "Alice", "Phone", []string{AppProtocolSMTP, AppProtocolIMAP, AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "veksel-app-") || created.SecretHash == "" || created.SecretPrefix != secret[:14] || created.UserID != "alice" {
		t.Fatalf("created credential=%+v secret prefix=%q", created, secret)
	}
	if len(created.Protocols) != 2 || created.Protocols[0] != AppProtocolIMAP || created.Protocols[1] != AppProtocolSMTP {
		t.Fatalf("normalized protocols=%v", created.Protocols)
	}
	if matched, err := passwords.Authenticate(t.Context(), "alice", secret, AppProtocolDAV); err != nil || matched != nil {
		t.Fatalf("unscoped authentication=%+v, %v", matched, err)
	}
	matched, err := passwords.Authenticate(t.Context(), "alice", secret, AppProtocolIMAP)
	if err != nil || matched == nil || matched.ID != created.ID || matched.LastUsedAt.IsZero() || matched.LastProtocol != AppProtocolIMAP {
		t.Fatalf("scoped authentication=%+v, %v", matched, err)
	}
	listed, err := passwords.ListByUser(t.Context(), "ALICE")
	if err != nil || len(listed) != 1 || listed[0].LastProtocol != AppProtocolIMAP {
		t.Fatalf("listed=%+v, %v", listed, err)
	}
	if other, err := passwords.ListByUser(t.Context(), "bob"); err != nil || len(other) != 0 {
		t.Fatalf("foreign list=%+v, %v", other, err)
	}

	rotated, replacement, err := passwords.Rotate(t.Context(), created.ID)
	if err != nil || replacement == secret || rotated.ID != created.ID || rotated.RotationCount != 1 || !rotated.LastUsedAt.IsZero() || rotated.LastProtocol != "" {
		t.Fatalf("rotation=%+v replacement=%q err=%v", rotated, replacement, err)
	}
	if matched, err := passwords.Authenticate(t.Context(), "alice", secret, AppProtocolIMAP); err != nil || matched != nil {
		t.Fatalf("obsolete secret authenticated=%+v, %v", matched, err)
	}
	if matched, err := passwords.Authenticate(t.Context(), "alice", replacement, AppProtocolSMTP); err != nil || matched == nil {
		t.Fatalf("replacement secret failed=%+v, %v", matched, err)
	}
	if err := passwords.Revoke(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	if matched, err := passwords.Authenticate(t.Context(), "alice", replacement, AppProtocolSMTP); err != nil || matched != nil {
		t.Fatalf("revoked secret authenticated=%+v, %v", matched, err)
	}
	if _, _, err := passwords.Rotate(t.Context(), created.ID); !errors.Is(err, ErrAppPasswordRevoked) {
		t.Fatalf("rotate revoked error=%v", err)
	}
}

func TestAppPasswordNeverPersistsPlaintext(t *testing.T) {
	passwords := appPasswordTestStore(t)
	created, secret, err := passwords.Create(t.Context(), "alice", "Tablet", []string{AppProtocolDAV})
	if err != nil {
		t.Fatal(err)
	}
	data, err := passwords.ts.Store().Get(t.Context(), NSAppPasswords, appPasswordRecordPrefix+created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("persisted record contains plaintext secret: %s", data)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil || record["secret_hash"] == "" {
		t.Fatalf("persisted record=%v, %v", record, err)
	}
}

func TestAppPasswordCreateIsAtomic(t *testing.T) {
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	faults := faultstore.New(backend)
	ts := NewTypedStore(faults, store.BackendJSON)
	testSetup(t, ts)
	if err := ts.EnsureNamespace(t.Context(), NSAppPasswords); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(t.Context(), "alice", "Alice", "password123"); err != nil {
		t.Fatal(err)
	}
	faults.Fail("batch_commit", 1)
	if _, _, err := NewAppPasswordStore(ts).Create(t.Context(), "alice", "Broken", []string{AppProtocolIMAP}); !errors.Is(err, faultstore.ErrInjected) {
		t.Fatalf("create error=%v", err)
	}
	keys, err := backend.List(t.Context(), NSAppPasswords)
	if err != nil || len(keys) != 0 {
		t.Fatalf("partial credential keys=%v, %v", keys, err)
	}
}

func TestAppPasswordConcurrentUseCannotRestoreRotatedSecret(t *testing.T) {
	passwords := appPasswordTestStore(t)
	created, secret, err := passwords.Create(t.Context(), "alice", "Concurrent", []string{AppProtocolIMAP})
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 12; iteration++ {
		start := make(chan struct{})
		var replacement string
		var rotateErr error
		var group sync.WaitGroup
		group.Add(2)
		go func(previous string) {
			defer group.Done()
			<-start
			_, _ = passwords.Authenticate(t.Context(), "alice", previous, AppProtocolIMAP)
		}(secret)
		go func() {
			defer group.Done()
			<-start
			_, replacement, rotateErr = passwords.Rotate(t.Context(), created.ID)
		}()
		close(start)
		group.Wait()
		if rotateErr != nil {
			t.Fatal(rotateErr)
		}
		if matched, err := passwords.Authenticate(t.Context(), "alice", secret, AppProtocolIMAP); err != nil || matched != nil {
			t.Fatalf("iteration %d obsolete secret restored: %+v, %v", iteration, matched, err)
		}
		secret = replacement
	}
}

func TestAppPasswordValidation(t *testing.T) {
	passwords := appPasswordTestStore(t)
	for _, test := range []struct {
		name      string
		protocols []string
	}{
		{name: ""},
		{name: "Valid", protocols: []string{"unknown"}},
	} {
		if _, _, err := passwords.Create(t.Context(), "alice", test.name, test.protocols); err == nil {
			t.Fatalf("invalid create succeeded: %+v", test)
		}
	}
}
