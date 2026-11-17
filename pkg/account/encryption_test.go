package account

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/jsonstore"
)

const encryptionCanary = "Subject: encryption-canary-7f3a"

func newTestRing(t *testing.T) *keyring.Ring {
	t.Helper()
	backend, err := jsonstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	ring, err := keyring.Load(t.Context(), backend)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func newEncryptionManager(t *testing.T, root string, ring KeyWrapper) *Manager {
	t.Helper()
	var options []ManagerOption
	if ring != nil {
		options = append(options, WithKeyRing(ring))
	}
	manager, err := NewManager(root, store.BackendPebble, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func ensureAlice(t *testing.T, manager *Manager) Entry {
	t.Helper()
	now := time.Now().UTC()
	entry, _, err := manager.Ensure(t.Context(), model.User{ID: "alice", Enabled: true, CreatedAt: now, UpdatedAt: now}, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

// appendCanary stores a message, a protected resource name, and returns the
// logical digest of the account.
func appendCanary(t *testing.T, manager *Manager, data string) string {
	t.Helper()
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	typed := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := typed.FolderStore().GetByPath(t.Context(), "alice", "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	created, err := typed.ItemStore().AppendItem(t.Context(), inbox.ID, model.Item{Data: []byte(data + "\r\n\r\nbody")})
	if err != nil {
		t.Fatal(err)
	}
	drafts, err := typed.FolderStore().GetByPath(t.Context(), "alice", "Drafts")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := typed.ItemStore().Move(t.Context(), created.ID, drafts.ID, "canary-resource-name.eml"); err != nil {
		t.Fatal(err)
	}
	stats, err := VerifyTransfer(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	return stats.Digest
}

func logicalDigest(t *testing.T, manager *Manager) string {
	t.Helper()
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	stats, err := VerifyTransfer(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	return stats.Digest
}

// logicalContent summarizes alice's items, which a restore keeps unchanged
// while it rebases folder and change-journal sync state.
func logicalContent(t *testing.T, manager *Manager) TransferStats {
	t.Helper()
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	stats, err := VerifyTransfer(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	return TransferStats{Items: stats.Items, HistoryVersions: stats.HistoryVersions, PayloadBytes: stats.PayloadBytes}
}

// assertGenerationPlaintext reports whether the canary text appears anywhere
// in a generation's files once the engine has flushed them.
func generationContains(t *testing.T, generationPath, needle string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(generationPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found = found || bytes.Contains(data, []byte(needle))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func activeGenerationPath(t *testing.T, manager *Manager) string {
	t.Helper()
	entry, found := manager.ByLogin("alice")
	if !found {
		t.Fatal("alice is not discoverable")
	}
	return filepath.Join(entry.Path, "generations", entry.Manifest.ActiveGeneration)
}

func TestNewAccountsFollowLiveEncryptionDefault(t *testing.T) {
	root := t.TempDir()
	plain := newEncryptionManager(t, t.TempDir(), nil)
	if err := plain.SetEncryptionDefault(true); !errors.Is(err, ErrEncryptionKeysUnavailable) {
		t.Fatalf("enabling encryption without a key ring = %v", err)
	}
	// Control: the same writes are visible in a plaintext generation's
	// files, so the at-rest assertions below are not vacuous.
	ensureAlice(t, plain)
	appendCanary(t, plain, encryptionCanary)
	plainPath := activeGenerationPath(t, plain)
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{encryptionCanary, "canary-resource-name"} {
		if !generationContains(t, plainPath, needle) {
			t.Fatalf("control: plaintext generation lacks %q", needle)
		}
	}
	ring := newTestRing(t)
	manager := newEncryptionManager(t, root, ring)
	if err := manager.SetEncryptionDefault(true); err != nil {
		t.Fatal(err)
	}
	entry := ensureAlice(t, manager)
	if !entry.Manifest.Encrypted {
		t.Fatalf("new account manifest is not encrypted: %+v", entry.Manifest)
	}
	appendCanary(t, manager, encryptionCanary)
	status := manager.EncryptionStatus()
	if !status.Available || !status.Default || status.Encrypted != 1 || status.Accounts[0].KeyID != ring.ActiveKeyID() {
		t.Fatalf("encryption status = %+v", status)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(entry.Path, "generations", entry.Manifest.ActiveGeneration)
	for _, needle := range []string{encryptionCanary, "canary-resource-name"} {
		if generationContains(t, path, needle) {
			t.Fatalf("encrypted generation contains plaintext %q", needle)
		}
	}
}

func TestEncryptDecryptAndRotateKeyThroughVerifiedConversions(t *testing.T) {
	root := t.TempDir()
	ring := newTestRing(t)
	manager := newEncryptionManager(t, root, ring)
	ensureAlice(t, manager)
	digest := appendCanary(t, manager, encryptionCanary)
	plaintextGeneration := activeGenerationPath(t, manager)

	steps := []struct {
		name   string
		target ConversionTarget
	}{
		{"encrypt", ConversionTarget{Engine: store.BackendPebble, Encrypted: true}},
		{"rotate data key", ConversionTarget{Engine: store.BackendPebble, Encrypted: true, RotateKey: true}},
		{"change engine encrypted", ConversionTarget{Engine: store.BackendBadger, Encrypted: true}},
		{"decrypt", ConversionTarget{Engine: store.BackendBadger, Encrypted: false}},
	}
	var previousKey []byte
	for _, step := range steps {
		job, err := manager.StartConversionTo("alice", step.target)
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		job = waitConversionPhase(t, manager, job.ID, ConversionCompleted)
		if job.TargetEncrypted != step.target.Encrypted || job.Stats.Digest != digest {
			t.Fatalf("%s: job = %+v, want digest %s", step.name, job, digest)
		}
		entry, _ := manager.ByLogin("alice")
		if entry.Manifest.Encrypted != step.target.Encrypted || entry.Manifest.Engine != step.target.Engine {
			t.Fatalf("%s: manifest = %+v", step.name, entry.Manifest)
		}
		if got := logicalDigest(t, manager); got != digest {
			t.Fatalf("%s: logical digest %s, want %s", step.name, got, digest)
		}
		keyFile, _ := os.ReadFile(generationKeyPath(activeGenerationPath(t, manager)))
		if step.target.Encrypted == (keyFile == nil) {
			t.Fatalf("%s: key file presence = %t", step.name, keyFile != nil)
		}
		if step.target.RotateKey && bytes.Equal(keyFile, previousKey) {
			t.Fatalf("%s: data-encryption key file did not change", step.name)
		}
		previousKey = keyFile
	}
	// The plaintext source of the first conversion is retained for rollback.
	if _, err := os.Stat(plaintextGeneration); err != nil {
		t.Fatalf("retained plaintext generation: %v", err)
	}
	if _, err := manager.StartConversionTo("alice", ConversionTarget{Engine: store.BackendBadger}); !errors.Is(err, ErrConversionConflict) {
		t.Fatalf("no-op conversion error = %v", err)
	}
	if _, err := manager.StartConversionTo("alice", ConversionTarget{Engine: store.BackendBadger, RotateKey: true}); !errors.Is(err, ErrConversionConflict) {
		t.Fatalf("plaintext key rotation error = %v", err)
	}
}

func TestEncryptedConversionRollbackRestoresEncryption(t *testing.T) {
	ring := newTestRing(t)
	manager := newEncryptionManager(t, t.TempDir(), ring)
	ensureAlice(t, manager)
	appendCanary(t, manager, encryptionCanary)
	job, err := manager.StartConversionTo("alice", ConversionTarget{Engine: store.BackendPebble, Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	job = waitConversionPhase(t, manager, job.ID, ConversionCompleted)
	rollback, err := manager.StartConversionRollback("alice", job.ID)
	if err != nil {
		t.Fatal(err)
	}
	rollback = waitConversionPhase(t, manager, rollback.ID, ConversionCompleted)
	if entry, _ := manager.ByLogin("alice"); entry.Manifest.Encrypted || rollback.TargetEncrypted {
		t.Fatalf("rollback left encryption on: manifest=%+v job=%+v", entry.Manifest, rollback)
	}
}

// failingKeys forwards to a ring until it is told to fail, simulating a key
// ring that becomes unavailable mid-conversion.
type failingKeys struct {
	*keyring.Ring
	fail atomic.Bool
}

func (k *failingKeys) OpenSecret(purpose, id string, sealed []byte) ([]byte, error) {
	if k.fail.Load() {
		return nil, errors.New("injected key ring failure")
	}
	return k.Ring.OpenSecret(purpose, id, sealed)
}

func TestFailedEncryptionConversionRollsBackToSource(t *testing.T) {
	accountPath, original := createConvertibleAccount(t, store.BackendPebble)
	keys := &failingKeys{Ring: newTestRing(t)}
	job, err := prepareConversion(accountPath, ConversionTarget{Engine: store.BackendPebble, Encrypted: true}, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys.fail.Store(true)
	job, err = resumeConversion(t.Context(), accountPath, job.ID, keys, nil)
	if err == nil || job.Phase != ConversionFailed {
		t.Fatalf("conversion with failing key ring = %+v, %v", job, err)
	}
	manifest, err := ReadManifest(filepath.Join(accountPath, ManifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Encrypted || manifest.ActiveGeneration != original.ActiveGeneration || manifest.State != StateReady {
		t.Fatalf("manifest after failed conversion = %+v", manifest)
	}
	active, err := OpenActive(Entry{Manifest: manifest, Path: accountPath})
	if err != nil {
		t.Fatal(err)
	}
	_ = active.Close()
}

func TestKeyRotationRewrapsWithoutReencrypting(t *testing.T) {
	root := t.TempDir()
	ring := newTestRing(t)
	manager := newEncryptionManager(t, root, ring)
	if err := manager.SetEncryptionDefault(true); err != nil {
		t.Fatal(err)
	}
	ensureAlice(t, manager)
	digest := appendCanary(t, manager, encryptionCanary)
	// A retained encrypted rollback generation is rewrapped as well.
	job, err := manager.StartConversionTo("alice", ConversionTarget{Engine: store.BackendPebble, Encrypted: true, RotateKey: true})
	if err != nil {
		t.Fatal(err)
	}
	waitConversionPhase(t, manager, job.ID, ConversionCompleted)
	indexBefore := snapshotIndex(t, activeGenerationPath(t, manager))
	before := ring.ActiveKeyID()
	if _, err := ring.Rotate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := manager.EncryptionStatus(); status.Stale != 1 {
		t.Fatalf("status before rewrap = %+v", status)
	}
	report, err := manager.RewrapKeys(t.Context())
	if err != nil || report.Generations != 2 || report.Rewrapped != 2 || report.ActiveKeyID == before {
		t.Fatalf("rewrap = %+v, %v", report, err)
	}
	if again, err := manager.RewrapKeys(t.Context()); err != nil || again.Rewrapped != 0 {
		t.Fatalf("second rewrap = %+v, %v", again, err)
	}
	if status := manager.EncryptionStatus(); status.Stale != 0 || status.Accounts[0].KeyID != ring.ActiveKeyID() {
		t.Fatalf("status after rewrap = %+v", status)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(indexBefore, snapshotIndex(t, activeGenerationPath(t, manager))) {
		t.Fatal("rewrapping changed encrypted index files")
	}
	reopened := newEncryptionManager(t, root, ring)
	if got := logicalDigest(t, reopened); got != digest {
		t.Fatalf("digest after rewrap %s, want %s", got, digest)
	}
}

// snapshotIndex concatenates the object segments, which a rewrap must leave
// untouched; LSM engines rewrite their own files on open and close.
func snapshotIndex(t *testing.T, generationPath string) []byte {
	t.Helper()
	var all []byte
	segments, err := filepath.Glob(filepath.Join(generationPath, "objects", "segments", "*.seg"))
	if err != nil || len(segments) == 0 {
		t.Fatalf("segments = %v, %v", segments, err)
	}
	for _, segment := range segments {
		data, err := os.ReadFile(segment)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, data...)
	}
	return all
}

func TestEncryptedBundleRestoresOnlyWithTheKeyRing(t *testing.T) {
	ring := newTestRing(t)
	manager := newEncryptionManager(t, t.TempDir(), ring)
	if err := manager.SetEncryptionDefault(true); err != nil {
		t.Fatal(err)
	}
	ensureAlice(t, manager)
	appendCanary(t, manager, encryptionCanary)
	content := logicalContent(t, manager)
	var bundle bytes.Buffer
	if err := manager.Export(t.Context(), "alice", &bundle); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bundle.String(), encryptedBundleMark) || bytes.Contains(bundle.Bytes(), []byte("encryption-canary")) {
		t.Fatal("exported bundle of an encrypted account is not encrypted")
	}
	if _, err := ImportAccount(t.Context(), t.TempDir(), bytes.NewReader(bundle.Bytes()), store.BackendBadger, nil); !errors.Is(err, ErrEncryptionKeysUnavailable) {
		t.Fatalf("import without key ring = %v", err)
	}
	if _, err := ImportAccount(t.Context(), t.TempDir(), bytes.NewReader(bundle.Bytes()), store.BackendBadger, newTestRing(t)); !errors.Is(err, keyring.ErrKeyUnavailable) {
		t.Fatalf("import with a foreign key ring = %v", err)
	}
	tampered := bytes.Clone(bundle.Bytes())
	tampered[len(tampered)-5] ^= 1
	if _, err := ImportAccount(t.Context(), t.TempDir(), bytes.NewReader(tampered), store.BackendBadger, ring); err == nil {
		t.Fatal("tampered encrypted bundle restored")
	}
	restoreRoot := t.TempDir()
	restored, err := ImportAccount(t.Context(), restoreRoot, bytes.NewReader(bundle.Bytes()), store.BackendBadger, ring)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Manifest.Encrypted || restored.Manifest.Engine != store.BackendBadger {
		t.Fatalf("restored manifest = %+v", restored.Manifest)
	}
	if generationContains(t, filepath.Join(restored.Path, "generations", restored.Manifest.ActiveGeneration), "encryption-canary") {
		t.Fatal("restored generation stores plaintext")
	}
	restoredManager := newEncryptionManager(t, restoreRoot, ring)
	// A restore rebases client sync state, so only the content compares.
	if got := logicalContent(t, restoredManager); got != content {
		t.Fatalf("restored content %+v, want %+v", got, content)
	}
	// Manager.Restore accepts the encrypted bundle into the live account.
	if report, err := manager.Restore(t.Context(), "alice", bytes.NewReader(bundle.Bytes()), store.BackendPebble); err != nil || !report.Healthy {
		t.Fatalf("Restore = %+v, %v", report, err)
	}
	if entry, _ := manager.ByLogin("alice"); !entry.Manifest.Encrypted {
		t.Fatal("restore dropped account encryption")
	}
}

func TestWrongOrMissingKeysAreDetected(t *testing.T) {
	root := t.TempDir()
	ring := newTestRing(t)
	manager := newEncryptionManager(t, root, ring)
	if err := manager.SetEncryptionDefault(true); err != nil {
		t.Fatal(err)
	}
	entry := ensureAlice(t, manager)
	appendCanary(t, manager, encryptionCanary)
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newEncryptionManager(t, root, nil).Acquire("alice"); !errors.Is(err, ErrEncryptionKeysUnavailable) {
		t.Fatalf("open without key ring = %v", err)
	}
	if _, _, err := newEncryptionManager(t, root, newTestRing(t)).Acquire("alice"); !errors.Is(err, keyring.ErrKeyUnavailable) {
		t.Fatalf("open with foreign key ring = %v", err)
	}
	if _, err := OpenActive(entry); !errors.Is(err, ErrEncryptionKeysUnavailable) {
		t.Fatalf("OpenActive without keys = %v", err)
	}
	keyPath := generationKeyPath(filepath.Join(entry.Path, "generations", entry.Manifest.ActiveGeneration))
	if err := os.Rename(keyPath, keyPath+".moved"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newEncryptionManager(t, root, ring).Acquire("alice"); err == nil || !strings.Contains(err.Error(), "does not match its generation") {
		t.Fatalf("open with missing key file = %v", err)
	}
}

func TestDerivedDataIsSealedPerGeneration(t *testing.T) {
	ring := newTestRing(t)
	manager := newEncryptionManager(t, t.TempDir(), ring)
	ensureAlice(t, manager)
	if manager.DerivedEncrypted("alice") {
		t.Fatal("plaintext account reports encrypted derived data")
	}
	if _, err := manager.SealDerived("alice", []byte("aad"), []byte("x")); err == nil {
		t.Fatal("sealed derived data of a plaintext account")
	}
	job, err := manager.StartConversionTo("alice", ConversionTarget{Engine: store.BackendPebble, Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	waitConversionPhase(t, manager, job.ID, ConversionCompleted)
	sealed, err := manager.SealDerived("alice", []byte("aad"), []byte("Subject: preview"))
	if err != nil || bytes.Contains(sealed, []byte("preview")) || !manager.DerivedEncrypted("alice") {
		t.Fatalf("SealDerived = %q, %v", sealed, err)
	}
	if plain, err := manager.OpenDerived("alice", []byte("aad"), sealed); err != nil || string(plain) != "Subject: preview" {
		t.Fatalf("OpenDerived = %q, %v", plain, err)
	}
	if _, err := manager.OpenDerived("alice", []byte("other"), sealed); err == nil {
		t.Fatal("derived data opened under different associated data")
	}
	job, err = manager.StartConversionTo("alice", ConversionTarget{Engine: store.BackendPebble, Encrypted: true, RotateKey: true})
	if err != nil {
		t.Fatal(err)
	}
	waitConversionPhase(t, manager, job.ID, ConversionCompleted)
	if _, err := manager.OpenDerived("alice", []byte("aad"), sealed); err == nil {
		t.Fatal("derived data sealed under a replaced generation still opens")
	}
}
