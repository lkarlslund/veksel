package backup_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/keyring"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

type installationFixture struct {
	dataDir string
	config  []byte
	user    model.User
	folders []model.Folder
	account account.Entry
	item    model.Item
	archive []byte
}

// attachmentMessage is a MIME message whose binary attachment is stored in
// the account object store.
func attachmentMessage() []byte {
	attachment := bytes.Repeat([]byte("binary-attachment-payload\x00\x01\x02"), 4096)
	var message bytes.Buffer
	message.WriteString("Subject: restore drill\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n")
	message.WriteString("--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n")
	message.WriteString("--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=data.bin\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	message.WriteString(strings.Repeat("QUJD", len(attachment)/3))
	message.WriteString("\r\n--b--\r\n")
	return message.Bytes()
}

// newInstallation builds a real data directory (Pebble system store, account
// manager with one account holding an item) and takes an online backup.
func newInstallation(t *testing.T) installationFixture { return newInstallationWith(t, false) }

// newInstallationWith optionally encrypts the account under the system key ring.
func newInstallationWith(t *testing.T, encrypted bool) installationFixture {
	return newConfiguredInstallation(t, encrypted, nil)
}

// newConfiguredInstallation applies settings to config.toml before the
// installation is populated.
func newConfiguredInstallation(t *testing.T, encrypted bool, settings map[string]any) installationFixture {
	t.Helper()
	ctx := t.Context()
	dataDir := filepath.Join(t.TempDir(), "source")
	cfgService, err := config.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if settings != nil {
		if _, err := cfgService.Patch(cfgService.Current().Revision, settings); err != nil {
			t.Fatal(err)
		}
	}
	cfg := cfgService.Current().Config
	system, err := cfg.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()
	ts := model.NewTypedStore(system, cfg.StoreBackend)
	if err := model.InitializeSystemStore(ctx, ts); err != nil {
		t.Fatal(err)
	}
	if err := ts.DomainStore().Create(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := ts.UserStore().Create(ctx, "alice", "Alice", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if err := ts.FolderStore().EnsureForUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	user, err := ts.UserStore().Get(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	folders, err := ts.FolderStore().ListForUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.For(ctx, system)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := account.NewManagerWithRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots), cfg.PrimaryAccountRoot, cfg.DefaultAccountEngine, account.WithKeyRing(ring))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	if err := manager.SetEncryptionDefault(encrypted); err != nil {
		t.Fatal(err)
	}
	entry, _, err := manager.Ensure(ctx, user, "alice@example.test", []string{"alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	accountModel := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	inbox, err := accountModel.FolderStore().GetByPath(ctx, "alice", "INBOX")
	if err != nil {
		release()
		t.Fatal(err)
	}
	item, err := accountModel.ItemStore().AppendItem(ctx, inbox.ID, model.Item{Data: attachmentMessage()})
	release()
	if err != nil {
		t.Fatal(err)
	}
	// AppendItem bypasses the folder space that maintains quota counters;
	// repair them so the source account is healthy before it is backed up.
	if report, err := manager.Check(ctx, "alice", true); err != nil || !report.Healthy {
		t.Fatalf("source integrity = %+v, %v", report, err)
	}
	configContents, err := os.ReadFile(config.FilePath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := backup.WriteInstallation(ctx, backup.InstallationSource{
		System: system, SystemBackend: cfg.StoreBackend, Accounts: manager, ConfigPath: config.FilePath(dataDir), TempDir: t.TempDir(),
	}, &archive); err != nil {
		t.Fatal(err)
	}
	return installationFixture{dataDir: dataDir, config: configContents, user: user, folders: folders, account: entry, item: item, archive: archive.Bytes()}
}

func TestInstallationBackupRestoreRoundTrip(t *testing.T) {
	ctx := t.Context()
	fixture := newInstallation(t)

	verification, err := backup.VerifyArchive(ctx, bytes.NewReader(fixture.archive), t.TempDir())
	if err != nil {
		t.Fatalf("VerifyArchive: %v", err)
	}
	if verification.Kind != backup.ArchiveKindInstallation || !verification.Verified || len(verification.Installation.Accounts) != 1 ||
		verification.Installation.SystemSchemaVersion != model.SystemSchemaVersion || verification.Metadata.SchemaVersion != model.SystemSchemaVersion {
		t.Fatalf("verification = %+v installation=%+v", verification, verification.Installation)
	}

	target := filepath.Join(t.TempDir(), "restored")
	manifest, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{})
	if err != nil {
		t.Fatalf("RestoreInstallation: %v", err)
	}
	if len(manifest.Accounts) != 1 {
		t.Fatalf("restored accounts = %+v", manifest.Accounts)
	}
	if staging, _ := filepath.Glob(filepath.Join(target, ".veksel-restore-*")); len(staging) != 0 {
		t.Fatalf("restore left staging behind: %v", staging)
	}
	restoredConfig, err := os.ReadFile(config.FilePath(target))
	if err != nil || !bytes.Equal(restoredConfig, fixture.config) {
		t.Fatalf("config.toml not restored verbatim: %v", err)
	}

	cfgService, err := config.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgService.Current().Config
	system, err := cfg.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()
	ts := model.NewTypedStore(system, cfg.StoreBackend)
	if err := model.InitializeSystemStore(ctx, ts); err != nil {
		t.Fatalf("restored store does not start: %v", err)
	}
	if _, err := ts.DomainStore().Get(ctx, "example.test"); err != nil {
		t.Fatalf("domain: %v", err)
	}
	user, err := ts.UserStore().Get(ctx, "alice")
	if err != nil || !reflect.DeepEqual(user, fixture.user) {
		t.Fatalf("user = %+v, %v; want %+v", user, err, fixture.user)
	}
	folders, err := ts.FolderStore().ListForUser(ctx, "alice")
	if err != nil || !reflect.DeepEqual(folders, fixture.folders) {
		t.Fatalf("system folders = %d, %v; want %d", len(folders), err, len(fixture.folders))
	}

	manager, err := account.NewManagerWithRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots), cfg.PrimaryAccountRoot, cfg.DefaultAccountEngine)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	if issues := manager.Issues(); len(issues) != 0 {
		t.Fatalf("restored account issues: %+v", issues)
	}
	entry, found := manager.ByLogin("alice")
	if !found || entry.Manifest.ID != fixture.account.Manifest.ID || entry.Manifest.Engine != fixture.account.Manifest.Engine ||
		!reflect.DeepEqual(entry.Manifest.Addresses, fixture.account.Manifest.Addresses) {
		t.Fatalf("restored account = %+v found=%t", entry.Manifest, found)
	}
	report, err := manager.Check(ctx, "alice", false)
	if err != nil || !report.Healthy {
		t.Fatalf("integrity = %+v, %v", report, err)
	}
	if _, created, err := manager.Ensure(ctx, user, "alice@example.test", []string{"alice@example.test"}); err != nil || created {
		t.Fatalf("startup reconciliation would recreate the account: created=%t err=%v", created, err)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	accountModel := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects)
	item, err := accountModel.ItemStore().Get(ctx, fixture.item.ID)
	if err != nil || !bytes.Equal(item.Data, fixture.item.Data) || item.FolderID != fixture.item.FolderID {
		t.Fatalf("restored item = %v (len %d), want len %d", err, len(item.Data), len(fixture.item.Data))
	}
}

func TestEncryptedAccountInstallationRoundTrip(t *testing.T) {
	ctx := t.Context()
	fixture := newInstallationWith(t, true)
	if !fixture.account.Manifest.Encrypted {
		t.Fatal("fixture account is not encrypted")
	}
	rewriteInstallation(t, fixture.archive, func(name string, data []byte) []byte {
		if strings.HasPrefix(name, "accounts/") && (bytes.Contains(data, []byte("restore drill")) || !bytes.HasPrefix(data, []byte("VEKSEL-ENCRYPTED-BUNDLE-1\n"))) {
			t.Fatalf("archived bundle %s is not encrypted", name)
		}
		return data
	})
	verification, err := backup.VerifyArchive(ctx, bytes.NewReader(fixture.archive), t.TempDir())
	if err != nil || !verification.Installation.Accounts[0].Encrypted {
		t.Fatalf("VerifyArchive = %+v, %v", verification, err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{}); err != nil {
		t.Fatalf("RestoreInstallation: %v", err)
	}
	cfgService, err := config.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgService.Current().Config
	system, err := cfg.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()
	ring, err := keyring.For(ctx, system)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := account.NewManagerWithRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots), cfg.PrimaryAccountRoot, cfg.DefaultAccountEngine, account.WithKeyRing(ring))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close() }()
	entry, found := manager.ByLogin("alice")
	if !found || !entry.Manifest.Encrypted {
		t.Fatalf("restored account = %+v found=%t", entry.Manifest, found)
	}
	generation, release, err := manager.Acquire("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	item, err := model.NewTypedStoreWithObjects(generation.Index, generation.Engine, generation.Objects).ItemStore().Get(ctx, fixture.item.ID)
	if err != nil || !bytes.Equal(item.Data, fixture.item.Data) {
		t.Fatalf("restored encrypted item = %v (len %d)", err, len(item.Data))
	}
}

func TestInstallationRestoreRefusesNonEmptyTargetUnlessForced(t *testing.T) {
	ctx := t.Context()
	fixture := newInstallation(t)
	target := t.TempDir()
	sentinel := filepath.Join(target, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("operator data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{}); !errors.Is(err, backup.ErrTargetNotEmpty) {
		t.Fatalf("restore into non-empty target error = %v", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 1 {
		t.Fatalf("refused restore changed target: %v", entries)
	}
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{Force: true}); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forced restore kept prior contents: %v", err)
	}
	if _, err := os.Stat(config.FilePath(target)); err != nil {
		t.Fatalf("forced restore did not write configuration: %v", err)
	}
}

// TestInstallationRestoreMovesAccountRoots restores an installation whose
// account root has an absolute path onto a host where that path is taken: the
// restore is refused before the data directory changes, and succeeds with the
// root moved, recording the new path in config.toml.
func TestInstallationRestoreMovesAccountRoots(t *testing.T) {
	ctx := t.Context()
	originalRoot := filepath.Join(t.TempDir(), "original-root")
	fixture := newConfiguredInstallation(t, false, map[string]any{
		"account_storage_roots": []string{"main=" + originalRoot},
		"primary_account_root":  "main",
	})
	if fixture.account.RootID != "main" {
		t.Fatalf("fixture account root = %q", fixture.account.RootID)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{}); !errors.Is(err, backup.ErrTargetNotEmpty) {
		t.Fatalf("restore over the live account root error = %v", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("refused restore wrote into the data directory: %v", entries)
	}
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{AccountRoots: map[string]string{"elsewhere": "x"}}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unknown account root error = %v", err)
	}
	movedRoot := filepath.Join(t.TempDir(), "moved-root")
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{AccountRoots: map[string]string{"main": movedRoot}}); err != nil {
		t.Fatalf("restore with moved root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(movedRoot, fixture.account.Manifest.ID)); err != nil {
		t.Fatalf("account not restored into the moved root: %v", err)
	}
	if entries, _ := os.ReadDir(originalRoot); len(entries) != 1 {
		t.Fatalf("restore touched the original root: %v", entries)
	}
	cfgService, err := config.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if roots := cfgService.Current().Config.AccountStorageRoots; !reflect.DeepEqual(roots, []string{"main=" + movedRoot}) {
		t.Fatalf("restored account_storage_roots = %q", roots)
	}
}

// TestInstallationRestoreRemovesPartialRestore fails a restore after the
// system store is written, when the account root cannot be created, and
// requires the data directory to be left empty so the restore can rerun.
func TestInstallationRestoreRemovesPartialRestore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	ctx := t.Context()
	fixture := newInstallation(t)
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	target := filepath.Join(t.TempDir(), "restored")
	roots := map[string]string{fixture.account.RootID: filepath.Join(locked, "accounts")}
	_, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{AccountRoots: roots})
	if err == nil || !strings.Contains(err.Error(), "partial restore was removed") {
		t.Fatalf("restore into an unwritable account root error = %v", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("failed restore left %v in the data directory", entries)
	}
	if err := os.Chmod(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(fixture.archive), target, backup.InstallationRestoreOptions{AccountRoots: roots}); err != nil {
		t.Fatalf("rerun after the failure: %v", err)
	}
}

func TestInstallationVerifyAndRestoreRejectTamperedMember(t *testing.T) {
	ctx := t.Context()
	fixture := newInstallation(t)
	tampered := rewriteInstallation(t, fixture.archive, func(name string, data []byte) []byte {
		if strings.HasPrefix(name, "accounts/") {
			data = bytes.Clone(data)
			data[len(data)/2] ^= 0xff
		}
		return data
	})
	if _, err := backup.VerifyArchive(ctx, bytes.NewReader(tampered), t.TempDir()); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered archive verification error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := backup.RestoreInstallation(ctx, bytes.NewReader(tampered), target, backup.InstallationRestoreOptions{}); err == nil {
		t.Fatal("tampered archive restored")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("rejected restore wrote into target: %v", entries)
	}
	truncated := fixture.archive[:len(fixture.archive)/2]
	if _, err := backup.VerifyArchive(ctx, bytes.NewReader(truncated), t.TempDir()); err == nil {
		t.Fatal("truncated archive passed verification")
	}
}

func TestInstallationRejectsNewerSchemaAndFormat(t *testing.T) {
	ctx := t.Context()
	fixture := newInstallation(t)
	for name, mutate := range map[string]func(map[string]any){
		"system schema":  func(m map[string]any) { m["system_schema_version"] = model.SystemSchemaVersion + 1 },
		"account schema": func(m map[string]any) { m["account_schema_version"] = account.CurrentSchemaVersion + 1 },
		"format":         func(m map[string]any) { m["format_version"] = backup.InstallationFormatVersion + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			newer := rewriteInstallation(t, fixture.archive, func(member string, data []byte) []byte {
				if member != "manifest.json" {
					return data
				}
				var manifest map[string]any
				if err := json.Unmarshal(data, &manifest); err != nil {
					t.Fatal(err)
				}
				mutate(manifest)
				data, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				return data
			})
			if _, err := backup.VerifyArchive(ctx, bytes.NewReader(newer), t.TempDir()); err == nil {
				t.Fatal("newer archive passed verification")
			}
			target := filepath.Join(t.TempDir(), "restored")
			_, err := backup.RestoreInstallation(ctx, bytes.NewReader(newer), target, backup.InstallationRestoreOptions{})
			if err == nil || !strings.Contains(err.Error(), "newer") && !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("newer archive restore error = %v", err)
			}
		})
	}
}

func TestSystemBackupRecordsAndEnforcesSchemaVersion(t *testing.T) {
	ctx := t.Context()
	source := newTestStore(t)
	ts := model.NewTypedStore(source, store.BackendJSON)
	if err := model.InitializeSystemStore(ctx, ts); err != nil {
		t.Fatal(err)
	}
	data, err := backup.BackupToBytes(source, "json")
	if err != nil {
		t.Fatal(err)
	}
	verification, err := backup.Verify(bytes.NewReader(data))
	if err != nil || verification.Metadata.SchemaVersion != model.SystemSchemaVersion {
		t.Fatalf("verification = %+v, %v", verification, err)
	}
	if err := source.Set(ctx, model.NSSchema, "system", []byte(strconv.Itoa(model.SystemSchemaVersion+1))); err != nil {
		t.Fatal(err)
	}
	if err := model.InitializeSystemStore(ctx, ts); !errors.Is(err, model.ErrSystemSchemaTooNew) {
		t.Fatalf("opening newer store error = %v", err)
	}
	newer, err := backup.BackupToBytes(source, "json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(newer)); !errors.Is(err, model.ErrSystemSchemaTooNew) {
		t.Fatalf("verify newer backup error = %v", err)
	}
	if _, err := backup.Restore(newTestStore(t), bytes.NewReader(newer), backup.Replace); !errors.Is(err, model.ErrSystemSchemaTooNew) {
		t.Fatalf("restore newer backup error = %v", err)
	}
}

// TestSystemRestoreUpgradesOlderArchive restores a schema 1 archive, which
// still holds a namespace retired in schema 2, into a current store.
func TestSystemRestoreUpgradesOlderArchive(t *testing.T) {
	ctx := t.Context()
	source := newTestStore(t)
	if err := model.InitializeSystemStore(ctx, model.NewTypedStore(source, store.BackendJSON)); err != nil {
		t.Fatal(err)
	}
	if err := source.Set(ctx, model.NSSchema, "system", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := source.CreateNamespace(ctx, "forwarding"); err != nil {
		t.Fatal(err)
	}
	if err := source.Set(ctx, "forwarding", "alice", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	older, err := backup.BackupToBytes(source, "json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(bytes.NewReader(older)); err != nil {
		t.Fatalf("verify older backup: %v", err)
	}
	for _, mode := range []backup.Mode{backup.Replace, backup.Merge} {
		target := newTestStore(t)
		if err := model.InitializeSystemStore(ctx, model.NewTypedStore(target, store.BackendJSON)); err != nil {
			t.Fatal(err)
		}
		if _, err := backup.Restore(target, bytes.NewReader(older), mode); err != nil {
			t.Fatalf("restore older backup (mode %v): %v", mode, err)
		}
		if version, err := model.ReadSystemSchemaVersion(ctx, target); err != nil || version != model.SystemSchemaVersion {
			t.Fatalf("restored schema version = %d, %v", version, err)
		}
		if exists, err := target.NamespaceExists(ctx, "forwarding"); err != nil || exists {
			t.Fatalf("retired namespace survived restore: %v, %v", exists, err)
		}
	}
}

func rewriteInstallation(t *testing.T, archive []byte, rewrite func(string, []byte) []byte) []byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(archive))
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		data = rewrite(header.Name, data)
		header.Size = int64(len(data))
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
