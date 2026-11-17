package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/backup/archivecrypt"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
)

func runCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status, handled := runOfflineCommand(args, &stdout, &stderr)
	if !handled {
		t.Fatalf("%v was not handled as an offline command", args)
	}
	return status, stdout.String(), stderr.String()
}

// offlineSource builds a stopped data directory holding user alice and her
// account storage.
func offlineSource(t *testing.T) (string, *config.Config) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "source")
	withUserStore(t, source, func(users *model.UserStore) {
		if err := users.Create(context.Background(), "alice", "Alice", "secret-password"); err != nil {
			t.Fatal(err)
		}
	})
	cfgService, err := config.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgService.Current().Config
	manager, err := account.NewManagerWithRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots), cfg.PrimaryAccountRoot, cfg.DefaultAccountEngine)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Ensure(context.Background(), model.User{ID: "alice", DisplayName: "Alice", Enabled: true}, "alice@example.test", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	return source, cfg
}

func TestOfflineBackupRestoreVerifyCommands(t *testing.T) {
	source, cfg := offlineSource(t)
	archive := filepath.Join(t.TempDir(), "veksel.tar")

	locked, err := cfg.OpenStore()
	if err != nil {
		t.Fatal(err)
	}
	status, _, stderr := runCommand(t, "backup", "--data-dir", source, "--output", archive)
	_ = locked.Close()
	if status == 0 || !strings.Contains(stderr, "still running") {
		t.Fatalf("backup of a locked store: status=%d stderr=%q", status, stderr)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("failed backup left output behind: %v", err)
	}

	if status, _, stderr := runCommand(t, "backup", "--data-dir", source, "--output", archive); status != 0 {
		t.Fatalf("backup status=%d stderr=%q", status, stderr)
	}
	status, stdout, stderr := runCommand(t, "backup-verify", "--input", archive, "--temp-dir", t.TempDir())
	var verification backup.ArchiveVerification
	if status != 0 || json.Unmarshal([]byte(stdout), &verification) != nil || verification.Kind != backup.ArchiveKindInstallation || len(verification.Installation.Accounts) != 1 {
		t.Fatalf("verify status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}

	if status, _, stderr := runCommand(t, "restore", "--data-dir", source, "--input", archive); status == 0 || !strings.Contains(stderr, "not empty") {
		t.Fatalf("restore into populated directory: status=%d stderr=%q", status, stderr)
	}
	target := filepath.Join(t.TempDir(), "target")
	if status, _, stderr := runCommand(t, "restore", "--data-dir", target, "--input", archive); status != 0 {
		t.Fatalf("restore status=%d stderr=%q", status, stderr)
	}
	withUserStore(t, target, func(users *model.UserStore) {
		if user, err := users.Get(context.Background(), "alice"); err != nil || user.DisplayName != "Alice" {
			t.Fatalf("restored user = %+v, %v", user, err)
		}
	})
	catalog, err := account.Discover(filepath.Join(target, "accounts"))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := catalog.ByLogin("alice"); !found || len(catalog.Issues()) != 0 {
		t.Fatalf("restored accounts = %+v issues=%+v", catalog.Entries(), catalog.Issues())
	}
}

func TestOfflineRestoreAndVerifyDecryptEncryptedArchives(t *testing.T) {
	source, _ := offlineSource(t)
	plain := filepath.Join(t.TempDir(), "veksel.tar")
	if status, _, stderr := runCommand(t, "backup", "--data-dir", source, "--output", plain); status != 0 {
		t.Fatalf("backup status=%d stderr=%q", status, stderr)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	encryptor, err := archivecrypt.Encrypt(&ciphertext, []age.Recipient{identity.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encryptor.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := encryptor.Close(); err != nil {
		t.Fatal(err)
	}
	encrypted := plain + ".age"
	identityFile := filepath.Join(t.TempDir(), "backup-key.txt")
	if err := os.WriteFile(encrypted, ciphertext.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityFile, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if status, _, stderr := runCommand(t, "backup-verify", "--input", encrypted); status == 0 || !strings.Contains(stderr, "--identity") {
		t.Fatalf("verify without identity: status=%d stderr=%q", status, stderr)
	}
	status, stdout, stderr := runCommand(t, "backup-verify", "--input", encrypted, "--identity", identityFile, "--temp-dir", t.TempDir())
	var verification backup.ArchiveVerification
	if status != 0 || json.Unmarshal([]byte(stdout), &verification) != nil || !verification.Verified || len(verification.Installation.Accounts) != 1 {
		t.Fatalf("verify with identity: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	// A plain archive opens the same way when an identity is passed.
	if status, _, stderr := runCommand(t, "backup-verify", "--input", plain, "--identity", identityFile, "--temp-dir", t.TempDir()); status != 0 {
		t.Fatalf("verify plain archive with identity: status=%d stderr=%q", status, stderr)
	}
	target := filepath.Join(t.TempDir(), "target")
	if status, _, stderr := runCommand(t, "restore", "--data-dir", target, "--input", encrypted); status == 0 || !strings.Contains(stderr, "--identity") {
		t.Fatalf("restore without identity: status=%d stderr=%q", status, stderr)
	}
	if status, _, stderr := runCommand(t, "restore", "--data-dir", target, "--input", encrypted, "--identity", identityFile); status != 0 {
		t.Fatalf("restore with identity: status=%d stderr=%q", status, stderr)
	}
	withUserStore(t, target, func(users *model.UserStore) {
		if user, err := users.Get(context.Background(), "alice"); err != nil || user.DisplayName != "Alice" {
			t.Fatalf("restored user = %+v, %v", user, err)
		}
	})
}

func TestOfflineCommandExitCodes(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage.tar")
	if err := os.WriteFile(garbage, []byte("not an archive at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args   []string
		status int
	}{
		{[]string{"backup-verify", "--input", garbage}, 1},
		{[]string{"backup-verify"}, 1},
		{[]string{"backup", "--data-dir", t.TempDir()}, 1},
		{[]string{"backup", "--data-dir", filepath.Join(t.TempDir(), "missing"), "--output", filepath.Join(t.TempDir(), "out.tar")}, 1},
		{[]string{"restore", "--data-dir", t.TempDir(), "--input", garbage}, 1},
		{[]string{"restore", "--data-dir", t.TempDir(), "--input", filepath.Join(t.TempDir(), "missing.tar")}, 1},
		{[]string{"restore", "--data-dir", t.TempDir(), "--input", garbage, "--account-root", "no-path"}, 1},
		{[]string{"restore", "--data-dir", t.TempDir(), "--input", garbage, "--account-root", "a=/x", "--account-root", "a=/y"}, 1},
		{[]string{"backup", "-h"}, 0},
	} {
		if status, _, stderr := runCommand(t, test.args...); status != test.status {
			t.Errorf("%v: status=%d want %d (stderr=%q)", test.args, status, test.status, stderr)
		}
	}
	if _, handled := runOfflineCommand([]string{"--data-dir", "x"}, &bytes.Buffer{}, &bytes.Buffer{}); handled {
		t.Fatal("server flags were treated as an offline command")
	}
}
