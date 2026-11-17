package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/backup"
	"github.com/lkarlslund/veksel/pkg/backup/archivecrypt"
	"github.com/lkarlslund/veksel/pkg/config"
)

// runBackup writes an installation archive of a stopped server. The embedded
// engines lock their directories, so it fails clearly while Veksel runs; use
// the online backup endpoint for a running server.
func runBackup(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data-dir", "./data", "directory containing Veksel data and config.toml")
	output := flags.String("output", "", "archive file to write (required)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: veksel backup [--data-dir DIR] --output FILE")
		fmt.Fprintln(stderr, "Writes a full installation archive. Stop the server first, or use the online backup API.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *output == "" || flags.NArg() != 0 {
		flags.Usage()
		return errors.New("--output is required")
	}
	if _, err := os.Stat(config.FilePath(*dataDir)); err != nil {
		return fmt.Errorf("%s is not a Veksel data directory: %w", *dataDir, err)
	}
	cfgService, err := config.Open(*dataDir)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	cfg := cfgService.Current().Config
	system, err := cfg.OpenStore()
	if err != nil {
		return fmt.Errorf("open system store (is the server still running? stop it first, or use the online backup API): %w", err)
	}
	defer system.Close()
	catalog, err := account.DiscoverRoots(account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots))
	if err != nil {
		return fmt.Errorf("discover accounts: %w", err)
	}
	keys, err := backup.AccountKeys(context.Background(), system)
	if err != nil {
		return fmt.Errorf("load installation key ring: %w", err)
	}
	outputPath, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	partial, err := os.CreateTemp(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".partial-")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = partial.Close()
			_ = os.Remove(partial.Name())
		}
	}()
	if err := backup.WriteInstallation(context.Background(), backup.InstallationSource{
		System: system, SystemBackend: cfg.StoreBackend, Accounts: account.CatalogExporter{Catalog: catalog, Keys: keys},
		ConfigPath: config.FilePath(cfg.DataDir), VekselVersion: buildVersion, TempDir: filepath.Dir(outputPath),
	}, partial); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	if err := errors.Join(partial.Sync(), partial.Close()); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := os.Rename(partial.Name(), outputPath); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	committed = true
	fmt.Fprintf(stdout, "backup written to %s (%d accounts)\n", outputPath, len(catalog.Entries()))
	return nil
}

// runRestore rebuilds a data directory from an installation archive.
func runRestore(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data-dir", "./data", "empty directory to restore into")
	input := flags.String("input", "", "installation archive to restore (required)")
	force := flags.Bool("force", false, "replace existing data in --data-dir and account directories in the configured account roots")
	identity := flags.String("identity", "", "age or SSH private key file that decrypts an encrypted archive")
	accountRoots := map[string]string{}
	flags.Func("account-root", "move a configured account storage root: `ID=PATH` (repeatable); the restored config.toml records PATH", func(value string) error {
		id, path, found := strings.Cut(value, "=")
		id, path = strings.TrimSpace(id), strings.TrimSpace(path)
		if !found || id == "" || path == "" {
			return errors.New("expected ID=PATH")
		}
		if _, duplicate := accountRoots[id]; duplicate {
			return fmt.Errorf("account root %q given twice", id)
		}
		accountRoots[id] = path
		return nil
	})
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: veksel restore [--data-dir DIR] --input FILE [--identity KEYFILE] [--account-root ID=PATH]... [--force]")
		fmt.Fprintln(stderr, "Restores a full installation archive into an empty data directory. The server must be stopped.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || flags.NArg() != 0 {
		flags.Usage()
		return errors.New("--input is required")
	}
	archive, closeArchive, err := openArchiveInput(*input, *identity)
	if err != nil {
		return err
	}
	defer closeArchive()
	manifest, err := backup.RestoreInstallation(context.Background(), archive, *dataDir, backup.InstallationRestoreOptions{Force: *force, AccountRoots: accountRoots})
	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	fmt.Fprintf(stdout, "restored backup from %s (%d accounts) into %s\n", manifest.CreatedAt.Format("2006-01-02 15:04:05Z07:00"), len(manifest.Accounts), *dataDir)
	return nil
}

// runBackupVerify checks an archive of either kind without restoring it.
func runBackupVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backup-verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "archive to verify (required)")
	tempDir := flags.String("temp-dir", "", "scratch directory for the restore drill (default: system temp directory)")
	identity := flags.String("identity", "", "age or SSH private key file that decrypts an encrypted archive")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: veksel backup-verify --input FILE [--identity KEYFILE] [--temp-dir DIR]")
		fmt.Fprintln(stderr, "Checks every digest and rebuilds each account in scratch space; prints the result as JSON.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || flags.NArg() != 0 {
		flags.Usage()
		return errors.New("--input is required")
	}
	archive, closeArchive, err := openArchiveInput(*input, *identity)
	if err != nil {
		return err
	}
	defer closeArchive()
	verification, err := backup.VerifyArchive(context.Background(), archive, *tempDir)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(verification)
}

// openArchiveInput opens an archive file, decrypting it with the identity
// file when it is age-encrypted. Encryption is detected from the file header,
// so plain archives open the same way with or without --identity.
func openArchiveInput(path, identityPath string) (io.Reader, func(), error) {
	var identities []age.Identity
	if identityPath != "" {
		contents, err := os.ReadFile(identityPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read identity: %w", err)
		}
		if identities, err = archivecrypt.ParseIdentities(contents); err != nil {
			return nil, nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	archive, _, err := archivecrypt.Open(file, identities)
	if errors.Is(err, archivecrypt.ErrIdentityRequired) {
		err = errors.New("archive is age-encrypted; pass --identity with the matching private key file")
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return archive, func() { _ = file.Close() }, nil
}

// offlineCommands are the maintenance subcommands that run instead of the
// server. Each needs exclusive access to the data directory.
var offlineCommands = map[string]func(args []string, stdout, stderr io.Writer) error{
	"reset-password": func(args []string, stdout, stderr io.Writer) error {
		return runResetPassword(args, os.Stdin, stdout, stderr)
	},
	"backup":        runBackup,
	"restore":       runRestore,
	"backup-verify": runBackupVerify,
}

// runOfflineCommand runs a maintenance subcommand and returns its process exit
// status, or false when args do not name one.
func runOfflineCommand(args []string, stdout, stderr io.Writer) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	command, ok := offlineCommands[args[0]]
	if !ok {
		return 0, false
	}
	if err := command(args[1:], stdout, stderr); errors.Is(err, flag.ErrHelp) {
		return 0, true
	} else if err != nil {
		fmt.Fprintf(stderr, "veksel %s: %v\n", args[0], err)
		return 1, true
	}
	return 0, true
}
