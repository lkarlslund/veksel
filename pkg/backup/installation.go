package backup

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/backup/archivecrypt"
	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// An installation archive is an uncompressed tar whose members are, in order:
//
//	config.toml                     managed configuration (optional)
//	system.tar.gz                   system store, v2 logical backup format
//	accounts/<account-id>.tar.gz    one portable account bundle per account
//	manifest.json                   InstallationManifest, always last
//
// The manifest carries a SHA-256 digest and size for every other member, so
// verification detects missing, extra, truncated, or modified members. Members
// are already compressed, so the outer tar is not.
const (
	InstallationFormat        = "veksel-installation"
	InstallationFormatVersion = 1

	installationManifestName  = "manifest.json"
	installationSystemName    = "system.tar.gz"
	installationConfigName    = "config.toml"
	installationAccountPrefix = "accounts/"
	maxInstallationManifest   = 64 << 20
	maxInstallationMembers    = 1_000_000
)

var installationAccountMember = regexp.MustCompile(`^accounts/acc_[0-9a-f]{32}\.tar\.gz$`)

// ErrTargetNotEmpty is returned when a restore target already holds data and
// the caller did not ask to replace it.
var ErrTargetNotEmpty = errors.New("restore target is not empty")

// InstallationAccount locates one account bundle inside an installation archive.
type InstallationAccount struct {
	ID     string        `json:"account_id"`
	Login  string        `json:"login"`
	RootID string        `json:"root_id,omitempty"`
	Engine store.Backend `json:"engine"`
	// Encrypted accounts are archived as encrypted bundles that restore only
	// with the installation key ring carried in the system store.
	Encrypted bool   `json:"encrypted,omitempty"`
	File      string `json:"file"`
}

// InstallationManifest describes and authenticates an installation archive.
type InstallationManifest struct {
	Format               string                `json:"format"`
	FormatVersion        int                   `json:"format_version"`
	CreatedAt            time.Time             `json:"created_at"`
	VekselVersion        string                `json:"veksel_version,omitempty"`
	SystemBackend        store.Backend         `json:"system_backend"`
	SystemSchemaVersion  int                   `json:"system_schema_version"`
	AccountSchemaVersion int                   `json:"account_schema_version"`
	Algorithm            string                `json:"algorithm"`
	Files                []ManifestRecord      `json:"files"`
	TotalBytes           int64                 `json:"total_bytes"`
	Accounts             []InstallationAccount `json:"accounts"`
}

// HasConfig reports whether the archive carries config.toml.
func (m *InstallationManifest) HasConfig() bool {
	return slices.ContainsFunc(m.Files, func(record ManifestRecord) bool { return record.Name == installationConfigName })
}

// AccountExporter is the account source of an installation backup. Both
// *account.Manager (online) and account.CatalogExporter (offline) satisfy it.
type AccountExporter interface {
	Entries() []account.Entry
	Issues() []account.Issue
	Export(ctx context.Context, login string, destination io.Writer) error
}

// InstallationSource names everything an installation backup reads.
type InstallationSource struct {
	System        store.Store
	SystemBackend store.Backend
	// Accounts is optional only for installations without account storage.
	Accounts AccountExporter
	// ConfigPath is the managed config.toml; empty omits it.
	ConfigPath    string
	VekselVersion string
	// TempDir holds one spooled member at a time; empty uses os.TempDir.
	TempDir string
}

// LiveSource describes a running installation for an online backup. accounts
// and configPath may be absent in embedded or test setups; spooling then uses
// the system temporary directory instead of the data directory.
func LiveSource(system store.Store, backend store.Backend, accounts *account.Manager, configPath string) InstallationSource {
	source := InstallationSource{System: system, SystemBackend: backend, ConfigPath: configPath}
	if accounts != nil {
		source.Accounts = accounts
	}
	if configPath != "" {
		source.TempDir = filepath.Dir(configPath)
	}
	return source
}

// WriteInstallation writes a complete installation archive to w. Each store is
// read from its own consistent snapshot: the system store through one store
// view and every account through the bundle exporter's view. Stores are not
// frozen together, so writes landing between snapshots may appear in one store
// and not another; quiesce the server (or back up offline) for a single point
// in time.
func WriteInstallation(ctx context.Context, source InstallationSource, w io.Writer) error {
	if source.System == nil || w == nil {
		return errors.New("installation backup requires a system store and a destination")
	}
	spool, err := os.MkdirTemp(source.TempDir, "veksel-backup-")
	if err != nil {
		return fmt.Errorf("create backup spool: %w", err)
	}
	defer func() { _ = os.RemoveAll(spool) }()
	schemaVersion, err := model.ReadSystemSchemaVersion(ctx, source.System)
	if err != nil {
		return err
	}
	manifest := InstallationManifest{
		Format: InstallationFormat, FormatVersion: InstallationFormatVersion, CreatedAt: time.Now().UTC(),
		VekselVersion: source.VekselVersion, SystemBackend: source.SystemBackend, SystemSchemaVersion: schemaVersion,
		AccountSchemaVersion: account.CurrentSchemaVersion, Algorithm: "sha256", Files: []ManifestRecord{}, Accounts: []InstallationAccount{},
	}
	tarWriter := tar.NewWriter(w)
	addMember := func(name string, produce func(io.Writer) error) error {
		record, err := writeSpooledMember(ctx, tarWriter, spool, name, manifest.CreatedAt, produce)
		if err != nil {
			return fmt.Errorf("back up %s: %w", name, err)
		}
		manifest.Files = append(manifest.Files, record)
		manifest.TotalBytes += record.Size
		return nil
	}
	log.Info("backup: starting installation backup")
	started := time.Now()
	writeErr := func() error {
		if source.ConfigPath != "" {
			contents, err := os.ReadFile(source.ConfigPath)
			if err != nil {
				return fmt.Errorf("read configuration: %w", err)
			}
			if err := addMember(installationConfigName, func(w io.Writer) error { _, err := w.Write(contents); return err }); err != nil {
				return err
			}
		}
		if err := addMember(installationSystemName, func(w io.Writer) error {
			return BackupContext(ctx, source.System, w, string(source.SystemBackend))
		}); err != nil {
			return err
		}
		if source.Accounts != nil {
			if issues := source.Accounts.Issues(); len(issues) > 0 {
				return fmt.Errorf("account discovery reports %d issue(s) (first: %s: %s); resolve them so no account is silently left out", len(issues), issues[0].Path, issues[0].Message)
			}
			for _, entry := range source.Accounts.Entries() {
				file := installationAccountPrefix + entry.Manifest.ID + ".tar.gz"
				if err := addMember(file, func(w io.Writer) error {
					return source.Accounts.Export(ctx, entry.Manifest.Login, w)
				}); err != nil {
					return err
				}
				manifest.Accounts = append(manifest.Accounts, InstallationAccount{
					ID: entry.Manifest.ID, Login: entry.Manifest.Login, RootID: entry.RootID, Engine: entry.Manifest.Engine, Encrypted: entry.Manifest.Encrypted, File: file,
				})
			}
		}
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		return writeRecord(tarWriter, installationManifestName, data, manifest.CreatedAt)
	}()
	if err := errors.Join(writeErr, tarWriter.Close()); err != nil {
		return err
	}
	log.Info("backup: installation backup completed", "accounts", len(manifest.Accounts), "bytes", manifest.TotalBytes, "duration", time.Since(started))
	return nil
}

// writeSpooledMember produces one member into a temporary file, because a tar
// header needs the size up front, then copies it into the archive.
func writeSpooledMember(ctx context.Context, tarWriter *tar.Writer, spool, name string, modified time.Time, produce func(io.Writer) error) (ManifestRecord, error) {
	file, err := os.CreateTemp(spool, "member-")
	if err != nil {
		return ManifestRecord{}, err
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	digest := sha256.New()
	buffered := bufio.NewWriter(io.MultiWriter(file, digest))
	if err := produce(buffered); err != nil {
		return ManifestRecord{}, err
	}
	if err := buffered.Flush(); err != nil {
		return ManifestRecord{}, err
	}
	size, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return ManifestRecord{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ManifestRecord{}, err
	}
	header := &tar.Header{Name: name, Size: size, Mode: 0o600, ModTime: modified, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := tarWriter.WriteHeader(header); err != nil {
		return ManifestRecord{}, err
	}
	if _, err := io.Copy(tarWriter, contextReader{ctx: ctx, r: file}); err != nil {
		return ManifestRecord{}, err
	}
	return ManifestRecord{Name: name, Size: size, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

// stagedInstallation is an installation archive extracted to disk whose
// members all matched the manifest.
type stagedInstallation struct {
	dir      string
	manifest InstallationManifest
	paths    map[string]string
}

func (s *stagedInstallation) Close() error { return os.RemoveAll(s.dir) }

func (s *stagedInstallation) open(name string) (*os.File, error) {
	path, ok := s.paths[name]
	if !ok {
		return nil, fmt.Errorf("archive member %s is missing", name)
	}
	return os.Open(path)
}

// stageInstallation extracts every member into a private directory under
// tempDir and validates the manifest, digests, and version compatibility.
func stageInstallation(ctx context.Context, r io.Reader, tempDir string) (_ *stagedInstallation, err error) {
	dir, err := os.MkdirTemp(tempDir, ".veksel-restore-")
	if err != nil {
		return nil, fmt.Errorf("create restore staging directory: %w", err)
	}
	staged := &stagedInstallation{dir: dir, paths: make(map[string]string)}
	defer func() {
		if err != nil {
			_ = staged.Close()
		}
	}()
	tarReader := tar.NewReader(contextReader{ctx: ctx, r: r})
	observed := make(map[string]ManifestRecord)
	var manifestData []byte
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("read installation archive: %w", nextErr)
		}
		name := header.Name
		if header.Typeflag != tar.TypeReg || header.Size < 0 || !validInstallationMember(name) {
			return nil, fmt.Errorf("unexpected installation archive entry %q", name)
		}
		if _, duplicate := observed[name]; duplicate || (name == installationManifestName && manifestData != nil) {
			return nil, fmt.Errorf("duplicate installation archive entry %q", name)
		}
		if len(observed) >= maxInstallationMembers {
			return nil, errors.New("installation archive has too many entries")
		}
		if name == installationManifestName {
			if header.Size > maxInstallationManifest {
				return nil, errors.New("installation manifest is too large")
			}
			manifestData, err = io.ReadAll(io.LimitReader(tarReader, header.Size+1))
			if err != nil || int64(len(manifestData)) != header.Size {
				return nil, errors.New("truncated installation manifest")
			}
			continue
		}
		path := filepath.Join(dir, fmt.Sprintf("member-%d", len(observed)))
		record, err := stageMember(tarReader, path, name, header.Size)
		if err != nil {
			return nil, err
		}
		observed[name] = record
		staged.paths[name] = path
	}
	if manifestData == nil {
		return nil, errors.New("not a Veksel installation archive: manifest.json is missing")
	}
	if err := json.Unmarshal(manifestData, &staged.manifest); err != nil {
		return nil, fmt.Errorf("parse installation manifest: %w", err)
	}
	if err := validateInstallationManifest(&staged.manifest, observed); err != nil {
		return nil, err
	}
	return staged, nil
}

func validInstallationMember(name string) bool {
	switch name {
	case installationManifestName, installationSystemName, installationConfigName:
		return true
	}
	return installationAccountMember.MatchString(name)
}

func stageMember(source io.Reader, path, name string, size int64) (ManifestRecord, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ManifestRecord{}, err
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(source, size))
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return ManifestRecord{}, fmt.Errorf("stage %s: %w", name, err)
	}
	if written != size {
		return ManifestRecord{}, fmt.Errorf("truncated installation archive entry %q", name)
	}
	return ManifestRecord{Name: name, Size: size, SHA256: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

func validateInstallationManifest(manifest *InstallationManifest, observed map[string]ManifestRecord) error {
	if manifest.Format != InstallationFormat {
		return fmt.Errorf("unknown archive format %q", manifest.Format)
	}
	if manifest.FormatVersion < 1 || manifest.FormatVersion > InstallationFormatVersion {
		return fmt.Errorf("installation archive format version %d is not supported (this binary reads up to %d)", manifest.FormatVersion, InstallationFormatVersion)
	}
	if err := model.CheckSystemSchemaVersion(manifest.SystemSchemaVersion); err != nil {
		return err
	}
	if manifest.AccountSchemaVersion > account.CurrentSchemaVersion {
		return fmt.Errorf("account schema version %d is newer than this binary supports (%d)", manifest.AccountSchemaVersion, account.CurrentSchemaVersion)
	}
	if manifest.Algorithm != "sha256" || len(manifest.Files) != len(observed) {
		return errors.New("installation manifest does not match archive contents")
	}
	var totalBytes int64
	declared := make(map[string]struct{}, len(manifest.Files))
	for _, record := range manifest.Files {
		actual, ok := observed[record.Name]
		if _, duplicate := declared[record.Name]; duplicate || !ok || actual != record {
			return fmt.Errorf("installation integrity check failed for %q", record.Name)
		}
		declared[record.Name] = struct{}{}
		totalBytes += record.Size
	}
	if totalBytes != manifest.TotalBytes {
		return errors.New("installation integrity byte count mismatch")
	}
	if _, ok := observed[installationSystemName]; !ok {
		return errors.New("installation archive has no system store")
	}
	referenced := make(map[string]struct{}, len(manifest.Accounts))
	logins := make(map[string]struct{}, len(manifest.Accounts))
	for _, entry := range manifest.Accounts {
		if entry.File != installationAccountPrefix+entry.ID+".tar.gz" || !installationAccountMember.MatchString(entry.File) || !account.SupportedEngine(entry.Engine) || entry.Login == "" {
			return fmt.Errorf("invalid account entry %q in installation manifest", entry.ID)
		}
		if _, ok := observed[entry.File]; !ok {
			return fmt.Errorf("account bundle %s is missing", entry.File)
		}
		_, duplicateFile := referenced[entry.File]
		_, duplicateLogin := logins[entry.Login]
		if duplicateFile || duplicateLogin {
			return fmt.Errorf("duplicate account %q in installation manifest", entry.Login)
		}
		referenced[entry.File], logins[entry.Login] = struct{}{}, struct{}{}
	}
	for name := range observed {
		if _, ok := referenced[name]; strings.HasPrefix(name, installationAccountPrefix) && !ok {
			return fmt.Errorf("account bundle %s is not listed in the manifest", name)
		}
	}
	return nil
}

// importAccounts rebuilds every account bundle under the root chosen by
// rootFor, checking that each bundle carries the identity the manifest names.
// Each account directory it creates is passed to created, if set.
func (s *stagedInstallation) importAccounts(ctx context.Context, rootFor func(InstallationAccount) string, keys account.KeyWrapper, created func(path string)) error {
	for _, entry := range s.manifest.Accounts {
		file, err := s.open(entry.File)
		if err != nil {
			return err
		}
		restored, err := account.ImportAccount(ctx, rootFor(entry), bufio.NewReader(file), entry.Engine, keys)
		_ = file.Close()
		if err != nil {
			return fmt.Errorf("account %s: %w", entry.Login, err)
		}
		if created != nil {
			created(restored.Path)
		}
		if restored.Manifest.ID != entry.ID || restored.Manifest.Login != entry.Login {
			return fmt.Errorf("account bundle %s does not contain account %s", entry.File, entry.Login)
		}
	}
	return nil
}

// ArchiveVerification is the non-mutating result for either archive kind.
// The embedded Verification describes the system store: the whole archive for
// kind "system", or the nested system.tar.gz for kind "installation".
type ArchiveVerification struct {
	Kind string `json:"kind"`
	*Verification
	Installation *InstallationManifest `json:"installation,omitempty"`
}

const (
	ArchiveKindSystem       = "system"
	ArchiveKindInstallation = "installation"
)

// DetectArchive reports which archive kind r holds without consuming it: a
// gzip stream is a system-store backup, anything else an installation archive.
// The returned reader must be used in place of r. An age-encrypted archive
// fails with archivecrypt.ErrIdentityRequired; decrypt it with
// archivecrypt.Open first.
func DetectArchive(r io.Reader) (string, io.Reader, error) {
	buffered := bufio.NewReader(r)
	magic, err := buffered.Peek(archivecrypt.HeaderLength)
	if len(magic) < 2 {
		if err == nil || errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return "", nil, fmt.Errorf("read archive: %w", err)
	}
	if archivecrypt.IsEncrypted(magic) {
		return "", nil, archivecrypt.ErrIdentityRequired
	}
	if magic[0] == 0x1f && magic[1] == 0x8b {
		return ArchiveKindSystem, buffered, nil
	}
	return ArchiveKindInstallation, buffered, nil
}

// VerifyArchive fully checks a system-store or installation archive without
// changing any live data. Installation verification is a restore drill: every
// member's digest is checked, config.toml is parsed and validated, the system
// backup is verified, and each account bundle is rebuilt in a scratch
// directory under tempDir and passed through the account integrity check.
func VerifyArchive(ctx context.Context, r io.Reader, tempDir string) (*ArchiveVerification, error) {
	kind, reader, err := DetectArchive(r)
	if err != nil {
		return nil, err
	}
	if kind == ArchiveKindSystem {
		verification, err := VerifyContext(ctx, reader)
		if err != nil {
			return nil, err
		}
		return &ArchiveVerification{Kind: kind, Verification: verification}, nil
	}
	staged, err := stageInstallation(ctx, reader, tempDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = staged.Close() }()
	if staged.manifest.HasConfig() {
		contents, err := os.ReadFile(staged.paths[installationConfigName])
		if err != nil {
			return nil, err
		}
		if _, err := config.Parse(filepath.Join(staged.dir, "data"), contents); err != nil {
			return nil, fmt.Errorf("archived configuration is invalid: %w", err)
		}
	}
	system, err := staged.open(installationSystemName)
	if err != nil {
		return nil, err
	}
	verification, err := VerifyContext(ctx, system)
	_ = system.Close()
	if err != nil {
		return nil, fmt.Errorf("system store: %w", err)
	}
	scratch := filepath.Join(staged.dir, "accounts")
	if err := staged.importAccounts(ctx, func(InstallationAccount) string { return scratch }, newArchiveKeys(ctx, staged, filepath.Join(staged.dir, "system-keys")), nil); err != nil {
		return nil, err
	}
	return &ArchiveVerification{Kind: kind, Verification: verification, Installation: &staged.manifest}, nil
}

// InstallationRestoreOptions controls RestoreInstallation.
type InstallationRestoreOptions struct {
	// Force allows a non-empty target. After the archive has been verified,
	// the data directory's contents and any account directories in the
	// configured account roots are deleted before restoring.
	Force bool
	// TempDir holds the extracted archive; empty stages inside the data
	// directory itself, so staging shares its filesystem and permissions.
	TempDir string
	// AccountRoots moves configured account storage roots, by root ID, to
	// new paths, for a host whose disk layout differs from the original.
	// The restored config.toml records the new paths. A relative path is
	// anchored at the data directory, as in config.toml.
	AccountRoots map[string]string
}

// RestoreInstallation rebuilds a stopped installation in dataDir from an
// installation archive. The archive is extracted and fully validated, and
// every reason to refuse is checked, before anything in dataDir changes. A
// failure after that point removes what the restore wrote: dataDir is left
// empty and the account directories it created are deleted, so the restore
// can be run again. A forced restore has already deleted the prior contents.
func RestoreInstallation(ctx context.Context, r io.Reader, dataDir string, options InstallationRestoreOptions) (_ *InstallationManifest, err error) {
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	empty, err := directoryEmpty(dataDir)
	if err != nil {
		return nil, err
	}
	if !empty && !options.Force {
		return nil, fmt.Errorf("%w: %s holds existing data; restore into an empty directory or pass --force to replace it", ErrTargetNotEmpty, dataDir)
	}
	kind, reader, err := DetectArchive(r)
	if err != nil {
		return nil, err
	}
	if kind != ArchiveKindInstallation {
		return nil, errors.New("this is a system-store-only backup; restore it through the online restore API, or use an installation archive")
	}
	tempDir := options.TempDir
	if tempDir == "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
		tempDir = dataDir
	}
	staged, err := stageInstallation(ctx, reader, tempDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = staged.Close() }()
	notStaging := func(name string) bool { return filepath.Join(dataDir, name) != staged.dir }
	// Everything that can refuse the restore is checked before the data
	// directory changes, so a refused restore can simply be run again.
	configContents, cfg, err := staged.restoredConfig(dataDir, options.AccountRoots)
	if err != nil {
		return nil, err
	}
	roots := account.RootsFromDefinitions(cfg.DataDir, cfg.AccountStorageRoots)
	isAccount := func(name string) bool { return strings.HasPrefix(name, "acc_") }
	if !options.Force {
		for _, root := range roots {
			if found, err := directoryHas(root.Path, isAccount); err != nil {
				return nil, err
			} else if found {
				return nil, fmt.Errorf("%w: account root %s already holds accounts; restore with --account-root %s=NEWPATH to place them elsewhere, or pass --force to replace them", ErrTargetNotEmpty, root.Path, root.ID)
			}
		}
	}
	if !empty {
		if err := ensureStoreReleased(dataDir); err != nil {
			return nil, err
		}
	}
	var createdAccounts []string
	defer func() {
		if err == nil {
			return
		}
		cleanup := clearDirectory(dataDir, notStaging)
		for _, path := range createdAccounts {
			cleanup = errors.Join(cleanup, os.RemoveAll(path))
		}
		if cleanup != nil {
			err = fmt.Errorf("%w (removing the partial restore also failed: %v; empty %s before running the restore again)", err, cleanup, dataDir)
			return
		}
		err = fmt.Errorf("%w; the partial restore was removed", err)
	}()
	if !empty {
		if err := clearDirectory(dataDir, notStaging); err != nil {
			return nil, err
		}
	}
	log.Info("restore: restoring installation", "data_dir", dataDir, "accounts", len(staged.manifest.Accounts))
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if configContents != nil {
		if err := os.WriteFile(config.FilePath(dataDir), configContents, 0o600); err != nil {
			return nil, fmt.Errorf("write configuration: %w", err)
		}
	}
	if _, err := config.Open(dataDir); err != nil {
		return nil, fmt.Errorf("open restored configuration: %w", err)
	}
	rootPaths := make(map[string]string, len(roots))
	for _, root := range roots {
		if options.Force {
			if err := clearDirectory(root.Path, isAccount); err != nil {
				return nil, err
			}
		}
		rootPaths[root.ID] = root.Path
	}
	keys, err := restoreSystemStore(ctx, cfg, staged)
	if err != nil {
		return nil, fmt.Errorf("restore system store: %w", err)
	}
	if err := staged.importAccounts(ctx, func(entry InstallationAccount) string {
		if path, ok := rootPaths[entry.RootID]; ok {
			return path
		}
		return rootPaths[cfg.PrimaryAccountRoot]
	}, keys, func(path string) { createdAccounts = append(createdAccounts, path) }); err != nil {
		return nil, err
	}
	log.Info("restore: installation restored", "data_dir", dataDir, "accounts", len(staged.manifest.Accounts))
	return &staged.manifest, nil
}

// restoredConfig returns the config.toml to write into dataDir (nil when the
// archive has none and defaults apply) and the configuration it describes,
// with account storage roots moved as requested. Nothing in dataDir changes.
func (s *stagedInstallation) restoredConfig(dataDir string, moves map[string]string) ([]byte, *config.Config, error) {
	var contents []byte
	if s.manifest.HasConfig() {
		var err error
		if contents, err = os.ReadFile(s.paths[installationConfigName]); err != nil {
			return nil, nil, err
		}
	}
	cfg, err := config.Parse(dataDir, contents)
	if err != nil {
		return nil, nil, fmt.Errorf("archived configuration is invalid: %w", err)
	}
	if len(moves) == 0 {
		return contents, cfg, nil
	}
	definitions := slices.Clone(cfg.AccountStorageRoots)
	pending := maps.Clone(moves)
	for i, definition := range definitions {
		id, _, _ := strings.Cut(definition, "=")
		id = strings.TrimSpace(id)
		if path, ok := pending[id]; ok {
			definitions[i] = id + "=" + path
			delete(pending, id)
		}
	}
	if len(pending) > 0 {
		unknown := slices.Sorted(maps.Keys(pending))
		return nil, nil, fmt.Errorf("account root %q is not configured in the archived config.toml (configured: %s)", unknown[0], strings.Join(cfg.AccountStorageRoots, ", "))
	}
	// The managed configuration service rewrites the one setting and keeps
	// the rest of the document, comments included. It runs on a scratch copy.
	scratch := filepath.Join(s.dir, "config")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, nil, err
	}
	if contents != nil {
		if err := os.WriteFile(config.FilePath(scratch), contents, 0o600); err != nil {
			return nil, nil, err
		}
	}
	service, err := config.Open(scratch)
	if err != nil {
		return nil, nil, fmt.Errorf("archived configuration is invalid: %w", err)
	}
	if _, err := service.Patch(service.Current().Revision, map[string]any{"account_storage_roots": definitions}); err != nil {
		return nil, nil, fmt.Errorf("move account roots: %w", err)
	}
	if contents, err = os.ReadFile(service.Path()); err != nil {
		return nil, nil, err
	}
	if cfg, err = config.Parse(dataDir, contents); err != nil {
		return nil, nil, fmt.Errorf("move account roots: %w", err)
	}
	return contents, cfg, nil
}

// restoreSystemStore restores the archived system store and returns its
// installation key ring, which encrypted account bundles need.
func restoreSystemStore(ctx context.Context, cfg *config.Config, staged *stagedInstallation) (account.KeyWrapper, error) {
	system, err := staged.open(installationSystemName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = system.Close() }()
	target, err := cfg.OpenStore()
	if err != nil {
		return nil, err
	}
	_, restoreErr := RestoreContext(ctx, target, system, Replace)
	var keys account.KeyWrapper
	if restoreErr == nil {
		keys, restoreErr = AccountKeys(ctx, target)
	}
	return keys, errors.Join(restoreErr, target.Close())
}

// ensureStoreReleased refuses to clear a data directory whose system store a
// running server still holds. Embedded engines lock their directory, so a
// failed open means another process owns it.
func ensureStoreReleased(dataDir string) error {
	contents, err := os.ReadFile(config.FilePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg, err := config.Parse(dataDir, contents)
	if err != nil {
		return nil // an unreadable configuration cannot belong to a running server
	}
	if _, err := os.Stat(cfg.StorePath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	existing, err := cfg.OpenStore()
	if err != nil {
		return fmt.Errorf("existing system store in %s cannot be opened (is the server still running? stop it first): %w", dataDir, err)
	}
	return existing.Close()
}

func directoryEmpty(path string) (bool, error) {
	found, err := directoryHas(path, func(string) bool { return true })
	return !found, err
}

func directoryHas(path string, match func(string) bool) (bool, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", path, err)
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool { return match(entry.Name()) }), nil
}

func clearDirectory(path string, match func(string) bool) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	for _, entry := range entries {
		if match(entry.Name()) {
			if err := os.RemoveAll(filepath.Join(path, entry.Name())); err != nil {
				return fmt.Errorf("clear %s: %w", path, err)
			}
		}
	}
	return nil
}
