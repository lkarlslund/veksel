package account

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

// RootsFromDefinitions resolves configured "id=path" account storage roots.
// Relative paths are anchored at dataDir, matching configuration validation.
func RootsFromDefinitions(dataDir string, definitions []string) []Root {
	roots := make([]Root, 0, len(definitions))
	for _, definition := range definitions {
		id, rootPath, _ := strings.Cut(definition, "=")
		rootPath = strings.TrimSpace(rootPath)
		if !filepath.IsAbs(rootPath) {
			rootPath = filepath.Join(dataDir, rootPath)
		}
		roots = append(roots, Root{ID: strings.TrimSpace(id), Path: filepath.Clean(rootPath)})
	}
	return roots
}

// CatalogExporter exports accounts straight from discovered directories
// without a Manager. It is meant for offline tools: unlike NewManager it never
// runs interrupted-operation recovery, and each export opens the active
// generation exclusively, so it fails while a server holds the account open.
type CatalogExporter struct {
	*Catalog
	// Keys is the installation key ring; it is required for encrypted
	// accounts, whose bundles stay encrypted.
	Keys KeyWrapper
}

// Export writes the active generation of login as a logical bundle.
func (c CatalogExporter) Export(ctx context.Context, login string, destination io.Writer) error {
	entry, found := c.ByLogin(login)
	if !found {
		return store.ErrNotFound
	}
	generation, err := openActive(entry, c.Keys)
	if err != nil {
		return fmt.Errorf("open account %s: %w", login, err)
	}
	return errors.Join(ExportBundle(ctx, entry, generation, destination), generation.Close())
}

// ImportAccount recreates one account from a logical bundle under root. The
// account keeps its identity and gets a fresh generation on engine. Client
// synchronization state is rebased so clients resynchronize; see
// rebaseRestoredSyncState. It is staged in a hidden directory and only
// becomes discoverable after the integrity check passes; an existing account
// directory with the same ID is never overwritten. An encrypted bundle needs
// keys to open and restores as an encrypted account under a new
// data-encryption key.
func ImportAccount(ctx context.Context, root string, source io.Reader, engine store.Backend, keys KeyWrapper) (Entry, error) {
	source, encrypted, err := openBundle(source, keys)
	if err != nil {
		return Entry{}, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Entry{}, fmt.Errorf("create account root: %w", err)
	}
	staging, err := os.MkdirTemp(root, ".import-")
	if err != nil {
		return Entry{}, fmt.Errorf("create account staging directory: %w", err)
	}
	activated := false
	defer func() {
		if !activated {
			_ = os.RemoveAll(staging)
		}
	}()
	generationID, err := NewGenerationID()
	if err != nil {
		return Entry{}, err
	}
	target, err := createGeneration(staging, generationID, engine, keys, encrypted)
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = target.Close() }()
	manifest, err := ImportBundle(ctx, source, target)
	if err != nil {
		return Entry{}, err
	}
	if err := rebaseRestoredSyncState(ctx, target, time.Now()); err != nil {
		return Entry{}, err
	}
	manifest.Engine = engine
	manifest.Encrypted = encrypted
	manifest.ActiveGeneration = generationID
	manifest.ConversionID = ""
	if manifest.State != StateDisabled {
		manifest.State = StateReady
	}
	manifest.UpdatedAt = time.Now().UTC()
	finalPath := filepath.Join(root, manifest.ID)
	entry := Entry{Manifest: manifest, Path: finalPath}
	report, err := CheckGeneration(ctx, entry, target, false)
	if err != nil {
		return Entry{}, err
	}
	if !report.Healthy {
		return Entry{}, fmt.Errorf("restored account %s failed integrity verification", manifest.Login)
	}
	if err := target.Close(); err != nil {
		return Entry{}, err
	}
	target = nil
	if err := WriteManifest(filepath.Join(staging, ManifestFilename), manifest); err != nil {
		return Entry{}, err
	}
	if _, err := os.Lstat(finalPath); err == nil {
		return Entry{}, fmt.Errorf("account directory %s already exists", finalPath)
	}
	if err := os.Rename(staging, finalPath); err != nil {
		return Entry{}, fmt.Errorf("activate restored account: %w", err)
	}
	activated = true
	return entry, nil
}
