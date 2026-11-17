package account

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lkarlslund/veksel/pkg/dek"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/objectstore"
	"github.com/lkarlslund/veksel/pkg/store"
	"github.com/lkarlslund/veksel/pkg/store/badgerstore"
	"github.com/lkarlslund/veksel/pkg/store/cryptstore"
	"github.com/lkarlslund/veksel/pkg/store/pebblestore"
)

// ProductionEngines is the complete list of engines offered in API and UI.
var ProductionEngines = []store.Backend{store.BackendPebble, store.BackendBadger}

// SupportedEngine reports whether an engine is supported for live account data.
func SupportedEngine(engine store.Backend) bool {
	return engine == store.BackendPebble || engine == store.BackendBadger
}

// Generation is one open physical account generation.
type Generation struct {
	ID      string
	Path    string
	Engine  store.Backend
	Index   store.Store
	Objects *objectstore.Store
	// Encrypted generations seal every index value, protected key names,
	// and object payload with their own data-encryption key. KeyID names
	// the installation key version wrapping it.
	Encrypted bool
	KeyID     string
	keys      KeyWrapper
	key       *dek.Key
}

// OpenGeneration opens an existing plaintext account generation. Encrypted
// generations are opened through a Manager, which holds the key ring.
func OpenGeneration(accountPath, generationID string, engine store.Backend) (*Generation, error) {
	return openGenerationWith(accountPath, generationID, engine, nil)
}

func openGenerationWith(accountPath, generationID string, engine store.Backend, keys KeyWrapper) (*Generation, error) {
	if !generationPattern.MatchString(generationID) {
		return nil, fmt.Errorf("invalid generation ID %q", generationID)
	}
	path := filepath.Join(accountPath, "generations", generationID)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("open account generation: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("account generation is not a directory")
	}
	key, keyID, err := loadGenerationKey(path, keys)
	if err != nil {
		return nil, err
	}
	return openGeneration(path, generationID, engine, key, keyID, keys)
}

// CreateGeneration creates and opens a new empty plaintext account generation.
func CreateGeneration(accountPath, generationID string, engine store.Backend) (*Generation, error) {
	return createGeneration(accountPath, generationID, engine, nil, false)
}

// createGeneration creates a generation, encrypted under a fresh DEK wrapped
// by keys when encrypted is set.
func createGeneration(accountPath, generationID string, engine store.Backend, keys KeyWrapper, encrypted bool) (*Generation, error) {
	if !generationPattern.MatchString(generationID) {
		return nil, fmt.Errorf("invalid generation ID %q", generationID)
	}
	if !SupportedEngine(engine) {
		return nil, fmt.Errorf("unsupported account engine %q", engine)
	}
	if encrypted && keys == nil {
		return nil, ErrEncryptionKeysUnavailable
	}
	path := filepath.Join(accountPath, "generations", generationID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create generations directory: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("create account generation: %w", err)
	}
	var key *dek.Key
	var keyID string
	if encrypted {
		var err error
		if key, keyID, err = createGenerationKey(path, generationID, keys); err != nil {
			return nil, errors.Join(err, os.RemoveAll(path))
		}
	}
	generation, err := openGeneration(path, generationID, engine, key, keyID, keys)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	return generation, nil
}

func openGeneration(path, generationID string, engine store.Backend, key *dek.Key, keyID string, keys KeyWrapper) (*Generation, error) {
	indexPath := filepath.Join(path, "index")
	if err := os.MkdirAll(indexPath, 0o700); err != nil {
		return nil, fmt.Errorf("create account index directory: %w", err)
	}
	var index store.Store
	var err error
	switch engine {
	case store.BackendPebble:
		index, err = pebblestore.New(indexPath)
	case store.BackendBadger:
		index, err = badgerstore.New(indexPath)
	default:
		return nil, fmt.Errorf("unsupported account engine %q", engine)
	}
	if err != nil {
		return nil, err
	}
	if key != nil {
		encrypted, wrapErr := cryptstore.New(index, key, model.ProtectedKeyFamilies())
		if wrapErr != nil {
			return nil, errors.Join(wrapErr, index.Close())
		}
		index = encrypted
	}
	objects, err := objectstore.Open(filepath.Join(path, "objects", "segments"), objectstore.Options{SyncWrites: true, Key: key})
	if err != nil {
		return nil, errors.Join(err, index.Close())
	}
	return &Generation{ID: generationID, Path: path, Engine: engine, Index: index, Objects: objects, Encrypted: key != nil, KeyID: keyID, keys: keys, key: key}, nil
}

// Close flushes and releases all generation resources.
func (g *Generation) Close() error {
	if g == nil {
		return nil
	}
	if g.Objects == nil && g.Index == nil {
		return nil
	}
	if g.Objects == nil {
		return g.Index.Close()
	}
	if g.Index == nil {
		return g.Objects.Close()
	}
	return errors.Join(g.Objects.Close(), g.Index.Close())
}
