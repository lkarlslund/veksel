package account

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/lkarlslund/veksel/pkg/dek"
	"github.com/lkarlslund/veksel/pkg/keyring"
)

// KeyWrapper seals and opens data-encryption keys with the installation key
// ring. *keyring.Ring satisfies it.
type KeyWrapper interface {
	SealSecret(purpose, id string, plaintext []byte) ([]byte, error)
	OpenSecret(purpose, id string, sealed []byte) ([]byte, error)
}

const (
	// EncryptionFilename holds a generation's wrapped data-encryption key.
	EncryptionFilename  = "encryption.json"
	encryptionVersion   = 1
	encryptionAlgorithm = "xchacha20-poly1305/hmac-siv"
	dekPurpose          = "account-dek"
	bundleKeyPurpose    = "account-bundle"
	encryptedBundleMark = "VEKSEL-ENCRYPTED-BUNDLE-1\n"
	maxBundleHeader     = 64 << 10
)

// ErrEncryptionKeysUnavailable reports an encrypted account opened without
// access to the installation key ring.
var ErrEncryptionKeysUnavailable = errors.New("account is encrypted and the installation key ring is unavailable")

// generationKeyFile is the durable form of a generation's wrapped DEK. The
// wrapping binds the generation ID, so a key file copied to another
// generation does not open.
type generationKeyFile struct {
	Version     int             `json:"version"`
	Algorithm   string          `json:"algorithm"`
	Generation  string          `json:"generation"`
	WrappedKey  json.RawMessage `json:"wrapped_key"`
	CreatedAt   time.Time       `json:"created_at"`
	RewrappedAt *time.Time      `json:"rewrapped_at,omitzero"`
}

func generationKeyPath(generationPath string) string {
	return filepath.Join(generationPath, EncryptionFilename)
}

// createGenerationKey generates, wraps, and durably records a fresh DEK.
func createGenerationKey(generationPath, generationID string, keys KeyWrapper) (*dek.Key, string, error) {
	if keys == nil {
		return nil, "", ErrEncryptionKeysUnavailable
	}
	raw, err := dek.Generate()
	if err != nil {
		return nil, "", err
	}
	wrapped, err := keys.SealSecret(dekPurpose, generationID, raw)
	if err != nil {
		return nil, "", fmt.Errorf("wrap account data-encryption key: %w", err)
	}
	file := generationKeyFile{Version: encryptionVersion, Algorithm: encryptionAlgorithm, Generation: generationID, WrappedKey: wrapped, CreatedAt: time.Now().UTC()}
	if err := writeGenerationKey(generationPath, file); err != nil {
		return nil, "", err
	}
	key, err := dek.New(raw)
	return key, keyring.SealedKeyID(wrapped), err
}

func readGenerationKey(generationPath string) (generationKeyFile, bool, error) {
	data, err := os.ReadFile(generationKeyPath(generationPath))
	if errors.Is(err, os.ErrNotExist) {
		return generationKeyFile{}, false, nil
	}
	if err != nil {
		return generationKeyFile{}, false, fmt.Errorf("read account encryption key: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file generationKeyFile
	if err := decoder.Decode(&file); err != nil {
		return generationKeyFile{}, false, fmt.Errorf("decode account encryption key: %w", err)
	}
	if file.Version != encryptionVersion || file.Algorithm != encryptionAlgorithm || file.Generation != filepath.Base(generationPath) {
		return generationKeyFile{}, false, errors.New("account encryption key file does not match its generation")
	}
	return file, true, nil
}

// loadGenerationKey returns the generation's DEK, or nil for a plaintext
// generation.
func loadGenerationKey(generationPath string, keys KeyWrapper) (*dek.Key, string, error) {
	file, found, err := readGenerationKey(generationPath)
	if err != nil || !found {
		return nil, "", err
	}
	if keys == nil {
		return nil, "", ErrEncryptionKeysUnavailable
	}
	raw, err := keys.OpenSecret(dekPurpose, file.Generation, file.WrappedKey)
	if err != nil {
		return nil, "", fmt.Errorf("unwrap account data-encryption key: %w", err)
	}
	key, err := dek.New(raw)
	return key, keyring.SealedKeyID(file.WrappedKey), err
}

// rewrapGenerationKey reseals a generation's DEK under the active installation
// key without touching the encrypted data. It reports whether it rewrote the
// file; a generation already under activeKeyID is left alone.
func rewrapGenerationKey(generationPath, activeKeyID string, keys KeyWrapper) (bool, error) {
	file, found, err := readGenerationKey(generationPath)
	if err != nil || !found || keyring.SealedKeyID(file.WrappedKey) == activeKeyID {
		return false, err
	}
	raw, err := keys.OpenSecret(dekPurpose, file.Generation, file.WrappedKey)
	if err != nil {
		return false, fmt.Errorf("unwrap account data-encryption key: %w", err)
	}
	if file.WrappedKey, err = keys.SealSecret(dekPurpose, file.Generation, raw); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	file.RewrappedAt = &now
	return true, writeGenerationKey(generationPath, file)
}

func writeGenerationKey(generationPath string, file generationKeyFile) error {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(generationKeyPath(generationPath), append(data, '\n'))
}

// writeFileAtomic replaces path with data through a synced temporary file
// and a synced directory.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Chmod(0o600); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

// encryptedBundleHeader precedes the ciphertext of an encrypted bundle. The
// bundle key is random per export and wrapped by the installation key ring,
// so the bundle restores only where that key ring is available.
type encryptedBundleHeader struct {
	Version    int             `json:"version"`
	BundleID   string          `json:"bundle_id"`
	AccountID  string          `json:"account_id"`
	WrappedKey json.RawMessage `json:"wrapped_key"`
}

func bundleAAD(header encryptedBundleHeader) []byte {
	return []byte("veksel-bundle-v1\x00" + header.BundleID + "\x00" + header.AccountID)
}

// sealBundle writes an encrypted bundle header to destination and returns
// the writer for the plaintext bundle. Closing it writes the final chunk.
func sealBundle(destination io.Writer, accountID string, keys KeyWrapper) (io.WriteCloser, error) {
	if keys == nil {
		return nil, ErrEncryptionKeysUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	raw, err := dek.Generate()
	if err != nil {
		return nil, err
	}
	header := encryptedBundleHeader{Version: 1, BundleID: hex.EncodeToString(id[:]), AccountID: accountID}
	if header.WrappedKey, err = keys.SealSecret(bundleKeyPurpose, header.BundleID, raw); err != nil {
		return nil, err
	}
	key, err := dek.New(raw)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(destination, encryptedBundleMark+string(encoded)+"\n"); err != nil {
		return nil, err
	}
	return key.NewSealingWriter(destination, bundleAAD(header)), nil
}

// openBundle returns the plaintext bundle stream of source and whether it
// was encrypted. A plaintext bundle passes through unchanged.
func openBundle(source io.Reader, keys KeyWrapper) (io.Reader, bool, error) {
	buffered := bufio.NewReader(source)
	mark, err := buffered.Peek(len(encryptedBundleMark))
	if err != nil || string(mark) != encryptedBundleMark {
		return buffered, false, nil
	}
	if _, err := buffered.Discard(len(encryptedBundleMark)); err != nil {
		return nil, true, err
	}
	line, err := buffered.ReadSlice('\n')
	if err != nil || len(line) > maxBundleHeader {
		return nil, true, errors.New("invalid encrypted account bundle header")
	}
	var header encryptedBundleHeader
	if err := json.Unmarshal(line, &header); err != nil || header.Version != 1 || header.BundleID == "" {
		return nil, true, errors.New("invalid encrypted account bundle header")
	}
	if keys == nil {
		return nil, true, ErrEncryptionKeysUnavailable
	}
	raw, err := keys.OpenSecret(bundleKeyPurpose, header.BundleID, header.WrappedKey)
	if err != nil {
		return nil, true, fmt.Errorf("unwrap account bundle key: %w", err)
	}
	key, err := dek.New(raw)
	if err != nil {
		return nil, true, err
	}
	return key.NewOpeningReader(buffered, bundleAAD(header)), true, nil
}
