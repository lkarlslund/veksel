package account

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/lkarlslund/veksel/pkg/keyring"
)

// ManagerOption configures NewManager and NewManagerWithRoots.
type ManagerOption func(*managerSettings)

type managerSettings struct {
	keys KeyWrapper
}

// WithKeyRing gives the manager the installation key ring that wraps account
// data-encryption keys. Without it encrypted accounts cannot be opened and
// encryption cannot be enabled.
func WithKeyRing(keys KeyWrapper) ManagerOption {
	return func(settings *managerSettings) { settings.keys = keys }
}

// EncryptionAvailable reports whether the manager holds a key ring.
func (m *Manager) EncryptionAvailable() bool { return m.keys != nil }

// SetEncryptionDefault controls whether newly created accounts are encrypted.
// Existing accounts change only through an explicit conversion.
func (m *Manager) SetEncryptionDefault(enabled bool) error {
	if enabled && m.keys == nil {
		return ErrEncryptionKeysUnavailable
	}
	m.encryptByDefault.Store(enabled)
	return nil
}

// EncryptionDefault reports whether new accounts are encrypted.
func (m *Manager) EncryptionDefault() bool { return m.encryptByDefault.Load() }

// DerivedEncrypted reports whether derived data about login, such as folder
// list projections stored outside the account directory, must be sealed.
func (m *Manager) DerivedEncrypted(login string) bool {
	entry, found := m.ByLogin(login)
	return found && entry.Manifest.Encrypted
}

// SealDerived encrypts derived data about login under the active
// generation's data-encryption key. A conversion changes the generation, so
// data sealed before it no longer opens and is rebuilt by its owner.
func (m *Manager) SealDerived(login string, aad, plaintext []byte) ([]byte, error) {
	generation, release, err := m.Acquire(login)
	if err != nil {
		return nil, err
	}
	defer release()
	if generation.key == nil {
		return nil, errors.New("account is not encrypted")
	}
	return generation.key.Seal(derivedAAD(generation.ID, aad), plaintext)
}

// OpenDerived decrypts data sealed by SealDerived.
func (m *Manager) OpenDerived(login string, aad, sealed []byte) ([]byte, error) {
	generation, release, err := m.Acquire(login)
	if err != nil {
		return nil, err
	}
	defer release()
	if generation.key == nil {
		return nil, errors.New("account is not encrypted")
	}
	return generation.key.Open(derivedAAD(generation.ID, aad), sealed)
}

func derivedAAD(generationID string, aad []byte) []byte {
	return append([]byte("veksel-derived-v1\x00"+generationID+"\x00"), aad...)
}

// AccountEncryption is one account's encryption-at-rest state.
type AccountEncryption struct {
	AccountID  string `json:"account_id"`
	Login      string `json:"login"`
	Encrypted  bool   `json:"encrypted"`
	Generation string `json:"generation"`
	// KeyID names the installation key version wrapping the active
	// generation's data-encryption key.
	KeyID string `json:"key_id,omitempty"`
	Error string `json:"error,omitempty"`
}

// EncryptionStatus summarizes encryption at rest without disclosing keys.
type EncryptionStatus struct {
	Available   bool                `json:"available"`
	Default     bool                `json:"default"`
	ActiveKeyID string              `json:"active_key_id,omitempty"`
	Encrypted   int                 `json:"encrypted"`
	Stale       int                 `json:"stale_wrapped"`
	Accounts    []AccountEncryption `json:"accounts"`
}

func (m *Manager) activeKeyID() string {
	if active, ok := m.keys.(interface{ ActiveKeyID() string }); ok {
		return active.ActiveKeyID()
	}
	return ""
}

// EncryptionStatus reads each active generation's key file.
func (m *Manager) EncryptionStatus() EncryptionStatus {
	status := EncryptionStatus{Available: m.keys != nil, Default: m.EncryptionDefault(), ActiveKeyID: m.activeKeyID(), Accounts: []AccountEncryption{}}
	for _, entry := range m.Entries() {
		account := AccountEncryption{AccountID: entry.Manifest.ID, Login: entry.Manifest.Login, Encrypted: entry.Manifest.Encrypted, Generation: entry.Manifest.ActiveGeneration}
		if entry.Manifest.Encrypted {
			status.Encrypted++
			file, found, err := readGenerationKey(filepath.Join(entry.Path, "generations", entry.Manifest.ActiveGeneration))
			switch {
			case err != nil:
				account.Error = err.Error()
			case !found:
				account.Error = "generation key file is missing"
			default:
				account.KeyID = keyring.SealedKeyID(file.WrappedKey)
				if status.ActiveKeyID != "" && account.KeyID != status.ActiveKeyID {
					status.Stale++
				}
			}
		}
		status.Accounts = append(status.Accounts, account)
	}
	return status
}

// RewrapReport is the outcome of RewrapKeys.
type RewrapReport struct {
	ActiveKeyID string   `json:"active_key_id"`
	Generations int      `json:"generations"`
	Rewrapped   int      `json:"rewrapped"`
	Failures    []string `json:"failures,omitempty"`
}

// RewrapKeys reseals the data-encryption key of every encrypted generation,
// including retained rollback generations, under the active installation key.
// Encrypted data is untouched, so this is cheap and safe online; it is the
// account half of an installation key rotation. Each file is replaced
// atomically, so an interrupted run leaves keys under a retired but still
// readable installation key and can simply be repeated.
func (m *Manager) RewrapKeys(ctx context.Context) (RewrapReport, error) {
	if m.keys == nil {
		return RewrapReport{}, ErrEncryptionKeysUnavailable
	}
	report := RewrapReport{ActiveKeyID: m.activeKeyID()}
	var failures error
	for _, entry := range m.Entries() {
		generations := filepath.Join(entry.Path, "generations")
		dirs, err := os.ReadDir(generations)
		if err != nil {
			report.Failures = append(report.Failures, entry.Manifest.Login+": "+err.Error())
			failures = errors.Join(failures, err)
			continue
		}
		for _, dir := range dirs {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			if !dir.IsDir() || !generationPattern.MatchString(dir.Name()) {
				continue
			}
			path := filepath.Join(generations, dir.Name())
			if _, found, _ := readGenerationKey(path); !found {
				continue
			}
			report.Generations++
			rewrapped, err := rewrapGenerationKey(path, report.ActiveKeyID, m.keys)
			if err != nil {
				report.Failures = append(report.Failures, entry.Manifest.Login+"/"+dir.Name()+": "+err.Error())
				failures = errors.Join(failures, err)
				continue
			}
			if rewrapped {
				report.Rewrapped++
			}
		}
	}
	return report, failures
}
