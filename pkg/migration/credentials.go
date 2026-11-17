package migration

import (
	"context"

	"github.com/lkarlslund/veksel/pkg/keyring"
)

const (
	credentialEnvelopeType = keyring.EnvelopeType
	credentialEnvelopeV1   = keyring.EnvelopeVersion
)

type credentialEnvelope = keyring.Envelope

// CredentialKeyStatus exposes rotation evidence without disclosing key bytes.
type CredentialKeyStatus = keyring.Status

func (s *Store) sealCredential(jobID, password string) ([]byte, error) {
	return s.keys.Seal(credentialAAD(jobID), []byte(password))
}

func (s *Store) openCredential(jobID string, data []byte) (string, bool, error) {
	if !keyring.IsEnvelope(data) {
		// Credentials written before encrypted envelopes were introduced are
		// upgraded after the first successful read.
		return string(data), true, nil
	}
	plaintext, err := s.keys.Open(credentialAAD(jobID), data)
	return string(plaintext), false, err
}

func credentialAAD(jobID string) []byte { return []byte("veksel-sync-credential:" + jobID) }

// SealSecret protects another subsystem's secret, such as a TOTP seed, with
// the installation key ring. purpose and id are bound as associated data;
// OpenSecret must be given the same values. Rotation keeps retired keys, so
// sealed secrets stay readable after RotateCredentialKey.
func (s *Store) SealSecret(purpose, id string, plaintext []byte) ([]byte, error) {
	return s.keys.SealSecret(purpose, id, plaintext)
}

// OpenSecret decrypts a secret sealed by SealSecret.
func (s *Store) OpenSecret(purpose, id string, sealed []byte) ([]byte, error) {
	return s.keys.OpenSecret(purpose, id, sealed)
}

// KeyRing returns the shared installation key ring.
func (s *Store) KeyRing() *keyring.Ring { return s.keys }

// CredentialKeyStatus returns non-secret evidence for administration and tests.
func (s *Store) CredentialKeyStatus() CredentialKeyStatus { return s.keys.Status() }

// RotateCredentialKey creates a new active installation key and rewraps every
// stored sync credential. Old keys remain readable so an interrupted rotation
// is safe. Other owners of sealed data rewrap their own envelopes.
func (s *Store) RotateCredentialKey(ctx context.Context) (CredentialKeyStatus, error) {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()
	status, err := s.keys.Rotate(ctx)
	if err != nil {
		return status, err
	}
	ids, err := s.backend.List(ctx, credentialNamespace)
	if err != nil {
		return status, err
	}
	for _, id := range ids {
		data, err := s.backend.Get(ctx, credentialNamespace, id)
		if err != nil {
			return status, err
		}
		password, _, err := s.openCredential(id, data)
		if err != nil {
			return status, err
		}
		sealed, err := s.sealCredential(id, password)
		if err != nil {
			return status, err
		}
		if err := s.backend.Set(ctx, credentialNamespace, id, sealed); err != nil {
			return status, err
		}
	}
	return status, nil
}
