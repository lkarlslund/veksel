// Package account owns account identity, discovery, lifecycle, and storage generations.
package account

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	ManifestFilename     = "manifest.json"
	CurrentSchemaVersion = 1
	maxManifestSize      = 1 << 20
)

var (
	accountIDPattern  = regexp.MustCompile(`^acc_[0-9a-f]{32}$`)
	generationPattern = regexp.MustCompile(`^gen_[0-9a-f]{32}$`)
)

// State is the externally visible account lifecycle state.
type State string

const (
	StateReady       State = "ready"
	StateDisabled    State = "disabled"
	StateConverting  State = "converting"
	StateUnavailable State = "unavailable"
)

// Manifest is the small backend-independent authority used to discover an account.
type Manifest struct {
	SchemaVersion  int           `json:"schema_version"`
	ID             string        `json:"account_id"`
	Login          string        `json:"login"`
	DisplayName    string        `json:"display_name,omitempty"`
	PrimaryAddress string        `json:"primary_address,omitempty"`
	Addresses      []string      `json:"addresses,omitempty"`
	Engine         store.Backend `json:"engine"`
	// Encrypted records that the active generation is encrypted at rest, so
	// a missing generation key file is detected instead of read as plaintext.
	Encrypted        bool      `json:"encrypted,omitempty"`
	ActiveGeneration string    `json:"active_generation"`
	State            State     `json:"state"`
	ConversionID     string    `json:"conversion_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// NewID returns a cryptographically random opaque account ID.
func NewID() (string, error) {
	return randomID("acc")
}

// NewGenerationID returns a cryptographically random opaque generation ID.
func NewGenerationID() (string, error) {
	return randomID("gen")
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate %s ID: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

// NewManifest builds a normalized manifest for a new account.
func NewManifest(login, displayName, primaryAddress string, addresses []string, engine store.Backend, now time.Time) (Manifest, error) {
	id, err := NewID()
	if err != nil {
		return Manifest{}, err
	}
	generation, err := NewGenerationID()
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		SchemaVersion:    CurrentSchemaVersion,
		ID:               id,
		Login:            normalizeLogin(login),
		DisplayName:      strings.TrimSpace(displayName),
		PrimaryAddress:   normalizeAddress(primaryAddress),
		Addresses:        normalizeAddresses(addresses),
		Engine:           engine,
		ActiveGeneration: generation,
		State:            StateReady,
		CreatedAt:        now.UTC(),
		UpdatedAt:        now.UTC(),
	}
	if manifest.PrimaryAddress != "" && !slices.Contains(manifest.Addresses, manifest.PrimaryAddress) {
		manifest.Addresses = append(manifest.Addresses, manifest.PrimaryAddress)
		slices.Sort(manifest.Addresses)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate checks all identity, state, and generation invariants.
func (m Manifest) Validate() error {
	if m.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported account manifest schema %d", m.SchemaVersion)
	}
	if !accountIDPattern.MatchString(m.ID) {
		return fmt.Errorf("invalid account ID %q", m.ID)
	}
	if m.Login == "" || m.Login != normalizeLogin(m.Login) || strings.ContainsAny(m.Login, "\x00/\\") {
		return fmt.Errorf("invalid normalized account login %q", m.Login)
	}
	if !generationPattern.MatchString(m.ActiveGeneration) {
		return fmt.Errorf("invalid active generation %q", m.ActiveGeneration)
	}
	if !SupportedEngine(m.Engine) {
		return fmt.Errorf("unsupported account engine %q", m.Engine)
	}
	switch m.State {
	case StateReady, StateDisabled, StateUnavailable:
		if m.ConversionID != "" {
			return errors.New("conversion ID is only valid while converting")
		}
	case StateConverting:
		if strings.TrimSpace(m.ConversionID) == "" {
			return errors.New("converting account requires a conversion ID")
		}
	default:
		return fmt.Errorf("invalid account state %q", m.State)
	}
	if m.CreatedAt.IsZero() || m.UpdatedAt.IsZero() || m.UpdatedAt.Before(m.CreatedAt) {
		return errors.New("invalid account manifest timestamps")
	}
	seen := make(map[string]struct{}, len(m.Addresses))
	for _, address := range m.Addresses {
		if address == "" || address != normalizeAddress(address) || !validAddress(address) {
			return fmt.Errorf("invalid normalized account address %q", address)
		}
		if _, duplicate := seen[address]; duplicate {
			return fmt.Errorf("duplicate account address %q", address)
		}
		seen[address] = struct{}{}
	}
	if m.PrimaryAddress != "" {
		if m.PrimaryAddress != normalizeAddress(m.PrimaryAddress) || !validAddress(m.PrimaryAddress) {
			return fmt.Errorf("invalid primary address %q", m.PrimaryAddress)
		}
		if _, found := seen[m.PrimaryAddress]; !found {
			return errors.New("primary address must be present in addresses")
		}
	}
	return nil
}

// ReadManifest reads and strictly validates one manifest file.
func ReadManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open account manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestSize+1))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode account manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Manifest{}, errors.New("account manifest contains trailing data")
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// WriteManifest atomically replaces one manifest and flushes its directory.
func WriteManifest(path string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account manifest: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create account directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace symlinked account manifest")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect account manifest: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary account manifest: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	failure := func(cause error) error {
		return errors.Join(cause, temporary.Close())
	}
	if err := temporary.Chmod(0o600); err != nil {
		return failure(fmt.Errorf("protect temporary account manifest: %w", err))
	}
	if _, err := io.Copy(temporary, bytes.NewReader(data)); err != nil {
		return failure(fmt.Errorf("write temporary account manifest: %w", err))
	}
	if err := temporary.Sync(); err != nil {
		return failure(fmt.Errorf("sync temporary account manifest: %w", err))
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary account manifest: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate account manifest: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open account directory for sync: %w", err)
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func normalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func normalizeAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

func normalizeAddresses(addresses []string) []string {
	unique := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		normalized := normalizeAddress(address)
		if normalized != "" {
			unique[normalized] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	slices.Sort(result)
	return result
}

func validAddress(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value && strings.Contains(value, "@")
}
