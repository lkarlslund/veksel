package model

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/store"
)

const (
	AppProtocolIMAP        = "imap"
	AppProtocolSMTP        = "smtp"
	AppProtocolPOP3        = "pop3"
	AppProtocolDAV         = "dav"
	AppProtocolJMAP        = "jmap"
	AppProtocolManageSieve = "managesieve"
	AppProtocolEWS         = "ews"
	AppProtocolEAS         = "eas"
)

var (
	ErrAppPasswordRevoked = errors.New("application password is revoked")
	ErrAppPasswordChanged = errors.New("application password changed during authentication")
	appProtocols          = []string{AppProtocolIMAP, AppProtocolSMTP, AppProtocolPOP3, AppProtocolDAV, AppProtocolJMAP, AppProtocolManageSieve, AppProtocolEWS, AppProtocolEAS}
)

const appPasswordRecordPrefix = "record:"

// SupportedAppProtocols returns the stable protocol-scope catalog.
func SupportedAppProtocols() []string { return append([]string(nil), appProtocols...) }

// IsSupportedAppProtocol reports whether protocol is a valid credential scope.
func IsSupportedAppProtocol(protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	for _, supported := range appProtocols {
		if supported == protocol {
			return true
		}
	}
	return false
}

// AppPasswordStore owns application-password lifecycle and authentication.
type AppPasswordStore struct{ ts *TypedStore }

func NewAppPasswordStore(ts *TypedStore) *AppPasswordStore { return &AppPasswordStore{ts: ts} }

func appPasswordUserPrefix(userID string) string {
	digest := sha256.Sum256([]byte(normalizeID(userID)))
	return "user:" + hex.EncodeToString(digest[:]) + ":"
}

func normalizeAppProtocols(protocols []string) ([]string, error) {
	allowed := make(map[string]struct{}, len(appProtocols))
	for _, protocol := range appProtocols {
		allowed[protocol] = struct{}{}
	}
	seen := make(map[string]struct{}, len(protocols))
	result := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if _, ok := allowed[protocol]; !ok {
			return nil, fmt.Errorf("unsupported application-password protocol %q", protocol)
		}
		if _, exists := seen[protocol]; exists {
			continue
		}
		seen[protocol] = struct{}{}
		result = append(result, protocol)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one application-password protocol is required")
	}
	sort.Strings(result)
	return result, nil
}

func newAppPasswordSecret() (plain, hash, prefix string, err error) {
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return "", "", "", err
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random))
	plain = "veksel-app-" + encoded
	hash, err = auth.HashPassword(plain)
	if err != nil {
		return "", "", "", err
	}
	return plain, hash, plain[:14], nil
}

func (aps *AppPasswordStore) Create(ctx context.Context, userID, name string, protocols []string) (*AppPassword, string, error) {
	userID, name = normalizeID(userID), strings.TrimSpace(name)
	if userID == "" || name == "" || len(name) > 200 {
		return nil, "", errors.New("account and a name of at most 200 characters are required")
	}
	if _, err := aps.ts.UserStore().RequireInteractive(ctx, userID); err != nil {
		return nil, "", fmt.Errorf("application-password account: %w", err)
	}
	normalized, err := normalizeAppProtocols(protocols)
	if err != nil {
		return nil, "", err
	}
	plain, hash, prefix, err := newAppPasswordSecret()
	if err != nil {
		return nil, "", err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", err
	}
	record := &AppPassword{ID: hex.EncodeToString(idBytes), UserID: userID, Name: name, SecretHash: hash, SecretPrefix: prefix, Protocols: normalized, CreatedAt: time.Now().UTC()}
	err = store.Batch(ctx, aps.ts.Store(), func(batchCtx context.Context) error {
		if err := aps.ts.Put(batchCtx, NSAppPasswords, appPasswordRecordPrefix+record.ID, record); err != nil {
			return err
		}
		return aps.ts.Put(batchCtx, NSAppPasswords, appPasswordUserPrefix(userID)+record.ID, record.ID)
	})
	if err != nil {
		return nil, "", err
	}
	return cloneAppPassword(record), plain, nil
}

func cloneAppPassword(record *AppPassword) *AppPassword {
	if record == nil {
		return nil
	}
	copy := *record
	copy.Protocols = append([]string(nil), record.Protocols...)
	return &copy
}

func (aps *AppPasswordStore) Get(ctx context.Context, id string) (*AppPassword, error) {
	var record AppPassword
	if err := aps.ts.Get(ctx, NSAppPasswords, appPasswordRecordPrefix+strings.TrimSpace(id), &record); err != nil {
		return nil, err
	}
	return cloneAppPassword(&record), nil
}

func (aps *AppPasswordStore) ListByUser(ctx context.Context, userID string) ([]AppPassword, error) {
	keys, err := aps.ts.Scan(ctx, NSAppPasswords, appPasswordUserPrefix(userID))
	if err != nil {
		return nil, err
	}
	result := make([]AppPassword, 0, len(keys))
	for _, key := range keys {
		id := strings.TrimPrefix(key, appPasswordUserPrefix(userID))
		record, getErr := aps.Get(ctx, id)
		if errors.Is(getErr, store.ErrNotFound) || (getErr == nil && record.Revoked) {
			continue
		}
		if getErr != nil {
			return nil, getErr
		}
		result = append(result, *record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (aps *AppPasswordStore) Rotate(ctx context.Context, id string) (*AppPassword, string, error) {
	plain, hash, prefix, err := newAppPasswordSecret()
	if err != nil {
		return nil, "", err
	}
	var result *AppPassword
	err = store.Batch(ctx, aps.ts.Store(), func(batchCtx context.Context) error {
		record, err := aps.Get(batchCtx, id)
		if err != nil {
			return err
		}
		if record.Revoked {
			return ErrAppPasswordRevoked
		}
		record.SecretHash, record.SecretPrefix = hash, prefix
		record.LastUsedAt, record.LastProtocol = time.Time{}, ""
		record.RotatedAt, record.RotationCount = time.Now().UTC(), record.RotationCount+1
		if err := aps.ts.Set(batchCtx, NSAppPasswords, appPasswordRecordPrefix+record.ID, record); err != nil {
			return err
		}
		result = cloneAppPassword(record)
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return result, plain, nil
}

func (aps *AppPasswordStore) Revoke(ctx context.Context, id string) error {
	return store.Batch(ctx, aps.ts.Store(), func(batchCtx context.Context) error {
		record, err := aps.Get(batchCtx, id)
		if err != nil {
			return err
		}
		if record.Revoked {
			return nil
		}
		record.Revoked, record.RevokedAt = true, time.Now().UTC()
		return aps.ts.Set(batchCtx, NSAppPasswords, appPasswordRecordPrefix+record.ID, record)
	})
}

func appPasswordAllows(record *AppPassword, protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	for _, allowed := range record.Protocols {
		if allowed == protocol {
			return true
		}
	}
	return false
}

// Authenticate verifies an active credential for exactly one protocol and
// atomically records its use. A rotation/revocation racing the bcrypt check
// causes authentication to fail instead of restoring stale credential state.
func (aps *AppPasswordStore) Authenticate(ctx context.Context, userID, secret, protocol string) (*AppPassword, error) {
	if _, err := normalizeAppProtocols([]string{protocol}); err != nil {
		return nil, err
	}
	if _, err := aps.ts.UserStore().RequireInteractive(ctx, userID); err != nil {
		return nil, err
	}
	prefix := secret
	if len(prefix) > 14 {
		prefix = prefix[:14]
	}
	records, err := aps.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for index := range records {
		candidate := &records[index]
		if candidate.SecretPrefix != prefix || !appPasswordAllows(candidate, protocol) || !auth.ComparePassword(secret, candidate.SecretHash) {
			continue
		}
		var used *AppPassword
		err := store.Batch(ctx, aps.ts.Store(), func(batchCtx context.Context) error {
			current, err := aps.Get(batchCtx, candidate.ID)
			if err != nil {
				return err
			}
			if current.Revoked {
				return ErrAppPasswordRevoked
			}
			if current.SecretHash != candidate.SecretHash || current.SecretPrefix != candidate.SecretPrefix {
				return ErrAppPasswordChanged
			}
			if !appPasswordAllows(current, protocol) {
				return ErrAppPasswordChanged
			}
			current.LastUsedAt, current.LastProtocol = time.Now().UTC(), strings.ToLower(strings.TrimSpace(protocol))
			if err := aps.ts.Set(batchCtx, NSAppPasswords, appPasswordRecordPrefix+current.ID, current); err != nil {
				return err
			}
			used = cloneAppPassword(current)
			return nil
		})
		return used, err
	}
	return nil, nil
}
