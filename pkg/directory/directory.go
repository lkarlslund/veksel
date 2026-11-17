// Package directory connects Veksel accounts to an external LDAP or Active
// Directory server. Directory accounts verify their password only against the
// directory, are provisioned locally on first sign-in, and are kept in step
// (display name, addresses, administrator role, enabled state) by sign-in and
// a periodic sync that disables but never deletes accounts.
package directory

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrInvalidCredentials reports an unknown login or a wrong password.
	ErrInvalidCredentials = errors.New("invalid directory credentials")
	// ErrAmbiguousLogin reports a login matching more than one entry.
	ErrAmbiguousLogin = errors.New("login matches more than one directory entry")
	// ErrUnavailable reports that no directory server could be used.
	ErrUnavailable = errors.New("directory is unavailable")
	// ErrDisabled reports that directory accounts are turned off.
	ErrDisabled = errors.New("directory accounts are disabled")
	// ErrAccountConflict reports a directory entry whose account ID belongs
	// to a local account or to a different directory entry.
	ErrAccountConflict = errors.New("directory entry conflicts with an existing account")
	// ErrSyncRunning reports that a sync is already in progress.
	ErrSyncRunning = errors.New("a directory sync is already running")
)

// Settings configures the directory connection and account mapping.
type Settings struct {
	Enabled        bool
	URLs           []string
	AllowPlaintext bool
	CACertificate  string
	BindDN         string
	BindPassword   string
	BaseDN         string
	// UserFilter finds a login's entry; every {login} is replaced by the
	// escaped login.
	UserFilter   string
	IDAttributes []string
	AdminGroupDN string
	// AdminRole selects the role administrator group members receive:
	// "admin" grants system.admin, anything else system.owner.
	AdminRole    string
	SyncFilter   string
	SyncInterval time.Duration
	Timeout      time.Duration
}

// Entry is one directory user projected onto what Veksel uses.
type Entry struct {
	DN string
	// GUID is objectGUID (Active Directory) or entryUUID (RFC 4530); empty
	// when the directory exposes neither.
	GUID string
	// Login is the first present ID attribute, lowercased: the local ID.
	Login       string
	DisplayName string
	// Addresses lists mail and SMTP proxy addresses, preferred first.
	Addresses []string
	// Disabled is Active Directory's userAccountControl ACCOUNTDISABLE.
	Disabled bool
	// Admin reports direct membership of the administrator group.
	Admin bool
}

// Directory is the LDAP boundary the account service uses.
type Directory interface {
	// Authenticate finds exactly one entry for login and binds as it with
	// password; an empty password never succeeds.
	Authenticate(ctx context.Context, login, password string) (Entry, error)
	// Users lists every entry matching the sync filter and fails rather than
	// return a partial list of more than limit entries.
	Users(ctx context.Context, limit int) ([]Entry, error)
	// Test binds with the service account and runs a sample search.
	Test(ctx context.Context) Diagnostic
	Close()
}

// Diagnostic is the redacted result of a connection test: it names servers,
// DNs and step errors, never the service password.
type Diagnostic struct {
	OK        bool              `json:"ok"`
	Server    string            `json:"server,omitempty"`
	Transport string            `json:"transport,omitempty"`
	BindDN    string            `json:"bind_dn,omitempty"`
	BaseDN    string            `json:"base_dn,omitempty"`
	Steps     []DiagnosticStep  `json:"steps"`
	Sample    []DiagnosticEntry `json:"sample,omitempty"`
}

// DiagnosticStep is one stage of a connection test.
type DiagnosticStep struct {
	Name         string `json:"name"`
	OK           bool   `json:"ok"`
	Detail       string `json:"detail,omitempty"`
	Milliseconds int64  `json:"milliseconds"`
}

// DiagnosticEntry is one entry found by the sample search.
type DiagnosticEntry struct {
	DN    string `json:"dn"`
	Login string `json:"login,omitempty"`
}
