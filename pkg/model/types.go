// Package model defines the domain types and store layout for Veksel.
//
// Folders are the universal storage primitive. Email, calendar events,
// contacts, and files all live in typed folders owned by users.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Domain represents a managed mail domain.
type Domain struct {
	ID string `json:"id"` // the domain name, e.g. "example.com"

	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`

	// DKIM configuration for outbound mail signing.
	DkimPrivateKey string    `json:"dkim_private_key,omitempty"` // PEM-encoded private key
	DkimPublicKey  string    `json:"dkim_public_key,omitempty"`  // PEM-encoded public key
	DkimSelector   string    `json:"dkim_selector,omitempty"`    // DKIM selector (default "default")
	DKIMKeys       []DKIMKey `json:"dkim_keys,omitempty"`
	DKIMRevision   uint64    `json:"dkim_revision,omitempty"`

	// VirusScanEnabled controls per-domain virus scanning override.
	VirusScanEnabled bool `json:"virus_scan_enabled"` // per-domain virus scan toggle (default true)

	// CatchAll is the local email identity that receives mail for unknown
	// recipients in this domain. Empty rejects unknown recipients.
	CatchAll string `json:"catch_all,omitempty"`

	// UnknownRecipients routes mail for addresses the domain does not host
	// to another server instead of rejecting it, so a domain can be shared
	// with an old mail system while accounts move over one at a time.
	UnknownRecipients UnknownRecipientPolicy `json:"unknown_recipients,omitzero"`

	// Limits bound what the domain's accounts and aliases may consume and
	// what its delegated administrators may assign. Only system
	// administrators change them.
	Limits DomainLimits `json:"limits,omitzero"`
}

// UnknownRecipientPolicy is a domain's split-delivery setting. With Route,
// an address in the domain that matches no local identity, alias or
// catch-all is delivered through the domain's outbound route (the other
// server) instead of being rejected.
type UnknownRecipientPolicy struct {
	Route bool `json:"route,omitempty"`
	// Check decides which unknown recipients SMTP accepts for routing:
	// UnknownRecipientCallout (the default) asks the route's server at RCPT
	// time, so mail for addresses no system hosts is refused rather than
	// bounced later; UnknownRecipientAccept accepts every address.
	Check string `json:"check,omitempty"`
}

const (
	UnknownRecipientCallout = "callout"
	UnknownRecipientAccept  = "accept"
)

// Validate reports an unknown Check mode.
func (p UnknownRecipientPolicy) Validate() error {
	switch p.Check {
	case "", UnknownRecipientCallout, UnknownRecipientAccept:
		return nil
	}
	return fmt.Errorf("unknown recipient check must be %q or %q", UnknownRecipientCallout, UnknownRecipientAccept)
}

// CheckMode returns Check with its default applied.
func (p UnknownRecipientPolicy) CheckMode() string {
	if p.Check == "" {
		return UnknownRecipientCallout
	}
	return p.Check
}

// DomainLimits are per-domain ceilings and defaults. Zero means unlimited
// for a ceiling and "no default" for a default.
type DomainLimits struct {
	// MaxAccounts bounds accounts whose primary identity is in the domain.
	MaxAccounts int `json:"max_accounts,omitempty"`
	// MaxAliases bounds non-primary identities plus recipient aliases.
	MaxAliases int `json:"max_aliases,omitempty"`
	// MaxStorageBytes bounds the sum of the per-account storage quotas
	// assigned in the domain. While set, every account needs a quota.
	MaxStorageBytes int64 `json:"max_storage_bytes,omitempty"`
	// DefaultAccountStorageBytes is the quota a new account receives when
	// its creator does not choose one.
	DefaultAccountStorageBytes int64 `json:"default_account_storage_bytes,omitempty"`
	// MaxAccountStorageBytes is the largest per-account quota a domain
	// administrator may assign.
	MaxAccountStorageBytes int64 `json:"max_account_storage_bytes,omitempty"`
	// DefaultSendLimits apply to the domain's accounts beneath their own
	// overrides, on top of the server defaults.
	DefaultSendLimits *SendLimits `json:"default_send_limits,omitempty"`
}

// DKIMKeyState describes whether a domain key may sign, is waiting for DNS
// publication, or is retained temporarily while old DNS records overlap.
type DKIMKeyState string

const (
	DKIMKeyStaged   DKIMKeyState = "staged"
	DKIMKeyActive   DKIMKeyState = "active"
	DKIMKeyRetiring DKIMKeyState = "retiring"
)

// DKIMKey is persisted with its domain. Transport projections must never
// expose PrivateKey; the public key is intentionally available for DNS setup.
type DKIMKey struct {
	Selector    string       `json:"selector"`
	PrivateKey  string       `json:"private_key"`
	PublicKey   string       `json:"public_key"`
	State       DKIMKeyState `json:"state"`
	CreatedAt   time.Time    `json:"created_at"`
	ActivatedAt time.Time    `json:"activated_at,omitzero"`
}

// User represents an account that owns folders and email addresses.
type User struct {
	ID string `json:"id"` // unique username, e.g. "alice"

	DisplayName string `json:"display_name"`

	PasswordHash string `json:"password_hash"`

	// Source records where the account's password is verified: empty for a
	// local account, UserSourceLDAP for a directory account, which never
	// verifies against PasswordHash. DirectoryDN and DirectoryID (objectGUID
	// or entryUUID) identify the directory entry stably across renames.
	Source      string `json:"source,omitempty"`
	DirectoryDN string `json:"directory_dn,omitempty"`
	DirectoryID string `json:"directory_id,omitempty"`
	// DirectoryDisabled is set when directory sync disabled the account, so
	// only sync re-enables it and an administrator's own disable is kept.
	DirectoryDisabled bool `json:"directory_disabled,omitempty"`

	// SieveScript is the user's active Sieve filtering script (RFC 5228).
	SieveScript string `json:"sieve_script,omitempty"`

	// SieveActive enables/disables the user's Sieve script.
	SieveActive bool `json:"sieve_active"`

	// ForwardTo is an external email address. When set, a copy of every
	// delivered message is forwarded to this address.
	ForwardTo string `json:"forward_to,omitempty"`

	// Vacation auto-reply fields.
	VacationEnabled bool      `json:"vacation_enabled"`
	VacationStart   time.Time `json:"vacation_start,omitzero"`
	VacationEnd     time.Time `json:"vacation_end,omitzero"`
	VacationSubject string    `json:"vacation_subject,omitempty"`
	VacationMessage string    `json:"vacation_message,omitempty"`

	// MailSignatures are owner-only composer preferences keyed by normalized
	// owned email identity. Delegated identities are never stored here.
	MailSignatures map[string]MailSignature `json:"mail_signatures,omitempty"`

	// RemoteImageSenders are normalized sender addresses whose remote images
	// the web reader shows without asking.
	RemoteImageSenders []string `json:"remote_image_senders,omitempty"`

	// FavoriteContacts are contact item IDs the user starred. They are
	// preferences only: every read re-enters FolderSpace authorization, so a
	// favorite whose address book is no longer visible simply disappears.
	FavoriteContacts []string `json:"favorite_contacts,omitempty"`

	// MailPreferences hold the owner's undo-send and shortcut choices.
	MailPreferences MailPreferences `json:"mail_preferences,omitzero"`

	// Categories is the owner's master category list, shared by mail
	// (IMAP keywords), events and tasks (CATEGORIES), and contacts.
	Categories []Category `json:"categories,omitempty"`

	// DisplayPreferences and NotificationPreferences are the web app's
	// account-wide display and desktop notification choices.
	DisplayPreferences      DisplayPreferences      `json:"display_preferences,omitzero"`
	NotificationPreferences NotificationPreferences `json:"notification_preferences,omitzero"`

	// Spam filtering fields.
	SpamEnabled   bool    `json:"spam_enabled"`   // Enable spam filtering (default true)
	SpamThreshold float64 `json:"spam_threshold"` // Junk score threshold; 0 uses the server default

	// Quota fields. Zero means unlimited.
	MaxStorageBytes     int64 `json:"max_storage_bytes"`
	MaxItems            int   `json:"max_items"`
	CurrentStorageBytes int64 `json:"current_storage_bytes"`
	CurrentItems        int   `json:"current_items"`

	// SendLimits overrides the server's outbound rate limits for this
	// account; nil inherits every server default.
	SendLimits *SendLimits `json:"send_limits,omitempty"`
	// OutboundHold is set while suspected compromise holds the account's
	// outbound mail until an administrator releases it.
	OutboundHold *OutboundHold `json:"outbound_hold,omitempty"`

	// Resource marks a bookable room or equipment account. Resource accounts
	// cannot sign in; their calendar answers invitations by BookingPolicy.
	Resource *ResourceProfile `json:"resource,omitempty"`

	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SendLimits holds per-account outbound rate limit overrides. A nil field
// inherits the server default; zero means unlimited.
type SendLimits struct {
	MessagesPerHour   *int `json:"messages_per_hour,omitempty"`
	RecipientsPerHour *int `json:"recipients_per_hour,omitempty"`
	RecipientsPerDay  *int `json:"recipients_per_day,omitempty"`
}

// OutboundHold records why and since when an account's outbound mail is held.
type OutboundHold struct {
	Since   time.Time `json:"since"`
	Score   float64   `json:"score"`
	Signals []string  `json:"signals,omitempty"`
}

// BookableKind distinguishes rooms from equipment.
type BookableKind string

const (
	BookableRoom      BookableKind = "room"
	BookableEquipment BookableKind = "equipment"
)

// BookingPolicy decides how a resource answers an invitation.
type BookingPolicy string

const (
	// BookingAutoAccept accepts a request when the resource is free.
	BookingAutoAccept BookingPolicy = "auto_accept"
	// BookingApproval leaves a free request for a delegate to approve.
	BookingApproval BookingPolicy = "approval"
)

// ResourceProfile describes a bookable resource account.
type ResourceProfile struct {
	Kind     BookableKind  `json:"kind"`
	Capacity int           `json:"capacity,omitempty"`
	Location string        `json:"location,omitempty"`
	Policy   BookingPolicy `json:"policy"`
	// AllowConflicts accepts (or forwards for approval) requests that
	// overlap an existing booking instead of declining them.
	AllowConflicts bool `json:"allow_conflicts,omitempty"`
}

// UserSourceLDAP marks an account provisioned from an LDAP directory.
const UserSourceLDAP = "ldap"

// Directory reports whether the account's password belongs to a directory.
func (u User) Directory() bool { return u.Source != "" }

// MailSignature configures one identity signature. Text is the plain-text
// form; HTML, when set, is the sanitized rich form used by the HTML composer.
type MailSignature struct {
	Text            string `json:"text"`
	HTML            string `json:"html,omitempty"`
	NewMessages     bool   `json:"new_messages"`
	RepliesForwards bool   `json:"replies_forwards"`
}

// DefaultUndoSendSeconds is the undo-send hold of an account that has not
// chosen one.
const DefaultUndoSendSeconds = 10

// UndoSendChoices are the selectable undo-send holds; 0 sends immediately.
var UndoSendChoices = []int{0, 5, 10, 20, 30}

// ShortcutSets are the selectable webmail keyboard shortcut sets.
var ShortcutSets = []string{"owa", "gmail", "off"}

// MailPreferences are the owner's webmail behavior settings.
type MailPreferences struct {
	// UndoSendSeconds is the undo-send hold; nil means
	// DefaultUndoSendSeconds and 0 sends immediately.
	UndoSendSeconds *int `json:"undo_send_seconds,omitempty"`
	// Shortcuts is one of ShortcutSets; empty means "owa".
	Shortcuts string `json:"shortcuts,omitempty"`
}

// UndoSend returns the effective undo-send hold in seconds.
func (p MailPreferences) UndoSend() int {
	if p.UndoSendSeconds == nil {
		return DefaultUndoSendSeconds
	}
	return *p.UndoSendSeconds
}

// ShortcutSet returns the effective keyboard shortcut set.
func (p MailPreferences) ShortcutSet() string {
	if p.Shortcuts == "" {
		return "owa"
	}
	return p.Shortcuts
}

// Category is one named, colored entry of a master category list.
type Category struct {
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

// EmailAddress is an alias pointing to a user on a domain.
type EmailAddress struct {
	ID string `json:"id"` // full address, e.g. "alice@example.com"

	UserID    string `json:"user_id"`
	DomainID  string `json:"domain_id"`
	LocalPart string `json:"local_part"`

	Primary   bool      `json:"primary"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// RecipientAlias expands one local address to terminal local identities.
// Targets are deliberately not aliases: bounded one-level expansion keeps
// admission deterministic and prevents recipient loops.
type RecipientAlias struct {
	Address   string    `json:"address"`
	DomainID  string    `json:"domain_id"`
	Targets   []string  `json:"targets"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// APIKey represents an API key for authenticating REST API requests.
// Each key belongs to a user and is stored as a bcrypt hash.
// The plain key is only shown once on creation or rotation.
type APIKey struct {
	ID            string    `json:"id"`       // unique key ID (UUID-like)
	UserID        string    `json:"user_id"`  // owner user ID
	Name          string    `json:"name"`     // optional human-readable label
	KeyHash       string    `json:"key_hash"` // bcrypt hash of the secret
	Secret        string    `json:"secret"`   // first 8 chars of the plain key (for display)
	Scopes        []string  `json:"scopes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	LastUsedAt    time.Time `json:"last_used_at"`
	RotatedAt     time.Time `json:"rotated_at"`
	RotationCount int       `json:"rotation_count,omitempty"`
	RevokedAt     time.Time `json:"revoked_at"`
	Revoked       bool      `json:"revoked"`
}

// AppPassword is a revocable client credential scoped to selected protocols.
// SecretPrefix is non-secret display/lookup evidence; SecretHash is the only
// persisted representation of the full credential.
type AppPassword struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	Name          string    `json:"name"`
	SecretHash    string    `json:"secret_hash"`
	SecretPrefix  string    `json:"secret_prefix"`
	Protocols     []string  `json:"protocols"`
	CreatedAt     time.Time `json:"created_at"`
	LastUsedAt    time.Time `json:"last_used_at,omitzero"`
	LastProtocol  string    `json:"last_protocol,omitempty"`
	RotatedAt     time.Time `json:"rotated_at,omitzero"`
	RotationCount int       `json:"rotation_count,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitzero"`
	Revoked       bool      `json:"revoked"`
}

// FolderType indicates what kind of items a folder holds.
type FolderType string

const (
	FolderTypeMail     FolderType = "mail"
	FolderTypeCalendar FolderType = "calendar"
	// FolderTypeTasks is a task list: a CalDAV calendar collection that
	// holds VTODO components only.
	FolderTypeTasks          FolderType = "tasks"
	FolderTypeContacts       FolderType = "contacts"
	FolderTypeFiles          FolderType = "files"
	FolderTypeNotes          FolderType = "notes"
	FolderTypeSieve          FolderType = "sieve"
	FolderTypeScheduleInbox  FolderType = "schedule-inbox"
	FolderTypeScheduleOutbox FolderType = "schedule-outbox"
	FolderTypeSavedSearch    FolderType = "saved-search"
	FolderTypeMailTemplate   FolderType = "mail-template"
)

const validACLRights = RightAll + RightCreate + RightDelete

// ValidateACLRights rejects characters outside RFC 4314 and its obsolete
// RFC 2086 compatibility aliases.
func ValidateACLRights(rights string) error {
	for _, right := range strings.ToLower(rights) {
		if !strings.ContainsRune(validACLRights, right) {
			return fmt.Errorf("invalid ACL right %q", string(right))
		}
	}
	return nil
}

// ScheduleInboxPath and ScheduleOutboxPath are the canonical paths
// for CalDAV scheduling collections (RFC 7959).
const (
	ScheduleInboxPath  = "schedule-inbox"
	ScheduleOutboxPath = "schedule-outbox"
)

// Folder is a typed container for items, owned by a single user.
type Folder struct {
	ID        string     `json:"id"` // immutable opaque resource ID
	UserID    string     `json:"user_id"`
	Name      string     `json:"name"`      // display name, e.g. "INBOX"
	Path      string     `json:"path"`      // hierarchical, e.g. "INBOX/Work"
	ParentID  string     `json:"parent_id"` // empty for root folders
	Type      FolderType `json:"type"`
	Delimiter string     `json:"delimiter"` // typically "/"

	Subscribed bool   `json:"subscribed"`
	System     bool   `json:"system,omitempty"`
	SpecialUse string `json:"special_use,omitempty"`

	// Recoverable deletion metadata. Trashed folders are hidden from normal
	// protocol and workspace listings until restored or purged.
	TrashedAt        time.Time `json:"trashed_at,omitzero"`
	PurgeAfter       time.Time `json:"purge_after,omitzero"`
	OriginalPath     string    `json:"original_path,omitempty"`
	OriginalParentID string    `json:"original_parent_id,omitempty"`

	// Calendar-specific properties (CalDAV)
	Color       string `json:"color,omitempty"`       // calendar color, e.g. "#ff0000"
	Description string `json:"description,omitempty"` // calendar description
	Order       int    `json:"order,omitempty"`       // client sort position (Apple calendar-order)

	// Indexes are derived capabilities attached to this folder. The folder
	// abstraction owns their lifecycle; item-type consumers only use a named
	// index that the folder declares.
	Indexes []FolderIndex `json:"indexes,omitempty"`

	// IMAP support
	UIDValidity   uint32 `json:"uid_validity"` // changes if UIDs are reset
	NextUID       uint32 `json:"next_uid"`     // next UID to assign
	HighestModSeq uint64 `json:"highest_mod_seq"`

	// Derived per-folder accounting avoids enumerating item metadata for quota
	// and status views. Recoverably deleted items remain accounted until purge.
	ItemCount    int64 `json:"item_count"`
	LogicalBytes int64 `json:"logical_bytes"`
	UsageVersion int   `json:"usage_version"`

	// History is an optional folder capability. Version accounting is kept
	// separate from current-item accounting so status and quota projections do
	// not need to enumerate retained snapshots.
	History             ItemHistoryPolicy `json:"history"`
	HistoryVersionCount int64             `json:"history_version_count"`
	HistoryLogicalBytes int64             `json:"history_logical_bytes"`
	HistoryUsageVersion int               `json:"history_usage_version"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	CalendarRangeIndex = "calendar-range"
	// MailListIndex holds per-message list projections (preview, marks,
	// sort keys); MailUnseenIndex holds only unseen message identities so
	// folder unread counts stay cheap.
	MailListIndex   = "mail-list"
	MailUnseenIndex = "mail-unseen"
)

type FolderIndex struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

func DefaultFolderIndexes(folderType FolderType) []FolderIndex {
	switch folderType {
	case FolderTypeCalendar:
		return []FolderIndex{{Name: CalendarRangeIndex, Version: 1}}
	case FolderTypeMail:
		return []FolderIndex{{Name: MailListIndex, Version: 1}, {Name: MailUnseenIndex, Version: 1}}
	}
	return nil
}

func (f Folder) HasIndex(name string, version int) bool {
	for _, index := range f.Indexes {
		if index.Name == name && index.Version == version {
			return true
		}
	}
	return false
}

func (f Folder) withLegacyDefaultIndexes() Folder {
	if len(f.Indexes) == 0 {
		f.Indexes = DefaultFolderIndexes(f.Type)
	}
	return f
}

// ItemHistoryPolicy controls immutable snapshots for one folder. A zero age or
// version bound disables that particular bound; enabled policies are normalized
// by FolderSpace so at least one bound is always present.
type ItemHistoryPolicy struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retention_days"`
	MaxVersions   int  `json:"max_versions"`
}

// ItemHistoryOperation identifies the mutation that caused a snapshot.
type ItemHistoryOperation string

const (
	ItemHistoryUpdate   ItemHistoryOperation = "update"
	ItemHistoryMetadata ItemHistoryOperation = "metadata"
	ItemHistoryMove     ItemHistoryOperation = "move"
	ItemHistoryDelete   ItemHistoryOperation = "delete"
	ItemHistoryTrash    ItemHistoryOperation = "trash"
	ItemHistoryRestore  ItemHistoryOperation = "restore"
)

// ItemVersion is one immutable generic item snapshot. List operations omit
// Item.Data; retrieving a specific version materializes the complete payload.
type ItemVersion struct {
	ID         string               `json:"id"`
	UserID     string               `json:"user_id"`
	FolderID   string               `json:"folder_id"`
	ItemID     string               `json:"item_id"`
	Operation  ItemHistoryOperation `json:"operation"`
	Item       Item                 `json:"item"`
	CapturedAt time.Time            `json:"captured_at"`
}

// ACLEntry represents one ACL entry for a folder (RFC 4314).
type ACLEntry struct {
	Username string `json:"username"`
	Rights   string `json:"rights"` // canonical RFC 4314 order
}

// ACL rights constants (RFC 4314).
const (
	RightLookup         = "l"
	RightRead           = "r"
	RightSeen           = "s"
	RightWrite          = "w"
	RightInsert         = "i"
	RightPost           = "p"
	RightCreateMailbox  = "k"
	RightDeleteMailbox  = "x"
	RightDeleteMessages = "t"
	RightExpunge        = "e"
	RightAdmin          = "a"
	RightAll            = "lrswipkxtea"

	// RightCreate and RightDelete are obsolete RFC 2086 aliases retained for
	// source compatibility. NormalizeACLRights expands c to k and d to xte.
	RightCreate = "c"
	RightDelete = "d"
)

// NormalizeACLRights expands obsolete rights and returns canonical RFC 4314 order.
func NormalizeACLRights(rights string) string {
	rights = strings.ToLower(rights)
	if strings.Contains(rights, RightCreate) {
		rights += RightCreateMailbox
	}
	if strings.Contains(rights, RightDelete) {
		rights += RightDeleteMailbox + RightDeleteMessages + RightExpunge
	}
	var normalized strings.Builder
	for _, right := range RightAll {
		if strings.ContainsRune(rights, right) {
			normalized.WriteRune(right)
		}
	}
	return normalized.String()
}

// HasACLRights reports whether rights contains every requested right.
func HasACLRights(rights, requested string) bool {
	rights = NormalizeACLRights(rights)
	for _, right := range NormalizeACLRights(requested) {
		if !strings.ContainsRune(rights, right) {
			return false
		}
	}
	return true
}

// CalDAV sharing permission levels (RFC 3744).
// These map to ACL rights for calendar sharing.
const (
	ShareOwner  = "owner"  // full control: read, write, delete, manage sharing
	ShareWriter = "writer" // can read and write events
	ShareReader = "reader" // can read events only
)

// Sharee represents a user who has been granted access to a shared calendar.
type Sharee struct {
	UserID string `json:"user_id"` // the grantee user ID
	Role   string `json:"role"`    // ShareOwner, ShareWriter, ShareReader
}

// ShareInfo aggregates sharing metadata for a single calendar folder.
type ShareInfo struct {
	OwnerID  string   `json:"owner_id"`  // calendar owner
	FolderID string   `json:"folder_id"` // folder being shared
	Sharees  []Sharee `json:"sharees"`   // granted users and their roles
}

// ShareRoleToRights converts a CalDAV sharing role to ACL rights string.
func ShareRoleToRights(role string) string {
	switch role {
	case ShareOwner:
		return RightAll
	case ShareWriter:
		return "lrw" // lookup, read, write
	case ShareReader:
		return "lr" // lookup, read
	default:
		return "lr"
	}
}

// ShareRightsToRole converts an ACL rights string back to a CalDAV sharing role.
func ShareRightsToRole(rights string) string {
	if HasACLRights(rights, RightAll) {
		return ShareOwner
	}
	if strings.Contains(rights, RightWrite) {
		return ShareWriter
	}
	return ShareReader
}

// TLSCert represents a stored TLS certificate for a domain.
type TLSCert struct {
	Domain    string    `json:"domain"`     // domain name, e.g. "example.com"
	CertPEM   string    `json:"cert_pem"`   // PEM-encoded certificate
	KeyPEM    string    `json:"key_pem"`    // PEM-encoded private key
	NotBefore time.Time `json:"not_before"` // certificate validity start
	NotAfter  time.Time `json:"not_after"`  // certificate validity end
	Uploaded  time.Time `json:"uploaded"`   // when the cert was uploaded
	Subject   string    `json:"subject"`    // certificate subject CN
	Signer    string    `json:"signer"`     // certificate issuer CN
	SANs      []string  `json:"sans"`       // Subject Alternative Names
}

// OAuth2Client represents a registered OAuth 2.0 client application.
type OAuth2Client struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"` // bcrypt hash
	RedirectURIs []string  `json:"redirect_uris"`
	TokenURL     string    `json:"token_url"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

// OAuth2Token represents a stored OAuth 2.0 access token for a user.
type OAuth2Token struct {
	UserID       string    `json:"user_id"`
	Provider     string    `json:"provider"` // "google", "microsoft", etc.
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

// PasswordResetToken represents a time-limited token for password reset.
// Generated by admins and used by users to self-service reset their password.
type PasswordResetToken struct {
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`      // random 32-byte hex
	ExpiresAt time.Time `json:"expires_at"` // 1h TTL
	UsedAt    time.Time `json:"used_at,omitzero"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

// Item is a single entry in a folder.
type Item struct {
	ID          string            `json:"id"`             // immutable resource ID
	Name        string            `json:"name,omitempty"` // protocol-facing name within the folder
	FolderID    string            `json:"folder_id"`
	Data        []byte            `json:"data"`
	Headers     map[string]string `json:"headers,omitempty"`
	ExternalIDs map[string]string `json:"external_ids,omitempty"` // source namespace to stable source item ID
	Size        int64             `json:"size"`

	// IMAP support
	UID          uint32    `json:"uid"`           // IMAP UID within the folder
	Flags        []string  `json:"flags"`         // IMAP flags (\Seen, \Answered, etc.)
	InternalDate time.Time `json:"internal_date"` // when message was received
	ModSeq       uint64    `json:"mod_seq"`       // modification sequence (RFC 4551)
	// SavedAt is when the item entered its current folder (RFC 8514 save
	// date); zero for items stored before it was recorded.
	SavedAt time.Time `json:"saved_at,omitzero"`

	TrashedAt        time.Time `json:"trashed_at,omitzero"`
	PurgeAfter       time.Time `json:"purge_after,omitzero"`
	OriginalFolderID string    `json:"original_folder_id,omitempty"`
	OriginalName     string    `json:"original_name,omitempty"`

	// Legal-hold preservation metadata. A user deletion while the owning
	// account is under legal hold moves the item into the account's hidden
	// held-deleted folder instead of destroying it.
	HeldDeletedAt   time.Time `json:"held_deleted_at,omitzero"`
	HeldDeletedFrom string    `json:"held_deleted_from,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
