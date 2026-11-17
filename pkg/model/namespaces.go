package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lkarlslund/veksel/pkg/store/cryptstore"
)

// Store namespace names used by the model layer.
const (
	NSDomains               = "domains"
	NSOutboundRoutes        = "outbound_routes"
	NSUsers                 = "users"
	NSEmails                = "emails"
	NSRecipientAliases      = "recipient_aliases"
	NSUserAliases           = "user_aliases"
	NSFolders               = "folders"
	NSFolderIndexes         = "folder_indexes"
	NSItems                 = "items"
	NSItemHistory           = "item_history"
	NSVacationReplies       = "vacation_replies"
	NSAudit                 = "audit"
	NSACL                   = "acl"
	NSQueue                 = "queue"
	NSMessageTrace          = "message_trace"
	NSMessageTraceIndexes   = "message_trace_indexes"
	NSHealthAlerts          = "health_alerts"
	NSChanges               = "changes"
	NSMetadata              = "metadata"
	NSCerts                 = "tls_certs"
	NSACMECache             = "acme_cache"
	NSAPIKeys               = "api_keys"
	NSAppPasswords          = "app_passwords"
	NSAccountVerifications  = "account_verifications"
	NSScheduledSubmissions  = "scheduled_submissions"
	NSMailItemState         = "mail_item_state"
	NSWebhooks              = "webhooks"
	NSWebhookOutbox         = "webhook_outbox"
	NSMailPolicies          = "mail_policies"
	NSGreylisting           = "greylisting"
	NSMTASTSPolicies        = "mta_sts_policies"
	NSTLSRPT                = "tls_reporting"
	NSDMARCAggregates       = "dmarc_aggregates"
	NSOAuth2Clients         = "oauth2_clients"
	NSOAuth2Tokens          = "oauth2_tokens"
	NSPasswordResets        = "password_resets"
	NSWebhookDeliveries     = "webhook_deliveries"
	NSSessions              = "sessions"
	NSSecondFactors         = "second_factors"
	NSRoles                 = "roles"
	NSGroups                = "groups"
	NSPolicyBindings        = "policy_bindings"
	NSPolicyIndexes         = "policy_indexes"
	NSAuthorizationMetadata = "authorization_metadata"
	NSShareLinks            = "share_links"
	NSAutomationRules       = "automation_rules"
	NSAutomationRuns        = "automation_runs"
	NSAutomationEvidence    = "automation_evidence"
	NSIMIPState             = "imip_state"
	NSBackupSchedule        = "backup_schedule"
	NSDNSZones              = "dns_zones"
	NSDNSHostedZones        = "dns_hosted_zones"
	NSBans                  = "bans"
	NSSenderRoutes          = "sender_routes"
	NSAddressRewrites       = "address_rewrites"
	NSJournalRules          = "journal_rules"
	NSBCCRules              = "bcc_rules"
	NSPGPKeys               = "pgp_keys"
	NSCalendarFeeds         = "calendar_feeds"
)

// Namespaces returns every namespace owned by the model package. Startup and
// maintenance tools use this catalog so adding a model cannot silently omit
// its durable storage area.
func Namespaces() []string {
	return []string{
		NSDomains, NSOutboundRoutes, NSUsers, NSEmails, NSRecipientAliases, NSUserAliases, NSFolders, NSFolderIndexes, NSItems, NSItemHistory,
		NSVacationReplies, NSAudit, NSACL, NSQueue, NSMessageTrace, NSMessageTraceIndexes, NSHealthAlerts, NSChanges, NSMetadata,
		NSCerts, NSACMECache, NSAPIKeys, NSAppPasswords, NSAccountVerifications, NSScheduledSubmissions, NSMailItemState, NSWebhooks,
		NSOAuth2Clients, NSOAuth2Tokens,
		NSPasswordResets, NSWebhookDeliveries, NSWebhookOutbox, NSSessions, NSSecondFactors,
		NSRoles, NSGroups, NSPolicyBindings, NSPolicyIndexes, NSMailPolicies, NSGreylisting,
		NSAuthorizationMetadata, NSSettings, NSMTASTSPolicies, NSTLSRPT, NSDMARCAggregates,
		NSShareLinks, NSAutomationRules, NSAutomationRuns, NSAutomationEvidence, NSIMIPState, NSBackupSchedule, NSDNSZones, NSDNSHostedZones, NSBans,
		NSSenderRoutes, NSAddressRewrites, NSJournalRules, NSBCCRules, NSPGPKeys, NSCalendarFeeds, NSSchema,
	}
}

// ProtectedKeyFamilies lists the account key-name families that embed
// user-chosen or correspondent text. Encrypted accounts keep each family's
// leading segments (folder or owner IDs) in plaintext for prefix scans and
// encrypt the rest of the key name. Other account keys are opaque IDs,
// digests, sequence numbers, or fixed names.
func ProtectedKeyFamilies() []cryptstore.KeyFamily {
	return []cryptstore.KeyFamily{
		// name:<folderID>:<resource name> - DAV hrefs and file names.
		{Namespace: NSItems, Prefix: "name:", Segments: 1},
		// <folderID>:<grantee> - folder sharing grantees.
		{Namespace: NSACL, Prefix: "", Segments: 1},
		// <userID>:<sender> - vacation reply correspondents.
		{Namespace: NSVacationReplies, Prefix: "", Segments: 1},
	}
}

// FolderIndexVersion is the current rebuildable owner/path index schema.
// Account integrity checks use the same marker as FolderStore so repair never
// invents a parallel index contract.
const FolderIndexVersion = 1

// Folder index keys use digests for owner IDs and paths so arbitrary Unicode
// and separator characters remain safe and consistently ordered in every
// backend. Folder IDs are opaque and already safe as the final key segment.
func folderOwnerIndexToken(userID string) string {
	digest := sha256.Sum256([]byte(normalizeID(userID)))
	return hex.EncodeToString(digest[:])
}

func FolderUserIndexPrefix(userID string) string {
	return "user:" + folderOwnerIndexToken(userID) + ":"
}

func FolderUserIndexKey(userID, folderID string) string {
	return FolderUserIndexPrefix(userID) + folderID
}

func FolderPathIndexKey(userID, path string) string {
	digest := sha256.Sum256([]byte(strings.Trim(path, "/")))
	return FolderPathIndexPrefix(userID) + hex.EncodeToString(digest[:])
}

// FolderPathIndexPrefix returns the complete owner-scoped path-index prefix.
func FolderPathIndexPrefix(userID string) string {
	return "path:" + folderOwnerIndexToken(userID) + ":"
}

func FolderIndexMarkerKey(userID string) string {
	return "version:" + folderOwnerIndexToken(userID)
}

// Key builders for the emails namespace (triple-index pattern).
func EmailAddrKey(addr string) string       { return "addr:" + addr }
func EmailUserKey(userID string) string     { return "user:" + userID }
func EmailDomainKey(domainID string) string { return "domain:" + domainID }

// FolderKey returns the stable ID for built-in folders. Custom folders must be
// resolved by FolderStore.GetByPath because their IDs are randomly generated.
func FolderKey(userID, path string) string {
	special := map[string]string{
		"INBOX": SpecialUseInbox, "Drafts": SpecialUseDrafts, "Sent": SpecialUseSent,
		"Trash": SpecialUseTrash, "Junk": SpecialUseJunk, "Archive": SpecialUseArchive,
		"Calendar": SpecialUseCalendar, "Contacts": SpecialUseContacts, "Files": SpecialUseFiles,
		ScheduleInboxPath: SpecialUseScheduleInbox, ScheduleOutboxPath: SpecialUseScheduleOutbox,
	}[path]
	if special != "" {
		return specialFolderID(userID, special)
	}
	return userID + ":" + path
}

// ItemKey builds the store key for an item: "folderID:itemID".
func ItemKey(folderID, itemID string) string { return folderID + ":" + itemID }

// ItemMemberKey indexes immutable item IDs by their current folder.
func ItemMemberKey(folderID, itemID string) string { return "member:" + folderID + ":" + itemID }

// ItemMemberPrefix is the prefix used to list a folder's current members.
func ItemMemberPrefix(folderID string) string { return "member:" + folderID + ":" }

// ItemNameKey resolves a protocol-facing resource name within a folder.
func ItemNameKey(folderID, name string) string { return "name:" + folderID + ":" + name }

// ExternalItemIndexKey resolves a stable source identity within a folder. The
// digest keeps arbitrary protocol identifiers safe for every store backend.
func ExternalItemIndexKey(folderID, namespace, externalID string) string {
	digest := sha256.Sum256([]byte(namespace + "\x00" + externalID))
	return "external:" + folderID + ":" + hex.EncodeToString(digest[:])
}

// TrashedItemKey indexes recoverable items by owner independently of their
// protocol folder type or current folder.
func TrashedItemKey(userID, itemID string) string { return "trash:" + userID + ":" + itemID }

func TrashedItemPrefix(userID string) string { return "trash:" + userID + ":" }

// UIDIndexKey builds the reverse index key for UID lookup: "uid:{folderID}:{uid}".
func UIDIndexKey(folderID string, uid uint32) string {
	return fmt.Sprintf("uid:%s:%d", folderID, uid)
}

// DateIndexKey builds the secondary index key for date-range queries:
// "date:{folderID}:{YYYYMMDD}:{itemID}". The date string uses the time.Time
// format "20060102" so keys sort lexicographically by calendar date.
// Scan with DateIndexPrefix to find all date-index entries for a folder.
func DateIndexKey(folderID, dateStr, itemID string) string {
	return fmt.Sprintf("date:%s:%s:%s", folderID, dateStr, itemID)
}

// DateIndexPrefix returns the prefix for scanning all date-index entries of a folder.
func DateIndexPrefix(folderID string) string { return fmt.Sprintf("date:%s:", folderID) }

// ACLKey builds the store key for an ACL entry: "folderID:username".
func ACLKey(folderID, username string) string { return folderID + ":" + username }

// ACLPrefix returns the prefix for scanning all ACL entries of a folder.
func ACLPrefix(folderID string) string { return folderID + ":" }

// MetadataKey builds the store key for a metadata entry: "entryName" within the
// metadata namespace. For per-mailbox metadata the key is "mailbox:entryName".
// For server-level metadata the key is "server:entryName".
func MetadataKey(scope, entryName string) string { return scope + ":" + entryName }

// MetadataPrefix returns the prefix for scanning all metadata entries for a scope.
func MetadataPrefix(scope string) string { return scope + ":" }

// PasswordResetKey builds the store key for a password reset token:
// "userID:tokenPrefix" where tokenPrefix is the first 8 chars of the token.
func PasswordResetKey(userID, tokenPrefix string) string {
	return userID + ":" + tokenPrefix
}

// WebhookDeliveryKey builds the store key for a webhook delivery: "webhookID:deliveryID".
func WebhookDeliveryKey(webhookID, deliveryID string) string {
	return webhookID + ":" + deliveryID
}

// WebhookDeliveryKeyPrefix builds the prefix for scanning deliveries by webhook ID.
func WebhookDeliveryKeyPrefix(webhookID string) string {
	return webhookID + ":"
}
