package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/audit"
	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/authz"
	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/folderindex"
	"github.com/lkarlslund/veksel/pkg/imip"
	"github.com/lkarlslund/veksel/pkg/log"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/sendguard"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// registerAPI mounts the REST control plane. Every route is reachable with a
// browser session (CSRF-protected changes) and, unless browser-only, with an
// administrator's X-API-Key (scope-checked); see apiRouter.
func (h *Handler) registerAPI(api apiRouter) {
	api.public("GET /api/v1/setup", h.apiSetupStatus)
	api.public("POST /api/v1/setup", h.apiSetupCreate)
	api.public("POST /api/v1/session/login", h.apiSessionLogin)
	api.public("GET /api/v1/health", h.apiHealth)
	api.public("GET /api/v1/health/ready", h.apiHealthReady)
	api.public("GET /api/v1/health/live", h.apiHealthLive)
	h.registerPublicShareRoutes(api)
	h.registerReference(api)
	h.registerShareManagementRoutes(api)
	h.registerCalendarSharingRoutes(api)
	h.registerComplianceRoutes(api)
	h.registerCategoryRoutes(api)
	h.registerTaskRoutes(api)
	api.browserOnly("GET /api/v1/session", h.apiSession)
	api.handle("GET /api/v1/client-manifest", h.apiClientManifest)
	api.handle("GET /api/v1/user/settings", h.apiUserSettings)
	api.browserOnly("GET /api/v1/user/browser-sessions", h.apiUserBrowserSessions)
	api.browserOnly("DELETE /api/v1/user/browser-sessions", h.apiDeleteOtherBrowserSessions)
	api.browserOnly("DELETE /api/v1/user/browser-sessions/{id}", h.apiDeleteUserBrowserSession)
	api.handle("GET /api/v1/user/export", h.apiUserAccountExport)
	api.handle("GET /api/v1/user/eas-devices", h.apiEASDevices)
	api.browserOnly("GET /api/v1/user/mobileconfig", h.apiUserMobileConfig)
	api.handle("DELETE /api/v1/user/eas-devices/{id}", h.apiRemoveEASDevice)
	api.handle("POST /api/v1/user/eas-devices/{id}/wipe", h.apiWipeEASDevice)
	api.handle("PATCH /api/v1/user/profile", h.apiUserProfile)
	api.handle("GET /api/v1/user/api-keys", h.apiUserAPIKeys)
	api.handle("POST /api/v1/user/api-keys", h.apiCreateUserAPIKey)
	api.handle("POST /api/v1/user/api-keys/{id}/rotate", h.apiRotateUserAPIKey)
	api.handle("DELETE /api/v1/user/api-keys/{id}", h.apiDeleteUserAPIKey)
	api.handle("GET /api/v1/user/app-passwords", h.apiUserAppPasswords)
	api.handle("POST /api/v1/user/app-passwords", h.apiCreateUserAppPassword)
	api.handle("POST /api/v1/user/app-passwords/{id}/rotate", h.apiRotateUserAppPassword)
	api.handle("DELETE /api/v1/user/app-passwords/{id}", h.apiDeleteUserAppPassword)
	api.handle("PUT /api/v1/user/vacation", h.apiUserVacation)
	api.handle("PUT /api/v1/user/signatures/{address}", h.apiUserMailSignature)
	api.handle("PUT /api/v1/user/mail-preferences", h.apiUserMailPreferences)
	api.handle("PUT /api/v1/user/display-preferences", h.apiUserDisplayPreferences)
	api.handle("PUT /api/v1/user/notification-preferences", h.apiUserNotificationPreferences)
	api.handle("GET /api/v1/user/remote-image-senders", h.apiRemoteImageSenders)
	api.handle("PUT /api/v1/user/remote-image-senders/{sender}", h.apiSetRemoteImageSender)
	api.handle("DELETE /api/v1/user/remote-image-senders/{sender}", h.apiSetRemoteImageSender)
	api.handle("GET /api/v1/user/contact-favorites", h.apiContactFavorites)
	api.handle("PUT /api/v1/user/contact-favorites/{id}", h.apiSetContactFavorite)
	api.handle("DELETE /api/v1/user/contact-favorites/{id}", h.apiSetContactFavorite)
	api.handle("GET /api/v1/automation", h.apiAutomation)
	api.handle("POST /api/v1/automation/rules", h.apiCreateAutomationRule)
	api.handle("PATCH /api/v1/automation/rules/{id}", h.apiUpdateAutomationRule)
	api.handle("DELETE /api/v1/automation/rules/{id}", h.apiDeleteAutomationRule)
	api.handle("POST /api/v1/automation/reorder", h.apiReorderAutomationRules)
	api.readOnly("POST /api/v1/automation/rules/{id}/preview", h.apiPreviewAutomationRule)
	api.handle("POST /api/v1/automation/rules/{id}/runs", h.apiRunAutomationRule)
	api.handle("GET /api/v1/automation/runs", h.apiAutomationRuns)
	api.handle("POST /api/v1/automation/runs/{id}/cancel", h.apiCancelAutomationRun)
	api.handle("GET /api/v1/automation/evidence", h.apiAutomationEvidence)
	api.handle("GET /api/v1/roles", h.apiRoles)
	api.handle("POST /api/v1/roles", h.apiCreateRole)
	api.handle("GET /api/v1/groups", h.apiGroups)
	api.handle("POST /api/v1/groups", h.apiSetGroup)
	api.handle("GET /api/v1/grants", h.apiManagedGrants)
	api.handle("GET /api/v1/grants/{id}", h.apiManagedGrant)
	api.handle("PATCH /api/v1/grants/{id}", h.apiUpdateManagedGrant)
	api.handle("DELETE /api/v1/grants/{id}", h.apiDeleteManagedGrant)
	api.handle("GET /api/v1/grants/{id}/effective-access", h.apiManagedGrantEffectiveAccess)
	api.handle("GET /api/v1/folders/{id}/grants", h.apiFolderGrants)
	api.handle("POST /api/v1/folders/{id}/grants", h.apiCreateFolderGrant)
	api.handle("DELETE /api/v1/folders/{id}/grants/{grantID}", h.apiDeleteFolderGrant)
	api.handle("GET /api/v1/identities/{id}/grants", h.apiIdentityGrants)
	api.handle("POST /api/v1/identities/{id}/grants", h.apiCreateIdentityGrant)
	api.handle("DELETE /api/v1/identities/{id}/grants/{grantID}", h.apiDeleteIdentityGrant)
	api.handle("GET /api/v1/accounts/{id}/delegations", h.apiAccountDelegations)
	api.handle("POST /api/v1/accounts/{id}/delegations", h.apiCreateAccountDelegation)
	api.handle("DELETE /api/v1/accounts/{id}/delegations/{grantID}", h.apiDeleteAccountDelegation)
	api.handle("GET /api/v1/accounts/{id}/search-grants", h.apiAccountSearchGrants)
	api.handle("POST /api/v1/accounts/{id}/search-grants", h.apiCreateAccountSearchGrant)
	api.handle("DELETE /api/v1/accounts/{id}/search-grants/{grantID}", h.apiDeleteAccountSearchGrant)
	api.readOnly("POST /api/v1/search/query", h.apiSearch)
	api.handle("GET /api/v1/search/suggestions", h.apiSearchSuggestions)
	api.handle("GET /api/v1/search/saved", h.apiSavedSearches)
	api.handle("POST /api/v1/search/saved", h.apiCreateSavedSearch)
	api.handle("PATCH /api/v1/search/saved/{id}", h.apiUpdateSavedSearch)
	api.handle("DELETE /api/v1/search/saved/{id}", h.apiDeleteSavedSearch)
	api.handle("GET /api/v1/search/index/status", h.apiSearchStatus)
	api.handle("POST /api/v1/search/index/rebuild", h.apiSearchRebuild)
	api.readOnly("POST /api/v1/authorization/check", h.apiAuthorizationCheck)
	api.handle("POST /api/v1/mail/submissions", h.apiMailSubmission)
	api.handle("GET /api/v1/mail/templates", h.apiMessageTemplates)
	api.handle("POST /api/v1/mail/templates", h.apiCreateMessageTemplate)
	api.handle("PATCH /api/v1/mail/templates/{id}", h.apiUpdateMessageTemplate)
	api.handle("DELETE /api/v1/mail/templates/{id}", h.apiDeleteMessageTemplate)
	api.handle("GET /api/v1/mail/scheduled", h.apiScheduledSubmissions)
	api.handle("POST /api/v1/mail/scheduled", h.apiScheduledSubmissions)
	api.handle("GET /api/v1/mail/scheduled/{id}", h.apiScheduledSubmission)
	api.handle("PATCH /api/v1/mail/scheduled/{id}", h.apiScheduledSubmission)
	api.handle("POST /api/v1/mail/scheduled/{id}/cancel", h.apiScheduledSubmissionCancel)
	api.handle("POST /api/v1/mail/scheduled/{id}/send", h.apiScheduledSubmissionSend)
	api.handle("POST /api/v1/workspace/mail/drafts", h.apiWorkspaceSaveDraft)
	api.handle("GET /api/v1/workspace/mail/drafts/{id}", h.apiWorkspaceDraft)
	api.handle("PUT /api/v1/workspace/mail/drafts/{id}", h.apiWorkspaceSaveDraft)
	api.handle("GET /api/v1/workspace/mail/list", h.apiWorkspaceMailList)
	api.handle("GET /api/v1/workspace/mail/follow-ups", h.apiWorkspaceMailFollowUps)
	api.handle("GET /api/v1/workspace/mail/reminders", h.apiWorkspaceMailReminders)
	api.handle("GET /api/v1/workspace/mail/messages/{id}", h.apiWorkspaceMailMessage)
	api.handle("POST /api/v1/workspace/mail/messages/{id}/invitation", h.apiWorkspaceMailInvitationRespond)
	api.handle("POST /api/v1/workspace/mail/messages/{id}/receipt", h.apiWorkspaceMailReceipt)
	api.handle("GET /api/v1/workspace/mail/messages/{id}/source", h.apiWorkspaceMailSource)
	api.handle("GET /api/v1/workspace/mail/messages/{id}/eml", h.apiWorkspaceMailEML)
	api.handle("GET /api/v1/workspace/mail/messages/{id}/attachments/{part}", h.apiWorkspaceMailAttachment)
	api.handle("GET /api/v1/workspace/mail/messages/{id}/attachments/{part}/preview", h.apiWorkspaceMailAttachmentPreview)
	api.handle("GET /api/v1/workspace/folders", h.apiWorkspaceFolders)
	api.handle("GET /api/v1/workspace/folders/{id}/export", h.apiWorkspaceFolderExport)
	api.handle("POST /api/v1/workspace/folders", h.apiWorkspaceCreateFolder)
	api.handle("PATCH /api/v1/workspace/folders/{id}", h.apiWorkspaceMoveFolder)
	api.handle("DELETE /api/v1/workspace/folders/{id}", h.apiWorkspaceTrashFolder)
	api.handle("POST /api/v1/workspace/folders/{id}/restore", h.apiWorkspaceRestoreFolder)
	api.handle("DELETE /api/v1/workspace/folders/{id}/purge", h.apiWorkspacePurgeFolder)
	api.handle("GET /api/v1/workspace/folders/{id}/history", h.apiItemHistoryPolicy)
	api.handle("PATCH /api/v1/workspace/folders/{id}/history", h.apiConfigureItemHistory)
	api.handle("GET /api/v1/workspace/folders/{id}/items/{itemID}/versions", h.apiItemVersions)
	api.handle("GET /api/v1/workspace/folders/{id}/items/{itemID}/versions/{versionID}", h.apiItemVersion)
	api.handle("POST /api/v1/workspace/folders/{id}/items/{itemID}/versions/{versionID}/restore", h.apiRestoreItemVersion)
	api.handle("GET /api/v1/workspace/items", h.apiWorkspaceItems)
	api.handle("GET /api/v1/workspace/items/page", h.apiWorkspaceItemPage)
	api.handle("GET /api/v1/workspace/item", h.apiWorkspaceItem)
	api.handleBulk("POST /api/v1/workspace/items/actions", h.apiWorkspaceItemActions)
	api.handle("GET /api/v1/workspace/trash", h.apiWorkspaceTrash)
	api.handle("PUT /api/v1/workspace/files/{name}", h.apiWorkspacePutFile)
	api.handle("GET /api/v1/workspace/files/{id}/content", h.apiWorkspaceFileContent)
	api.handle("GET /api/v1/workspace/files/{id}/preview", h.apiWorkspaceFilePreview)
	api.handle("PATCH /api/v1/workspace/files/{id}", h.apiWorkspaceMoveFile)
	api.handle("DELETE /api/v1/workspace/files/{id}", h.apiWorkspaceDeleteFile)
	api.handle("GET /api/v1/workspace/calendar/events", h.apiWorkspaceCalendarEvents)
	api.handle("GET /api/v1/workspace/calendar/events/{id}", h.apiWorkspaceCalendarEvent)
	api.handle("POST /api/v1/workspace/calendar/events", h.apiWorkspaceCreateCalendarEvent)
	api.handle("PUT /api/v1/workspace/calendar/events/{id}", h.apiWorkspaceUpdateCalendarEvent)
	api.handle("DELETE /api/v1/workspace/calendar/events/{id}", h.apiWorkspaceDeleteCalendarEvent)
	api.handle("POST /api/v1/workspace/calendar/events/{id}/respond", h.apiWorkspaceCalendarEventRespond)
	api.handle("POST /api/v1/workspace/calendar/events/{id}/proposal", h.apiWorkspaceCalendarProposal)
	api.handle("GET /api/v1/workspace/calendar/freebusy", h.apiWorkspaceCalendarFreeBusy)
	api.handle("GET /api/v1/workspace/contacts", h.apiWorkspaceContacts)
	api.handle("GET /api/v1/workspace/contacts/page", h.apiWorkspaceContactPage)
	api.handle("GET /api/v1/workspace/contacts/query", h.apiWorkspaceContactQuery)
	api.handle("GET /api/v1/workspace/contacts/suggestions", h.apiWorkspaceContactSuggestions)
	api.handle("GET /api/v1/workspace/people/suggestions", h.apiPeopleSuggestions)
	api.handle("GET /api/v1/workspace/people/group", h.apiPeopleGroupMembers)
	api.handle("GET /api/v1/workspace/people/card", h.apiPersonCard)
	api.readOnly("POST /api/v1/workspace/contacts/import/preview", h.apiWorkspaceContactImportPreview)
	api.handleBulk("POST /api/v1/workspace/contacts/import", h.apiWorkspaceContactImport)
	api.handle("GET /api/v1/workspace/contacts/export", h.apiWorkspaceContactExport)
	api.handle("POST /api/v1/workspace/contacts", h.apiWorkspaceCreateContact)
	api.handle("GET /api/v1/workspace/contacts/{id}/photo", h.apiWorkspaceContactPhoto)
	api.handle("GET /api/v1/workspace/contact", h.apiWorkspaceContact)
	api.handle("PUT /api/v1/workspace/contact", h.apiWorkspaceUpdateContact)
	api.handle("DELETE /api/v1/workspace/contact", h.apiWorkspaceDeleteContact)
	api.browserOnly("PUT /api/v1/session/delegation", h.apiStartDelegation)
	api.browserOnly("DELETE /api/v1/session/delegation", h.apiStopActing)
	api.browserOnly("PUT /api/v1/session/impersonation", h.apiStartImpersonation)
	api.browserOnly("DELETE /api/v1/session/impersonation", h.apiStopActing)
	api.handle("GET /api/v1/admin/users", h.apiAdminUsers)
	api.handle("GET /api/v1/admin/recipient-aliases", h.apiAdminRecipientAliases)
	api.handle("POST /api/v1/admin/recipient-aliases", h.apiAdminCreateRecipientAlias)
	api.handle("PUT /api/v1/admin/recipient-aliases/{address}", h.apiAdminUpdateRecipientAlias)
	api.handle("DELETE /api/v1/admin/recipient-aliases/{address}", h.apiAdminDeleteRecipientAlias)
	api.handle("POST /api/v1/admin/users", h.apiAdminCreateUser)
	api.handle("POST /api/v1/admin/users/provision", h.apiAdminProvisionUsers)
	api.handle("GET /api/v1/admin/users/{id}/usage", h.apiAdminUserUsage)
	api.handle("GET /api/v1/admin/users/{id}/spam-config", h.apiAdminUserSpamConfig)
	api.handle("PUT /api/v1/admin/users/{id}/spam-config", h.apiAdminUserSpamConfig)
	api.handle("GET /api/v1/admin/users/{id}/spam-classifier", h.apiAdminUserSpamClassifier)
	api.handle("DELETE /api/v1/admin/users/{id}/spam-classifier", h.apiAdminUserSpamClassifier)
	api.handle("GET /api/v1/account/usage", h.apiAccountUsage)
	api.handle("GET /api/v1/admin/accounts/usage", h.apiAdminAccountUsage)
	api.handle("GET /api/v1/admin/health", h.apiAdminHealth)
	api.handle("GET /api/v1/admin/setup-checklist", h.apiAdminSetupChecklist)
	api.handle("PUT /api/v1/admin/setup-checklist/dismissals", h.apiAdminSetupChecklistDismiss)
	api.handle("POST /api/v1/admin/setup-checklist/port25-probe", h.apiAdminSetupPort25Probe)
	api.handle("POST /api/v1/admin/deliverability/self-test", h.apiAdminDeliverabilitySelfTest)
	api.handle("GET /api/v1/admin/deliverability/messages/{id}", h.apiAdminDeliverabilityMessage)
	api.handle("GET /api/v1/admin/metrics", h.apiAdminMetrics)
	api.handle("GET /api/v1/admin/metrics/prometheus", h.apiAdminMetricsPrometheus)
	api.handle("POST /api/v1/admin/server/restart", h.apiAdminRestartServer)
	api.handle("POST /api/v1/admin/server/shutdown", h.apiAdminShutdownServer)
	api.handle("GET /api/v1/admin/support-bundle/preview", h.apiAdminSupportBundlePreview)
	api.readOnly("POST /api/v1/admin/support-bundle/download", h.apiAdminSupportBundleDownload)
	api.handle("GET /api/v1/admin/sync/credential-keys", h.apiAdminSyncCredentialKeys)
	api.handle("POST /api/v1/admin/sync/credential-keys/rotate", h.apiAdminRotateSyncCredentialKey)
	api.handle("GET /api/v1/admin/alerts", h.apiAdminAlerts)
	api.handle("POST /api/v1/admin/alerts/{id}/acknowledge", h.apiAdminAcknowledgeAlert)
	api.handle("POST /api/v1/admin/alerts/{id}/silence", h.apiAdminSilenceAlert)
	api.handle("GET /api/v1/admin/alerts/notifications", h.apiAdminAlertNotifications)
	api.handle("POST /api/v1/admin/alerts/notifications/test", h.apiAdminTestAlertNotification)
	api.handle("GET /api/v1/admin/notifications/webhooks", h.apiAdminWebhooks)
	api.handle("POST /api/v1/admin/notifications/webhooks", h.apiAdminCreateWebhook)
	api.handle("PATCH /api/v1/admin/notifications/webhooks/{id}", h.apiAdminUpdateWebhook)
	api.handle("POST /api/v1/admin/notifications/webhooks/{id}/rotate-secret", h.apiAdminRotateWebhookSecret)
	api.handle("DELETE /api/v1/admin/notifications/webhooks/{id}", h.apiAdminDeleteWebhook)
	api.handle("POST /api/v1/admin/notifications/webhooks/{id}/test", h.apiAdminTestWebhook)
	api.handle("GET /api/v1/admin/notifications/webhooks/{id}/deliveries", h.apiAdminWebhookDeliveries)
	api.handle("GET /api/v1/user/webhooks", h.apiUserWebhooks)
	api.handle("POST /api/v1/user/webhooks", h.apiUserCreateWebhook)
	api.handle("PATCH /api/v1/user/webhooks/{id}", h.apiUserUpdateWebhook)
	api.handle("POST /api/v1/user/webhooks/{id}/rotate-secret", h.apiUserRotateWebhookSecret)
	api.handle("DELETE /api/v1/user/webhooks/{id}", h.apiUserDeleteWebhook)
	api.handle("POST /api/v1/user/webhooks/{id}/test", h.apiUserTestWebhook)
	api.handle("GET /api/v1/user/webhooks/{id}/deliveries", h.apiUserWebhookDeliveries)
	api.handle("GET /api/v1/admin/mail-policies", h.apiAdminMailPolicies)
	api.handle("POST /api/v1/admin/mail-policies/rules", h.apiAdminCreateMailPolicyRule)
	api.handle("PATCH /api/v1/admin/mail-policies/rules/{id}", h.apiAdminUpdateMailPolicyRule)
	api.handle("DELETE /api/v1/admin/mail-policies/rules/{id}", h.apiAdminDeleteMailPolicyRule)
	api.handle("POST /api/v1/admin/mail-policies/reorder", h.apiAdminReorderMailPolicyRules)
	api.readOnly("POST /api/v1/admin/mail-policies/simulate", h.apiAdminSimulateMailPolicy)
	api.handle("GET /api/v1/admin/directory", h.apiAdminDirectory)
	api.handle("POST /api/v1/admin/directory/sync", h.apiAdminDirectorySync)
	api.handle("POST /api/v1/admin/directory/test", h.apiAdminDirectoryTest)
	api.handle("GET /api/v1/admin/greylisting", h.apiAdminGreylisting)
	api.handle("POST /api/v1/admin/greylisting/allows", h.apiAdminCreateGreylistAllow)
	api.handle("DELETE /api/v1/admin/greylisting/allows/{id}", h.apiAdminDeleteGreylistAllow)
	api.handle("POST /api/v1/admin/greylisting/cleanup", h.apiAdminCleanupGreylisting)
	api.handle("GET /api/v1/admin/security/bans", h.apiAdminBans)
	api.handle("POST /api/v1/admin/security/bans", h.apiAdminCreateBan)
	api.handle("DELETE /api/v1/admin/security/bans", h.apiAdminDeleteBan)
	api.handle("GET /api/v1/admin/security/scanners", h.apiAdminContentScanners)
	api.handle("GET /api/v1/admin/security/dmarc-reports", h.apiAdminDMARCReports)
	api.handle("POST /api/v1/admin/security/dmarc-reports/{day}/retry", h.apiAdminRetryDMARCReports)
	api.handle("POST /api/v1/admin/security/scanners/test", h.apiAdminTestContentScanners)
	api.handle("GET /api/v1/admin/security/antispam", h.apiAdminSpamFiltering)
	api.handle("DELETE /api/v1/admin/security/antispam/classifier", h.apiAdminResetSharedSpamClassifier)
	api.handle("GET /api/v1/admin/security/antispam/reputation", h.apiAdminSpamReputation)
	api.handle("DELETE /api/v1/admin/security/antispam/reputation", h.apiAdminSpamReputation)
	api.handle("GET /api/v1/admin/outbound-tls/status", h.apiAdminOutboundTLSStatus)
	api.handle("GET /api/v1/admin/outbound-tls/mta-sts", h.apiAdminMTASTSPolicies)
	api.handle("POST /api/v1/admin/outbound-tls/mta-sts/{domain}/refresh", h.apiAdminRefreshMTASTSPolicy)
	api.handle("GET /api/v1/admin/outbound-tls/reports", h.apiAdminTLSReports)
	api.handle("GET /api/v1/admin/account-storage", h.apiAdminAccountStorage)
	api.handle("GET /api/v1/admin/account-storage/encryption", h.apiAdminStorageEncryption)
	api.handle("POST /api/v1/admin/account-storage/encryption/rotate", h.apiAdminStorageEncryptionRotate)
	api.handle("POST /api/v1/admin/account-storage/encryption/rewrap", h.apiAdminStorageEncryptionRewrap)
	api.handle("GET /api/v1/admin/account-verifications", h.apiAdminAccountVerifications)
	api.handle("GET /api/v1/admin/account-storage/{login}/conversions", h.apiAdminAccountConversions)
	api.handle("POST /api/v1/admin/account-storage/{login}/conversions", h.apiAdminAccountConversions)
	api.handle("POST /api/v1/admin/account-storage/{login}/conversions/{job}/cancel", h.apiAdminAccountConversionCancel)
	api.handle("POST /api/v1/admin/account-storage/{login}/conversions/{job}/rollback", h.apiAdminAccountConversionRollback)
	api.handle("DELETE /api/v1/admin/account-storage/{login}/conversions/{job}/retained", h.apiAdminAccountConversionCleanup)
	api.handle("POST /api/v1/admin/account-storage/{login}/checks", h.apiAdminAccountCheck)
	api.handle("GET /api/v1/admin/account-storage/{login}/checks/{report}", h.apiAdminAccountCheckReport)
	api.handle("GET /api/v1/admin/account-storage/{login}/export", h.apiAdminAccountExport)
	api.handle("POST /api/v1/admin/account-storage/{login}/restore", h.apiAdminAccountRestore)
	api.handle("POST /api/v1/admin/account-storage/{login}/move", h.apiAdminAccountMove)
	api.handle("DELETE /api/v1/admin/account-storage/{login}", h.apiAdminAccountPurge)
	api.handle("GET /api/v1/admin/account-storage/{login}/lifecycle", h.apiAdminAccountLifecycle)
	api.handle("POST /api/v1/admin/account-storage/{login}/lifecycle/{job}/rollback", h.apiAdminAccountRollback)
	api.handle("DELETE /api/v1/admin/account-storage/{login}/lifecycle/{job}/retained", h.apiAdminAccountRetainedCleanup)
	api.handle("GET /api/v1/admin/domains", h.apiAdminDomains)
	api.handle("POST /api/v1/admin/domains", h.apiAdminCreateDomain)
	api.handle("GET /api/v1/admin/domains/{id}/dkim", h.apiAdminDKIMKeys)
	api.handle("GET /api/v1/admin/domains/{id}/dns", h.apiAdminDNSGuidance)
	api.handle("GET /api/v1/admin/domains/{id}/dns/publish", h.apiAdminDNSPublishPlan)
	api.handle("POST /api/v1/admin/domains/{id}/dns/publish", h.apiAdminDNSPublish)
	api.handle("GET /api/v1/admin/dns/zones", h.apiAdminDNSZones)
	api.handle("PUT /api/v1/admin/dns/zones/{zone}", h.apiAdminPutDNSZone)
	api.handle("DELETE /api/v1/admin/dns/zones/{zone}", h.apiAdminDeleteDNSZone)
	api.handle("GET /api/v1/admin/dns/zones/{zone}/records", h.apiAdminHostedZone)
	api.handle("POST /api/v1/admin/dns/zones/{zone}/records", h.apiAdminAddHostedRecord)
	api.handle("DELETE /api/v1/admin/dns/zones/{zone}/records/{id}", h.apiAdminDeleteHostedRecord)
	api.handle("POST /api/v1/admin/dns/zones/{zone}/dnssec/rollover", h.apiAdminDNSSECRollover)
	api.handle("POST /api/v1/admin/domains/{id}/dkim/keys", h.apiAdminStageDKIMKey)
	api.handle("POST /api/v1/admin/domains/{id}/dkim/keys/{selector}/activate", h.apiAdminActivateDKIMKey)
	api.handle("DELETE /api/v1/admin/domains/{id}/dkim/keys/{selector}", h.apiAdminDeleteDKIMKey)
	api.handle("GET /api/v1/admin/routes", h.apiAdminRoutes)
	api.handle("POST /api/v1/admin/routes", h.apiAdminCreateRoute)
	api.handle("GET /api/v1/admin/certificates", h.apiAdminCertificates)
	api.handle("POST /api/v1/admin/certificates", h.apiAdminCreateCertificate)
	api.handle("PUT /api/v1/admin/certificates/{name}", h.apiAdminReplaceCertificate)
	api.handle("DELETE /api/v1/admin/certificates/{name}", h.apiAdminDeleteCertificate)
	api.handle("GET /api/v1/admin/routes/{domain}", h.apiAdminRoute)
	api.handle("PUT /api/v1/admin/routes/{domain}", h.apiAdminReplaceRoute)
	api.handle("DELETE /api/v1/admin/routes/{domain}", h.apiAdminDeleteRoute)
	api.handle("GET /api/v1/admin/mail-flow", h.apiAdminMailFlow)
	api.handle("POST /api/v1/admin/mail-flow/{kind}", h.apiAdminSaveMailFlow)
	api.handle("PUT /api/v1/admin/mail-flow/{kind}/{id}", h.apiAdminSaveMailFlow)
	api.handle("DELETE /api/v1/admin/mail-flow/{kind}/{id}", h.apiAdminDeleteMailFlow)
	api.handle("POST /api/v1/admin/identities", h.apiAdminCreateIdentity)
	api.handle("GET /api/v1/admin/users/{id}/identities", h.apiAdminListIdentities)
	api.handle("PATCH /api/v1/admin/identities/{address}", h.apiAdminUpdateIdentity)
	api.handle("DELETE /api/v1/admin/identities/{address}", h.apiAdminDeleteIdentity)
	api.handle("GET /api/v1/admin/audit", h.apiAdminAudit)
	api.handle("GET /api/v1/admin/audit/page", h.apiAdminAuditPage)
	api.readOnly("POST /api/v1/admin/backup/download", h.apiAdminDownloadBackup)
	api.readOnly("POST /api/v1/admin/backup/verify", h.apiAdminVerifyBackup)
	api.handle("POST /api/v1/admin/backup/restore", h.apiAdminRestoreBackup)
	api.handle("GET /api/v1/admin/backup/schedule", h.apiAdminBackupSchedule)
	api.handle("POST /api/v1/admin/backup/run", h.apiAdminRunBackup)
	api.handle("GET /api/v1/admin/backup/archives/{name}", h.apiAdminDownloadScheduledBackup)
	api.handle("GET /api/v1/admin/settings", h.apiAdminSettings)
	api.handle("GET /api/v1/admin/protocol-connections", h.apiAdminProtocolConnections)
	api.handle("PATCH /api/v1/admin/settings", h.apiAdminPatchSettings)
	api.handle("GET /api/v1/admin/config", h.apiAdminConfig)
	api.handle("PATCH /api/v1/admin/config", h.apiAdminPatchConfig)
	api.handle("GET /api/v1/admin/config/history", h.apiAdminConfigHistory)
	api.readOnly("POST /api/v1/admin/config/history/{revision}/validate", h.apiAdminConfigValidateRestore)
	api.handle("POST /api/v1/admin/config/history/{revision}/restore", h.apiAdminConfigRestore)
	api.readOnly("POST /api/v1/admin/config/validate", h.apiAdminValidateConfig)
	api.handle("POST /api/v1/admin/config/reload", h.apiAdminReloadConfig)
	api.handle("POST /api/v1/admin/config/recover", h.apiAdminRecoverConfig)
	api.handle("GET /api/v1/admin/http-listeners", h.apiAdminHTTPListeners)
	api.handle("POST /api/v1/admin/http-listeners", h.apiAdminCreateHTTPListener)
	api.handle("PUT /api/v1/admin/http-listeners/{id}", h.apiAdminUpdateHTTPListener)
	api.handle("DELETE /api/v1/admin/http-listeners/{id}", h.apiAdminDeleteHTTPListener)
	api.handle("PUT /api/v1/admin/http-bindings/{service}", h.apiAdminUpdateHTTPBinding)
	api.handle("GET /api/v1/admin/logging", h.apiAdminLogging)
	api.handle("PATCH /api/v1/admin/logging", h.apiAdminLogging)
	api.handle("GET /api/v1/admin/logging/entries", h.apiAdminLogEntries)
	api.handle("PATCH /api/v1/admin/users/{id}", h.apiAdminUpdateUser)
	api.handle("DELETE /api/v1/admin/users/{id}", h.apiAdminUpdateUser)
	api.handle("PATCH /api/v1/admin/domains/{id}", h.apiAdminUpdateDomain)
	api.handle("DELETE /api/v1/admin/domains/{id}", h.apiAdminUpdateDomain)
	api.handle("GET /api/v1/admin/queue", h.apiAdminQueue)
	api.handle("GET /api/v1/admin/queue/stats", h.apiAdminQueueStats)
	api.handle("GET /api/v1/admin/queue/{id}", h.apiAdminQueueDetail)
	api.handle("POST /api/v1/admin/queue/receipts/prune", h.apiAdminQueueReceiptPrune)
	api.handle("GET /api/v1/admin/cache/stats", h.apiAdminCacheStats)
	api.handle("POST /api/v1/admin/queue/actions", h.apiAdminQueueAction)
	api.handle("POST /api/v1/admin/queue/{id}/retry", h.apiAdminQueueRetry)
	api.handle("POST /api/v1/admin/queue/{id}/cancel", h.apiAdminQueueCancel)
	api.handle("POST /api/v1/admin/queue/{id}/hold", h.apiAdminQueueHold)
	api.handle("POST /api/v1/admin/queue/{id}/release", h.apiAdminQueueRelease)
	api.handle("POST /api/v1/admin/queue/{id}/reroute", h.apiAdminQueueReroute)
	api.handle("GET /api/v1/admin/message-trace", h.apiAdminMessageTrace)
	api.handle("GET /api/v1/admin/message-trace/status", h.apiAdminMessageTraceStatus)
	api.handle("POST /api/v1/admin/message-trace/index/rebuild", h.apiAdminMessageTraceRebuild)
	api.handle("POST /api/v1/admin/message-trace/prune", h.apiAdminMessageTracePrune)
	api.handle("GET /api/v1/admin/message-trace/{id}", h.apiAdminMessageTraceDetail)
	api.handle("GET /api/v1/quarantine", h.apiQuarantine)
	api.handle("GET /api/v1/quarantine/digest", h.apiQuarantineDigestPreference)
	api.handle("PUT /api/v1/quarantine/digest", h.apiUpdateQuarantineDigestPreference)
	api.handle("GET /api/v1/quarantine/{id}", h.apiQuarantineDetail)
	api.handle("POST /api/v1/quarantine/{id}/release", h.apiQuarantineRelease)
	api.handle("POST /api/v1/quarantine/{id}/spam", h.apiQuarantineSpam)
	api.handle("POST /api/v1/quarantine/{id}/train", h.apiQuarantineTrain)
	api.handle("GET /api/v1/admin/quarantine/status", h.apiAdminQuarantineStatus)
	api.handle("GET /api/v1/admin/quarantine/digests", h.apiAdminQuarantineDigests)
	api.handle("POST /api/v1/admin/quarantine/cleanup", h.apiAdminQuarantineCleanup)
	api.handle("POST /api/v1/admin/quarantine/rebuild", h.apiAdminQuarantineRebuild)
	api.handle("GET /api/v1/spam-lists", h.apiSpamLists)
	api.handle("GET /api/v1/spam-classifier", h.apiSpamClassifier)
	api.handle("DELETE /api/v1/spam-classifier", h.apiSpamClassifier)
	api.handle("POST /api/v1/spam-lists/{kind}", h.apiSpamListAdd)
	api.handle("DELETE /api/v1/spam-lists/{kind}", h.apiSpamListRemove)
	api.stream("GET /api/v1/events", h.handleEvents)
	api.handle("GET /api/v1/migrations", h.apiMigrations)
	api.handle("POST /api/v1/migrations", h.apiCreateMigration)
	api.handle("POST /api/v1/migrations/inventory", h.apiMigrationInventory)
	api.handle("POST /api/v1/migrations/preflight", h.apiMigrationPreflight)
	api.handle("GET /api/v1/migrations/{id}", h.apiMigration)
	api.handle("POST /api/v1/migrations/{id}/start", h.apiStartMigration)
	api.handle("POST /api/v1/migrations/{id}/cutover", h.apiCutoverMigration)
	api.handle("GET /api/v1/migrations/{id}/runs", h.apiMigrationRuns)
	api.handle("POST /api/v1/migrations/{id}/pause", h.apiPauseMigration)
	api.handle("DELETE /api/v1/migrations/{id}", h.apiDeleteMigration)
	// Sync jobs are the canonical API. Migration routes remain as compatibility aliases.
	api.handle("GET /api/v1/sync-jobs", h.apiMigrations)
	api.handle("POST /api/v1/sync-jobs", h.apiCreateMigration)
	api.handle("POST /api/v1/sync-jobs/inventory", h.apiMigrationInventory)
	api.handle("POST /api/v1/sync-jobs/preflight", h.apiMigrationPreflight)
	api.handle("GET /api/v1/sync-jobs/{id}", h.apiMigration)
	api.handle("PATCH /api/v1/sync-jobs/{id}", h.apiUpdateSyncJob)
	api.handle("POST /api/v1/sync-jobs/{id}/start", h.apiStartMigration)
	api.handle("POST /api/v1/sync-jobs/{id}/cutover", h.apiCutoverMigration)
	api.handle("GET /api/v1/sync-jobs/{id}/runs", h.apiMigrationRuns)
	api.handle("GET /api/v1/sync-jobs/{id}/runs/{run_id}", h.apiMigrationRun)
	api.handle("POST /api/v1/sync-jobs/{id}/pause", h.apiPauseMigration)
	api.handle("POST /api/v1/sync-jobs/{id}/reread", h.apiRereadMigration)
	api.handle("DELETE /api/v1/sync-jobs/{id}", h.apiDeleteMigration)
}

type adminUserUsageType struct {
	Type  model.FolderType `json:"type"`
	Items int64            `json:"items"`
	Bytes int64            `json:"bytes"`
}

type adminUserUsage struct {
	Quota           model.QuotaInfo      `json:"quota"`
	ByType          []adminUserUsageType `json:"by_type"`
	ActualItems     int64                `json:"actual_items"`
	ActualBytes     int64                `json:"actual_bytes"`
	AccountingReady bool                 `json:"accounting_ready"`
	Status          service.QuotaStatus  `json:"status"`
}

func (h *Handler) apiAdminUserUsage(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	reach, ok := h.requireAccountAdmin(w, r, userID, authz.DomainAccountsManage)
	if !ok {
		return
	}
	actor := currentActor(r)
	mode := authz.ActingImpersonation
	if reach.delegated {
		// Usage is metadata the domain grant already covers; a domain
		// administrator holds no impersonation right, so the account's own
		// context reads it.
		actor = model.PrincipalRef{Kind: model.PrincipalUser, ID: userID}
	}
	if actor.ID == userID {
		mode = authz.ActingNone
	}
	access := service.AccessContext{
		Actor: actor, Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: userID},
		Mode: mode, Protocol: "admin",
	}
	usage, err := h.folderSpace.AccountUsage(r.Context(), access)
	if err != nil {
		apiError(w, err)
		return
	}
	byType := make(map[model.FolderType]service.UsageByType, len(usage.ByType))
	for _, entry := range usage.ByType {
		byType[entry.Type] = entry
	}
	typeOrder := []model.FolderType{
		model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts,
		model.FolderTypeFiles, model.FolderTypeNotes, model.FolderTypeScheduleInbox,
		model.FolderTypeScheduleOutbox,
	}
	result := adminUserUsage{
		Quota: usage.Quota, ActualItems: usage.Items, ActualBytes: usage.LogicalBytes,
		AccountingReady: usage.AccountingReady, Status: h.quotaPolicy().Classify(usage),
		ByType: make([]adminUserUsageType, 0, len(typeOrder)+len(byType)),
	}
	for _, folderType := range typeOrder {
		entry := byType[folderType]
		result.ByType = append(result.ByType, adminUserUsageType{Type: folderType, Items: entry.Items, Bytes: entry.LogicalBytes})
		delete(byType, folderType)
	}
	remaining := make([]model.FolderType, 0, len(byType))
	for folderType := range byType {
		remaining = append(remaining, folderType)
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i] < remaining[j] })
	for _, folderType := range remaining {
		entry := byType[folderType]
		if folderType == "" {
			folderType = "other"
		}
		result.ByType = append(result.ByType, adminUserUsageType{Type: folderType, Items: entry.Items, Bytes: entry.LogicalBytes})
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiAdminUsers(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	users, err := h.users.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	users = h.filterUsersToScope(r.Context(), scope, users)
	type userSummary struct {
		ID           string   `json:"id"`
		DisplayName  string   `json:"display_name"`
		Enabled      bool     `json:"enabled"`
		Identities   []string `json:"identities"`
		AccountID    string   `json:"account_id,omitempty"`
		Engine       string   `json:"engine,omitempty"`
		Encrypted    bool     `json:"encrypted,omitempty"`
		StorageState string   `json:"storage_state,omitempty"`
		RootID       string   `json:"root_id,omitempty"`
		TwoFactor    bool     `json:"two_factor"`
		MaxStorage   int64    `json:"max_storage_bytes"`
		SendingHeld  bool     `json:"sending_held,omitempty"`
		Source       string   `json:"source,omitempty"`
		DirectoryDN  string   `json:"directory_dn,omitempty"`
	}
	result := make([]userSummary, 0, len(users))
	for _, user := range users {
		identities, _ := h.users.ListEmailAddressesForUser(r.Context(), user.ID)
		addresses := make([]string, 0, len(identities))
		for _, identity := range identities {
			addresses = append(addresses, identity.ID)
		}
		summary := userSummary{ID: user.ID, DisplayName: user.DisplayName, Enabled: user.Enabled, Identities: addresses, Source: user.Source, DirectoryDN: user.DirectoryDN, SendingHeld: user.OutboundHold != nil, MaxStorage: user.MaxStorageBytes}
		if factors, err := h.secondFactors.Get(r.Context(), user.ID); err == nil {
			summary.TwoFactor = factors.Enabled()
		}
		if h.accountManager != nil {
			if entry, found := h.accountManager.ByLogin(user.ID); found {
				summary.AccountID = entry.Manifest.ID
				summary.Engine = string(entry.Manifest.Engine)
				summary.Encrypted = entry.Manifest.Encrypted
				summary.StorageState = string(entry.Manifest.State)
				summary.RootID = entry.RootID
			}
		}
		result = append(result, summary)
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	var request struct {
		ID              string `json:"id"`
		DisplayName     string `json:"display_name"`
		Password        string `json:"password"`
		Address         string `json:"address"`
		MaxStorageBytes *int64 `json:"max_storage_bytes"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.ID = strings.ToLower(strings.TrimSpace(request.ID))
	request.Address = strings.ToLower(strings.TrimSpace(request.Address))
	if request.ID == "" || strings.ContainsAny(request.ID, "@:/\\ ") || len(request.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "valid account ID and password of at least 8 characters required")
		return
	}
	if request.MaxStorageBytes != nil && *request.MaxStorageBytes < 0 {
		jsonError(w, http.StatusBadRequest, "quota limits cannot be negative")
		return
	}
	domainID := addressDomain(request.Address)
	if request.Address != "" && (domainID == "" || strings.Index(request.Address, "@") < 1) {
		jsonError(w, http.StatusBadRequest, "valid primary email address required")
		return
	}
	// A domain administrator creates accounts only inside its domains, so
	// the account must start with a primary identity there.
	if !scope.system {
		if domainID == "" {
			jsonError(w, http.StatusBadRequest, "a primary email address in a domain you administer is required")
			return
		}
		if !h.requireDomainAction(w, r, domainID, authz.DomainAccountsManage) {
			return
		}
	}
	account := model.User{ID: request.ID, DisplayName: strings.TrimSpace(request.DisplayName)}
	if request.MaxStorageBytes != nil {
		account.MaxStorageBytes = *request.MaxStorageBytes
	}
	h.domainLimitMu.Lock()
	defer h.domainLimitMu.Unlock()
	if domainID != "" {
		domain, err := h.ts.DomainStore().Get(r.Context(), domainID)
		if err != nil {
			apiError(w, err)
			return
		}
		if _, err := h.users.GetEmailAddress(r.Context(), request.Address); err == nil {
			jsonError(w, http.StatusConflict, "email address is already in use")
			return
		}
		if request.MaxStorageBytes == nil {
			account.MaxStorageBytes = domain.Limits.DefaultAccountStorageBytes
		}
		if err := h.checkAccountCapacity(r.Context(), domainID); err != nil {
			apiError(w, err)
			return
		}
		if err := h.checkAccountQuota(r.Context(), domainID, 0, account.MaxStorageBytes, !scope.system); err != nil {
			apiError(w, err)
			return
		}
	}
	if err := h.createAccountRecord(r.Context(), account, request.Password); err != nil {
		apiError(w, err)
		return
	}
	reach := accountAccess{domain: domainID, delegated: !scope.system}
	if request.Address != "" {
		if err := h.users.AddEmailAddress(r.Context(), request.Address, request.ID, domainID, true); err != nil {
			// The account is new and empty; do not leave it outside the
			// domain its creator administers.
			_ = h.users.Delete(r.Context(), request.ID)
			apiError(w, err)
			return
		}
		if err := h.syncAccountManifest(r.Context(), request.ID); err != nil {
			apiError(w, err)
			return
		}
	}
	h.audit.Log(currentActor(r).ID, "account.create", request.ID, reach.auditDetails(map[string]string{"address": request.Address}))
	h.events.Publish(events.Event{Type: "account.created", Resource: request.ID, Recipients: []string{currentActor(r).ID}})
	jsonResponse(w, http.StatusCreated, map[string]any{"id": request.ID, "display_name": request.DisplayName, "enabled": true, "address": request.Address, "max_storage_bytes": account.MaxStorageBytes})
}

// createAccount is the canonical account bootstrap used by interactive and
// bulk provisioning. It either leaves a discoverable account with its default
// folders or rolls the partial account back.
func (h *Handler) createAccount(ctx context.Context, id, displayName, password string) error {
	return h.createAccountRecord(ctx, model.User{ID: id, DisplayName: displayName}, password)
}

// createAccountRecord provisions user, hashing password into it.
func (h *Handler) createAccountRecord(ctx context.Context, user model.User, password string) error {
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	user.PasswordHash = passwordHash
	return h.accountProvisioner().Create(ctx, user)
}

func (h *Handler) accountProvisioner() account.Provisioner {
	return account.Provisioner{TS: h.ts, Manager: h.accountManager}
}

func (h *Handler) apiAdminDomains(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	domains, err := h.ts.DomainStore().List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	response := make([]adminDomainResponse, 0, len(domains))
	for _, domain := range domains {
		if !scope.covers(domain.ID) {
			continue
		}
		projected := projectAdminDomain(domain)
		if usage, err := h.ts.DomainStore().Usage(r.Context(), domain.ID); err == nil {
			projected.Usage = &usage
		}
		response = append(response, projected)
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiAdminCreateDomain(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	var request struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.ID = strings.ToLower(strings.TrimSpace(request.ID))
	if request.ID == "" || !strings.Contains(request.ID, ".") {
		jsonError(w, http.StatusBadRequest, "valid domain required")
		return
	}
	if err := h.ts.DomainStore().Create(r.Context(), request.ID); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "domain.create", request.ID, nil)
	jsonResponse(w, http.StatusCreated, map[string]string{"id": request.ID})
}

func (h *Handler) apiAdminCreateIdentity(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Address string `json:"address"`
		UserID  string `json:"user_id"`
		Primary bool   `json:"primary"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Address = strings.ToLower(strings.TrimSpace(request.Address))
	request.UserID = strings.ToLower(strings.TrimSpace(request.UserID))
	at := strings.LastIndex(request.Address, "@")
	if at < 1 {
		jsonError(w, http.StatusBadRequest, "valid email address required")
		return
	}
	domainID := request.Address[at+1:]
	if !h.requireDomainAction(w, r, domainID, authz.DomainIdentitiesManage) {
		return
	}
	reach, ok := h.requireAccountAdmin(w, r, request.UserID, authz.DomainAccountsManage)
	if !ok {
		return
	}
	if _, err := h.users.Get(r.Context(), request.UserID); err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.ts.DomainStore().Get(r.Context(), domainID); err != nil {
		apiError(w, err)
		return
	}
	h.domainLimitMu.Lock()
	defer h.domainLimitMu.Unlock()
	switch {
	case !request.Primary:
		if err := h.checkAliasCapacity(r.Context(), domainID); err != nil {
			apiError(w, err)
			return
		}
	case reach.domain != domainID:
		// A new primary identity moves the account into this domain.
		if err := h.checkAccountCapacity(r.Context(), domainID); err != nil {
			apiError(w, err)
			return
		}
	}
	if err := h.users.AddEmailAddress(r.Context(), request.Address, request.UserID, domainID, request.Primary); err != nil {
		apiError(w, err)
		return
	}
	if err := h.syncAccountManifest(r.Context(), request.UserID); err != nil {
		apiError(w, err)
		return
	}
	reach.domain = domainID
	h.audit.Log(currentActor(r).ID, "identity.create", request.Address, reach.auditDetails(map[string]string{"user_id": request.UserID}))
	jsonResponse(w, http.StatusCreated, request)
}

func (h *Handler) apiAdminListIdentities(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if _, ok := h.requireAccountAdmin(w, r, userID, authz.DomainAccountsManage); !ok {
		return
	}
	if _, err := h.users.Get(r.Context(), userID); err != nil {
		apiError(w, err)
		return
	}
	identities, err := h.users.ListEmailAddressesForUser(r.Context(), userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, err)
		return
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	if identities == nil {
		identities = []model.EmailAddress{}
	}
	jsonResponse(w, http.StatusOK, identities)
}

func (h *Handler) apiAdminUpdateIdentity(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	if !h.requireDomainAction(w, r, addressDomain(address), authz.DomainIdentitiesManage) {
		return
	}
	var request struct {
		Enabled bool `json:"enabled"`
		Primary bool `json:"primary"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Primary && !request.Enabled {
		jsonError(w, http.StatusBadRequest, "a disabled identity cannot be primary")
		return
	}
	identity, err := h.users.GetEmailAddress(r.Context(), address)
	if err != nil {
		apiError(w, err)
		return
	}
	reach, ok := h.requireAccountAdmin(w, r, identity.UserID, authz.DomainAccountsManage)
	if !ok {
		return
	}
	if err := h.users.UpdateEmailAddress(r.Context(), address, request.Enabled, request.Primary); err != nil {
		apiError(w, err)
		return
	}
	if err := h.syncAccountManifest(r.Context(), identity.UserID); err != nil {
		apiError(w, err)
		return
	}
	updated, err := h.users.GetEmailAddress(r.Context(), address)
	if err != nil {
		apiError(w, err)
		return
	}
	reach.domain = identity.DomainID
	h.audit.Log(currentActor(r).ID, "identity.update", address, reach.auditDetails(map[string]string{"user_id": identity.UserID}))
	jsonResponse(w, http.StatusOK, updated)
}

func (h *Handler) apiAdminDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	if !h.requireDomainAction(w, r, addressDomain(address), authz.DomainIdentitiesManage) {
		return
	}
	identity, err := h.users.GetEmailAddress(r.Context(), address)
	if err != nil {
		apiError(w, err)
		return
	}
	reach, ok := h.requireAccountAdmin(w, r, identity.UserID, authz.DomainAccountsManage)
	if !ok {
		return
	}
	if err := h.users.DeleteEmailAddress(r.Context(), address); err != nil {
		apiError(w, err)
		return
	}
	if err := h.syncAccountManifest(r.Context(), identity.UserID); err != nil {
		apiError(w, err)
		return
	}
	reach.domain = identity.DomainID
	h.audit.Log(currentActor(r).ID, "identity.delete", address, reach.auditDetails(map[string]string{"user_id": identity.UserID}))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) syncAccountManifest(ctx context.Context, userID string) error {
	_, err := h.accountProvisioner().Sync(ctx, userID)
	return err
}

func (h *Handler) apiAdminAudit(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	entries, err := h.audit.QueryReverse(r.Context(), time.Time{}, "", "", 100)
	if err != nil {
		apiError(w, err)
		return
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	jsonResponse(w, http.StatusOK, entries)
}

func (h *Handler) apiAdminAuditPage(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	pageSize := 25
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			jsonError(w, http.StatusBadRequest, "page_size must be between 1 and 100")
			return
		}
		pageSize = value
	}
	var before int64
	if raw := r.URL.Query().Get("before_sequence"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 {
			jsonError(w, http.StatusBadRequest, "before_sequence must be a positive integer")
			return
		}
		before = value
	}
	page, err := h.audit.QueryReversePage(r.Context(), before, pageSize)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, struct {
		Entries            []audit.Entry `json:"entries"`
		Total              int           `json:"total"`
		PageSize           int           `json:"page_size"`
		NextBeforeSequence int64         `json:"next_before_sequence,omitempty"`
	}{
		Entries:            page.Entries,
		Total:              page.Total,
		PageSize:           pageSize,
		NextBeforeSequence: page.NextBefore,
	})
}

func (h *Handler) apiWorkspaceFolders(w http.ResponseWriter, r *http.Request) {
	// Every workspace entry loads this catalog, which evaluates discovery plus
	// four item capabilities per foreign folder; the router's request scope
	// resolves the caller's policy bindings once for all of them.
	ctx := r.Context()
	folders, err := h.workspace.ListFolders(ctx, currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		apiError(w, err)
		return
	}
	// The mail workspace asks for unread counts; they come from each folder's
	// unseen projection, which catches up from the change journal. A folder
	// whose projection is still being built answers "counting" at once and
	// announces its count with a folders.counts event; "first" lists the
	// client's current and favorite folders, whose builds follow Inbox's.
	withUnread := r.URL.Query().Get("include") == "unread"
	preferred := strings.Split(r.URL.Query().Get("first"), ",")
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	response := make([]workspaceFolder, 0, len(folders))
	for _, folder := range folders {
		capabilities, err := h.workspaceFolderCapabilities(ctx, r, folder)
		if err != nil {
			apiError(w, err)
			return
		}
		entry := workspaceFolder{Folder: folder, Capabilities: capabilities}
		if !strings.EqualFold(folder.UserID, currentSubject(r).ID) {
			entry.OwnerName = folder.UserID
			if owner, err := h.users.Get(ctx, folder.UserID); err == nil && owner.DisplayName != "" {
				entry.OwnerName = owner.DisplayName
			}
		}
		if withUnread && folder.Type == model.FolderTypeMail && capabilities.ReadItems {
			if unread, err := h.mailIndex.Unseen(ctx, h.folderSpace, access, folder, mailFolderPriority(folder, preferred)); err == nil {
				entry.UnreadCount = &unread
			} else if errors.Is(err, folderindex.ErrBuilding) {
				entry.UnreadState = unreadCounting
			} else {
				log.Warn("mail unread count unavailable", "folder_id", folder.ID, "error", err)
			}
		}
		response = append(response, entry)
	}
	jsonResponse(w, http.StatusOK, response)
}

type workspaceFolderCapabilities struct {
	ReadItems   bool `json:"read_items"`
	CreateItems bool `json:"create_items"`
	UpdateItems bool `json:"update_items"`
	DeleteItems bool `json:"delete_items"`
	// Calendar folders: FreeBusy shows busy times, Schedule answers the
	// owner's invitations (a delegate), and ManageSharing changes who the
	// calendar is shared with.
	FreeBusy      bool `json:"free_busy,omitempty"`
	Schedule      bool `json:"schedule,omitempty"`
	ManageSharing bool `json:"manage_sharing,omitempty"`
}

// unreadCounting is the unread_state of a folder whose count is first built.
const unreadCounting = "counting"

type workspaceFolder struct {
	model.Folder
	Capabilities workspaceFolderCapabilities `json:"capabilities"`
	UnreadCount  *int64                      `json:"unread_count,omitempty"`
	UnreadState  string                      `json:"unread_state,omitempty"`
	// OwnerName is the display name of another account's shared folder.
	OwnerName string `json:"owner_name,omitempty"`
}

func (h *Handler) workspaceFolderCapabilities(ctx context.Context, r *http.Request, folder model.Folder) (workspaceFolderCapabilities, error) {
	subject := currentSubject(r)
	if subject.Kind == model.PrincipalUser && strings.EqualFold(folder.UserID, subject.ID) {
		owned := workspaceFolderCapabilities{ReadItems: true, CreateItems: true, UpdateItems: true, DeleteItems: true}
		if folder.Type == model.FolderTypeCalendar {
			owned.FreeBusy, owned.Schedule, owned.ManageSharing = true, true, true
		}
		return owned, nil
	}
	request := authz.Request{
		Actor: currentActor(r), Subject: subject, Mode: currentActingMode(r),
		Resource: model.ResourceRef{Kind: model.ResourceFolder, ID: folder.ID},
	}
	allowed := func(action authz.Action) (bool, error) {
		request.Action = action
		decision, err := h.authorizer.Check(ctx, request)
		return decision.Allowed, err
	}
	readItems, err := allowed(authz.FolderItemsRead)
	if err != nil {
		return workspaceFolderCapabilities{}, fmt.Errorf("check read capability for folder %q: %w", folder.ID, err)
	}
	createItems, err := allowed(authz.FolderItemsCreate)
	if err != nil {
		return workspaceFolderCapabilities{}, fmt.Errorf("check create capability for folder %q: %w", folder.ID, err)
	}
	updateItems, err := allowed(authz.FolderItemsUpdate)
	if err != nil {
		return workspaceFolderCapabilities{}, fmt.Errorf("check update capability for folder %q: %w", folder.ID, err)
	}
	deleteItems, err := allowed(authz.FolderItemsDelete)
	if err != nil {
		return workspaceFolderCapabilities{}, fmt.Errorf("check delete capability for folder %q: %w", folder.ID, err)
	}
	capabilities := workspaceFolderCapabilities{ReadItems: readItems, CreateItems: createItems, UpdateItems: updateItems, DeleteItems: deleteItems}
	if folder.Type == model.FolderTypeCalendar {
		for _, check := range []struct {
			action authz.Action
			target *bool
		}{{authz.CalendarFreeBusyRead, &capabilities.FreeBusy}, {authz.CalendarSchedule, &capabilities.Schedule}, {authz.FolderPermissionsManage, &capabilities.ManageSharing}} {
			if *check.target, err = allowed(check.action); err != nil {
				return workspaceFolderCapabilities{}, fmt.Errorf("check %s for folder %q: %w", check.action, folder.ID, err)
			}
		}
		capabilities.FreeBusy = capabilities.FreeBusy || readItems
	}
	return capabilities, nil
}

type workspaceFolderRequest struct {
	Name     string           `json:"name"`
	Type     model.FolderType `json:"type,omitempty"`
	ParentID string           `json:"parent_id"`
	Default  *bool            `json:"default,omitempty"`
}

func (h *Handler) apiWorkspaceCreateFolder(w http.ResponseWriter, r *http.Request) {
	var request workspaceFolderRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	folder, err := h.workspace.CreateFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), request.Name, request.Type, request.ParentID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "folder.created", folder.ID, map[string]any{"parent_id": folder.ParentID})
	jsonResponse(w, http.StatusCreated, folder)
}

func (h *Handler) apiWorkspaceMoveFolder(w http.ResponseWriter, r *http.Request) {
	var request workspaceFolderRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var folder model.Folder
	var err error
	if request.Default != nil && request.Name == "" {
		folder, err = h.workspace.UpdateFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"), service.FolderUpdate{Default: request.Default})
	} else {
		folder, err = h.workspace.MoveFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"), request.ParentID, request.Name)
		if err == nil && request.Default != nil {
			folder, err = h.workspace.UpdateFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folder.ID, service.FolderUpdate{Default: request.Default})
		}
	}
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "folder.moved", folder.ID, map[string]any{"parent_id": folder.ParentID})
	jsonResponse(w, http.StatusOK, folder)
}

func (h *Handler) apiWorkspaceTrashFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.workspace.TrashFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), id); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "folder.trashed", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiWorkspaceRestoreFolder(w http.ResponseWriter, r *http.Request) {
	folder, err := h.workspace.RestoreFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "folder.restored", folder.ID, nil)
	jsonResponse(w, http.StatusOK, folder)
}

func (h *Handler) apiWorkspacePurgeFolder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.workspace.PurgeFolder(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), id); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "folder.purged", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiWorkspaceItems(w http.ResponseWriter, r *http.Request) {
	items, err := h.workspace.ListItems(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.URL.Query().Get("folder_id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, items)
}

func (h *Handler) apiWorkspaceItemPage(w http.ResponseWriter, r *http.Request) {
	limit, beforeUID, err := itemPageParameters(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := service.ItemPageQuery{BeforeUID: beforeUID, Limit: limit}
	if order := strings.TrimSpace(r.URL.Query().Get("order")); order != "" {
		if order != string(service.ItemPageOrderInternalDateDescending) {
			jsonError(w, http.StatusBadRequest, "unsupported item page order")
			return
		}
		query.Order = service.ItemPageOrderInternalDateDescending
		query.Cursor = strings.TrimSpace(r.URL.Query().Get("cursor"))
		query.AnchorItemID = strings.TrimSpace(r.URL.Query().Get("around_item_id"))
		if beforeUID != 0 {
			jsonError(w, http.StatusBadRequest, "before_uid cannot be combined with ordered paging")
			return
		}
		if query.Cursor != "" && query.AnchorItemID != "" {
			jsonError(w, http.StatusBadRequest, "cursor cannot be combined with around_item_id")
			return
		}
	} else if strings.TrimSpace(r.URL.Query().Get("cursor")) != "" {
		jsonError(w, http.StatusBadRequest, "cursor requires an item page order")
		return
	} else if strings.TrimSpace(r.URL.Query().Get("around_item_id")) != "" {
		jsonError(w, http.StatusBadRequest, "around_item_id requires an item page order")
		return
	}
	page, err := h.workspace.ListItemPage(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.URL.Query().Get("folder_id"), query)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, page)
}

func itemPageParameters(r *http.Request) (int, uint32, error) {
	limit := 100
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			return 0, 0, errors.New("limit must be between 1 and 200")
		}
		limit = parsed
	}
	var beforeUID uint64
	if value := strings.TrimSpace(r.URL.Query().Get("before_uid")); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, 0, errors.New("before_uid must be an unsigned integer")
		}
		beforeUID = parsed
	}
	return limit, uint32(beforeUID), nil
}

func (h *Handler) apiWorkspaceItem(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.URL.Query().Get("item_id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, item)
}

// workspaceMailMessage adds the calendar invitation, when the message
// carries one, to the presentation-safe MIME projection.
type workspaceMailMessage struct {
	service.MessageProjection
	Invitation *imip.Invitation `json:"invitation,omitempty"`
	// RemoteImagesAllowed is set when the viewer always shows remote images
	// from this sender.
	RemoteImagesAllowed bool `json:"remote_images_allowed,omitempty"`
}

func (h *Handler) apiWorkspaceMailMessage(w http.ResponseWriter, r *http.Request) {
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	projection, err := h.mimeReader.Project(r.Context(), access, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	response := workspaceMailMessage{MessageProjection: projection}
	if projection.RemoteContentBlocked {
		response.RemoteImagesAllowed = h.remoteImagesAllowed(r, projection.Headers["From"])
	}
	if h.scheduling != nil && len(projection.Calendar) > 0 {
		if response.Invitation, _ = h.scheduling.Describe(r.Context(), access, projection.FolderID, projection.Calendar); response.Invitation != nil {
			response.Invitation.ItemID = r.PathValue("id")
		}
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) apiWorkspaceMailInvitationRespond(w http.ResponseWriter, r *http.Request) {
	invitation, ok := h.answerInvitation(w, r, webAccess(currentActor(r), currentSubject(r), currentActingMode(r)))
	if ok {
		invitation.ItemID = r.PathValue("id")
		jsonResponse(w, http.StatusOK, invitation)
	}
}

func (h *Handler) apiWorkspaceMailAttachment(w http.ResponseWriter, r *http.Request) {
	stream, err := h.mimeReader.OpenAttachment(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.PathValue("id"), r.PathValue("part"))
	if err != nil {
		apiError(w, err)
		return
	}
	defer stream.Reader.Close()
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": stream.Name}))
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Content-Type", stream.ContentType)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, stream.Reader)
}

func (h *Handler) apiWorkspaceMailAttachmentPreview(w http.ResponseWriter, r *http.Request) {
	stream, err := h.mimeReader.OpenAttachment(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.PathValue("id"), r.PathValue("part"))
	if err != nil {
		apiError(w, err)
		return
	}
	defer stream.Reader.Close()
	serveSafeContentPreview(w, r, stream.Name, stream.ContentType, stream.Size, stream.Reader)
}

func serveSafeContentPreview(w http.ResponseWriter, r *http.Request, name, contentType string, declaredSize int64, reader io.Reader) {
	limit, ok := service.ContentPreviewLimit(contentType)
	if !ok {
		jsonError(w, http.StatusUnsupportedMediaType, "this content type is download-only")
		return
	}
	if declaredSize > limit {
		jsonError(w, http.StatusRequestEntityTooLarge, "content exceeds the inline preview limit")
		return
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "content preview could not be read")
		return
	}
	if int64(len(data)) > limit {
		jsonError(w, http.StatusRequestEntityTooLarge, "content exceeds the inline preview limit")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": name}))
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: blob:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

type workspaceItemActionRequest struct {
	ItemIDs             []string `json:"item_ids"`
	Action              string   `json:"action"`
	DestinationFolderID string   `json:"destination_folder_id,omitempty"`
	// ConversationIDs add every message of these conversations in FolderID
	// (Outlook semantics: a conversation action stays within the folder).
	ConversationIDs []string `json:"conversation_ids,omitempty"`
	FolderID        string   `json:"folder_id,omitempty"`
	// Until is the snooze wake time; DueAt and ReminderAt are the
	// follow-up dates (either may be omitted).
	Until      time.Time  `json:"until,omitzero"`
	DueAt      *time.Time `json:"due_at,omitzero"`
	ReminderAt *time.Time `json:"reminder_at,omitzero"`
	// Category names the master category for categorize and uncategorize.
	Category string `json:"category,omitempty"`
}

func (h *Handler) apiWorkspaceItemActions(w http.ResponseWriter, r *http.Request) {
	var request workspaceItemActionRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(request.ConversationIDs) > 500 {
		jsonError(w, http.StatusBadRequest, "at most 500 conversation IDs are allowed")
		return
	}
	if len(request.ConversationIDs) > 0 {
		itemIDs, err := h.conversationActionItems(r, request.FolderID, request.ConversationIDs)
		if err != nil {
			apiError(w, err)
			return
		}
		request.ItemIDs = append(request.ItemIDs, itemIDs...)
	}
	if len(request.ItemIDs) == 0 || len(request.ItemIDs) > 500 {
		jsonError(w, http.StatusBadRequest, "between 1 and 500 item IDs are required")
		return
	}
	seen := make(map[string]struct{}, len(request.ItemIDs))
	updated := make([]model.Item, 0, len(request.ItemIDs))
	triage := &mailTriage{h: h, r: r}
	categories := &categoryActions{h: h, r: r}
	for _, itemID := range request.ItemIDs {
		if itemID == "" {
			jsonError(w, http.StatusBadRequest, "item IDs cannot be empty")
			return
		}
		if _, duplicate := seen[itemID]; duplicate {
			continue
		}
		seen[itemID] = struct{}{}
		var item model.Item
		var err error
		switch request.Action {
		case "archive", "junk", "not_junk", "block_sender":
			item, err = triage.apply(itemID, request.Action)
		case "pin", "unpin", "snooze", "unsnooze", "follow_up", "complete", "dismiss_reminder":
			item, err = h.applyMailStateAction(r, itemID, request)
		case "categorize", "uncategorize":
			item, err = categories.apply(itemID, request.Category, request.Action == "categorize")
		default:
			item, err = h.applyWorkspaceItemAction(r, itemID, request)
		}
		if err != nil {
			apiError(w, err)
			return
		}
		if item.ID != "" {
			item.Headers = displayHeaders(item.Headers)
			updated = append(updated, item)
		}
	}
	h.workspaceChanged(r, "items."+request.Action, "", map[string]any{"item_ids": request.ItemIDs, "destination_folder_id": request.DestinationFolderID})
	response := map[string]any{"action": request.Action, "items": updated, "count": len(seen)}
	if triage.trained > 0 {
		response["trained"] = triage.trained
	}
	if len(triage.blocked) > 0 {
		response["blocked_senders"] = slices.Compact(slices.Sorted(slices.Values(triage.blocked)))
	}
	jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) applyWorkspaceItemAction(r *http.Request, itemID string, request workspaceItemActionRequest) (model.Item, error) {
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	switch request.Action {
	case "mark_read":
		return h.workspace.SetItemRead(r.Context(), actor, subject, mode, itemID, true)
	case "mark_unread":
		return h.workspace.SetItemRead(r.Context(), actor, subject, mode, itemID, false)
	case "flag":
		return h.workspace.SetItemFlagged(r.Context(), actor, subject, mode, itemID, true)
	case "unflag":
		item, err := h.workspace.SetItemFlagged(r.Context(), actor, subject, mode, itemID, false)
		if err == nil && h.mailState != nil {
			err = h.mailState.ForgetFollowUp(r.Context(), subject.ID, itemID)
		}
		return item, err
	case "move":
		if request.DestinationFolderID == "" {
			return model.Item{}, errors.New("destination_folder_id is required for move")
		}
		return h.workspace.MoveItem(r.Context(), actor, subject, mode, itemID, request.DestinationFolderID)
	case "trash":
		return h.workspace.TrashItem(r.Context(), actor, subject, mode, itemID)
	case "restore":
		return h.workspace.RestoreItem(r.Context(), actor, subject, mode, itemID)
	case "purge":
		return model.Item{}, h.workspace.DeleteItem(r.Context(), actor, subject, mode, itemID)
	default:
		return model.Item{}, fmt.Errorf("unsupported item action %q", request.Action)
	}
}

func (h *Handler) apiWorkspaceTrash(w http.ResponseWriter, r *http.Request) {
	items, err := h.workspace.ListTrash(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		apiError(w, err)
		return
	}
	folders, err := h.workspace.ListTrashedFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": items, "folders": folders})
}

const maxWorkspaceFileBytes = 50 << 20

func (h *Handler) workspaceFileLimit() int64 {
	if h.cfg != nil && h.cfg.WebdavMaxFileSize > 0 {
		return h.cfg.WebdavMaxFileSize
	}
	return maxWorkspaceFileBytes
}

func (h *Handler) apiWorkspacePutFile(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	folder, err := h.workspaceFolder(r, folderID, model.FolderTypeFiles)
	if err != nil {
		apiError(w, err)
		return
	}
	limit := h.workspaceFileLimit()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds the configured %d byte limit", limit))
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	item, err := h.workspace.PutNamedItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folder.ID, r.PathValue("name"), data, map[string]string{"Content-Type": contentType})
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "file.saved", item.ID, map[string]any{"folder_id": item.FolderID, "name": item.Name})
	jsonResponse(w, http.StatusCreated, summarizeItem(item))
}

func (h *Handler) apiWorkspaceFileContent(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeFiles); err != nil {
		apiError(w, err)
		return
	}
	contentType := item.Headers["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": item.Name}))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(item.Data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(item.Data)
}

func (h *Handler) apiWorkspaceFilePreview(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeFiles); err != nil {
		apiError(w, err)
		return
	}
	contentType := item.Headers["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	serveSafeContentPreview(w, r, item.Name, contentType, item.Size, bytes.NewReader(item.Data))
}

func (h *Handler) apiWorkspaceMoveFile(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeFiles); err != nil {
		apiError(w, err)
		return
	}
	var request struct {
		FolderID string `json:"folder_id"`
		Name     string `json:"name"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.workspaceFolder(r, request.FolderID, model.FolderTypeFiles); err != nil {
		apiError(w, err)
		return
	}
	item, err = h.workspace.MoveItemNamed(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), item.ID, request.FolderID, request.Name)
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "file.moved", item.ID, map[string]any{"folder_id": item.FolderID, "name": item.Name})
	jsonResponse(w, http.StatusOK, summarizeItem(item))
}

func (h *Handler) apiWorkspaceDeleteFile(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeFiles); err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspace.TrashItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), item.ID); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "file.trashed", item.ID, map[string]any{"folder_id": item.FolderID})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) workspaceChanged(r *http.Request, eventType, resource string, data map[string]any) {
	actor, subject := currentActor(r).ID, currentSubject(r).ID
	recipients := []string{actor}
	if subject != actor {
		recipients = append(recipients, subject)
	}
	h.audit.Log(actor, eventType, resource, map[string]string{"subject_id": subject})
	h.events.Publish(events.Event{Type: eventType, Resource: resource, Data: data, Recipients: recipients})
}

type workspaceCalendarEvent struct {
	ID           string   `json:"id"`
	FolderID     string   `json:"folder_id"`
	UID          string   `json:"uid"`
	Summary      string   `json:"summary"`
	Description  string   `json:"description,omitempty"`
	Location     string   `json:"location,omitempty"`
	Organizer    string   `json:"organizer,omitempty"`
	Attendees    []string `json:"attendees,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	Status       string   `json:"status,omitempty"`
	URL          string   `json:"url,omitempty"`
	DTStart      string   `json:"dtstart"`
	DTEnd        string   `json:"dtend,omitempty"`
	AllDay       bool     `json:"all_day"`
	Timezone     string   `json:"timezone,omitempty"`
	Recurrence   string   `json:"recurrence"`
	RecurrenceID string   `json:"recurrence_id,omitempty"`
	RRule        string   `json:"rrule,omitempty"`
	// OrganizerAddress, Participants, Sequence, Transparent, and Alarms
	// mirror the calendar projection for editors and reminders.
	OrganizerAddress string                     `json:"organizer_address,omitempty"`
	Participants     []calendarcore.Participant `json:"participants,omitempty"`
	Sequence         int                        `json:"sequence,omitempty"`
	Transparent      bool                       `json:"transparent,omitempty"`
	Alarms           []calendarcore.Alarm       `json:"alarms,omitempty"`
	// Scheduling is the owner's organizer/attendee view (single-event reads).
	Scheduling *imip.EventScheduling `json:"scheduling,omitempty"`
	// ReadOnly marks events of subscribed, generated, and free/busy-only
	// calendars, which cannot be opened or edited; FreeBusyOnly events
	// carry only a busy interval.
	ReadOnly     bool `json:"read_only,omitempty"`
	FreeBusyOnly bool `json:"free_busy_only,omitempty"`
}

func calendarEventView(itemID, folderID string, event calendarcore.Event, recurrenceID string) workspaceCalendarEvent {
	return workspaceCalendarEvent{ID: itemID, FolderID: folderID, UID: event.UID, Summary: event.Summary, Description: event.Description, Location: event.Location,
		Organizer: event.Organizer, Attendees: event.Attendees, Categories: event.Categories, Status: event.Status, URL: event.URL, DTStart: event.Start, DTEnd: event.End,
		AllDay: event.AllDay, Timezone: event.Timezone, Recurrence: event.Recurrence, RecurrenceID: recurrenceID, RRule: event.RRule, OrganizerAddress: event.OrganizerAddress,
		Participants: event.Participants, Sequence: event.Sequence, Transparent: event.Transparent, Alarms: event.Alarms}
}

type workspaceCalendarEventRequest struct {
	FolderID        string  `json:"folder_id"`
	Summary         string  `json:"summary"`
	Description     string  `json:"description,omitempty"`
	Location        string  `json:"location,omitempty"`
	Start           string  `json:"start"`
	End             string  `json:"end,omitempty"`
	AllDay          bool    `json:"all_day"`
	Timezone        string  `json:"timezone,omitempty"`
	Recurrence      *string `json:"recurrence,omitempty"`
	RecurrenceID    string  `json:"recurrence_id,omitempty"`
	RecurrenceScope string  `json:"recurrence_scope,omitempty"`
	// Attendees, Alarms (minutes before the start), and Categories replace
	// the stored values when present and are preserved when omitted.
	Attendees  *[]calendarcore.AttendeeUpdate `json:"attendees,omitempty"`
	Alarms     *[]int                         `json:"alarms,omitempty"`
	Categories *[]string                      `json:"categories,omitempty"`
}

func (h *Handler) workspaceFolder(r *http.Request, folderID string, folderType model.FolderType) (model.Folder, error) {
	folders, err := h.workspace.ListFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		return model.Folder{}, err
	}
	for _, folder := range folders {
		if folder.ID == folderID && folder.Type == folderType {
			return folder, nil
		}
	}
	return model.Folder{}, store.ErrNotFound
}

func (h *Handler) apiWorkspaceCalendarEvents(w http.ResponseWriter, r *http.Request) {
	folderIDs := r.URL.Query()["folder_id"]
	if len(folderIDs) == 0 || len(folderIDs) > 50 {
		jsonError(w, http.StatusBadRequest, "between 1 and 50 folder_id values are required")
		return
	}
	rangeStart, err := time.Parse(time.RFC3339, r.URL.Query().Get("start"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "start must be an RFC 3339 timestamp")
		return
	}
	rangeEnd, err := time.Parse(time.RFC3339, r.URL.Query().Get("end"))
	if err != nil || !rangeEnd.After(rangeStart) || rangeEnd.Sub(rangeStart) > 370*24*time.Hour {
		jsonError(w, http.StatusBadRequest, "end must be after start and the range must not exceed 370 days")
		return
	}
	events := make([]workspaceCalendarEvent, 0)
	for _, folderID := range folderIDs {
		virtual, handled, err := h.virtualCalendarEvents(r, folderID, rangeStart, rangeEnd)
		if err != nil {
			apiError(w, err)
			return
		}
		if handled {
			events = append(events, virtual...)
			continue
		}
		folder, err := h.workspaceFolder(r, folderID, model.FolderTypeCalendar)
		if err != nil {
			apiError(w, err)
			return
		}
		if !strings.EqualFold(folder.UserID, currentSubject(r).ID) {
			capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
			if err != nil {
				apiError(w, err)
				return
			}
			if !capabilities.ReadItems {
				if !capabilities.FreeBusy {
					apiError(w, service.ErrForbidden)
					return
				}
				busy, err := h.freeBusyEvents(r.Context(), folder, rangeStart, rangeEnd)
				if err != nil {
					apiError(w, err)
					return
				}
				events = append(events, busy...)
				continue
			}
		}
		// Preserve the full-item listing authorization boundary even when a
		// ready projection can answer without opening each payload.
		if folder.ItemCount > 0 {
			if _, err := h.workspace.ListFullItemPage(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folderID, 0, 1); err != nil {
				apiError(w, err)
				return
			}
		}
		projected, err := h.calendarIndex.Query(r.Context(), h.folderSpace, webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), folder, rangeStart, rangeEnd)
		if err != nil {
			apiError(w, err)
			return
		}
		for _, result := range projected {
			events = append(events, calendarEventView(result.ItemID, result.FolderID, result.Occurrence.Event, result.Occurrence.RecurrenceID))
			if len(events) >= 5000 {
				jsonResponse(w, http.StatusOK, events)
				return
			}
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].DTStart < events[j].DTStart })
	jsonResponse(w, http.StatusOK, events)
}

func (h *Handler) apiWorkspaceCalendarEvent(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	event := parseWorkspaceCalendarEvent(item)
	if h.scheduling != nil {
		scheduling := h.scheduling.Scheduling(r.Context(), folder, item)
		if !strings.EqualFold(currentActor(r).ID, folder.UserID) {
			// Answers, pending proposals, and reply comments belong to the
			// owner and their scheduling delegates, not to every reader.
			capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
			if err != nil || !capabilities.Schedule {
				scheduling.CanRespond = false
				scheduling.Proposals, scheduling.Comments = nil, nil
			}
		}
		event.Scheduling = &scheduling
	}
	jsonResponse(w, http.StatusOK, event)
}

func (h *Handler) apiWorkspaceCreateCalendarEvent(w http.ResponseWriter, r *http.Request) {
	var request workspaceCalendarEventRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	folder, err := h.workspaceFolder(r, request.FolderID, model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	uid := fmt.Sprintf("web-%d@veksel", time.Now().UTC().UnixNano())
	update, err := h.calendarUpdate(r.Context(), request, folder, "")
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := calendarcore.Create(update, uid, time.Now())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	itemID, err := h.workspace.CreateItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folder.ID, data, map[string]string{"UID": uid, "SUMMARY": strings.TrimSpace(request.Summary)})
	if err != nil {
		apiError(w, err)
		return
	}
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.event.created", item.ID, map[string]any{"folder_id": folder.ID})
	jsonResponse(w, http.StatusCreated, parseWorkspaceCalendarEvent(item))
}

func (h *Handler) apiWorkspaceUpdateCalendarEvent(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeCalendar)
	if err != nil {
		apiError(w, err)
		return
	}
	var request workspaceCalendarEventRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	projected, projectErr := calendarcore.Project(item.Data)
	uid := projected.UID
	if projectErr != nil {
		uid = ""
	}
	if uid == "" {
		uid = fmt.Sprintf("web-%d@veksel", time.Now().UTC().UnixNano())
	}
	update, err := h.calendarUpdate(r.Context(), request, folder, projected.OrganizerAddress)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var data []byte
	if request.RecurrenceID != "" {
		if request.RecurrenceScope != "occurrence" {
			jsonError(w, http.StatusBadRequest, "recurrence_scope must be occurrence when recurrence_id is set")
			return
		}
		data, err = calendarcore.UpdateOccurrence(item.Data, request.RecurrenceID, update)
	} else {
		if request.RecurrenceScope == "occurrence" {
			jsonError(w, http.StatusBadRequest, "recurrence_id is required for occurrence scope")
			return
		}
		data, err = calendarcore.UpdateExisting(item.Data, update)
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.FolderID != "" && request.FolderID != item.FolderID {
		if _, err := h.workspaceFolder(r, request.FolderID, model.FolderTypeCalendar); err != nil {
			apiError(w, err)
			return
		}
		item, err = h.workspace.MoveItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), item.ID, request.FolderID)
		if err != nil {
			apiError(w, err)
			return
		}
	}
	item, err = h.workspace.UpdateItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), item.ID, data, map[string]string{"UID": uid, "SUMMARY": strings.TrimSpace(request.Summary)})
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.event.updated", item.ID, map[string]any{"folder_id": item.FolderID})
	jsonResponse(w, http.StatusOK, parseWorkspaceCalendarEvent(item))
}

func (h *Handler) apiWorkspaceDeleteCalendarEvent(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeCalendar); err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspace.TrashItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), item.ID); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "calendar.event.trashed", item.ID, map[string]any{"folder_id": item.FolderID})
	w.WriteHeader(http.StatusNoContent)
}

func parseWorkspaceCalendarEvent(item model.Item) workspaceCalendarEvent {
	projected, err := calendarcore.Project(item.Data)
	if err != nil {
		return workspaceCalendarEvent{ID: item.ID, FolderID: item.FolderID}
	}
	return calendarEventView(item.ID, item.FolderID, projected, "")
}

func (h *Handler) apiWorkspaceContacts(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	folder, err := h.workspaceFolder(r, folderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	items, err := h.workspace.ListItems(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folderID)
	if err != nil {
		apiError(w, err)
		return
	}
	contacts := make([]workspaceListedContact, 0, len(items))
	for _, summary := range items {
		item, itemErr := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), summary.ID)
		if itemErr != nil {
			continue
		}
		contacts = append(contacts, listedContact(item, folder))
	}
	jsonResponse(w, http.StatusOK, contacts)
}

type workspaceContactPage struct {
	Contacts      []workspaceListedContact `json:"contacts"`
	Total         int64                    `json:"total"`
	NextBeforeUID uint32                   `json:"next_before_uid,omitempty"`
	NextCursor    string                   `json:"next_cursor,omitempty"`
}

type workspaceContactSummary struct {
	ID          string   `json:"id"`
	FolderID    string   `json:"folder_id"`
	FN          string   `json:"fn"`
	Kind        string   `json:"kind,omitempty"`
	MemberCount int      `json:"member_count,omitempty"`
	Org         string   `json:"org,omitempty"`
	Email       string   `json:"email,omitempty"`
	Phone       string   `json:"phone,omitempty"`
	PhotoToken  string   `json:"photo_token,omitempty"`
	Categories  []string `json:"categories,omitempty"`
}

type workspaceContactSummaryPage struct {
	Contacts   []workspaceContactSummary `json:"contacts"`
	Total      int64                     `json:"total"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

func (h *Handler) apiWorkspaceContactQuery(w http.ResponseWriter, r *http.Request) {
	if h.search == nil {
		jsonError(w, http.StatusServiceUnavailable, "contact search is unavailable")
		return
	}
	folderID := r.URL.Query().Get("folder_id")
	folder, err := h.workspaceFolder(r, folderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 250 {
			jsonError(w, http.StatusBadRequest, "limit must be between 1 and 250")
			return
		}
		limit = parsed
	}
	sortKey := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	if sortKey == "" {
		sortKey = "fn"
	}
	sortFields := map[string]string{"fn": "contact_name", "org": "contact_org", "email": "contact_email", "phone": "contact_phone"}
	sortField, ok := sortFields[sortKey]
	if !ok {
		jsonError(w, http.StatusBadRequest, "sort must be fn, org, email, or phone")
		return
	}
	if strings.EqualFold(r.URL.Query().Get("direction"), "desc") {
		sortField += "_desc"
	}
	view := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("view")))
	if view != "" && view != "full" && view != "summary" {
		jsonError(w, http.StatusBadRequest, "view must be full or summary")
		return
	}
	var categoryFilter *service.SearchFilter
	if name := strings.TrimSpace(r.URL.Query().Get("category")); name != "" {
		categoryFilter = &service.SearchFilter{Operator: service.SearchEquals, Field: "category", Value: name}
	}
	page, err := h.search.Search(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), service.SearchQuery{
		AccountID: folder.UserID, Text: strings.TrimSpace(r.URL.Query().Get("q")), FolderIDs: []string{folder.ID},
		Types: []model.FolderType{model.FolderTypeContacts}, Filter: categoryFilter, Sort: sortField, Limit: limit, Cursor: r.URL.Query().Get("cursor"),
		OmitSnippets: true,
	})
	if err != nil {
		apiError(w, err)
		return
	}
	if view == "summary" {
		result := workspaceContactSummaryPage{Contacts: make([]workspaceContactSummary, 0, len(page.Hits)), Total: int64(page.Total), NextCursor: page.NextCursor}
		for _, hit := range page.Hits {
			result.Contacts = append(result.Contacts, contactSummary(hit))
		}
		jsonResponse(w, http.StatusOK, result)
		return
	}
	result := workspaceContactPage{Contacts: make([]workspaceListedContact, 0, len(page.Hits)), Total: int64(page.Total), NextCursor: page.NextCursor}
	for _, hit := range page.Hits {
		item, itemErr := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), hit.ItemID)
		if itemErr != nil {
			continue
		}
		result.Contacts = append(result.Contacts, listedContact(item, folder))
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiWorkspaceContactPage(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	folder, err := h.workspaceFolder(r, folderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	limit, beforeUID, err := itemPageParameters(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	page, err := h.workspace.ListFullItemPage(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folderID, beforeUID, limit)
	if err != nil {
		apiError(w, err)
		return
	}
	result := workspaceContactPage{Contacts: make([]workspaceListedContact, 0, len(page.Items)), Total: page.Total, NextBeforeUID: page.NextBeforeUID}
	for _, item := range page.Items {
		result.Contacts = append(result.Contacts, listedContact(item, folder))
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiWorkspaceContact(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.URL.Query().Get("item_id"))
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, workspaceContact(item, folder))
}

func (h *Handler) apiWorkspaceContactPhoto(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeContacts); err != nil {
		apiError(w, err)
		return
	}
	contact := model.ParseVCard(item.Data)
	if len(contact.PhotoData) == 0 {
		jsonError(w, http.StatusNotFound, "contact has no photo")
		return
	}
	contentType, ok := contactPhotoContentType(contact.PhotoType, contact.PhotoData)
	if !ok {
		jsonError(w, http.StatusUnsupportedMediaType, "contact photo type is unsupported")
		return
	}
	etag := `"` + contactPhotoToken(contact.PhotoData) + `"`
	if r.URL.Query().Get("v") == contactPhotoVersion(item.UpdatedAt) {
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "private, no-cache")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(contact.PhotoData)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(contact.PhotoData)
}

type contactSuggestion struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Addressbook string `json:"addressbook"`
	FolderID    string `json:"folder_id"`
	UserID      string `json:"user_id"`
	PhotoURL    string `json:"photo_url,omitempty"`
}

// apiWorkspaceContactSuggestions searches every RBAC-visible contact folder
// in the current acting context. It intentionally returns no contact payload,
// notes, phone numbers, custom fields, or photograph bytes. Optional photo
// URLs re-enter normal FolderSpace authorization when requested.
func (h *Handler) apiWorkspaceContactSuggestions(w http.ResponseWriter, r *http.Request) {
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if query == "" {
		jsonResponse(w, http.StatusOK, []contactSuggestion{})
		return
	}
	if h.search == nil {
		jsonError(w, http.StatusServiceUnavailable, "contact search is unavailable")
		return
	}
	limit := 12
	if requested, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && requested > 0 {
		limit = min(requested, 50)
	}
	hits, err := h.searchVisibleContacts(r, query, limit, false)
	if err != nil {
		apiError(w, err)
		return
	}
	suggestions := make([]contactSuggestion, 0, limit)
	seen := make(map[string]struct{})
	for _, hit := range hits {
		for _, address := range hit.addresses() {
			email := strings.ToLower(address.Address)
			if _, duplicate := seen[email]; duplicate {
				continue
			}
			name := strings.TrimSpace(hit.Name)
			if name == "" {
				name = strings.TrimSpace(address.Name)
			}
			seen[email] = struct{}{}
			suggestions = append(suggestions, contactSuggestion{Name: name, Email: email, Addressbook: hit.Folder.Name, FolderID: hit.Folder.ID, UserID: hit.Folder.UserID, PhotoURL: contactSuggestionPhotoURL(hit.SearchHit)})
		}
	}
	sort.SliceStable(suggestions, func(i, j int) bool {
		left, right := suggestionRank(suggestions[i], query), suggestionRank(suggestions[j], query)
		if left != right {
			return left < right
		}
		if !strings.EqualFold(suggestions[i].Name, suggestions[j].Name) {
			return strings.ToLower(suggestions[i].Name) < strings.ToLower(suggestions[j].Name)
		}
		return suggestions[i].Email < suggestions[j].Email
	})
	if len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}
	jsonResponse(w, http.StatusOK, suggestions)
}

func contactSuggestionPhotoURL(hit service.SearchHit) string {
	version := contactPhotoVersion(hit.Updated)
	if !hit.ContactHasPhoto || hit.ItemID == "" || version == "" {
		return ""
	}
	return "/api/v1/workspace/contacts/" + url.PathEscape(hit.ItemID) + "/photo?v=" + url.QueryEscape(version)
}

func suggestionRank(suggestion contactSuggestion, query string) int {
	name, email := strings.ToLower(suggestion.Name), strings.ToLower(suggestion.Email)
	switch {
	case email == query:
		return 0
	case strings.HasPrefix(name, query):
		return 1
	case strings.HasPrefix(email, query):
		return 2
	default:
		return 3
	}
}

const maxContactPhotoBytes = 3 << 20
const maxContactGroupMembers = 1000

// contactEditRequest is the contact editor's payload: the contact plus
// whether the user replaced or removed its photo.
type contactEditRequest struct {
	model.Contact
	PhotoChanged bool `json:"photo_changed"`
}

func (h *Handler) apiWorkspaceCreateContact(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	folder, err := h.workspaceFolder(r, folderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	// The editor sends one payload shape for create and update; a new
	// contact has no stored photo to keep, so photo_changed is moot here.
	var request contactEditRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	contact := request.Contact
	if err := validateWorkspaceContact(&contact); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	contact.UID = fmt.Sprintf("%d@veksel", time.Now().UTC().UnixNano())
	data := model.ContactToVCard(contact)
	itemID, err := h.workspace.CreateItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folder.ID, data, map[string]string{"Name": contact.FN})
	if err != nil {
		apiError(w, err)
		return
	}
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID)
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "contact.create", itemID, map[string]string{"folder_id": folder.ID})
	jsonResponse(w, http.StatusCreated, workspaceContact(item, folder))
}

func (h *Handler) apiWorkspaceUpdateContact(w http.ResponseWriter, r *http.Request) {
	itemID := r.URL.Query().Get("item_id")
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID)
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	var request contactEditRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	contact := request.Contact
	if err := validateWorkspaceContact(&contact); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if contact.ModSeq == 0 {
		jsonError(w, http.StatusBadRequest, "contact version is required")
		return
	}
	data, err := model.PatchContactVCard(item.Data, contact, request.PhotoChanged)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "stored contact cannot be safely edited: "+err.Error())
		return
	}
	item, err = h.workspace.UpdateItemIfModSeq(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID, contact.ModSeq, data, map[string]string{"Name": contact.FN})
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "contact.update", itemID, map[string]string{"folder_id": folder.ID})
	jsonResponse(w, http.StatusOK, workspaceContact(item, folder))
}

func (h *Handler) apiWorkspaceDeleteContact(w http.ResponseWriter, r *http.Request) {
	itemID := r.URL.Query().Get("item_id")
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID)
	if err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeContacts); err != nil {
		apiError(w, err)
		return
	}
	if _, err := h.workspace.TrashItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID); err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "contact.trashed", itemID, map[string]any{"folder_id": item.FolderID})
	w.WriteHeader(http.StatusNoContent)
}

func validateWorkspaceContact(contact *model.Contact) error {
	contact.FN = strings.TrimSpace(contact.FN)
	if contact.FN == "" {
		return errors.New("contact name is required")
	}
	if len(contact.PhotoData) > maxContactPhotoBytes {
		return errors.New("contact photo must be 3 MB or smaller")
	}
	contact.Kind = strings.ToLower(strings.TrimSpace(contact.Kind))
	switch contact.Kind {
	case "", "individual":
		if len(contact.Members) > 0 {
			return errors.New("contact members require a group")
		}
		contact.Kind = ""
	case "group":
		if len(contact.Members) > maxContactGroupMembers {
			return fmt.Errorf("contact group may contain at most %d members", maxContactGroupMembers)
		}
		normalized := make([]string, 0, len(contact.Members))
		seen := make(map[string]struct{}, len(contact.Members))
		for index, member := range contact.Members {
			value, err := normalizeContactGroupMember(member)
			if err != nil {
				return fmt.Errorf("contact group member %d: %w", index+1, err)
			}
			key := value
			if strings.HasPrefix(strings.ToLower(value), "mailto:") {
				key = strings.ToLower(value)
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			normalized = append(normalized, value)
		}
		contact.Members = normalized
	default:
		return errors.New("contact kind must be individual or group")
	}
	contact.PhotoType = strings.ToUpper(strings.TrimSpace(contact.PhotoType))
	if len(contact.PhotoData) > 0 {
		switch contact.PhotoType {
		case "JPEG", "JPG", "PNG", "GIF", "WEBP":
		default:
			return errors.New("contact photo must be JPEG, PNG, GIF, or WebP")
		}
	}
	return nil
}

func normalizeContactGroupMember(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("member URI is required")
	}
	if len(value) > 2048 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", errors.New("member URI is invalid or too long")
	}
	if address, err := mail.ParseAddress(value); err == nil && strings.EqualFold(address.Address, value) {
		return "mailto:" + address.Address, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Opaque == "" && parsed.Host == "" && parsed.Path == "" {
		return "", errors.New("member must be an email address or absolute URI")
	}
	return value, nil
}

func workspaceContact(item model.Item, folder model.Folder) model.Contact {
	contact := model.ParseVCard(item.Data)
	contact.ID, contact.ItemID, contact.FolderID = item.ID, item.ID, folder.ID
	contact.ModSeq = item.ModSeq
	contact.Addressbook, contact.UserID = folder.Path, folder.UserID
	return contact
}

// workspaceListedContact is a contact in a list response: the full card
// except the photograph, which is fetched from PhotoURL (cacheable for as long
// as PhotoToken is unchanged) so a page of contacts stays small.
type workspaceListedContact struct {
	model.Contact
	PhotoToken string `json:"photo_token,omitempty"`
	PhotoURL   string `json:"photo_url,omitempty"`
}

func listedContact(item model.Item, folder model.Folder) workspaceListedContact {
	listed := workspaceListedContact{Contact: workspaceContact(item, folder)}
	if len(listed.PhotoData) > 0 {
		listed.PhotoToken = contactPhotoVersion(item.UpdatedAt)
		listed.PhotoURL = "/api/v1/workspace/contacts/" + url.PathEscape(item.ID) + "/photo?v=" + url.QueryEscape(listed.PhotoToken)
	}
	listed.PhotoData = nil
	return listed
}

func contactSummary(hit service.SearchHit) workspaceContactSummary {
	summary := workspaceContactSummary{ID: hit.ItemID, FolderID: hit.FolderID, FN: hit.Name, Kind: hit.ContactKind, MemberCount: hit.ContactMembers, Org: hit.ContactOrg, Phone: hit.ContactPhone, Categories: hit.ContactCategories}
	if len(hit.ContactEmails) > 0 {
		summary.Email = hit.ContactEmails[0]
	}
	if hit.ContactHasPhoto {
		summary.PhotoToken = contactPhotoVersion(hit.Updated)
	}
	return summary
}

func contactPhotoVersion(updated time.Time) string {
	if updated.IsZero() {
		return ""
	}
	return strconv.FormatInt(updated.UnixNano(), 36)
}

func contactPhotoToken(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:16])
}

func contactPhotoContentType(declared string, data []byte) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(declared)) {
	case "JPEG", "JPG":
		return "image/jpeg", true
	case "PNG":
		return "image/png", true
	case "GIF":
		return "image/gif", true
	case "WEBP":
		return "image/webp", true
	}
	detected := http.DetectContentType(data)
	switch detected {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
		return detected, true
	default:
		return "", false
	}
}

func (h *Handler) apiMailSubmission(w http.ResponseWriter, r *http.Request) {
	if h.mail == nil {
		jsonError(w, http.StatusServiceUnavailable, "mail submission is unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 72<<20)
	var request struct {
		service.Submission
		DraftID string `json:"draft_id,omitempty"`
	}
	if err := decodeBoundedJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.DraftID != "" && request.Attachments == nil {
		saved, err := h.workspaceDraftSubmission(r, request.DraftID)
		if err != nil {
			apiError(w, err)
			return
		}
		request.Attachments = saved.Attachments
	}
	result, err := h.mail.Submit(r.Context(), currentActor(r), request.Submission)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusAccepted, result)
}

func (h *Handler) apiWorkspaceSaveDraft(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 72<<20)
	var draft service.Submission
	if err := decodeBoundedJSON(r, &draft); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	importance, err := service.NormalizeMailImportance(draft.Importance)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	draft.Importance = importance
	if id := r.PathValue("id"); id != "" && draft.Attachments == nil {
		saved, err := h.workspaceDraftSubmission(r, id)
		if err != nil {
			apiError(w, err)
			return
		}
		draft.Attachments = saved.Attachments
	}
	headers := map[string]string{
		"From": sanitizeDraftHeader(draft.From), "To": sanitizeDraftHeader(strings.Join(draft.To, ", ")),
		"Cc": sanitizeDraftHeader(strings.Join(draft.CC, ", ")), "Bcc": sanitizeDraftHeader(strings.Join(draft.BCC, ", ")),
		"Subject": sanitizeDraftHeader(draft.Subject), "MIME-Version": "1.0", "X-Veksel-Send-Mode": string(draft.Mode),
	}
	if draft.RequireTLS {
		headers["X-Veksel-Require-TLS"] = "true"
	}
	if draft.ReadReceipt {
		headers["Disposition-Notification-To"] = headers["From"]
	}
	service.SetMailImportanceHeaders(headers, draft.Importance)
	for key, value := range headers {
		if value == "" {
			delete(headers, key)
		}
	}
	contentType, mimeBody, err := service.BuildSubmissionMIME(draft.Body, draft.HTML, draft.Attachments)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	headers["Content-Type"] = contentType
	raw := draftMessage(headers, mimeBody)
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	var item model.Item
	err = nil
	status := http.StatusCreated
	if id := r.PathValue("id"); id != "" {
		status = http.StatusOK
		item, err = h.workspace.GetItem(r.Context(), actor, subject, mode, id)
		if err == nil {
			var folder model.Folder
			folder, err = h.workspaceFolder(r, item.FolderID, model.FolderTypeMail)
			if err == nil && folder.SpecialUse != model.SpecialUseDrafts {
				err = errors.New("item is not in the Drafts folder")
			}
		}
		if err == nil {
			item, err = h.workspace.UpdateItem(r.Context(), actor, subject, mode, id, raw, headers)
		}
	} else {
		folders, listErr := h.workspace.ListFolders(r.Context(), actor, subject, mode)
		if listErr != nil {
			err = listErr
		} else {
			var drafts model.Folder
			for _, folder := range folders {
				if folder.UserID == subject.ID && folder.Type == model.FolderTypeMail && folder.SpecialUse == model.SpecialUseDrafts {
					drafts = folder
					break
				}
			}
			if drafts.ID == "" {
				err = errors.New("drafts folder is unavailable")
			} else if item.ID, err = h.workspace.CreateItem(r.Context(), actor, subject, mode, drafts.ID, raw, headers); err == nil {
				item, err = h.workspace.GetItem(r.Context(), actor, subject, mode, item.ID)
			}
		}
	}
	if err == nil {
		item, err = h.workspace.SetItemDraft(r.Context(), actor, subject, mode, item.ID, true)
	}
	if err != nil {
		apiError(w, err)
		return
	}
	h.workspaceChanged(r, "mail.draft.saved", item.ID, map[string]any{"folder_id": item.FolderID})
	jsonResponse(w, status, service.ItemSummary{ID: item.ID, FolderID: item.FolderID, Headers: item.Headers, Size: item.Size, UID: item.UID, Flags: item.Flags, InternalDate: item.InternalDate.UTC().Format(time.RFC3339)})
}

func sanitizeDraftHeader(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}

func draftMessage(headers map[string]string, body []byte) []byte {
	order := []string{"From", "To", "Cc", "Bcc", "Subject", "Importance", "X-Priority", "Priority", "Disposition-Notification-To", "MIME-Version", "Content-Type", "X-Veksel-Send-Mode", "X-Veksel-Require-TLS"}
	var message bytes.Buffer
	for _, key := range order {
		if value := headers[key]; value != "" {
			fmt.Fprintf(&message, "%s: %s\r\n", key, value)
		}
	}
	message.WriteString("\r\n")
	_, _ = message.Write(body)
	return message.Bytes()
}

func (h *Handler) apiWorkspaceDraft(w http.ResponseWriter, r *http.Request) {
	draft, err := h.workspaceDraftSubmission(r, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, draft)
}

func (h *Handler) workspaceDraftSubmission(r *http.Request, id string) (service.Submission, error) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), id)
	if err != nil {
		return service.Submission{}, err
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeMail)
	if err != nil || folder.SpecialUse != model.SpecialUseDrafts {
		return service.Submission{}, errors.New("item is not a saved draft")
	}
	draft, err := service.ParseSubmissionMIME(item.Data)
	if err != nil {
		return service.Submission{}, errors.New("saved draft is not readable")
	}
	return draft, nil
}

func (h *Handler) apiSession(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionFromContext(r.Context())
	jsonResponse(w, http.StatusOK, map[string]any{
		"actor_id": session.ActorID, "subject_id": session.SubjectID,
		"acting_mode": session.ActingMode, "expires_at": session.ExpiresAt,
		"acting_expires_at": session.ActingExpiresAt, "acting_reason": session.ActingReason,
		"is_admin": h.isAdmin(r.Context(), session.ActorID),
	})
}

func (h *Handler) apiStartDelegation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		SubjectID string `json:"subject_id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	subjectID := strings.ToLower(strings.TrimSpace(request.SubjectID))
	if err := h.canAssumeAccount(r.Context(), currentActor(r), subjectID, authz.AccountDelegate); err != nil {
		apiError(w, err)
		return
	}
	session, err := h.setRequestActing(r, subjectID, string(authz.ActingDelegation), "", time.Time{})
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(session.ActorID, "session.delegation.start", subjectID, nil)
	h.events.Publish(events.Event{Type: "session.delegation.started", Resource: subjectID, Recipients: []string{session.ActorID}})
	jsonResponse(w, http.StatusOK, session)
}

func (h *Handler) apiStartImpersonation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		SubjectID string `json:"subject_id"`
		Password  string `json:"password"`
		Reason    string `json:"reason"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.SubjectID = strings.ToLower(strings.TrimSpace(request.SubjectID))
	request.Reason = strings.TrimSpace(request.Reason)
	if len(request.Reason) < 3 {
		jsonError(w, http.StatusBadRequest, "an impersonation reason is required")
		return
	}
	if !h.confirmPassword(r.Context(), currentActor(r).ID, request.Password) {
		jsonError(w, http.StatusForbidden, "password confirmation failed")
		return
	}
	if err := h.canAssumeAccount(r.Context(), currentActor(r), request.SubjectID, authz.AccountImpersonate); err != nil {
		apiError(w, err)
		return
	}
	session, err := h.setRequestActing(r, request.SubjectID, string(authz.ActingImpersonation), request.Reason, time.Now().UTC().Add(15*time.Minute))
	if err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(session.ActorID, "session.impersonation.start", request.SubjectID, map[string]string{"reason": request.Reason, "expires_at": session.ActingExpiresAt.Format(time.RFC3339)})
	h.events.Publish(events.Event{Type: "session.impersonation.started", Resource: request.SubjectID, Recipients: []string{session.ActorID}})
	jsonResponse(w, http.StatusOK, session)
}

func (h *Handler) apiStopActing(w http.ResponseWriter, r *http.Request) {
	previous, _ := sessionFromContext(r.Context())
	session, err := h.setRequestActing(r, "", "", "", time.Time{})
	if err != nil {
		apiError(w, err)
		return
	}
	if previous.ActingMode != "" {
		h.audit.Log(session.ActorID, "session."+previous.ActingMode+".stop", previous.SubjectID, map[string]string{"reason": previous.ActingReason})
		h.events.Publish(events.Event{Type: "session.acting.stopped", Resource: previous.SubjectID, Recipients: []string{session.ActorID}})
	}
	jsonResponse(w, http.StatusOK, session)
}

func (h *Handler) canAssumeAccount(ctx context.Context, actor model.PrincipalRef, subjectID string, action authz.Action) error {
	if subjectID == "" || subjectID == actor.ID {
		return errors.New("a different target account is required")
	}
	subject, err := h.users.Get(ctx, subjectID)
	if err != nil || !subject.Enabled {
		return store.ErrNotFound
	}
	decision, err := h.authorizer.Check(ctx, authz.Request{
		Actor: actor, Subject: actor, Action: action,
		Resource: model.ResourceRef{Kind: model.ResourceAccount, ID: subjectID},
	})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: %s", service.ErrForbidden, decision.Reason)
	}
	return nil
}

func (h *Handler) setRequestActing(r *http.Request, subjectID, mode, reason string, expiresAt time.Time) (model.Session, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return model.Session{}, store.ErrNotFound
	}
	return h.sessions.SetActing(r.Context(), cookie.Value, subjectID, mode, reason, expiresAt)
}

func (h *Handler) apiRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.authorization.ListRoles(r.Context(), currentActor(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, roles)
}

func (h *Handler) apiCreateRole(w http.ResponseWriter, r *http.Request) {
	var role model.Role
	if err := decodeJSON(r, &role); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.authorization.CreateRole(r.Context(), currentActor(r), role); err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, role)
}

func (h *Handler) apiGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.authorization.ListGroups(r.Context(), currentActor(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, groups)
}

func (h *Handler) apiSetGroup(w http.ResponseWriter, r *http.Request) {
	var group model.Group
	if err := decodeJSON(r, &group); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.authorization.SetGroup(r.Context(), currentActor(r), group); err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, group)
}

func (h *Handler) apiManagedGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := h.authorization.ListManagedGrants(r.Context(), currentActor(r))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grants)
}

func (h *Handler) apiManagedGrant(w http.ResponseWriter, r *http.Request) {
	grant, err := h.authorization.GetManagedGrant(r.Context(), currentActor(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grant)
}

func (h *Handler) apiUpdateManagedGrant(w http.ResponseWriter, r *http.Request) {
	var update service.ManagedGrantUpdate
	if err := decodeJSON(r, &update); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	grant, err := h.authorization.UpdateManagedGrant(r.Context(), currentActor(r), r.PathValue("id"), update)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grant)
}

func (h *Handler) apiManagedGrantEffectiveAccess(w http.ResponseWriter, r *http.Request) {
	effective, err := h.authorization.EffectiveManagedGrant(r.Context(), currentActor(r), r.PathValue("id"), time.Now().UTC())
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, effective)
}

func (h *Handler) apiDeleteManagedGrant(w http.ResponseWriter, r *http.Request) {
	if err := h.authorization.DeleteManagedGrant(r.Context(), currentActor(r), r.PathValue("id")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiFolderGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := h.authorization.ListFolderGrants(r.Context(), currentActor(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grants)
}

func (h *Handler) apiCreateFolderGrant(w http.ResponseWriter, r *http.Request) {
	var binding model.PolicyBinding
	if err := decodeJSON(r, &binding); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	binding.ID = ""
	binding.Resource = model.ResourceRef{Kind: model.ResourceFolder, ID: r.PathValue("id")}
	created, err := h.authorization.CreateFolderGrant(r.Context(), currentActor(r), binding)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, created)
}

func (h *Handler) apiDeleteFolderGrant(w http.ResponseWriter, r *http.Request) {
	err := h.authorization.DeleteFolderGrant(r.Context(), currentActor(r), r.PathValue("id"), r.PathValue("grantID"))
	if err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiIdentityGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := h.authorization.ListIdentityGrants(r.Context(), currentActor(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grants)
}

func (h *Handler) apiCreateIdentityGrant(w http.ResponseWriter, r *http.Request) {
	var binding model.PolicyBinding
	if err := decodeJSON(r, &binding); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	binding.ID = ""
	binding.Resource = model.ResourceRef{Kind: model.ResourceIdentity, ID: r.PathValue("id")}
	created, err := h.authorization.CreateIdentityGrant(r.Context(), currentActor(r), binding)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, created)
}

func (h *Handler) apiDeleteIdentityGrant(w http.ResponseWriter, r *http.Request) {
	if err := h.authorization.DeleteIdentityGrant(r.Context(), currentActor(r), r.PathValue("id"), r.PathValue("grantID")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiAccountDelegations(w http.ResponseWriter, r *http.Request) {
	grants, err := h.authorization.ListAccountDelegations(r.Context(), currentActor(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grants)
}

func (h *Handler) apiCreateAccountDelegation(w http.ResponseWriter, r *http.Request) {
	var binding model.PolicyBinding
	if err := decodeJSON(r, &binding); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	binding.ID = ""
	binding.Resource = model.ResourceRef{Kind: model.ResourceAccount, ID: r.PathValue("id")}
	created, err := h.authorization.CreateAccountDelegation(r.Context(), currentActor(r), binding)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, created)
}

func (h *Handler) apiDeleteAccountDelegation(w http.ResponseWriter, r *http.Request) {
	if err := h.authorization.DeleteAccountDelegation(r.Context(), currentActor(r), r.PathValue("id"), r.PathValue("grantID")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiAccountSearchGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := h.authorization.ListAccountSearchGrants(r.Context(), currentActor(r), r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, grants)
}

func (h *Handler) apiCreateAccountSearchGrant(w http.ResponseWriter, r *http.Request) {
	var binding model.PolicyBinding
	if err := decodeJSON(r, &binding); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	binding.ID = ""
	binding.Resource = model.ResourceRef{Kind: model.ResourceAccount, ID: r.PathValue("id")}
	created, err := h.authorization.CreateAccountSearchGrant(r.Context(), currentActor(r), binding)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, created)
}

func (h *Handler) apiDeleteAccountSearchGrant(w http.ResponseWriter, r *http.Request) {
	if err := h.authorization.DeleteAccountSearchGrant(r.Context(), currentActor(r), r.PathValue("id"), r.PathValue("grantID")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiSearch(w http.ResponseWriter, r *http.Request) {
	if h.search == nil {
		jsonError(w, http.StatusServiceUnavailable, "search is unavailable")
		return
	}
	var query service.SearchQuery
	if err := decodeJSON(r, &query); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.search.Search(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), query)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, result)
}

func (h *Handler) apiSearchStatus(w http.ResponseWriter, r *http.Request) {
	if h.search == nil {
		jsonError(w, http.StatusServiceUnavailable, "search is unavailable")
		return
	}
	status, err := h.search.SearchStatus(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), r.URL.Query().Get("account_id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, status)
}

func (h *Handler) apiSearchRebuild(w http.ResponseWriter, r *http.Request) {
	if h.search == nil {
		jsonError(w, http.StatusServiceUnavailable, "search is unavailable")
		return
	}
	var request struct {
		AccountID string `json:"account_id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.search.RequestSearchRebuild(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), request.AccountID); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) apiAuthorizationCheck(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Action   authz.Action      `json:"action"`
		Resource model.ResourceRef `json:"resource"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := currentActor(r)
	decision, err := h.authorizer.Check(r.Context(), authz.Request{Actor: actor, Subject: actor, Action: request.Action, Resource: request.Resource})
	if err != nil {
		apiError(w, err)
		return
	}
	if !h.isAdmin(r.Context(), actor.ID) {
		decision.MatchedBindingIDs = nil
	}
	jsonResponse(w, http.StatusOK, decision)
}

func (h *Handler) requireAPISession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		session, err := h.sessions.Get(r.Context(), cookie.Value)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		user, err := h.users.Get(r.Context(), session.ActorID)
		if err != nil || !user.Enabled {
			jsonError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		session, err = h.revalidateActing(r.Context(), cookie.Value, session)
		if err != nil {
			jsonError(w, http.StatusServiceUnavailable, "authorization state unavailable")
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), session)))
	})
}

// requireAPICSRF protects session-authenticated changes. Key-authenticated
// requests skip it: the key is not an ambient credential.
func (h *Handler) requireAPICSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, byKey := apiKeyFromContext(r.Context()); byKey {
			next.ServeHTTP(w, r)
			return
		}
		session, ok := sessionFromContext(r.Context())
		if !ok || !h.sessions.ValidCSRF(session, r.Header.Get("X-CSRF-Token")) {
			jsonError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withSession(ctx context.Context, session model.Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

func currentActor(r *http.Request) model.PrincipalRef {
	session, _ := sessionFromContext(r.Context())
	return model.PrincipalRef{Kind: model.PrincipalUser, ID: session.ActorID}
}

func currentSubject(r *http.Request) model.PrincipalRef {
	session, _ := sessionFromContext(r.Context())
	return model.PrincipalRef{Kind: model.PrincipalUser, ID: session.SubjectID}
}

func currentActingMode(r *http.Request) authz.ActingMode {
	session, _ := sessionFromContext(r.Context())
	return authz.ActingMode(session.ActingMode)
}

func decodeJSON(r *http.Request, value any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return nil
}

// decodeBoundedJSON is for the few endpoints that intentionally accept
// payloads larger than the API-wide 1 MiB default. The handler must install an
// http.MaxBytesReader before calling it.
func decodeBoundedJSON(r *http.Request, value any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func apiError(w http.ResponseWriter, err error) {
	var quota *sendguard.QuotaError
	switch {
	case errors.As(err, &quota):
		w.Header().Set("Retry-After", strconv.Itoa(max(int(quota.RetryAfter.Seconds()), 1)))
		jsonError(w, http.StatusTooManyRequests, quota.Error())
	case errors.Is(err, service.ErrSearchUnavailable):
		w.Header().Set("Retry-After", "2")
		jsonError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, service.ErrItemHistoryUnavailable):
		jsonError(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, account.ErrTemporarilyUnavailable):
		w.Header().Set("Retry-After", "5")
		jsonError(w, http.StatusServiceUnavailable, "account is temporarily unavailable")
	case errors.Is(err, service.ErrForbidden):
		jsonError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, service.ErrLegalHold):
		jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrExists):
		jsonError(w, http.StatusConflict, "already exists")
	case errors.Is(err, store.ErrPreconditionFailed):
		jsonError(w, http.StatusConflict, "resource changed; reload and try again")
	case errors.Is(err, service.ErrItemUpdateConflict):
		jsonError(w, http.StatusConflict, "contact changed; reload the current version and try again")
	case errors.Is(err, model.ErrItemHistoryConflict), errors.Is(err, model.ErrDirectoryPassword), errors.Is(err, model.ErrResourceAccount), errors.Is(err, model.ErrDomainLimit):
		jsonError(w, http.StatusConflict, err.Error())
	default:
		jsonError(w, http.StatusBadRequest, err.Error())
	}
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}
