package model

import "testing"

func TestNamespacesAreCompleteAndUnique(t *testing.T) {
	want := []string{
		NSDomains, NSOutboundRoutes, NSUsers, NSEmails, NSRecipientAliases, NSUserAliases, NSFolders, NSFolderIndexes, NSItems, NSItemHistory,
		NSVacationReplies, NSAudit, NSACL, NSQueue, NSMessageTrace, NSMessageTraceIndexes, NSHealthAlerts, NSChanges, NSMetadata,
		NSCerts, NSACMECache, NSAPIKeys, NSAppPasswords, NSAccountVerifications, NSScheduledSubmissions, NSMailItemState, NSWebhooks,
		NSOAuth2Clients, NSOAuth2Tokens,
		NSPasswordResets, NSWebhookDeliveries, NSWebhookOutbox, NSSessions, NSSecondFactors,
		NSRoles, NSGroups, NSPolicyBindings, NSPolicyIndexes,
		NSAuthorizationMetadata, NSSettings, NSMailPolicies, NSGreylisting, NSMTASTSPolicies, NSTLSRPT, NSDMARCAggregates, NSShareLinks,
		NSAutomationRules, NSAutomationRuns, NSAutomationEvidence, NSIMIPState, NSBackupSchedule, NSDNSZones, NSDNSHostedZones, NSBans,
		NSSenderRoutes, NSAddressRewrites, NSJournalRules, NSBCCRules, NSPGPKeys, NSCalendarFeeds, NSSchema,
	}
	got := Namespaces()
	if len(got) != len(want) {
		t.Fatalf("Namespaces has %d entries, want %d", len(got), len(want))
	}
	seen := make(map[string]bool, len(got))
	for _, namespace := range got {
		if namespace == "" {
			t.Fatal("Namespaces contains an empty name")
		}
		if seen[namespace] {
			t.Fatalf("Namespaces contains duplicate %q", namespace)
		}
		seen[namespace] = true
	}
	for _, namespace := range want {
		if !seen[namespace] {
			t.Fatalf("Namespaces omitted %q", namespace)
		}
	}
}
