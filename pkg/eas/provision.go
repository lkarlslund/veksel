package eas

import (
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"time"
)

// Global status codes shared by every command (MS-ASCMD 2.2.2).
const (
	statusInvalidContent       = "101"
	statusInvalidWBXML         = "102"
	statusInvalidMIME          = "107"
	statusServerError          = "110"
	statusServerErrorRetry     = "111"
	statusMailSubmissionFailed = "120"
	statusRemoteWipeRequested  = "140"
	statusDeviceNotProvisioned = "142"
	statusPolicyRefresh        = "143"
	statusInvalidPolicyKey     = "144"
	statusItemNotFound         = "150"
)

const provisioningPolicyType = "MS-EAS-Provisioning-WBXML"

// statusRoots names the element that carries a command's top-level Status.
// Commands without one fall back to HTTP 449, which every client honors.
var statusRoots = map[string]struct {
	page byte
	tag  string
}{
	"FolderSync": {7, "FolderSync"}, "FolderCreate": {7, "FolderCreate"}, "FolderDelete": {7, "FolderDelete"},
	"FolderUpdate": {7, "FolderUpdate"}, "Sync": {0, "Sync"}, "GetItemEstimate": {6, "GetItemEstimate"},
	"Ping": {13, "Ping"}, "ItemOperations": {20, "ItemOperations"}, "Settings": {18, "Settings"},
	"Search": {15, "Search"}, "SendMail": {21, "SendMail"}, "SmartReply": {21, "SmartReply"},
	"SmartForward": {21, "SmartForward"}, "ResolveRecipients": {10, "ResolveRecipients"},
	"Find": {25, "Find"}, "MeetingResponse": {8, "MeetingResponse"},
}

func statusResponse(command, status string) *Node {
	root, ok := statusRoots[command]
	if !ok {
		return nil
	}
	return E(root.page, root.tag, T(root.page, "Status", status))
}

// policyBlock enforces the device policy contract of MS-ASPROV 3.2.5.1:
// a pending remote wipe and a stale X-MS-PolicyKey both send the device
// back through Provision. Devices that never provisioned (no key, or the
// key 0) are allowed, because Veksel publishes no restricting policy.
// Protocol 14.0 and later carry the reason as a command status; older
// clients, and commands without a top-level Status, get HTTP 449.
func policyBlock(state *DeviceState, command *commandContext) (*Node, error) {
	if command.line.Command == "Provision" {
		return nil, nil
	}
	status := ""
	switch {
	case state.WipePending:
		status = statusRemoteWipeRequested
	case command.line.PolicyKey != "" && command.line.PolicyKey != "0" && command.line.PolicyKey != state.PolicyKey:
		status = statusInvalidPolicyKey
	default:
		return nil, nil
	}
	if command.version(14, 0) {
		if response := statusResponse(command.line.Command, status); response != nil {
			return response, nil
		}
	}
	return nil, errRetryWithProvision
}

func (h *Handler) provision(command *commandContext) (*Node, error) {
	state, request := command.state, command.request
	response := E(14, "Provision", T(14, "Status", "1"))
	if request.Child("DeviceInformation") != nil {
		response.Children = append(response.Children, E(18, "DeviceInformation", T(18, "Status", "1")))
	}
	if request.Child("RemoteWipe") != nil || request.Child("AccountOnlyRemoteWipe") != nil {
		// The device reports the outcome of a wipe it performed. The wipe
		// stays pending, so a restored device is wiped again until an
		// administrator removes the partnership.
		if state.WipePending && state.WipeAcknowledgedAt.IsZero() {
			state.WipeAcknowledgedAt = time.Now().UTC()
		}
		response.Children = append(response.Children, E(14, "RemoteWipe"))
		return response, nil
	}
	if state.WipePending {
		response.Children = append(response.Children, E(14, "RemoteWipe"))
		return response, nil
	}
	policyRequest := request.Child("Policies").Child("Policy")
	if policyRequest == nil {
		response.Children[0].Text = "2"
		return response, nil
	}
	policyType := childText(policyRequest, "PolicyType")
	if policyType != provisioningPolicyType {
		response.Children = append(response.Children, E(14, "Policies", E(14, "Policy",
			T(14, "PolicyType", policyType), T(14, "Status", "3"))))
		return response, nil
	}
	acknowledged := childText(policyRequest, "PolicyKey")
	if acknowledged == "" {
		// Phase one: hand out a temporary key with the policy document.
		state.PendingPolicyKey = nextPolicyKey()
		response.Children = append(response.Children, E(14, "Policies", E(14, "Policy",
			T(14, "PolicyType", provisioningPolicyType), T(14, "Status", "1"),
			T(14, "PolicyKey", state.PendingPolicyKey), E(14, "Data", provisioningDocument()))))
		return response, nil
	}
	// Phase two: the device acknowledges the temporary key and receives
	// the permanent one it sends as X-MS-PolicyKey from now on. A repeated
	// acknowledgement (lost response) returns the same permanent key.
	switch acknowledged {
	case state.PendingPolicyKey:
		state.PolicyKey = nextPolicyKey()
		state.PendingPolicyKey = ""
	case state.PolicyKey:
	default:
		response.Children = append(response.Children, E(14, "Policies", E(14, "Policy",
			T(14, "PolicyType", provisioningPolicyType), T(14, "Status", "5"))))
		return response, nil
	}
	response.Children = append(response.Children, E(14, "Policies", E(14, "Policy",
		T(14, "PolicyType", provisioningPolicyType), T(14, "Status", "1"), T(14, "PolicyKey", state.PolicyKey))))
	return response, nil
}

// provisioningDocument is a permissive policy: no device password, HTML
// mail and attachments allowed, no size or age caps. Clients still require
// a document with these members to finish provisioning; an empty one makes
// some Android clients loop on Provision.
func provisioningDocument() *Node {
	settings := []struct{ tag, value string }{
		{"DevicePasswordEnabled", "0"}, {"AlphanumericDevicePasswordRequired", "0"},
		{"PasswordRecoveryEnabled", "0"}, {"RequireStorageCardEncryption", "0"},
		{"AttachmentsEnabled", "1"}, {"MinDevicePasswordLength", ""},
		{"MaxInactivityTimeDeviceLock", ""}, {"MaxDevicePasswordFailedAttempts", ""},
		{"MaxAttachmentSize", ""}, {"AllowSimpleDevicePassword", "1"},
		{"DevicePasswordExpiration", ""}, {"DevicePasswordHistory", "0"},
		{"AllowStorageCard", "1"}, {"AllowCamera", "1"}, {"RequireDeviceEncryption", "0"},
		{"AllowUnsignedApplications", "1"}, {"AllowUnsignedInstallationPackages", "1"},
		{"MinDevicePasswordComplexCharacters", "1"}, {"AllowWiFi", "1"},
		{"AllowTextMessaging", "1"}, {"AllowPOPIMAPEmail", "1"}, {"AllowBluetooth", "2"},
		{"AllowIrDA", "1"}, {"RequireManualSyncWhenRoaming", "0"}, {"AllowDesktopSync", "1"},
		{"MaxCalendarAgeFilter", "0"}, {"AllowHTMLEmail", "1"}, {"MaxEmailAgeFilter", "0"},
		{"MaxEmailBodyTruncationSize", "-1"}, {"MaxEmailHTMLBodyTruncationSize", "-1"},
		{"RequireSignedSMIMEMessages", "0"}, {"RequireEncryptedSMIMEMessages", "0"},
		{"RequireSignedSMIMEAlgorithm", "0"}, {"RequireEncryptionSMIMEAlgorithm", "0"},
		{"AllowSMIMEEncryptionAlgorithmNegotiation", "2"}, {"AllowSMIMESoftCerts", "1"},
		{"AllowBrowser", "1"}, {"AllowConsumerEmail", "1"}, {"AllowRemoteDesktop", "1"},
		{"AllowInternetSharing", "1"},
	}
	document := E(14, "EASProvisionDoc")
	for _, setting := range settings {
		document.Children = append(document.Children, T(14, setting.tag, setting.value))
	}
	return document
}

// nextPolicyKey returns a non-zero unsigned 32-bit key: base64-encoded
// request lines carry the policy key as a binary uint32.
func nextPolicyKey() string {
	var value [4]byte
	for {
		_, _ = rand.Read(value[:])
		if key := binary.LittleEndian.Uint32(value[:]); key != 0 {
			return strconv.FormatUint(uint64(key), 10)
		}
	}
}
