package autodiscover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

const (
	soap11Namespace            = "http://schemas.xmlsoap.org/soap/envelope/"
	soap12Namespace            = "http://www.w3.org/2003/05/soap-envelope"
	autodiscoverHTTPNamespace  = "http://schemas.microsoft.com/exchange/2010/Autodiscover"
	autodiscoverHTTPSNamespace = "https://schemas.microsoft.com/exchange/2010/Autodiscover"
	wsa2004Namespace           = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	wsa2005Namespace           = "http://www.w3.org/2005/08/addressing"

	maxSOAPBodyBytes = 1 << 20
	maxSOAPUsers     = 32
	maxSOAPSettings  = 64
	maxSOAPDepth     = 24
	maxSOAPNodes     = 512
)

var knownSOAPUserSettings = func() map[string]struct{} {
	// UserSettingName values published for the Exchange SOAP Autodiscover
	// contract. Keeping unsupported names distinct from unknown input lets
	// clients make the protocol-defined SettingIsNotAvailable decision.
	names := strings.Fields(`
		UserDisplayName UserDN UserDeploymentId InternalMailboxServer
		InternalRpcClientServer InternalMailboxServerDN InternalEcpUrl
		InternalEcpVoicemailUrl InternalEcpEmailSubscriptionsUrl
		InternalEcpTextMessagingUrl InternalEcpDeliveryReportUrl
		InternalEcpRetentionPolicyTagsUrl InternalEcpPublishingUrl
		InternalEcpPhotoUrl InternalEcpConnectUrl InternalEcpTeamMailboxUrl
		InternalEcpTeamMailboxCreatingUrl InternalEcpTeamMailboxEditingUrl
		InternalEcpTeamMailboxHidingUrl InternalEcpExtensionInstallationUrl
		InternalEwsUrl InternalEmwsUrl InternalOABUrl InternalPhotosUrl
		InternalUMUrl InternalWebClientUrls MailboxDN PublicFolderServer
		ActiveDirectoryServer ExternalMailboxServer
		ExternalMailboxServerRequiresSSL ExternalMailboxServerAuthenticationMethods
		EcpVoicemailUrlFragment EcpEmailSubscriptionsUrlFragment
		EcpTextMessagingUrlFragment EcpDeliveryReportUrlFragment
		EcpRetentionPolicyTagsUrlFragment EcpPublishingUrlFragment
		EcpPhotoUrlFragment EcpConnectUrlFragment EcpTeamMailboxUrlFragment
		EcpTeamMailboxCreatingUrlFragment EcpTeamMailboxEditingUrlFragment
		EcpExtensionInstallationUrlFragment ExternalEcpUrl
		ExternalEcpVoicemailUrl ExternalEcpEmailSubscriptionsUrl
		ExternalEcpTextMessagingUrl ExternalEcpDeliveryReportUrl
		ExternalEcpRetentionPolicyTagsUrl ExternalEcpPublishingUrl
		ExternalEcpPhotoUrl ExternalEcpConnectUrl ExternalEcpTeamMailboxUrl
		ExternalEcpTeamMailboxCreatingUrl ExternalEcpTeamMailboxEditingUrl
		ExternalEcpTeamMailboxHidingUrl ExternalEcpExtensionInstallationUrl
		ExternalEwsUrl ExternalEmwsUrl ExternalOABUrl ExternalPhotosUrl
		ExternalUMUrl ExternalWebClientUrls CrossOrganizationSharingEnabled
		AlternateMailboxes CasVersion EwsSupportedSchemas InternalPop3Connections
		ExternalPop3Connections InternalImap4Connections ExternalImap4Connections
		InternalSmtpConnections ExternalSmtpConnections InternalServerExclusiveConnect
		ExternalEwsVersion MobileMailboxPolicy DocumentSharingLocations UserMSOnline
		InternalMailboxServerAuthenticationMethods MailboxVersion SPMySiteHostURL
		SiteMailboxCreationURL InternalRpcHttpServer
		InternalRpcHttpConnectivityRequiresSsl InternalRpcHttpAuthenticationMethod
		ExternalServerExclusiveConnect ExchangeRpcUrl ShowGalAsDefaultView
		AutoDiscoverSMTPAddress InteropExternalEwsUrl InteropExternalEwsVersion
		PublicFolderInformation RedirectUrl EwsPartnerUrl CertPrincipalName
		GroupingInformation`)
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}()

type soapNode struct {
	name     xml.Name
	text     strings.Builder
	children []*soapNode
}

type soapRequest struct {
	version             string
	namespace           string
	addressingNamespace string
	mailboxes           []string
	settings            []string
}

type soapConnection struct {
	host       string
	port       int
	encryption string
}

type soapSetting struct {
	name        string
	value       string
	connections []soapConnection
}

type soapSettingError struct {
	name    string
	code    string
	message string
}

type soapUserResponse struct {
	code     string
	message  string
	settings []soapSetting
	errors   []soapSettingError
}

func (h *Handler) handleMicrosoftSOAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	version, mediaAction, err := soapMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "unsupported SOAP content type", http.StatusUnsupportedMediaType)
		return
	}
	request, err := parseSOAPRequest(r.Body, version, firstNonEmpty(mediaAction, trimSOAPAction(r.Header.Get("SOAPAction"))))
	if err != nil {
		writeSOAPFault(w, version, "InvalidRequest", err.Error(), http.StatusBadRequest)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok || h.authenticate == nil {
		writeAutodiscoverUnauthorized(w)
		return
	}
	userID, err := h.authenticate(r.Context(), username, password)
	if err != nil {
		writeAutodiscoverUnauthorized(w)
		return
	}
	user, err := h.userStore.Get(r.Context(), userID)
	if err != nil || !user.Enabled {
		writeAutodiscoverUnauthorized(w)
		return
	}
	identities, err := h.userStore.ListEmailAddressesForUser(r.Context(), user.ID)
	if err != nil {
		writeSOAPFault(w, version, "InternalServerError", "unable to resolve account identities", http.StatusInternalServerError)
		return
	}
	owned := make(map[string]bool, len(identities))
	primary := ""
	for _, identity := range identities {
		if !identity.Enabled {
			continue
		}
		address := strings.ToLower(strings.TrimSpace(identity.ID))
		owned[address] = true
		if identity.Primary && primary == "" {
			primary = address
		}
	}
	if primary == "" {
		for _, identity := range identities {
			address := strings.ToLower(strings.TrimSpace(identity.ID))
			if owned[address] {
				primary = address
				break
			}
		}
	}

	responses := make([]soapUserResponse, 0, len(request.mailboxes))
	for _, mailbox := range request.mailboxes {
		if !owned[strings.ToLower(mailbox)] {
			responses = append(responses, soapUserResponse{code: "InvalidUser", message: "The requested user is invalid."})
			continue
		}
		responses = append(responses, h.soapSettings(user.ID, user.DisplayName, primary, request.settings))
	}
	writeSOAPResponse(w, request, responses)
}

func soapMediaType(raw string) (version, action string, err error) {
	mediaType, params, parseErr := mime.ParseMediaType(raw)
	if parseErr != nil {
		return "", "", parseErr
	}
	switch strings.ToLower(mediaType) {
	case "text/xml":
		return soap11Namespace, "", nil
	case "application/soap+xml":
		return soap12Namespace, strings.TrimSpace(params["action"]), nil
	default:
		return "", "", errors.New("unsupported SOAP media type")
	}
}

func parseSOAPRequest(body io.Reader, contentVersion, httpAction string) (soapRequest, error) {
	limited := io.LimitReader(body, maxSOAPBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return soapRequest{}, fmt.Errorf("read request: %w", err)
	}
	if len(raw) > maxSOAPBodyBytes {
		return soapRequest{}, errors.New("SOAP request exceeds the size limit")
	}
	root, err := parseSOAPTree(raw)
	if err != nil {
		return soapRequest{}, err
	}
	if root.name.Local != "Envelope" || root.name.Space != contentVersion {
		return soapRequest{}, errors.New("SOAP envelope does not match the content type")
	}

	var header, bodyNode *soapNode
	for index, child := range root.children {
		switch {
		case child.name == (xml.Name{Space: contentVersion, Local: "Header"}) && header == nil && index == 0:
			header = child
		case child.name == (xml.Name{Space: contentVersion, Local: "Body"}) && bodyNode == nil && index == len(root.children)-1:
			bodyNode = child
		default:
			return soapRequest{}, fmt.Errorf("unexpected SOAP envelope element %q", child.name.Local)
		}
	}
	if bodyNode == nil || len(bodyNode.children) != 1 {
		return soapRequest{}, errors.New("SOAP body must contain exactly one operation")
	}
	message := bodyNode.children[0]
	if message.name.Local != "GetUserSettingsRequestMessage" || !isAutodiscoverNamespace(message.name.Space) {
		return soapRequest{}, errors.New("unsupported SOAP operation")
	}
	namespace := message.name.Space
	expectedAction := namespace + "/Autodiscover/GetUserSettings"
	headerAction := ""
	addressingNamespace := wsa2005Namespace
	if header != nil {
		for _, child := range header.children {
			if child.name.Local == "Action" && (child.name.Space == wsa2004Namespace || child.name.Space == wsa2005Namespace) {
				if headerAction != "" {
					return soapRequest{}, errors.New("multiple WS-Addressing actions")
				}
				headerAction = strings.TrimSpace(child.text.String())
				addressingNamespace = child.name.Space
			}
		}
	}
	if httpAction != "" && httpAction != expectedAction {
		return soapRequest{}, errors.New("SOAP action does not match GetUserSettings")
	}
	if headerAction != "" && headerAction != expectedAction {
		return soapRequest{}, errors.New("WS-Addressing action does not match GetUserSettings")
	}
	if httpAction != "" && headerAction != "" && httpAction != headerAction {
		return soapRequest{}, errors.New("conflicting SOAP actions")
	}
	if httpAction == "" && headerAction == "" {
		return soapRequest{}, errors.New("GetUserSettings action is required")
	}
	if len(message.children) != 1 || message.children[0].name != (xml.Name{Space: namespace, Local: "Request"}) {
		return soapRequest{}, errors.New("GetUserSettings must contain exactly one Request")
	}
	requestNode := message.children[0]
	usersNode, settingsNode, err := exactRequestChildren(requestNode, namespace)
	if err != nil {
		return soapRequest{}, err
	}
	mailboxes, err := parseMailboxes(usersNode, namespace)
	if err != nil {
		return soapRequest{}, err
	}
	settings, err := parseRequestedSettings(settingsNode, namespace)
	if err != nil {
		return soapRequest{}, err
	}
	return soapRequest{version: contentVersion, namespace: namespace, addressingNamespace: addressingNamespace, mailboxes: mailboxes, settings: settings}, nil
}

func parseSOAPTree(raw []byte) (*soapNode, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	var root *soapNode
	stack := make([]*soapNode, 0, maxSOAPDepth)
	nodes := 0
	sawDeclaration := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode SOAP XML: %w", err)
		}
		switch typed := token.(type) {
		case xml.StartElement:
			if len(stack) >= maxSOAPDepth {
				return nil, errors.New("SOAP XML nesting exceeds the limit")
			}
			nodes++
			if nodes > maxSOAPNodes {
				return nil, errors.New("SOAP XML element count exceeds the limit")
			}
			node := &soapNode{name: typed.Name}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("SOAP request contains multiple documents")
				}
				root = node
			} else {
				stack[len(stack)-1].children = append(stack[len(stack)-1].children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unexpected SOAP end element")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write([]byte(typed))
			} else if strings.TrimSpace(string(typed)) != "" {
				return nil, errors.New("non-whitespace data outside SOAP envelope")
			}
		case xml.Directive:
			return nil, errors.New("XML directives are not allowed")
		case xml.ProcInst:
			if !strings.EqualFold(typed.Target, "xml") || root != nil || sawDeclaration {
				return nil, errors.New("XML processing instructions are not allowed")
			}
			sawDeclaration = true
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errors.New("SOAP XML is incomplete")
	}
	return root, nil
}

func exactRequestChildren(request *soapNode, namespace string) (*soapNode, *soapNode, error) {
	var users, settings *soapNode
	for _, child := range request.children {
		switch child.name {
		case xml.Name{Space: namespace, Local: "Users"}:
			if users != nil {
				return nil, nil, errors.New("duplicate Users element")
			}
			users = child
		case xml.Name{Space: namespace, Local: "RequestedSettings"}:
			if settings != nil {
				return nil, nil, errors.New("duplicate RequestedSettings element")
			}
			settings = child
		default:
			return nil, nil, fmt.Errorf("unexpected GetUserSettings request element %q", child.name.Local)
		}
	}
	if users == nil || settings == nil {
		return nil, nil, errors.New("Users and RequestedSettings are required")
	}
	return users, settings, nil
}

func parseMailboxes(users *soapNode, namespace string) ([]string, error) {
	if len(users.children) == 0 || len(users.children) > maxSOAPUsers {
		return nil, fmt.Errorf("GetUserSettings requires between 1 and %d users", maxSOAPUsers)
	}
	mailboxes := make([]string, 0, len(users.children))
	for _, user := range users.children {
		if user.name != (xml.Name{Space: namespace, Local: "User"}) || len(user.children) != 1 || user.children[0].name != (xml.Name{Space: namespace, Local: "Mailbox"}) || len(user.children[0].children) != 0 {
			return nil, errors.New("each User must contain exactly one Mailbox")
		}
		mailbox := strings.TrimSpace(user.children[0].text.String())
		if mailbox == "" || len(mailbox) > 320 || strings.ContainsAny(mailbox, "\r\n") {
			return nil, errors.New("mailbox is empty or exceeds its limit")
		}
		mailboxes = append(mailboxes, mailbox)
	}
	return mailboxes, nil
}

func parseRequestedSettings(settings *soapNode, namespace string) ([]string, error) {
	if len(settings.children) == 0 || len(settings.children) > maxSOAPSettings {
		return nil, fmt.Errorf("GetUserSettings requires between 1 and %d settings", maxSOAPSettings)
	}
	result := make([]string, 0, len(settings.children))
	for _, setting := range settings.children {
		if setting.name != (xml.Name{Space: namespace, Local: "Setting"}) || len(setting.children) != 0 {
			return nil, errors.New("RequestedSettings may contain only Setting values")
		}
		name := strings.TrimSpace(setting.text.String())
		if name == "" || len(name) > 128 {
			return nil, errors.New("setting name is empty or exceeds its limit")
		}
		result = append(result, name)
	}
	return result, nil
}

func (h *Handler) soapSettings(userID, displayName, primary string, requested []string) soapUserResponse {
	response := soapUserResponse{code: "NoError", message: "No error."}
	for _, name := range requested {
		setting, known, available := h.soapSetting(userID, displayName, primary, name)
		if !known {
			response.errors = append(response.errors, soapSettingError{name: name, code: "InvalidSetting", message: "The requested setting is not recognized."})
			continue
		}
		if !available {
			response.errors = append(response.errors, soapSettingError{name: name, code: "SettingIsNotAvailable", message: "The requested setting is not available."})
			continue
		}
		response.settings = append(response.settings, setting)
	}
	return response
}

func (h *Handler) soapSetting(userID, displayName, primary, name string) (soapSetting, bool, bool) {
	host := h.cfg.host()
	deployment := sha256.Sum256([]byte("veksel-autodiscover:" + strings.ToLower(host)))
	stringsByName := map[string]string{
		"UserDisplayName":         displayName,
		"UserDN":                  "/o=Veksel/ou=Accounts/cn=Recipients/cn=" + userID,
		"UserDeploymentId":        hex.EncodeToString(deployment[:16]),
		"AutoDiscoverSMTPAddress": primary,
		"InternalMailboxServer":   host,
		"CasVersion":              "15.2.0.0",
	}
	if value, ok := stringsByName[name]; ok {
		return soapSetting{name: name, value: value}, true, value != ""
	}
	if name == "InternalEwsUrl" || name == "ExternalEwsUrl" || name == "InteropExternalEwsUrl" {
		ewsURL, enabled := h.cfg.EWSURL()
		return soapSetting{name: name, value: ewsURL}, true, enabled
	}
	if name == "ExternalEwsVersion" || name == "InteropExternalEwsVersion" {
		return soapSetting{name: name, value: "15.2.0.0"}, true, h.cfg.EwsEnabled
	}
	if name == "EwsSupportedSchemas" {
		return soapSetting{name: name, value: "Exchange2010,Exchange2010_SP1,Exchange2010_SP2,Exchange2013"}, true, h.cfg.EwsEnabled
	}

	var endpoints []Endpoint
	switch name {
	case "InternalImap4Connections", "ExternalImap4Connections":
		endpoints = h.cfg.IMAPEndpoints()
	case "InternalPop3Connections", "ExternalPop3Connections":
		endpoints = h.cfg.POP3Endpoints()
	case "InternalSmtpConnections", "ExternalSmtpConnections":
		endpoints = h.cfg.SubmissionEndpoints()
	default:
		_, known := knownSOAPUserSettings[name]
		return soapSetting{}, known, false
	}
	return soapSetting{name: name, connections: soapConnections(endpoints)}, true, len(endpoints) > 0
}

func soapConnections(endpoints []Endpoint) []soapConnection {
	connections := make([]soapConnection, 0, len(endpoints))
	for _, endpoint := range endpoints {
		encryption := "None"
		switch endpoint.Security {
		case SecuritySSL:
			encryption = "SSL"
		case SecuritySTARTTLS:
			encryption = "TLS"
		}
		connections = append(connections, soapConnection{host: endpoint.Host, port: endpoint.Port, encryption: encryption})
	}
	return connections
}

func writeSOAPResponse(w http.ResponseWriter, request soapRequest, responses []soapUserResponse) {
	responseAction := request.namespace + "/Autodiscover/GetUserSettingsResponse"
	contentType := soapResponseContentType(request.version)
	if request.version == soap12Namespace {
		contentType += `; action="` + responseAction + `"`
	}
	w.Header().Set("Content-Type", contentType)
	encoder := xml.NewEncoder(w)
	_ = encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: "s:Envelope"}, Attr: []xml.Attr{
		{Name: xml.Name{Local: "xmlns:s"}, Value: request.version},
		{Name: xml.Name{Local: "xmlns:a"}, Value: request.addressingNamespace},
	}})
	start(encoder, "s:Header")
	startAttr(encoder, "a:Action", xml.Attr{Name: xml.Name{Local: "s:mustUnderstand"}, Value: "1"})
	chars(encoder, responseAction)
	end(encoder, "a:Action")
	end(encoder, "s:Header")
	start(encoder, "s:Body")
	startAttr(encoder, "GetUserSettingsResponseMessage",
		xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: request.namespace},
		xml.Attr{Name: xml.Name{Local: "xmlns:i"}, Value: "http://www.w3.org/2001/XMLSchema-instance"})
	start(encoder, "Response")
	element(encoder, "ErrorCode", "NoError")
	element(encoder, "ErrorMessage", "")
	start(encoder, "UserResponses")
	for _, response := range responses {
		start(encoder, "UserResponse")
		element(encoder, "ErrorCode", response.code)
		element(encoder, "ErrorMessage", response.message)
		startAttr(encoder, "RedirectTarget", xml.Attr{Name: xml.Name{Local: "i:nil"}, Value: "true"})
		end(encoder, "RedirectTarget")
		start(encoder, "UserSettingErrors")
		for _, settingErr := range response.errors {
			start(encoder, "UserSettingError")
			element(encoder, "ErrorCode", settingErr.code)
			element(encoder, "ErrorMessage", settingErr.message)
			element(encoder, "SettingName", settingErr.name)
			end(encoder, "UserSettingError")
		}
		end(encoder, "UserSettingErrors")
		start(encoder, "UserSettings")
		for _, setting := range response.settings {
			settingType := "StringSetting"
			if setting.connections != nil {
				settingType = "ProtocolConnectionCollectionSetting"
			}
			startAttr(encoder, "UserSetting", xml.Attr{Name: xml.Name{Local: "i:type"}, Value: settingType})
			element(encoder, "Name", setting.name)
			if setting.connections == nil {
				element(encoder, "Value", setting.value)
			} else {
				start(encoder, "ProtocolConnections")
				for _, connection := range setting.connections {
					start(encoder, "ProtocolConnection")
					element(encoder, "Hostname", connection.host)
					element(encoder, "Port", strconv.Itoa(connection.port))
					element(encoder, "EncryptionMethod", connection.encryption)
					end(encoder, "ProtocolConnection")
				}
				end(encoder, "ProtocolConnections")
			}
			end(encoder, "UserSetting")
		}
		end(encoder, "UserSettings")
		end(encoder, "UserResponse")
	}
	end(encoder, "UserResponses")
	end(encoder, "Response")
	end(encoder, "GetUserSettingsResponseMessage")
	end(encoder, "s:Body")
	end(encoder, "s:Envelope")
	_ = encoder.Flush()
}

func writeSOAPFault(w http.ResponseWriter, version, code, message string, status int) {
	w.Header().Set("Content-Type", soapResponseContentType(version))
	w.WriteHeader(status)
	encoder := xml.NewEncoder(w)
	startAttr(encoder, "s:Envelope", xml.Attr{Name: xml.Name{Local: "xmlns:s"}, Value: version})
	start(encoder, "s:Body")
	start(encoder, "s:Fault")
	if version == soap12Namespace {
		start(encoder, "s:Code")
		element(encoder, "s:Value", "s:Sender")
		end(encoder, "s:Code")
		start(encoder, "s:Reason")
		startAttr(encoder, "s:Text", xml.Attr{Name: xml.Name{Local: "xml:lang"}, Value: "en"})
		chars(encoder, code+": "+message)
		end(encoder, "s:Text")
		end(encoder, "s:Reason")
	} else {
		element(encoder, "faultcode", "s:Client")
		element(encoder, "faultstring", code+": "+message)
	}
	end(encoder, "s:Fault")
	end(encoder, "s:Body")
	end(encoder, "s:Envelope")
	_ = encoder.Flush()
}

func writeAutodiscoverUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func soapResponseContentType(version string) string {
	if version == soap12Namespace {
		return "application/soap+xml; charset=utf-8"
	}
	return "text/xml; charset=utf-8"
}

func start(encoder *xml.Encoder, name string) {
	_ = encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}})
}
func startAttr(encoder *xml.Encoder, name string, attrs ...xml.Attr) {
	_ = encoder.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
}
func end(encoder *xml.Encoder, name string) {
	_ = encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: name}})
}
func chars(encoder *xml.Encoder, value string) { _ = encoder.EncodeToken(xml.CharData(value)) }
func element(encoder *xml.Encoder, name, value string) {
	start(encoder, name)
	chars(encoder, value)
	end(encoder, name)
}

func trimSOAPAction(action string) string { return strings.Trim(strings.TrimSpace(action), `"`) }
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func isAutodiscoverNamespace(namespace string) bool {
	return namespace == autodiscoverHTTPNamespace || namespace == autodiscoverHTTPSNamespace
}
