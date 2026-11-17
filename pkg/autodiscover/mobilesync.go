package autodiscover

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
)

// EASURL reports the Exchange ActiveSync URL, if EAS is enabled.
func (c Config) EASURL() (string, bool) {
	return "https://" + c.host() + "/Microsoft-Server-ActiveSync", c.EasEnabled
}

const (
	mobileSyncResponseSchema = "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006"
	autodiscoverEnvelope     = "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006"
)

// mobileSyncResponse is the MS-ASCMD/MS-OXDISCO "mobilesync" POX answer
// that ActiveSync clients (iOS, Android, Windows Mail) request with
// AcceptableResponseSchema .../mobilesync/responseschema/2006.
type mobileSyncResponse struct {
	XMLName  xml.Name         `xml:"Autodiscover"`
	XMLNS    string           `xml:"xmlns,attr"`
	Response mobileSyncAnswer `xml:"Response"`
}

type mobileSyncAnswer struct {
	XMLNS   string            `xml:"xmlns,attr"`
	Culture string            `xml:"Culture,omitempty"`
	User    *mobileSyncUser   `xml:"User,omitempty"`
	Action  *mobileSyncAction `xml:"Action,omitempty"`
	Error   *mobileSyncError  `xml:"Error,omitempty"`
}

type mobileSyncUser struct {
	DisplayName  string `xml:"DisplayName"`
	EMailAddress string `xml:"EMailAddress"`
}

type mobileSyncAction struct {
	Servers []mobileSyncServer `xml:"Settings>Server"`
}

type mobileSyncServer struct {
	Type string `xml:"Type"`
	URL  string `xml:"Url"`
	Name string `xml:"Name"`
}

type mobileSyncError struct {
	ErrorCode string `xml:"ErrorCode"`
	Message   string `xml:"Message"`
	DebugData string `xml:"DebugData"`
}

func wantsMobileSync(schema string) bool {
	return strings.Contains(strings.ToLower(schema), "/mobilesync/")
}

// handleMobileSync answers a mobilesync request. Unlike the Outlook
// schema it always requires credentials: every ActiveSync client has the
// password before it asks, and Exchange challenges the same way.
func (h *Handler) handleMobileSync(w http.ResponseWriter, r *http.Request, email string) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if email == "" {
		email = username
	}
	ea, err := h.userStore.GetEmailAddress(r.Context(), strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user, err := h.userStore.Get(r.Context(), ea.UserID)
	if err != nil || !user.Enabled || (username != ea.UserID && !strings.EqualFold(username, ea.ID)) || !h.validPassword(r.Context(), username, password, user) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	answer := mobileSyncAnswer{XMLNS: mobileSyncResponseSchema, Culture: "en:us", User: &mobileSyncUser{DisplayName: user.DisplayName, EMailAddress: ea.ID}}
	if easURL, enabled := h.cfg.EASURL(); enabled {
		answer.Action = &mobileSyncAction{Servers: []mobileSyncServer{{Type: "MobileSync", URL: easURL, Name: easURL}}}
	} else {
		answer.User = nil
		answer.Error = &mobileSyncError{ErrorCode: "600", Message: "Invalid Request", DebugData: "Exchange ActiveSync is disabled"}
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = w.Write([]byte(xml.Header))
	if err := xml.NewEncoder(w).Encode(mobileSyncResponse{XMLNS: autodiscoverEnvelope, Response: answer}); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// handleJSON serves Autodiscover v2 (/autodiscover/autodiscover.json),
// which Outlook for iOS/Android and Windows use to find the ActiveSync and
// EWS endpoints. It names service URLs only, so it is anonymous like
// Exchange Online's and does not reveal whether a mailbox exists.
func (h *Handler) handleJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	protocol := ""
	for key, values := range query {
		if strings.EqualFold(key, "Protocol") && len(values) > 0 {
			protocol = values[0]
		}
	}
	email := ""
	lower := strings.ToLower(r.URL.Path)
	if index := strings.Index(lower, "/autodiscover.json/v1.0/"); index >= 0 {
		email, _ = url.PathUnescape(r.URL.Path[index+len("/autodiscover.json/v1.0/"):])
	}
	for key, values := range query {
		if strings.EqualFold(key, "Email") && len(values) > 0 && email == "" {
			email = values[0]
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if email == "" || !strings.Contains(email, "@") {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"ErrorCode": "InvalidUser", "ErrorMessage": "A valid email address is required."})
		return
	}
	var target string
	enabled := false
	canonical := protocol
	switch strings.ToLower(protocol) {
	case "activesync":
		canonical = "ActiveSync"
		target, enabled = h.cfg.EASURL()
	case "ews":
		canonical = "EWS"
		target, enabled = h.cfg.EWSURL()
	case "autodiscoverv1":
		canonical = "AutodiscoverV1"
		target, enabled = "https://"+h.cfg.host()+"/autodiscover/autodiscover.xml", true
	}
	if !enabled {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ErrorCode":    "ProtocolNotSupported",
			"ErrorMessage": "The given protocol value '" + protocol + "' is invalid. Supported values are '" + h.jsonProtocols() + "'",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"Protocol": canonical, "Url": target})
}

func (h *Handler) jsonProtocols() string {
	protocols := []string{"AutodiscoverV1"}
	if h.cfg.EasEnabled {
		protocols = append(protocols, "ActiveSync")
	}
	if h.cfg.EwsEnabled {
		protocols = append(protocols, "Ews")
	}
	return strings.Join(protocols, ",")
}
