package autodiscover

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/model"
)

// --- Microsoft Autodiscover POX (MS-OXDISCO) ---

// msRequest is the incoming Microsoft Autodiscover POX request.
type msRequest struct {
	XMLName       xml.Name `xml:"Autodiscover"`
	RequestedInfo []string `xml:"Request>AcceptedSettings>Setting"`
	Email         string   `xml:"Request>EMailAddress"`
	Schema        string   `xml:"Request>AcceptableResponseSchema"`
}

// msResponse is the Microsoft Autodiscover POX response.
type msResponse struct {
	XMLName  xml.Name       `xml:"Autodiscover"`
	XMLNS    string         `xml:"xmlns,attr"`
	Response msResponseBody `xml:"Response"`
}

type msResponseBody struct {
	User    msUser    `xml:"User"`
	Account msAccount `xml:"Account"`
}

type msUser struct {
	DN          string `xml:"DN"`
	DisplayName string `xml:"DisplayName"`
	EmailAddr   string `xml:"EmailAddress"`
}

type msAccount struct {
	AccountType string       `xml:"AccountType"`
	Action      string       `xml:"Action"`
	Protocols   []msProtocol `xml:"Protocol"`
}

type msProtocol struct {
	Type              string `xml:"Type"`
	ServerVersion     string `xml:"ServerVersion,omitempty"`
	ManualConfig      bool   `xml:"ManualConfig,omitempty"`
	Server            string `xml:"Server"`
	ASUrl             string `xml:"ASUrl,omitempty"`
	EwsUrl            string `xml:"EwsUrl,omitempty"`
	AuthPackage       string `xml:"AuthPackage,omitempty"`
	Port              int    `xml:"Port"`
	DirectoryPort     int    `xml:"DirectoryPort,omitempty"`
	ReferrerURL       string `xml:"ReferrerURL,omitempty"`
	IPv6              string `xml:"IPv6,omitempty"`
	SubmitMessages    string `xml:"SubmitMessages"`
	SSL               string `xml:"SSL"`
	AuthenticateOut   string `xml:"AuthenticateOut"`
	AuthInit          string `xml:"AuthInit,omitempty"`
	EnableEtu         string `xml:"EnableEtu,omitempty"`
	EtuServer         string `xml:"EtuServer,omitempty"`
	EtuServerInfo     string `xml:"EtuServerInfo,omitempty"`
	CredentialsSource string `xml:"CredentialsSource,omitempty"`
}

// maxPOXBodyBytes bounds a POX Autodiscover request body.
const maxPOXBodyBytes = 64 << 10

func (h *Handler) handleMicrosoft(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body to extract the email address
	// The endpoint answers unauthenticated clients, and a POX request is a
	// few hundred bytes, so the body is capped before decoding.
	var req msRequest
	if err := xml.NewDecoder(http.MaxBytesReader(w, r.Body, maxPOXBodyBytes)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	if wantsMobileSync(req.Schema) {
		h.handleMobileSync(w, r, strings.TrimSpace(req.Email))
		return
	}

	email := req.Email
	if email == "" {
		// Fall back to Basic auth username
		if username, _, ok := r.BasicAuth(); ok {
			// Try to find email by username
			user, err := h.userStore.Get(r.Context(), username)
			if err == nil {
				emailAddrs, err := h.userStore.ListEmailAddressesForUser(r.Context(), user.ID)
				if err == nil && len(emailAddrs) > 0 {
					email = emailAddrs[0].ID
				}
			}
		}
	}

	if email == "" {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Look up the user by email
	ea, err := h.userStore.GetEmailAddress(r.Context(), email)
	if err != nil {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	user, err := h.userStore.Get(r.Context(), ea.UserID)
	if err != nil || !user.Enabled {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Validate credentials if Basic auth is provided
	if username, password, ok := r.BasicAuth(); ok {
		if username != ea.UserID && username != email {
			w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// If username is email, look up the user
		u := user
		if username == email {
			u, err = h.userStore.Get(r.Context(), ea.UserID)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if !u.Enabled || !h.validPassword(r.Context(), username, password, u) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Autodiscover"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	smtp := h.cfg.SubmissionEndpoint()
	resp := msResponse{
		XMLNS: "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a",
		Response: msResponseBody{
			User: msUser{
				DN:          fmt.Sprintf("CN=%s", user.DisplayName),
				DisplayName: user.DisplayName,
				EmailAddr:   email,
			},
			Account: msAccount{
				AccountType: "email",
				Action:      "settings",
				Protocols: []msProtocol{{
					Type:            "SMTP",
					Server:          smtp.Host,
					Port:            smtp.Port,
					SubmitMessages:  "off",
					SSL:             onOff(smtp.UsesTLS()),
					AuthenticateOut: "on",
				}},
			},
		},
	}
	if ewsURL, ok := h.cfg.EWSURL(); ok {
		resp.Response.Account.Protocols = append([]msProtocol{{
			Type: "EXPR", Server: h.cfg.host(), ServerVersion: "15.2.0.0", ASUrl: ewsURL, EwsUrl: ewsURL,
			SSL: "on", AuthPackage: "Basic",
		}}, resp.Response.Account.Protocols...)
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	if err := xml.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// validPassword checks Basic credentials through the shared protocol
// authenticator, so directory accounts and application passwords work, and
// falls back to the local hash for handlers built without one.
func (h *Handler) validPassword(ctx context.Context, username, password string, user model.User) bool {
	if h.authenticate == nil {
		return auth.ComparePassword(password, user.PasswordHash)
	}
	userID, err := h.authenticate(ctx, username, password)
	return err == nil && userID == user.ID
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
