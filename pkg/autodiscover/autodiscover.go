package autodiscover

import (
	"context"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/protocolauth"
)

// Config holds the server settings used to generate autodiscover responses.
type Config struct {
	// MTASTSPolicy returns the MTA-STS policy text served on host (an
	// mta-sts.<domain> name), or false when none is published there.
	MTASTSPolicy func(ctx context.Context, host string) (string, bool)
	// ServerName is the public hostname of the mail server (e.g. "mail.example.com").
	ServerName     string
	ImapServerName string
	Pop3ServerName string

	// ListenAddr is the HTTP listen address (e.g. ":8080").
	ListenAddr string

	// SMTP ports
	SmtpPort    int // submission port (587)
	SmtpTlsPort int // SMTPS port (465)

	// IMAP ports
	ImapPort    int // STARTTLS port (143)
	ImapTlsPort int // implicit TLS port (993)

	// POP3 ports
	Pop3Port    int // STARTTLS port (110)
	Pop3TlsPort int // implicit TLS port (995)

	// CalDAV/CardDAV base path (served over HTTPS on the HTTP listener)
	DavPath    string
	EwsEnabled bool
	EasEnabled bool

	// DavPort and DavTLS locate the HTTP listener that serves the DAV
	// service; DavPort is zero when none does.
	DavPort int
	DavTLS  bool

	// Whether TLS is configured for each protocol
	ImapTlsEnabled bool
	Pop3TlsEnabled bool

	// Whether client-facing protocol listeners are enabled. SMTP discovery
	// advertises authenticated submission, never the server-to-server listener.
	SmtpSubmissionEnabled  bool
	SmtpImplicitTLSEnabled bool
	ImapEnabled            bool
	ImapStartTLSEnabled    bool
	Pop3Enabled            bool
	Pop3StartTLSEnabled    bool
}

// Handler serves autodiscover endpoints.
type Handler struct {
	cfg          Config
	userStore    *model.UserStore
	authenticate protocolauth.AuthenticateFunc
}

// New creates a new autodiscover handler.
func New(userStore *model.UserStore, cfg Config, authenticate ...protocolauth.AuthenticateFunc) *Handler {
	var authFn protocolauth.AuthenticateFunc
	if len(authenticate) > 0 {
		authFn = authenticate[0]
	}
	return &Handler{
		cfg:          cfg,
		userStore:    userStore,
		authenticate: authFn,
	}
}

// Config returns the server settings this handler advertises.
func (h *Handler) Config() Config { return h.cfg }

// Handle routes incoming requests to the appropriate autodiscover protocol handler.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	lowerPath := strings.ToLower(path)

	switch {
	case lowerPath == "/autodiscover/autodiscover.svc":
		h.handleMicrosoftSOAP(w, r)
	case strings.HasPrefix(lowerPath, "/autodiscover/autodiscover.json"):
		h.handleJSON(w, r)
	case strings.HasSuffix(lowerPath, "/autodiscover/autodiscover.xml"):
		h.handleMicrosoft(w, r)
	case lowerPath == "/.well-known/mta-sts.txt":
		h.handleMTASTS(w, r)
	case lowerPath == "/.well-known/caldav" || lowerPath == "/.well-known/carddav":
		// RFC 6764 section 6: clients that only know the host name start here.
		dav := h.cfg.DavPath
		if dav == "" {
			dav = "/dav/"
		}
		http.Redirect(w, r, dav, http.StatusMovedPermanently)
	case lowerPath == "/.well-known/autoconfig/mail" || lowerPath == "/.well-known/autoconfig/mail/config-v1.1.xml",
		strings.HasPrefix(lowerPath, "/mail/") && strings.HasSuffix(lowerPath, "/config-v1.1.xml"),
		lowerPath == "/mail/config-v1.1.xml":
		h.handleAutoconfig(w, r)
	default:
		http.NotFound(w, r)
	}
}
