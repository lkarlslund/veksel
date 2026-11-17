package autodiscover

import (
	"encoding/xml"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/httpservice"
)

// --- Mozilla autoconfig (clientConfig 1.1) ---
//
// Thunderbird, K-9/Thunderbird for Android, FairEmail, Evolution and other
// clients fetch https://autoconfig.<domain>/mail/config-v1.1.xml and
// https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml, adding
// ?emailaddress=<address>. The answer is an <emailProvider> listing every
// enabled server; usernames use the %EMAILADDRESS% placeholder.

type clientConfig struct {
	XMLName     xml.Name      `xml:"clientConfig"`
	Version     string        `xml:"version,attr"`
	Provider    emailProvider `xml:"emailProvider"`
	AddressBook []davConfig   `xml:"addressBook,omitempty"`
	Calendar    []davConfig   `xml:"calendar,omitempty"`
}

type emailProvider struct {
	ID               string           `xml:"id,attr"`
	Domain           string           `xml:"domain"`
	DisplayName      string           `xml:"displayName"`
	DisplayShortName string           `xml:"displayShortName"`
	Incoming         []incomingServer `xml:"incomingServer"`
	Outgoing         []outgoingServer `xml:"outgoingServer"`
}

type incomingServer struct {
	Type           string `xml:"type,attr"`
	Hostname       string `xml:"hostname"`
	Port           int    `xml:"port"`
	SocketType     string `xml:"socketType"`
	Authentication string `xml:"authentication"`
	Username       string `xml:"username"`
	// Exchange servers (type "exchange") carry their service URLs.
	OWAURL string `xml:"owaURL,omitempty"`
	EWSURL string `xml:"ewsURL,omitempty"`
}

type outgoingServer struct {
	Type           string `xml:"type,attr"`
	Hostname       string `xml:"hostname"`
	Port           int    `xml:"port"`
	SocketType     string `xml:"socketType"`
	Authentication string `xml:"authentication"`
	Username       string `xml:"username"`
}

type davConfig struct {
	Type           string `xml:"type,attr"`
	Username       string `xml:"username"`
	Authentication string `xml:"authentication"`
	ServerURL      string `xml:"serverURL"`
}

const emailAddressPlaceholder = "%EMAILADDRESS%"

// socketType is the clientConfig spelling of a security mode.
func (e Endpoint) socketType() string {
	switch e.Security {
	case SecuritySSL:
		return "SSL"
	case SecuritySTARTTLS:
		return "STARTTLS"
	}
	return "plain"
}

var domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// autoconfigDomain is the mail domain a request asks about: the domain of
// the emailaddress parameter, else the autoconfig.<domain> or <domain> host
// the client contacted, else the server name's parent domain.
func (h *Handler) autoconfigDomain(r *http.Request) string {
	query := r.URL.Query()
	for _, key := range []string{"emailaddress", "email"} {
		if _, domain, ok := strings.Cut(query.Get(key), "@"); ok {
			if domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), "."); domainPattern.MatchString(domain) {
				return domain
			}
		}
	}
	host := httpservice.RequestClient(r).Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	server := strings.ToLower(h.cfg.host())
	if domain, ok := strings.CutPrefix(host, "autoconfig."); ok && domainPattern.MatchString(domain) {
		return domain
	}
	if host != server && net.ParseIP(host) == nil && domainPattern.MatchString(host) {
		return host
	}
	if _, parent, ok := strings.Cut(server, "."); ok && strings.Contains(parent, ".") {
		return parent
	}
	return server
}

// autoconfigDocument returns the Mozilla autoconfig document for domain.
func (c Config) autoconfigDocument(domain string) clientConfig {
	host := c.host()
	short, _, _ := strings.Cut(domain, ".")
	provider := emailProvider{ID: domain, Domain: domain, DisplayName: domain, DisplayShortName: short}
	add := func(kind string, endpoints []Endpoint) {
		for _, endpoint := range endpoints {
			provider.Incoming = append(provider.Incoming, incomingServer{Type: kind, Hostname: endpoint.Host, Port: endpoint.Port, SocketType: endpoint.socketType(), Authentication: "password-cleartext", Username: emailAddressPlaceholder})
		}
	}
	add("imap", c.IMAPEndpoints())
	if ews, ok := c.EWSURL(); ok {
		provider.Incoming = append(provider.Incoming, incomingServer{Type: "exchange", Hostname: host, Port: 443, SocketType: "SSL", Authentication: "password-cleartext", Username: emailAddressPlaceholder, EWSURL: ews})
	}
	add("pop3", c.POP3Endpoints())
	for _, endpoint := range c.SubmissionEndpoints() {
		provider.Outgoing = append(provider.Outgoing, outgoingServer{Type: "smtp", Hostname: endpoint.Host, Port: endpoint.Port, SocketType: endpoint.socketType(), Authentication: "password-cleartext", Username: emailAddressPlaceholder})
	}
	config := clientConfig{Version: "1.1", Provider: provider}
	if c.DavPort != 0 && c.DavTLS {
		base := "https://" + host
		if c.DavPort != 443 {
			base += ":" + strconv.Itoa(c.DavPort)
		}
		dav := c.DavPath
		if dav == "" {
			dav = "/dav/"
		}
		config.AddressBook = []davConfig{{Type: "carddav", Username: emailAddressPlaceholder, Authentication: "http-basic", ServerURL: base + dav}}
		config.Calendar = []davConfig{{Type: "caldav", Username: emailAddressPlaceholder, Authentication: "http-basic", ServerURL: base + dav}}
	}
	return config
}

func (h *Handler) handleAutoconfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_, _ = w.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	if err := encoder.Encode(h.cfg.autoconfigDocument(h.autoconfigDomain(r))); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
