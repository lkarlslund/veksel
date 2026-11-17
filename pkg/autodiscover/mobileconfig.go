package autodiscover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNothingToConfigure is returned when no mail or DAV service is enabled.
var ErrNothingToConfigure = errors.New("no mail or DAV service is enabled")

// Transport security modes of a mail endpoint.
const (
	SecuritySSL      = "ssl"
	SecuritySTARTTLS = "starttls"
	SecurityNone     = "none"
)

// Endpoint is one client-facing service address.
type Endpoint struct {
	Host     string
	Port     int
	Security string
}

func (c Config) host() string {
	if host := strings.TrimSpace(c.ServerName); host != "" {
		return host
	}
	return "localhost"
}

// UsesTLS reports whether the endpoint is encrypted, implicitly or by STARTTLS.
func (e Endpoint) UsesTLS() bool { return e.Security != SecurityNone }

// mailEndpoints lists a retrieval protocol's client-facing endpoints,
// implicit TLS first, then the plain port (STARTTLS when offered).
func mailEndpoints(host string, plainEnabled bool, plainPort int, startTLS bool, tlsEnabled bool, tlsPort int) []Endpoint {
	endpoints := make([]Endpoint, 0, 2)
	if tlsEnabled && tlsPort > 0 {
		endpoints = append(endpoints, Endpoint{host, tlsPort, SecuritySSL})
	}
	if plainEnabled && plainPort > 0 {
		security := SecurityNone
		if startTLS {
			security = SecuritySTARTTLS
		}
		endpoints = append(endpoints, Endpoint{host, plainPort, security})
	}
	return endpoints
}

func firstEndpoint(endpoints []Endpoint) (Endpoint, bool) {
	if len(endpoints) == 0 {
		return Endpoint{}, false
	}
	return endpoints[0], true
}

// IMAPEndpoints lists every enabled IMAP endpoint, preferred first.
func (c Config) IMAPEndpoints() []Endpoint {
	return mailEndpoints(firstNonEmpty(c.ImapServerName, c.host()), c.ImapEnabled, c.ImapPort, c.ImapStartTLSEnabled, c.ImapTlsEnabled, c.ImapTlsPort)
}

// IMAPEndpoint reports where clients reach IMAP, preferring implicit TLS.
// The bool is false when no IMAP listener is enabled.
func (c Config) IMAPEndpoint() (Endpoint, bool) { return firstEndpoint(c.IMAPEndpoints()) }

// POP3Endpoints lists every enabled POP3 endpoint, preferred first.
func (c Config) POP3Endpoints() []Endpoint {
	return mailEndpoints(firstNonEmpty(c.Pop3ServerName, c.host()), c.Pop3Enabled, c.Pop3Port, c.Pop3StartTLSEnabled, c.Pop3TlsEnabled, c.Pop3TlsPort)
}

// POP3Endpoint reports where clients reach POP3, preferring implicit TLS.
// The bool is false when no POP3 listener is enabled.
func (c Config) POP3Endpoint() (Endpoint, bool) { return firstEndpoint(c.POP3Endpoints()) }

// SubmissionEndpoints lists every enabled authenticated submission endpoint,
// preferred first: STARTTLS submission, then implicit TLS.
func (c Config) SubmissionEndpoints() []Endpoint {
	endpoints := make([]Endpoint, 0, 2)
	if c.SmtpSubmissionEnabled && c.SmtpPort > 0 {
		endpoints = append(endpoints, Endpoint{c.host(), c.SmtpPort, SecuritySTARTTLS})
	}
	if c.SmtpImplicitTLSEnabled && c.SmtpTlsPort > 0 {
		endpoints = append(endpoints, Endpoint{c.host(), c.SmtpTlsPort, SecuritySSL})
	}
	return endpoints
}

// SubmissionEndpoint reports where clients submit mail: the preferred enabled
// endpoint, falling back to the configured submission port.
func (c Config) SubmissionEndpoint() Endpoint {
	if endpoint, ok := firstEndpoint(c.SubmissionEndpoints()); ok {
		return endpoint
	}
	return Endpoint{c.host(), c.SmtpPort, SecurityNone}
}

// EWSURL reports the Exchange Web Services URL, if EWS is enabled.
func (c Config) EWSURL() (string, bool) {
	return "https://" + c.host() + "/EWS/Exchange.asmx", c.EwsEnabled
}

// MobileConfigParams selects the account a profile configures.
type MobileConfigParams struct {
	// AccountID keys the stable payload UUIDs so a reinstalled profile
	// replaces the earlier one.
	AccountID   string
	Email       string
	DisplayName string
	Username    string
	// Password is embedded as-is when set; otherwise the device prompts.
	Password string
}

// MobileConfig renders an unsigned Apple configuration profile that sets up
// Mail (IMAP and SMTP submission), Calendar (CalDAV) and Contacts (CardDAV)
// from the advertised server settings.
func (c Config) MobileConfig(p MobileConfigParams) ([]byte, string, error) {
	host := c.host()
	identifier := reverseDNS(host) + ".account." + shortHash(p.AccountID)
	description := p.Email + " on " + host
	var payloads []plistDict
	payload := func(kind, name string, values plistDict) {
		payloads = append(payloads, append(plistDict{
			{"PayloadType", kind},
			{"PayloadVersion", 1},
			{"PayloadIdentifier", identifier + "." + name},
			{"PayloadUUID", stableUUID(p.AccountID, host, name)},
			{"PayloadDisplayName", description},
			{"PayloadOrganization", host},
		}, values...))
	}
	if imap, ok := c.IMAPEndpoint(); ok {
		smtp := c.SubmissionEndpoint()
		mail := plistDict{
			{"EmailAccountDescription", description},
			{"EmailAccountName", p.DisplayName},
			{"EmailAccountType", "EmailTypeIMAP"},
			{"EmailAddress", p.Email},
			{"IncomingMailServerAuthentication", "EmailAuthPassword"},
			{"IncomingMailServerHostName", imap.Host},
			{"IncomingMailServerPortNumber", imap.Port},
			{"IncomingMailServerUseSSL", imap.UsesTLS()},
			{"IncomingMailServerUsername", p.Username},
			{"OutgoingMailServerAuthentication", "EmailAuthPassword"},
			{"OutgoingMailServerHostName", smtp.Host},
			{"OutgoingMailServerPortNumber", smtp.Port},
			{"OutgoingMailServerUseSSL", smtp.UsesTLS()},
			{"OutgoingMailServerUsername", p.Username},
			{"OutgoingPasswordSameAsIncomingPassword", true},
		}
		if p.Password != "" {
			mail = append(mail, plistKV{"IncomingPassword", p.Password})
		}
		payload("com.apple.mail.managed", "mail", mail)
	}
	if c.DavPort != 0 {
		for _, dav := range []struct{ name, kind, prefix string }{
			{"caldav", "com.apple.caldav.account", "CalDAV"},
			{"carddav", "com.apple.carddav.account", "CardDAV"},
		} {
			values := plistDict{
				{dav.prefix + "AccountDescription", description},
				{dav.prefix + "HostName", host},
				{dav.prefix + "Port", c.DavPort},
				{dav.prefix + "UseSSL", c.DavTLS},
				{dav.prefix + "Username", p.Username},
			}
			if p.Password != "" {
				values = append(values, plistKV{dav.prefix + "Password", p.Password})
			}
			payload(dav.kind, dav.name, values)
		}
	}
	if len(payloads) == 0 {
		return nil, "", ErrNothingToConfigure
	}
	content := make([]any, len(payloads))
	for i, item := range payloads {
		content[i] = item
	}
	profile := plistDict{
		{"PayloadContent", content},
		{"PayloadDescription", "Mail, calendar and contacts for " + description},
		{"PayloadDisplayName", description},
		{"PayloadIdentifier", identifier},
		{"PayloadOrganization", host},
		{"PayloadRemovalDisallowed", false},
		{"PayloadType", "Configuration"},
		{"PayloadUUID", stableUUID(p.AccountID, host, "profile")},
		{"PayloadVersion", 1},
	}
	var out bytes.Buffer
	out.WriteString(xml.Header + `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n<plist version=\"1.0\">\n")
	if err := writePlist(&out, profile, 0); err != nil {
		return nil, "", err
	}
	out.WriteString("</plist>\n")
	return out.Bytes(), identifier, nil
}

// plistKV is one ordered dictionary entry; plistDict keeps output stable.
type plistKV struct {
	Key   string
	Value any
}

type plistDict []plistKV

func writePlist(out *bytes.Buffer, value any, depth int) error {
	indent := strings.Repeat("\t", depth)
	switch v := value.(type) {
	case string:
		out.WriteString(indent + "<string>")
		if err := xml.EscapeText(out, []byte(v)); err != nil {
			return err
		}
		out.WriteString("</string>\n")
	case int:
		out.WriteString(indent + "<integer>" + strconv.Itoa(v) + "</integer>\n")
	case bool:
		out.WriteString(indent + "<" + strconv.FormatBool(v) + "/>\n")
	case []any:
		out.WriteString(indent + "<array>\n")
		for _, item := range v {
			if err := writePlist(out, item, depth+1); err != nil {
				return err
			}
		}
		out.WriteString(indent + "</array>\n")
	case plistDict:
		out.WriteString(indent + "<dict>\n")
		for _, entry := range v {
			out.WriteString(indent + "\t<key>")
			if err := xml.EscapeText(out, []byte(entry.Key)); err != nil {
				return err
			}
			out.WriteString("</key>\n")
			if err := writePlist(out, entry.Value, depth+1); err != nil {
				return err
			}
		}
		out.WriteString(indent + "</dict>\n")
	default:
		return fmt.Errorf("unsupported plist value %T", value)
	}
	return nil
}

// stableUUID derives a version 5 style UUID from the account, server and
// payload name, so regenerating a profile yields identical identifiers.
func stableUUID(account, server, name string) string {
	sum := sha256.Sum256([]byte(account + "\x00" + server + "\x00" + name))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	h := hex.EncodeToString(sum[:16])
	return strings.ToUpper(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:6])
}

// reverseDNS turns mail.example.com into com.example.mail.
func reverseDNS(host string) string {
	labels := strings.Split(strings.ToLower(strings.Trim(host, ".")), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}
