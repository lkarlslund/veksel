package autodiscover

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type autoconfigServer struct {
	Host string `xml:"hostname"`
	Port int    `xml:"port"`
	SSL  string `xml:"socketType"`
}

// TestDiscoveryFormatsAdvertiseSameEndpoints pins every discovery format to
// the shared endpoint helpers for the same configuration.
func TestDiscoveryFormatsAdvertiseSameEndpoints(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	for name, mutate := range map[string]func(*Config){
		"implicit and starttls": func(*Config) {},
		"starttls only": func(c *Config) {
			c.ImapTlsEnabled, c.SmtpImplicitTLSEnabled = false, false
		},
		"implicit submission only": func(c *Config) {
			c.SmtpSubmissionEnabled = false
		},
		"custom hosts": func(c *Config) {
			c.ImapServerName, c.Pop3ServerName = "imap.example.com", "pop.example.com"
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := testHandler(t, ts)
			mutate(&h.cfg)
			imap, ok := h.cfg.IMAPEndpoint()
			if !ok {
				t.Fatal("no IMAP endpoint")
			}
			smtp := h.cfg.SubmissionEndpoint()
			wantIn := autoconfigServer{imap.Host, imap.Port, imap.socketType()}
			wantOut := autoconfigServer{smtp.Host, smtp.Port, smtp.socketType()}

			// Mozilla autoconfig.
			for _, path := range []string{"/mail/config-v1.1.xml?emailaddress=alice@example.com", "/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=alice@example.com"} {
				w := httptest.NewRecorder()
				h.Handle(w, httptest.NewRequest(http.MethodGet, path, nil))
				var got struct {
					In  []autoconfigServer `xml:"emailProvider>incomingServer"`
					Out []autoconfigServer `xml:"emailProvider>outgoingServer"`
				}
				if err := xml.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.In) == 0 || len(got.Out) == 0 {
					t.Fatalf("%s: %v: %s", path, err, w.Body.String())
				}
				if got.In[0] != wantIn || got.Out[0] != wantOut {
					t.Errorf("%s = %+v, want in %+v out %+v", path, got, wantIn, wantOut)
				}
			}

			// Microsoft POX.
			r := httptest.NewRequest(http.MethodPost, "/autodiscover/autodiscover.xml", strings.NewReader(`<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006a"><Request><EMailAddress>alice@example.com</EMailAddress></Request></Autodiscover>`))
			r.SetBasicAuth("alice", "pass123")
			w := httptest.NewRecorder()
			h.Handle(w, r)
			var pox msResponse
			if err := xml.Unmarshal(w.Body.Bytes(), &pox); err != nil {
				t.Fatal(err)
			}
			var gotSMTP msProtocol
			for _, p := range pox.Response.Account.Protocols {
				switch p.Type {
				case "SMTP":
					gotSMTP = p
				case "EXPR":
					if want, _ := h.cfg.EWSURL(); p.EwsUrl != want {
						t.Errorf("POX EWS = %q, want %q", p.EwsUrl, want)
					}
				}
			}
			if gotSMTP.Server != smtp.Host || gotSMTP.Port != smtp.Port || (gotSMTP.SSL == "on") != smtp.UsesTLS() {
				t.Errorf("POX SMTP = %+v, want %+v", gotSMTP, smtp)
			}

			// SOAP GetUserSettings lists every enabled endpoint.
			body := soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"ExternalImap4Connections", "ExternalPop3Connections", "ExternalSmtpConnections"})
			resp := serveSOAP(t, h, "/autodiscover/autodiscover.svc", "text/xml", "", "alice", "pass123", body)
			root, err := parseSOAPTree(resp.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			var got, want []string
			for _, node := range descendantsNamed(root, autodiscoverHTTPSNamespace, "ProtocolConnection") {
				fields := map[string]string{}
				for _, child := range node.children {
					fields[child.name.Local] = strings.TrimSpace(child.text.String())
				}
				got = append(got, fields["Hostname"]+":"+fields["Port"]+":"+fields["EncryptionMethod"])
			}
			encryption := map[string]string{SecuritySSL: "SSL", SecuritySTARTTLS: "TLS", SecurityNone: "None"}
			for _, group := range [][]Endpoint{h.cfg.IMAPEndpoints(), h.cfg.POP3Endpoints(), h.cfg.SubmissionEndpoints()} {
				for _, e := range group {
					want = append(want, e.Host+":"+strconv.Itoa(e.Port)+":"+encryption[e.Security])
				}
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("SOAP connections = %v, want %v", got, want)
			}

			// Apple configuration profile.
			data, _, err := h.cfg.MobileConfig(MobileConfigParams{AccountID: "a", Email: "alice@example.com", Username: "alice@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			mail := payloadsByType(t, parsePlistDict(t, data))["com.apple.mail.managed"]
			for key, want := range map[string]any{
				"IncomingMailServerHostName": imap.Host, "IncomingMailServerPortNumber": "int:" + strconv.Itoa(imap.Port),
				"OutgoingMailServerHostName": smtp.Host, "OutgoingMailServerPortNumber": "int:" + strconv.Itoa(smtp.Port),
			} {
				if mail[key] != want {
					t.Errorf("mobileconfig %s = %v, want %v", key, mail[key], want)
				}
			}
		})
	}
}

func TestDiscoveryOmitsDisabledIMAP(t *testing.T) {
	ts := testStoreSetup(t)
	testUserWithEmail(t, ts, "alice", "pass123", "alice@example.com")
	h := testHandler(t, ts)
	h.cfg.ImapEnabled, h.cfg.ImapStartTLSEnabled, h.cfg.ImapTlsEnabled = false, false, false
	w := httptest.NewRecorder()
	h.Handle(w, httptest.NewRequest(http.MethodGet, "/mail/config-v1.1.xml?emailaddress=alice@example.com", nil))
	if body := w.Body.String(); strings.Contains(body, `incomingServer type="imap"`) || !strings.Contains(body, "outgoingServer") {
		t.Errorf("autoconfig with IMAP disabled = %s", body)
	}
}
