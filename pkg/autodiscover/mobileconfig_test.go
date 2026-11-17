package autodiscover

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

// parsePlistDict decodes the top-level plist dictionary into nested Go values.
func parsePlistDict(t *testing.T, data []byte) map[string]any {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	decoder.Strict = false
	var read func(start xml.StartElement) any
	read = func(start xml.StartElement) any {
		switch start.Name.Local {
		case "string", "integer":
			var text string
			if err := decoder.DecodeElement(&text, &start); err != nil {
				t.Fatal(err)
			}
			if start.Name.Local == "integer" {
				return "int:" + text
			}
			return text
		case "true", "false":
			_ = decoder.Skip()
			return start.Name.Local == "true"
		case "array":
			var items []any
			for {
				token, err := decoder.Token()
				if err != nil {
					t.Fatal(err)
				}
				if child, ok := token.(xml.StartElement); ok {
					items = append(items, read(child))
				} else if _, ok := token.(xml.EndElement); ok {
					return items
				}
			}
		case "dict":
			values, key := map[string]any{}, ""
			for {
				token, err := decoder.Token()
				if err != nil {
					t.Fatal(err)
				}
				switch typed := token.(type) {
				case xml.StartElement:
					if typed.Name.Local == "key" {
						if err := decoder.DecodeElement(&key, &typed); err != nil {
							t.Fatal(err)
						}
					} else {
						values[key] = read(typed)
					}
				case xml.EndElement:
					return values
				}
			}
		}
		t.Fatalf("unexpected plist element %s", start.Name.Local)
		return nil
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("no dict found: %v", err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "dict" {
			return read(start).(map[string]any)
		}
	}
}

func payloadsByType(t *testing.T, profile map[string]any) map[string]map[string]any {
	t.Helper()
	result := map[string]map[string]any{}
	for _, item := range profile["PayloadContent"].([]any) {
		payload := item.(map[string]any)
		result[payload["PayloadType"].(string)] = payload
	}
	return result
}

func mobileTestConfig() Config {
	return Config{
		ServerName: "mail.example.com", SmtpPort: 587, SmtpTlsPort: 465, ImapPort: 143, ImapTlsPort: 993,
		ImapTlsEnabled: true, ImapEnabled: true, ImapStartTLSEnabled: true,
		SmtpSubmissionEnabled: true, SmtpImplicitTLSEnabled: true,
		DavPort: 443, DavTLS: true,
	}
}

func TestMobileConfigPayloads(t *testing.T) {
	params := MobileConfigParams{AccountID: "alice", Email: "alice@example.com", DisplayName: "Alice <A>", Username: "alice@example.com"}
	data, identifier, err := mobileTestConfig().MobileConfig(params)
	if err != nil {
		t.Fatal(err)
	}
	if identifier != parsePlistDict(t, data)["PayloadIdentifier"] || !strings.HasPrefix(identifier, "com.example.mail.account.") {
		t.Fatalf("identifier = %q", identifier)
	}
	profile := parsePlistDict(t, data)
	if profile["PayloadType"] != "Configuration" {
		t.Fatalf("profile = %#v", profile)
	}
	payloads := payloadsByType(t, profile)
	mail := payloads["com.apple.mail.managed"]
	for key, want := range map[string]any{
		"EmailAddress": "alice@example.com", "EmailAccountName": "Alice <A>", "EmailAccountType": "EmailTypeIMAP",
		"IncomingMailServerHostName": "mail.example.com", "IncomingMailServerPortNumber": "int:993", "IncomingMailServerUseSSL": true,
		"IncomingMailServerUsername": "alice@example.com", "OutgoingMailServerHostName": "mail.example.com",
		"OutgoingMailServerPortNumber": "int:587", "OutgoingMailServerUseSSL": true, "OutgoingMailServerUsername": "alice@example.com",
	} {
		if mail[key] != want {
			t.Errorf("mail %s = %#v, want %#v", key, mail[key], want)
		}
	}
	if _, embedded := mail["IncomingPassword"]; embedded {
		t.Error("password embedded without being requested")
	}
	for kind, prefix := range map[string]string{"com.apple.caldav.account": "CalDAV", "com.apple.carddav.account": "CardDAV"} {
		dav := payloads[kind]
		if dav[prefix+"HostName"] != "mail.example.com" || dav[prefix+"Port"] != "int:443" || dav[prefix+"UseSSL"] != true || dav[prefix+"Username"] != "alice@example.com" {
			t.Errorf("%s payload = %#v", kind, dav)
		}
	}
}

func TestMobileConfigTransportModes(t *testing.T) {
	cfg := mobileTestConfig()
	cfg.ImapTlsEnabled, cfg.SmtpSubmissionEnabled = false, false
	cfg.DavPort, cfg.DavTLS = 8472, false
	data, _, err := cfg.MobileConfig(MobileConfigParams{AccountID: "alice", Email: "a@example.com", Username: "a@example.com", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	payloads := payloadsByType(t, parsePlistDict(t, data))
	mail := payloads["com.apple.mail.managed"]
	if mail["IncomingMailServerPortNumber"] != "int:143" || mail["IncomingMailServerUseSSL"] != true {
		t.Errorf("STARTTLS IMAP = %#v", mail)
	}
	if mail["OutgoingMailServerPortNumber"] != "int:465" || mail["OutgoingMailServerUseSSL"] != true {
		t.Errorf("implicit TLS SMTP = %#v", mail)
	}
	if mail["IncomingPassword"] != "s3cret" || payloads["com.apple.caldav.account"]["CalDAVPassword"] != "s3cret" {
		t.Error("requested password is not embedded")
	}
	if dav := payloads["com.apple.carddav.account"]; dav["CardDAVPort"] != "int:8472" || dav["CardDAVUseSSL"] != false {
		t.Errorf("plain HTTP DAV = %#v", dav)
	}
}

func TestMobileConfigStableIdentifiers(t *testing.T) {
	params := MobileConfigParams{AccountID: "alice", Email: "alice@example.com", Username: "alice@example.com"}
	first, _, _ := mobileTestConfig().MobileConfig(params)
	params.Email = "other@example.com"
	second, _, _ := mobileTestConfig().MobileConfig(params)
	a, b := parsePlistDict(t, first), parsePlistDict(t, second)
	if a["PayloadUUID"] != b["PayloadUUID"] || a["PayloadIdentifier"] != b["PayloadIdentifier"] {
		t.Error("identifiers changed with the chosen identity")
	}
	pa, pb := payloadsByType(t, a), payloadsByType(t, b)
	for kind, payload := range pa {
		if payload["PayloadUUID"] != pb[kind]["PayloadUUID"] {
			t.Errorf("%s UUID is unstable", kind)
		}
	}
	params.AccountID = "bob"
	third, _, _ := mobileTestConfig().MobileConfig(params)
	if parsePlistDict(t, third)["PayloadUUID"] == a["PayloadUUID"] {
		t.Error("different accounts share a profile UUID")
	}
	uuid := a["PayloadUUID"].(string)
	if len(uuid) != 36 || uuid != strings.ToUpper(uuid) {
		t.Errorf("malformed UUID %q", uuid)
	}
}

func TestMobileConfigNothingEnabled(t *testing.T) {
	if _, _, err := (Config{ServerName: "mail.example.com"}).MobileConfig(MobileConfigParams{AccountID: "a"}); !errors.Is(err, ErrNothingToConfigure) {
		t.Fatalf("err = %v", err)
	}
}
