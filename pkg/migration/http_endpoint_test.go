package migration

import "testing"

func TestNormalizeHTTPEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		mode        string
		defaultPath string
		want        string
		wantError   bool
	}{
		{name: "HTTPS host", endpoint: "mail.example.test", mode: "https", defaultPath: "/Microsoft-Server-ActiveSync", want: "https://mail.example.test/Microsoft-Server-ActiveSync"},
		{name: "HTTP host and port", endpoint: "mail.example.test:8080", mode: "http", defaultPath: "EWS/Exchange.asmx", want: "http://mail.example.test:8080/EWS/Exchange.asmx"},
		{name: "complete URL", endpoint: "https://mail.example.test/custom/eas", mode: "https", defaultPath: "ignored", want: "https://mail.example.test/custom/eas"},
		{name: "default HTTPS", endpoint: "mail.example.test", defaultPath: "EWS/Exchange.asmx", want: "https://mail.example.test/EWS/Exchange.asmx"},
		{name: "conflicting scheme", endpoint: "http://mail.example.test/eas", mode: "https", defaultPath: "eas", wantError: true},
		{name: "IMAP mode rejected", endpoint: "mail.example.test", mode: "starttls", defaultPath: "eas", wantError: true},
		{name: "invalid endpoint", endpoint: "https://", mode: "https", defaultPath: "eas", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeHTTPEndpoint(test.endpoint, test.mode, test.defaultPath)
			if test.wantError {
				if err == nil {
					t.Fatalf("NormalizeHTTPEndpoint() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeHTTPEndpoint() error = %v", err)
			}
			if got != test.want {
				t.Errorf("NormalizeHTTPEndpoint() = %q, want %q", got, test.want)
			}
		})
	}
}
