package autodiscover

import (
	"strings"
	"testing"
)

// FuzzSOAPRequest feeds unauthenticated Autodiscover SOAP bodies into the
// bounded SOAP parser for both SOAP versions.
func FuzzSOAPRequest(f *testing.F) {
	action := autodiscoverHTTPSNamespace + "/Autodiscover/GetUserSettings"
	f.Add(soap11Request(autodiscoverHTTPSNamespace, []string{"alice@example.com"}, []string{"UserDisplayName", "ExternalEwsUrl"}))
	f.Add(`<?xml version="1.0"?><s:Envelope xmlns:s="` + soap11Namespace + `"><s:Body/></s:Envelope>`)
	f.Add(`<!DOCTYPE x><s:Envelope xmlns:s="` + soap11Namespace + `"/>`)
	f.Add(strings.Repeat("<a>", 100))
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = parseSOAPRequest(strings.NewReader(input), soap11Namespace, action)
		_, _ = parseSOAPRequest(strings.NewReader(input), soap12Namespace, action)
	})
}
