package authresults

import (
	"strings"
	"testing"
)

func TestBuildProducesStableSafeCombinedField(t *testing.T) {
	value, err := Build("mx.example.test", []Result{
		{Method: "spf", Result: "pass", Properties: []Property{{Name: "smtp.mailfrom", Value: "sender@example.test"}}},
		{Method: "dkim", Result: "fail", Reason: "bad signature", Properties: []Property{{Name: "header.d", Value: "example.test"}, {Name: "header.s", Value: "mail"}}},
		{Method: "dmarc", Result: "fail", Properties: []Property{{Name: "header.from", Value: "example.test"}, {Name: "policy.dmarc", Value: "quarantine"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `mx.example.test; spf=pass smtp.mailfrom="sender@example.test"; dkim=fail reason="bad signature" header.d=example.test header.s=mail; dmarc=fail header.from=example.test policy.dmarc=quarantine`
	if unfolded := strings.ReplaceAll(value, "\r\n\t", " "); unfolded != want {
		t.Fatalf("header = %q, want %q", unfolded, want)
	}
	for index, line := range strings.Split("Authentication-Results: "+value, "\r\n") {
		if len(line) > foldWidth || index > 0 && !strings.HasPrefix(line, "\t") {
			t.Fatalf("line %d = %q", index, line)
		}
	}
}

// TestBuildFoldsLongResults keeps many results and long peer-derived values,
// such as several DKIM signatures, within the line limit instead of
// refusing them (which turned every such message into a 451).
func TestBuildFoldsLongResults(t *testing.T) {
	results := []Result{{Method: "dmarc", Result: "fail", Properties: []Property{{Name: "header.from", Value: strings.Repeat("a", 500) + ".example"}}}}
	for range 9 {
		results = append(results, Result{Method: "dkim", Result: "pass", Properties: []Property{
			{Name: "header.d", Value: strings.Repeat("d", 200) + ".example"}, {Name: "header.s", Value: "selector"}, {Name: "header.b", Value: "AbCdEfGh+/12"}}})
	}
	value, err := Build("mx.example.test", results)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(value, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("line of %d octets", len(line))
		}
	}
}

func TestBuildRejectsInjectionAndBounds(t *testing.T) {
	for name, test := range map[string]struct {
		authserv string
		result   Result
	}{
		"authserv": {authserv: "mx\r\nBcc", result: Result{Method: "spf", Result: "pass"}},
		"value":    {authserv: "mx.test", result: Result{Method: "spf", Result: "pass", Properties: []Property{{Name: "smtp.mailfrom", Value: "safe\r\nBcc: victim"}}}},
		"property": {authserv: "mx.test", result: Result{Method: "spf", Result: "pass", Properties: []Property{{Name: "smtp mailfrom", Value: "safe"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(test.authserv, []Result{test.result}); err == nil {
				t.Fatal("unsafe result was accepted")
			}
		})
	}
	if _, err := Build("mx.test", []Result{{Method: "spf", Result: "pass", Reason: strings.Repeat("x", maxValueBytes+1)}}); err == nil {
		t.Fatal("oversized reason was accepted")
	}
	properties := make([]Property, 0, maxProperties)
	for index := 0; index < maxProperties; index++ {
		properties = append(properties, Property{Name: "policy.value", Value: strings.Repeat("x", maxValueBytes)})
	}
	if _, err := Build("mx.test", []Result{{Method: "dmarc", Result: "fail", Properties: properties}}); err == nil {
		t.Fatal("overlong header line was accepted")
	}
}
