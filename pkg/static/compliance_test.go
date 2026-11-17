package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestComplianceAdministrationUI keeps the Compliance section's holds,
// policies, and eDiscovery export, and the folder properties that show users
// the retention policy in effect.
func TestComplianceAdministrationUI(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"section==='compliance'",
		"api('/api/v1/admin/compliance')",
		"'/api/v1/admin/compliance/holds'",
		"/api/v1/admin/compliance/held-items?account=",
		"'/api/v1/admin/compliance/policies'",
		"'/api/v1/admin/compliance/export?'",
		"'/api/v1/admin/compliance/retention/run'",
		"title:'Release legal hold'",
		"title:'Delete retention policy'",
		"/retention`",
		"label:'Properties…'",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("app.js lacks %q", required)
		}
	}
}
