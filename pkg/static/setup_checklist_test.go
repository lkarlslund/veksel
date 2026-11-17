package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestAdminOverviewSetupChecklistUI keeps the first-run checklist and the
// deliverability self-test on Administration → Overview.
func TestAdminOverviewSetupChecklistUI(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	overview := strings.Index(script, "if(section==='overview'){")
	health := strings.Index(script, "} else if(section==='health'){")
	if overview < 0 || health < overview {
		t.Fatal("app.js lacks the admin Overview section")
	}
	section := script[overview:health]
	for _, required := range []string{
		// System administrators only; domain administrators never call it.
		"if(!domainScope){",
		"api('/api/v1/admin/setup-checklist')",
		"/api/v1/admin/setup-checklist?refresh=1",
		"/api/v1/admin/setup-checklist/dismissals',{method:'PUT'",
		"/api/v1/admin/setup-checklist/port25-probe',{method:'POST'}",
		"data-setup-dismiss",
		"check.fix_url&&check.status!=='pass'",
		"Dismissed (${dismissed.length})",
		"id=\"deliverability-self-test\"",
		"/api/v1/admin/deliverability/self-test',{method:'POST'",
		"/api/v1/admin/deliverability/messages/${encodeURIComponent(id)}",
		"check.remediation",
		"aria-live=\"polite\"",
	} {
		if !strings.Contains(section, required) {
			t.Errorf("admin Overview lacks %q", required)
		}
	}
	for _, native := range []string{"confirm(", "prompt(", "alert("} {
		if strings.Contains(section, native) {
			t.Errorf("admin Overview uses native dialog %s", native)
		}
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{".setup-checklist-list{", ".setup-check.fail{", ".setup-check-status.warn{", ".deliverability-form{", ".deliverability-message dl{"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("app.css lacks %q", required)
		}
	}
}
