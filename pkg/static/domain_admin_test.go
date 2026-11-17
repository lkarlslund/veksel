package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestDelegatedDomainAdministrationUI keeps the domain-scoped console and
// the system administrator's limits and domain administrator controls.
func TestDelegatedDomainAdministrationUI(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"domainScope=root.dataset.adminScope==='domain'",
		// Domain administrators never request system-only endpoints.
		"domainScope?Promise.resolve({settings:[]",
		"domainScope?{lifecycle_jobs:[],conversion_jobs:[],roots:[]}:api('/api/v1/admin/account-storage')",
		"(traceView||overview)&&!domainScope?api('/api/v1/admin/message-trace/status')",
		"if(!domainScope)document.querySelector('#new-domain').onclick",
		"if(!domainScope)document.querySelector('#import-accounts').onclick",
		// Limits and delegated administrators in the domain editor.
		"/limits`,{method:'PUT'",
		"Domain administrators",
		"/admins`",
		"data-remove-domain-admin",
		"title:'Remove domain administrator'",
		"name=\"address\" type=\"email\"",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("app.js lacks %q", required)
		}
	}
	for _, native := range []string{"window.confirm(", "window.prompt(", "window.alert("} {
		if strings.Contains(script, native) {
			t.Errorf("app.js uses native dialog %s", native)
		}
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{".domain-limits{", ".domain-admin-panel{", ".domain-admin-list li{", ".domain-usage-note{"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("app.css lacks %q", required)
		}
	}
}
