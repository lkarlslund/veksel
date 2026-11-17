package app

import (
	"strings"
	"testing"
)

func TestTemplatesReferenceVersionedAssets(t *testing.T) {
	handler, _ := testHandler(t)
	for _, name := range []string{"app.gohtml", "login.gohtml", "setup.gohtml", "share.gohtml"} {
		var out strings.Builder
		data := map[string]any{"ClientManifest": handler.clientManifest, "Client": handler.clientManifest}
		_ = handler.templates.ExecuteTemplate(&out, name, data)
		if !strings.Contains(out.String(), `/static/`) || !strings.Contains(out.String(), "?v=") {
			t.Fatalf("%s lacks versioned asset URLs", name)
		}
	}
}
