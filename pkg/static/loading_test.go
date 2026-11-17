package static

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceLoadsUseSharedSkeletonAndPrefetch(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source, css, template := string(javascriptData), string(cssData), string(templateData)
	for _, required := range []string{
		"const loadingMarkup=(label,{variant='rows',columns=0}={})=>",
		`role="status"><span class="sr-only">Loading ${escapeHTML(label)}…</span>`,
		`<tr class="loading-skeleton-row"><td colspan="${Number(columns)}">`,
		"const prefetchOnce=url=>",
		"const page=await fetchMessagePage(mailListURL(currentFolder.id,parameters))",
		"fetchMessage=prefetchOnce(openedItemID?",
		"const page=await fetchContactPage('/api/v1/workspace/contacts/query?'+params",
		"files=await fetchFolderFiles('/api/v1/workspace/items?folder_id='",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js does not contain %q", required)
		}
	}
	for _, required := range []string{
		".loading-skeleton.skeleton-rows {", ".loading-skeleton.skeleton-spinner::before {", "var(--skeleton-bar)",
		"@media(prefers-reduced-motion:reduce){.loading-skeleton,.loading-skeleton::before{animation:none}}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("app.css does not contain %q", required)
		}
	}
	for _, required := range []string{
		`{{define "loading-rows"}}<div class="loading-skeleton skeleton-rows" role="status"><span class="sr-only">Loading {{.}}…</span></div>{{end}}`,
		`{{define "loading-spinner"}}<div class="loading-skeleton skeleton-spinner" role="status">`,
		`{{template "loading-rows" "messages"}}`, `{{template "loading-spinner" "calendar"}}`,
		`<td colspan="5">{{template "loading-rows" "contacts"}}</td>`, `<td colspan="5">{{template "loading-rows" "files"}}</td>`,
	} {
		if !strings.Contains(template, required) {
			t.Errorf("app.gohtml does not contain %q", required)
		}
	}
	for _, text := range []string{"Loading messages…", "Loading folders…", "Loading calendar…", "Loading contacts…", "Loading files…", "Loading trash…", "Loading quarantine…"} {
		if strings.Contains(template, text) || strings.Contains(source, text) {
			t.Errorf("workspace still renders visible placeholder text %q", text)
		}
	}
}
