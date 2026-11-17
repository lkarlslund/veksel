package static

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedAssetsExist(t *testing.T) {
	err := fs.WalkDir(Content, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		t.Logf("embedded: %s (dir=%v)", path, d.IsDir())
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	files := []string{
		"js/app.js",
		"js/theme.js",
		"fonts/inter-var.woff2",
		"images/favicon.svg",
	}
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			f, err := Content.Open(name)
			if err != nil {
				t.Fatalf("open %s: %v", name, err)
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if len(data) == 0 {
				t.Errorf("%s is empty", name)
			}
			t.Logf("%s: %d bytes", name, len(data))
		})
	}
}

func TestDomainAdministrationUsesDKIMRotationModal(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	for _, required := range []string{
		"Manage DKIM keys",
		"dkim-key-dialog",
		"Rotate without breaking signatures",
		"data-dkim-activate",
		"data-dkim-delete",
		"/dkim/keys",
		"revision:data.revision",
		"error.status===409",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("DKIM rotation UI does not contain %q", required)
		}
	}
	if strings.Contains(javascript, `name="dkim_selector"`) {
		t.Error("ordinary domain editor still permits direct DKIM selector changes")
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{".dkim-key-dialog", ".dkim-key-record.active", "@media(max-width:600px)"} {
		if !strings.Contains(string(cssData), required) {
			t.Errorf("DKIM rotation styling does not contain %q", required)
		}
	}
}

func TestAdminNavigationSwitchesInPlace(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"history.pushState(null,'',link.pathname+link.search+link.hash)",
		"window.addEventListener('popstate',()=>{if(!showAdminRoute())location.reload()})",
		"adminLinkFor(link.pathname)", "event.metaKey||event.ctrlKey||event.shiftKey",
		"({section,protocol,operation}=adminRoute(location.pathname))",
		"api=supersedable(++renderSeq)", "if(token!==renderSeq)throw new DOMException", "if(e.name==='AbortError'||superseded())return", "resetAdminPaging()",
		"item.classList.toggle('active',active)", "item.setAttribute('aria-current','page')",
		"let root=document.querySelector('#admin-control-plane')", "the menu element is never recreated",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("admin in-place navigation is missing %q", required)
		}
	}
	if strings.Contains(script, "adminMenu.innerHTML") || strings.Contains(script, "adminMenu.replaceWith") {
		t.Error("admin menu must not be recreated on navigation")
	}
}

func TestManageSieveAdminCopyIsDefined(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, expected := range []string{"managesieve:'ManageSieve'", "managesieve:'Authenticated management of named Sieve filtering scripts.'"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("admin script is missing %q", expected)
		}
	}
}

func TestHTTPServe(t *testing.T) {
	// Test FileServer directly without mux prefix stripping
	srv := httptest.NewServer(http.FileServer(FS))
	defer srv.Close()

	tests := []struct {
		path     string
		wantCode int
		minBytes int
	}{
		{"/js/app.js", 200, 1000},
		{"/fonts/inter-var.woff2", 200, 10000},
		{"/images/favicon.svg", 200, 200},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.wantCode {
				t.Errorf("GET %s: status = %d, want %d, body = %q", tc.path, resp.StatusCode, tc.wantCode, string(body)[:min(100, len(body))])
			}
			if len(body) < tc.minBytes {
				t.Errorf("GET %s: body = %d bytes, want at least %d", tc.path, len(body), tc.minBytes)
			}
		})
	}
}

func TestServeFaviconUsesStableValidationAndSafeHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	response := httptest.NewRecorder()
	ServeFavicon(response, request)
	result := response.Result()
	body, err := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	etag := result.Header.Get("ETag")
	if result.StatusCode != http.StatusOK || result.Header.Get("Content-Type") != "image/svg+xml" || result.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(result.Header.Get("Cache-Control"), "must-revalidate") || etag == "" || !strings.Contains(string(body), "#3cc2b3") || !strings.Contains(string(body), "<title>Veksel</title>") {
		t.Fatalf("favicon status=%d type=%q cache=%q etag=%q body=%q", result.StatusCode, result.Header.Get("Content-Type"), result.Header.Get("Cache-Control"), etag, body)
	}
	request = httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	request.Header.Set("If-None-Match", etag)
	response = httptest.NewRecorder()
	ServeFavicon(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("conditional favicon status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAppDoesNotUseNativeBrowserDialogs(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, call := range []string{"confirm(", "alert(", "prompt("} {
		// A bare or window-qualified call opens a native dialog; a method on
		// another object, such as the install prompt event's prompt(), does not.
		for index := strings.Index(source, call); index >= 0; {
			before := byte(' ')
			if index > 0 {
				before = source[index-1]
			}
			member := before == '.' || before == '_' || before == '$' || before >= 'a' && before <= 'z' || before >= 'A' && before <= 'Z' || before >= '0' && before <= '9'
			if !member || strings.HasSuffix(source[:index], "window.") {
				t.Errorf("app.js contains native browser dialog call %q", call)
				break
			}
			next := strings.Index(source[index+len(call):], call)
			if next < 0 {
				break
			}
			index += len(call) + next
		}
	}
	if strings.Count(source, ".prompt(") != 1 || !strings.Contains(source, "deferredInstall.prompt()") {
		t.Error("only the browser install prompt may call prompt()")
	}
}

func TestComposerExposesDurableRequireTLSOption(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	for _, required := range []string{
		`name="require_tls"`,
		"Require encrypted delivery",
		"delivery fails instead of falling back to plaintext",
		"require_tls:form.get('require_tls')==='on'",
		"composeForm.elements.require_tls.checked=payload.require_tls===true",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("composer REQUIRETLS UI does not contain %q", required)
		}
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cssData), ".compose-require-tls") {
		t.Error("composer REQUIRETLS styling is missing")
	}
}

func TestThemeBootstrapSupportsAllModes(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"'auto'", "'light'", "'dark'", "prefers-color-scheme: dark", "localStorage", "data-theme-toggle", "data-theme-icon", "order.indexOf(current)"} {
		if !strings.Contains(source, required) {
			t.Errorf("theme.js does not contain %q", required)
		}
	}
}

func TestApplicationRailUsesCompactBorderlessLayout(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"--sidebar-w:56px", "border-right:0", "width:44px", "scrollbar-width:none"} {
		if !strings.Contains(source, required) {
			t.Errorf("app.css compact rail does not contain %q", required)
		}
	}
}

func TestCompactApplicationNavigationIsAccessibleAndDismissible(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := os.ReadFile("../web/app/templates/app.gohtml")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript, template := string(cssData), string(jsData), string(templateData)
	for _, required := range []string{".sidebar-backdrop", ".sidebar-close", "z-index:1030"} {
		if !strings.Contains(css, required) {
			t.Errorf("compact navigation CSS does not contain %q", required)
		}
	}
	for _, required := range []string{"sidebar.inert=compact.matches&&!visible", "main.inert=visible", "event.key==='Escape'", "restoreFocus:true", "aria-hidden"} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact navigation behavior does not contain %q", required)
		}
	}
	for _, required := range []string{`id="app-navigation"`, `class="rail-link sidebar-close"`, `class="sidebar-backdrop"`, `aria-controls="app-navigation"`, `aria-expanded="false"`} {
		if !strings.Contains(template, required) {
			t.Errorf("compact navigation template does not contain %q", required)
		}
	}
}

func TestCompactContactsUseSinglePaneNavigation(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := os.ReadFile("../web/app/templates/app.gohtml")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript, template := string(cssData), string(jsData), string(templateData)
	for _, required := range []string{".contacts-workspace.detail-open .contacts-table-pane", ".contacts-workspace.detail-open .contact-detail-pane", ".contact-mobile-toolbar"} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Contacts CSS does not contain %q", required)
		}
	}
	for _, required := range []string{"mobile_pane:mobilePane", "setContactPane('detail',{focus:true})", "setContactPane('list',{focus:true})", "tablePane.inert=showDetail", "event.key==='Enter'"} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact Contacts behavior does not contain %q", required)
		}
	}
	for _, required := range []string{`class="contact-mobile-toolbar"`, `id="contact-detail-back"`} {
		if !strings.Contains(template, required) {
			t.Errorf("compact Contacts template does not contain %q", required)
		}
	}
}

func TestContactDetailsExposeSafeContactMethods(t *testing.T) {
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	javascript, css := string(jsData), string(cssData)
	for _, required := range []string{
		"const contactMethodHref=",
		"mailto:${encodeURIComponent(address)",
		"/^\\+?[0-9*#,;]{3,}$/",
		"['http:','https:'].includes(parsed.protocol)&&parsed.hostname",
		`target="_blank" rel="noopener noreferrer"`,
		"['Email',value,'email']",
		"['Phone',value,'phone']",
		"['Website',selected.url,'website']",
		"contactEmailMarkup=value=>",
		"contactEmailMarkup(contactValue(contact,'email'))",
		"const contactEmailAddress=",
		"contactEmailLabel=value=>contactEmailAddress(value)||String(value||'').trim()",
		"label=kind==='email'?contactEmailLabel(raw):raw",
		`title="${escapeHTML(raw)}" aria-label="Email ${escapeHTML(raw)}"`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("actionable contact renderer does not contain %q", required)
		}
	}
	for _, required := range []string{".contact-method-link {", ".contact-method-link:focus-visible {"} {
		if !strings.Contains(css, required) {
			t.Errorf("actionable contact styles do not contain %q", required)
		}
	}
}

func TestAddressBookNameDoesNotInvitePersonalProfileAutofill(t *testing.T) {
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	const required = `<form id="addressbook-form"><div class="dialog-header"><div><span class="eyebrow">Contacts</span><h2>Create address book</h2></div><button type="button" class="icon-button" data-close aria-label="Close">×</button></div><label>Name<input name="name" required maxlength="120" autocomplete="off">`
	if !strings.Contains(string(template), required) {
		t.Fatal("address-book resource name must opt out of personal profile autofill")
	}
}

func TestSyncRunDetailsUseBoundedLazyFolderEvidence(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript := string(cssData), string(jsData)
	for _, required := range []string{".sync-evidence-toolbar", ".sync-evidence-pagination", ".sync-history-pagination", ".sync-reconciliation-table.responsive-table", ".sync-history-table.responsive-table"} {
		if !strings.Contains(css, required) {
			t.Errorf("bounded sync evidence CSS does not contain %q", required)
		}
	}
	for _, required := range []string{"const pageSize=20", `aria-label="Filter folder evidence" name="folder_filter" autocomplete="off"`, "page_size:'10'", "data.next_cursor", "sync-history-pagination", "run_history:runHistoryStates", "historyState.expanded_run", "runs.map(runSummary)", "const runBody=run=>", "Loading folder evidence", "/runs/${encodeURIComponent(runs[index].id)}", "if(details.open)", "other.open=false", "bindSyncEvidenceTable(table", "table.sync-reconciliation-table,table.sync-history-table"} {
		if !strings.Contains(javascript, required) {
			t.Errorf("bounded sync evidence behavior does not contain %q", required)
		}
	}
	for _, required := range []string{
		"folderResultStateLabel = (result) =>",
		"folderCompactOutcome = (result) =>",
		`class="sync-folder-destination"`,
		`class="sync-folder-compact-summary"`,
		`0).toLocaleString()} synced · ${Number(result.skipped_items || 0).toLocaleString()} unchanged · ${Number(result.failed_items || 0).toLocaleString()} failed`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact sync folder outcome does not contain %q", required)
		}
	}
	for _, required := range []string{
		`.sync-history-table .sync-folder-compact-summary { display:none; }`,
		`.sync-history-table .sync-folder-destination{display:none;flex-basis:100%;margin-top:0}`,
		`.sync-history-table .sync-folder-compact-summary{display:block;flex-basis:100%;margin-top:0}`,
		`.sync-history-table tr.responsive-expanded .sync-folder-destination{display:block}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("responsive sync folder outcome CSS does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"metric=()=>''", "folderRows=()=>''"} {
		if strings.Contains(javascript, forbidden) {
			t.Errorf("bounded sync evidence behavior still contains obsolete eager-render placeholder %q", forbidden)
		}
	}
	for _, required := range []string{"syncRunSummaryPerformance=run=>", "remainderSeconds", " elapsed`", "Throughput not recorded", "No source changes", "No measured throughput", `class="sync-history-performance"`, `class="sync-history-summary-footer"`} {
		if !strings.Contains(javascript, required) {
			t.Errorf("comparable sync run summary does not contain %q", required)
		}
	}
	if !strings.Contains(css, ".sync-history-performance { font-variant-numeric:tabular-nums;") {
		t.Error("comparable sync run summary lacks stable numeric styling")
	}
	if !strings.Contains(css, ".sync-history-summary-footer { display:flex;") {
		t.Error("comparable sync run summary does not keep performance and outcome compact")
	}
	for _, required := range []string{
		`@media(max-width:360px){.sync-history-summary-footer{align-items:flex-start;flex-direction:column;gap:.25rem}`,
		`.sync-history-summary-footer .status-pill{order:-1;max-width:100%}`,
		`.sync-history-performance{width:100%;overflow-wrap:normal}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("minimum-width sync run summary does not contain %q", required)
		}
	}
	for _, required := range []string{
		`role="tablist" aria-label="Synchronization detail views"`,
		`role="tabpanel" aria-labelledby="sync-detail-tab-overview"`,
		`role="tabpanel" aria-labelledby="sync-detail-tab-history"`,
		`void loadRunHistory(job)`,
		`syncUIState.detail_view=next`,
		`detailTarget.scrollTo({top:0,behavior:'auto'})`,
		`event.key==='ArrowRight'`,
		`event.key==='Home'`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("task-focused sync details do not contain %q", required)
		}
	}
	for _, required := range []string{".task-tabs { position:sticky;", ".task-tabs button:focus-visible", ".sync-detail-panel[hidden] { display:none; }"} {
		if !strings.Contains(css, required) {
			t.Errorf("task-focused sync details CSS does not contain %q", required)
		}
	}
}

func TestMailFlowAdvancedSettingsPersistLocally(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"veksel.admin.routing.advanced", "advanced-routing-settings", "advanced||!setting.advanced", "Outbound relay and queue"} {
		if !strings.Contains(source, required) {
			t.Errorf("mail-flow advanced settings do not contain %q", required)
		}
	}
}

func TestAdministrationSettingsModeIsExplicitAndShared(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript)
	for _, required := range []string{
		"settingsModeControl", "bindSettingsMode", `role="group"`,
		`aria-label="Settings detail level"`, `data-settings-mode="normal"`,
		`data-settings-mode="advanced"`, `aria-pressed="${!advanced}"`,
		"advanced-routing-settings", "security-mode", "advanced-settings",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("shared settings mode control does not contain %q", required)
		}
	}
	for _, required := range []string{
		".settings-mode-control { display:inline-flex; vertical-align:top; }",
		".settings-mode-control button { min-width:70px; }",
		".settings-mode-control button:focus-visible",
		"@media(min-width:721px){#admin-primary-action>.settings-mode-control+.btn{margin-left:.5rem}}",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("shared settings mode styling does not contain %q", required)
		}
	}
}

func TestTargetedAdvancedSecuritySettingRemainsVisibleInNormalMode(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		`setting.category==='security'&&(securityAdvanced||!setting.advanced||setting.key===targetSetting)`,
		`bindSettingsMode('security-mode','veksel.admin.security.advanced',securityAdvanced)`,
		`row.classList.add('setting-target')`,
		`row.scrollIntoView({block:'center'})`,
		`row.querySelector('input,select')?.focus({preventScroll:true})`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("targeted advanced Mail Security setting does not contain %q", required)
		}
	}
}

func TestOperationsShowsAndPrunesCompletionReceiptsWithModal(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"Completion receipts", "oldest_receipt_age_seconds", "queue-prune-receipts", "/api/v1/admin/queue/receipts/prune", "Dry run only", "openEditor('Prune completion receipts'", "{filter:false,key:r=>r.queue_id}", "{key:e=>String(e.sequence)}"} {
		if !strings.Contains(source, required) {
			t.Errorf("completion-receipt operations UI does not contain %q", required)
		}
	}
}

func TestEmptySystemQueueUsesCompactCollectionState(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		`queueBadge=queue.length?`,
		`queueBulk=queue.length?`,
		`compactEmpty:true,emptyMessage:'Queue is clear. New delivery work will appear here.'`,
		`queueTable=bulkToolbar?.closest('.card').querySelector('table')||null`,
		`if(queueTable){`,
		`if(queueView)toast('This delivery is no longer in the live queue.')`,
		`data-filter-empty hidden`,
		`No records match this filter.`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact System queue empty state does not contain %q", required)
		}
	}
}

func TestSystemQueueExposesBoundedDeliveryTranscript(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"Inspect delivery attempts",
		"'queue-inspect'",
		"/api/v1/admin/queue/${encodeURIComponent(id)}",
		"System queue · delivery transcript",
		"Delivery attempts",
		"attempts_dropped",
		"policyEvidenceMarkup(record.policy)",
		"Possible duplicate delivery",
		"Select outbound route",
		"Administrative route history",
		"record.administrative_route",
		"/reroute`,{method:'POST'",
		"Why is this delivery being rerouted?",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("queue transcript UI does not contain %q", required)
		}
	}
}

func TestAPIKeySettingsExposeOneTimeRotationFlow(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"data-rotate-key", "Rotate API key", "Its current secret will stop working immediately.",
		"/api/v1/user/api-keys/'+encodeURIComponent(key.id)+'/rotate", "showIssuedKey(rotated,true)",
		"API key rotated", "The previous secret has stopped working", "rotation_count", "rotated_at",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("API key rotation UI does not contain %q", required)
		}
	}
}

func TestOperationsUseTaskFocusedRoutesAndDataRequests(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := os.ReadFile("../web/app/templates/app.gohtml")
	if err != nil {
		t.Fatal(err)
	}
	javascript, css, template := string(javascriptData), string(cssData), string(templateData)
	for _, required := range []string{
		`data-operation="{{.AdminOperation}}"`, `href="/app/admin/operations/overview"`,
		`href="/app/admin/operations/logging"`, `href="/app/admin/operations/queue"`,
		`href="/app/admin/operations/trace"`, `href="/app/admin/operations/audit"`,
	} {
		if !strings.Contains(template, required) {
			t.Errorf("task-focused operations navigation does not contain %q", required)
		}
	}
	for _, required := range []string{
		"operation=root.dataset.operation||'overview'", "queueView?api('/api/v1/admin/queue'):[]",
		"auditView?api('/api/v1/admin/audit/page?'", "loggingView?api('/api/v1/admin/logging')",
		"traceView||overview?api('/api/v1/admin/message-trace?'", "if(auditView)", "if(queueView)",
		"if(traceView)", `class="operations-route-grid"`, "/app/admin/operations/queue?reveal=",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("task-focused operations behavior does not contain %q", required)
		}
	}
	for _, required := range []string{".operations-route-grid { display:grid;", "@media(max-width:720px){.operations-route-grid{grid-template-columns:1fr}"} {
		if !strings.Contains(css, required) {
			t.Errorf("task-focused operations styles do not contain %q", required)
		}
	}
}

func TestModuleLoggingUsesOneRegistryDrivenAdminPattern(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loggingLevels=['trace','debug','info','warn','error','fatal']", "/api/v1/admin/logging",
		"Logging by module", "appendPageLogging", "module.settings===location.pathname",
		"data-log-module", "module-log-level", "name=\"logging-${escapeHTML(module.id)}-level\"", "file_pattern", "Effective immediately",
		"${modules.length} module${modules.length===1?'':'s'}", ".module-logging-heading { display:flex;", ".module-logging-heading .badge { flex:0 0 auto; white-space:nowrap; }",
		".module-logging-heading small { display:block; margin-top:.2rem; color:var(--text-secondary); font-weight:400; }",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("module logging UI does not contain %q", required)
		}
	}
}

func TestAdministrationLoggingHasBoundedLiveViewer(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"/api/v1/admin/logging/entries?", `id="log-query-form"`, `id="log-follow"`, `id="log-new"`,
		"query({after:head})", "if(page.truncated){await reload();return}", "setTimeout(poll,2000)",
		"query({cursor:olderCursor})", "data-log-older", "history.replaceState(history.state,''",
		"params.get('min_level')", "navigator.clipboard.writeText(filteredText())", "link.download=`veksel-logs-",
		"sectionTeardown.push(()=>{clearTimeout(timer);clearTimeout(searchTimer);listening.abort()})", "teardownSection();",
		"detailMarkup(record)", "loggingCard(logging,logging.modules,'Log levels')",
		".log-scroll { flex:1; min-height:0; overflow:auto; overflow-anchor:none;", ".log-detail-fields { display:grid;",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("live administration log viewer does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"refreshLogEntries", "logCursorStack", "loadUIState('admin-log-viewer')"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("superseded operations log viewer still contains %q", forbidden)
		}
	}
	template, err := os.ReadFile("../web/app/templates/app.gohtml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(template), `href="/app/admin/logs">Logs</a>`) {
		t.Error("administration navigation has no top-level Logs entry")
	}
}

func TestMessageTraceWorkspacePersistsFiltersMaintainsIndexAndUsesTimeline(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loadUIState('admin-trace')", "persistTraceState", "trace-filter-panel", "correlation_id",
		"traceDateBoundary", "/api/v1/admin/message-trace/status", "trace-rebuild", "trace-prune",
		"openEditor('Message trace retention'", "trace-timeline", "duration_ms", "outcome_class", "Transport security",
		"data-open-related-trace", "data-open-live-queue", "trace-linked-row",
		`id="trace-prev" ${traceCursorStack.length?'':'disabled hidden'}`,
		`id="trace-next" ${tracePage.next_cursor?'':'disabled hidden'}`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("message-trace operations UI does not contain %q", required)
		}
	}
}

func TestOperationsAuditFeedUsesBoundedCursorPages(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loadUIState('admin-audit')", "persistAuditUI", "/api/v1/admin/audit/page?",
		"before_sequence", "auditCursorStack", "audit-page-size", "audit-refresh",
		"audit-previous", "audit-next", "showAuditPage", "navigateAuditPage",
		"audit-activity-card", ".audit-card-heading>div{flex:1 0 100%}",
		`.responsive-table[data-responsive-key="admin-operations-audit"] tbody td.responsive-primary{display:flex`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("paged operations audit UI does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "api('/api/v1/admin/audit')") {
		t.Error("operations UI still requests the eager compatibility audit response")
	}
}

func TestSyncWorkspaceMakesImportOnlyDirectionExplicit(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript)
	for _, required := range []string{
		"Source → Veksel", "source read-only", "never writes, moves, or deletes items on the source",
		"Reading source…", "apply remote changes in Veksel", "Calendaring Extensions to WebDAV (CalDAV)",
		"vCard Extensions to WebDAV (CardDAV)", "job.source?.capabilities?.direction_label",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("sync workspace does not contain %q", required)
		}
	}
}

func TestAdministrationSearchesStagesPlansAndRestoresConfiguration(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loadUIState('admin-config')", "persistStagedSettings", "setting.sensitive", "admin-setting-search",
		"adminSettingsRequest=null", "if(adminSettingsRequest)return adminSettingsRequest",
		".catch(error=>{adminSettingsRequest=null;throw error})", "return adminSettingsRequest",
		"clearStagedSettings();invalidateAdminSettings();configDialog.close()",
		"settingOwner", "data-setting-row", "admin-change-tray", "Review and apply", "setTimeout(stage,150)",
		"stagedSettingCount=()=>Object.keys(stagedSettings).length", "reviewSettingsLabel=count=>",
		"data-review-settings", "review.disabled=!count", "review.textContent=reviewSettingsLabel(count)",
		"/api/v1/admin/config/validate", "renderPlan", "dependency_groups", "restart_required",
		"/api/v1/admin/config/history?limit=50", "/validate`,{method:'POST'", "Review restore",
		"admin-config-dialog", "config-history-list", "setting-apply-state", "data-ui-state-only",
		"openConfigRevisionDetails", "data-inspect-revision", "Inspect ${changes.length} change",
		"configHistoryValueMarkup", "Values were redacted before", "Display truncated",
		"config-revision-diff", "config-history-values", "config-history-arrow",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("configuration operations UI does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), `<button class="btn btn-primary">Review changes</button>`) {
		t.Error("configuration form retains an always-enabled dead review action")
	}
}

func TestUserQuotaWorkspaceUsesCanonicalUsageProjection(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"/api/v1/account/usage", "quota-pressure", "quota-resource", "What uses your storage",
		"storage_percent", "items_percent", "Recoverably deleted items count", "quota-table-wrap",
		`=>limited?`, `<progress value=`, `class="quota-unlimited-state"`,
		`<span class="sr-only">; no limit configured</span>`,
		`.quota-resource-unlimited { grid-template-columns`, "no limit configured",
		"hasLimits=Boolean(status.storage_limited||status.items_limited)", "limits=hasLimits?",
		`${limits}<section class="settings-form-card quota-breakdown${hasLimits?'':' span-2'}">`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("user quota workspace does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), `${escapeHTML(value)} · Unlimited`) {
		t.Error("unlimited quota resources still duplicate their state beside the value")
	}
}

func TestAdminAccountsExposePersistentServerSideQuotaInventory(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loadUIState('admin-account-quota')", "/api/v1/admin/accounts/usage?", "account-quota-filters",
		"quota-summary-grid", "state_counts", "page_size", "data-quota-page", "openAccountDetails",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("administrator quota inventory does not contain %q", required)
		}
	}
}

func TestAccountDetailsUseStableActionsAndSemanticTabs(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(template), `id="admin-detail-actions"`) {
		t.Error("account details are missing the shared stable action footer")
	}
	for _, required := range []string{
		`role="tablist" aria-label="Account details"`, `role="tab" aria-controls="account-detail-panel"`,
		`role="tabpanel" aria-labelledby="account-detail-tab-edit"`,
		"candidate.setAttribute('aria-selected',String(active))", "candidate.tabIndex=active?0:-1",
		"panel.setAttribute('aria-labelledby',tab.id)", "['ArrowRight','ArrowDown','ArrowLeft','ArrowUp','Home','End']",
		"activateTab(tabs[next],{focus:true})", "tab.focus({preventScroll:true})",
		`form="account-edit-form"`, `id="account-edit-form"`, "const projectPanelActions=()",
		`name="account_id" value="${escapeHTML(user.id)}" disabled`,
		"while(actions.firstChild)detailActions.append(actions.firstChild)",
		"accountActionObserver.disconnect()", "resetDetailActions()",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("account details behavior does not contain %q", required)
		}
	}
	for _, required := range []string{
		".account-detail-dialog>.dialog-actions { flex:0 0 auto;",
		".account-detail-tabs button:focus-visible",
	} {
		if !strings.Contains(string(stylesheet), required) {
			t.Errorf("account details styles do not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), `<div class="dialog-actions"><button class="btn btn-primary" type="submit">Save account`) {
		t.Error("account Save action is still buried inside the scrolling panel")
	}
}

func TestSyncWorkspaceExposesPreflightAndConflictControls(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"/api/v1/sync-jobs/preflight", "folder_targets", "conflict_policy",
		"source_wins", "destination_wins", "keep_both", "migration-preflight",
		"cutover':'start", "/runs", "Final cutover sync", "sync-run-history",
		"source_peak_concurrency", "conflict_items", "preserved_items",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("sync workspace JavaScript does not contain %q", required)
		}
	}
	for _, required := range []string{".migration-preflight", ".migration-mapping-row", ".migration-mapping-row.conflict", ".sync-run-history", ".sync-history-metrics"} {
		if !strings.Contains(string(stylesheet), required) {
			t.Errorf("sync workspace stylesheet does not contain %q", required)
		}
	}
}

func TestMailPolicyAdministrationUsesSharedTableAndModalFramework(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loadUIState('admin-mail-policies')", "/api/v1/admin/mail-policies", "openPolicyEditor",
		"policy-builder-row", "policy-json-editor", "Advanced JSON", "Normal editor",
		"data-add-policy-condition", "data-add-policy-action", "confirmAction(`Delete the mail policy rule",
		"Discard the unsaved mail policy changes", "/api/v1/admin/mail-policies/reorder", "rule_matches", "CSS.escape(targetRule)",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("mail policy administration UI does not contain %q", required)
		}
	}
}

func TestOutboundTLSWorkspaceUsesPagedEvidenceAndPersistentFilters(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"loadUIState('admin-outbound-tls')", "/api/v1/admin/outbound-tls/status",
		"/api/v1/admin/outbound-tls/mta-sts?", "/api/v1/admin/outbound-tls/reports?",
		"mta-sts-filters", "tls-report-filters", "data-tls-page", "refresh-mta-sts",
		"Check recipient domain", "outbound-tls-workspace", "machine payload bytes are never returned",
		"admin-outbound-tls-policies", "admin-outbound-tls-reports", "data-row-id=\"${escapeHTML(entry.domain)}\"",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("outbound TLS workspace does not contain %q", required)
		}
	}
}

func TestMailPolicySimulatorAndTraceExposeEscapedExplanation(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet)
	for _, required := range []string{
		"openPolicySimulator", "policy-simulator-form", "/api/v1/admin/mail-policies/simulate",
		"Simulation uses the live policy revision", "policyEvidenceMarkup(response.result)",
		"policyEvidenceMarkup(record.policy)", "Admission policy", "/app/admin/policies?rule=",
		"rules_dropped", "conditions_dropped", "actions_dropped", "policy-evidence-rule",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("mail policy explanation UI does not contain %q", required)
		}
	}
}

func TestAccountStorageShowsDurableIntegrityJobsAndReports(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"Verify account integrity", "Repair derived account state", "items_scanned", "issues_found", "inspect-check", "/checks/${encodeURIComponent(j.report_id)}", "detailDialog.showModal()"} {
		if !strings.Contains(source, required) {
			t.Errorf("account integrity UI does not contain %q", required)
		}
	}
}

func TestToastsRenderInsideOpenDialogs(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"dialog[open]", "activeDialog.append(region)", "aria-live"} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js toast handling does not contain %q", required)
		}
	}
}

func TestMailTreePersistsWorkspaceState(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"veksel.ui.v1.", "collapsed_folder_ids", "folder_tree_initialized", "opened_item_id", "mobile_pane", "folder_scroll", "role','treeitem", "aria-expanded", "persistCalendarState", "persistContactState", "persistFileState"} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js mail tree state does not contain %q", required)
		}
	}
}

func TestFolderExportIsReachableAcrossUserWorkspaces(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template)
	for _, required := range []string{
		"downloadFolderExport", "/api/v1/workspace/folders/", "/export",
		`data-folder-action="export"`, `data-export-calendar`,
		`id="export-addressbook"`, `id="export-file-folder"`,
		"capabilities?.read_items===false",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("folder export UI does not contain %q", required)
		}
	}
}

func TestContactPortabilityUsesPreviewedModalWorkflow(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template) + string(stylesheet)
	for _, required := range []string{
		`id="contact-portability-dialog"`, `id="contact-import-preview"`,
		`/api/v1/workspace/contacts/import/preview`, `/api/v1/workspace/contacts/import`,
		`/api/v1/workspace/contacts/export`, `new FormData(portabilityForm)`,
		`options.body instanceof FormData`, `it never merges with or replaces existing contacts`,
		`result.valid?'valid':'invalid'`, `contact-import-preview invalid`,
		`id="contact-export-vcard"`, `id="contact-export-csv"`, `id="contact-export-zip"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("contact portability UI does not contain %q", required)
		}
	}
}

func TestAccountDataExportIsReachableFromProfile(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`id="download-account-export"`, `/api/v1/user/export`, `Download account data`,
		`Shared folders, recoverable trash and history`, `synchronization secrets`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("account export UI does not contain %q", required)
		}
	}
}

func TestMailTreeCanCollapseAndTraversePersistedHierarchy(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`id="collapse-mail-folders"`, `aria-label="Collapse other folder branches"`,
		`class="folder-toolbar-actions"`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("mail folder toolbar does not contain %q", required)
		}
	}
	for _, required := range []string{
		"const visibleMailFolderRows=", "const focusMailFolderRelative=", "const toggleMailFolder=",
		"const currentMailFolderAncestors=", "const collapseOtherMailFolders=",
		"collapsedFolderIDs=new Set([...parents].filter(id=>!ancestors.has(id)))",
		"collapseFolders.disabled=collapsible.every(id=>collapsedFolderIDs.has(id))",
		"focusTarget==='toggle'?replacement?.querySelector('.folder-toggle'):replacement",
		"node.querySelector(':scope > .folder-children > .folder-tree-node > .folder-row')",
		"event.key==='ArrowRight'", "event.key==='ArrowLeft'", "event.key==='ArrowDown'",
		"event.key==='ArrowUp'", "event.key==='Home'", "event.key==='End'",
		"collapseFolders.onclick=collapseOtherMailFolders", "active?.focus({preventScroll:true})",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("mail folder traversal does not contain %q", required)
		}
	}
	for _, required := range []string{
		".folder-toolbar-actions { display:flex;", ".toolbar-icon:disabled { opacity:.45; cursor:default; pointer-events:none; }",
		`body[data-page="mail"] .folder-toolbar{display:grid;grid-template-columns:64px minmax(0,1fr) 64px}`,
	} {
		if !strings.Contains(string(stylesheet), required) {
			t.Errorf("mail folder toolbar styles do not contain %q", required)
		}
	}
}

func TestMailBulkActionsRemainReachableAtMinimumWidth(t *testing.T) {
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(stylesheet)
	for _, required := range []string{
		`@media(max-width:360px){body[data-page="mail"] .message-toolbar:has(.bulk-actions:not([hidden])){display:grid;`,
		`grid-template-columns:auto auto minmax(0,1fr) auto;grid-template-rows:30px 30px`,
		`>#message-count{grid-column:4;grid-row:1;align-self:center;margin-left:0;white-space:nowrap}`,
		`>.bulk-actions{grid-column:1/-1;grid-row:2;justify-self:end}`,
		`.message-row.selected .message-meta small { color:var(--text-secondary); }`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("minimum-width Mail bulk toolbar does not contain %q", required)
		}
	}
}

func TestMailHeaderPreservesSearchAtMinimumWidth(t *testing.T) {
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`body[data-page="mail"] .mail-tools{gap:.4rem}`,
		`body[data-page="mail"] .mail-tools .topbar-search{width:auto;flex:1;min-width:0}`,
		`body[data-page="mail"] .mail-tools .topbar-search input{width:100%;min-width:0;padding-left:1.7rem;padding-right:.45rem}`,
		`body[data-page="mail"] #compose-toggle{padding:.45rem .6rem}`,
		`body[data-page="mail"] #compose-toggle{width:36px;min-width:36px;padding:0}`,
		`body[data-page="mail"] .compose-button-label{display:none}`,
	} {
		if !strings.Contains(string(stylesheet), required) {
			t.Errorf("minimum-width Mail header CSS does not contain %q", required)
		}
	}
	for _, required := range []string{
		`id="mail-search" type="search" placeholder="Search messages" aria-label="Search messages"`,
		`id="compose-toggle" aria-label="Compose message" title="Compose message"`,
		`<span aria-hidden="true">＋</span><span class="compose-button-label">Compose</span>`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("minimum-width Mail header template does not contain %q", required)
		}
	}
}

func TestMailPaginationStaysOutsideListboxAndTreeTargetsRemainCompact(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(template)
	list := strings.Index(markup, `id="message-list"`)
	more := strings.Index(markup, `id="mail-load-more"`)
	if list < 0 || more < 0 || more < list {
		t.Fatal("mail paging control must be a stable sibling after the message list")
	}
	for _, required := range []string{
		"messageList.setAttribute('role',items.length?'listbox':'status')",
		"mailLoadMore.hidden=!canLoadMore",
		"mailLoadMore.onclick=()=>loadMessagePage(false)",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("mail paging semantics do not contain %q", required)
		}
	}
	for _, required := range []string{
		"min-height:28px; padding:.125rem", "flex:0 0 24px", "width:24px", "height:24px",
	} {
		if !strings.Contains(string(stylesheet), required) {
			t.Errorf("compact folder target styles do not contain %q", required)
		}
	}
}

func TestMailWorkspaceRecoversStalePersistedSelections(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"restoreOpenedMessage=async()=>",
		"requestReaderWindow(openedItemID)",
		"restored=openedRow(windowPage.items)",
		"if(!restored){clearReader();return}",
		"if([403,404].includes(error.status)){clearReader();return}",
		"if(searchItems!==null){clearReader();return}",
		"if(mailSearch?.value)return",
		"showMessageError(error,()=>restoreOpenedMessage())",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("mail stale-selection recovery does not contain %q", required)
		}
	}
}

func TestMailWorkspaceUsesAnchoredWindowsForRestoredNavigation(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"currentItems=[],readerWindow=[]",
		"const readerItems=()=>",
		"around_item_id:itemID",
		"const openMessage=async(row,item,refreshWindow=false,focusID='')=>",
		"Promise.all([fetchMessage('/api/v1/workspace/mail/messages/'",
		"openMessage(row,item,usingReaderWindow)",
		"items=inVisible?visible:readerWindow",
		"inVisible?!nextPageCursor:true",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("restored mail navigation does not contain %q", required)
		}
	}
	if strings.Contains(source, "const restored=await api('/api/v1/workspace/item?item_id=") {
		t.Error("restored mail navigation still performs the superseded standalone item lookup")
	}
}

func TestMailWorkspaceSupportsResponsiveNavigationAndRecoverableFailures(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(stylesheet) + string(template)
	for _, required := range []string{
		"setMobilePane", "folders-open", "reader-open", "mail-reader-back", "mail-folders-toggle",
		"messageOpenToken", "openAdjacent", "queueWorkspaceRefresh", "data-mail-retry-message",
		"data-mail-retry-page", "data-mail-retry-folders", "loadingMarkup('message',{variant:'spinner'})", "mail-reader-mobile-toolbar",
		`name="name" required maxlength="120" autocomplete="off"`,
		"mailListURL(currentFolder.id,{around_item_id:itemID})", "parameters.cursor=nextPageCursor", "next_cursor",
		"messagePageSize=()=>mobileMail.matches?30:100", "limit:String(requestedPageSize)",
		"loadedPageSize=requestedPageSize", "pageSizeResetQueued=true",
		"loadedPageSize!==messagePageSize()", "queueMicrotask(()=>refreshMessages()",
		"itemView.dataset.itemPosition=String(openedItemPosition)",
		"openedItemPosition=Number(itemView.dataset.itemPosition)||0", "`Opened message · ${total} total`",
		"selectedIDs=new Set([...selectedIDs].filter(id=>searchItems.some(item=>item.id===id)))",
		".message-meta small:first-child { min-width:0; flex:1 1 auto; }",
		".message-meta small:last-child { flex:0 0 auto; white-space:nowrap; }",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("responsive mail workspace does not contain %q", required)
		}
	}
}

func TestMailWorkspaceUsesContextAwareAccessibleDates(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"displayDate=(value,now=new Date())=>",
		"if(Number.isNaN(date.valueOf()))return{label:'',full:''}",
		"date.getFullYear()===now.getFullYear()&&date.getMonth()===now.getMonth()&&date.getDate()===now.getDate()",
		"sameYear=date.getFullYear()===now.getFullYear()",
		"sameDay?{hour:'numeric',minute:'2-digit'}",
		"sameYear?{month:'short',day:'numeric'}:{month:'short',day:'numeric',year:'numeric'}",
		"{dateStyle:'medium',timeStyle:'short'}",
		`title="${escapeHTML(date.full)}" aria-label="${escapeHTML(date.full||'Unknown date')}"`,
		"escapeHTML(date.label)",
		"displayDate(item.internal_date||headers.date).label",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("mail date formatter does not contain %q", required)
		}
	}
	if strings.Contains(source, "escapeHTML(item.internal_date||'')") {
		t.Error("mail rows still expose only the raw timestamp through a pointer tooltip")
	}
}

func TestMailRowsUseConservativeFriendlySenderLabels(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"compactMailboxLabel=value=>",
		"if(!match)return raw",
		"return name||match[3]",
		":item.headers?.From||'Unknown sender',sender=",
		`title="${escapeHTML(rawSender)}" aria-label="${escapeHTML(rawSender)}"${conversation?.participants?.length>1?'':`, `data-person="${escapeHTML(addressKey(rawSender))}"`, "`}>${escapeHTML(sender)}</small>", ":compactMailboxLabel(rawSender)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("friendly Mail sender projection does not contain %q", required)
		}
	}
}

func TestAdminOverviewUsesCanonicalProtocolHealth(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"api('/api/v1/admin/health')",
		"new Set(['http','smtp','imap','pop3','caldav','jmap','ews','eas'])",
		"protocolComponents=(healthSnapshot.components||[]).filter",
		"desiredProtocols=protocolComponents.filter(component=>component.desired)",
		"healthyProtocols=desiredProtocols.filter(component=>component.state==='healthy')",
		"protocolAttention=desiredProtocols.length-healthyProtocols.length",
		"<span>Services</span>",
		"need attention",
		"All configured services healthy",
		"No protocol services configured",
		"Not in this build:",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("administration Overview protocol health does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"Protocols available", "Object.values(settings.status||{}).filter(Boolean)", "total=4+compiled.length"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("administration Overview retains mixed protocol inference %q", forbidden)
		}
	}
}

func TestFilesWorkspaceUsesPersistentCompactFolderDrawer(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`id="files-layout"`, `id="file-folder-pane"`, `id="open-file-folders"`,
		`aria-controls="file-folder-pane"`, `aria-expanded="false"`,
		`id="close-file-folders"`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("files workspace template does not contain %q", required)
		}
	}
	for _, required := range []string{
		"mobile_pane:mobilePane", "const setFilePane=", "folderPane.inert=compact&&!foldersOpen",
		"filesPane.inert=compact&&foldersOpen", "openFolders.onclick=()=>setFilePane('folders'",
		"closeFolders.onclick=()=>setFilePane('content'", "event.key==='Escape'",
		"compactFilesQuery.addEventListener('change'", "openFileFolder(folder,false,true)",
		"folderList.setAttribute('role','tree')", "row.setAttribute('role','treeitem')",
		"collapsed_folder_ids:[...collapsedFileFolderIDs]", "row.setAttribute('aria-expanded',String(expanded))",
		"const visibleFileFolderRows=", "const appendBranch=(parentID,parentElement,depth=1)",
		"focusTarget==='toggle'?replacement?.querySelector('.folder-toggle'):replacement",
		"node.querySelector(':scope > .folder-children > .folder-tree-node > .folder-row')",
		"event.key==='ArrowRight'", "event.key==='ArrowLeft'", "event.key==='ArrowDown'",
		"event.key==='ArrowUp'", "event.key==='Home'", "event.key==='End'",
		"foldersOpen?closeFolders:openFolders).focus(),foldersOpen?200:0",
		"folderDialog.showModal();folderForm.elements.name.focus();folderForm.elements.name.select()",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("files compact folder drawer does not contain %q", required)
		}
	}
	for _, required := range []string{
		".files-layout { display:grid; grid-template-columns:240px minmax(0,1fr)",
		".files-layout{display:block;position:relative;overflow:hidden}",
		".files-layout.folders-open>.folder-pane{visibility:visible;transform:none}",
		".file-folders-open,.file-folders-close{display:grid}",
		"#folder-list .folder-tree-node,#file-folder-list .folder-tree-node",
		"#folder-list .folder-toggle,#file-folder-list .folder-toggle",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("files compact folder drawer styles do not contain %q", required)
		}
	}
}

func TestFilesWorkspaceUsesActionableTruthfulEmptyStates(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}

	for _, required := range []string{
		"const emptyFileMarkup=()", "No matching files", "data-file-empty-action=\"clear\"",
		"data-file-drop-zone", "Empty folder. Upload files or create a folder.",
		"data-file-empty-action=\"upload\"", "data-file-empty-action=\"folder\"",
		"const bindFileEmptyState=()", "event.dataTransfer?.types", "event.dataTransfer.dropEffect='copy'",
		"uploadFiles(event.dataTransfer?.files)", "const uploadFiles=async fileList",
		"await uploadFiles(uploadInput.files)", "data-file-drop-status", "Upload failed:",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("files empty-state behavior does not contain %q", required)
		}
	}
	for _, required := range []string{
		".files-table .file-empty-cell { display:table-cell; padding:0;", ".file-empty-state { display:grid;",
		".file-empty-state.drag-active", ".file-empty-state.upload-error",
		".responsive-table td.file-empty-cell{padding:0}",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("files empty-state styles do not contain %q", required)
		}
	}
	if count := strings.Count(string(template), `id="file-upload-input"`); count != 1 {
		t.Errorf("file upload input count = %d, want 1 shared input", count)
	}
	for _, required := range []string{
		`id="file-folder-form"`, `name="name" required maxlength="120" autocomplete="off"`,
		`id="file-editor-form"`, `name="name" required autocomplete="off"`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("files form markup does not contain %q", required)
		}
	}
}

func TestCalendarWorkspaceManagesFoldersWithoutNativeDialogs(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template)
	for _, required := range []string{
		"calendar-folder-list", "data-edit-calendar", "data-default-calendar",
		"manage_open", "manage_calendar_id", "collapsed_calendar_ids", "data-toggle-calendar", "default:true", "calendar-folder-new",
		"calendar-count", "No events", "> Manage</button>", "Built-in · ",
		"/api/v1/workspace/folders/", "/restore", "confirmAction", "Create, rename, organize, delete, or choose the default calendar",
		"selected_calendar_ids", "calendar_colors", "visibleRange", "overlapsDay", "recurrence", "timezone", "data-calendar-color",
		"const calendarMinimum=matchMedia('(max-width: 360px)')",
		"const calendarPeriodRange=(start,end,year='numeric')=>",
		"const calendarFullPeriod=()=>{if(view==='month')return new Intl.DateTimeFormat(undefined,{month:'long',year:'numeric'})",
		"const calendarMinimumPeriod=()=>{if(view==='month')return new Intl.DateTimeFormat(undefined,{month:'short',year:'numeric'})",
		"if(view==='day')return new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric',year:'numeric'}).format(anchor)",
		"return calendarPeriodRange(start,end,'2-digit')",
		"setCalendarPeriod=value=>{period.textContent=calendarMinimum.matches?calendarMinimumPeriod():value;period.title=value;period.setAttribute('aria-label',value)}",
		"calendarMinimum.addEventListener('change',()=>setCalendarPeriod(calendarFullPeriod()))",
		"formatter.formatRange?formatter.formatRange(start,end)",
		"weekday:'short',month:'short',day:'numeric',year:'numeric'",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("calendar management UI does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("calendar management introduced a native browser dialog")
	}
}

func TestCalendarEventsMoveAndResizeThroughSharedUpdateFlow(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"calendar-adjust-dialog", "calendar-adjust-form", "calendar-recurrence-scope",
		"This occurrence only", "The entire series", "Move / resize",
		`name="summary" required maxlength="240" autocomplete="off"`,
		`name="location" maxlength="500" autocomplete="off"`,
		`name="name" required maxlength="120" autocomplete="off"`,
	} {
		if !strings.Contains(string(template)+string(javascript), required) {
			t.Errorf("calendar adjustment flow does not contain %q", required)
		}
	}
	for _, required := range []string{
		"data-occurrence", "data-resize=\"start\"", "data-resize=\"end\"",
		"button.onpointerdown", "button.onkeydown", "key.altKey", "key.shiftKey",
		"recurrence_scope='occurrence'", "payload.recurrence_id=undoPayload.recurrence_id=event.recurrence_id",
		"clearCalendarProjections();await loadEvents()", "calendar-drag-status", "canUpdateEvent",
		"data-editable=\"${editable}\"", "if(!canUpdateEvent(event))return", "Event change undone.",
		"Series change undone.", "label:'Undo'",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("calendar direct manipulation does not contain %q", required)
		}
	}
	for _, required := range []string{
		".calendar-resize-handle", ".calendar-event.drag-preview", ".calendar-drop-target",
		".calendar-adjust-dialog", "touch-action:none", ".calendar-event.read-only",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("calendar direct manipulation styles do not contain %q", required)
		}
	}
}

func TestCalendarEventInspectionUsesBoundedModal(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"calendar-event-detail-dialog", "calendar-event-detail-content", "calendar-detail-edit",
		"calendar-detail-adjust", "calendar-detail-delete", "openEventDetail(event)",
		"event.organizer", "event.attendees", "event.categories", "eventSafeURL", "calendar-detail-no-footer-actions",
		"eventTimeLabel=(event,start,end)=>{if(!start)return 'Unknown start'", "dateStyle:'medium'", "timeStyle:'short'",
		"${time.format(start)}–${time.format(end)}", "dayKey(start)===dayKey(end)",
		"calendarDescriptionMarkup=value=>", "pattern=/https?:\\/\\/[^\\s<>",
		"while(/[.,;:!?]$/.test(url))", "const safe=eventSafeURL(url)",
		"calendarDescriptionMarkup(event.description)", `aria-label="Open link: ${escapeHTML(url)}"`,
		`target="_blank" rel="noopener noreferrer"`,
	} {
		if !strings.Contains(string(template)+string(javascript), required) {
			t.Errorf("calendar detail modal does not contain %q", required)
		}
	}
	for _, required := range []string{
		".calendar-event-detail-dialog { width:min(640px,calc(100vw - 1rem)); max-height:calc(100dvh - 1rem);",
		"border:1px solid var(--border-color);", "box-shadow:0 16px 44px", ".calendar-event-detail-content { display:grid;", "overflow-wrap:anywhere", "word-break:break-all",
		".calendar-detail-description a { color:var(--text-link); font-weight:650; text-decoration:underline;",
		".calendar-detail-technical summary { display:list-item; min-height:24px;",
		".calendar-event-detail-dialog .dialog-actions>[data-close]{display:none}", ".calendar-event-detail-dialog.calendar-detail-no-footer-actions .dialog-actions{display:none}",
		"@media(max-width:360px){.calendar-event-detail-dialog .dialog-actions{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}",
		".calendar-event-detail-dialog #calendar-detail-edit{grid-column:1/-1;width:100%;min-width:0}",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("bounded calendar detail styles do not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "calendar-event-popover") {
		t.Error("legacy body-level calendar popover remains in the application")
	}
}

func TestDarkDangerButtonsUseContrastingInkAndHoverSurface(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`html[data-color-scheme="dark"] .btn-danger { color:#102f38; }`,
		`html[data-color-scheme="dark"] .btn-danger:hover { color:#102f38; background-color:#ff958d; border-color:#ff958d; }`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("dark destructive button CSS does not contain %q", required)
		}
	}
}

func TestAutomationWorkspaceUsesPersistentTableAndModalFlows(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template)
	for _, required := range []string{
		"automation-rule-rows", "automation-rule-dialog", "automation-run-dialog", "automation-history-dialog", "automation-detail-dialog",
		"automation-rules-toolbar", "automation-rules-collection", "automation-rules-empty", "genuinelyEmpty=!all.length&&!query",
		"toolbar.hidden=genuinelyEmpty", "collection.hidden=genuinelyEmpty", "empty.hidden=!genuinelyEmpty",
		"loadUIState('automation')", "history_open", "run_filter", "run_sort", "expanded_runs", "data-rule-row", "ondragstart", "saveOrder",
		"folder.trashed_at.startsWith('0001-')",
		"rulesChanged=nextDocument.revision!==rulesDocument.revision",
		"/api/v1/automation/reorder", "/preview", "/runs", "/evidence", "confirmAction", "Rule deleted · retained snapshot only",
		"History records cannot run rules", "data-run-sort", "Cancel active run", "Inspect retained record",
		"table.automation-runs-table", "data-row-id=\"${escapeHTML(run.id)}\"", "automation-run-compact-summary", "table.dataset.responsiveKey='automation-runs'",
		"renderRunSortState", "aria-sort", "responsive-table-controls select",
		"trash:'Move to trash'", "Recoverable; must be the final action.",
		"['add_flag','remove_flag','add_tag','remove_tag'].includes(type)",
		"trashIndex=rule.actions.findIndex", "Move to trash must be the final action.",
		"entry.final_trashed?'Trash'",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("automation workspace does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("automation workspace introduced a native browser dialog")
	}
	if strings.Contains(source, "data-retry-run") || strings.Contains(source, "automation-runs-card") {
		t.Error("run history still exposes rerun controls or dominates the settings page")
	}
	if !strings.Contains(string(css), ".automation-rules-card>#automation-rules-empty { min-height:96px;") {
		t.Error("genuine empty rules state does not use the compact card treatment")
	}
	for _, required := range []string{
		`.automation-history-toolbar{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))`,
		`.automation-runs-table .automation-run-compact-summary{display:flex`,
		`.automation-history-dialog .responsive-table-controls>span{display:none}`,
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("compact automation run history CSS does not contain %q", required)
		}
	}
}

func TestComposerAutocompleteUsesContactSuggestionAPIAndKeyboardControls(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data) + string(css)
	for _, required := range []string{"workspace/people/suggestions", "workspace/people/group", "setupRecipientAutocomplete", "createCombobox", "recipient-group-expand", "ArrowDown", "ArrowUp", "aria-activedescendant", "AbortController", "suggestion.photo_url", "data-recipient-photo", `loading="lazy" decoding="async" referrerpolicy="no-referrer"`, "image.addEventListener('error',()=>image.remove()", ".recipient-suggestion-avatar img"} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js composer autocomplete does not contain %q", required)
		}
	}
}

func TestComposerExplainsMissingSendingIdentity(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`placeholder="Assigned or delegated address"`,
		`id="compose-identity-status" class="compose-identity-status" role="status" aria-live="polite" hidden`,
		`identityBaseStatus=personal.length?'':sendingIdentities.some(identity=>identity.delegated)?'No personal email identity is assigned.`,
		`identityBaseStatus='Sending identities could not be loaded. You can still enter an assigned or delegated address.'`,
		`const initialField=composeForm.elements.from.value?composeForm.elements[action==='new'||action==='forward'?'to':'body']:composeForm.elements.from;if(initialField===bodyField)focusComposeBody(true);else initialField.focus()`,
		`.compose-identity-status { margin-top:.15rem; padding:.45rem .55rem;`,
	} {
		if !strings.Contains(string(javascript)+string(template)+string(css), required) {
			t.Errorf("composer identity guidance does not contain %q", required)
		}
	}
	if strings.Contains(string(template), `placeholder="you@example.com"`) {
		t.Error("composer still presents a fictitious sending identity")
	}
}

func TestComposerDistinguishesDelegatedSendingIdentities(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		`const personal=sendingIdentities.filter(identity=>!identity.delegated),primary=personal.find(identity=>identity.primary)||personal[0]`,
		`identity.delegated?` + "`Delegated · ${(identity.modes||[]).map(sendingModeLabel).join(' / ')}`" + `:'Personal identity'`,
		"Delegated identity · Allowed modes:",
		`settings.identities.filter(identity=>!identity.delegated&&!identity.alias)`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("delegated composer identity behavior does not contain %q", required)
		}
	}
}

func TestComposerAttachmentsSupportFilesDropPasteAndDraftRecovery(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template)
	for _, required := range []string{"compose-attachment-input", "compose-attachment-drop", "addComposeFiles", "event.clipboardData?.items||[]", "payload.attachments=[...composeAttachments,...inline]", "workspace/mail/drafts/", "FileReader", "draft_id", "includeAttachments"} {
		if !strings.Contains(source, required) {
			t.Errorf("composer attachment flow does not contain %q", required)
		}
	}
}

func TestComposerKeepsFailuresAndProgressInsideDialog(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template)
	for _, required := range []string{"compose-operation-status", "Message was not accepted", "Draft could not be saved", "Preparing ${file.name}", "requestComposerClose", "requestSubmit()", "peopleSuggestionCache"} {
		if !strings.Contains(source, required) {
			t.Errorf("composer daily flow does not contain %q", required)
		}
	}
}

func TestComposerScheduledSendUsesDurableDraftLifecycle(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template) + string(css)
	for _, required := range []string{
		`id="send-later"`,
		`id="schedule-mail-dialog"`,
		`id="scheduled-mail-dialog"`,
		`id="scheduled-mail-filter" data-ui-state-only`,
		`/api/v1/mail/scheduled`,
		`Saving the latest draft before scheduling`,
		`latest saved draft when they become due`,
		`scheduled_job_id`,
		`scheduled-mail-error`,
		`scheduleTimezone`,
		`due.toISOString()`,
		`saveUIState('scheduled-mail'`,
		`confirmAction('Cancel this scheduled message?`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("scheduled composer flow does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"window.confirm(", "window.prompt(", "window.alert("} {
		if strings.Contains(source, forbidden) {
			t.Errorf("scheduled composer flow contains native dialog call %q", forbidden)
		}
	}
}

func TestMailImportanceUsesComposerDraftAndReaderContracts(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css)
	for _, required := range []string{
		`name="importance"`,
		`<option value="normal">Normal</option><option value="high">High</option><option value="low">Low</option>`,
		`importance:form.get('importance')`,
		`['from','mode','importance','subject']`,
		`mailImportance(item.headers)`, `mailImportance(headers)`,
		`messageMarksMarkup`,
		"`mail-importance-mark ${importance}`",
		`.compose-delivery-options { display:grid;`,
		`.mail-importance-mark.high`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("mail importance UI does not contain %q", required)
		}
	}
}

func TestComposerFitsCompactViewport(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		"#compose-dialog { max-height:calc(100dvh - 2rem); padding:0; overflow:hidden; }",
		"#compose-dialog form { max-height:calc(100dvh - 2rem); grid-template-rows:minmax(0,1fr) auto; gap:0; overflow:hidden; }",
		".compose-editor-scroll { display:grid; gap:1rem; min-width:0; min-height:0; padding:1rem; overflow:auto; }",
		"#compose-dialog .dialog-actions { padding:1rem; border-top:1px solid var(--border-color); background:var(--bg-secondary); }",
		"#compose-dialog{width:calc(100vw - 1rem);max-width:calc(100vw - 1rem);max-height:calc(100dvh - 1rem)}",
		"#compose-dialog form{max-height:calc(100dvh - 1rem)}",
		"#compose-dialog .compose-editor-scroll{padding:.75rem}",
		"#compose-dialog form,#compose-dialog label,#compose-dialog .compose-copy-fields,#compose-dialog .recipient-field,#compose-dialog .compose-attachments,#compose-dialog .dialog-header,#compose-dialog .dialog-actions{min-width:0}",
		"#compose-dialog .dialog-actions{display:grid;grid-template-columns:auto minmax(0,1fr) auto",
		"padding:.65rem .75rem",
		"#compose-dialog #draft-save-status{grid-column:1/3;grid-row:1}",
		"#compose-dialog .compose-attach-action{display:grid;grid-column:3;grid-row:1;justify-self:end",
		"#compose-dialog .compose-attach-action:focus-visible{outline:2px solid var(--brand)",
		"#compose-dialog #send-message{grid-column:3;grid-row:2}",
		"@media(max-width:360px){#compose-dialog .compose-editor-scroll{gap:.55rem}",
		"#compose-dialog .compose-editor-scroll :is(input:not([type=file]),select,textarea){padding:.58rem .65rem}",
		"#compose-dialog .compose-editor-scroll :is(input:not([type=file]),select){box-sizing:border-box;min-height:40px}",
		"#compose-dialog .compose-identity-status{padding:.35rem .45rem}",
		"#compose-dialog .dialog-header h2{margin:.1rem 0;font-size:1.35rem}",
		"#compose-dialog .compose-mode-field{grid-template-columns:auto minmax(0,1fr);align-items:center;gap:.65rem}",
		"#compose-dialog .compose-mode-field select{min-width:0}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact composer CSS does not contain %q", required)
		}
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(template), `<div class="compose-editor-scroll"><div class="dialog-header">`) {
		t.Error("composer fields are not isolated in the bounded editor scroller")
	}
	if !strings.Contains(string(template), `<label class="compose-mode-field">Sending mode<select name="mode">`) {
		t.Error("composer sending mode does not opt into the minimum-width inline projection")
	}
	if count := strings.Count(string(template), `id="compose-attachment-input"`); count != 1 {
		t.Errorf("composer contains %d attachment inputs, want one", count)
	}
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"attachmentAction.className='toolbar-icon compose-attach-action'",
		"attachmentAction.onclick=()=>attachmentInput.click()",
		"new MutationObserver(updateAttachmentAction).observe(attachmentList,{childList:true})",
		"`Add attachments, ${count} attached`",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("compact composer attachment action does not contain %q", required)
		}
	}
}

func TestMailReaderUsesSafeMIMEProjectionAndAttachmentCards(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css)
	for _, required := range []string{"workspace/mail/messages/", "remote_content_blocked", "data-body-mode", "message-html-body", "message-attachment-card", "unsafe_content_removed"} {
		if !strings.Contains(source, required) {
			t.Errorf("mail MIME reader does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "decodeItem(full.data)") {
		t.Error("mail reader still parses raw MIME in the browser")
	}
	for _, required := range []string{"const richMessageCSS=", "renderSanitizedMessageHTML=", "attachShadow({mode:'open'})", "rich-message-canvas", "nofollow noopener noreferrer", ".rich-message-frame", "link.getAttribute('aria-labelledby')", "link.querySelectorAll('img[alt]')", "link.replaceWith(...link.childNodes)"} {
		if !strings.Contains(source, required) {
			t.Errorf("contained HTML message renderer does not contain %q", required)
		}
	}
	if strings.Count(string(javascript), "renderSanitizedMessageHTML(bodyHost") < 2 {
		t.Error("Mail and Search do not share the contained HTML message renderer")
	}
	if strings.Contains(string(css), ".message-html-body :is(td,th)") {
		t.Error("application cell styling still leaks into sanitized HTML messages")
	}
}

func TestMailAndFilePreviewUseSharedBoundedVekselModal(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css) + string(template)
	for _, required := range []string{
		`id="attachment-preview-dialog"`,
		`id="attachment-preview-download" data-content-preview-download download`,
		`id="file-preview-dialog"`,
		"data-file-action=\"preview\"",
		"data-attachment-preview",
		"createContentPreview",
		"ContentPreview",
		"/preview",
		"frame.setAttribute('sandbox','')",
		"preview.textContent=await blob.text()",
		"content-preview-text",
		"content-preview-loading",
		"content-preview-error",
		".content-preview-dialog { width:min(900px,calc(100vw - 2rem));",
		"height:calc(100dvh - 1rem)",
		".files-table th { position:sticky; top:0;",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("shared content preview UI does not contain %q", required)
		}
	}
	// The only new window is the support action that opens an account in
	// a new tab (opened before the impersonation request so popup blockers
	// allow it); content preview never opens one.
	if strings.Count(string(javascript), "window.open(") > 1 || !strings.Contains(string(javascript), "const tab=window.open('about:blank','_blank')") || strings.Contains(string(javascript), "window.confirm(") {
		t.Error("content preview introduced a native browser surface")
	}
}

func TestFilesExposeGenericItemHistoryWorkflow(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css) + string(template)
	for _, required := range []string{
		`id="file-history-policy-dialog"`,
		`id="file-versions-dialog"`,
		`name="retention_days"`,
		`name="max_versions"`,
		"data-file-action=\"history\"",
		"Item history settings",
		"Earlier versions",
		"The current file will be retained as another version.",
		"folder.history.configured",
		"item.history.restored",
		"/versions",
		"/restore",
		".file-history-dialog",
		".file-version-row",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("file history workflow does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") {
		t.Error("file history uses a native browser confirmation")
	}
}

func TestSearchWorkspacesExposeIndexHealthAndRecovery(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template)
	for _, required := range []string{"createSearchHealth", "search-index-health", "serving_index_id", "serving_documents", "resume_count", "last_completed_folder_id", "Build started", "Last resumed", "data-search-health-retry", "data-search-health-rebuild", "contact-index-health"} {
		if !strings.Contains(source, required) {
			t.Errorf("search health UI does not contain %q", required)
		}
	}
}

func TestSearchSelectedAndDetailMetadataUseStrongSemanticText(t *testing.T) {
	stylesheet, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		".search-facet.active { color:var(--brand-hover); }",
		".search-result.active .search-result-copy :is(small,em) { color:var(--text-secondary); }",
		".search-detail header :is(.eyebrow,p),.search-detail dt { color:var(--text-secondary); }",
	} {
		if !strings.Contains(string(stylesheet), required) {
			t.Errorf("Search contextual contrast styles do not contain %q", required)
		}
	}
}

func TestContactsRevealRestoredSelection(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript)
	for _, required := range []string{
		"if(!selected&&restoreSelection&&selectedID&&!contactSearch.value)",
		"restoreSelection&&selectedID&&selected?.id===selectedID",
		"rows.querySelector(`[data-contact-id=\"${CSS.escape(selectedID)}\"]`)",
		"scrollIntoView({block:'nearest'})",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("contact selection restoration does not contain %q", required)
		}
	}
}

func TestContactsProjectPersistedSortStateIntoEveryControl(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	for _, required := range []string{
		"const contactSortButtons=[...document.querySelectorAll('[data-contact-sort]')]",
		"button.dataset.contactSort===sortKey",
		"button.classList.toggle('active',active)",
		"button.querySelector('span').textContent=active?(sortDirection===-1?'↓':'↑'):'↕'",
		"button.closest('th').setAttribute('aria-sort',active?direction:'none')",
		".contacts-table-wrap .responsive-table-controls select",
		"compactSort.value=String(activeButton.closest('th').cellIndex)",
		"updateContactSortState();persistContactState();loadContacts(true,true)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("contact sort state projection does not contain %q", required)
		}
	}
}

func TestContactsUseLazySummariesAndRaceSafeDetails(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript)
	for _, required := range []string{
		"contactPageLimit=()=>contactMedia.matches?30:100",
		"limit:String(contactPageLimit())",
		"contactMedia.addEventListener('change'",
		"loadContacts(true,true)",
		"`${contactTotal} match${contactTotal===1?'':'es'} · ${contacts.length} loaded`",
		"view:'summary'",
		"photo_token",
		"/api/v1/workspace/contacts/${encodeURIComponent(contact.id)}/photo",
		`loading="lazy" decoding="async"`,
		"contactDetailController?.abort()",
		"generation!==contactDetailGeneration||selected?.id!==id",
		"contactDetails.get(contact.id)",
		"while(contactDetails.size>20)",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("contact summary/detail behavior does not contain %q", required)
		}
	}
}

func TestNotificationsWorkspaceUsesSafeModalCRUDAndPersistedFilters(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css) + string(template)
	for _, required := range []string{"admin-notifications", "/api/v1/admin/notifications/webhooks", "openWebhookEditor", "openWebhookDeliveries", "has_secret", "webhook-event-options", "webhook-pagination", `/app/admin/notifications`, "webhook-secret-dialog", "/rotate-secret", "Secret shown once", "previous signing secret stopped working immediately", "secret_rotation_count"} {
		if !strings.Contains(source, required) {
			t.Errorf("notifications workspace does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("notifications workspace introduced a native browser dialog")
	}
	if !strings.Contains(string(javascript), "notificationCard=search.closest('.card'),rows=[...notificationCard.querySelectorAll('tbody tr[data-row-id]')]") {
		t.Error("notifications workspace counts the empty table placeholder as an endpoint")
	}
}

func TestHealthWorkspaceFormatsCapacityAndLinksComponentOwners(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css)
	for _, required := range []string{
		"healthDetail", "healthDuration", "health-capacity", "used_percent",
		"/app/admin/notifications", "/app/admin/settings?setting=account_storage_roots",
		"Inspect delivery", "Manage storage",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("health remediation UI does not contain %q", required)
		}
	}
}

func TestSearchWorkspaceHasPersistedBuilderAndTypedInspection(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template) + string(css)
	for _, required := range []string{
		"search-advanced-panel", "search-filter-count", "buildFilter", "advancedValues", "const query=currentQuery()",
		"attachmenttext", "data-open-search-result", "renderMailResult", "renderContactResult", "renderCalendarResult",
		"/api/v1/workspace/mail/messages/", "/api/v1/workspace/contact?item_id=", "/api/v1/workspace/calendar/events/",
		"/api/v1/workspace/files/", "saveUIState('search'", "search-detail-dialog", "search-detail-close",
		"showNarrowDetail", "closeNarrowDetail", "detailDialog.showModal()", "detailDialog.addEventListener('cancel'",
		"narrowSearch.addEventListener('change'", ".search-detail-dialog[open]{display:grid;width:100vw;height:100dvh",
		"const searchMailDateMarkup=", "searchMailDateMarkup(headers.date,hit.date)",
		`datetime="${escapeHTML(date.toISOString())}"`, `aria-label="${escapeHTML(exact)}"`,
		"return escapeHTML(raw||'Unknown date')",
		`const detailHeader=(hit,subtitle,openLabel='')=>`,
		`<span class="search-result-icon" data-type="${escapeHTML(hit.type||'')}">${typeIcon(hit.type)}</span><div><span class="eyebrow">${escapeHTML(hit.folder_name||'Folder')}</span>`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("advanced typed search UI does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), `${escapeHTML(typeLabel(hit.type))} · ${escapeHTML(hit.folder_name||'Folder')}`) {
		t.Error("Search detail repeats its typed badge in the neighboring eyebrow")
	}
}

func TestSearchHeaderKeepsQueryAndControlsVisibleAtNarrowWidths(t *testing.T) {
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(css)
	for _, required := range []string{
		`body[data-page="search"] .app-topbar{display:grid;grid-template-columns:auto minmax(0,1fr) auto;grid-template-rows:36px 36px`,
		`body[data-page="search"] .global-search-tools{display:contents}`,
		`body[data-page="search"] .global-search-tools .topbar-search{grid-column:2;grid-row:1;width:100%;min-width:0}`,
		`body[data-page="search"] .search-query-actions{grid-column:1;grid-row:2;gap:.2rem}`,
		`body[data-page="search"] #global-search-sort{grid-column:2;grid-row:2;align-self:center;min-width:0;width:min(132px,100%);height:36px`,
		`body[data-page="search"] .search-trash-toggle{grid-column:3;grid-row:2;align-self:center`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("narrow search header CSS does not contain %q", required)
		}
	}
}

func TestSavedSearchWorkspaceUsesDurableCRUDAndWebModals(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(template) + string(css)
	for _, required := range []string{
		`id="search-saved-toggle"`, `id="saved-search-dialog"`, `id="saved-search-create"`,
		`id="saved-search-list"`, `/api/v1/search/saved`, `method:'PATCH'`, `method:'DELETE'`,
		`data-saved-apply`, `data-saved-edit`, `data-saved-delete`, `confirmAction(`,
		`saved_query:savedQueryOverride`, `currentQuery=()`, `savedDialog.showModal()`,
		`.saved-search-dialog`, `.saved-search-row`, `.search-query-actions`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("saved-search UI does not contain %q", required)
		}
	}
}

func TestTrashHeaderPreservesFiltersAtMinimumWidth(t *testing.T) {
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`.trash-tools #trash-type-filter { width:auto; min-width:110px; height:36px; padding:.4rem 1.8rem .4rem .65rem; }`,
		`body[data-page="trash"] .trash-tools{gap:.4rem}`,
		`body[data-page="trash"] #trash-type-filter{width:96px;min-width:96px;padding-left:.5rem;padding-right:1.1rem;font-size:.75rem}`,
		`body[data-page="trash"] .trash-tools .topbar-search{width:auto;flex:1;min-width:0}`,
		`body[data-page="trash"] .trash-tools .topbar-search input{width:100%;min-width:0}`,
		`body[data-page="trash"] .trash-tools .topbar-search input{padding-left:1.7rem;padding-right:.45rem}`,
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("minimum-width Trash header CSS does not contain %q", required)
		}
	}
	for _, required := range []string{
		`id="trash-type-filter" aria-label="Filter trash by type"><option value="all">All</option>`,
		`id="trash-search" type="search" placeholder="Filter trash" aria-label="Filter trash"`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("minimum-width Trash header template does not contain %q", required)
		}
	}
}

func TestTrashWorkspaceUsesStableLocalRenderingAndBatchedItemActions(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"persistTrashState", "performAction", "previousEntries", "previousMobilePane", "item_ids:itemIDs", "visibleEntries", "trash-detail", "renderSortState", "compactSort.value=String({name:1,type:2,deleted:3}[sortKey])", "mobile_pane:mobilePane", "setTrashPane('detail',{focus:true})", "setTrashPane('list',{focus:true})", "listPane.inert=showDetail", "detailPane.inert=trashMedia.matches&&!showDetail", "trashHeader=(headers,...names)", "trashItemName=(item,type)", "if(type==='mail')return subject||'(no subject)'", "if(type==='files')return String(item.original_name||'').trim()||stored||fullName||'(unnamed file)'", "opaqueItemName(stored,item.id)", "aria-label=\"Open deleted ${escapeHTML(kindLabel(entry))}: ${escapeHTML(entry.name)}\"", "name=\"trash-selected\"", "name=\"${escapeHTML(key||'table')}-sort\""} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js trash workspace does not contain %q", required)
		}
	}
	if strings.Contains(source, "await renderTrash()") {
		t.Error("trash actions still refetch and rebuild through renderTrash")
	}
	if !strings.Contains(source, `<header class="trash-detail-head"><span class="trash-kind-icon">${kindIcon(entry)}</span><div><h2>`) {
		t.Error("Trash detail does not retain one compact type badge before its title")
	}
	if strings.Contains(source, `<div><span class="eyebrow">${escapeHTML(kindLabel(entry))}</span><h2>`) {
		t.Error("Trash detail repeats its type badge as a neighboring eyebrow")
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssData)
	for _, required := range []string{
		`body[data-page="trash"] .trash-workspace{position:relative;display:block;overflow:hidden}`,
		`body[data-page="trash"] .trash-workspace.detail-open .trash-list-pane{display:none}`,
		`body[data-page="trash"] .trash-workspace.detail-open .trash-detail-pane{display:block}`,
		`body[data-page="trash"] .trash-mobile-toolbar{position:sticky;top:0;z-index:3;display:flex`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Trash pane CSS does not contain %q", required)
		}
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`class="trash-mobile-toolbar"`, `id="trash-detail-back"`, `<th class="selection-column"><span class="sr-only">Select</span></th>`} {
		if !strings.Contains(string(template), required) {
			t.Errorf("Trash workspace template does not contain %q", required)
		}
	}
}

func TestQuarantineWorkspaceSupportsPagingInspectionAndPrivateSenderLists(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data) + string(template) + string(css)
	for _, required := range []string{
		"page_size:pageSize.value", "data-quarantine-sort", "openEntry", "Release to Inbox",
		"Confirm spam & block sender", "/api/v1/spam-lists/", "sender-lists-dialog",
		"scanTranscriptMarkup", "authentication_results", "Train as spam", "/train",
		"/api/v1/quarantine/digest", "quarantine-digest-settings", "Quarantine digest settings", "getUTCFullYear()<2000",
		"table.classList.contains('quarantine-table')?'quarantine'", "table.dataset.responsivePrimary='2'",
		"row.dataset.quarantineId", "renderSortState", "{date:0,sender:1,subject:2,detection:3,size:4}[sortKey]",
		"quarantine-search-field", "quarantine-empty", "const syncCollectionState=", "genuinelyEmpty=total===0&&!search.value.trim()",
		"searchField.hidden=genuinelyEmpty", "tableWrap.hidden=genuinelyEmpty", "pagination.hidden=genuinelyEmpty", "detailPane.hidden=genuinelyEmpty",
		".quarantine-workspace.genuinely-empty .quarantine-list-pane{min-height:0}",
		".sender-list-values{display:grid;gap:.35rem;max-height:min(240px,30vh)", ".sender-list-values>.empty-state{min-height:52px", ".sender-list-values{max-height:180px}",
		`label for="sender-allow-entry"`, `id="sender-allow-entry" name="entry"`, `aria-label="Add to allow list"`,
		`label for="sender-block-entry"`, `id="sender-block-entry" name="entry"`, `aria-label="Add to block list"`,
		`name="expires_at" type="datetime-local"`, "allow_entries||lists.allow", "block_entries||lists.block",
		"Temporary sender rule added.", "Permanent sender rule added.", "Until ${formatDateTime(expiry)}",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js quarantine workspace does not contain %q", required)
		}
	}
}

func TestMailSecurityWorkspaceShowsRuntimeAndGreylistOperations(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data) + string(css)
	for _, required := range []string{
		"Mail security", "/api/v1/admin/security/scanners", "Run scanner test",
		"/api/v1/admin/greylisting", "Add greylist bypass", "Clean expired",
		"/api/v1/admin/security/dmarc-reports", "DMARC aggregate reports", "retry-dmarc-day",
		"veksel.admin.security.advanced", "delete-greylist-allow", "allowActions,null,{key:entry=>entry.id}",
		".security-card-heading small{color:var(--text-secondary);font-weight:400}",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("mail security workspace does not contain %q", required)
		}
	}
}

func TestAdminBansWorkspaceListsAndManagesBans(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"section==='bans'", "/api/v1/admin/security/bans", "Ban network", "unban-network",
		"/api/v1/admin/security/bans?network=${encodeURIComponent(prefix)}", "No client networks are banned.",
	} {
		if !strings.Contains(string(data), required) {
			t.Errorf("bans workspace does not contain %q", required)
		}
	}
}

func TestAdminQuarantineWorkspaceExposesLifecycleAndPagedOperations(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"loadUIState('admin-quarantine')", "/api/v1/admin/quarantine/status", "/api/v1/admin/quarantine/digests",
		"quarantine-admin-filter", "data-quarantine-admin-sort", "data-quarantine-admin-page",
		"Storage lifecycle", "/api/v1/admin/quarantine/cleanup", "/api/v1/admin/quarantine/rebuild",
		"Inspect quarantined message", "data-quarantine-admin-action", "Digest delivery jobs",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("admin quarantine workspace does not contain %q", required)
		}
	}
}

func TestManualSyncJobHidesZeroNextRunTime(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"job.schedule==='manual'", "date.getFullYear()<2000", "nextRunLabel(job)"} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js next-run formatting does not contain %q", required)
		}
	}
}

func TestSyncWorkspaceExposesEditablePolicyAndReconciliation(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"source_deletion_policy", "Move Veksel items to trash when removed at source",
		"data-sync-details", "run_folder_results", "sync-reconciliation-table",
		"destination_items_before", "destination_items_after", "run_source_deleted_items",
		"remaining", "Checkpoint saved",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("sync workspace does not contain %q", required)
		}
	}
}

func TestSyncWorkspaceExposesPOP3WithHonestLimitations(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"Post Office Protocol version 3 (POP3)", "mail.example.com:995", "STARTTLS / STLS",
		"POP3 imports one mailbox; remote folders, flags, and deletion history are unavailable.",
		"source deletion tracking unavailable", "source_deletion_tracking===false", "deletion.disabled=pop3",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("POP3 sync workflow does not contain %q", required)
		}
	}
}

func TestSyncErrorDisclosureStateSurvivesProfileRerenders(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"loadUIState('sync')", "expanded_failure_runs", "failureRunIdentity",
		"job.run_started_at||job.run_finished_at||'legacy'",
		"data-sync-failure-job", "data-sync-failure-run", "details.open",
		"persistSyncUIState()",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("sync error disclosure persistence does not contain %q", required)
		}
	}
}

func TestSyncWorkspaceRefreshIsEventDrivenSingleFlightAndProjectionDriven(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"jobsLoading=false,lastJobsMarkup=''",
		"if(jobsLoading)return false",
		"markup!==lastJobsMarkup",
		"jobsActive()?2000:60000",
		"if(document.hidden)return",
		"document.addEventListener('veksel:event'",
		"event.detail?.type?.startsWith('sync.')",
		"document.addEventListener('visibilitychange'",
		"const jobCardMarkup=job=>",
		"terminalFailureCard(job)",
		"data-cutover-migration",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("bounded sync polling does not contain %q", required)
		}
	}
	for _, forbidden := range []string{
		"setInterval(renderJobs",
		"MutationObserver(revealTerminalFailures)",
		"MutationObserver(expandProtocolText)",
		"MutationObserver(revealSyncDirections)",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("bounded sync polling retains %q", forbidden)
		}
	}
}

func TestSyncProfileCardsUseCompactResponsiveLayout(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		".migration-job { display:grid; grid-template-columns:minmax(0,1fr) auto",
		".migration-job-main { display:grid; grid-template-columns:minmax(0,1fr)",
		".migration-job .protocol-icon { width:max-content; max-width:100%; min-width:0",
		".migration-job-actions { align-self:start; justify-content:flex-end; flex-wrap:wrap; max-width:330px",
		".sync-run-button>span:first-child { display:none; }",
		".migration-job{grid-template-columns:1fr;gap:.55rem;padding:.7rem}",
		".sync-profiles-card{padding:.75rem}", "#migration-jobs.resource-list{padding:0}",
		".migration-job-actions{justify-content:flex-start;max-width:none;padding-top:.55rem",
		".migration-job-actions .status-pill{display:none}",
		".migration-job-actions .sync-run-button{width:32px;height:32px;padding:0}",
		".migration-job-actions .sync-run-button>span:first-child{display:inline}",
		".migration-job-actions .sync-action-label{display:none}",
		".migration-detail-dialog[open]{display:grid;grid-template-rows:auto minmax(0,1fr) auto;height:calc(100dvh - 1rem);overflow:hidden}",
		".migration-detail-dialog>.migration-detail-content{min-height:0;max-height:none}",
		".migration-detail-dialog .sync-detail-tabs{min-height:43px}",
		`html[data-color-scheme="dark"] .identity-card { background:var(--bg-secondary); }`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("responsive sync profile card CSS does not contain %q", required)
		}
	}
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`class="btn btn-sm btn-primary sync-run-button"`,
		`title="Sync now" aria-label="Sync now"`,
		`<span aria-hidden="true">↻</span><span class="sync-action-label">Sync now</span>`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("responsive sync action markup does not contain %q", required)
		}
	}
}

func TestNarrowMetricSummariesRemainCompact(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		".metric-card .metric-value-phrase { font-size:1.75rem; letter-spacing:-.02em; overflow-wrap:normal; white-space:nowrap; }",
		".metric-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem",
		".metric-card{min-height:96px;padding:.75rem",
		"@media(max-width:720px){.metric-card .metric-value-phrase{font-size:1.5rem}}",
		"@media(max-width:360px){.metric-card .metric-value-phrase{font-size:1.2rem;letter-spacing:-.02em;overflow-wrap:normal;white-space:nowrap}}",
		".health-summary{grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}",
		".quota-metrics{grid-template-columns:repeat(3,minmax(0,1fr))}",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("compact narrow metric CSS does not contain %q", required)
		}
	}
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(javascript), `<span>Trace history</span><strong class="metric-value-phrase">${traceStats.records||0} messages</strong>`) {
		t.Error("operations trace history does not opt its phrase value into compact metric treatment")
	}
}

func TestResponsiveTablesKeepPrimaryActionsAndDiscloseSecondaryFields(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript := string(cssData), string(jsData)
	for _, required := range []string{
		".responsive-table-controls{display:flex",
		".responsive-table-controls label{display:flex;align-items:center;gap:.35rem;color:var(--text-secondary)",
		".responsive-table-controls>span{margin-left:auto;color:var(--text-secondary)",
		"@media(max-width:360px){#admin-control-plane .responsive-table-controls > span{display:none}}",
		"td.responsive-primary{display:block",
		"td.responsive-actions{display:flex",
		"td.responsive-actions{grid-row:1",
		"tr.responsive-expanded td.responsive-secondary:not(.responsive-empty){display:grid",
		"tr:not(.responsive-expanded) td.responsive-secondary.responsive-sort-value:not(.responsive-empty){display:grid",
		".responsive-row-toggle{display:inline-flex;align-items:center;gap:.2rem;margin:.35rem 0 0 .45rem",
		"min-height:24px;padding:0;color:var(--brand-hover)",
		"padding:0;color:var(--brand-hover);border:0;background:transparent;font-size:.68rem",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("responsive table CSS does not contain %q", required)
		}
	}
	for _, required := range []string{
		"enhanceResponsiveTable=table=>",
		"aria-label=\"Sort rows on narrow screens\"",
		"toggle.setAttribute('aria-expanded'",
		"const next=!expanded.has(rowID)",
		"saveUIState(`responsive-table:${key}`",
		"table.contacts-table,table.files-table,table.trash-table,table.quarantine-table,table.access-grant-table",
		"table.classList.contains('trash-table')?'trash'",
		"table.matches('.contacts-table,.trash-table')",
		"row.dataset.trashKey",
		"['accounts','domains','recipients','certificates','notifications','quarantine','security','operations','outbound-tls','policies','settings'].includes(admin?.dataset.section)",
		"admin?.dataset.section==='protocols'",
		"logging?`admin-protocol-${admin.dataset.protocol}-logging`:'admin-http-listeners'",
		"adminSection==='settings'", "table.dataset.responsiveKey='admin-settings-logging'",
		"messages?'admin-quarantine-messages':'admin-quarantine-digests'",
		"table.dataset.responsivePrimary=messages?'3':'2'",
		"greylisting?'admin-security-greylist':'admin-security-logging'",
		"table.dataset.responsivePrimary=greylisting?'1':'0'",
		"\"System queue\":['queue',4]", "\"Message trace\":['trace',4]", "\"Audit activity\":['audit',2]",
		"rules?'admin-policies-rules':'admin-policies-logging'", "table.dataset.responsivePrimary=rules?'1':'0'",
		"table.dataset.responsiveKey=`admin-${adminSection}-${[...document.querySelectorAll('#admin-page-content table')].indexOf(table)}`",
		"if(controls)controls.hidden=!dataRows.length",
		"hasMeaningfulCellContent=cell=>",
		"cell.classList.toggle('responsive-empty'",
		"sortIndex=Number(controls?.querySelector('select')?.value)",
		"cell.classList.toggle('responsive-sort-value',secondary&&index===sortIndex)",
		"if(!hasSecondary){toggle?.remove()",
		"new MutationObserver(refreshRows)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("responsive table behavior does not contain %q", required)
		}
	}
	for _, required := range []string{
		"responsive-logging-table",
		".responsive-table.responsive-logging-table:not(.has-responsive-actions) tbody td.responsive-primary{display:flex;grid-column:1",
		"tbody td:nth-child(2){display:flex", ".module-log-level{width:5rem",
		"td.responsive-primary>strong{min-width:0", "td.responsive-primary>small{display:none",
		".responsive-row-toggle{flex:0 0 auto",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("responsive protocol logging CSS does not contain %q", required)
		}
	}
	if !strings.Contains(css, `.responsive-logging-table tbody td:nth-child(2){display:flex`) {
		t.Error("responsive Settings logging CSS does not keep the level selector in the compact row")
	}
}

func TestBrowserSessionSettingsExposeRevocationWithoutNativeDialogs(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"section==='sessions'", `id="revoke-other-browser-sessions"`,
		`data-responsive-key="user-browser-sessions"`, "session.current",
		"/api/v1/user/browser-sessions/", "'/api/v1/user/browser-sessions'",
		"title:'Sign out browser session'", "title:'Sign out other browsers'",
		"event.type==='browser.session.revoked'&&event.resource===body.dataset.sessionId",
		"location.replace('/app/login')", "if(browserSessionEnded)return",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("browser-session workflow does not contain %q", required)
		}
	}
}

func TestQueueBulkActionsAreContextualToSelection(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript := string(cssData), string(jsData)
	for _, required := range []string{
		`class="resource-toolbar queue-bulk-toolbar" hidden`,
		"bulkToolbar.hidden=!selectedQueue.size",
		"selectionCount.textContent=`${selectedQueue.size} selected`",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("contextual queue bulk controls do not contain %q", required)
		}
	}
	if !strings.Contains(css, ".queue-bulk-toolbar[hidden]{display:none}") {
		t.Error("hidden queue bulk toolbar is not removed from layout")
	}
	for _, required := range []string{
		".queue-bulk-toolbar{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))",
		".queue-bulk-toolbar #queue-selection-count,.queue-bulk-toolbar input{grid-column:1/-1}",
		".queue-bulk-toolbar input{width:100%;min-width:0}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact selected queue actions do not contain %q", required)
		}
	}
}

func TestCompactContactRowsKeepDisclosureInline(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(javascriptData), `<span class="contact-name-text">${escapeHTML(contact.fn)}</span>`) {
		t.Error("contact names do not have a bounded text wrapper")
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssData)
	for _, required := range []string{
		".contacts-table.responsive-table tbody td.responsive-selection{align-items:center;padding:.4rem .2rem}",
		".contacts-table.responsive-table tbody td.responsive-primary{display:flex;align-items:center;gap:.45rem;padding:.4rem .5rem}",
		".contacts-table .contact-name-text{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
		".contacts-table .responsive-row-toggle{flex:0 0 auto;margin:0 0 0 auto;white-space:nowrap}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact contact row CSS does not contain %q", required)
		}
	}
}

func TestHTTPProtocolsUseSharedListenerAdministration(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	for _, required := range []string{
		"api('/api/v1/admin/http-listeners')",
		"/api/v1/admin/http-bindings/",
		"Add HTTP(S) listener",
		"Save listener bindings",
		"settingsCards(data.settings,[name])",
		"data-http-listener-certificate",
		"data-http-listener-log-level",
		"data-http-listener-hsts-toggle",
		"data-http-listener-hsts",
		"hsts_max_age_days",
		"hsts_include_subdomains",
		"hsts_preload",
		"Enforce HTTPS in browsers (HSTS)",
		"Preload is difficult to reverse",
		"const hstsSummary=",
		"HSTS removal policy",
		"const bindListenerEditorState=",
		"certificateField.hidden=!https",
		"certificate.required=https&&enabled.checked",
		"logLevelField.hidden=!accessLog.checked",
		"transport.onchange=sync",
		"enabled.onchange=sync",
		"accessLog.onchange=sync",
		"data-http-listener-hsts-proxy-note]').hidden=https",
		"hstsFields.hidden=!hsts",
		"previouslyConfigured=Object.hasOwn(listener||{},'hsts_max_age_days')",
		"previouslyConfigured?0:undefined",
		"if(Number(hstsDays.value)<365)hstsDays.value='365'",
		"openListenerEditor",
		`class="http-listener-id"`,
		`class="http-listener-summary"`,
		"${escapeHTML(item.transport.toUpperCase())} · ${escapeHTML(item.address)} · ${item.enabled?'Enabled':'Disabled'}",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("shared HTTP listener UI does not contain %q", required)
		}
	}
	if strings.Contains(javascript, "settingsCards(data.settings,[name,'https'])") {
		t.Error("EWS/EAS still render duplicated HTTPS settings")
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssData)
	for _, required := range []string{
		"listener-binding-heading",
		"listener-binding-option",
		"listener-binding-copy",
		"listener-binding-empty",
		"No HTTP(S) listeners are available",
		"Manage HTTP(S) listeners",
	} {
		if !strings.Contains(javascript, required) && !strings.Contains(css, required) {
			t.Errorf("shared HTTP listener binding UI does not contain %q", required)
		}
	}
	for _, required := range []string{
		".listener-binding-heading { display:grid; gap:.25rem; }",
		".listener-binding-heading small { display:block; color:var(--text-secondary); font-weight:400; line-height:1.45; }",
		".listener-binding-option { display:grid; grid-template-columns:18px minmax(0,1fr)",
		".listener-binding-copy { display:grid; gap:.15rem; min-width:0; }",
		".listener-binding-copy strong,.listener-binding-copy small { display:block; min-width:0; overflow-wrap:anywhere; }",
		".listener-binding-actions { padding:.75rem 1rem; border-top:1px solid var(--border-light); }",
		".data-table .http-listener-summary { display:none; }",
		`.responsive-table[data-responsive-key="admin-http-listeners"] .http-listener-id{display:none}`,
		`.responsive-table[data-responsive-key="admin-http-listeners"] .http-listener-summary{display:block`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("shared HTTP listener binding CSS does not contain %q", required)
		}
	}
}

func TestSocketProtocolPagesExposeLiveAggregateConnections(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(javascript) + string(css)
	for _, required := range []string{
		"/api/v1/admin/protocol-connections",
		"['smtp','imap','pop3'].includes(protocol)",
		"Live connections",
		"Aggregate across every enabled listener",
		"document.hidden",
		"setInterval(update,5000)",
		"clearInterval(protocolConnectionTimer)",
		"Live count unavailable",
		".protocol-connections-card",
		".protocol-active-count",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("protocol connection UI does not contain %q", required)
		}
	}
}

func TestAdminTableFilteringReportsTruthfulResults(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	for _, required := range []string{
		"recordLabel=count=>`${count} record${count===1?'':'s'}`",
		"data-filter-empty hidden",
		"No records match this filter.",
		"aria-live=\"polite\"",
		"name=\"${id}-filter\"",
		"query?`${visible} of ${recordLabel(rows.length)}`:recordLabel(rows.length)",
		"filterEmpty.hidden=visible>0",
		"tbody tr[data-search]",
		"if(filterEmpty)body.append(filterEmpty)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("truthful admin table filtering does not contain %q", required)
		}
	}
	if strings.Contains(javascript, "${rows.length} records</span>") {
		t.Error("generic admin tables still render an unconditional plural record count")
	}
}

func TestCertificateInventoryUsesCanonicalListenerAssignments(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	for _, required := range []string{
		"api('/api/v1/admin/http-listeners')",
		"const labels=assigned.get(name)||new Set()",
		"for(const key of ['smtp_certificate','imap_certificate','pop3_certificate'])",
		"listener.transport==='https'&&listener.certificate?.startsWith('stored:')",
		"addAssignment(listener.certificate.slice(7),`HTTPS · ${listener.name}`)",
		"[...(assigned.get(c.name)||[])].join(', ')||'Not assigned'",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("certificate assignment inventory does not contain %q", required)
		}
	}
	if strings.Contains(javascript, "['smtp_certificate','imap_certificate','pop3_certificate','https_certificate']") {
		t.Error("certificate inventory still treats the legacy singleton HTTPS setting as canonical")
	}
}

func TestHealthOwnerRoutingCoversRuntimeComponents(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"caldav:{href:'/app/admin/protocols/dav',label:'Configure DAV services'}",
		"http:{href:'/app/admin/protocols/http',label:'Manage HTTP(S) listeners'}",
		"'system-queue':{href:'/app/admin/operations/queue',label:'Inspect queue'}",
		"'system-store':{href:'/app/admin/settings',label:'Open settings'}",
		"component.kind==='storage'?{href:'/app/admin/settings?setting=account_storage_roots',label:'Manage storage'}",
		"component.kind==='certificate'?{href:'/app/admin/certificates',label:'Manage certificates'}",
		"component.kind==='notification'?healthOwners['webhook-delivery']",
		"healthOwners[component.id]||{href:'/app/admin/health',label:'View health'}",
		"healthLink({id:alert.component_id,kind:alert.component_kind})",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("health owner routing does not contain %q", required)
		}
	}
}

func TestCompactHealthComponentsUsePersistentDisclosure(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	javascript, css := string(javascriptData), string(cssData)
	for _, required := range []string{
		"loadUIState('admin-health')",
		"expanded_components:[...expandedHealthComponents]",
		"card.dataset.healthComponent=componentID",
		"button.setAttribute('aria-controls',details.id)",
		"button.setAttribute('aria-expanded',String(open))",
		"expandedHealthComponents.add(componentID)",
		"expandedHealthComponents.delete(componentID)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact Health disclosure does not contain %q", required)
		}
	}
	for _, required := range []string{
		".health-component-toggle{display:none}",
		".health-component-toggle{display:flex;",
		".health-component:not(.expanded) .health-component-details{display:none}",
		".health-component-toggle:focus-visible",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Health disclosure CSS does not contain %q", required)
		}
	}
}

func TestCertificateAdministrationUsesCompactEmptyCollection(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	javascript, css := string(javascriptData), string(cssData)
	for _, required := range []string{
		"if(!normalized.length&&options.compactEmpty)",
		"compact-collection-empty",
		`{compactEmpty:true,emptyMessage:"No uploaded certificates. Upload one or configure Let's Encrypt below."}`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact certificate collection does not contain %q", required)
		}
	}
	if !strings.Contains(css, ".compact-collection-empty { min-height:96px; padding:1rem; }") {
		t.Error("compact administration collection empty state is not height-bounded")
	}
}

func TestAccountAdministrationSeparatesTaskFocusedViews(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	javascript, css := string(javascriptData), string(cssData)
	for _, required := range []string{
		`role="tablist" aria-label="Account administration views"`,
		`role="tabpanel" aria-labelledby="account-admin-tab-directory"`,
		`data-account-admin-panel="quotas" hidden`,
		`data-account-admin-panel="storage" hidden`,
		`data-account-admin-panel="logging" hidden`,
		"loadUIState('admin-accounts-view')",
		"saveUIState('admin-accounts-view'",
		"document.querySelector('#new-account').hidden=next!=='directory'",
		"accountScroll?.scrollTo({top:0,behavior:'auto'})",
		"if(next==='quotas'&&!quotaLoaded)",
		"if(loggingLoaded||loggingLoading)return",
		"loggingLoaded=await appendPageLogging()",
		"if(next==='logging')loadAccountLogging()",
		"if(section!=='accounts')await appendPageLogging()",
		"event.key==='ArrowRight'",
		"event.key==='Home'",
		`content.querySelector('[data-account-admin-panel="logging"]')`,
		`Account ID<input name="id" required autocomplete="off">`,
		`Display name<input name="display_name" autocomplete="off">`,
		`Initial password<input name="password" type="password" minlength="8" required autocomplete="new-password">`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("task-focused account administration does not contain %q", required)
		}
	}
	for _, required := range []string{
		".account-admin-tabs { position:sticky;",
		".account-admin-tabs button:focus-visible",
		".account-admin-panel[hidden] { display:none; }",
		".account-admin-tabs button{padding-left:.55rem;padding-right:.55rem}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("task-focused account administration CSS does not contain %q", required)
		}
	}
}

func TestAccountAdministrationTabsFitMinimumWidth(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssData)
	for _, required := range []string{
		`@media(max-width:360px){.account-admin-tabs button{padding-left:.25rem;padding-right:.25rem;font-size:.7rem}`,
		`.account-admin-tabs small{min-width:1rem;padding-left:.2rem;padding-right:.2rem}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("minimum-width Account tabs CSS does not contain %q", required)
		}
	}
}

func TestNarrowWorkspaceNavigationUsesAccessibleMenu(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript := string(cssData), string(javascriptData)
	for _, required := range []string{
		".workspace-menu-toggle { display:none; }",
		".workspace-menu-toggle{display:grid",
		".workspace-menu-body[hidden]{display:none}",
		"max-height:calc(100vh - 5.5rem)",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("narrow workspace navigation CSS does not contain %q", required)
		}
	}
	for _, required := range []string{
		"const bindWorkspaceMenu=scope=>{", "workspacePanel=scope.querySelector('.workspace-panel')",
		"bindWorkspaceMenu(workspaceModal)", "if(adminShell)bindWorkspaceMenu(adminShell)",
		"workspacePanel.inert=menuState.open",
		"menuBody.hidden=menuMedia.matches&&!menuState.open",
		"activeTab?.setAttribute('aria-current','page')",
		"currentTab()?.scrollIntoView({block:'nearest'})",
		"if(event.target.closest('a[href]'))setMenuOpen(false)",
		"if(menuState.open&&!workspaceMenu.contains(event.target))",
		"menuMedia.addEventListener('change',()=>setMenuOpen(false))",
		"if(event.key==='Escape'){event.preventDefault();event.stopPropagation();setMenuOpen(false,{restoreFocus:true});return}if(event.key!=='Tab')return",
		"current===focusables.length-1",
		"event.preventDefault();target.focus()",
		"setMenuOpen(false,{restoreFocus:true})",
		"event.stopImmediatePropagation()",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("narrow workspace navigation behavior does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"menuStateKey=menuBody?.dataset.uiState", "loadUIState(menuStateKey)", "saveUIState(menuStateKey"} {
		if strings.Contains(javascript, forbidden) {
			t.Errorf("transient workspace menu state still contains %q", forbidden)
		}
	}
}

func TestAutomationRulesTableUsesCompactResponsiveRows(t *testing.T) {
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, javascript := string(cssData), string(jsData)
	for _, required := range []string{
		`.automation-rules-table { min-width:880px; table-layout:fixed; }`,
		`.automation-rules-table td.empty-state { display:table-cell; min-height:0; padding:1rem; }`,
		`.automation-rules-table.responsive-table tbody tr{grid-template-columns:minmax(0,1fr) minmax(108px,auto)}`,
		`td:nth-child(1):not(.empty-state),.automation-rules-table.responsive-table tbody td:nth-child(2):not(.empty-state){display:flex!important`,
		`.automation-rules-table.responsive-table td.empty-state{display:block;min-height:0}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("responsive automation rules CSS does not contain %q", required)
		}
	}
	for _, required := range []string{
		`table.automation-rules-table`,
		`table.dataset.responsiveKey='automation-rules'`,
		`table.dataset.responsivePrimary='2'`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("responsive automation rules behavior does not contain %q", required)
		}
	}
}

func TestRuleEditorFitsCompactViewport(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		".automation-rule-dialog .dialog-header,.automation-rule-dialog .dialog-actions { padding:1rem 1.25rem; }",
		".automation-builder-controls { display:flex; align-items:center; justify-content:flex-end; gap:.25rem; }",
		".automation-rule-dialog{width:calc(100vw - 1rem);max-width:calc(100vw - 1rem);max-height:calc(100dvh - 1rem);overflow:hidden}",
		".automation-rule-dialog form{min-width:0;max-height:calc(100dvh - 1rem);grid-template-rows:auto minmax(0,1fr) auto}",
		".automation-rule-dialog .automation-folder-choices{grid-template-columns:repeat(2,minmax(0,1fr))",
		".automation-rule-dialog .automation-builder-row{grid-template-columns:minmax(0,1fr);align-items:stretch}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact rule editor CSS does not contain %q", required)
		}
	}
}

func TestRuleEditorFolderScopeIsSearchableAndSelectionAware(t *testing.T) {
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(template)
	for _, required := range []string{
		`id="automation-folder-filter"`,
		`aria-label="Find a rule scope folder"`,
		`id="automation-folder-filter-count"`,
		`id="automation-folder-clear-selection" disabled`,
	} {
		if !strings.Contains(markup, required) {
			t.Errorf("rule scope finder markup does not contain %q", required)
		}
	}

	jsData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(jsData)
	for _, required := range []string{
		`const syncFolderScopeFilter=()=>`,
		`choice.dataset.folderSearch.includes(query)`,
		`choice.hidden=!match`,
		`folders · ${selected} selected`,
		`clearFolderScope.disabled=!selected`,
		`folderScopeFilter.value=''`,
		`event.stopPropagation()`,
		`[name=source_folder]:checked`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("rule scope finder behavior does not contain %q", required)
		}
	}

	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssData)
	for _, required := range []string{
		`.automation-folder-filter { display:flex; align-items:center; gap:.5rem; margin:0 0 .4rem; }`,
		`.automation-folder-no-match { grid-column:1/-1; }`,
		`.automation-rule-dialog .automation-folder-filter{align-items:stretch;flex-wrap:wrap}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("rule scope finder CSS does not contain %q", required)
		}
	}
}

func TestCompactChromeControlsKeepAccessibleTargetsAndState(t *testing.T) {
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(template)
	for _, required := range []string{
		`id="connection-state" aria-label="Connection status: Live" aria-live="polite" aria-atomic="true" tabindex="-1"`,
		`class="connection-dot" aria-hidden="true"`,
	} {
		if !strings.Contains(markup, required) {
			t.Errorf("connection indicator markup does not contain %q", required)
		}
	}

	script, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(script)
	for _, required := range []string{
		"accessibleLabel=refreshRequired?`${label}. Reload Veksel when you are ready.`:`Connection status: ${label}`",
		"state.tabIndex=refreshRequired?0:-1",
		"notice.setAttribute('aria-label',`${label}. Reload Veksel when you are ready.`)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("connection indicator behavior does not contain %q", required)
		}
	}

	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssData)
	for _, required := range []string{
		`.connection-state { display:flex; align-items:center; gap:.55rem; min-height:24px;`,
		`.mobile-menu { display:none; min-width:24px; min-height:24px; padding:0; }`,
		`.connection-state{min-width:24px;padding:.4rem}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact chrome CSS does not contain %q", required)
		}
	}
}

func TestGlobalSearchUsesViewportBoundedPanes(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`body[data-page="search"] .app-content,body[data-page="trash"] .app-content`,
		`.global-search-workspace { display:grid; grid-row:3;`,
		`.search-result-list{grid-row:3;min-height:0;overflow:auto}`,
		`.search-index-health { display:grid; grid-row:2;`,
		`body[data-page="search"] .app-content{height:calc(100dvh - var(--search-topbar-height))}`,
		`body[data-page="search"] .global-search-workspace{grid-template-rows:auto minmax(0,1fr);overflow:hidden}`,
		`body[data-page="search"] .search-facet-pane,body[data-page="search"] .search-results-pane{min-height:0}`,
		`body[data-page="search"] .search-facet-toggle{display:inline-flex}`,
		`body[data-page="search"] .search-facet-pane.facets-open{max-height:min(46dvh,360px)}`,
		`body[data-page="search"] .search-facets[hidden]{display:none}`,
		`body[data-page="search"] .search-detail-pane{display:none}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("viewport-bounded search CSS does not contain %q", required)
		}
	}
}

func TestCompactSearchFacetsArePersistedAndAccessible(t *testing.T) {
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(template)
	for _, required := range []string{
		`id="search-facet-toggle" aria-expanded="false" aria-controls="search-facets"`,
		`id="search-facet-active-count" class="search-facet-active-count" hidden`,
	} {
		if !strings.Contains(markup, required) {
			t.Errorf("compact search facet markup does not contain %q", required)
		}
	}

	script, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(script)
	for _, required := range []string{
		`facets_open:facetsOpen`,
		`facetsTarget.hidden=compact&&!facetsOpen`,
		`if(narrowSearch.matches)setFacetsOpen(false,{focus:true})`,
		`event.key==='Escape'&&narrowSearch.matches&&facetsOpen`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact search facet behavior does not contain %q", required)
		}
	}
}

func TestAdministrationSettingCardsUseConsistentInsetsAndProportions(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`#admin-control-plane[data-section="protocols"] #admin-page-content>.card { max-width:860px; padding:1.25rem; }`,
		`#admin-control-plane[data-section="protocols"] #admin-page-content>.card>.card-body { padding:1rem 0; }`,
		`.operations-stack>.card>.setting-list,.admin-grid>.card>.setting-list { padding:0 1.25rem 1.25rem; }`,
		`#admin-control-plane[data-section="routing"] .admin-grid { grid-template-columns:minmax(420px,1.2fr) minmax(280px,.8fr); }`,
		`@media(max-width:1050px){#admin-control-plane[data-section="routing"] .admin-grid{grid-template-columns:1fr}}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("administration card CSS does not contain %q", required)
		}
	}
}

func TestAdministrationHeaderActionsStayCompactAtNarrowWidths(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`#admin-control-plane .workspace-panel-header{display:grid;grid-template-columns:minmax(0,1fr);gap:.75rem}`,
		`#admin-control-plane .workspace-header-actions{width:100%;min-width:0;justify-content:flex-end;gap:.4rem}`,
		`@media(max-width:360px){#admin-control-plane .workspace-panel-header{gap:.4rem;padding:.65rem .75rem}`,
		`#admin-control-plane .workspace-panel-header h1{font-size:1.45rem;line-height:1.15}`,
		`#admin-control-plane .workspace-panel-header .page-subtitle{font-size:.82rem;line-height:1.4}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("narrow Administration header CSS does not contain %q", required)
		}
	}
	for _, required := range []string{
		`#admin-control-plane[data-section="security"] #admin-primary-action{display:flex;min-width:0;flex:1;gap:.4rem}`,
		`#admin-control-plane[data-section="security"] #admin-primary-action .btn{min-width:0;flex:1;padding:.45rem .35rem;white-space:nowrap;font-size:.75rem}`,
		`#admin-control-plane[data-section="security"] :is(.admin-alert-button,.workspace-close){flex:0 0 36px}`,
		`.scanner-test-icon{display:none}`,
		`@media(max-width:360px){#admin-control-plane[data-section="security"] #admin-primary-action #scanner-test{display:grid;place-items:center;width:36px;min-width:36px;flex:0 0 36px;padding:0}`,
		`#admin-control-plane[data-section="security"] .scanner-test-icon{display:inline;font-size:1rem}`,
		`#admin-control-plane[data-section="security"] .scanner-test-label{display:none}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("narrow multi-action Administration header CSS does not contain %q", required)
		}
	}
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`id="scanner-test" title="Run scanner test" aria-label="Run scanner test"`,
		`<span class="scanner-test-icon" aria-hidden="true">▷</span><span class="scanner-test-label">Run scanner test</span>`,
		`document.querySelector('#scanner-test').onclick=async event=>{const button=event.currentTarget;button.disabled=true;`,
		`finally{button.disabled=false}};`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("responsive scanner test action does not contain %q", required)
		}
	}
}

func TestAsyncDialogsPreserveExplicitReturnFocus(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		`const showModalFrom=(dialog,invoker)=>{if(!dialog||dialog.open)return;dialog.showModal();if(invoker?.isConnected)dialog._vekselReturnFocus=invoker};`,
		`showModalFrom(detailDialog,button);toast('Scanner test completed.')`,
		`requestAnimationFrame(()=>target.focus({preventScroll:true}))`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("async dialog focus restoration does not contain %q", required)
		}
	}
}

func TestProtocolRuntimeStatusStaysCompleteAtMinimumWidth(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`@media(max-width:360px){.protocol-heading{align-items:flex-start;flex-direction:column;gap:.6rem}`,
		`.protocol-heading>.status-pill{align-self:flex-start;max-width:100%;white-space:normal}`,
		`@media(max-width:360px){.protocol-grid>.card,.protocol-detail>.card{padding:.75rem}`,
		`.protocol-detail .protocol-runtime-error{margin:0 0 .75rem;padding:.65rem}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("minimum-width protocol status CSS does not contain %q", required)
		}
	}
}

func TestOperationalAlertLinksKeepAccessibleTargets(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`.alert-drawer-toolbar>a{display:inline-flex;align-items:center;min-height:24px;`,
		`.alert-drawer-item footer>a{display:inline-flex;align-items:center;min-height:24px;`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("operational alert link CSS does not contain %q", required)
		}
	}
}

func TestOperationalAlertLabelsUseReadableSemanticColor(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`.alert-drawer-toolbar label{display:grid;gap:.2rem;color:var(--text-secondary);`,
		`.alert-drawer-summary span{display:grid;gap:.1rem;padding:.55rem;border-right:1px solid var(--border-color);color:var(--text-secondary);`,
		`@media(max-width:360px){.alert-drawer-toolbar{display:grid;grid-template-columns:minmax(0,1fr);align-items:start;gap:.5rem}`,
		`.alert-drawer-toolbar label,.alert-drawer-toolbar select{width:100%;min-width:0}`,
		`.alert-drawer-summary{grid-template-columns:repeat(3,minmax(0,1fr))}`,
		`.alert-drawer-summary span{min-width:0;padding:.55rem .35rem;font-size:.6rem;line-height:1.2;overflow-wrap:anywhere}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("operational alert label CSS does not contain %q", required)
		}
	}
}

func TestAdministrationEditorFocusesFirstUsableField(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"const openEditor=(heading,eyebrow,fields,onSubmit",
		"dialog.showModal();[...editorFields.querySelectorAll",
		`':is(input,select,textarea,button):not([type="hidden"]):not(:disabled)'`,
		"].find(field=>field.getClientRects().length)?.focus()",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("Administration editor focus behavior does not contain %q", required)
		}
	}
}

func TestResourceEditorsDeclareScopedAutofillIntent(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"const declareResourceEditorAutofill=root=>",
		`input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]),textarea`,
		"if(!field.hasAttribute('autocomplete'))field.autocomplete=field.type==='password'?'new-password':'off'",
		"declareResourceEditorAutofill(form);declareResourceEditorAutofill(addressbookForm)",
		"editorFields.innerHTML=fields;declareResourceEditorAutofill(editorFields)",
		`autocomplete="current-password"`,
		`autocomplete="new-password"`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("resource editor autofill behavior does not contain %q", required)
		}
	}
}

func TestSyncReauthenticationDeclaresSourceUsernameContext(t *testing.T) {
	templateData, err := os.ReadFile("../web/app/templates/app.gohtml")
	if err != nil {
		t.Fatal(err)
	}
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, javascript := string(templateData), string(javascriptData)
	for _, required := range []string{
		`<input name="username" autocomplete="username" hidden>`,
		`<input name="password" type="password" autocomplete="current-password">`,
		"runForm.elements.username.value=job.connection?.username||''",
	} {
		if !strings.Contains(template+javascript, required) {
			t.Errorf("sync reauthentication context does not contain %q", required)
		}
	}
	if strings.Contains(javascript, "username:runForm.elements.username.value") {
		t.Error("sync reauthentication username was added to the update payload")
	}
}

func TestAdministrationAlertLinksDismissPersistedDrawer(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"alertContent.addEventListener('click'",
		"const link=event.target.closest('a[href]')",
		"event.metaKey||event.ctrlKey||event.shiftKey||event.altKey",
		"link.target==='_blank'||link.hasAttribute('download')",
		"alertDialog.close()",
		"alertDialog.addEventListener('close',persistAlertUI)",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("alert remediation navigation does not contain %q", required)
		}
	}
}

func TestWorkspaceKeepsLongPageScrollingInsidePanel(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		".workspace-modal { width:min(1180px,calc(100vw - 7rem)); height:min(860px,calc(100vh - 4rem)); max-width:none; max-height:none; padding:0; overflow:clip;",
		".workspace-panel-body { min-height:0; padding:1.5rem; overflow:auto; overscroll-behavior:contain; }",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("bounded workspace scrolling CSS does not contain %q", required)
		}
	}
}

func TestGeneratedSettingControlsHaveFormAndAccessibleNames(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		"name=escapeHTML(s.key),label=escapeHTML(s.label)",
		"common=`name=\"${name}\" aria-label=\"${label}\" ${metadata}`",
		"<input type=\"checkbox\" name=\"${name}\" ${metadata} value=\"${escapeHTML(option)}\"",
		"numeric=s.type==='number'||s.type.startsWith('int')",
		"Number.isFinite(s.min)?` min=\"${s.min}\"`",
		"Number.isFinite(s.max)?` max=\"${s.max}\"`",
		"input.type==='number'?Number(input.value):input.value",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("named generated setting controls do not contain %q", required)
		}
	}
}

func TestAdministrationTablesRenderContextualEmptyRows(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		`columnCount=columns.length+(selection?1:0)+(actions?1:0)`,
		`colspan="${columnCount}" class="empty-state"`,
		`escapeHTML(options.emptyMessage||'No records are available in this view.')`,
		`if(normalized.length){input?.addEventListener`,
		`emptyMessage:'No domains are configured yet.'`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("Administration empty-table behavior does not contain %q", required)
		}
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cssData), `.data-table td.empty-state { display:table-cell; min-height:0; padding:1rem; }`) {
		t.Error("Administration empty-table row does not preserve table-cell colspan layout")
	}
}

func TestDelegationToolbarAndEmptyGrantStateStayCompact(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`.access-grant-table td.empty-state { display:table-cell; min-height:0; padding:1rem; }`,
		`[data-settings-section="delegation"] .access-toolbar{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.5rem;padding:.6rem 1rem}`,
		`[data-settings-section="delegation"] .access-toolbar .search-field{grid-column:1/-1;min-width:0}`,
		`[data-settings-section="delegation"] .access-toolbar .dialog-spacer{display:none}`,
		`[data-settings-section="delegation"] .access-toolbar>.btn{width:100%;min-width:0`,
		`.access-grant-table.responsive-table td.empty-state{display:block;min-height:0}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Delegation CSS does not contain %q", required)
		}
	}
}

func TestWorkspaceNavigationAvoidsSyntheticEntryFocus(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(data)
	for _, required := range []string{
		`revealActiveWorkspaceTab=(menu,active)=>`,
		`matchMedia('(max-width: 720px)').matches`,
		`menu.scrollWidth<=menu.clientWidth`,
		`activeRect.left>=menuRect.left&&activeRect.right<=menuRect.right`,
		`menu.scrollLeft+=activeRect.left-menuRect.left-(menu.clientWidth-activeRect.width)/2`,
		`if(menuState.open)(currentTab()||menuBody.querySelector('a'))?.focus()`,
		`menuToggle?.focus({preventScroll:true})`,
		`requestAnimationFrame(()=>revealActiveWorkspaceTab(workspaceMenu,activeTab))`,
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("active workspace-tab reveal does not contain %q", required)
		}
	}
	for _, forbidden := range []string{
		`setMenuOpen(menuState.open);if(menuMedia.matches&&!menuState.open)`,
		`else if(!menuMedia.matches)activeTab?.focus`,
		`}else activeTab?.focus`,
	} {
		if strings.Contains(javascript, forbidden) {
			t.Errorf("workspace navigation still forces initial focus through %q", forbidden)
		}
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`<h1 tabindex="-1" autofocus>`, `<h1 id="admin-title" tabindex="-1" autofocus>`} {
		if !strings.Contains(string(template), required) {
			t.Errorf("workspace heading does not own initial dialog focus through %q", required)
		}
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), `.workspace-panel-header h1:focus { outline:none; }`) {
		t.Error("non-interactive workspace focus target has a visible control-style outline")
	}
}

func TestProfileFormsUseCompactNaturalHeightCards(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`#user-profile-settings .user-settings-grid { align-items:start; }`,
		`#user-profile-settings .settings-form-card { gap:.75rem; padding:1rem; }`,
		`#user-profile-settings .sticky-actions { padding-top:.5rem; }`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Profile form CSS does not contain %q", required)
		}
	}
}

func TestVacationFormKeepsEditorAndActionInCompactFlow(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`#vacation-settings-form { gap:.75rem; padding:1rem; }`,
		`#vacation-settings-form .setting-toggle-row { padding-bottom:.75rem; }`,
		`#vacation-settings-form textarea { height:120px; min-height:100px; resize:vertical; }`,
		`#vacation-settings-form .sticky-actions { padding-top:.5rem; }`,
		`html[data-color-scheme="dark"] .material-switch input:checked+span { border-color:var(--brand); background:var(--brand); }`,
		`html[data-color-scheme="dark"] .material-switch input:checked+span:after { background:#07363b; }`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Auto-reply CSS does not contain %q", required)
		}
	}
}

func TestMaterialSwitchNativeInputDoesNotExpandItsWorkspace(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `.material-switch input{position:absolute;width:1px;height:1px;opacity:0}`) {
		t.Error("material switch does not constrain its accessible native input")
	}
}

func TestEmailIdentityEmptyStateStaysCompactWithoutChangingCards(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	if !strings.Contains(css, `.identity-list>.empty-state { display:block; min-height:0; padding:1rem; border:1px solid var(--border-light); background:var(--bg-secondary); text-align:left; }`) {
		t.Error("Email identities does not contain its compact direct-child empty state")
	}
	if !strings.Contains(css, `.identity-card { display:flex; align-items:center; justify-content:space-between;`) {
		t.Error("Email identity card behavior is no longer present")
	}
}

func TestNotificationCardsUseNaturalDesktopHeights(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `.notification-settings-grid { align-items:start; }`) {
		t.Error("Notifications grid does not align cards to their natural heights")
	}
}

func TestHomeDashboardIsPersonalAndResponsive(t *testing.T) {
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`.home-grid{`, `.home-card{`, `.home-row.unread`, `@media(max-width:900px){.home-grid{grid-template-columns:1fr}}`} {
		if !strings.Contains(string(css), required) {
			t.Errorf("home dashboard CSS does not contain %q", required)
		}
	}
	for _, forbidden := range []string{".hero ", ".feature-card", ".feature-grid"} {
		if strings.Contains(string(css), forbidden) {
			t.Errorf("marketing home CSS %q remains", forbidden)
		}
	}
	js, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`if(page==='home')`, `/api/v1/workspace/items/page?`, `/api/v1/workspace/calendar/events?`, `/api/v1/account/usage`, `/api/v1/quarantine?`, `data-home-open`} {
		if !strings.Contains(string(js), required) {
			t.Errorf("home dashboard script does not contain %q", required)
		}
	}
	if _, err := fs.ReadFile(Content, "welcome/index.html"); err == nil {
		t.Error("unused welcome page is still embedded")
	}
}

func TestContactsTopbarUsesCompactNarrowGrid(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`body[data-page="contacts"]{--contacts-topbar-height:91.4px}`,
		`body[data-page="contacts"]:has(#contact-bulk-actions:not([hidden])){--contacts-topbar-height:133px}`,
		`body[data-page="contacts"] .app-topbar{display:grid;grid-template-columns:auto minmax(0,1fr) auto;grid-template-rows:repeat(2,36px)`,
		`body[data-page="contacts"] .contact-tools{display:grid;grid-column:2;grid-row:1/3;grid-template-columns:minmax(112px,1fr) auto auto`,
		// Import/export and new address book share row one; an unplaced button spilled into a third row over the list.
		`body[data-page="contacts"] #export-addressbook{grid-column:3;grid-row:1}body[data-page="contacts"] #new-addressbook{grid-column:4;grid-row:1}`,
		`body[data-page="contacts"] .contact-tools .topbar-search{grid-column:1/4;grid-row:2;width:100%;min-width:0}`,
		`body[data-page="contacts"] #new-contact{grid-column:4;grid-row:2}`,
		`body[data-page="contacts"] #contact-bulk-actions:not([hidden]){display:flex;grid-column:1/-1;grid-row:2;min-width:0}`,
		`body[data-page="contacts"] .app-content{height:calc(100vh - var(--contacts-topbar-height))}`,
		`@media(max-width:360px){body[data-page="contacts"] #new-contact{width:36px;min-width:36px;padding:0}`,
		`body[data-page="contacts"] #new-contact .contact-create-label{display:none}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact narrow Contacts topbar CSS does not contain %q", required)
		}
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`id="new-contact" title="Create contact or group" aria-label="New contact or group"`, `<span aria-hidden="true">＋</span><span class="contact-create-label">New</span>`} {
		if !strings.Contains(string(template), required) {
			t.Errorf("minimum-width Contacts create action does not contain %q", required)
		}
	}
}

func TestContactsExposeFirstClassVCardGroupWorkflow(t *testing.T) {
	jsData, err := fs.ReadFile(Content, "js/app.js")
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
	javascript, css, template := string(jsData), string(cssData), string(templateData)
	for _, required := range []string{
		"kindDialog.showModal()", "button.dataset.contactKind", "kind:form.elements.kind.value",
		"members:form.elements.kind.value==='group'?values(form.elements.members.value):[]",
		"contact.member_count", "groupMemberEntry=value=>", "it does not expand mail recipients",
	} {
		if !strings.Contains(javascript+template, required) {
			t.Errorf("contact-group workflow does not contain %q", required)
		}
	}
	for _, required := range []string{`id="contact-kind-dialog"`, `data-contact-kind="individual"`, `data-contact-kind="group"`, `name="kind" type="hidden"`, `name="members"`} {
		if !strings.Contains(template, required) {
			t.Errorf("contact-group template does not contain %q", required)
		}
	}
	for _, required := range []string{".contact-kind-options {", ".contact-kind-badge {", ".contact-group-avatar {", "@media(max-width:480px){.contact-kind-options"} {
		if !strings.Contains(css, required) {
			t.Errorf("contact-group styles do not contain %q", required)
		}
	}
}

func TestContactsSortHeadingHonorsDarkTheme(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `html[data-color-scheme="dark"] .contacts-table th button { color:inherit; }`) {
		t.Error("Contacts sort headings do not inherit the accessible dark-theme heading color")
	}
}

func TestCalendarTopbarExposesAllNarrowControls(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`body[data-page="calendar"]{--calendar-topbar-height:133px}`,
		`body[data-page="calendar"] .app-topbar{display:grid;grid-template-columns:auto minmax(0,1fr) auto;grid-template-rows:repeat(3,36px)`,
		`body[data-page="calendar"] .calendar-tools{display:grid;grid-column:2;grid-row:1/4;grid-template-columns:auto minmax(0,1fr) auto`,
		`body[data-page="calendar"] .calendar-picker-options{position:fixed;top:44px;right:auto;left:2.6rem;width:min(272px,calc(100vw - 5.2rem));min-width:0}`,
		`body[data-page="calendar"] #calendar-count{grid-column:3;grid-row:1;align-self:center;max-width:5rem;overflow:hidden;text-overflow:ellipsis`,
		`body[data-page="calendar"] #calendar-period{display:block;grid-column:1/3;grid-row:2;min-width:0;align-self:center;padding-left:72px;padding-right:.4rem;overflow:hidden;text-overflow:ellipsis`,
		`@media(max-width:360px){body[data-page="calendar"] #calendar-period{padding-left:44px}}`,
		`body[data-page="calendar"] .calendar-manage-button{z-index:1;grid-column:1;grid-row:2;justify-self:start;width:36px;min-width:36px;padding:0;font-size:0}`,
		`body[data-page="calendar"] .calendar-manage-button span{font-size:.8rem}`,
		`body[data-page="calendar"] #new-calendar-event{grid-column:3;grid-row:2}`,
		`body[data-page="calendar"] #calendar-views{grid-column:1/-1;grid-row:3;width:100%}`,
		`body[data-page="calendar"] .app-content{height:calc(100vh - var(--calendar-topbar-height))}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("complete narrow Calendar topbar CSS does not contain %q", required)
		}
	}
}

func TestLightThemeSemanticTokensRetainNormalTextContrast(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		`--text-muted:#51666b`,
		`--brand:#007f82`,
		`--danger:#b3322b`,
		`--success:#06704f`,
		// Focus rings reference --focus, so it must exist in both themes.
		`:root { --focus:#00676a; }`,
		`html[data-color-scheme="dark"] { --focus:#63ddd2; }`,
		`.calendar-month-day.outside { color:var(--text-muted); background:#f4f8f7; }`,
		`html[data-color-scheme="dark"] .calendar-month-day.outside { color:var(--text-muted); background:var(--bg-primary); }`,
		`html[data-color-scheme="dark"] .compact-button-group button { color:var(--text-secondary); background:var(--bg-primary); }`,
		`html[data-color-scheme="dark"] .compact-button-group button:hover,html[data-color-scheme="dark"] .compact-button-group button.active { color:#062f32; background:var(--brand); }`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("light-theme contrast contract does not contain %q", required)
		}
	}
}

func TestCalendarTimelineRestoresCompactPosition(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheetData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	stylesheet := string(stylesheetData)
	for _, required := range []string{
		"timeline_scrolls",
		"timelineScope=days=>",
		"restoreTimelinePosition=(days,scope,previous,token)=>",
		"grid.dataset.timelineScope",
		"grid.scrollTo({left,top,behavior:'auto'})",
		"Swipe for later days →",
		"← Earlier days",
		"queueTimelinePersistence",
		"calendarCompact.addEventListener('change'",
		"existing?.scope===grid.dataset.timelineScope?existing.left:0",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("calendar timeline state does not contain %q", required)
		}
	}
	for _, required := range []string{
		".calendar-time-label { position:sticky; z-index:5; top:0; left:0;",
		".calendar-time-column { display:grid; min-height:1152px;",
		".calendar-time-column { position:sticky; z-index:4; left:0;",
		"body[data-page=\"calendar\"] .calendar-scroll-cue{position:absolute;z-index:7;",
		"body[data-page=\"calendar\"] .calendar-scroll-cue[hidden]{display:none}",
	} {
		if !strings.Contains(stylesheet, required) {
			t.Errorf("calendar compact timeline CSS does not contain %q", required)
		}
	}
}

func TestCalendarCompactMonthAgendaKeepsSelectedDayUseful(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheetData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	stylesheet := string(stylesheetData)
	template := string(templateData)
	for _, required := range []string{
		`id="calendar-day-agenda"`, `id="calendar-day-agenda-date"`,
		`id="calendar-day-agenda-events"`, `<button type="button" class="btn btn-sm" data-new-calendar-day>＋ Event</button>`,
		`aria-labelledby="calendar-day-agenda-date"`,
	} {
		if !strings.Contains(template, required) {
			t.Errorf("compact Calendar agenda template does not contain %q", required)
		}
	}
	for _, required := range []string{
		"selected_day:selectedDay", "const renderDayAgenda=", "const selectMonthDay=",
		`data-select-calendar-day=`, `aria-controls="calendar-day-agenda"`,
		`aria-pressed=`, `data-agenda-event=`, "events.filter(event=>overlapsDay(event,date))",
		"openEventEditor(null,date)", `const recurring=Boolean(event?.recurrence&&event.recurrence!=="none")`,
		"ArrowLeft:-1", "ArrowRight:1", "ArrowUp:-7", "ArrowDown:7",
		"event.key==='Home'", "event.key==='End'", "workspace.classList.toggle('agenda-visible'",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("compact Calendar agenda behavior does not contain %q", required)
		}
	}
	for _, required := range []string{
		".calendar-day-agenda { display:none;", ".calendar-month-day.selected {",
		`body[data-page="calendar"] .calendar-workspace.agenda-visible{display:grid;grid-template-rows:minmax(0,1fr) minmax(112px,21dvh)}`,
		`body[data-page="calendar"] .calendar-workspace.agenda-visible>.calendar-day-agenda{display:grid;grid-template-rows:auto minmax(0,1fr)}`,
		`body[data-page="calendar"] .calendar-month{grid-template-rows:30px repeat(6,minmax(52px,1fr))}`,
		`body[data-page="calendar"] .calendar-month .calendar-event{min-height:24px;margin:.1rem 0;padding:.28rem .2rem;font-size:.62rem}`,
		".calendar-agenda-event strong{font-size:.72rem;line-height:1.35;overflow-wrap:anywhere}",
	} {
		if !strings.Contains(stylesheet, required) {
			t.Errorf("compact Calendar agenda styles do not contain %q", required)
		}
	}
}

func TestCalendarFullAgendaViewUsesIndexedRangeAndExistingEventFlow(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	stylesheetData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(javascriptData)
	stylesheet := string(stylesheetData)
	template := string(templateData)
	for _, required := range []string{
		`id="calendar-views" aria-label="Calendar view"`,
		`data-view="agenda">Agenda</button>`,
	} {
		if !strings.Contains(template, required) {
			t.Errorf("Calendar agenda template does not contain %q", required)
		}
	}
	for _, required := range []string{
		"['day','week','month','agenda'].includes(calendarState.view)",
		"const agendaRange=()=>",
		"end.setDate(end.getDate()+31)",
		"const renderAgenda=()=>",
		"grid.className='calendar-grid calendar-agenda-list'",
		`data-static-event aria-label=`,
		"eventTimeLabel(event,start,end)",
		"eventRecurrenceLabel(event)",
		"if(button.dataset.staticEvent!==undefined)return",
		"if(view==='agenda')return agendaRange()",
		"else if(view==='agenda')renderAgenda()",
		"view==='agenda'?31:0",
		"No events in this 31-day window",
		"calendarProjectionState=()=>loadUIState('calendar-projections')",
		"selected_calendar_ids:[...selectedCalendars]",
	} {
		if !strings.Contains(javascript, required) {
			t.Errorf("Calendar agenda behavior does not contain %q", required)
		}
	}
	for _, required := range []string{
		".calendar-agenda-list { display:block; overflow:auto;",
		".calendar-agenda-list-day>header { position:sticky;",
		".calendar-agenda-list-event { display:grid; width:100%; min-height:44px;",
		"border-left:4px solid var(--event-color,var(--brand))",
		".calendar-agenda-list-event:hover,.calendar-agenda-list-event:focus-visible",
		`body[data-page="calendar"] .calendar-agenda-list-event{grid-template-columns:3.75rem minmax(0,1fr)`,
		`body[data-page="calendar"] .calendar-agenda-list-calendar{display:none}`,
	} {
		if !strings.Contains(stylesheet, required) {
			t.Errorf("Calendar agenda styles do not contain %q", required)
		}
	}
}

func TestCalendarEventEditorFitsCompactViewport(t *testing.T) {
	data, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(data)
	for _, required := range []string{
		"#calendar-event-dialog { max-height:calc(100dvh - 2rem); padding:0; overflow:hidden; }",
		"#calendar-event-dialog form { max-height:calc(100dvh - 2rem); grid-template-rows:minmax(0,1fr) auto; gap:0; overflow:hidden; }",
		".calendar-event-editor-scroll { display:grid; gap:1rem; min-width:0; min-height:0; padding:1rem; overflow:auto; }",
		"#calendar-event-dialog .dialog-actions { padding:1rem; border-top:1px solid var(--border-color); background:var(--bg-secondary); }",
		"#calendar-event-dialog{width:calc(100vw - 1rem);max-width:calc(100vw - 1rem);max-height:calc(100dvh - 1rem)}",
		"#calendar-event-dialog form{max-height:calc(100dvh - 1rem)}",
		"#calendar-event-dialog .calendar-event-editor-scroll{padding:.75rem}",
		"#calendar-event-dialog form,#calendar-event-dialog label,#calendar-event-dialog input,#calendar-event-dialog select,#calendar-event-dialog textarea,#calendar-event-dialog .dialog-header,#calendar-event-dialog .dialog-actions,#calendar-event-dialog .calendar-event-times{min-width:0}",
		"#calendar-event-dialog .calendar-event-times{grid-template-columns:minmax(0,1fr)}",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact Calendar event editor CSS does not contain %q", required)
		}
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(template), `<div class="calendar-event-editor-scroll"><div class="dialog-header">`) {
		t.Error("calendar event fields are not isolated in the bounded editor scroller")
	}
}

func TestQuotaBreakdownFitsCompactNarrowCard(t *testing.T) {
	styleData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css := string(styleData)
	client := string(clientData)
	for _, required := range []string{
		`class="data-table quota-breakdown-table" data-responsive-key="user-storage-by-type" data-responsive-primary="0"`,
		`data-row-id="${escapeHTML(String(entry.type||'other'))}"`,
	} {
		if !strings.Contains(client, required) {
			t.Errorf("compact quota table client does not contain %q", required)
		}
	}
	for _, required := range []string{
		`.quota-breakdown-table.responsive-table tbody td.responsive-primary{display:flex`,
		`.quota-breakdown-table .responsive-row-toggle{flex:0 0 auto;margin:0 0 0 auto;white-space:nowrap}`,
		`.quota-breakdown-table.responsive-table tbody td.responsive-secondary{white-space:nowrap}`,
	} {
		if !strings.Contains(css, required) {
			t.Errorf("compact narrow quota table CSS does not contain %q", required)
		}
	}
}

func TestSyncWorkspaceSeparatesLifetimeAndLatestRunProgress(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"run_source_items_known", "run_items_examined", "run_items_failed", "run_items_remaining_known",
		`class="sync-total-label">All runs`, "Last run · <strong>", "Latest run ·", "Latest run transferred", "Latest run failed",
		"No source changes returned", "source changes received · inventory total unavailable",
		"source changes examined · full traversal unavailable", "Source inventory total", "Source changes returned",
		"Inventory traversal did not finish", "Completed with errors", "Stopped by fatal error",
		"Completed with item errors", "item_failures", "result.item_failures.length", "terminal item error", "sync-item-failures",
		"run_last_checkpoint_folder_name", "run_fatal_error", "items_remaining_known", "traversal_complete",
		"run_terminal_failure", "terminalFailureCard", "Run-stopping failure", "Failed phase", "retry_recommended",
		"retry_disposition", "retry_advice", "occurred_at", "data-sync-terminal-details", "Inspect retained run details", `aria-label="Run-stopping failure"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("sync progress workspace does not contain %q", required)
		}
	}
	if strings.Contains(source, "source total unknown") {
		t.Error("incremental sync progress still presents an unavailable inventory total as contradictory item examination")
	}
	if strings.Contains(source, `class="sync-terminal-failure" role="alert"`) {
		t.Error("terminal sync failure would be re-announced on every polling render")
	}
	data, err = fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `.migration-job-copy>small>:is(.sync-direction,.sync-total-label),.sync-run-progress>div>span>strong { display:inline; }`) {
		t.Error("sync scope labels do not remain inline in the compact profile summary")
	}
}

func TestAccessWorkspaceUsesListFirstGrantPattern(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"/api/v1/grants", "loadUIState(view==='delegation'?'delegation_grants':'access_grants')", "renderGrants", "configureGrantType",
		"grant-review", "data-grant-sort", "data-grant-action", "inspectGrant", "editGrant",
		"effectiveGrant", "effective-access", "grant-page-size", "persistAccessState",
		"expected_updated_at", "account-acting-dialog", "folderGrantPermissions",
		"data-grant-step", "grant-resource-filter", "grant-custom-permissions",
		"grantConsequences", "explicit deny", "folder.permissions.manage",
		"pendingGrant.custom", "pendingGrant.inheritance", "['access','delegation','share-links']",
		"allowedGrantTypes", "grantBelongsToView", "view==='share-links'",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("access list-first client does not contain %q", required)
		}
	}
	for _, required := range []string{".access-grant-overview", ".access-toolbar", ".access-grant-table", ".access-pagination", ".grant-management-dialog", ".grant-dialog", ".grant-wizard-progress", ".grant-wizard-step", ".grant-resource-options", ".grant-custom-permissions", ".grant-review-consequences", `.workspace-shell[data-settings-section="share-links"]`, ".access-overview-header{flex-direction:column"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("access list-first styles do not contain %q", required)
		}
	}
	for _, repeated := range []string{
		"grantOverview.querySelector('h2')",
		"grantOverview.querySelector('.eyebrow')",
		`<h2>Share links</h2>`,
		`<span class="eyebrow">Bearer capabilities</span>`,
	} {
		if strings.Contains(string(javascript), repeated) {
			t.Errorf("access collection repeats its workspace title through %q", repeated)
		}
	}
}

func TestAccessCollectionsSuppressInertEmptyChrome(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"noCollection=grants.length===0&&!filter.value.trim()",
		"emptyMessage=noCollection?(view==='delegation'?'No delegations yet.':'No access grants yet.'):'No grants match this view.'",
		`${escapeHTML(emptyMessage)}</td></tr>`,
		"rows.closest('table').classList.toggle('empty-collection',noCollection)",
		"grantToolbar.hidden=noCollection&&view!=='delegation'",
		"querySelectorAll('.search-field,.record-count,.access-page-size')",
		"grantPagination.hidden=pages<=1",
		"noCollection=shareLinks.length===0&&!query",
		"shareToolbar.hidden=noCollection",
		"sharePagination.hidden=pages<=1",
		`class="resource-toolbar share-links-toolbar" hidden`,
		"table.classList.contains('share-links-table')?'share-links'",
		"table.access-grant-table,table.share-links-table",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("access collection state does not contain %q", required)
		}
	}
	for _, required := range []string{
		`class="resource-toolbar access-toolbar" hidden`,
		`class="access-pagination" hidden`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("access collection initial state does not contain %q", required)
		}
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		".access-grant-table.empty-collection { min-width:0; }",
		".access-grant-table.empty-collection thead { display:none; }",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("empty Access collection style does not contain %q", required)
		}
	}
}

func TestShareLinksUseGuidedManagementAndFragmentBearerUI(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	publicJavascript, err := fs.ReadFile(Content, "js/share.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"/api/v1/share-links", "loadUIState('share_links')", "persistShareUI",
		"share-link-rows", "data-share-sort", "new-share-link", "data-share-step",
		"shareConsequences", "Accepted request limit", "Secret shown once",
		"confirmAction(`Revoke", "folder.shares.manage",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("share-link management client does not contain %q", required)
		}
	}
	for _, required := range []string{
		"location.hash.slice(1)", "Authorization:'Share '+token", "/api/v1/public/share",
		"public-share-confirm", "confirmDialog.showModal()", "URL.createObjectURL",
		"classList.toggle('enabled',loaded.access==='write')",
	} {
		if !strings.Contains(string(publicJavascript), required) {
			t.Errorf("public share client does not contain %q", required)
		}
	}
	if strings.Contains(string(publicJavascript), "confirm(") || strings.Contains(string(javascript), "window.confirm") {
		t.Error("share UI uses a browser-native confirmation dialog")
	}
	for _, required := range []string{".share-links-table", ".share-link-dialog", ".share-issued-dialog", ".public-share-page", ".public-share-layout", ".public-share-item-detail", ".public-share-editor[hidden]"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("share UI styles do not contain %q", required)
		}
	}
}

func TestMCPKeyUIRequiresExplicitWriteOptIn(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`name="write_access" type="checkbox"`,
		"Allow this client to change items",
		"mcp.write",
		"bounded draft, event, contact, and file creation or replacement",
		"folder changes; flags, copies, moves, recoverable trash, and restoration",
		"form.elements.write_access.checked?['mcp.write']:[]",
		`name="rest_access"`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("MCP credential UI does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("MCP credential UI introduced a native browser dialog")
	}
}

func TestIdentitySignatureUIAndComposerUseManagedPlainTextBlocks(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`data-signature-identity`, `data-clear-signature`, `/api/v1/user/signatures/`,
		`new_messages`, `replies_forwards`, `withoutManagedSignature`,
		`applyManagedSignature`, `managedSignature`, `-- \n`,
		`candidate=>!candidate.delegated`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("identity signature workflow does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("identity signature workflow introduced a native browser dialog")
	}
}

func TestAdminAccountIdentityLifecycleUsesSharedModalFramework(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`data-account-tab="identities"`, `/api/v1/admin/users/${encodeURIComponent(id)}/identities`,
		`data-add-identity`, `edit-identity`, `delete-identity`, `openIdentityEditor`,
		`title:'Delete email identity'`, `editorAfterSubmit`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("account identity lifecycle does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("account identity lifecycle introduced a native browser dialog")
	}
}

func TestComposerMessageTemplatesUseOwnerRESTAndSafeProjection(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`message-templates-toggle`, `message-templates-dialog`, `message-template-editor-dialog`,
		`/api/v1/mail/templates`, `method:id?'PATCH':'POST'`, `method:'DELETE'`,
		`confirmAction(`, `title:'Apply message template'`, `title:'Delete message template'`,
		`composeForm.elements.subject.value=template.subject`, `setComposeBody(template.body)`,
		`Recipients, sender, attachments, and delivery options stay unchanged.`,
		`message_template.`, `managedSignature=null;applyManagedSignature();markComposeChanged()`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("message-template workflow does not contain %q", required)
		}
	}
	for _, required := range []string{".message-templates-dialog", ".message-template-list", ".message-template-row", ".message-template-editor-dialog"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("message-template styles do not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") {
		t.Error("message-template workflow introduced a native browser dialog")
	}
}

func TestAdminSupportBundlePreviewsPrivacyBoundaryBeforeCSRFDownload(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`operation==='support'`, `/api/v1/admin/support-bundle/preview`, `/api/v1/admin/support-bundle/download`,
		`Privacy-scoped contents`, `Always excluded`, `file.description`, `file.privacy`, `file.sha256`,
		`method:'POST'`, `'X-CSRF-Token':csrf`, `URL.createObjectURL(blob)`, `Support bundle created`,
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("support-bundle workflow does not contain %q", required)
		}
	}
	for _, required := range []string{".support-bundle-workspace", ".support-privacy-notice", ".support-bundle-table", ".support-exclusion-list"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("support-bundle styles do not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "window.confirm(") || strings.Contains(string(javascript), "window.prompt(") || strings.Contains(string(javascript), "window.alert(") {
		t.Error("support-bundle workflow introduced a native browser dialog")
	}
}

func TestDomainAdministrationOffersDNSGuidance(t *testing.T) {
	javascriptData, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"DNS records", "openDNSGuidance", "dns-guidance-dialog", "/dns`", "data-dns-copy", "Live value"} {
		if !strings.Contains(string(javascriptData), required) {
			t.Errorf("DNS guidance UI does not contain %q", required)
		}
	}
	cssData, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cssData), ".dns-guidance-table") {
		t.Error("DNS guidance styling is missing")
	}
}

func TestSyncProfilesShowCompactStatusLine(t *testing.T) {
	js, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"syncStatusLine=job=>", "${syncStatusLine(job)}", "Intl.RelativeTimeFormat", "'Synced'", "'Syncing…'", "'Failed'", "'Not run yet'",
		"Last attempt ", "Last success ", "No changes", "Next run ", "humanSyncError", "certificate or TLS problem", "over its storage quota",
		`class="sync-status-details"`, "<summary>Details</summary>", "job.last_success_at", `role="status"`,
	} {
		if !strings.Contains(string(js), required) {
			t.Errorf("sync status line does not contain %q", required)
		}
	}
	for _, required := range []string{".sync-status-line{", ".sync-pill-running::before", "@media(prefers-reduced-motion:reduce){.sync-pill-running::before{animation:none}}"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("sync status CSS does not contain %q", required)
		}
	}
}
