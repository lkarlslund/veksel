package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestQAPassRegressions pins fixes from the October 2026 end-to-end QA pass
// whose behavior lives in the client script.
func TestQAPassRegressions(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		// A typed name or partial address adds the attendee it uniquely matches.
		"const suggestedAttendee=", "parseAttendee(value)||suggestedAttendee(value)",
		// Attendee and sharing pickers search the directory like the mail recipient field.
		"getPeopleSuggestions(query,attendeeSuggestController.signal)", "getPeopleSuggestions(query);shareOptions",
		// The work week count covers only the working days it shows.
		"const visibleEventCount=", "count.textContent=visibleCountLabel()",
		// A just-saved contact stays listed and selected while the search index catches up.
		"selected=saved;await loadContacts(true,true)", "contactTotal=Math.max(contactTotal,contacts.length)",
		// Imported contacts appear once the index applies its batched catch-up (at most 5 s).
		"if(contactTotal<before+result.imported)setTimeout(()=>loadContacts(true,true)",
		// Share links are revoked only when revoked_at is a real date.
		"shareStatus=link=>validDate(link.revoked_at)?'Revoked'",
		// The domain administrator console never calls system-only alert, logging, storage, or trace-index APIs.
		"if(!domainScope){document.addEventListener('veksel:event',event=>{if(event.detail?.type?.startsWith('health.alert.'))", "section==='logs'||domainScope)return true;", "(u.engine&&!domainScope?iconButton('Verify account integrity'", "if(!domainScope)document.querySelector('#trace-rebuild')",
		// Trace and queue times are formatted, not raw RFC 3339.
		"{label:'Updated',value:r=>r.updated_at,render:r=>escapeHTML(formatDateTime(r.updated_at))}",
		// The admin setting search opens its first result on Enter and moves into the results with the arrow keys.
		"else if(event.key==='Enter'){const first=settingResults.querySelector('a[href]')", "settingResults.addEventListener('keydown'",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("app.js does not contain %q", required)
		}
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		// The admin detail dialog (DNS records, DKIM keys) has no form of its own to pad it.
		".admin-editor>form,#admin-detail{padding:1.4rem}",
		// Settings cards placed directly on an admin page are padded like grid cards.
		"#admin-page-content>.card>.setting-list",
		// Card header subtitles sit under their title.
		".card-header>div>strong+small{display:block",
		// Between phone and desktop widths the calendar toolbar wraps instead of overflowing behind the rail.
		"@media(min-width:721px) and (max-width:1279px){body[data-page=\"calendar\"]{--calendar-topbar-height:104px}",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("app.css does not contain %q", required)
		}
	}
}
