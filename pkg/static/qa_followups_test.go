package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestQAFollowUps pins the client side of the gaps the October 2026 QA pass
// noted but left unchanged.
func TestQAFollowUps(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		// A system-only admin page opened by a domain administrator shows the in-app role notice,
		// and in-place navigation to a permitted page clears it.
		"if(root.dataset.denied==='true'){content.classList.remove('skeleton');setHeader('Not available for your role'",
		"resetAdminPaging();delete root.dataset.denied;",
		// Follow-up This week is due on the last working day and is hidden when that is today or tomorrow.
		"const lastWorkdayOffset=(now,weeksAhead)=>", "...(thisWeek>1?[['This week',thisWeek]]:[]),['Next week',nextWeek]]",
		// Reply and forward headers format the original Date in the account's display settings.
		"formatQuoteDate=value=>{const day=formatDisplayDate(value,{weekday:'short',day:'numeric',month:'short',year:'numeric'})",
		"<div>On ${escapeHTML(formatQuoteDate(headers.date)||'an earlier message')}, ${escapeHTML(headers.from||'the sender')} wrote:</div>",
		"On ${formatQuoteDate(headers.date)||'an earlier message'}, ${headers.from||'the sender'} wrote:",
		"<br>Date: ${escapeHTML(formatQuoteDate(headers.date))}<br>", "\\nDate: ${formatQuoteDate(headers.date)}\\n",
		// File rows are focusable and open on double-click or Enter.
		`<tr data-file-id="${escapeHTML(file.id)}" draggable="true" tabindex="0"`,
		"row.ondblclick=event=>{if(!event.target.closest('button,a,input,label'))openFile()}",
		"row.onkeydown=event=>{if(event.key==='Enter'&&event.target===row",
		// Search facets and results name tasks, and never repeat a folder named like its type.
		"tasks:'Tasks',contacts:'Contacts'", "tasks:'check',contacts:'person'",
		"const resultSource=hit=>{const same=value=>value.toLowerCase().replace(/s$/,'');return [hit.sender||typeLabel(hit.type),hit.folder_name||'Folder'].filter(", "<span>${escapeHTML(resultSource(hit))}</span>",
		// The open message row is exposed as selected and current; focus follows j/k and survives list re-renders.
		"row.setAttribute('aria-selected',String(selected||row.dataset.itemId===openedItemID))",
		"row?.classList.add('active');row?.setAttribute('aria-current','true');row?.setAttribute('aria-selected','true');",
		"messageList.setAttribute('aria-multiselectable','true')", "row.setAttribute('aria-selected',String(selectedIDs.has(item.id)||item.id===openedItemID))",
		"if(focusedID)messageList.querySelector(`[data-item-id=\"${CSS.escape(focusedID)}\"]`)?.focus({preventScroll:true})",
		"const opened=messageList.querySelector(`[data-item-id=\"${CSS.escape(item.id)}\"]`)||row;opened?.focus({preventScroll:true})",
		// Toasts in an open dialog start below its header.
		"if(region){const header=activeDialog.querySelector('.dialog-header');region.style.top=header?",
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
		".admin-role-denied p{",
		"dialog>.toast-region { position:absolute; top:1rem; right:1rem; pointer-events:none; }",
		".files-table tr[data-file-id]:focus-visible{",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("app.css does not contain %q", required)
		}
	}
}
