package static

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMailTriageListUsesServerProjectionAndAccessibleControls(t *testing.T) {
	js, css := readAsset(t, "js/app.js"), readAsset(t, "css/app.css")
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(template)
	for _, required := range []string{
		// Rows come from the list projection with the persisted filter and sort.
		"'/api/v1/workspace/mail/list?'", "filter:mailListFilter,sort:mailListSort", "filter:mailListFilter,sort:mailListSort,dir:mailListAscending?'asc':'desc',favorite_folder_ids:favoriteFolderIDs,recent_searches:recentMailSearches,search_scope:mailSearchScope",
		"item.preview", "class=\"${snippet?'search-result-snippet':'message-preview'}\"", "'$Forwarded'", "'\\\\Answered'", "item.has_attachments",
		// Hover quick actions stay keyboard reachable and never open the row.
		"data-quick-action=\"${action}\"", "if(!event.target.closest('label,button'))openMessage(row,item)", "if(event.target!==row)return;",
		// Folder unread counts and favorites.
		"'/api/v1/workspace/folders?'+new URLSearchParams({include:'unread',first:", "if(!mailListBuilding)syncFolderUnread(currentFolder.id,Number(page.unread)||0)", "registerContextMenu('#mail-favorites .favorite-row'", "moveFavoriteFolder(folder.id,index+(event.key==='ArrowUp'?-1:1))",
		// Counts and lists still building in the background update from events.
		"event.detail?.type==='folders.counts'||event.detail?.type==='mail.list.ready'", "mailListBuilding=Boolean(page.building)", "reloadBuildingList(250)",
		// Archive, junk, and block sender go through server actions with Undo.
		"act('archive')", "act('junk')", "act('not_junk')", "actOnItems('block_sender'", "restoreMailSources(sources)", "['E','archive']",
		// Search suggestions and scope.
		"expression:query", "folder_ids:[currentFolder.id]", "/api/v1/workspace/people/suggestions?", "aria-activedescendant", "rememberMailSearch(",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("mail triage UI does not contain %q", required)
		}
	}
	for _, required := range []string{
		`id="mail-filter"`, `<option value="to_me">To me</option>`, `id="mail-sort"`, `id="mail-sort-direction"`,
		`id="mail-favorites"`, `data-item-action="archive"`, `data-item-action="junk"`,
		`role="combobox"`, `aria-controls="mail-search-suggestions"`, `id="mail-search-scope"`,
	} {
		if !strings.Contains(markup, required) {
			t.Errorf("mail template does not contain %q", required)
		}
	}
	for _, required := range []string{
		".message-row:hover .message-quick-actions,.message-row:focus-within .message-quick-actions { display:flex; }",
		".message-quick-actions .toolbar-icon { width:24px; height:24px;", ".folder-unread[hidden] { display:none; }",
		".message-toolbar:has(.bulk-actions:not([hidden])) .mail-list-controls { display:none; }", ".topbar-search>span {",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("mail triage styles do not contain %q", required)
		}
	}
	if strings.Contains(js, "new MutationObserver(renderMailImportanceMarks)") {
		t.Error("importance marks must render with the row, not through a DOM observer")
	}
}
