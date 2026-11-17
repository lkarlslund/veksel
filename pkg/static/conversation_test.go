package static

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMailConversationViewReadingLayoutsAndInlineComposer(t *testing.T) {
	js, css := readAsset(t, "js/app.js"), readAsset(t, "css/app.css")
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(template)
	for _, required := range []string{
		// The list asks the server projection for conversations; reading pane and density are account display settings.
		"view:mailListView,...extra", "view:mailListView,conversation_order:conversationOrder", "readingPane=displayPrefs.reading_pane,mailDensity=displayPrefs.density", "saveDisplayPreferences({reading_pane:readingPane,density:mailDensity})",
		// Conversation rows: participants, count badge, combined marks, expansion into member rows.
		"conversation.participants.map(compactMailboxLabel)", `class="conversation-count"`, "messageMarksMarkup(state)", "messageQuickActionsMarkup(state)", "toggleConversationRow(row,item)", "openMessage(row,item,false,message.id)",
		// Row actions go to the server as folder-scoped conversation IDs; card actions stay on one message.
		"conversation_ids:conversationIDs,folder_id:currentFolder?.id||''", "actOnItems(button.dataset.cardAction,[message.id],'','messages')", "registerContextMenu('#message-list .conversation-child'",
		// Stacked reader: order setting, newest unread expands, quoted text collapses.
		"conversationOrder==='oldest'?[...messages].reverse():messages", "!hasFlag(message,'\\\\Seen'))||messages[0]", "const root=renderSanitizedMessageHTML(bodyHost,projection.html);resolveMessageImages(root,item,projection,showRemote);collapseHTMLQuotes(bodyHost,root)", "renderPlainBody(bodyHost,projection.text||replyBody)",
		// Reading pane placement and the Shift+P cycle.
		"mailLayout.dataset.readingPane=readingPane", "{right:'bottom',bottom:'off',off:'right'}[readingPane]", "(mobileMail.matches||readingPane==='off')",
		// One composer: replies open it inline and pop out into the dialog.
		"openComposer(action,message,{inline:slot})", "inline.append(composeForm)", "dialog.append(composeForm)", "popOutButton.onclick=popOutComposer", "rescueInlineComposer();",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("conversation UI does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"alert(", "confirm(\"", "window.confirm"} {
		if strings.Contains(js, forbidden) {
			t.Errorf("conversation UI must not use native dialogs (%q)", forbidden)
		}
	}
	for _, required := range []string{`id="mail-view" aria-pressed="true" title="Show as conversations"`, `id="mail-layout-options"`, `aria-haspopup="menu"`} {
		if !strings.Contains(markup, required) {
			t.Errorf("mail template does not contain %q", required)
		}
	}
	for _, required := range []string{
		`.mail-layout[data-reading-pane="bottom"] { grid-template-columns:210px minmax(0,1fr); grid-template-rows:minmax(0,2fr) minmax(0,3fr); }`,
		`.mail-layout[data-reading-pane="off"].reader-open>.reading-pane { display:block; }`,
		`.mail-layout[data-density="comfortable"] .message-row:not(.conversation-child)`,
		"#compose-form.inline-composer-form {", ".message-quote-toggle {", ".message-card-summary {",
	} {
		if !strings.Contains(css, required) {
			t.Errorf("conversation styles do not contain %q", required)
		}
	}
}
