package static

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMailShortcutsUndoSendSnoozePinAndFollowUpContracts(t *testing.T) {
	js, css := readAsset(t, "js/app.js"), readAsset(t, "css/app.css")
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		// Shortcut sets are selectable and documented by the "?" overlay.
		"const mailShortcutSets={owa:[", "gmail:[['C','compose']", "off:[]", "['Ctrl+Shift+R','replyAll']", "['Ctrl+Shift+F','forward']",
		"['Insert','flag']", "['Ctrl+Q','read']", "['Ctrl+U','unread']", "['#','delete']", "['X','select']", "['?','help']",
		"mailShortcutSets[mailPreferences.shortcuts]||mailShortcutSets.owa", "id='shortcut-help-dialog'", "openShortcutHelp",
		// Shortcuts never fire in text entry, the composer, menus, or dialogs.
		"event.target.closest('input,textarea,select,[contenteditable=\"true\"],#compose-form')||document.querySelector('dialog[open]')", "contextMenu.isOpen()",
		"event.key==='Enter'){event.preventDefault();composeForm.requestSubmit()}",
		// Undo send holds the saved draft server-side and reopens it on Undo.
		"undo_seconds:undoSeconds", "undoSendToast(held,undoSeconds)", "'/cancel',{method:'POST'}", "reopenHeldDraft(held)", "watchHeldSend",
		"filter(job=>!job.undo||job.state==='failed')", "action?.until", "action.expired?.()",
		// Snooze, pin, and follow-up use server actions.
		"actOnItems('snooze',ids,'',scope,{until:until.toISOString()})", "act('unsnooze')", "act('pin')", "act('unpin')", "act('complete')",
		"actOnItems('follow_up',ids,'',scope,{due_at:due.toISOString()", "item.snoozed_until", "item.follow_up?.due_at", "'$Pinned'",
		"'/api/v1/workspace/mail/follow-ups'", "'/api/v1/workspace/mail/reminders'", "action:'dismiss_reminder'", "id='mail-date-dialog'",
		"'/api/v1/user/mail-preferences'",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("app.js does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"window.confirm(", "window.prompt(", "window.alert("} {
		if strings.Contains(js, forbidden) {
			t.Errorf("app.js contains native dialog call %q", forbidden)
		}
	}
	for _, required := range []string{`id="mail-follow-up-view"`, `href="/app/settings/mail"`, `id="mail-preferences-form"`, `name="undo_send_seconds"`, `<option value="gmail">Gmail</option>`} {
		if !strings.Contains(string(template), required) {
			t.Errorf("template does not contain %q", required)
		}
	}
	for _, required := range []string{".follow-up-due", ".shortcut-help-table kbd", ".pin-mark"} {
		if !strings.Contains(css, required) {
			t.Errorf("app.css does not contain %q", required)
		}
	}
}

// TestMailShortcutMatcher runs the shortcut matcher under Node when it is installed.
func TestMailShortcutMatcher(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	js := readAsset(t, "js/app.js")
	match := regexp.MustCompile(`(?m)^\s*const shortcutMatches=.*;$`).FindString(js)
	if match == "" {
		t.Fatal("shortcutMatches not found as a single-line declaration")
	}
	script := match + `
const assert=(ok,message)=>{if(!ok){console.error(message);process.exit(1)}};
const key=(key,extra={})=>({key,code:/^[a-z]$/i.test(key)?'Key'+key.toUpperCase():'',ctrlKey:false,metaKey:false,altKey:false,shiftKey:false,...extra});
assert(shortcutMatches('R',key('r')),'R matches r');
assert(!shortcutMatches('R',key('R',{shiftKey:true})),'R does not match Shift+R');
assert(shortcutMatches('Shift+R',key('R',{shiftKey:true})),'Shift+R');
assert(shortcutMatches('Ctrl+Shift+R',key('R',{ctrlKey:true,shiftKey:true})),'Ctrl+Shift+R');
assert(shortcutMatches('Ctrl+Shift+F',key('F',{metaKey:true,shiftKey:true})),'Cmd acts as Ctrl');
assert(!shortcutMatches('R',key('r',{ctrlKey:true})),'plain R ignores Ctrl+R');
assert(shortcutMatches('Alt+Q',{key:'œ',code:'KeyQ',altKey:true,ctrlKey:false,metaKey:false,shiftKey:false}),'Alt+Q by physical key');
assert(shortcutMatches('?',key('?',{shiftKey:true})),'? ignores the shift needed to type it');
assert(shortcutMatches('#',key('#',{shiftKey:true})),'# ignores shift');
assert(shortcutMatches('Delete',key('Delete')),'Delete');
assert(!shortcutMatches('Delete',key('Delete',{shiftKey:true})),'Shift+Delete is not Delete');
assert(shortcutMatches('Insert',key('Insert')),'Insert');
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("shortcut matcher failed: %v\n%s", err, output)
	}
}
