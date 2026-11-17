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

func TestRichComposerAndMessageToolsContracts(t *testing.T) {
	js, css := readAsset(t, "js/app.js"), readAsset(t, "css/app.css")
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		// One shared allowlist sanitizes paste, editor content, and signatures in an inert document.
		"const sanitizeRichHTML=", "new DOMParser().parseFromString('<!doctype html><body></body>','text/html')", "richTextDropped.has(name)", "const sanitizeRichCSS=", "const richHTMLToText=",
		// The editor toolbar, shortcuts, paste, and drop handling.
		"const createRichEditor=", "document.execCommand('styleWithCSS',false,true)", "'insertUnorderedList'", "'insertOrderedList'", "'indent'", "'outdent'", "'justifyCenter'", "'createLink'", "'unlink'", "'removeFormat'", "'hiliteColor'", "'foreColor'", "'fontSize'", "exec('undo')", "exec('redo')",
		"{b:'bold',i:'italic',u:'underline'}[key]", "key==='k'", "surface.addEventListener('paste'", "data.getData('text/html')", "surface.addEventListener('drop'", "const richEmoji=",
		// Composer: plain-text toggle with confirmation, inline images as Content-ID parts, HTML drafts and quoting.
		"compose-format-toggle", "Switch this message to plain text?", "payload.html=content.html", "content_id:cid", "image.setAttribute('src',`cid:${cid}`)", "withInlineImages(payload.html,attachments)", "quotedOriginalHTML(message)", "<blockquote type=\"cite\"", "data-veksel-signature", "signature.html||textToRichHTML(signature.text)", "name=\"read_receipt\"", "read_receipt:form.get('read_receipt')==='on'",
		// Reader tools.
		"resolveMessageImages(root,item,projection,showRemote)", "image.src=image.dataset.remoteSrc", "data-remote-images=\"always\"", "'/api/v1/user/remote-image-senders/'", "data-receipt=\"send\"", "messageURL(item,'/receipt')", "messageURL(item,'/source')", "messageURL(item,'/eml')", "printMailMessages", "data-conversation-print", "id='message-source-dialog'",
		// Rich signatures in Settings.
		"createRichEditor({label:`Signature for ${form.dataset.signatureIdentity}`", "html:clear||!editor.hasFormatting()?'':markup",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("app.js does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"window.confirm(", "window.prompt(", "window.alert(", "prompt('", "cdn.jsdelivr", "unpkg.com"} {
		if strings.Contains(js, forbidden) {
			t.Errorf("app.js contains %q", forbidden)
		}
	}
	if receipt := regexp.MustCompile(`/receipt'\),\{method:'POST'`).FindAllString(js, -1); len(receipt) != 1 {
		t.Errorf("read receipts must be sent only from the reader prompt; found %d senders", len(receipt))
	}
	for _, required := range []string{`id="compose-message-label"`, `aria-labelledby="compose-message-label"`} {
		if !strings.Contains(string(template), required) {
			t.Errorf("template does not contain %q", required)
		}
	}
	for _, required := range []string{".rich-editor-toolbar", ".rich-editor-surface", ".rich-editor-popover", ".message-source-text", "body.printing-mail>:not(#mail-print-root)", ".message-receipt-notice"} {
		if !strings.Contains(css, required) {
			t.Errorf("app.css does not contain %q", required)
		}
	}
}

// TestRichCSSSanitizer runs the composer's CSS allowlist under Node when it is installed.
func TestRichCSSSanitizer(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	js := readAsset(t, "js/app.js")
	properties := regexp.MustCompile(`(?m)^\s*const richCSSProperties=.*;$`).FindString(js)
	sanitizer := regexp.MustCompile(`(?m)^\s*const sanitizeRichCSS=.*;$`).FindString(js)
	if properties == "" || sanitizer == "" {
		t.Fatal("richCSSProperties or sanitizeRichCSS not found as single-line declarations")
	}
	script := properties + "\n" + sanitizer + `
const assert=(ok,message)=>{if(!ok){console.error(message);process.exit(1)}};
assert(sanitizeRichCSS('color: rgb(200, 0, 0); font-size: large')==='color: rgb(200, 0, 0); font-size: large','keeps safe declarations');
assert(sanitizeRichCSS('background-image:url(https://evil.test/x)')==='','drops url()');
assert(sanitizeRichCSS('width:expression(alert(1))')==='','drops expression()');
assert(sanitizeRichCSS('position:fixed;z-index:9999;color:red')==='color: red','drops positioning');
assert(sanitizeRichCSS('margin-left:-400px')==='','drops negative offsets');
assert(sanitizeRichCSS('color:\\72 ed')==='','drops escapes');
assert(sanitizeRichCSS('font-family:var(--x)')==='','drops var()');
assert(sanitizeRichCSS('text-align: center; margin-left: 40px')==='text-align: center; margin-left: 40px','keeps alignment and indent');
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("CSS sanitizer failed: %v\n%s", err, output)
	}
}
