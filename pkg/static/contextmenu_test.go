package static

import (
	"context"
	"io/fs"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func readAsset(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(Content, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestContextMenusUseOneSharedAccessibleComponent(t *testing.T) {
	js, css := readAsset(t, "js/app.js"), readAsset(t, "css/app.css")
	if count := strings.Count(js, "document.addEventListener('contextmenu'"); count != 1 {
		t.Fatalf("app.js has %d document contextmenu listeners, want exactly one shared handler", count)
	}
	for _, required := range []string{
		"const contextMenu=(()=>", "registerContextMenu=(selector,provider)", "const contextSelection=",
		"setAttribute('role','menu')", "setAttribute('role','menuitem')", "setAttribute('role','separator')",
		"aria-haspopup','menu'", "event.key==='ContextMenu'", "event.key==='F10'&&event.shiftKey",
		"event.key==='Home'", "event.key==='End'", "event.key==='Escape'", "event.key==='ArrowRight'", "event.key==='ArrowLeft'",
		"pointerType!=='touch'", "},500)", "contextMenuNativeTarget", "contextMenuTextEntry", "contextRowActions",
		"popover='manual'", "addEventListener('resize'", "addEventListener('blur'", "addEventListener('scroll'",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("context menu component does not contain %q", required)
		}
	}
	for _, selector := range []string{
		"'#message-list .message-row'", "'#item-view .message-attachment-card'", "'#item-view.message-view'", "'#folder-list .folder-row'",
		"'#calendar-grid [data-event],#calendar-day-agenda [data-agenda-event]'", "'#calendar-grid [data-calendar-day]'", "'#calendar-select label'",
		"'#contact-rows tr[data-contact-id]'", "'#file-rows tr[data-file-id]'", "'#files-layout .files-pane'", "'#file-folder-list [data-folder-id]'",
		"'#global-search-results [data-search-item]'", "'#trash-rows tr[data-trash-key]'", "'#quarantine-rows tr[data-quarantine-id]'",
	} {
		if !strings.Contains(js, "registerContextMenu("+selector) {
			t.Errorf("no context menu provider is registered for %s", selector)
		}
	}
	for _, required := range []string{".context-menu-layer{", ".context-menu{", ".context-menu-item{", ".context-menu-item.danger{", ".context-menu-separator{", "@media(pointer:coarse){.context-menu-item{min-height:40px}}"} {
		if !strings.Contains(css, required) {
			t.Errorf("context menu CSS does not contain %q", required)
		}
	}
}

// TestContextMenuPureHelpers runs the item normaliser and viewport positioning helpers under Node when it is installed.
func TestContextMenuPureHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	js := readAsset(t, "js/app.js")
	var helpers []string
	for _, name := range []string{"contextMenuItems", "contextMenuPosition"} {
		match := regexp.MustCompile(`(?m)^\s*const ` + name + `=.*;$`).FindString(js)
		if match == "" {
			t.Fatalf("helper %s not found as a single-line declaration", name)
		}
		helpers = append(helpers, match)
	}
	script := strings.Join(helpers, "\n") + `
const assert=(ok,message)=>{if(!ok){console.error(message);process.exit(1)}};
const items=contextMenuItems([{separator:true},{label:'A'},null,false,{separator:true},{separator:true},{label:'Hidden',hidden:true},{label:'Empty',submenu:[false,{separator:true}]},{label:'B',submenu:()=>[]},{separator:true}]);
assert(items.map(item=>item.label||'-').join(',')==='A,-,B','normalised items: '+JSON.stringify(items));
let p=contextMenuPosition({x:10,y:10,width:100,height:50,viewportWidth:800,viewportHeight:600});
assert(p.left===10&&p.top===10,'in-viewport position: '+JSON.stringify(p));
p=contextMenuPosition({x:780,y:590,width:100,height:50,viewportWidth:800,viewportHeight:600});
assert(p.left===680&&p.top===540,'flipped position: '+JSON.stringify(p));
p=contextMenuPosition({x:500,y:100,width:200,height:50,viewportWidth:600,viewportHeight:600,flipX:300});
assert(p.left===100,'submenu flips to the parent side: '+JSON.stringify(p));
p=contextMenuPosition({x:5,y:5,width:900,height:900,viewportWidth:300,viewportHeight:300});
assert(p.left===4&&p.top===4,'oversized menu clamps to margin: '+JSON.stringify(p));
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("context menu helpers failed: %v\n%s", err, output)
	}
}
