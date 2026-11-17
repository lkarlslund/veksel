package static

import (
	"io/fs"
	"strings"
	"testing"
)

// TestSplitDeliveryDomainUI keeps the split-delivery controls in the system
// administrator's domain editor: the fieldset, the route it stores, and the
// policy it sends with the domain.
func TestSplitDeliveryDomainUI(t *testing.T) {
	data, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		`<fieldset class="domain-split" id="domain-split">`,
		`name="split_route"`,
		`name="split_host"`,
		`name="split_check"`,
		"/api/v1/admin/routes/${encodeURIComponent(id)}",
		"transport:'relay'",
		"unknown_recipients:unknownRecipients",
		"${catchAllField}${domainSplitFields}",
		"bindDomainSplit(d)",
		"label:'Unknown recipients'",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("app.js lacks %q", required)
		}
	}
	// Domain administrators cannot change delivery, so their editor stays
	// catch-all only.
	if strings.Contains(script, "openEditor(id,'Edit domain',catchAllField+domainSplitFields") {
		t.Error("the domain-scoped editor offers split delivery")
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".domain-split{") {
		t.Error("app.css lacks .domain-split{")
	}
}

// TestInlineReplyHeaderDoesNotCoverComposer keeps the reading pane's sticky
// message header from pinning over the inline composer's address fields.
func TestInlineReplyHeaderDoesNotCoverComposer(t *testing.T) {
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"#item-view:has(.inline-composer-form) .message-header { position:static; }",
		".message-header { position:sticky; z-index:3;",
		".message-header-actions { display:flex; flex-wrap:wrap;",
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("app.css lacks %q", required)
		}
	}
}

// TestReaderLargerView keeps the reading pane's larger-view toggle.
func TestReaderLargerView(t *testing.T) {
	script, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(Content, "css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`data-reader-expand title="Open in a larger view"`, "setReaderExpanded(!readerPaneElement", "'Open in a window'"} {
		if !strings.Contains(string(script), required) {
			t.Errorf("app.js lacks %q", required)
		}
	}
	if !strings.Contains(string(css), ".reading-pane.reader-expanded {") {
		t.Error("app.css lacks the larger reader view")
	}
}
