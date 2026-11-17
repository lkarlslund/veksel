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

func TestPeopleCardsAutocompleteAndSearchSuggestionContracts(t *testing.T) {
	js, css := readAsset(t, "js/app.js"), readAsset(t, "css/app.css")
	template, err := os.ReadFile(filepath.Join("..", "web", "app", "templates", "app.gohtml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		// One listbox controller with keyboard navigation and stale-answer protection.
		"const createCombobox=", "aria-activedescendant", "event.stopImmediatePropagation();pick(active)", "if(current!==token||document.activeElement!==input)return",
		// The shared recipient autocomplete ranks people server-side and expands groups.
		"const setupRecipientAutocomplete=(input,", "/api/v1/workspace/people/suggestions?", "/api/v1/workspace/people/group?item_id=", "data-expand-index", "event.key==='ArrowRight'&&entry?.kind==='group'", "kind:'all'", "['to','cc','bcc'].forEach(name=>setupRecipientAutocomplete(composeForm.elements[name]))",
		// One card for every person surface, cached and opened on hover delay or keyboard focus.
		"const personCard=(()=>{", "'[data-person],.calendar-attendee-name[title*=\"@\"]'", "/api/v1/workspace/people/card?", "Date.now()-cached.at<300000", "showTimer=setTimeout(()=>open(element),450)", "element?.matches(':focus-visible')", "data-card-mail", "data-card-add", "data-card-open", "data-card-favorite", "data-card-message", "data-card-meeting",
		"peopleMarkup(headers.from)", "data-person=\"${escapeHTML(addressKey(sender))}\"", "const composeTo=", "document.addEventListener('veksel:compose'", "loadUIState('compose-intent')",
		// Favorites persist on the server and pin to the contacts workspace.
		"const setContactFavorite=", "/api/v1/user/contact-favorites", "const renderFavorites=", "favoriteIDs.has(contact.id)", "id=\"favorite-contact\"", "'veksel:contact-favorites'",
		// Typed suggestions and scopes for both search boxes.
		"const loadSearchSuggestions=", "/api/v1/search/suggestions?", "Search all apps for", "function renderScopeChips()", "data-search-scope-folder", "const applySavedSearch=", "recent:recentSearches",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("app.js does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"window.confirm(", "window.prompt(", "window.alert("} {
		if strings.Contains(js, forbidden) {
			t.Errorf("app.js contains %q", forbidden)
		}
	}
	for _, required := range []string{`id="global-search-suggestions"`, `aria-controls="global-search-suggestions"`, `id="search-scope-bar"`, `id="contact-favorites"`} {
		if !strings.Contains(string(template), required) {
			t.Errorf("template does not contain %q", required)
		}
	}
	for _, required := range []string{".person-card {", ".person-chip {", ".scope-chip.active", ".contact-favorite-chip", ".recipient-suggestion.recipient-group", ".search-page-shell { display:grid; grid-template-rows:auto auto minmax(0,1fr);"} {
		if !strings.Contains(css, required) {
			t.Errorf("app.css does not contain %q", required)
		}
	}
}

// TestPeopleAddressHelpers runs the shared address helpers under Node when it is installed.
func TestPeopleAddressHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	js := readAsset(t, "js/app.js")
	var declarations []string
	for _, name := range []string{"splitAddressList", "mailboxParts", "personInitials", "formatMailbox"} {
		declaration := regexp.MustCompile(`(?m)^\s*const ` + name + `=.*;$`).FindString(js)
		if declaration == "" {
			t.Fatalf("%s not found as a single-line declaration", name)
		}
		declarations = append(declarations, declaration)
	}
	script := strings.Join(declarations, "\n") + `
const assert=(ok,message)=>{if(!ok){console.error(message);process.exit(1)}};
const parts=splitAddressList('"Lovelace, Ada" <ada@example.test>, bob@example.test; Carol <carol@example.test>');
assert(parts.length===3&&parts[0]==='"Lovelace, Ada" <ada@example.test>','splits outside quotes');
assert(addressKey(parts[2])==='carol@example.test','extracts the address');
const ada=mailboxParts(parts[0]);
assert(ada.email==='ada@example.test'&&ada.name==='Lovelace, Ada','parses quoted display names');
assert(mailboxParts('not an address').email==='','rejects non-addresses');
assert(personInitials('Ada Lovelace')==='AL'&&personInitials('bob')==='B'&&personInitials('')==='?'&&personInitials('ada.lovelace@example.test')==='AL','builds initials');
assert(formatMailbox('Lovelace, Ada','ada@example.test')==='Lovelace Ada <ada@example.test>','strips address-list separators');
assert(formatMailbox('ada@example.test','ada@example.test')==='ada@example.test','omits a redundant name');
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("address helpers failed: %v\n%s", err, output)
	}
}
