package static

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCategoriesAndTasksUIUsesSharedFlows pins the UX-OWA-008 surfaces: one
// master category store behind chips, filters, and "Categorize" submenus in
// mail, calendar, contacts, and tasks; the Settings category editor; the rule
// category condition and action; and the Tasks workspace with smart lists,
// steps, the shared recurrence editor, and flagged mail.
func TestCategoriesAndTasksUIUsesSharedFlows(t *testing.T) {
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
		`href="/app/tasks" aria-label="Tasks"`, `id="tasks-workspace"`, `id="task-smart-lists"`, `id="task-quick-add"`, `id="task-form"`,
		`id="task-recurrence-editor"`, `id="task-step-list"`, `id="task-category-filter"`, `id="home-tasks"`,
		`href="/app/settings/categories"`, `id="category-settings"`, `id="calendar-category-filter"`, `id="contact-category-filter"`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("template does not contain %q", required)
		}
	}
	for _, required := range []string{
		"const categoryStore=", "'/api/v1/user/categories'", "label:'Categorize'", "action:add?'categorize':'uncategorize'",
		"actOnItems(add?'categorize':'uncategorize'", "category:mailListFilter.slice(9)", "categoryStore.chips(item.categories)",
		"categoryStore.chips(contact.categories", "categoryFiltered(allEvents)", "add_category:'Assign category'", "category:'Category'",
		"const createRecurrenceEditor=", "rruleEditor=createRecurrenceEditor({form,", "/api/v1/workspace/tasks/lists", "/complete`",
		"related_to:task.uid", "/api/v1/workspace/mail/follow-ups", "action:'complete'", "Manage categories…",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("client does not contain %q", required)
		}
	}
	for _, required := range []string{".category-chip {", ".tasks-workspace {", ".task-row {", ".task-check input:focus-visible+span", ".category-row {"} {
		if !strings.Contains(string(css), required) {
			t.Errorf("styles do not contain %q", required)
		}
	}
}

// TestFollowUpReloadsCoalesceMailEvents pins the follow-up reload policy: the
// Tasks view reloads flagged mail once per burst of item events and ignores
// deliveries, and the mail Follow up smart view is not re-queried for them.
func TestFollowUpReloadsCoalesceMailEvents(t *testing.T) {
	javascript, err := fs.ReadFile(Content, "js/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"followUpTimer=setTimeout(loadFollowUps,1500)",
		"type.startsWith('items.')&&type!=='items.delivered')scheduleFollowUps()",
		"queueWorkspaceRefresh(event.detail.type!=='items.delivered')",
		"if(mailSearch?.value||smartView&&search)await runMailSearch()",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("client does not contain %q", required)
		}
	}
	if strings.Contains(string(javascript), "else if(type.startsWith('items.'))loadFollowUps()") {
		t.Error("the Tasks view must not reload follow-ups on every item event")
	}
}
