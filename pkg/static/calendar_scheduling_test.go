package static

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCalendarSchedulingUIUsesSharedFlows pins the UX-OWA-006 surfaces: the
// attendee editor, reminders with the notification permission flow, invitation
// answers with comments and proposals, the scheduling assistant over free/busy,
// work week and custom recurrence (shared with tasks), category colors, and
// print styles.
func TestCalendarSchedulingUIUsesSharedFlows(t *testing.T) {
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
		`id="calendar-attendee-input" list="calendar-attendee-options"`, `id="calendar-find-time"`, `id="calendar-recurrence-editor"`,
		`<option value="custom">Custom…</option>`, `name="reminder"`, `<option value="1440">1 day before</option>`, `name="categories"`,
		`data-view="workweek"`, `id="calendar-assistant-dialog"`, `id="calendar-options-dialog"`, `id="calendar-print"`,
		`id="calendar-notification-enable"`, `id="calendar-folder-options"`,
	} {
		if !strings.Contains(string(template), required) {
			t.Errorf("calendar template does not contain %q", required)
		}
	}
	for _, required := range []string{
		// One shared answer dialog for the mail card and the event detail.
		"const askInvitationAnswer=", "data-invitation-more=\"propose\"", "data-invitation-proposal=\"accept\"", "propose_start:from.toISOString()",
		"data-calendar-respond-more=\"propose\"", "data-proposal-decision=\"accept\"", "'/respond'", "'/proposal'",
		// Reminders: server-refreshed schedule delivered through the shared notification module, session snooze.
		"const startReminderSchedule=", "notifier.notify({kind:'meeting'", "Notification.requestPermission()", "notificationButton.onclick=async()=>{await notifier.request();notificationStatus()}", "sessionStorage.getItem('veksel.reminders')", "label:'Snooze 5 min'",
		// Editor values are only sent when changed so existing data round-trips.
		"const eventSchedulingPayload=", "attendeeKey(editorAttendees)!==editorAttendeesOriginal", "getPeopleSuggestions(query,attendeeSuggestController.signal)",
		"const createRecurrenceEditor=", "rruleEditor.dirty||!rruleEditor.original", "kept unless you change this rule",
		// Scheduling assistant over free/busy only.
		"/api/v1/workspace/calendar/freebusy?", "data-assistant-suggestion", "Every required attendee is free",
		// Work week and configurable week start; category colors.
		"view==='workweek'", "calendarPrefs().weekStart", "category_colors", "categoryColor=event=>",
		"window.print()",
	} {
		if !strings.Contains(string(javascript), required) {
			t.Errorf("calendar scheduling client does not contain %q", required)
		}
	}
	for _, required := range []string{
		".calendar-assistant-table {", ".calendar-attendee-chip {", ".calendar-weekday-toggle input:focus-visible+span", ".calendar-day-column.working-day::before",
		".invitation-answer-dialog {", "@media print{", `body[data-page="calendar"] .calendar-agenda-list-day { break-inside:avoid; }`,
	} {
		if !strings.Contains(string(css), required) {
			t.Errorf("calendar scheduling styles do not contain %q", required)
		}
	}
}
