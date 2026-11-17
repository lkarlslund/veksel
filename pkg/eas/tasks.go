package eas

import (
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

// taskDay parses a Task date (YYYY-MM-DD or RFC 3339) as a calendar day.
func taskDay(value string, location *time.Location) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	if parsed, err := time.ParseInLocation("2006-01-02", value, location); err == nil {
		return parsed, true
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		local := parsed.In(location)
		return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location), true
	}
	return time.Time{}, false
}

// taskImportance maps RFC 5545 PRIORITY (1 high .. 9 low) to EAS 0-2.
func taskImportance(priority int) string {
	switch {
	case priority >= 1 && priority <= 4:
		return "2"
	case priority >= 6:
		return "0"
	}
	return "1"
}

func (h *Handler) taskData(command *commandContext, item model.Item, options SyncOptions) *Node {
	data := E(0, "ApplicationData")
	task, err := calendar.ProjectTask(item.Data)
	if err != nil {
		return data
	}
	location := h.userLocation(command)
	data.Children = append(data.Children, textBody(task.Description, options), T(9, "Subject", task.Summary), T(9, "Importance", taskImportance(task.Priority)))
	// Each date is sent twice: in UTC and as the user's local day.
	dates := func(utcTag, localTag string, day time.Time) {
		data.Children = append(data.Children,
			T(9, utcTag, day.UTC().Format(easDateFormat)),
			T(9, localTag, time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC).Format(easDateFormat)))
	}
	if start, ok := taskDay(task.Start, location); ok {
		dates("UtcStartDate", "StartDate", start)
	}
	if due, ok := taskDay(task.Due, location); ok {
		dates("UtcDueDate", "DueDate", due)
	}
	if len(task.Categories) > 0 {
		node := E(9, "Categories")
		for _, category := range task.Categories {
			node.Children = append(node.Children, T(9, "Category", category))
		}
		data.Children = append(data.Children, node)
	}
	if task.RRule != "" {
		reference, ok := taskDay(firstNonEmpty(task.Start, task.Due), location)
		if !ok {
			reference = time.Now().In(location)
		}
		if recurrence := recurrenceNode(9, task.RRule, reference); recurrence != nil {
			data.Children = append(data.Children, recurrence)
		}
	}
	data.Children = append(data.Children, T(9, "Complete", boolNumber(task.Completed)))
	if task.Completed {
		completed := time.Now().UTC()
		if parsed, err := time.Parse(time.RFC3339, task.CompletedAt); err == nil {
			completed = parsed
		}
		data.Children = append(data.Children, T(9, "DateCompleted", completed.UTC().Format(easDateFormat)))
	}
	data.Children = append(data.Children, T(9, "Sensitivity", "0"))
	if reminder, err := time.Parse(time.RFC3339, task.ReminderAt); err == nil {
		data.Children = append(data.Children, T(9, "ReminderTime", reminder.UTC().Format(easDateFormat)), T(9, "ReminderSet", "1"))
	} else {
		data.Children = append(data.Children, T(9, "ReminderSet", "0"))
	}
	return data
}

// taskFromEAS builds or updates a VTODO from task ApplicationData.
func (h *Handler) taskFromEAS(command *commandContext, existing []byte, data *Node) ([]byte, map[string]string, error) {
	location := h.userLocation(command)
	update := calendar.TaskUpdate{Timezone: location.String()}
	if location == time.Local {
		update.Timezone = ""
	}
	summary := strings.TrimSpace(childText(data, "Subject"))
	if summary == "" {
		summary = "Untitled task"
	}
	update.Summary = &summary
	if body := data.Child("Body"); body != nil {
		description := clientBodyText(body)
		update.Description = &description
	} else if existing == nil {
		empty := ""
		update.Description = &empty
	}
	day := func(localTag, utcTag string) *string {
		value := ""
		if local, ok := parseEASTime(childText(data, localTag)); ok {
			value = local.Format("2006-01-02")
		} else if utc, ok := parseEASTime(childText(data, utcTag)); ok {
			value = utc.In(location).Format("2006-01-02")
		}
		return &value
	}
	update.Start = day("StartDate", "UtcStartDate")
	update.Due = day("DueDate", "UtcDueDate")
	if *update.Start != "" && *update.Due != "" && *update.Due < *update.Start {
		update.Start = update.Due
	}
	priority := 0
	switch childText(data, "Importance") {
	case "0":
		priority = 9
	case "2":
		priority = 1
	}
	update.Priority = &priority
	categories := []string{}
	if node := data.Child("Categories"); node != nil {
		for _, category := range node.Children {
			if value := strings.TrimSpace(nodeValue(category)); value != "" {
				categories = append(categories, value)
			}
		}
	}
	update.Categories = &categories
	rule := ""
	if recurrence := data.Child("Recurrence"); recurrence != nil {
		rule = ruleFromEAS(recurrence, false, utcTimeZone)
	}
	update.Recurrence = &rule
	reminder := ""
	if childText(data, "ReminderSet") == "1" {
		if value, ok := parseEASTime(childText(data, "ReminderTime")); ok {
			reminder = value.Format(time.RFC3339)
		}
	}
	update.ReminderAt = &reminder
	status := calendar.TaskNeedsAction
	if childText(data, "Complete") == "1" {
		status = calendar.TaskCompleted
	}
	update.Status = &status
	now := time.Now().UTC()
	var output []byte
	var err error
	if existing == nil {
		output, err = calendar.CreateTask(update, newUID(), now)
	} else {
		output, err = calendar.UpdateTask(existing, update, now)
	}
	if err != nil {
		return nil, nil, err
	}
	task, _ := calendar.ProjectTask(output)
	return output, map[string]string{"UID": task.UID, "SUMMARY": task.Summary}, nil
}
