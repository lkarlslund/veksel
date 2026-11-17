package calendar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
)

// Task status values (RFC 5545 3.8.1.11 for VTODO).
const (
	TaskNeedsAction = "NEEDS-ACTION"
	TaskInProcess   = "IN-PROCESS"
	TaskCompleted   = "COMPLETED"
	TaskCancelled   = "CANCELLED"
)

// Task is the editor projection of one VTODO. Due and Start are a date
// (YYYY-MM-DD) for date-only values or an RFC 3339 timestamp.
type Task struct {
	UID         string   `json:"uid"`
	Summary     string   `json:"summary"`
	Description string   `json:"description,omitempty"`
	Status      string   `json:"status"`
	Completed   bool     `json:"completed"`
	CompletedAt string   `json:"completed_at,omitempty"`
	Due         string   `json:"due,omitempty"`
	Start       string   `json:"start,omitempty"`
	Priority    int      `json:"priority,omitempty"`
	Percent     int      `json:"percent_complete,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	// RelatedTo is the parent task's UID (RELATED-TO;RELTYPE=PARENT).
	RelatedTo  string `json:"related_to,omitempty"`
	Recurrence string `json:"recurrence"`
	RRule      string `json:"rrule,omitempty"`
	// ReminderAt is the first reminder's absolute time.
	ReminderAt string `json:"reminder_at,omitempty"`
	Created    string `json:"created,omitempty"`
	Modified   string `json:"modified,omitempty"`
}

// TaskUpdate edits a VTODO. Nil fields keep the stored value; an empty
// string clears an optional value.
type TaskUpdate struct {
	Summary     *string
	Description *string
	Due         *string
	Start       *string
	Priority    *int
	Categories  *[]string
	RelatedTo   *string
	Recurrence  *string
	ReminderAt  *string
	Status      *string
	Timezone    string
}

// IsTask reports whether an iCalendar payload carries a VTODO.
func IsTask(data []byte) bool {
	return bytes.Contains(bytes.ToUpper(data), []byte("BEGIN:VTODO"))
}

func decodeAny(data []byte) (*ical.Calendar, error) {
	cal, err := NewDecoder(data).Decode()
	if err != nil {
		return nil, fmt.Errorf("decode iCalendar: %w", err)
	}
	return cal, nil
}

// masterTodo returns the VTODO without a RECURRENCE-ID, or the first one.
func masterTodo(cal *ical.Calendar) *ical.Component {
	var first *ical.Component
	for _, child := range cal.Children {
		if child.Name != ical.CompToDo {
			continue
		}
		if child.Props.Get(ical.PropRecurrenceID) == nil {
			return child
		}
		if first == nil {
			first = child
		}
	}
	return first
}

// ProjectTask returns the editor view of a VTODO payload.
func ProjectTask(data []byte) (Task, error) {
	cal, err := decodeAny(data)
	if err != nil {
		return Task{}, err
	}
	todo := masterTodo(cal)
	if todo == nil {
		return Task{}, errors.New("iCalendar item contains no task")
	}
	return projectTodo(todo), nil
}

func projectTodo(todo *ical.Component) Task {
	props := todo.Props
	task := Task{Recurrence: "none"}
	task.UID, _ = props.Text(ical.PropUID)
	task.Summary, _ = props.Text(ical.PropSummary)
	task.Description, _ = props.Text(ical.PropDescription)
	task.Status = TaskNeedsAction
	if prop := props.Get(ical.PropStatus); prop != nil && strings.TrimSpace(prop.Value) != "" {
		task.Status = strings.ToUpper(strings.TrimSpace(prop.Value))
	}
	if prop := props.Get(ical.PropCompleted); prop != nil {
		if value, err := prop.DateTime(time.UTC); err == nil {
			task.CompletedAt = value.UTC().Format(time.RFC3339)
		}
	}
	task.Completed = task.Status == TaskCompleted || (task.CompletedAt != "" && task.Status != TaskNeedsAction && task.Status != TaskInProcess)
	if task.Completed {
		task.Status = TaskCompleted
	}
	task.Due = propTime(props.Get(ical.PropDue))
	task.Start = propTime(props.Get(ical.PropDateTimeStart))
	if prop := props.Get(ical.PropPriority); prop != nil {
		task.Priority, _ = prop.Int()
	}
	if prop := props.Get(ical.PropPercentComplete); prop != nil {
		task.Percent, _ = prop.Int()
	}
	for _, category := range props.Values(ical.PropCategories) {
		values, _ := category.TextList()
		task.Categories = append(task.Categories, values...)
	}
	for _, related := range props.Values(ical.PropRelatedTo) {
		if relType := strings.ToUpper(related.Params.Get(ical.ParamRelationshipType)); relType == "" || relType == "PARENT" {
			task.RelatedTo = strings.TrimSpace(related.Value)
			break
		}
	}
	if rule := props.Get(ical.PropRecurrenceRule); rule != nil {
		task.RRule = rule.Value
		task.Recurrence = recurrencePreset(rule.Value)
	}
	task.ReminderAt = todoReminder(todo)
	if prop := props.Get(ical.PropCreated); prop != nil {
		if value, err := prop.DateTime(time.UTC); err == nil {
			task.Created = value.UTC().Format(time.RFC3339)
		}
	}
	if prop := props.Get(ical.PropLastModified); prop != nil {
		if value, err := prop.DateTime(time.UTC); err == nil {
			task.Modified = value.UTC().Format(time.RFC3339)
		}
	}
	return task
}

func recurrencePreset(rule string) string {
	switch strings.ToUpper(rule) {
	case "FREQ=DAILY":
		return "daily"
	case "FREQ=WEEKLY":
		return "weekly"
	case "FREQ=MONTHLY":
		return "monthly"
	case "FREQ=YEARLY":
		return "yearly"
	}
	return "custom"
}

func propTime(prop *ical.Prop) string {
	if prop == nil {
		return ""
	}
	value, err := prop.DateTime(time.Local)
	if err != nil {
		return ""
	}
	if prop.ValueType() == ical.ValueDate || len(prop.Value) == len("20060102") {
		return value.Format(time.DateOnly)
	}
	return value.Format(time.RFC3339)
}

// todoReminder resolves the first VALARM to an absolute time: a DATE-TIME
// trigger directly, a duration relative to DTSTART, or to DUE for
// RELATED=END or a task without a start.
func todoReminder(todo *ical.Component) string {
	for _, child := range todo.Children {
		if child.Name != ical.CompAlarm {
			continue
		}
		trigger := child.Props.Get(ical.PropTrigger)
		if trigger == nil {
			continue
		}
		if trigger.ValueType() == ical.ValueDateTime {
			if value, err := trigger.DateTime(time.UTC); err == nil {
				return value.UTC().Format(time.RFC3339)
			}
			continue
		}
		offset, err := trigger.Duration()
		if err != nil {
			continue
		}
		anchor := todo.Props.Get(ical.PropDateTimeStart)
		if strings.EqualFold(trigger.Params.Get(ical.ParamRelated), "END") || anchor == nil {
			anchor = todo.Props.Get(ical.PropDue)
		}
		if anchor == nil {
			continue
		}
		if base, err := anchor.DateTime(time.Local); err == nil {
			return base.Add(offset).UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// CreateTask builds a new VTODO payload.
func CreateTask(update TaskUpdate, uid string, now time.Time) ([]byte, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//Veksel//Workspace//EN")
	todo := ical.NewComponent(ical.CompToDo)
	todo.Props.SetText(ical.PropUID, uid)
	todo.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	todo.Props.SetDateTime(ical.PropCreated, now.UTC())
	cal.Children = append(cal.Children, todo)
	if update.Status == nil {
		status := TaskNeedsAction
		update.Status = &status
	}
	if err := applyTask(todo, update, now); err != nil {
		return nil, err
	}
	return encodeCalendar(cal)
}

// UpdateTask edits the master VTODO of a payload.
func UpdateTask(data []byte, update TaskUpdate, now time.Time) ([]byte, error) {
	cal, err := decodeAny(data)
	if err != nil {
		return nil, err
	}
	todo := masterTodo(cal)
	if todo == nil {
		return nil, errors.New("iCalendar item contains no task")
	}
	if err := applyTask(todo, update, now); err != nil {
		return nil, err
	}
	return encodeCalendar(cal)
}

func encodeCalendar(cal *ical.Calendar) ([]byte, error) {
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, fmt.Errorf("encode iCalendar: %w", err)
	}
	return buf.Bytes(), nil
}

func applyTask(todo *ical.Component, update TaskUpdate, now time.Time) error {
	props := todo.Props
	loc := time.Local
	if update.Timezone != "" {
		var err error
		if loc, err = time.LoadLocation(update.Timezone); err != nil {
			return errors.New("timezone is not recognized")
		}
	}
	if update.Summary != nil {
		summary := strings.TrimSpace(*update.Summary)
		if summary == "" || len(summary) > 1000 {
			return errors.New("a task title of at most 1000 bytes is required")
		}
		props.SetText(ical.PropSummary, summary)
	} else if text, _ := props.Text(ical.PropSummary); strings.TrimSpace(text) == "" {
		return errors.New("a task title is required")
	}
	if update.Description != nil {
		if len(*update.Description) > 64<<10 {
			return errors.New("task notes cannot exceed 64 KiB")
		}
		setOptionalText(props, ical.PropDescription, strings.TrimRight(*update.Description, " \t\r\n"))
	}
	for _, field := range []struct {
		name  string
		value *string
	}{{ical.PropDue, update.Due}, {ical.PropDateTimeStart, update.Start}} {
		if field.value == nil {
			continue
		}
		if err := setTaskTime(props, field.name, *field.value, loc); err != nil {
			return err
		}
	}
	if start, due := props.Get(ical.PropDateTimeStart), props.Get(ical.PropDue); start != nil && due != nil {
		startTime, startErr := start.DateTime(time.Local)
		dueTime, dueErr := due.DateTime(time.Local)
		if startErr == nil && dueErr == nil && dueTime.Before(startTime) {
			return errors.New("the due date cannot be before the start date")
		}
	}
	if update.Priority != nil {
		if *update.Priority < 0 || *update.Priority > 9 {
			return errors.New("priority must be between 0 and 9")
		}
		if *update.Priority == 0 {
			props.Del(ical.PropPriority)
		} else {
			prop := ical.NewProp(ical.PropPriority)
			prop.Value = strconv.Itoa(*update.Priority)
			props.Set(prop)
		}
	}
	if update.Categories != nil {
		setCategories(props, *update.Categories)
	}
	if update.RelatedTo != nil {
		related := strings.TrimSpace(*update.RelatedTo)
		kept := slices.DeleteFunc(slices.Clone(props.Values(ical.PropRelatedTo)), func(prop ical.Prop) bool {
			relType := strings.ToUpper(prop.Params.Get(ical.ParamRelationshipType))
			return relType == "" || relType == "PARENT"
		})
		if uid, _ := props.Text(ical.PropUID); related != "" && related == uid {
			return errors.New("a task cannot be its own parent")
		}
		if related != "" {
			prop := ical.NewProp(ical.PropRelatedTo)
			prop.Value = related
			prop.Params.Set(ical.ParamRelationshipType, "PARENT")
			kept = append(kept, *prop)
		}
		if len(kept) == 0 {
			props.Del(ical.PropRelatedTo)
		} else {
			props[ical.PropRelatedTo] = kept
		}
	}
	if update.Recurrence != nil {
		switch preset := strings.ToLower(strings.TrimSpace(*update.Recurrence)); preset {
		case "", "none":
			props.Del(ical.PropRecurrenceRule)
		default:
			rule := "FREQ=" + strings.ToUpper(preset)
			if preset != "daily" && preset != "weekly" && preset != "monthly" && preset != "yearly" {
				var err error
				if rule, err = normalizeRRule(*update.Recurrence); err != nil {
					return err
				}
			}
			prop := ical.NewProp(ical.PropRecurrenceRule)
			prop.Value = rule
			props.Set(prop)
		}
	}
	if props.Get(ical.PropRecurrenceRule) != nil && props.Get(ical.PropDue) == nil && props.Get(ical.PropDateTimeStart) == nil {
		return errors.New("a repeating task needs a due or start date")
	}
	if update.ReminderAt != nil {
		children := todo.Children[:0]
		for _, child := range todo.Children {
			if child.Name != ical.CompAlarm {
				children = append(children, child)
			}
		}
		todo.Children = children
		if value := strings.TrimSpace(*update.ReminderAt); value != "" {
			at, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return errors.New("reminder_at must be an RFC 3339 timestamp")
			}
			alarm := ical.NewComponent(ical.CompAlarm)
			alarm.Props.SetText(ical.PropAction, "DISPLAY")
			trigger := ical.NewProp(ical.PropTrigger)
			trigger.SetDateTime(at.UTC())
			alarm.Props.Set(trigger)
			alarm.Props.SetText(ical.PropDescription, "Reminder")
			todo.Children = append(todo.Children, alarm)
		}
	}
	if update.Status != nil {
		setTaskStatus(props, *update.Status, now)
	}
	props.SetDateTime(ical.PropLastModified, now.UTC())
	props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	return nil
}

func setTaskTime(props ical.Props, name, value string, loc *time.Location) error {
	value = strings.TrimSpace(value)
	if value == "" {
		props.Del(name)
		return nil
	}
	if date, err := time.ParseInLocation(time.DateOnly, value, loc); err == nil {
		props.SetDate(name, date)
		return nil
	}
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("%s must be YYYY-MM-DD or an RFC 3339 timestamp", strings.ToLower(name))
	}
	props.SetDateTime(name, at.UTC())
	return nil
}

func setTaskStatus(props ical.Props, status string, now time.Time) {
	status = strings.ToUpper(strings.TrimSpace(status))
	switch status {
	case TaskCompleted:
		props.SetText(ical.PropStatus, TaskCompleted)
		if props.Get(ical.PropCompleted) == nil {
			props.SetDateTime(ical.PropCompleted, now.UTC())
		}
		percent := ical.NewProp(ical.PropPercentComplete)
		percent.Value = "100"
		props.Set(percent)
	case TaskInProcess, TaskCancelled:
		props.SetText(ical.PropStatus, status)
		props.Del(ical.PropCompleted)
	default:
		props.SetText(ical.PropStatus, TaskNeedsAction)
		props.Del(ical.PropCompleted)
		props.Del(ical.PropPercentComplete)
	}
}

// CompleteTask marks the master VTODO complete or open again. Completing a
// repeating task records the finished occurrence as a separate completed
// task (returned as done, with doneUID) and moves the series to its next
// occurrence, keeping the series UID so clients and subtasks stay linked.
// done is nil when nothing is split off.
func CompleteTask(data []byte, completed bool, doneUID string, now time.Time) (updated, done []byte, err error) {
	cal, err := decodeAny(data)
	if err != nil {
		return nil, nil, err
	}
	todo := masterTodo(cal)
	if todo == nil {
		return nil, nil, errors.New("iCalendar item contains no task")
	}
	if !completed {
		setTaskStatus(todo.Props, TaskNeedsAction, now)
		todo.Props.SetDateTime(ical.PropLastModified, now.UTC())
		updated, err = encodeCalendar(cal)
		return updated, nil, err
	}
	shift, ok := nextOccurrenceShift(todo)
	if !ok {
		setTaskStatus(todo.Props, TaskCompleted, now)
		todo.Props.SetDateTime(ical.PropLastModified, now.UTC())
		updated, err = encodeCalendar(cal)
		return updated, nil, err
	}
	finished := ical.NewCalendar()
	finished.Props = CloneProps(cal.Props)
	record := ical.NewComponent(ical.CompToDo)
	record.Props = CloneProps(todo.Props)
	record.Props.Del(ical.PropRecurrenceRule)
	record.Props.Del(ical.PropRecurrenceDates)
	record.Props.Del(ical.PropExceptionDates)
	record.Props.SetText(ical.PropUID, doneUID)
	record.Props.SetDateTime(ical.PropCreated, now.UTC())
	setTaskStatus(record.Props, TaskCompleted, now)
	record.Props.SetDateTime(ical.PropLastModified, now.UTC())
	finished.Children = append(finished.Children, record)
	if done, err = encodeCalendar(finished); err != nil {
		return nil, nil, err
	}
	for _, name := range []string{ical.PropDateTimeStart, ical.PropDue} {
		shiftTime(todo.Props, name, shift)
	}
	// Absolute reminders move with the series; relative ones follow it.
	for _, child := range todo.Children {
		if trigger := child.Props.Get(ical.PropTrigger); child.Name == ical.CompAlarm && trigger != nil && trigger.ValueType() == ical.ValueDateTime {
			if at, err := trigger.DateTime(time.UTC); err == nil {
				trigger.SetDateTime(at.Add(shift).UTC())
			}
		}
	}
	if option, _ := todo.Props.RecurrenceRule(); option != nil && option.Count > 0 {
		rule := todo.Props.Get(ical.PropRecurrenceRule)
		rule.Value = replaceRuleCount(rule.Value, option.Count-1)
	}
	setTaskStatus(todo.Props, TaskNeedsAction, now)
	todo.Props.SetDateTime(ical.PropLastModified, now.UTC())
	updated, err = encodeCalendar(cal)
	return updated, done, err
}

// nextOccurrenceShift returns how far the series moves to reach its next
// occurrence, anchored on DTSTART or, when absent, on DUE.
func nextOccurrenceShift(todo *ical.Component) (time.Duration, bool) {
	if todo.Props.Get(ical.PropRecurrenceRule) == nil {
		return 0, false
	}
	if option, err := todo.Props.RecurrenceRule(); err != nil || option == nil || option.Count == 1 {
		return 0, false
	}
	anchor := todo.Props.Get(ical.PropDateTimeStart)
	if anchor == nil {
		anchor = todo.Props.Get(ical.PropDue)
	}
	if anchor == nil {
		return 0, false
	}
	probe := ical.NewComponent(ical.CompToDo)
	probe.Props = CloneProps(todo.Props)
	probe.Props.Del(ical.PropDateTimeStart)
	probe.Props[ical.PropDateTimeStart] = []ical.Prop{*anchor}
	base, err := anchor.DateTime(time.Local)
	if err != nil {
		return 0, false
	}
	set, err := probe.RecurrenceSet(time.Local)
	if err != nil || set == nil {
		return 0, false
	}
	next := set.After(base, false)
	if next.IsZero() || !next.After(base) {
		return 0, false
	}
	return next.Sub(base), true
}

func shiftTime(props ical.Props, name string, shift time.Duration) {
	prop := props.Get(name)
	if prop == nil {
		return
	}
	value, err := prop.DateTime(time.Local)
	if err != nil {
		return
	}
	if prop.ValueType() == ical.ValueDate || len(prop.Value) == len("20060102") {
		days := int((shift + 12*time.Hour) / (24 * time.Hour))
		prop.SetDate(value.AddDate(0, 0, days))
		return
	}
	next := value.Add(shift)
	// Whole-day steps keep the wall-clock time across daylight saving
	// changes in the property's own zone.
	if days := int((shift + 12*time.Hour) / (24 * time.Hour)); days > 0 && (shift-time.Duration(days)*24*time.Hour).Abs() <= time.Hour {
		next = value.AddDate(0, 0, days)
	}
	if strings.HasSuffix(prop.Value, "Z") {
		prop.SetDateTime(next.UTC())
		return
	}
	// Zoned and floating values keep their TZID (or none) and local form.
	prop.Value = next.Format("20060102T150405")
}

func replaceRuleCount(rule string, count int) string {
	parts := strings.Split(rule, ";")
	for index, part := range parts {
		if strings.HasPrefix(strings.ToUpper(part), "COUNT=") {
			parts[index] = "COUNT=" + strconv.Itoa(count)
		}
	}
	return strings.Join(parts, ";")
}

// ItemCategories returns the CATEGORIES of the master VEVENT or VTODO.
func ItemCategories(data []byte) []string {
	cal, err := decodeAny(data)
	if err != nil {
		return nil
	}
	component := masterTodo(cal)
	if component == nil {
		events := cal.Events()
		if len(events) == 0 {
			return nil
		}
		component = MasterEvent(events).Component
	}
	var categories []string
	for _, category := range component.Props.Values(ical.PropCategories) {
		values, _ := category.TextList()
		categories = append(categories, values...)
	}
	return categories
}

// ReplaceCategories sets CATEGORIES on every VEVENT and VTODO of a payload,
// recurrence overrides included, leaving other properties unchanged.
func ReplaceCategories(data []byte, categories []string) ([]byte, error) {
	cal, err := decodeAny(data)
	if err != nil {
		return nil, err
	}
	found := false
	for _, child := range cal.Children {
		if child.Name == ical.CompEvent || child.Name == ical.CompToDo {
			setCategories(child.Props, categories)
			found = true
		}
	}
	if !found {
		return nil, errors.New("iCalendar item contains no event or task")
	}
	return encodeCalendar(cal)
}
