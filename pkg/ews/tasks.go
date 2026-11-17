package ews

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"

	"github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
)

// taskData is a decoded VTODO resource.
type taskData struct {
	cal  *ical.Calendar
	todo *ical.Component
}

func parseTask(data []byte) *taskData {
	cal, err := calendar.NewDecoder(data).Decode()
	if err != nil {
		return nil
	}
	var first *ical.Component
	for _, child := range cal.Children {
		if child.Name != ical.CompToDo {
			continue
		}
		if child.Props.Get(ical.PropRecurrenceID) == nil {
			return &taskData{cal: cal, todo: child}
		}
		if first == nil {
			first = child
		}
	}
	if first == nil {
		return nil
	}
	return &taskData{cal: cal, todo: first}
}

func newTask() *taskData {
	cal := ical.NewCalendar()
	cal.Props.SetText(ical.PropVersion, "2.0")
	cal.Props.SetText(ical.PropProductID, "-//Veksel//EWS//EN")
	todo := ical.NewComponent(ical.CompToDo)
	todo.Props.SetText(ical.PropUID, newUID())
	todo.Props.SetDateTime(ical.PropCreated, time.Now().UTC())
	todo.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
	todo.Props.SetText(ical.PropStatus, calendar.TaskNeedsAction)
	cal.Children = append(cal.Children, todo)
	return &taskData{cal: cal, todo: todo}
}

func (t *taskData) encode() ([]byte, map[string]string, error) {
	calendar.AddMissingTimezones(t.cal)
	var buffer bytes.Buffer
	if err := ical.NewEncoder(&buffer).Encode(t.cal); err != nil {
		return nil, nil, err
	}
	uid, _ := t.todo.Props.Text(ical.PropUID)
	summary, _ := t.todo.Props.Text(ical.PropSummary)
	return buffer.Bytes(), map[string]string{"UID": uid, "SUMMARY": summary}, nil
}

// ewsTaskStatus maps a VTODO STATUS to the EWS TaskStatusType.
func ewsTaskStatus(status string, percent int) string {
	switch strings.ToUpper(status) {
	case calendar.TaskCompleted:
		return "Completed"
	case calendar.TaskInProcess:
		return "InProgress"
	case calendar.TaskCancelled:
		return "Deferred"
	}
	if percent > 0 {
		return "InProgress"
	}
	return "NotStarted"
}

// renderTask renders a VTODO in ItemType/TaskType schema order.
func renderTask(item model.Item, shape itemShape) string {
	task := parseTask(item.Data)
	if task == nil {
		return `<t:Task><t:ItemId Id="` + encodeID("i:", item.ID) + `" ChangeKey="` + strconv.FormatUint(item.ModSeq, 10) + `"/><t:ParentFolderId Id="` + encodeID("f:", item.FolderID) + `"/><t:ItemClass>IPM.Task</t:ItemClass></t:Task>`
	}
	props := task.todo.Props
	projected, _ := calendar.ProjectTask(item.Data)
	summary, _ := props.Text(ical.PropSummary)
	description, _ := props.Text(ical.PropDescription)
	common := itemCommon{item: item, id: encodeID("i:", item.ID), class: "IPM.Task", subject: summary, sensitivity: sensitivityName(props), body: description, categories: categoryList(props), importance: importanceName(props)}
	if reminder, err := time.Parse(time.RFC3339, projected.ReminderAt); err == nil {
		common.reminderSet, common.reminderDue = true, reminder
	}
	if created, _, _, ok := propTime(props.Get(ical.PropCreated), time.UTC); ok {
		common.created = created
	}
	if modified, _, _, ok := propTime(props.Get(ical.PropLastModified), time.UTC); ok {
		common.modified = modified
	}
	var out strings.Builder
	out.WriteString(`<t:Task>`)
	if shape.mime {
		out.WriteString(`<t:MimeContent CharacterSet="UTF-8">` + base64.StdEncoding.EncodeToString(item.Data) + `</t:MimeContent>`)
	}
	out.WriteString(common.render(shape))
	percent := 0
	if prop := props.Get(ical.PropPercentComplete); prop != nil {
		percent, _ = prop.Int()
	}
	status, _ := props.Text(ical.PropStatus)
	completed := strings.EqualFold(status, calendar.TaskCompleted) || projected.Completed
	if completed {
		percent = 100
		if at, _, _, ok := propTime(props.Get(ical.PropCompleted), time.UTC); ok {
			out.WriteString(`<t:CompleteDate>` + formatDateTime(at) + `</t:CompleteDate>`)
		}
	}
	due, _, _, dueOK := propTime(props.Get(ical.PropDue), shape.zone)
	if dueOK {
		out.WriteString(`<t:DueDate>` + formatDateTime(due) + `</t:DueDate>`)
	}
	rule := props.Get(ical.PropRecurrenceRule)
	out.WriteString(`<t:IsComplete>` + strconv.FormatBool(completed) + `</t:IsComplete><t:IsRecurring>` + strconv.FormatBool(rule != nil) + `</t:IsRecurring>`)
	out.WriteString(`<t:PercentComplete>` + strconv.Itoa(percent) + `</t:PercentComplete>`)
	start, _, startLocation, startOK := propTime(props.Get(ical.PropDateTimeStart), shape.zone)
	if rule != nil {
		reference, location := start, startLocation
		if !startOK {
			reference, location = due, shape.zone
		}
		if !reference.IsZero() {
			out.WriteString(recurrenceXML(rule.Value, reference.In(location), true, location))
		}
	}
	if startOK {
		out.WriteString(`<t:StartDate>` + formatDateTime(start) + `</t:StartDate>`)
	}
	out.WriteString(`<t:Status>` + ewsTaskStatus(status, percent) + `</t:Status></t:Task>`)
	return out.String()
}

// applyTaskFields writes the Task properties in fields to the VTODO.
func applyTaskFields(task *taskData, fields fieldChanges, scope calendarContext) error {
	props := task.todo.Props
	zone := localZone{location: scope.zone}
	if scope.info.zone != nil {
		zone = localZone{location: scope.info.zone}
	}
	setText := func(name string, element *node, value string) {
		if element == nil || strings.TrimSpace(value) == "" {
			props.Del(name)
			return
		}
		props.SetText(name, value)
	}
	if element := fields.set["Subject"]; element != nil || fields.deleted["Subject"] {
		setText(ical.PropSummary, element, element.textOrEmpty())
	}
	if element := fields.set["Body"]; element != nil {
		setText(ical.PropDescription, element, bodyText(element))
	} else if fields.deleted["Body"] {
		props.Del(ical.PropDescription)
	}
	if element := fields.set["Sensitivity"]; element != nil {
		setSensitivity(props, element.Text)
	}
	if element := fields.set["Importance"]; element != nil {
		setImportance(props, element.Text)
	}
	if element := fields.set["Categories"]; element != nil {
		setCategories(props, stringList(element))
	} else if fields.deleted["Categories"] {
		props.Del(ical.PropCategories)
	}
	day := func(element string, name string) error {
		if value := fields.set[element]; value != nil {
			parsed, ok := parseDateTime(value.Text, zone)
			if !ok {
				return errors.New("invalid " + element)
			}
			local := parsed.In(zone.location)
			props.SetDate(name, time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC))
		} else if fields.deleted[element] {
			props.Del(name)
		}
		return nil
	}
	if err := day("DueDate", ical.PropDue); err != nil {
		return err
	}
	if err := day("StartDate", ical.PropDateTimeStart); err != nil {
		return err
	}
	now := time.Now().UTC()
	status := ""
	if element := fields.set["Status"]; element != nil {
		status = map[string]string{"notstarted": calendar.TaskNeedsAction, "inprogress": calendar.TaskInProcess, "waitingonothers": calendar.TaskInProcess, "completed": calendar.TaskCompleted, "deferred": calendar.TaskCancelled}[strings.ToLower(strings.TrimSpace(element.Text))]
	}
	if element := fields.set["IsComplete"]; element != nil && status == "" {
		status = calendar.TaskNeedsAction
		if parseBool(element.Text) {
			status = calendar.TaskCompleted
		}
	}
	if element := fields.set["PercentComplete"]; element != nil {
		percent, err := strconv.ParseFloat(strings.TrimSpace(element.Text), 64)
		if err != nil || percent < 0 || percent > 100 {
			return errors.New("PercentComplete must be between 0 and 100")
		}
		prop := ical.NewProp(ical.PropPercentComplete)
		prop.Value = strconv.Itoa(int(percent))
		props.Set(prop)
		if status == "" && percent >= 100 {
			status = calendar.TaskCompleted
		}
	}
	switch status {
	case calendar.TaskCompleted:
		props.SetText(ical.PropStatus, calendar.TaskCompleted)
		percent := ical.NewProp(ical.PropPercentComplete)
		percent.Value = "100"
		props.Set(percent)
		if props.Get(ical.PropCompleted) == nil {
			props.SetDateTime(ical.PropCompleted, now)
		}
	case calendar.TaskInProcess, calendar.TaskCancelled, calendar.TaskNeedsAction:
		props.SetText(ical.PropStatus, status)
		props.Del(ical.PropCompleted)
		if status == calendar.TaskNeedsAction && fields.set["PercentComplete"] == nil {
			props.Del(ical.PropPercentComplete)
		}
	}
	if element := fields.set["CompleteDate"]; element != nil {
		if parsed, ok := parseDateTime(element.Text, zone); ok {
			props.SetDateTime(ical.PropCompleted, parsed.UTC())
		}
	}
	if element := fields.set["Recurrence"]; element != nil {
		rule, err := ruleFromRecurrence(element, true, zone.location)
		if err != nil {
			return err
		}
		prop := ical.NewProp(ical.PropRecurrenceRule)
		prop.Value = rule
		props.Set(prop)
	} else if fields.deleted["Recurrence"] {
		props.Del(ical.PropRecurrenceRule)
	}
	if fields.has("ReminderIsSet") || fields.has("ReminderDueBy") {
		enabled := len(alarms(task.todo)) > 0
		if element := fields.set["ReminderIsSet"]; element != nil {
			enabled = parseBool(element.Text)
		} else if fields.deleted["ReminderIsSet"] {
			enabled = false
		}
		var at time.Time
		if projected, err := calendar.ProjectTask(mustEncodeTask(task)); err == nil {
			at, _ = time.Parse(time.RFC3339, projected.ReminderAt)
		}
		if element := fields.set["ReminderDueBy"]; element != nil {
			if parsed, ok := parseDateTime(element.Text, zone); ok {
				at = parsed
			}
		}
		removeAlarms(task.todo)
		if enabled && !at.IsZero() {
			alarm := ical.NewComponent(ical.CompAlarm)
			alarm.Props.SetText(ical.PropAction, "DISPLAY")
			alarm.Props.SetText(ical.PropDescription, "Reminder")
			trigger := ical.NewProp(ical.PropTrigger)
			trigger.SetDateTime(at.UTC())
			alarm.Props.Set(trigger)
			task.todo.Children = append(task.todo.Children, alarm)
		}
	}
	if text, _ := props.Text(ical.PropSummary); strings.TrimSpace(text) == "" {
		props.SetText(ical.PropSummary, "Untitled task")
	}
	props.SetDateTime(ical.PropDateTimeStamp, now)
	props.SetDateTime(ical.PropLastModified, now)
	return nil
}

func alarms(component *ical.Component) []*ical.Component {
	var result []*ical.Component
	for _, child := range component.Children {
		if child.Name == ical.CompAlarm {
			result = append(result, child)
		}
	}
	return result
}

func removeAlarms(component *ical.Component) {
	children := component.Children[:0]
	for _, child := range component.Children {
		if child.Name != ical.CompAlarm {
			children = append(children, child)
		}
	}
	component.Children = children
}

func mustEncodeTask(task *taskData) []byte {
	var buffer bytes.Buffer
	_ = ical.NewEncoder(&buffer).Encode(task.cal)
	return buffer.Bytes()
}
