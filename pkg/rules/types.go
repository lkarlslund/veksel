// Package rules implements protocol-neutral automation over FolderSpace items.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/category"
	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	CurrentVersion        = 1
	MaxRules              = 256
	MaxConditions         = 32
	MaxActions            = 16
	MaxTextBytes          = 2048
	MaxPreviewItems       = 50
	MaxPreviewExamined    = 1000
	MaxEvidencePerOwner   = 500
	MaxRunHistoryPerOwner = 100
)

type MatchMode string

const (
	MatchAll MatchMode = "all"
	MatchAny MatchMode = "any"
)

type Field string

const (
	FieldName         Field = "name"
	FieldContent      Field = "content"
	FieldContentType  Field = "content_type"
	FieldSize         Field = "size"
	FieldDate         Field = "date"
	FieldFlag         Field = "flag"
	FieldTag          Field = "tag"
	FieldFrom         Field = "from"
	FieldTo           Field = "to"
	FieldSubject      Field = "subject"
	FieldSummary      Field = "summary"
	FieldOrganizer    Field = "organizer"
	FieldAttendee     Field = "attendee"
	FieldEmail        Field = "email"
	FieldOrganization Field = "organization"
	// FieldCategory matches master categories: message keywords and the
	// CATEGORIES of events, tasks, and contacts.
	FieldCategory Field = "category"
)

type Operator string

const (
	OperatorEquals    Operator = "equals"
	OperatorNotEquals Operator = "not_equals"
	OperatorContains  Operator = "contains"
	OperatorPrefix    Operator = "prefix"
	OperatorSuffix    Operator = "suffix"
	OperatorExists    Operator = "exists"
	OperatorNotExists Operator = "not_exists"
	OperatorBefore    Operator = "before"
	OperatorAfter     Operator = "after"
	OperatorGreater   Operator = "greater_than"
	OperatorLess      Operator = "less_than"
)

type ActionType string

const (
	ActionMove       ActionType = "move"
	ActionCopy       ActionType = "copy"
	ActionAddFlag    ActionType = "add_flag"
	ActionRemoveFlag ActionType = "remove_flag"
	ActionAddTag     ActionType = "add_tag"
	ActionRemoveTag  ActionType = "remove_tag"
	ActionTrash      ActionType = "trash"
	// ActionAddCategory and ActionRemoveCategory assign a master category
	// in the item's own representation (keyword or CATEGORIES).
	ActionAddCategory    ActionType = "add_category"
	ActionRemoveCategory ActionType = "remove_category"
)

type Condition struct {
	Field         Field    `json:"field"`
	Header        string   `json:"header,omitempty"`
	Operator      Operator `json:"operator"`
	Value         string   `json:"value,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	Negate        bool     `json:"negate,omitempty"`
}

type Action struct {
	Type                ActionType `json:"type"`
	DestinationFolderID string     `json:"destination_folder_id,omitempty"`
	Value               string     `json:"value,omitempty"`
}

type Rule struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Description     string             `json:"description,omitempty"`
	Enabled         bool               `json:"enabled"`
	Priority        int                `json:"priority"`
	SourceFolderIDs []string           `json:"source_folder_ids,omitempty"`
	FolderTypes     []model.FolderType `json:"folder_types,omitempty"`
	Match           MatchMode          `json:"match"`
	Conditions      []Condition        `json:"conditions,omitempty"`
	Actions         []Action           `json:"actions"`
	Stop            bool               `json:"stop"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

type Document struct {
	Version   int       `json:"version"`
	OwnerID   string    `json:"owner_id"`
	Revision  string    `json:"revision"`
	Rules     []Rule    `json:"rules"`
	UpdatedAt time.Time `json:"updated_at"`
}

type MatchResult struct {
	Matched    bool                  `json:"matched"`
	Conditions []ConditionEvaluation `json:"conditions,omitempty"`
}

type ConditionEvaluation struct {
	Field    Field    `json:"field"`
	Operator Operator `json:"operator"`
	Matched  bool     `json:"matched"`
}

type ActionEvidence struct {
	Type                ActionType `json:"type"`
	DestinationFolderID string     `json:"destination_folder_id,omitempty"`
	Succeeded           bool       `json:"succeeded"`
	RolledBack          bool       `json:"rolled_back,omitempty"`
	Error               string     `json:"error,omitempty"`
}

type Execution struct {
	ID             string           `json:"id"`
	OwnerID        string           `json:"owner_id"`
	RuleID         string           `json:"rule_id"`
	RuleName       string           `json:"rule_name"`
	ItemID         string           `json:"item_id"`
	SourceFolderID string           `json:"source_folder_id"`
	FinalFolderID  string           `json:"final_folder_id,omitempty"`
	FinalTrashed   bool             `json:"final_trashed,omitempty"`
	Matched        bool             `json:"matched"`
	Succeeded      bool             `json:"succeeded"`
	Actions        []ActionEvidence `json:"actions,omitempty"`
	Error          string           `json:"error,omitempty"`
	StartedAt      time.Time        `json:"started_at"`
	FinishedAt     time.Time        `json:"finished_at"`
}

type RunStatus string

const (
	RunQueued              RunStatus = "queued"
	RunRunning             RunStatus = "running"
	RunCancelling          RunStatus = "cancelling"
	RunCancelled           RunStatus = "cancelled"
	RunCompleted           RunStatus = "completed"
	RunCompletedWithErrors RunStatus = "completed_with_errors"
	RunFailed              RunStatus = "failed"
)

type Run struct {
	ID                  string         `json:"id"`
	OwnerID             string         `json:"owner_id"`
	RuleID              string         `json:"rule_id"`
	RuleName            string         `json:"rule_name"`
	Status              RunStatus      `json:"status"`
	DryRun              bool           `json:"dry_run"`
	FoldersTotal        int            `json:"folders_total"`
	FoldersDone         int            `json:"folders_done"`
	ItemsEstimated      int64          `json:"items_estimated"`
	ItemsExamined       int64          `json:"items_examined"`
	ItemsMatched        int64          `json:"items_matched"`
	ItemsSucceeded      int64          `json:"items_succeeded"`
	ItemsFailed         int64          `json:"items_failed"`
	CheckpointFolder    int            `json:"checkpoint_folder"`
	CheckpointBeforeUID uint32         `json:"checkpoint_before_uid"`
	CancelRequested     bool           `json:"cancel_requested"`
	LastError           string         `json:"last_error,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	StartedAt           time.Time      `json:"started_at,omitzero"`
	UpdatedAt           time.Time      `json:"updated_at"`
	FinishedAt          time.Time      `json:"finished_at,omitzero"`
	Access              AccessSnapshot `json:"access"`
	RuleSnapshot        Rule           `json:"rule_snapshot"`
	FolderIDs           []string       `json:"folder_ids,omitempty"`
}

// AccessSnapshot retains enough identity to revalidate a checkpointed run
// through FolderSpace after restart. It intentionally contains no credentials.
type AccessSnapshot struct {
	ActorID   string `json:"actor_id"`
	SubjectID string `json:"subject_id"`
	Mode      string `json:"mode,omitempty"`
}

type Preview struct {
	RuleID    string        `json:"rule_id"`
	Examined  int64         `json:"examined"`
	Matched   int64         `json:"matched"`
	Truncated bool          `json:"truncated"`
	Items     []PreviewItem `json:"items"`
}

type PreviewItem struct {
	ItemID   string    `json:"item_id"`
	FolderID string    `json:"folder_id"`
	Name     string    `json:"name,omitempty"`
	Date     time.Time `json:"date,omitzero"`
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func ValidateDocument(document Document) error {
	if document.Version != CurrentVersion {
		return fmt.Errorf("unsupported automation document version %d", document.Version)
	}
	if strings.TrimSpace(document.OwnerID) == "" || strings.TrimSpace(document.Revision) == "" {
		return errors.New("automation owner and revision are required")
	}
	if len(document.Rules) > MaxRules {
		return fmt.Errorf("automation document has %d rules; maximum is %d", len(document.Rules), MaxRules)
	}
	seen := make(map[string]struct{}, len(document.Rules))
	for index, rule := range document.Rules {
		if err := ValidateRule(rule); err != nil {
			return fmt.Errorf("rule %d: %w", index+1, err)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

func ValidateRule(rule Rule) error {
	if !identifierPattern.MatchString(rule.ID) {
		return errors.New("rule ID is invalid")
	}
	if name := strings.TrimSpace(rule.Name); name == "" || len(name) > 200 {
		return errors.New("rule name is required and cannot exceed 200 bytes")
	}
	if len(rule.Description) > MaxTextBytes {
		return fmt.Errorf("rule description cannot exceed %d bytes", MaxTextBytes)
	}
	if rule.Match != MatchAll && rule.Match != MatchAny {
		return errors.New("rule match mode must be all or any")
	}
	if len(rule.Conditions) > MaxConditions {
		return fmt.Errorf("rule has too many conditions; maximum is %d", MaxConditions)
	}
	if len(rule.Actions) == 0 || len(rule.Actions) > MaxActions {
		return fmt.Errorf("rule must have between 1 and %d actions", MaxActions)
	}
	for _, kind := range rule.FolderTypes {
		if !validFolderType(kind) {
			return fmt.Errorf("unsupported folder type %q", kind)
		}
	}
	for index, condition := range rule.Conditions {
		if err := validateCondition(condition); err != nil {
			return fmt.Errorf("condition %d: %w", index+1, err)
		}
	}
	for index, action := range rule.Actions {
		if err := validateAction(action); err != nil {
			return fmt.Errorf("action %d: %w", index+1, err)
		}
		if action.Type == ActionTrash && index != len(rule.Actions)-1 {
			return fmt.Errorf("action %d: trash must be the final action", index+1)
		}
	}
	return nil
}

func validFolderType(kind model.FolderType) bool {
	return slices.Contains([]model.FolderType{model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts, model.FolderTypeFiles, model.FolderTypeNotes, model.FolderTypeScheduleInbox, model.FolderTypeScheduleOutbox}, kind)
}

func validateCondition(condition Condition) error {
	validField := slices.Contains([]Field{FieldName, FieldContent, FieldContentType, FieldSize, FieldDate, FieldFlag, FieldTag, FieldFrom, FieldTo, FieldSubject, FieldSummary, FieldOrganizer, FieldAttendee, FieldEmail, FieldOrganization, FieldCategory}, condition.Field) || condition.Field == "header"
	if !validField {
		return fmt.Errorf("unsupported field %q", condition.Field)
	}
	if condition.Field == "header" && strings.TrimSpace(condition.Header) == "" {
		return errors.New("header name is required")
	}
	if !slices.Contains([]Operator{OperatorEquals, OperatorNotEquals, OperatorContains, OperatorPrefix, OperatorSuffix, OperatorExists, OperatorNotExists, OperatorBefore, OperatorAfter, OperatorGreater, OperatorLess}, condition.Operator) {
		return fmt.Errorf("unsupported operator %q", condition.Operator)
	}
	if condition.Operator != OperatorExists && condition.Operator != OperatorNotExists && strings.TrimSpace(condition.Value) == "" {
		return errors.New("condition value is required")
	}
	if len(condition.Value) > MaxTextBytes || len(condition.Header) > 200 {
		return errors.New("condition value is too long")
	}
	return nil
}

func validateAction(action Action) error {
	switch action.Type {
	case ActionMove, ActionCopy:
		if strings.TrimSpace(action.DestinationFolderID) == "" {
			return errors.New("destination folder is required")
		}
	case ActionAddFlag, ActionRemoveFlag, ActionAddTag, ActionRemoveTag, ActionAddCategory, ActionRemoveCategory:
		if strings.TrimSpace(action.Value) == "" || len(action.Value) > 200 {
			return errors.New("action value is required and cannot exceed 200 bytes")
		}
	case ActionTrash:
		if action.DestinationFolderID != "" || action.Value != "" {
			return errors.New("trash does not accept a destination or value")
		}
	default:
		return fmt.Errorf("unsupported action %q", action.Type)
	}
	return nil
}

func Match(rule Rule, folder model.Folder, item model.Item) MatchResult {
	if (len(rule.SourceFolderIDs) > 0 && !slices.Contains(rule.SourceFolderIDs, folder.ID)) || (len(rule.FolderTypes) > 0 && !slices.Contains(rule.FolderTypes, folder.Type)) {
		return MatchResult{}
	}
	result := MatchResult{Matched: rule.Match == MatchAll, Conditions: make([]ConditionEvaluation, 0, len(rule.Conditions))}
	if len(rule.Conditions) == 0 {
		result.Matched = true
		return result
	}
	values := itemValues(folder, item)
	for _, condition := range rule.Conditions {
		var matched bool
		if condition.Field == FieldCategory && (condition.Operator == OperatorEquals || condition.Operator == OperatorNotEquals) {
			// Category names compare like the item stores them: a message
			// through its keyword, other items by name without case.
			matched = category.Has(folder.Type, item, condition.Value) == (condition.Operator == OperatorEquals)
		} else {
			matched = conditionMatches(condition, values)
		}
		if condition.Negate {
			matched = !matched
		}
		result.Conditions = append(result.Conditions, ConditionEvaluation{Field: condition.Field, Operator: condition.Operator, Matched: matched})
		if rule.Match == MatchAll && !matched {
			result.Matched = false
		}
		if rule.Match == MatchAny && matched {
			result.Matched = true
		}
	}
	return result
}

func conditionMatches(condition Condition, values map[string][]string) bool {
	key := string(condition.Field)
	if condition.Field == "header" {
		key = "header:" + strings.ToLower(strings.TrimSpace(condition.Header))
	}
	candidates := values[key]
	if condition.Operator == OperatorExists {
		return len(candidates) > 0 && slices.ContainsFunc(candidates, func(value string) bool { return value != "" })
	}
	if condition.Operator == OperatorNotExists {
		return len(candidates) == 0 || !slices.ContainsFunc(candidates, func(value string) bool { return value != "" })
	}
	if condition.Operator == OperatorNotEquals {
		return len(candidates) > 0 && !slices.ContainsFunc(candidates, func(candidate string) bool {
			comparison := condition
			comparison.Operator = OperatorEquals
			return compare(comparison, candidate)
		})
	}
	return slices.ContainsFunc(candidates, func(candidate string) bool { return compare(condition, candidate) })
}

func compare(condition Condition, candidate string) bool {
	want := condition.Value
	if !condition.CaseSensitive && condition.Operator != OperatorBefore && condition.Operator != OperatorAfter && condition.Operator != OperatorGreater && condition.Operator != OperatorLess {
		candidate, want = strings.ToLower(candidate), strings.ToLower(want)
	}
	switch condition.Operator {
	case OperatorEquals:
		return candidate == want
	case OperatorNotEquals:
		return candidate != want
	case OperatorContains:
		return strings.Contains(candidate, want)
	case OperatorPrefix:
		return strings.HasPrefix(candidate, want)
	case OperatorSuffix:
		return strings.HasSuffix(candidate, want)
	case OperatorBefore, OperatorAfter:
		left, leftErr := time.Parse(time.RFC3339, candidate)
		right, rightErr := time.Parse(time.RFC3339, condition.Value)
		if leftErr != nil || rightErr != nil {
			return false
		}
		if condition.Operator == OperatorBefore {
			return left.Before(right)
		}
		return left.After(right)
	case OperatorGreater, OperatorLess:
		left, leftErr := strconv.ParseInt(candidate, 10, 64)
		right, rightErr := strconv.ParseInt(condition.Value, 10, 64)
		if leftErr != nil || rightErr != nil {
			return false
		}
		if condition.Operator == OperatorGreater {
			return left > right
		}
		return left < right
	}
	return false
}

func itemValues(folder model.Folder, item model.Item) map[string][]string {
	result := map[string][]string{
		string(FieldName):     {item.Name},
		string(FieldContent):  {boundedString(item.Data)},
		string(FieldSize):     {strconv.FormatInt(item.Size, 10)},
		string(FieldDate):     {item.InternalDate.UTC().Format(time.RFC3339)},
		string(FieldFlag):     slices.Clone(item.Flags),
		string(FieldTag):      splitTags(item.Headers[tagHeader]),
		string(FieldCategory): category.ItemCategories(folder.Type, item, nil),
	}
	if item.InternalDate.IsZero() {
		result[string(FieldDate)] = []string{item.CreatedAt.UTC().Format(time.RFC3339)}
	}
	for name, value := range item.Headers {
		result["header:"+strings.ToLower(name)] = []string{value}
	}
	contentType := firstNonEmpty(item.Headers["Content-Type"], item.Headers["content-type"])
	result[string(FieldContentType)] = []string{contentType}
	if folder.Type == model.FolderTypeMail {
		if message, err := mail.ReadMessage(bytes.NewReader(item.Data)); err == nil {
			for name, values := range message.Header {
				result["header:"+strings.ToLower(name)] = slices.Clone(values)
			}
			result[string(FieldFrom)] = mailAddresses(message.Header["From"])
			result[string(FieldTo)] = mailAddresses(append(slices.Clone(message.Header["To"]), message.Header["Cc"]...))
			result[string(FieldSubject)] = slices.Clone(message.Header["Subject"])
		}
	}
	properties := contentProperties(item.Data)
	result[string(FieldSummary)] = properties["SUMMARY"]
	result[string(FieldOrganizer)] = properties["ORGANIZER"]
	result[string(FieldAttendee)] = properties["ATTENDEE"]
	result[string(FieldEmail)] = properties["EMAIL"]
	result[string(FieldOrganization)] = append(properties["ORG"], properties["ORGANIZATION"]...)
	return result
}

func mailAddresses(values []string) []string {
	result := slices.Clone(values)
	// A set keeps de-duplication linear in a header listing many addresses.
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range values {
		addresses, err := mail.ParseAddressList(value)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address.Address != "" && !seen[address.Address] {
				seen[address.Address] = true
				result = append(result, address.Address)
			}
		}
	}
	return result
}

func boundedString(data []byte) string {
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	return string(data)
}

func contentProperties(data []byte) map[string][]string {
	result := make(map[string][]string)
	lines := strings.Split(strings.ReplaceAll(boundedString(data), "\r\n", "\n"), "\n")
	// Continuations are collected in a builder: appending each one to the
	// previous string would copy it once per folded line, quadratic in a
	// value folded over many short lines.
	unfolded := make([]string, 0, len(lines))
	var current strings.Builder
	for index, line := range lines {
		if index > 0 && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			current.WriteString(strings.TrimLeft(line, " \t"))
			continue
		}
		if index > 0 {
			unfolded = append(unfolded, current.String())
			current.Reset()
		}
		current.WriteString(line)
	}
	if len(lines) > 0 {
		unfolded = append(unfolded, current.String())
	}
	for _, line := range unfolded {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(name, ";")
		name = strings.ToUpper(strings.TrimSpace(name))
		if slices.Contains([]string{"SUMMARY", "ORGANIZER", "ATTENDEE", "EMAIL", "ORG", "ORGANIZATION"}, name) {
			result[name] = append(result[name], strings.TrimSpace(value))
		}
	}
	return result
}

const tagHeader = "X-Veksel-Tags"

func splitTags(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" && !slices.Contains(result, part) {
			result = append(result, part)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func cloneDocument(document Document) Document {
	rules := document.Rules
	document.Rules = make([]Rule, len(rules))
	for index, rule := range rules {
		rule.SourceFolderIDs = slices.Clone(rule.SourceFolderIDs)
		rule.FolderTypes = slices.Clone(rule.FolderTypes)
		rule.Conditions = slices.Clone(rule.Conditions)
		rule.Actions = slices.Clone(rule.Actions)
		document.Rules[index] = rule
	}
	return document
}
