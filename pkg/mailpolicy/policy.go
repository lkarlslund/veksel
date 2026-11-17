// Package mailpolicy defines bounded, deterministic mail-flow policy semantics.
// It is deliberately independent of SMTP, queues, and storage so every
// protocol boundary can evaluate the same immutable compiled policy.
package mailpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	CurrentVersion        = 1
	MaxRules              = 1000
	MaxConditionsPerRule  = 64
	MaxActionsPerRule     = 16
	MaxValuesPerCondition = 64
	MaxPatternBytes       = 512
	MaxValueBytes         = 2048
	MaxEvidenceRules      = 32
	MaxEvidenceConditions = 256
	MaxEvidenceActions    = 64
)

type Direction string

const (
	DirectionInbound    Direction = "inbound"
	DirectionSubmission Direction = "submission"
	DirectionOutbound   Direction = "outbound"
)

type MatchMode string

const (
	MatchAll MatchMode = "all"
	MatchAny MatchMode = "any"
)

type Field string

const (
	FieldDirection          Field = "direction"
	FieldEnvelopeFrom       Field = "envelope_from"
	FieldEnvelopeTo         Field = "envelope_to"
	FieldAuthenticatedActor Field = "authenticated_actor"
	FieldSourceIP           Field = "source_ip"
	FieldSizeBytes          Field = "size_bytes"
	FieldHeaderFrom         Field = "header_from"
	FieldHeaderSubject      Field = "header_subject"
	FieldHasAttachment      Field = "has_attachment"
	FieldContentType        Field = "content_type"
	FieldDomain             Field = "domain"
)

type Operator string

const (
	OperatorEquals      Operator = "equals"
	OperatorNotEquals   Operator = "not_equals"
	OperatorContains    Operator = "contains"
	OperatorPrefix      Operator = "prefix"
	OperatorSuffix      Operator = "suffix"
	OperatorMatches     Operator = "matches"
	OperatorGreaterThan Operator = "greater_than"
	OperatorLessThan    Operator = "less_than"
	OperatorIn          Operator = "in"
	OperatorCIDR        Operator = "cidr"
)

type ActionType string

const (
	ActionAccept     ActionType = "accept"
	ActionReject     ActionType = "reject"
	ActionQuarantine ActionType = "quarantine"
	ActionRoute      ActionType = "route"
	ActionAddHeader  ActionType = "add_header"
	ActionStop       ActionType = "stop"
	ActionContinue   ActionType = "continue"
)

// Document is one complete optimistic policy revision.
type Document struct {
	Version  int    `json:"version"`
	Revision string `json:"revision"`
	Rules    []Rule `json:"rules"`
}

type Rule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Enabled    bool        `json:"enabled"`
	Priority   int         `json:"priority"`
	Match      MatchMode   `json:"match"`
	Conditions []Condition `json:"conditions"`
	Exceptions []Condition `json:"exceptions,omitempty"`
	Actions    []Action    `json:"actions"`
}

type Condition struct {
	Field    Field    `json:"field"`
	Operator Operator `json:"operator"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
}

type Action struct {
	Type               ActionType `json:"type"`
	Value              string     `json:"value,omitempty"`
	Header             string     `json:"header,omitempty"`
	EnhancedStatusCode string     `json:"enhanced_status_code,omitempty"`
}

// Message contains bounded metadata only. The evaluator never needs a body.
type Message struct {
	Direction          Direction `json:"direction"`
	EnvelopeFrom       string    `json:"envelope_from,omitempty"`
	EnvelopeTo         []string  `json:"envelope_to,omitempty"`
	AuthenticatedActor string    `json:"authenticated_actor,omitempty"`
	SourceIP           string    `json:"source_ip,omitempty"`
	SizeBytes          int64     `json:"size_bytes,omitempty"`
	HeaderFrom         string    `json:"header_from,omitempty"`
	HeaderSubject      string    `json:"header_subject,omitempty"`
	HasAttachment      bool      `json:"has_attachment,omitempty"`
	ContentType        string    `json:"content_type,omitempty"`
	Domain             string    `json:"domain,omitempty"`
}

// Validate checks simulator/admission metadata bounds independently from any
// particular rule set.
func (message Message) Validate() error {
	if message.Direction != DirectionInbound && message.Direction != DirectionSubmission && message.Direction != DirectionOutbound {
		return errors.New("direction must be inbound, submission, or outbound")
	}
	if message.SizeBytes < 0 {
		return errors.New("size_bytes cannot be negative")
	}
	if len(message.EnvelopeTo) > 100 {
		return errors.New("envelope_to cannot exceed 100 recipients")
	}
	values := append([]string{message.EnvelopeFrom, message.AuthenticatedActor, message.SourceIP, message.HeaderFrom, message.ContentType, message.Domain}, message.EnvelopeTo...)
	for _, value := range values {
		if len(value) > MaxValueBytes {
			return fmt.Errorf("message metadata value cannot exceed %d bytes", MaxValueBytes)
		}
	}
	if len(message.HeaderSubject) > 8192 {
		return errors.New("header_subject cannot exceed 8192 bytes")
	}
	return nil
}

type ConditionResult struct {
	Field     Field    `json:"field"`
	Operator  Operator `json:"operator"`
	Matched   bool     `json:"matched"`
	Exception bool     `json:"exception,omitempty"`
}

type RuleResult struct {
	RuleID     string            `json:"rule_id"`
	Matched    bool              `json:"matched"`
	Excepted   bool              `json:"excepted,omitempty"`
	Conditions []ConditionResult `json:"conditions,omitempty"`
	Actions    []Action          `json:"actions,omitempty"`
}

type Result struct {
	Revision          string       `json:"revision"`
	Rules             []RuleResult `json:"rules"`
	Actions           []Action     `json:"actions"`
	RulesDropped      int          `json:"rules_dropped,omitempty"`
	ConditionsDropped int          `json:"conditions_dropped,omitempty"`
	ActionsDropped    int          `json:"actions_dropped,omitempty"`
}

// Decision is the effective outcome of an ordered action stream. Later
// decisive actions replace earlier accept/reject/quarantine outcomes, route
// selection is last-wins, and safe header annotations accumulate.
type Decision struct {
	Reject     *Action
	Quarantine *Action
	Route      *Action
	Headers    []Action
}

// RejectionError lets protocol boundaries preserve a policy's enhanced status
// without coupling the policy engine to SMTP response framing.
type RejectionError struct {
	Reason             string
	EnhancedStatusCode string
}

func (err *RejectionError) Error() string {
	if err == nil {
		return "mail rejected by policy"
	}
	return err.Reason
}

// Clone returns a fully detached result suitable for a durable queue snapshot.
func (result Result) Clone() Result {
	cloned := Result{Revision: result.Revision, Actions: slices.Clone(result.Actions), Rules: make([]RuleResult, len(result.Rules)), RulesDropped: result.RulesDropped, ConditionsDropped: result.ConditionsDropped, ActionsDropped: result.ActionsDropped}
	for index, rule := range result.Rules {
		rule.Conditions = slices.Clone(rule.Conditions)
		rule.Actions = slices.Clone(rule.Actions)
		cloned.Rules[index] = rule
	}
	return cloned
}

// Evidence returns a bounded durable explanation without changing the full
// action stream used to make the live decision.
func (result Result) Evidence() Result {
	evidence := Result{Revision: result.Revision}
	conditionCount := 0
	for _, rule := range result.Rules {
		if !rule.Matched {
			continue
		}
		if len(evidence.Rules) >= MaxEvidenceRules {
			evidence.RulesDropped++
			evidence.ConditionsDropped += len(rule.Conditions)
			continue
		}
		remaining := MaxEvidenceConditions - conditionCount
		copy := rule
		switch {
		case remaining <= 0:
			evidence.ConditionsDropped += len(copy.Conditions)
			copy.Conditions = nil
		case len(copy.Conditions) > remaining:
			evidence.ConditionsDropped += len(copy.Conditions) - remaining
			copy.Conditions = slices.Clone(copy.Conditions[:remaining])
		default:
			copy.Conditions = slices.Clone(copy.Conditions)
		}
		conditionCount += len(copy.Conditions)
		copy.Actions = slices.Clone(copy.Actions)
		evidence.Rules = append(evidence.Rules, copy)
	}
	if len(result.Actions) > MaxEvidenceActions {
		evidence.Actions = slices.Clone(result.Actions[:MaxEvidenceActions])
		evidence.ActionsDropped = len(result.Actions) - MaxEvidenceActions
	} else {
		evidence.Actions = slices.Clone(result.Actions)
	}
	return evidence
}

// Decision reduces the ordered actions to one deterministic effective outcome.
func (result Result) Decision() Decision {
	var decision Decision
	for index := range result.Actions {
		action := result.Actions[index]
		switch action.Type {
		case ActionAccept:
			decision.Reject, decision.Quarantine = nil, nil
		case ActionReject:
			decision.Reject, decision.Quarantine = &action, nil
		case ActionQuarantine:
			decision.Quarantine, decision.Reject = &action, nil
		case ActionRoute:
			decision.Route = &action
		case ActionAddHeader:
			decision.Headers = append(decision.Headers, action)
		}
	}
	return decision
}

// MatchedRuleIDs returns decisive, non-excepted matches in evaluation order.
func (result Result) MatchedRuleIDs() []string {
	ids := make([]string, 0, len(result.Rules))
	for _, rule := range result.Rules {
		if rule.Matched && !rule.Excepted {
			ids = append(ids, rule.RuleID)
		}
	}
	return ids
}

type compiledCondition struct {
	condition Condition
	pattern   *regexp.Regexp
	prefixes  []netip.Prefix
}

type compiledRule struct {
	rule       Rule
	conditions []compiledCondition
	exceptions []compiledCondition
}

// Compiled is immutable and safe for concurrent evaluation.
type Compiled struct {
	revision string
	rules    []compiledRule
}

var (
	idPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	headerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,126}$`)
	statusPattern = regexp.MustCompile(`^[245]\.[0-9]\.[0-9]{1,3}$`)
)

// Compile validates the complete document and returns an immutable snapshot.
func Compile(document Document) (*Compiled, error) {
	if document.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported mail policy version %d", document.Version)
	}
	if strings.TrimSpace(document.Revision) == "" || len(document.Revision) > 128 {
		return nil, errors.New("mail policy revision is required and cannot exceed 128 bytes")
	}
	if len(document.Rules) > MaxRules {
		return nil, fmt.Errorf("mail policy cannot exceed %d rules", MaxRules)
	}
	seen := make(map[string]struct{}, len(document.Rules))
	rules := make([]compiledRule, 0, len(document.Rules))
	for _, rule := range document.Rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return nil, fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		rules = append(rules, compiled)
	}
	slices.SortStableFunc(rules, func(left, right compiledRule) int {
		if left.rule.Priority != right.rule.Priority {
			return left.rule.Priority - right.rule.Priority
		}
		return strings.Compare(left.rule.ID, right.rule.ID)
	})
	return &Compiled{revision: document.Revision, rules: rules}, nil
}

func compileRule(rule Rule) (compiledRule, error) {
	rule.Conditions = cloneConditions(rule.Conditions)
	rule.Exceptions = cloneConditions(rule.Exceptions)
	rule.Actions = slices.Clone(rule.Actions)
	if !idPattern.MatchString(rule.ID) {
		return compiledRule{}, errors.New("ID must contain only letters, numbers, dot, underscore, or dash")
	}
	if strings.TrimSpace(rule.Name) == "" || len(rule.Name) > 256 {
		return compiledRule{}, errors.New("name is required and cannot exceed 256 bytes")
	}
	if rule.Priority < 0 || rule.Priority > 1_000_000 {
		return compiledRule{}, errors.New("priority must be between 0 and 1000000")
	}
	if rule.Match == "" {
		rule.Match = MatchAll
	}
	if rule.Match != MatchAll && rule.Match != MatchAny {
		return compiledRule{}, errors.New("match must be all or any")
	}
	if len(rule.Conditions) == 0 || len(rule.Conditions) > MaxConditionsPerRule {
		return compiledRule{}, fmt.Errorf("between 1 and %d conditions are required", MaxConditionsPerRule)
	}
	if len(rule.Exceptions) > MaxConditionsPerRule {
		return compiledRule{}, fmt.Errorf("exceptions cannot exceed %d conditions", MaxConditionsPerRule)
	}
	if len(rule.Actions) == 0 || len(rule.Actions) > MaxActionsPerRule {
		return compiledRule{}, fmt.Errorf("between 1 and %d actions are required", MaxActionsPerRule)
	}
	conditions, err := compileConditions(rule.Conditions)
	if err != nil {
		return compiledRule{}, err
	}
	exceptions, err := compileConditions(rule.Exceptions)
	if err != nil {
		return compiledRule{}, fmt.Errorf("exception: %w", err)
	}
	for _, action := range rule.Actions {
		if err := validateAction(action); err != nil {
			return compiledRule{}, err
		}
	}
	if err := validateActionSequence(rule.Actions); err != nil {
		return compiledRule{}, err
	}
	return compiledRule{rule: rule, conditions: conditions, exceptions: exceptions}, nil
}

func cloneConditions(conditions []Condition) []Condition {
	result := slices.Clone(conditions)
	for index := range result {
		result[index].Values = slices.Clone(result[index].Values)
	}
	return result
}

func compileConditions(conditions []Condition) ([]compiledCondition, error) {
	result := make([]compiledCondition, 0, len(conditions))
	for _, condition := range conditions {
		compiled, err := compileCondition(condition)
		if err != nil {
			return nil, err
		}
		result = append(result, compiled)
	}
	return result, nil
}

func compileCondition(condition Condition) (compiledCondition, error) {
	if !validField(condition.Field) || !validOperator(condition.Operator) {
		return compiledCondition{}, fmt.Errorf("unsupported condition %s %s", condition.Field, condition.Operator)
	}
	if len(condition.Value) > MaxValueBytes || len(condition.Values) > MaxValuesPerCondition {
		return compiledCondition{}, errors.New("condition value exceeds policy bounds")
	}
	for _, value := range condition.Values {
		if len(value) > MaxValueBytes {
			return compiledCondition{}, errors.New("condition value exceeds policy bounds")
		}
	}
	compiled := compiledCondition{condition: condition}
	switch condition.Operator {
	case OperatorMatches:
		if condition.Value == "" || len(condition.Value) > MaxPatternBytes {
			return compiledCondition{}, fmt.Errorf("regular expression must contain 1 to %d bytes", MaxPatternBytes)
		}
		pattern, err := regexp.Compile(condition.Value)
		if err != nil {
			return compiledCondition{}, fmt.Errorf("invalid regular expression: %w", err)
		}
		compiled.pattern = pattern
	case OperatorCIDR:
		values := condition.Values
		if len(values) == 0 && condition.Value != "" {
			values = []string{condition.Value}
		}
		if condition.Field != FieldSourceIP || len(values) == 0 {
			return compiledCondition{}, errors.New("cidr requires source_ip and at least one prefix")
		}
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return compiledCondition{}, fmt.Errorf("invalid CIDR prefix %q", value)
			}
			compiled.prefixes = append(compiled.prefixes, prefix)
		}
	case OperatorIn:
		if len(condition.Values) == 0 {
			return compiledCondition{}, errors.New("in requires at least one value")
		}
	case OperatorGreaterThan, OperatorLessThan:
		if condition.Field != FieldSizeBytes {
			return compiledCondition{}, errors.New("numeric comparison requires size_bytes")
		}
		if _, err := strconv.ParseInt(condition.Value, 10, 64); err != nil {
			return compiledCondition{}, errors.New("size comparison requires an integer")
		}
	default:
		if condition.Value == "" {
			return compiledCondition{}, errors.New("condition value is required")
		}
	}
	return compiled, nil
}

func validateAction(action Action) error {
	if len(action.Value) > MaxValueBytes {
		return errors.New("action value exceeds policy bounds")
	}
	if strings.ContainsAny(action.Value, "\r\n") {
		return errors.New("action value cannot contain a line break")
	}
	switch action.Type {
	case ActionAccept, ActionStop, ActionContinue:
		if action.Value != "" || action.Header != "" || action.EnhancedStatusCode != "" {
			return fmt.Errorf("%s action does not accept parameters", action.Type)
		}
	case ActionReject:
		if strings.TrimSpace(action.Value) == "" {
			return errors.New("reject action requires a reason")
		}
		if action.EnhancedStatusCode != "" && !statusPattern.MatchString(action.EnhancedStatusCode) {
			return errors.New("reject action has an invalid enhanced status code")
		}
	case ActionQuarantine, ActionRoute:
		if strings.TrimSpace(action.Value) == "" {
			return fmt.Errorf("%s action requires a value", action.Type)
		}
	case ActionAddHeader:
		if !headerPattern.MatchString(action.Header) || strings.TrimSpace(action.Value) == "" {
			return errors.New("add_header requires a valid header name and value")
		}
	default:
		return fmt.Errorf("unsupported action %q", action.Type)
	}
	return nil
}

func validateActionSequence(actions []Action) error {
	control := 0
	accept, reject := false, false
	for index, action := range actions {
		switch action.Type {
		case ActionStop, ActionContinue:
			control++
			if index != len(actions)-1 {
				return errors.New("stop or continue must be the final action")
			}
		case ActionAccept:
			accept = true
		case ActionReject:
			reject = true
		}
	}
	if control > 1 {
		return errors.New("a rule cannot contain more than one stop or continue action")
	}
	if accept && reject {
		return errors.New("a rule cannot both accept and reject")
	}
	return nil
}

func validField(field Field) bool {
	return slices.Contains([]Field{FieldDirection, FieldEnvelopeFrom, FieldEnvelopeTo, FieldAuthenticatedActor, FieldSourceIP, FieldSizeBytes, FieldHeaderFrom, FieldHeaderSubject, FieldHasAttachment, FieldContentType, FieldDomain}, field)
}

func validOperator(operator Operator) bool {
	return slices.Contains([]Operator{OperatorEquals, OperatorNotEquals, OperatorContains, OperatorPrefix, OperatorSuffix, OperatorMatches, OperatorGreaterThan, OperatorLessThan, OperatorIn, OperatorCIDR}, operator)
}

// Evaluate returns a bounded explanation and the ordered actions to apply.
func (compiled *Compiled) Evaluate(message Message) Result {
	result := Result{Revision: compiled.revision, Rules: make([]RuleResult, 0, len(compiled.rules))}
	for _, rule := range compiled.rules {
		if !rule.rule.Enabled {
			continue
		}
		ruleResult := RuleResult{RuleID: rule.rule.ID}
		for _, condition := range rule.conditions {
			matched := condition.matches(message)
			ruleResult.Conditions = append(ruleResult.Conditions, ConditionResult{Field: condition.condition.Field, Operator: condition.condition.Operator, Matched: matched})
		}
		ruleResult.Matched = matchesMode(rule.rule.Match, ruleResult.Conditions)
		if ruleResult.Matched {
			for _, exception := range rule.exceptions {
				matched := exception.matches(message)
				ruleResult.Conditions = append(ruleResult.Conditions, ConditionResult{Field: exception.condition.Field, Operator: exception.condition.Operator, Matched: matched, Exception: true})
				if matched {
					ruleResult.Excepted = true
				}
			}
		}
		if ruleResult.Matched && !ruleResult.Excepted {
			ruleResult.Actions = slices.Clone(rule.rule.Actions)
			result.Actions = append(result.Actions, rule.rule.Actions...)
		}
		result.Rules = append(result.Rules, ruleResult)
		if ruleResult.Matched && !ruleResult.Excepted && slices.ContainsFunc(rule.rule.Actions, func(action Action) bool { return action.Type == ActionStop }) {
			break
		}
	}
	return result
}

func matchesMode(mode MatchMode, conditions []ConditionResult) bool {
	for _, condition := range conditions {
		if condition.Exception {
			continue
		}
		if mode == MatchAny && condition.Matched {
			return true
		}
		if mode == MatchAll && !condition.Matched {
			return false
		}
	}
	return mode == MatchAll
}

func (condition compiledCondition) matches(message Message) bool {
	values := messageValues(condition.condition.Field, message)
	if condition.condition.Operator == OperatorGreaterThan || condition.condition.Operator == OperatorLessThan {
		threshold, _ := strconv.ParseInt(condition.condition.Value, 10, 64)
		if condition.condition.Operator == OperatorGreaterThan {
			return message.SizeBytes > threshold
		}
		return message.SizeBytes < threshold
	}
	if condition.condition.Operator == OperatorCIDR {
		address, err := netip.ParseAddr(message.SourceIP)
		if err != nil {
			return false
		}
		return slices.ContainsFunc(condition.prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	}
	if condition.condition.Operator == OperatorNotEquals {
		return len(values) > 0 && !slices.ContainsFunc(values, func(value string) bool {
			return strings.EqualFold(value, condition.condition.Value)
		})
	}
	for _, value := range values {
		if matchString(value, condition) {
			return true
		}
	}
	return false
}

func messageValues(field Field, message Message) []string {
	switch field {
	case FieldDirection:
		return []string{string(message.Direction)}
	case FieldEnvelopeFrom:
		return []string{message.EnvelopeFrom}
	case FieldEnvelopeTo:
		return message.EnvelopeTo
	case FieldAuthenticatedActor:
		return []string{message.AuthenticatedActor}
	case FieldSourceIP:
		return []string{message.SourceIP}
	case FieldSizeBytes:
		return []string{strconv.FormatInt(message.SizeBytes, 10)}
	case FieldHeaderFrom:
		return []string{message.HeaderFrom}
	case FieldHeaderSubject:
		return []string{message.HeaderSubject}
	case FieldHasAttachment:
		return []string{strconv.FormatBool(message.HasAttachment)}
	case FieldContentType:
		return []string{message.ContentType}
	case FieldDomain:
		return []string{message.Domain}
	default:
		return nil
	}
}

func matchString(value string, condition compiledCondition) bool {
	left, right := strings.ToLower(value), strings.ToLower(condition.condition.Value)
	switch condition.condition.Operator {
	case OperatorEquals:
		return left == right
	case OperatorContains:
		return strings.Contains(left, right)
	case OperatorPrefix:
		return strings.HasPrefix(left, right)
	case OperatorSuffix:
		return strings.HasSuffix(left, right)
	case OperatorMatches:
		return condition.pattern.MatchString(value)
	case OperatorIn:
		return slices.ContainsFunc(condition.condition.Values, func(candidate string) bool { return strings.EqualFold(value, candidate) })
	default:
		return false
	}
}
