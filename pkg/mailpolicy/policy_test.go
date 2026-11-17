package mailpolicy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestCompileEvaluateOrdersRulesAndStops(t *testing.T) {
	document := Document{Version: CurrentVersion, Revision: "rev-7", Rules: []Rule{
		{
			ID: "large", Name: "Quarantine large inbound mail", Enabled: true, Priority: 20, Match: MatchAll,
			Conditions: []Condition{{Field: FieldDirection, Operator: OperatorEquals, Value: "inbound"}, {Field: FieldSizeBytes, Operator: OperatorGreaterThan, Value: "1000"}},
			Exceptions: []Condition{{Field: FieldEnvelopeFrom, Operator: OperatorSuffix, Value: "@trusted.example"}},
			Actions:    []Action{{Type: ActionQuarantine, Value: "oversize"}, {Type: ActionStop}},
		},
		{
			ID: "annotate", Name: "Mark example mail", Enabled: true, Priority: 10, Match: MatchAny,
			Conditions: []Condition{{Field: FieldEnvelopeTo, Operator: OperatorSuffix, Value: "@example.test"}, {Field: FieldDomain, Operator: OperatorEquals, Value: "example.test"}},
			Actions:    []Action{{Type: ActionAddHeader, Header: "X-Veksel-Policy", Value: "example"}},
		},
		{
			ID: "after-stop", Name: "Must not execute", Enabled: true, Priority: 30,
			Conditions: []Condition{{Field: FieldDirection, Operator: OperatorEquals, Value: "inbound"}},
			Actions:    []Action{{Type: ActionAccept}},
		},
	}}
	compiled, err := Compile(document)
	if err != nil {
		t.Fatal(err)
	}
	result := compiled.Evaluate(Message{Direction: DirectionInbound, EnvelopeFrom: "sender@outside.test", EnvelopeTo: []string{"user@example.test"}, Domain: "example.test", SizeBytes: 2048})
	if result.Revision != "rev-7" {
		t.Fatalf("revision = %q", result.Revision)
	}
	if len(result.Rules) != 2 || result.Rules[0].RuleID != "annotate" || result.Rules[1].RuleID != "large" {
		t.Fatalf("ordered stopped rules = %+v", result.Rules)
	}
	if got := actionTypes(result.Actions); got != "add_header,quarantine,stop" {
		t.Fatalf("actions = %s", got)
	}
}

func TestEvaluateExceptionAndMultiValueNotEquals(t *testing.T) {
	compiled, err := Compile(Document{Version: CurrentVersion, Revision: "one", Rules: []Rule{{
		ID: "rule", Name: "rule", Enabled: true,
		Conditions: []Condition{{Field: FieldEnvelopeTo, Operator: OperatorNotEquals, Value: "blocked@example.test"}},
		Exceptions: []Condition{{Field: FieldSourceIP, Operator: OperatorCIDR, Values: []string{"192.0.2.0/24", "2001:db8::/32"}}},
		Actions:    []Action{{Type: ActionReject, Value: "policy rejection", EnhancedStatusCode: "5.7.1"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	blockedRecipient := compiled.Evaluate(Message{EnvelopeTo: []string{"ok@example.test", "blocked@example.test"}, SourceIP: "198.51.100.4"})
	if len(blockedRecipient.Actions) != 0 {
		t.Fatalf("not_equals matched a multi-value field containing the excluded value: %+v", blockedRecipient)
	}
	excepted := compiled.Evaluate(Message{EnvelopeTo: []string{"ok@example.test"}, SourceIP: "192.0.2.9"})
	if len(excepted.Actions) != 0 || !excepted.Rules[0].Excepted {
		t.Fatalf("CIDR exception not applied: %+v", excepted)
	}
}

func TestCompileRejectsInvalidDocuments(t *testing.T) {
	valid := Rule{ID: "valid", Name: "Valid", Enabled: true, Conditions: []Condition{{Field: FieldDirection, Operator: OperatorEquals, Value: "inbound"}}, Actions: []Action{{Type: ActionAccept}}}
	tests := []struct {
		name     string
		document Document
		contains string
	}{
		{"version", Document{Version: 99, Revision: "r"}, "unsupported"},
		{"revision", Document{Version: CurrentVersion}, "revision"},
		{"duplicate", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{valid, valid}}, "duplicate"},
		{"regex", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withCondition(valid, Condition{Field: FieldHeaderSubject, Operator: OperatorMatches, Value: "["})}}, "regular expression"},
		{"regex bound", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withCondition(valid, Condition{Field: FieldHeaderSubject, Operator: OperatorMatches, Value: strings.Repeat("x", MaxPatternBytes+1)})}}, "regular expression"},
		{"numeric field", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withCondition(valid, Condition{Field: FieldHeaderSubject, Operator: OperatorGreaterThan, Value: "4"})}}, "size_bytes"},
		{"CIDR", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withCondition(valid, Condition{Field: FieldSourceIP, Operator: OperatorCIDR, Value: "bad"})}}, "CIDR"},
		{"header", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withActions(valid, Action{Type: ActionAddHeader, Header: "Bad Header", Value: "x"})}}, "header"},
		{"header injection", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withActions(valid, Action{Type: ActionAddHeader, Header: "X-Safe", Value: "safe\r\nBcc: victim@example.test"})}}, "line break"},
		{"status", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withActions(valid, Action{Type: ActionReject, Value: "no", EnhancedStatusCode: "9.9.9"})}}, "status"},
		{"control order", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withActions(valid, Action{Type: ActionStop}, Action{Type: ActionAccept})}}, "final action"},
		{"contradictory outcome", Document{Version: CurrentVersion, Revision: "r", Rules: []Rule{withActions(valid, Action{Type: ActionAccept}, Action{Type: ActionReject, Value: "no"})}}, "both accept and reject"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile(test.document)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want containing %q", err, test.contains)
			}
		})
	}
}

func TestCompiledPolicyIsSafeForConcurrentEvaluation(t *testing.T) {
	rules := make([]Rule, 50)
	for index := range rules {
		rules[index] = Rule{
			ID: fmt.Sprintf("rule-%02d", index), Name: "Concurrent", Enabled: true, Priority: index,
			Conditions: []Condition{{Field: FieldHeaderSubject, Operator: OperatorContains, Value: "match"}},
			Actions:    []Action{{Type: ActionAddHeader, Header: "X-Matched", Value: fmt.Sprint(index)}},
		}
	}
	compiled, err := Compile(Document{Version: CurrentVersion, Revision: "concurrent", Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				result := compiled.Evaluate(Message{HeaderSubject: "a match"})
				if len(result.Actions) != len(rules) {
					t.Errorf("actions = %d, want %d", len(result.Actions), len(rules))
					return
				}
			}
		}()
	}
	wait.Wait()
}

func TestCompiledPolicyIsDetachedFromSourceDocument(t *testing.T) {
	document := Document{Version: CurrentVersion, Revision: "detached", Rules: []Rule{{
		ID: "rule", Name: "Detached", Enabled: true,
		Conditions: []Condition{{Field: FieldDirection, Operator: OperatorIn, Values: []string{"inbound"}}},
		Actions:    []Action{{Type: ActionRoute, Value: "original-route"}},
	}}}
	compiled, err := Compile(document)
	if err != nil {
		t.Fatal(err)
	}
	document.Rules[0].Conditions[0].Values[0] = "outbound"
	document.Rules[0].Actions[0].Value = "mutated-route"
	result := compiled.Evaluate(Message{Direction: DirectionInbound})
	if len(result.Actions) != 1 || result.Actions[0].Value != "original-route" {
		t.Fatalf("compiled snapshot retained caller-owned slices: %+v", result)
	}
}

func TestDecisionUsesOrderedLastDecisiveAction(t *testing.T) {
	result := Result{Actions: []Action{
		{Type: ActionReject, Value: "first"},
		{Type: ActionAddHeader, Header: "X-One", Value: "one"},
		{Type: ActionAccept},
		{Type: ActionQuarantine, Value: "review"},
		{Type: ActionRoute, Value: "old"},
		{Type: ActionRoute, Value: "new"},
	}}
	decision := result.Decision()
	if decision.Reject != nil || decision.Quarantine == nil || decision.Quarantine.Value != "review" {
		t.Fatalf("decisive outcome = %+v", decision)
	}
	if decision.Route == nil || decision.Route.Value != "new" || len(decision.Headers) != 1 {
		t.Fatalf("accumulated decision = %+v", decision)
	}
}

func TestEvidenceIsBoundedAndDetached(t *testing.T) {
	result := Result{Revision: "bounded", Actions: make([]Action, MaxEvidenceActions+3)}
	for index := 0; index < MaxEvidenceRules+2; index++ {
		result.Rules = append(result.Rules, RuleResult{RuleID: fmt.Sprint(index), Matched: true, Conditions: make([]ConditionResult, MaxConditionsPerRule), Actions: []Action{{Type: ActionAccept}}})
	}
	evidence := result.Evidence()
	if len(evidence.Rules) != MaxEvidenceRules || evidence.RulesDropped != 2 {
		t.Fatalf("rule evidence = %d retained, %d dropped", len(evidence.Rules), evidence.RulesDropped)
	}
	conditions := 0
	for _, rule := range evidence.Rules {
		conditions += len(rule.Conditions)
	}
	if conditions != MaxEvidenceConditions || evidence.ConditionsDropped == 0 {
		t.Fatalf("condition evidence = %d retained, %d dropped", conditions, evidence.ConditionsDropped)
	}
	if len(evidence.Actions) != MaxEvidenceActions || evidence.ActionsDropped != 3 {
		t.Fatalf("action evidence = %d retained, %d dropped", len(evidence.Actions), evidence.ActionsDropped)
	}
	evidence.Actions[0].Value = "mutated"
	if result.Actions[0].Value == "mutated" {
		t.Fatal("evidence retained caller-owned action storage")
	}
}

func withCondition(rule Rule, condition Condition) Rule {
	rule.Conditions = []Condition{condition}
	return rule
}

func withActions(rule Rule, actions ...Action) Rule {
	rule.Actions = actions
	return rule
}

func actionTypes(actions []Action) string {
	values := make([]string, len(actions))
	for index, action := range actions {
		values[index] = string(action.Type)
	}
	return strings.Join(values, ",")
}
