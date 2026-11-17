package search

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func TestExpandExpression(t *testing.T) {
	request, err := expandExpression(service.SearchQuery{
		Text:       "literal",
		Expression: `quarterly from:"Alice Smith" to:bob@example.test subject:budget after:2026-01-01 before:2027-01-01 has:attachment is:unread -is:flagged type:mail`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.Expression != "" || request.Text != "literal quarterly" {
		t.Fatalf("expanded text = %q, expression = %q", request.Text, request.Expression)
	}
	if request.Filter == nil || request.Filter.Operator != service.SearchAll || len(request.Filter.Children) != 9 {
		t.Fatalf("expanded filter = %+v", request.Filter)
	}
	wantFirst := service.SearchFilter{Operator: service.SearchContains, Field: "from", Value: "Alice Smith"}
	if !reflect.DeepEqual(request.Filter.Children[0], wantFirst) {
		t.Fatalf("first filter = %+v, want %+v", request.Filter.Children[0], wantFirst)
	}
	wantType := service.SearchFilter{Operator: service.SearchEquals, Field: "type", Value: string(model.FolderTypeMail)}
	if !reflect.DeepEqual(request.Filter.Children[len(request.Filter.Children)-1], wantType) {
		t.Fatalf("type filter = %+v, want %+v", request.Filter.Children[len(request.Filter.Children)-1], wantType)
	}
}

func TestExpressionValidation(t *testing.T) {
	for _, test := range []struct {
		name       string
		expression string
	}{
		{name: "quote", expression: `subject:"unfinished`},
		{name: "empty field", expression: "from:"},
		{name: "type", expression: "type:unknown"},
		{name: "has", expression: "has:calendar"},
		{name: "is", expression: "is:important"},
		{name: "terms", expression: strings.Repeat("word ", maxExpressionTokens+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := expandExpression(service.SearchQuery{Expression: test.expression}); err == nil {
				t.Fatal("invalid expression was accepted")
			}
		})
	}
}

func TestUnknownExpressionPrefixRemainsLiteral(t *testing.T) {
	request, err := expandExpression(service.SearchQuery{Expression: `https://example.test tag:value`})
	if err != nil {
		t.Fatal(err)
	}
	if request.Text != "https://example.test tag:value" || request.Filter != nil {
		t.Fatalf("expanded request = %+v", request)
	}
}
