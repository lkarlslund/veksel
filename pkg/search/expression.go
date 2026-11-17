package search

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const maxExpressionTokens = 256

// expandExpression compiles the deliberately small end-user expression
// language to the backend-neutral SearchFilter tree. Existing Text and Filter
// values are preserved and combined, which keeps this additive for REST and
// protocol consumers that already build structured queries themselves.
func expandExpression(request service.SearchQuery) (service.SearchQuery, error) {
	if strings.TrimSpace(request.Expression) == "" {
		return request, nil
	}
	tokens, err := tokenizeExpression(request.Expression)
	if err != nil {
		return service.SearchQuery{}, err
	}
	text := make([]string, 0, len(tokens))
	filters := make([]service.SearchFilter, 0, len(tokens)+1)
	if request.Filter != nil {
		filters = append(filters, *request.Filter)
	}
	for _, token := range tokens {
		filter, structured, err := expressionFilter(token)
		if err != nil {
			return service.SearchQuery{}, err
		}
		if structured {
			filters = append(filters, filter)
			if strings.EqualFold(token, "is:trashed") {
				request.IncludeTrash = true
			}
			continue
		}
		text = append(text, token)
	}
	if literal := strings.TrimSpace(request.Text); literal != "" {
		text = append([]string{literal}, text...)
	}
	request.Text = strings.Join(text, " ")
	request.Expression = ""
	switch len(filters) {
	case 0:
		request.Filter = nil
	case 1:
		request.Filter = &filters[0]
	default:
		request.Filter = &service.SearchFilter{Operator: service.SearchAll, Children: filters}
	}
	return request, nil
}

func tokenizeExpression(expression string) ([]string, error) {
	var tokens []string
	var token strings.Builder
	quoted := false
	escaped := false
	flush := func() error {
		if token.Len() == 0 {
			return nil
		}
		tokens = append(tokens, token.String())
		token.Reset()
		if len(tokens) > maxExpressionTokens {
			return errors.New("search expression has too many terms")
		}
		return nil
	}
	for _, character := range expression {
		if escaped {
			token.WriteRune(character)
			escaped = false
			continue
		}
		if quoted && character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && unicode.IsSpace(character) {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		token.WriteRune(character)
	}
	if escaped {
		token.WriteByte('\\')
	}
	if quoted {
		return nil, errors.New("unterminated quote in search expression")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func expressionFilter(token string) (service.SearchFilter, bool, error) {
	negated := strings.HasPrefix(token, "-") && len(token) > 1
	if negated {
		token = token[1:]
	}
	name, value, found := strings.Cut(token, ":")
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	containsFields := map[string]string{
		"from": "from", "to": "to", "cc": "cc", "bcc": "bcc",
		"subject": "subject", "body": "body", "content": "content",
		"header": "header", "filename": "attachment", "attachment": "attachment",
		"attachmenttext": "attachmentcontent",
	}
	var filter service.SearchFilter
	switch {
	case found && containsFields[name] != "":
		if value == "" {
			return service.SearchFilter{}, true, fmt.Errorf("%s search requires a value", name)
		}
		filter = service.SearchFilter{Operator: service.SearchContains, Field: containsFields[name], Value: value}
	case found && (name == "after" || name == "before"):
		if value == "" {
			return service.SearchFilter{}, true, fmt.Errorf("%s search requires a date", name)
		}
		operator := service.SearchAfter
		if name == "before" {
			operator = service.SearchBefore
		}
		filter = service.SearchFilter{Operator: operator, Field: "date", Value: value}
	case found && name == "type":
		folderType := model.FolderType(strings.ToLower(value))
		switch folderType {
		case model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeTasks, model.FolderTypeContacts,
			model.FolderTypeFiles, model.FolderTypeNotes:
			filter = service.SearchFilter{Operator: service.SearchEquals, Field: "type", Value: string(folderType)}
		default:
			return service.SearchFilter{}, true, fmt.Errorf("unsupported search type %q", value)
		}
	case found && name == "has":
		if value != "attachment" && value != "attachments" {
			return service.SearchFilter{}, true, fmt.Errorf("unsupported has search %q", value)
		}
		filter = service.SearchFilter{Operator: service.SearchEquals, Field: "hasattachment", Value: "true"}
	case found && name == "is":
		var inner service.SearchFilter
		switch strings.ToLower(value) {
		case "read":
			inner = service.SearchFilter{Operator: service.SearchEquals, Field: "flag", Value: model.FlagSeen}
		case "unread":
			inner = notFilter(service.SearchFilter{Operator: service.SearchEquals, Field: "flag", Value: model.FlagSeen})
		case "flagged", "starred":
			inner = service.SearchFilter{Operator: service.SearchEquals, Field: "flag", Value: model.FlagFlagged}
		case "unflagged", "unstarred":
			inner = notFilter(service.SearchFilter{Operator: service.SearchEquals, Field: "flag", Value: model.FlagFlagged})
		case "trashed":
			inner = service.SearchFilter{Operator: service.SearchEquals, Field: "trashed", Value: "true"}
		case "attachment", "attachments":
			inner = service.SearchFilter{Operator: service.SearchEquals, Field: "hasattachment", Value: "true"}
		default:
			return service.SearchFilter{}, true, fmt.Errorf("unsupported is search %q", value)
		}
		filter = inner
	default:
		return service.SearchFilter{}, false, nil
	}
	if negated {
		filter = notFilter(filter)
	}
	return filter, true, nil
}

func notFilter(filter service.SearchFilter) service.SearchFilter {
	return service.SearchFilter{Operator: service.SearchNot, Children: []service.SearchFilter{filter}}
}
