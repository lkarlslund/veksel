package imap

import (
	"errors"
	"fmt"
	"strings"
)

type listRequest struct {
	Reference      string
	Patterns       []string
	Select         map[string]bool
	Return         map[string]bool
	ReturnStatus   []string
	ExtendedSyntax bool
}

func parseListRequest(args []string) (listRequest, error) {
	request := listRequest{Select: make(map[string]bool), Return: make(map[string]bool)}
	index := 0
	if index < len(args) && strings.HasPrefix(args[index], "(") {
		values, next, err := consumeParenthesized(args, index)
		if err != nil {
			return request, fmt.Errorf("LIST selection options: %w", err)
		}
		request.ExtendedSyntax = true
		for _, value := range values {
			option := strings.ToUpper(value)
			switch option {
			case "SUBSCRIBED", "RECURSIVEMATCH", "SPECIAL-USE":
				request.Select[option] = true
			default:
				return request, fmt.Errorf("unsupported LIST selection option %s", value)
			}
		}
		index = next
	}
	if len(args)-index < 2 {
		return request, errors.New("expected reference name and mailbox pattern")
	}
	request.Reference = args[index]
	index++
	if strings.HasPrefix(args[index], "(") {
		patterns, next, err := consumeParenthesized(args, index)
		if err != nil || len(patterns) == 0 {
			return request, errors.New("invalid mailbox pattern list")
		}
		for patternIndex := range patterns {
			patterns[patternIndex] = stripQuotes(patterns[patternIndex])
		}
		request.Patterns = patterns
		request.ExtendedSyntax = true
		index = next
	} else {
		request.Patterns = []string{args[index]}
		index++
	}
	if index == len(args) {
		if request.Select["RECURSIVEMATCH"] && !request.Select["SUBSCRIBED"] {
			return request, errors.New("RECURSIVEMATCH requires SUBSCRIBED")
		}
		return request, nil
	}
	if !strings.EqualFold(args[index], "RETURN") {
		return request, fmt.Errorf("unexpected LIST argument %s", args[index])
	}
	index++
	values, next, err := consumeParenthesized(args, index)
	if err != nil || next != len(args) {
		return request, errors.New("invalid LIST RETURN options")
	}
	request.ExtendedSyntax = true
	for valueIndex := 0; valueIndex < len(values); valueIndex++ {
		option := strings.ToUpper(values[valueIndex])
		switch option {
		case "SUBSCRIBED", "CHILDREN", "SPECIAL-USE":
			request.Return[option] = true
		case "STATUS":
			request.Return[option] = true
			valueIndex++
			if valueIndex >= len(values) || values[valueIndex] != "(" {
				return request, errors.New("STATUS requires a parenthesized data item list")
			}
			for valueIndex++; valueIndex < len(values) && values[valueIndex] != ")"; valueIndex++ {
				statusItem := strings.ToUpper(values[valueIndex])
				if !validStatusItem(statusItem) {
					return request, fmt.Errorf("unsupported STATUS data item %s", statusItem)
				}
				request.ReturnStatus = append(request.ReturnStatus, statusItem)
			}
			if valueIndex >= len(values) || len(request.ReturnStatus) == 0 {
				return request, errors.New("invalid STATUS data item list")
			}
		default:
			return request, fmt.Errorf("unsupported LIST RETURN option %s", values[valueIndex])
		}
	}
	if request.Select["RECURSIVEMATCH"] && !request.Select["SUBSCRIBED"] {
		return request, errors.New("RECURSIVEMATCH requires SUBSCRIBED")
	}
	return request, nil
}

// consumeParenthesized returns individual atoms while retaining nested list
// delimiters as "(" and ")" tokens. That is sufficient for LIST's one nested
// STATUS list without replacing command-specific parsers wholesale.
func consumeParenthesized(args []string, start int) ([]string, int, error) {
	if start >= len(args) || !strings.HasPrefix(args[start], "(") {
		return nil, start, errors.New("expected opening parenthesis")
	}
	var values []string
	depth := 0
	for index := start; index < len(args); index++ {
		token := args[index]
		var atom strings.Builder
		flush := func() {
			if atom.Len() > 0 {
				values = append(values, atom.String())
				atom.Reset()
			}
		}
		for _, character := range token {
			switch character {
			case '(':
				flush()
				if depth > 0 {
					values = append(values, "(")
				}
				depth++
			case ')':
				flush()
				depth--
				if depth < 0 {
					return nil, start, errors.New("unexpected closing parenthesis")
				}
				if depth > 0 {
					values = append(values, ")")
				}
			default:
				atom.WriteRune(character)
			}
		}
		flush()
		if depth == 0 {
			return values, index + 1, nil
		}
	}
	return nil, start, errors.New("unterminated parenthesized list")
}

func validStatusItem(value string) bool {
	switch value {
	// RECENT is IMAP4rev1 (Thunderbird asks for it on every folder check);
	// HIGHESTMODSEQ is CONDSTORE (RFC 7162 3.1.8).
	case "MESSAGES", "RECENT", "UIDNEXT", "UIDVALIDITY", "UNSEEN", "DELETED", "SIZE", "MAILBOXID", "HIGHESTMODSEQ":
		return true
	default:
		return false
	}
}
