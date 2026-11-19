package ews

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

// compileAQS compiles a FindItem QueryString in Advanced Query Syntax:
// free terms and "phrases", property terms such as subject:invoice,
// from:"Ann Example" or received:>=2026-11-01, joined by AND, OR, NOT and
// parentheses, with AND implied between adjacent terms. Text matches are
// case-insensitive substrings. A date without a time is a whole day in the
// mailbox's zone. An unknown property fails the request instead of being
// read as text.
func compileAQS(query string, zone *time.Location) (predicate, error) {
	if zone == nil {
		zone = time.UTC
	}
	tokens, err := tokenizeAQS(query)
	if err != nil {
		return nil, err
	}
	p := &aqsParser{tokens: tokens, zone: zone}
	filter, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("%w: unexpected %q in query string", errInvalidRestriction, p.tokens[p.pos].text)
	}
	return filter, nil
}

type aqsToken struct {
	text   string
	quoted bool // the token starts with a quote: a phrase, never a keyword
	open   bool
	close  bool
}

func tokenizeAQS(query string) ([]aqsToken, error) {
	var tokens []aqsToken
	runes := []rune(query)
	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '(':
			tokens = append(tokens, aqsToken{text: "(", open: true})
			i++
		case r == ')':
			tokens = append(tokens, aqsToken{text: ")", close: true})
			i++
		default:
			var text strings.Builder
			quoted := r == '"'
			for i < len(runes) && !unicode.IsSpace(runes[i]) && runes[i] != '(' && runes[i] != ')' {
				if runes[i] != '"' {
					text.WriteRune(runes[i])
					i++
					continue
				}
				end := slices.Index(runes[i+1:], '"')
				if end < 0 {
					return nil, fmt.Errorf("%w: unterminated quote in query string", errInvalidRestriction)
				}
				text.WriteString(string(runes[i+1 : i+1+end]))
				i += end + 2
			}
			if i < len(runes) && runes[i] == '(' && strings.HasSuffix(text.String(), ":") {
				return nil, fmt.Errorf("%w: grouped property values such as %s(...) are not supported", errInvalidRestriction, text.String())
			}
			tokens = append(tokens, aqsToken{text: text.String(), quoted: quoted})
		}
	}
	return tokens, nil
}

type aqsParser struct {
	tokens []aqsToken
	pos    int
	zone   *time.Location
}

func (p *aqsParser) keyword(word string) bool {
	if p.pos < len(p.tokens) && !p.tokens[p.pos].quoted && p.tokens[p.pos].text == word {
		p.pos++
		return true
	}
	return false
}

func (p *aqsParser) or() (predicate, error) {
	first, err := p.and()
	if err != nil {
		return nil, err
	}
	parts := []predicate{first}
	for p.keyword("OR") {
		next, err := p.and()
		if err != nil {
			return nil, err
		}
		parts = append(parts, next)
	}
	if len(parts) == 1 {
		return first, nil
	}
	return anyOf(parts), nil
}

func (p *aqsParser) and() (predicate, error) {
	var parts []predicate
	for {
		p.keyword("AND")
		if p.pos >= len(p.tokens) || p.tokens[p.pos].close || (!p.tokens[p.pos].quoted && p.tokens[p.pos].text == "OR") {
			break
		}
		part, err := p.unary()
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: a search term is missing in the query string", errInvalidRestriction)
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return allOf(parts), nil
}

func (p *aqsParser) unary() (predicate, error) {
	if p.keyword("NOT") {
		inner, err := p.unary()
		if err != nil {
			return nil, err
		}
		return func(f *itemFacts) bool { return !inner(f) }, nil
	}
	token := p.tokens[p.pos]
	p.pos++
	if token.open {
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.tokens) || !p.tokens[p.pos].close {
			return nil, fmt.Errorf("%w: unbalanced parentheses in query string", errInvalidRestriction)
		}
		p.pos++
		return inner, nil
	}
	if token.close {
		return nil, fmt.Errorf("%w: unbalanced parentheses in query string", errInvalidRestriction)
	}
	text := token.text
	if !token.quoted && strings.HasPrefix(text, "-") && len(text) > 1 {
		inner, err := p.term(text[1:], false)
		if err != nil {
			return nil, err
		}
		return func(f *itemFacts) bool { return !inner(f) }, nil
	}
	return p.term(text, token.quoted)
}

// term compiles one free term or property:value term.
func (p *aqsParser) term(text string, quoted bool) (predicate, error) {
	name, value, isProperty := strings.Cut(text, ":")
	if quoted || !isProperty || !isAQSName(name) {
		return freeText(text), nil
	}
	name = strings.ToLower(name)
	switch name {
	case "subject", "title":
		return textTerm(value, "item:Subject")
	case "from":
		return textTerm(value, "message:From", "message:Sender")
	case "to":
		return textTerm(value, "message:ToRecipients")
	case "cc":
		return textTerm(value, "message:CcRecipients")
	case "participants":
		return textTerm(value, "message:From", "message:ToRecipients", "message:CcRecipients")
	case "category", "categories":
		return textTerm(value, "item:Categories")
	case "importance":
		return textTerm(value, "item:Importance")
	case "body":
		want := strings.ToLower(value)
		return func(f *itemFacts) bool { return strings.Contains(strings.ToLower(f.body()), want) }, nil
	case "received", "sent":
		uri := "item:DateTimeReceived"
		if name == "sent" {
			uri = "item:DateTimeSent"
		}
		return dateTerm(queryFields[uri], value, p.zone)
	case "hasattachment", "hasattachments", "hasattach":
		want, ok := map[string]bool{"true": true, "yes": true, "false": false, "no": false}[strings.ToLower(value)]
		if !ok {
			return nil, fmt.Errorf("%w: %s takes true or false", errInvalidRestriction, name)
		}
		field := queryFields["item:HasAttachments"]
		return func(f *itemFacts) bool {
			values := f.values(field)
			return len(values) > 0 && strings.EqualFold(values[0], "true") == want
		}, nil
	case "kind":
		prefixes, ok := aqsKinds[strings.ToLower(value)]
		if !ok {
			return nil, fmt.Errorf("%w: unknown kind %q", errInvalidRestriction, value)
		}
		field := queryFields["item:ItemClass"]
		return func(f *itemFacts) bool {
			values := f.values(field)
			return len(values) > 0 && slices.ContainsFunc(prefixes, func(prefix string) bool {
				return strings.HasPrefix(strings.ToLower(values[0]), prefix)
			})
		}, nil
	}
	return nil, fmt.Errorf("%w: unsupported query string property %q", errInvalidRestriction, name)
}

var aqsKinds = map[string][]string{
	"email":    {"ipm.note"},
	"meetings": {"ipm.appointment", "ipm.schedule"},
	"calendar": {"ipm.appointment"},
	"contacts": {"ipm.contact"},
	"tasks":    {"ipm.task"},
}

func isAQSName(name string) bool {
	return name != "" && strings.IndexFunc(name, func(r rune) bool { return !unicode.IsLetter(r) }) < 0
}

// freeText matches subject, people, body and attachment names.
func freeText(text string) predicate {
	want := strings.ToLower(text)
	fields := []queryField{queryFields["item:Subject"], queryFields["message:From"], queryFields["message:ToRecipients"], queryFields["message:CcRecipients"]}
	return func(f *itemFacts) bool {
		for _, field := range fields {
			for _, value := range f.values(field) {
				if strings.Contains(strings.ToLower(value), want) {
					return true
				}
			}
		}
		return strings.Contains(strings.ToLower(f.body()), want)
	}
}

func textTerm(value string, uris ...string) (predicate, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: a property term needs a value", errInvalidRestriction)
	}
	if strings.ContainsAny(value[:1], "<>=") {
		return nil, fmt.Errorf("%w: %s takes text, not a comparison", errInvalidRestriction, uris[0])
	}
	want := strings.ToLower(value)
	return func(f *itemFacts) bool {
		for _, uri := range uris {
			for _, got := range f.values(queryFields[uri]) {
				if strings.Contains(strings.ToLower(got), want) {
					return true
				}
			}
		}
		return false
	}, nil
}

// dateTerm compiles received:VALUE with an optional comparison or a
// FROM..TO range. A bare date names the whole day.
func dateTerm(field queryField, value string, zone *time.Location) (predicate, error) {
	if from, to, isRange := strings.Cut(value, ".."); isRange {
		low, err := parseAQSDate(from, zone)
		if err != nil {
			return nil, err
		}
		high, err := parseAQSDate(to, zone)
		if err != nil {
			return nil, err
		}
		return timeTest(field, func(at time.Time) bool { return !at.Before(low.start) && at.Before(high.end) }), nil
	}
	operator := ""
	for _, candidate := range []string{">=", "<=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(value, candidate); ok {
			operator, value = candidate, rest
			break
		}
	}
	bound, err := parseAQSDate(value, zone)
	if err != nil {
		return nil, err
	}
	switch operator {
	case ">=":
		return timeTest(field, func(at time.Time) bool { return !at.Before(bound.start) }), nil
	case ">":
		return timeTest(field, func(at time.Time) bool { return !at.Before(bound.end) }), nil
	case "<":
		return timeTest(field, func(at time.Time) bool { return at.Before(bound.start) }), nil
	case "<=":
		return timeTest(field, func(at time.Time) bool { return at.Before(bound.end) }), nil
	}
	return timeTest(field, func(at time.Time) bool { return !at.Before(bound.start) && at.Before(bound.end) }), nil
}

func timeTest(field queryField, test func(time.Time) bool) predicate {
	return func(f *itemFacts) bool {
		values := f.values(field)
		if len(values) == 0 {
			return false
		}
		at, err := time.Parse(time.RFC3339, values[0])
		return err == nil && test(at)
	}
}

// aqsDate is the span a date value names: one instant for a timestamp,
// [midnight, next midnight) for a day.
type aqsDate struct{ start, end time.Time }

func parseAQSDate(value string, zone *time.Location) (aqsDate, error) {
	if at, err := time.Parse(time.RFC3339, value); err == nil {
		return aqsDate{at, at.Add(time.Nanosecond)}, nil
	}
	var day time.Time
	switch strings.ToLower(value) {
	case "today":
		now := time.Now().In(zone)
		day = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, zone)
	case "yesterday":
		now := time.Now().In(zone)
		day = time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, zone)
	default:
		parsed, err := time.ParseInLocation(time.DateOnly, value, zone)
		if err != nil {
			return aqsDate{}, fmt.Errorf("%w: %q is not a YYYY-MM-DD date or RFC 3339 timestamp", errInvalidRestriction, value)
		}
		day = parsed
	}
	return aqsDate{day, day.AddDate(0, 0, 1)}, nil
}
