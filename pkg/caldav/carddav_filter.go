package caldav

import (
	"bytes"
	"strings"

	"github.com/emersion/go-vcard"
)

// cardPropFilter is a CARDDAV:prop-filter (RFC 6352 §10.5.1), which sits
// directly under CARDDAV:filter.
type cardPropFilter struct {
	Name         string            `xml:"name,attr"`
	Test         string            `xml:"test,attr"`
	IsNotDefined *empty            `xml:"urn:ietf:params:xml:ns:carddav is-not-defined"`
	TextMatches  []cardTextMatch   `xml:"urn:ietf:params:xml:ns:carddav text-match"`
	ParamFilters []cardParamFilter `xml:"urn:ietf:params:xml:ns:carddav param-filter"`
}

// cardParamFilter is a CARDDAV:param-filter (RFC 6352 §10.5.2).
type cardParamFilter struct {
	Name         string         `xml:"name,attr"`
	IsNotDefined *empty         `xml:"urn:ietf:params:xml:ns:carddav is-not-defined"`
	TextMatch    *cardTextMatch `xml:"urn:ietf:params:xml:ns:carddav text-match"`
}

// cardTextMatch is a CARDDAV:text-match (RFC 6352 §10.5.4).
type cardTextMatch struct {
	Value     string `xml:",chardata"`
	Collation string `xml:"collation,attr"`
	MatchType string `xml:"match-type,attr"`
	Negate    string `xml:"negate-condition,attr"`
}

// cardMatchesQuery applies an RFC 6352 filter to a vCard: its prop-filters
// combine with the filter's test (anyof by default) and each prop-filter's
// text-match and param-filter children with its own test. Apple Contacts,
// Evolution, and DAVx5 send this shape; it was ignored (only a non-standard
// comp-filter wrapper was understood), so every query returned the whole
// address book. A vCard that cannot be parsed matches.
func cardMatchesQuery(data []byte, filter *carddavFilter) bool {
	card, err := vcard.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return true
	}
	allOf := strings.EqualFold(filter.Test, "allof")
	for _, prop := range filter.PropFilters {
		matched := cardPropMatches(card, prop)
		if matched && !allOf {
			return true
		}
		if !matched && allOf {
			return false
		}
	}
	return allOf
}

func cardPropMatches(card vcard.Card, filter cardPropFilter) bool {
	fields := card[strings.ToUpper(strings.TrimSpace(filter.Name))]
	if filter.IsNotDefined != nil {
		return len(fields) == 0
	}
	if len(fields) == 0 {
		return false
	}
	allOf := strings.EqualFold(filter.Test, "allof")
	for _, field := range fields {
		var results []bool
		for _, match := range filter.TextMatches {
			results = append(results, match.matchesField(filter.Name, field.Value))
		}
		for _, param := range filter.ParamFilters {
			results = append(results, cardParamMatches(field, param))
		}
		if combine(results, allOf) {
			return true
		}
	}
	return false
}

func cardParamMatches(field *vcard.Field, filter cardParamFilter) bool {
	values := field.Params[strings.ToUpper(strings.TrimSpace(filter.Name))]
	if filter.IsNotDefined != nil {
		return len(values) == 0
	}
	if len(values) == 0 {
		return false
	}
	if filter.TextMatch == nil {
		return true
	}
	for _, value := range values {
		if filter.TextMatch.matches(value) {
			return true
		}
	}
	return false
}

// combine applies a test to the children's results; no children match.
func combine(results []bool, allOf bool) bool {
	if len(results) == 0 {
		return true
	}
	for _, result := range results {
		if result && !allOf {
			return true
		}
		if !result && allOf {
			return false
		}
	}
	return allOf
}

// matchesField applies the text-match to a property value; CATEGORIES is
// matched per category.
func (m cardTextMatch) matchesField(name, value string) bool {
	if !strings.EqualFold(strings.TrimSpace(name), "CATEGORIES") {
		return m.matches(value)
	}
	negated := strings.EqualFold(strings.TrimSpace(m.Negate), "yes")
	positive := m
	positive.Negate = ""
	for category := range strings.SplitSeq(value, ",") {
		if positive.matches(strings.TrimSpace(category)) {
			return !negated
		}
	}
	return negated
}

// matches applies the match-type (contains by default) under the collation
// (case-insensitive unless i;octet), honoring negate-condition.
func (m cardTextMatch) matches(value string) bool {
	needle := m.Value
	if !strings.EqualFold(strings.TrimSpace(m.Collation), "i;octet") {
		value, needle = strings.ToLower(value), strings.ToLower(needle)
	}
	var found bool
	switch strings.ToLower(strings.TrimSpace(m.MatchType)) {
	case "equals":
		found = value == needle
	case "starts-with":
		found = strings.HasPrefix(value, needle)
	case "ends-with":
		found = strings.HasSuffix(value, needle)
	default:
		found = strings.Contains(value, needle)
	}
	if strings.EqualFold(strings.TrimSpace(m.Negate), "yes") {
		return !found
	}
	return found
}
