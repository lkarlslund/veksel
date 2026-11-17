package caldav

import (
	"bytes"
	"slices"
	"strings"

	ical "github.com/emersion/go-ical"
)

// propFilter is a CALDAV:prop-filter (RFC 4791 §9.7.2).
type propFilter struct {
	Name         string        `xml:"name,attr"`
	IsNotDefined *empty        `xml:"urn:ietf:params:xml:ns:caldav is-not-defined"`
	TextMatch    *textMatch    `xml:"urn:ietf:params:xml:ns:caldav text-match"`
	ParamFilters []paramFilter `xml:"urn:ietf:params:xml:ns:caldav param-filter"`
}

// paramFilter is a CALDAV:param-filter (RFC 4791 §9.7.3).
type paramFilter struct {
	Name         string     `xml:"name,attr"`
	IsNotDefined *empty     `xml:"urn:ietf:params:xml:ns:caldav is-not-defined"`
	TextMatch    *textMatch `xml:"urn:ietf:params:xml:ns:caldav text-match"`
}

// textMatch is a CALDAV:text-match (RFC 4791 §9.7.5): a substring match,
// case-insensitive under the default i;ascii-casemap collation.
type textMatch struct {
	Value     string `xml:",chardata"`
	Collation string `xml:"collation,attr"`
	Negate    string `xml:"negate-condition,attr"`
}

// hasPropertyFilters reports whether a comp-filter tree holds prop-filters
// or is-not-defined tests, which need the object to be parsed.
func hasPropertyFilters(filter *compFilter) bool {
	if filter == nil {
		return false
	}
	if filter.IsNotDefined != nil || len(filter.PropFilters) > 0 {
		return true
	}
	for index := range filter.CompFilters {
		if hasPropertyFilters(&filter.CompFilters[index]) {
			return true
		}
	}
	return false
}

// objectMatchesPropertyFilters applies the comp-filter tree under the
// VCALENDAR filter to a calendar object: prop-filters with is-not-defined,
// text-match, and param-filter, and component is-not-defined. Time ranges
// are applied separately; an object that cannot be parsed matches.
// Evolution and python caldav search with these filters, which were
// ignored, so every search returned the whole collection.
func objectMatchesPropertyFilters(data []byte, calendarFilter *compFilter) bool {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return true
	}
	return componentMatchesFilter(cal.Component, calendarFilter)
}

// componentMatchesFilter tests one component against its comp-filter.
func componentMatchesFilter(component *ical.Component, filter *compFilter) bool {
	for _, prop := range filter.PropFilters {
		if !propertyMatches(component, prop) {
			return false
		}
	}
	for index := range filter.CompFilters {
		child := &filter.CompFilters[index]
		name := strings.ToUpper(strings.TrimSpace(child.Name))
		var candidates []*ical.Component
		for _, nested := range component.Children {
			if nested.Name == name {
				candidates = append(candidates, nested)
			}
		}
		// RFC 4791 §9.7.1: is-not-defined matches an absent component;
		// otherwise some instance must satisfy the nested filters. Nested
		// time ranges (VALARM) are not evaluated and match.
		if child.IsNotDefined != nil {
			if len(candidates) > 0 {
				return false
			}
			continue
		}
		if !slices.ContainsFunc(candidates, func(candidate *ical.Component) bool { return componentMatchesFilter(candidate, child) }) {
			return false
		}
	}
	return true
}

// propertyMatches applies one prop-filter to a component.
func propertyMatches(component *ical.Component, filter propFilter) bool {
	props := component.Props[strings.ToUpper(strings.TrimSpace(filter.Name))]
	if filter.IsNotDefined != nil {
		return len(props) == 0
	}
	if len(props) == 0 {
		return false
	}
	for _, prop := range props {
		if filter.TextMatch != nil && !filter.TextMatch.matches(prop.Value) {
			continue
		}
		if parametersMatch(prop, filter.ParamFilters) {
			return true
		}
	}
	return false
}

func parametersMatch(prop ical.Prop, filters []paramFilter) bool {
	for _, filter := range filters {
		values := prop.Params[strings.ToUpper(strings.TrimSpace(filter.Name))]
		if filter.IsNotDefined != nil {
			if len(values) > 0 {
				return false
			}
			continue
		}
		if len(values) == 0 {
			return false
		}
		if filter.TextMatch != nil {
			matched := false
			for _, value := range values {
				if filter.TextMatch.matches(value) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

// matches applies the text-match to a property or parameter value.
func (m *textMatch) matches(value string) bool {
	needle := m.Value
	if !strings.EqualFold(strings.TrimSpace(m.Collation), "i;octet") {
		value, needle = strings.ToLower(value), strings.ToLower(needle)
	}
	found := strings.Contains(value, needle)
	if strings.EqualFold(strings.TrimSpace(m.Negate), "yes") {
		return !found
	}
	return found
}
