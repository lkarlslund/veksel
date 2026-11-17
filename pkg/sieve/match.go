package sieve

import (
	"strings"
	"unicode/utf8"
)

// asciiFold lower-cases ASCII letters only (i;ascii-casemap, RFC 4790
// section 9.2). It keeps every byte offset, so positions found in the
// folded string index the original.
func asciiFold(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// numericCompare orders two strings under i;ascii-numeric (RFC 4790
// section 9.1): the value is the leading decimal digits, and a string that
// does not start with a digit is positive infinity.
func numericCompare(a, b string) int {
	digits := func(s string) (string, bool) {
		end := 0
		for end < len(s) && isDigit(s[end]) {
			end++
		}
		if end == 0 {
			return "", true
		}
		trimmed := strings.TrimLeft(s[:end], "0")
		return trimmed, false
	}
	da, infA := digits(a)
	db, infB := digits(b)
	switch {
	case infA && infB:
		return 0
	case infA:
		return 1
	case infB:
		return -1
	case len(da) != len(db):
		if len(da) < len(db) {
			return -1
		}
		return 1
	}
	return strings.Compare(da, db)
}

// order compares a and b with the matcher's comparator.
func (m Matcher) order(a, b string) int {
	switch m.Comparator {
	case ComparatorOctet:
		return strings.Compare(a, b)
	case ComparatorASCIINumeric:
		return numericCompare(a, b)
	}
	return strings.Compare(asciiFold(a), asciiFold(b))
}

func relationHolds(relation string, order int) bool {
	switch relation {
	case "gt":
		return order > 0
	case "ge":
		return order >= 0
	case "lt":
		return order < 0
	case "le":
		return order <= 0
	case "eq":
		return order == 0
	case "ne":
		return order != 0
	}
	return false
}

// matchValue reports whether value matches key for :is, :contains,
// :matches, and :value. A successful :matches also returns the match
// variables: the whole value followed by the text of each wildcard.
func (m Matcher) matchValue(value, key string) (bool, []string) {
	if m.Match == MatchValue {
		return relationHolds(m.Relation, m.order(value, key)), nil
	}
	if m.Comparator == ComparatorASCIINumeric {
		// Only equality is defined; parsing rejects substring matches.
		return numericCompare(value, key) == 0, nil
	}
	folded, foldedKey := value, key
	if m.Comparator != ComparatorOctet {
		folded, foldedKey = asciiFold(value), asciiFold(key)
	}
	switch m.Match {
	case MatchContains:
		return strings.Contains(folded, foldedKey), nil
	case MatchMatches:
		return wildcardMatch(value, folded, foldedKey, m.Comparator == ComparatorOctet)
	}
	return folded == foldedKey, nil
}

// wildElem is a literal run or, when any is set, a "?" wildcard.
type wildElem struct {
	lit string
	any bool
}

// parseWildcard splits a :matches pattern at its "*" wildcards into
// segments of literals and "?" wildcards (RFC 5228 section 2.7.1). A
// backslash makes the next character literal.
func parseWildcard(pattern string) [][]wildElem {
	segments := [][]wildElem{nil}
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			last := len(segments) - 1
			segments[last] = append(segments[last], wildElem{lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			flush()
			segments = append(segments, nil)
		case '?':
			flush()
			last := len(segments) - 1
			segments[last] = append(segments[last], wildElem{any: true})
		case '\\':
			if i+1 < len(pattern) {
				_, size := utf8.DecodeRuneInString(pattern[i+1:])
				lit.WriteString(pattern[i+1 : i+1+size])
				i += size
				continue
			}
			lit.WriteByte(c)
		default:
			lit.WriteByte(c)
		}
	}
	flush()
	return segments
}

// wildcardMatcher matches one value against parsed segments. In octet mode
// "?" matches one octet; otherwise it matches one UTF-8 character.
type wildcardMatcher struct {
	value string // the value compared, folded for i;ascii-casemap
	octet bool
}

func (w wildcardMatcher) step(pos int) int {
	if w.octet {
		return 1
	}
	_, size := utf8.DecodeRuneInString(w.value[pos:])
	return size
}

func (w wildcardMatcher) stepBack(pos int) int {
	if w.octet {
		return 1
	}
	_, size := utf8.DecodeLastRuneInString(w.value[:pos])
	return size
}

// at matches segment at pos and returns its end; captures, when non-nil,
// receives the span of each "?".
func (w wildcardMatcher) at(segment []wildElem, pos int, captures *[][2]int) (int, bool) {
	for _, elem := range segment {
		if elem.any {
			if pos >= len(w.value) {
				return 0, false
			}
			next := pos + w.step(pos)
			if captures != nil {
				*captures = append(*captures, [2]int{pos, next})
			}
			pos = next
			continue
		}
		if !strings.HasPrefix(w.value[pos:], elem.lit) {
			return 0, false
		}
		pos += len(elem.lit)
	}
	return pos, true
}

// atEnd finds where segment must start to end at the end of the value,
// starting no earlier than from.
func (w wildcardMatcher) atEnd(segment []wildElem, from int) (int, bool) {
	pos := len(w.value)
	for i := len(segment) - 1; i >= 0; i-- {
		elem := segment[i]
		if elem.any {
			if pos <= from {
				return 0, false
			}
			pos -= w.stepBack(pos)
			continue
		}
		if !strings.HasSuffix(w.value[:pos], elem.lit) {
			return 0, false
		}
		pos -= len(elem.lit)
	}
	return pos, pos >= from
}

// find locates the leftmost occurrence of segment at or after from.
func (w wildcardMatcher) find(segment []wildElem, from int) (int, int, bool) {
	for pos := from; pos <= len(w.value); {
		if !segment[0].any {
			index := strings.Index(w.value[pos:], segment[0].lit)
			if index < 0 {
				return 0, 0, false
			}
			pos += index
		}
		if end, ok := w.at(segment, pos, nil); ok {
			return pos, end, true
		}
		if pos == len(w.value) {
			break
		}
		pos += w.step(pos)
	}
	return 0, 0, false
}

// wildcardMatch matches folded against the folded pattern. Each "*"
// matches as little as possible, leftmost first, except that the last one
// absorbs what the final segment leaves (RFC 5229 section 3.2). Literal
// segments are located with strings.Index, so matching never backtracks
// exponentially: every segment is placed once.
func wildcardMatch(value, folded, pattern string, octet bool) (bool, []string) {
	segments := parseWildcard(pattern)
	w := wildcardMatcher{value: folded, octet: octet}
	if len(segments) == 1 {
		var questions [][2]int
		end, ok := w.at(segments[0], 0, &questions)
		if !ok || end != len(folded) {
			return false, nil
		}
		return true, matchCaptures(value, questions)
	}
	starts := make([]int, len(segments))
	ends := make([]int, len(segments))
	end, ok := w.at(segments[0], 0, nil)
	if !ok {
		return false, nil
	}
	ends[0] = end
	for i := 1; i < len(segments)-1; i++ {
		if len(segments[i]) == 0 {
			starts[i], ends[i] = end, end
			continue
		}
		start, segmentEnd, found := w.find(segments[i], end)
		if !found {
			return false, nil
		}
		starts[i], ends[i], end = start, segmentEnd, segmentEnd
	}
	last := len(segments) - 1
	start, ok := w.atEnd(segments[last], end)
	if !ok {
		return false, nil
	}
	starts[last], ends[last] = start, len(folded)
	var spans [][2]int
	for i, segment := range segments {
		if i > 0 {
			spans = append(spans, [2]int{ends[i-1], starts[i]})
		}
		_, _ = w.at(segment, starts[i], &spans)
	}
	return true, matchCaptures(value, spans)
}

func matchCaptures(value string, spans [][2]int) []string {
	captures := []string{value}
	for _, span := range spans {
		if len(captures) == maxMatchVariables {
			break
		}
		captures = append(captures, value[span[0]:span[1]])
	}
	return captures
}
