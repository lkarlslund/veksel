package sieve

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Variable limits (RFC 5229 section 6 requires at least 128 variables of
// 4000 characters). Expansion output is capped so repeated references to a
// long variable cannot multiply memory use.
const (
	maxVariables       = 256
	maxVariableLength  = 16 << 10
	maxExpandedLength  = 64 << 10
	maxMatchVariables  = 10
	variableRefOpening = "${"
)

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isVariableName reports an RFC 5229 variable-name.
func isVariableName(name string) bool {
	if name == "" || !isAlpha(name[0]) && name[0] != '_' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if c := name[i]; !isAlpha(c) && !isDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

func isNumber(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isDigit(name[i]) {
			return false
		}
	}
	return true
}

// scanVariableRef parses a variable reference at s[start:], which begins
// with "${". It returns the reference name and the index after "}".
func scanVariableRef(s string, start int) (string, int, bool) {
	end := start + len(variableRefOpening)
	for end < len(s) && (isAlpha(s[end]) || isDigit(s[end]) || s[end] == '_' || s[end] == '.') {
		end++
	}
	if end >= len(s) || s[end] != '}' {
		return "", 0, false
	}
	name := s[start+len(variableRefOpening) : end]
	if isNumber(name) {
		return name, end + 1, true
	}
	for part := range strings.SplitSeq(name, ".") {
		if !isVariableName(part) {
			return "", 0, false
		}
	}
	return name, end + 1, true
}

// variableNamespace returns the namespace of the first namespaced variable
// reference in s; no namespace is supported.
func variableNamespace(s string) string {
	for i := strings.Index(s, variableRefOpening); i >= 0; {
		name, end, ok := scanVariableRef(s, i)
		if ok {
			if dot := strings.IndexByte(name, '.'); dot >= 0 {
				return name[:dot]
			}
		} else {
			end = i + len(variableRefOpening)
		}
		next := strings.Index(s[end:], variableRefOpening)
		if next < 0 {
			break
		}
		i = end + next
	}
	return ""
}

// expandVariables replaces variable references (RFC 5229 section 3).
// Unknown variables expand to the empty string; malformed references stay
// literal. The result is capped at maxExpandedLength bytes.
func expandVariables(s string, lookup func(name string) string) string {
	first := strings.Index(s, variableRefOpening)
	if first < 0 {
		return s
	}
	var b strings.Builder
	b.WriteString(s[:first])
	for i := first; i < len(s); {
		if b.Len() >= maxExpandedLength {
			break
		}
		if !strings.HasPrefix(s[i:], variableRefOpening) {
			next := strings.Index(s[i:], variableRefOpening)
			if next < 0 {
				next = len(s) - i
			}
			b.WriteString(s[i : i+next])
			i += next
			continue
		}
		name, end, ok := scanVariableRef(s, i)
		if !ok {
			b.WriteString(variableRefOpening)
			i += len(variableRefOpening)
			continue
		}
		b.WriteString(lookup(strings.ToLower(name)))
		i = end
	}
	return truncateUTF8(b.String(), maxExpandedLength)
}

// truncateUTF8 shortens s to at most limit bytes on a character boundary.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

// applySetModifiers applies set modifiers, already ordered by precedence.
func applySetModifiers(value string, modifiers []string) string {
	for _, modifier := range modifiers {
		switch modifier {
		case "lower":
			value = strings.ToLower(value)
		case "upper":
			value = strings.ToUpper(value)
		case "lowerfirst", "upperfirst":
			r, size := utf8.DecodeRuneInString(value)
			if size == 0 {
				continue
			}
			if modifier == "lowerfirst" {
				r = unicode.ToLower(r)
			} else {
				r = unicode.ToUpper(r)
			}
			value = string(r) + value[size:]
		case "quotewildcard":
			value = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`).Replace(value)
		case "encodeurl":
			value = encodeURL(value)
		case "length":
			value = strconv.Itoa(utf8.RuneCountInString(value))
		}
	}
	return value
}

// decodeEncodedCharacters expands "${hex:...}" and "${unicode:...}"
// sequences (RFC 5228 section 2.4.2.4). Malformed sequences stay literal;
// a Unicode value outside the scalar range is an error.
func decodeEncodedCharacters(s string) (string, error) {
	if !strings.Contains(s, variableRefOpening) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !strings.HasPrefix(s[i:], variableRefOpening) {
			b.WriteByte(s[i])
			i++
			continue
		}
		decoded, end, err := decodeEncodedSequence(s, i)
		if err != nil {
			return "", err
		}
		if end == 0 {
			b.WriteString(variableRefOpening)
			i += len(variableRefOpening)
			continue
		}
		b.WriteString(decoded)
		i = end
	}
	return b.String(), nil
}

func decodeEncodedSequence(s string, start int) (string, int, error) {
	rest := s[start+len(variableRefOpening):]
	kind := ""
	for _, prefix := range []string{"hex:", "unicode:"} {
		if len(rest) >= len(prefix) && strings.EqualFold(rest[:len(prefix)], prefix) {
			kind, rest = prefix[:len(prefix)-1], rest[len(prefix):]
		}
	}
	closing := strings.IndexByte(rest, '}')
	if kind == "" || closing < 0 {
		return "", 0, nil
	}
	end := len(s) - len(rest) + closing + 1
	fields := strings.FieldsFunc(rest[:closing], func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	if len(fields) == 0 {
		return "", 0, nil
	}
	var b strings.Builder
	for _, field := range fields {
		if kind == "hex" {
			if len(field)%2 != 0 {
				return "", 0, nil
			}
			for j := 0; j < len(field); j += 2 {
				value, err := strconv.ParseUint(field[j:j+2], 16, 8)
				if err != nil {
					return "", 0, nil
				}
				b.WriteByte(byte(value))
			}
			continue
		}
		if !isHex(field) {
			return "", 0, nil
		}
		value, err := strconv.ParseUint(field, 16, 64)
		if err != nil || value > unicode.MaxRune || value >= 0xD800 && value <= 0xDFFF {
			return "", 0, fmt.Errorf("unicode value %s out of range", field)
		}
		b.WriteRune(rune(value))
	}
	return b.String(), end, nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isDigit(c) && (c|0x20 < 'a' || c|0x20 > 'f') {
			return false
		}
	}
	return s != ""
}
