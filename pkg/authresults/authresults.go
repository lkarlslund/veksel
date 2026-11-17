// Package authresults builds bounded Authentication-Results field values.
package authresults

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maxResults    = 12
	maxProperties = 16
	maxValueBytes = 512
	// maxHeaderBytes bounds the whole folded value.
	maxHeaderBytes = 8192
	// foldWidth is the RFC 5322 section 2.1.1 recommended line length. The
	// field is folded between results and properties to stay within it, so
	// no element, at most a few hundred octets, can push a line past the
	// 998-octet limit.
	foldWidth = 78
	// fieldPrefix is the length of "Authentication-Results: ", which shares
	// the first line.
	fieldPrefix = len("Authentication-Results: ")
)

type Property struct {
	Name  string
	Value string
}

type Result struct {
	Method     string
	Result     string
	Reason     string
	Properties []Property
}

// Build returns an RFC 8601-style field value without the field name. All
// externally derived values are control-character checked and safely quoted.
// The value is folded (CRLF and a tab) between elements once a line would
// exceed foldWidth; unfolding restores single spaces.
func Build(authservID string, results []Result) (string, error) {
	authservID = strings.ToLower(strings.TrimSpace(authservID))
	if !validDottedToken(authservID) || len(authservID) > 255 {
		return "", errors.New("invalid authentication service identifier")
	}
	if len(results) > maxResults {
		return "", errors.New("too many authentication results")
	}
	output := folder{line: fieldPrefix}
	output.WriteString(authservID)
	for _, result := range results {
		method, outcome := strings.ToLower(strings.TrimSpace(result.Method)), strings.ToLower(strings.TrimSpace(result.Result))
		if !validToken(method) || !validToken(outcome) {
			return "", errors.New("invalid authentication method or result")
		}
		if len(result.Properties) > maxProperties {
			return "", fmt.Errorf("too many %s properties", method)
		}
		output.WriteString(";")
		output.element(method + "=" + outcome)
		if result.Reason != "" {
			encoded, err := encodeValue(result.Reason)
			if err != nil {
				return "", fmt.Errorf("%s reason: %w", method, err)
			}
			output.element("reason=" + encoded)
		}
		for _, property := range result.Properties {
			name := strings.ToLower(strings.TrimSpace(property.Name))
			if !validDottedToken(name) || !strings.Contains(name, ".") {
				return "", fmt.Errorf("invalid %s property name", method)
			}
			encoded, err := encodeValue(property.Value)
			if err != nil {
				return "", fmt.Errorf("%s %s: %w", method, name, err)
			}
			output.element(name + "=" + encoded)
		}
		if output.Len() > maxHeaderBytes {
			return "", errors.New("authentication results exceed header limit")
		}
	}
	return output.String(), nil
}

// folder accumulates a field value, tracking the current line's length.
type folder struct {
	strings.Builder
	line int
}

func (f *folder) WriteString(s string) {
	f.Builder.WriteString(s)
	f.line += len(s)
}

// element appends one white-space separated element, folding first when
// it would not fit on the current line.
func (f *folder) element(s string) {
	if f.line+1+len(s) > foldWidth {
		f.Builder.WriteString("\r\n\t")
		f.line = 1
	} else {
		f.Builder.WriteByte(' ')
		f.line++
	}
	f.WriteString(s)
}

func encodeValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxValueBytes || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid authentication property value")
	}
	if validDottedToken(value) {
		return value, nil
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`, nil
}

func validDottedToken(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !validToken(part) {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}
