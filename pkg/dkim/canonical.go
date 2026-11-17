package dkim

import (
	"bytes"
	"strings"
)

// headerField is one raw header field: its lower-case name and its exact
// text, folding included, with the terminating CRLF.
type headerField struct {
	key string
	raw string
}

// value returns the field body after the colon, folding included.
func (f headerField) value() string {
	_, value, _ := strings.Cut(f.raw, ":")
	return strings.TrimSuffix(value, "\r\n")
}

// splitMessage returns message's header fields in order and its body, with
// every line ending normalized to CRLF as signatures are computed over.
func splitMessage(message []byte) ([]headerField, []byte) {
	if bytes.Contains(message, []byte("\n")) && bytes.Count(message, []byte("\n")) != bytes.Count(message, []byte("\r\n")) {
		message = bytes.ReplaceAll(bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	}
	// Each field's raw text is accumulated in a byte slice: appending every
	// continuation line to a string would copy the field once per line,
	// quadratic in a header folded over many short lines.
	var fields []headerField
	var raw [][]byte
	finish := func() []headerField {
		for index := range fields {
			fields[index].raw = string(raw[index])
		}
		return fields
	}
	rest := message
	for len(rest) > 0 {
		end := bytes.Index(rest, []byte("\r\n"))
		if end < 0 {
			end = len(rest)
		}
		line := rest[:end]
		next := min(end+2, len(rest))
		if len(line) == 0 {
			return finish(), rest[next:]
		}
		if (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			raw[len(raw)-1] = append(append(raw[len(raw)-1], line...), '\r', '\n')
		} else if name, _, ok := bytes.Cut(line, []byte(":")); ok {
			fields = append(fields, headerField{key: strings.ToLower(strings.TrimRight(string(name), " \t"))})
			raw = append(raw, append(append([]byte(nil), line...), '\r', '\n'))
		}
		rest = rest[next:]
	}
	return finish(), nil
}

// canonicalHeader applies RFC 6376 section 3.4 header canonicalization to a
// raw field; the result ends in CRLF.
func canonicalHeader(raw string, relaxed bool) string {
	if !relaxed {
		return raw
	}
	name, value, _ := strings.Cut(raw, ":")
	value = strings.Join(strings.FieldsFunc(strings.NewReplacer("\r\n", "", "\r", "", "\n", "").Replace(value), isWSP), " ")
	return strings.ToLower(strings.TrimRight(name, " \t")) + ":" + value + "\r\n"
}

// isWSP reports RFC 5234 white space; other Unicode spaces are content.
func isWSP(r rune) bool { return r == ' ' || r == '\t' }

// canonicalBody applies RFC 6376 section 3.4 body canonicalization.
func canonicalBody(body []byte, relaxed bool) []byte {
	lines := strings.Split(string(body), "\r\n")
	// A body ending in CRLF splits into a trailing empty element.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if relaxed {
		for i, line := range lines {
			fields := strings.FieldsFunc(line, isWSP)
			collapsed := strings.Join(fields, " ")
			if len(fields) > 0 && (line[0] == ' ' || line[0] == '\t') {
				collapsed = " " + collapsed
			}
			lines[i] = collapsed
		}
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		if relaxed {
			return nil
		}
		return []byte("\r\n")
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// stripSignature returns a raw signature field with the value of its b= tag
// deleted, surrounding whitespace included, as RFC 6376 section 3.7 hashes
// it. Only a tag named exactly b is touched, never bh= or a base64 value
// that happens to contain "b=".
func stripSignature(raw string) string {
	name, value, _ := strings.Cut(raw, ":")
	trailing := ""
	if strings.HasSuffix(value, "\r\n") {
		value, trailing = strings.TrimSuffix(value, "\r\n"), "\r\n"
	}
	parts := strings.Split(value, ";")
	for i, part := range parts {
		tag, _, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(tag) == "b" {
			parts[i] = part[:strings.Index(part, "=")+1]
		}
	}
	return name + ":" + strings.Join(parts, ";") + trailing
}

// selectHeaders returns the fields named by names in RFC 6376 section 5.4.2
// order: each name takes the bottom-most instance not yet taken, and a name
// with no remaining instance contributes nothing.
func selectHeaders(fields []headerField, names []string) []headerField {
	used := make(map[string]int)
	var selected []headerField
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		seen := 0
		for i := len(fields) - 1; i >= 0; i-- {
			if fields[i].key != name {
				continue
			}
			if seen == used[name] {
				selected = append(selected, fields[i])
				used[name]++
				break
			}
			seen++
		}
	}
	return selected
}

// foldBase64 folds a base64 tag value so signature fields stay within line
// length limits; relaxed canonicalization and tag parsing ignore the folds.
func foldBase64(value string) string {
	const width = 72
	var out strings.Builder
	for len(value) > width {
		out.WriteString(value[:width])
		out.WriteString("\r\n\t ")
		value = value[width:]
	}
	out.WriteString(value)
	return out.String()
}
