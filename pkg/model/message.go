package model

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"slices"
	"strings"

	"golang.org/x/net/html/charset"
)

// SplitHeaderBody splits raw message bytes at the first blank line. The header
// block includes its terminating blank line, so head+body is the original
// message. Both CRLF and bare LF separators are accepted, whichever comes
// first. Without a separator the whole message is treated as headers and body
// is nil.
func SplitHeaderBody(data []byte) (head, body []byte) {
	// A message that opens with the blank line has no header fields; its
	// first line must not be mistaken for one.
	switch {
	case bytes.HasPrefix(data, []byte("\r\n")):
		return data[:2], data[2:]
	case bytes.HasPrefix(data, []byte("\n")):
		return data[:1], data[1:]
	}
	crlf := bytes.Index(data, []byte("\r\n\r\n"))
	lf := bytes.Index(data, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf < lf):
		return data[:crlf+4], data[crlf+4:]
	case lf >= 0:
		return data[:lf+2], data[lf+2:]
	default:
		return data, nil
	}
}

// BuildMessage serializes a header map and body as an RFC 5322 message, the
// inverse of ParseMessageHeaders. Header order follows map iteration, which
// is why signatures over the result use relaxed header canonicalization.
func BuildMessage(headers map[string]string, body []byte) []byte {
	var buf bytes.Buffer
	for name, value := range headers {
		writeHeaderField(&buf, name, value)
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// writeHeaderField writes one "name: value" field. Header maps carry values
// from users (vacation subjects, Sieve strings) and from parsed mail, so a
// line break that would start a new field is flattened to a space; a break
// followed by white space is a fold and is kept as CRLF.
func writeHeaderField(buf *bytes.Buffer, name, value string) {
	buf.WriteString(strings.NewReplacer("\r", "", "\n", "").Replace(name))
	buf.WriteString(": ")
	if !strings.ContainsAny(value, "\r\n") {
		buf.WriteString(value)
		buf.WriteString("\r\n")
		return
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\r' && c != '\n' {
			buf.WriteByte(c)
			continue
		}
		if c == '\r' && i+1 < len(value) && value[i+1] == '\n' {
			i++
		}
		if i+1 < len(value) && (value[i+1] == ' ' || value[i+1] == '\t') {
			buf.WriteString("\r\n")
		} else {
			buf.WriteByte(' ')
		}
	}
	buf.WriteString("\r\n")
}

// ParseMessageHeaders splits raw message bytes into headers and body. Header
// names keep their original case and the last value wins for duplicates. Use
// ParseHeaderValues when duplicates or case-insensitive lookup matter.
func ParseMessageHeaders(data []byte) (map[string]string, []byte) {
	head, body := SplitHeaderBody(data)
	headers := make(map[string]string)
	eachHeaderField(head, func(name, value string) { headers[name] = value })
	if body == nil {
		body = []byte{}
	}
	return headers, body
}

// ParseItemHeaders returns the header block of raw message bytes keyed by
// canonical MIME header name (for example "Message-Id"). The first value wins
// for duplicates, matching net/mail's Header.Get.
func ParseItemHeaders(data []byte) map[string]string {
	head, _ := SplitHeaderBody(data)
	headers := make(map[string]string)
	eachHeaderField(head, func(name, value string) {
		name = textproto.CanonicalMIMEHeaderKey(name)
		if _, ok := headers[name]; !ok {
			headers[name] = value
		}
	})
	return headers
}

// ParseHeaderValues returns every value of every header in the header block of
// raw message bytes, in message order, keyed by lowercase header name.
func ParseHeaderValues(data []byte) map[string][]string {
	head, _ := SplitHeaderBody(data)
	headers := make(map[string][]string)
	eachHeaderField(head, func(name, value string) {
		name = strings.ToLower(name)
		headers[name] = append(headers[name], value)
	})
	return headers
}

// eachHeaderField calls fn for every header field in head, with folded
// continuation lines unfolded into single-space-joined values. A continuation
// line is one starting with space or tab; it may itself contain colons. Lines
// without a colon that are not continuations are ignored.
func eachHeaderField(head []byte, fn func(name, value string)) {
	eachRawHeaderField(head, func(name, value string, _ []string) { fn(name, value) })
}

// eachRawHeaderField is eachHeaderField that also passes the field's
// original lines, without line terminators, so a caller can re-emit the
// field exactly as it arrived.
func eachRawHeaderField(head []byte, fn func(name, value string, lines []string)) {
	// The value is accumulated in a builder: concatenating each continuation
	// onto a string would copy the field once per folded line, quadratic in
	// a field folded over many short lines.
	name := ""
	var value strings.Builder
	var lines []string
	flush := func() {
		if name != "" {
			fn(name, value.String(), lines)
		}
		name, lines = "", nil
		value.Reset()
	}
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if name != "" {
				value.WriteByte(' ')
				value.WriteString(strings.TrimSpace(line))
				lines = append(lines, line)
			}
			continue
		}
		if colon := strings.IndexByte(line, ':'); colon > 0 {
			flush()
			name = strings.TrimSpace(line[:colon])
			value.WriteString(strings.TrimSpace(line[colon+1:]))
			lines = []string{line}
		}
	}
	flush()
}

// RebuildMessage serializes a header map and body like BuildMessage, but
// keeps the order, folding, and repeated occurrences of the fields of
// original, the raw message the map was parsed from. The map is an edit of
// original: a field whose name is absent from the map is dropped; a field
// whose map value still equals its last original value (the one
// ParseMessageHeaders keeps) is re-emitted unchanged with every occurrence,
// so repeated trace fields such as Received survive in order; a changed value
// replaces every occurrence at the position of the first one. Fields new to
// the map are prepended in name order, where RFC 5321 and RFC 8601 place
// fields added in transit.
func RebuildMessage(original []byte, headers map[string]string, body []byte) []byte {
	head, _ := SplitHeaderBody(original)
	current := make(map[string][]string, len(headers))
	for name := range headers {
		key := strings.ToLower(name)
		current[key] = append(current[key], name)
	}
	last := make(map[string]string)
	eachHeaderField(head, func(name, value string) { last[strings.ToLower(name)] = value })

	var out, kept bytes.Buffer
	emitted := make(map[string]bool, len(last))
	eachRawHeaderField(head, func(name, _ string, lines []string) {
		key := strings.ToLower(name)
		names := current[key]
		switch {
		case len(names) == 0:
		case len(names) == 1 && headers[names[0]] == last[key]:
			for _, line := range lines {
				kept.WriteString(line)
				kept.WriteString("\r\n")
			}
		case !emitted[key]:
			slices.Sort(names)
			for _, name := range names {
				writeHeaderField(&kept, name, headers[name])
			}
		}
		emitted[key] = true
	})
	var fresh []string
	for name := range headers {
		if _, present := last[strings.ToLower(name)]; !present {
			fresh = append(fresh, name)
		}
	}
	slices.Sort(fresh)
	for _, name := range fresh {
		writeHeaderField(&out, name, headers[name])
	}
	out.Write(kept.Bytes())
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes()
}

// ReplaceHeaderField returns message with every occurrence of the header
// field name replaced, at the position of the first one, by a single field
// with value. Other fields keep their order and folding.
func ReplaceHeaderField(message []byte, name, value string) []byte {
	head, body := SplitHeaderBody(message)
	var out bytes.Buffer
	replaced := false
	eachRawHeaderField(head, func(field, _ string, lines []string) {
		if !strings.EqualFold(field, name) {
			for _, line := range lines {
				out.WriteString(line)
				out.WriteString("\r\n")
			}
			return
		}
		if !replaced {
			writeHeaderField(&out, name, value)
			replaced = true
		}
	})
	if !replaced {
		writeHeaderField(&out, name, value)
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes()
}

// PrependHeaderField returns message with field, a complete and possibly
// folded header field without a trailing line break, above its existing
// header fields.
func PrependHeaderField(message []byte, field string) []byte {
	out := make([]byte, 0, len(field)+2+len(message))
	out = append(out, field...)
	out = append(out, "\r\n"...)
	return append(out, message...)
}

// HeaderWordDecoder decodes RFC 2047 encoded-words in any charset the WHATWG
// encoding index knows, such as Windows-1252 and ISO-8859-15, not only the
// UTF-8 and ISO-8859-1 the standard library decodes on its own.
var HeaderWordDecoder = &mime.WordDecoder{CharsetReader: charset.NewReaderLabel}

// DecodeHeaderValue decodes RFC 2047 encoded-words in a header value,
// returning the value unchanged when it cannot be decoded, for example
// because of an unknown charset.
func DecodeHeaderValue(value string) string {
	if !strings.Contains(value, "=?") {
		return value
	}
	decoded, err := HeaderWordDecoder.DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
}

// TransferDecoder wraps reader with the decoder for a Content-Transfer-Encoding
// value. Identity and unknown encodings return reader unchanged.
func TransferDecoder(reader io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		return quotedprintable.NewReader(reader)
	default:
		return reader
	}
}
