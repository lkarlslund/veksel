package imap

import (
	"bytes"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
)

type bodyFetchRequest struct {
	section     string
	partialFrom int64
	partialSize int64
	partial     bool
}

func parseBodyFetch(token string) (bodyFetchRequest, bool, error) {
	upper := strings.ToUpper(token)
	var rest string
	switch {
	case strings.HasPrefix(upper, "BODY.PEEK["):
		rest = upper[len("BODY.PEEK["):]
	case strings.HasPrefix(upper, "BODY["):
		rest = upper[len("BODY["):]
	case strings.HasPrefix(upper, "BODYPEEK["):
		rest = upper[len("BODYPEEK["):]
	default:
		return bodyFetchRequest{}, false, nil
	}
	closeBracket := strings.IndexByte(rest, ']')
	if closeBracket < 0 {
		return bodyFetchRequest{}, true, fmt.Errorf("unterminated BODY section")
	}
	request := bodyFetchRequest{section: rest[:closeBracket]}
	tail := rest[closeBracket+1:]
	if tail == "" {
		return request, true, nil
	}
	if len(tail) < 5 || tail[0] != '<' || tail[len(tail)-1] != '>' {
		return bodyFetchRequest{}, true, fmt.Errorf("invalid BODY partial")
	}
	rangeParts := strings.Split(tail[1:len(tail)-1], ".")
	if len(rangeParts) != 2 {
		return bodyFetchRequest{}, true, fmt.Errorf("invalid BODY partial")
	}
	var err error
	request.partialFrom, err = strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil || request.partialFrom < 0 {
		return bodyFetchRequest{}, true, fmt.Errorf("invalid BODY partial origin")
	}
	request.partialSize, err = strconv.ParseInt(rangeParts[1], 10, 64)
	if err != nil || request.partialSize < 1 {
		return bodyFetchRequest{}, true, fmt.Errorf("invalid BODY partial size")
	}
	request.partial = true
	return request, true, nil
}

func bodySection(data []byte, section string) ([]byte, error) {
	path, specifier, err := parseBodySection(section)
	if err != nil {
		return nil, err
	}
	if len(path) == 0 {
		switch {
		case specifier == "":
			return data, nil
		case specifier == "HEADER":
			return extractHeaders(data), nil
		case specifier == "TEXT":
			return extractBody(data), nil
		case strings.HasPrefix(specifier, "HEADER.FIELDS"):
			return filteredHeaders(extractHeaders(data), specifier)
		default:
			return nil, fmt.Errorf("invalid BODY section %q", section)
		}
	}

	root, err := readMIMEEntity(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	entity, err := root.part(path)
	if err != nil {
		return nil, err
	}
	switch {
	case specifier == "":
		return entity.body, nil
	case specifier == "MIME":
		return formatMIMEHeader(entity.header), nil
	case specifier == "HEADER":
		return extractHeaders(entity.body), nil
	case specifier == "TEXT":
		return extractBody(entity.body), nil
	case strings.HasPrefix(specifier, "HEADER.FIELDS"):
		return filteredHeaders(extractHeaders(entity.body), specifier)
	default:
		return nil, fmt.Errorf("invalid BODY section %q", section)
	}
}

func parseBodySection(section string) ([]int, string, error) {
	if section == "" {
		return nil, "", nil
	}
	parts := strings.Split(section, ".")
	var path []int
	for len(parts) > 0 {
		number, err := strconv.Atoi(parts[0])
		if err != nil {
			break
		}
		if number < 1 {
			return nil, "", fmt.Errorf("invalid BODY part number")
		}
		path = append(path, number)
		parts = parts[1:]
	}
	return path, strings.Join(parts, "."), nil
}

func filteredHeaders(header []byte, specifier string) ([]byte, error) {
	not := strings.HasPrefix(specifier, "HEADER.FIELDS.NOT")
	prefix := "HEADER.FIELDS"
	if not {
		prefix = "HEADER.FIELDS.NOT"
	}
	list := strings.TrimSpace(strings.TrimPrefix(specifier, prefix))
	if len(list) < 2 || list[0] != '(' || list[len(list)-1] != ')' {
		return nil, fmt.Errorf("invalid header field list")
	}
	wanted := make(map[string]bool)
	for _, name := range strings.Fields(list[1 : len(list)-1]) {
		name = strings.Trim(name, "\"")
		if name != "" {
			wanted[strings.ToLower(name)] = true
		}
	}

	normalized := strings.ReplaceAll(string(header), "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(normalized, "\n\n"), "\n")
	var fields [][]string
	for _, line := range lines {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			fields[len(fields)-1] = append(fields[len(fields)-1], line)
			continue
		}
		fields = append(fields, []string{line})
	}
	var output strings.Builder
	for _, field := range fields {
		name, _, ok := strings.Cut(field[0], ":")
		selected := ok && wanted[strings.ToLower(strings.TrimSpace(name))]
		if selected == not {
			continue
		}
		output.WriteString(strings.Join(field, "\r\n"))
		output.WriteString("\r\n")
	}
	output.WriteString("\r\n")
	return []byte(output.String()), nil
}

func formatMIMEHeader(header mail.Header) []byte {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var output strings.Builder
	for _, key := range keys {
		for _, value := range header[key] {
			output.WriteString(key)
			output.WriteString(": ")
			output.WriteString(value)
			output.WriteString("\r\n")
		}
	}
	output.WriteString("\r\n")
	return []byte(output.String())
}
