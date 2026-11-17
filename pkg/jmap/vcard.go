package jmap

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/lkarlslund/veksel/pkg/model"
)

// vcardProp is one vCard content line with its parameters kept in order, so
// cards round-trip semantically through JSContact conversion.
type vcardProp struct {
	group  string
	name   string // upper-case property name
	spelt  string // original spelling of the name, kept on output
	params []vcardParam
	value  string // raw, still escaped
}

type vcardParam struct {
	name   string // upper-case
	values []string
}

type vcardDoc struct{ props []*vcardProp }

const maxVCardSize = 4 << 20

// parseVCard decodes a single vCard (3.0 or 4.0). BEGIN and END are implied
// by the document and not kept as properties.
func parseVCard(data []byte) (*vcardDoc, error) {
	if len(data) > maxVCardSize {
		return nil, errors.New("vCard is too large")
	}
	raw := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	logical := model.UnfoldContentLines(strings.Split(raw, "\n"), func(line string) bool { return strings.TrimSpace(line) != "" })
	doc := &vcardDoc{}
	begun, ended := false, false
	for _, line := range logical {
		prop, err := parseVCardContentLine(line)
		if err != nil {
			return nil, err
		}
		switch {
		case prop.name == "BEGIN" && strings.EqualFold(prop.value, "VCARD") && !begun:
			begun = true
		case prop.name == "END" && strings.EqualFold(prop.value, "VCARD") && begun:
			ended = true
		case !begun || ended:
			return nil, errors.New("content outside BEGIN:VCARD/END:VCARD")
		default:
			doc.props = append(doc.props, prop)
		}
	}
	if !begun || !ended {
		return nil, errors.New("vCard must start with BEGIN:VCARD and end with END:VCARD")
	}
	return doc, nil
}

func parseVCardContentLine(line string) (*vcardProp, error) {
	colon, inQuote := -1, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case ':':
			if !inQuote {
				colon = i
			}
		}
		if colon >= 0 {
			break
		}
	}
	if colon < 1 {
		return nil, errors.New("invalid vCard content line")
	}
	head, value := line[:colon], line[colon+1:]
	parts := splitOutsideQuotes(head, ';')
	prop := &vcardProp{name: strings.ToUpper(parts[0]), spelt: parts[0], value: value}
	// The group dot is located in the original spelling: upper-casing can
	// change byte lengths, so an index into prop.name may not fit parts[0].
	if dot := strings.LastIndex(parts[0], "."); dot >= 0 {
		prop.group, prop.spelt = parts[0][:dot], parts[0][dot+1:]
		prop.name = strings.ToUpper(prop.spelt)
	}
	if prop.name == "" {
		return nil, errors.New("invalid vCard property name")
	}
	for _, raw := range parts[1:] {
		name, values, hasValue := strings.Cut(raw, "=")
		param := vcardParam{name: strings.ToUpper(strings.TrimSpace(name))}
		if !hasValue {
			// vCard 3.0 bare TYPE values ("TEL;WORK:...").
			param = vcardParam{name: "TYPE", values: []string{name}}
		} else {
			for _, v := range splitOutsideQuotes(values, ',') {
				param.values = append(param.values, strings.Trim(v, `"`))
			}
		}
		prop.params = append(prop.params, param)
	}
	return prop, nil
}

func splitOutsideQuotes(value string, separator byte) []string {
	var parts []string
	start, inQuote := 0, false
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '"':
			inQuote = !inQuote
		case separator:
			if !inQuote {
				parts = append(parts, value[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, value[start:])
}

func (d *vcardDoc) version() string {
	for _, prop := range d.props {
		if prop.name == "VERSION" {
			return strings.TrimSpace(prop.value)
		}
	}
	return "3.0"
}

// encode serializes the card with VERSION first and folded lines.
func (d *vcardDoc) encode() []byte {
	var out strings.Builder
	out.WriteString("BEGIN:VCARD\r\n")
	writeFolded(&out, "VERSION:"+d.version())
	for _, prop := range d.props {
		if prop.name != "VERSION" {
			writeFolded(&out, prop.line())
		}
	}
	out.WriteString("END:VCARD\r\n")
	return []byte(out.String())
}

func (p *vcardProp) line() string {
	var b strings.Builder
	if p.group != "" {
		b.WriteString(p.group + ".")
	}
	if strings.EqualFold(p.spelt, p.name) {
		b.WriteString(p.spelt)
	} else {
		b.WriteString(p.name)
	}
	for _, param := range p.params {
		b.WriteString(";" + param.name + "=")
		for i, v := range param.values {
			if i > 0 {
				b.WriteByte(',')
			}
			if strings.ContainsAny(v, ";:,") {
				v = `"` + strings.ReplaceAll(v, `"`, "'") + `"`
			}
			b.WriteString(v)
		}
	}
	b.WriteString(":" + p.value)
	return b.String()
}

// writeFolded writes one content line folded at 75 octets without splitting
// UTF-8 sequences (RFC 6350 §3.2).
func writeFolded(out *strings.Builder, line string) {
	limit := 75
	for len(line) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(line[cut]) {
			cut--
		}
		out.WriteString(line[:cut] + "\r\n ")
		line = line[cut:]
		limit = 74
	}
	out.WriteString(line + "\r\n")
}

func (p *vcardProp) clone() *vcardProp {
	c := *p
	c.params = make([]vcardParam, len(p.params))
	for i, param := range p.params {
		c.params[i] = vcardParam{name: param.name, values: append([]string(nil), param.values...)}
	}
	return &c
}

// paramValues returns every value of a parameter across repeated occurrences.
func (p *vcardProp) paramValues(name string) []string {
	var values []string
	for _, param := range p.params {
		if param.name == name {
			values = append(values, param.values...)
		}
	}
	return values
}

func (p *vcardProp) param(name string) string {
	values := p.paramValues(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// setParam replaces a parameter; no values removes it.
func (p *vcardProp) setParam(name string, values ...string) {
	kept := p.params[:0]
	index := -1
	for _, param := range p.params {
		if param.name == name {
			if index < 0 {
				index = len(kept)
				kept = append(kept, param)
			}
			continue
		}
		kept = append(kept, param)
	}
	p.params = kept
	switch {
	case len(values) == 0 && index >= 0:
		p.params = append(p.params[:index], p.params[index+1:]...)
	case len(values) > 0 && index >= 0:
		p.params[index].values = values
	case len(values) > 0:
		p.params = append(p.params, vcardParam{name: name, values: values})
	}
}

func (p *vcardProp) hasType(value string) bool {
	for _, t := range p.paramValues("TYPE") {
		if strings.EqualFold(t, value) {
			return true
		}
	}
	return false
}

func (p *vcardProp) text() string { return unescapeVCard(p.value) }

// components splits a structured value into components and their
// comma-separated values, unescaped.
func (p *vcardProp) components() [][]string {
	var out [][]string
	for _, component := range splitEscaped(p.value, ';') {
		var values []string
		for _, v := range splitEscaped(component, ',') {
			values = append(values, unescapeVCard(v))
		}
		out = append(out, values)
	}
	return out
}

func splitEscaped(value string, separator byte) []string {
	var parts []string
	var current strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			current.WriteByte(value[i])
			current.WriteByte(value[i+1])
			i++
			continue
		}
		if value[i] == separator {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(value[i])
	}
	return append(parts, current.String())
}

func unescapeVCard(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
			switch value[i] {
			case 'n', 'N':
				b.WriteByte('\n')
			default:
				b.WriteByte(value[i])
			}
			continue
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

var vcardEscaper = strings.NewReplacer(`\`, `\\`, "\r\n", `\n`, "\n", `\n`, ",", `\,`, ";", `\;`)

func escapeVCard(value string) string { return vcardEscaper.Replace(value) }

// structuredValue encodes components whose values are comma lists.
func structuredValue(components [][]string) string {
	parts := make([]string, len(components))
	for i, values := range components {
		escaped := make([]string, len(values))
		for j, v := range values {
			escaped[j] = escapeVCard(v)
		}
		parts[i] = strings.Join(escaped, ",")
	}
	return strings.Join(parts, ";")
}
