package calendar

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	ical "github.com/emersion/go-ical"
)

const (
	// maxParamValueBytes bounds one property parameter value. go-ical builds
	// parameter values a byte at a time by string concatenation, so their
	// decoding cost is quadratic in length; real values (CN, ALTREP, ...)
	// are far shorter.
	maxParamValueBytes = 1024
	// maxComponentDepth bounds BEGIN nesting. go-ical recurses once per
	// level; real calendars nest three or four levels deep.
	maxComponentDepth = 32
)

// Decoder decodes iCalendar objects from untrusted bytes. It wraps
// go-ical's decoder, which panics on some malformed parameter lists and
// degrades badly on others, so every content line is checked before
// go-ical sees it and any remaining panic is returned as an error.
type Decoder struct {
	decoder *ical.Decoder
	err     error
}

// NewDecoder returns a decoder over the iCalendar stream in data.
func NewDecoder(data []byte) *Decoder {
	if err := checkContentLines(data); err != nil {
		return &Decoder{err: fmt.Errorf("ical: %w", err)}
	}
	return &Decoder{decoder: ical.NewDecoder(bytes.NewReader(data))}
}

// Decode returns the next calendar object of the stream, or io.EOF after
// the last one.
func (d *Decoder) Decode() (cal *ical.Calendar, err error) {
	if d.err != nil {
		return nil, d.err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			cal, err = nil, fmt.Errorf("ical: malformed content: %v", recovered)
			d.err = err
		}
	}()
	return d.decoder.Decode()
}

// checkContentLines rejects content lines that go-ical would panic on or
// decode in super-linear time or stack depth. It unfolds lines the way
// go-ical does and mirrors its parameter grammar; lines go-ical rejects with
// an ordinary error are left for it to report.
func checkContentLines(data []byte) error {
	depth := 0
	check := func(line string) error {
		nameEnd := strings.IndexAny(line, ";:")
		if nameEnd <= 0 {
			return nil
		}
		name, rest := line[:nameEnd], line[nameEnd:]
		switch {
		case strings.EqualFold(name, "BEGIN"):
			if depth++; depth > maxComponentDepth {
				return fmt.Errorf("components nest deeper than %d levels", maxComponentDepth)
			}
		case strings.EqualFold(name, "END"):
			depth--
		}
		for strings.HasPrefix(rest, ";") {
			equals := strings.IndexByte(rest, '=')
			if equals <= 1 {
				return nil
			}
			rest = rest[equals+1:]
			for {
				var value string
				if strings.HasPrefix(rest, `"`) {
					end := strings.IndexByte(rest[1:], '"')
					if end < 0 {
						return nil
					}
					value, rest = rest[1:end+1], rest[end+2:]
				} else {
					end := strings.IndexAny(rest, "\";,:")
					if end < 0 {
						return errors.New("property parameter runs to the end of the line")
					}
					if rest[end] == '"' {
						return nil
					}
					value, rest = rest[:end], rest[end:]
				}
				if len(value) > maxParamValueBytes {
					return fmt.Errorf("property parameter value exceeds %d bytes", maxParamValueBytes)
				}
				if rest == "" {
					return errors.New("property parameter runs to the end of the line")
				}
				if rest[0] == ',' {
					rest = rest[1:]
					continue
				}
				if rest[0] != ';' && rest[0] != ':' {
					return fmt.Errorf("unexpected %q after a property parameter value", rest[0])
				}
				break
			}
		}
		return nil
	}

	var logical strings.Builder
	started := false
	for physical := range strings.SplitSeq(string(data), "\n") {
		physical = strings.TrimSuffix(physical, "\r")
		if started && (strings.HasPrefix(physical, " ") || strings.HasPrefix(physical, "\t")) {
			logical.WriteString(physical[1:])
			continue
		}
		if started {
			if err := check(logical.String()); err != nil {
				return err
			}
			logical.Reset()
		}
		logical.WriteString(physical)
		started = true
	}
	if started {
		return check(logical.String())
	}
	return nil
}
