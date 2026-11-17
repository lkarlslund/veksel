package imap

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var errInvalidMailboxName = errors.New("invalid mailbox name")

// Keep the protocol capability behind the conformance gate. The codecs and
// dual-mode behavior can be completed and tested without inviting clients to
// rely on an incomplete RFC 9051 implementation.
const imap4rev2Available = true

// encodeModifiedUTF7 encodes a Unicode mailbox name using IMAP's canonical
// modified UTF-7 representation. Printable US-ASCII is emitted directly,
// except ampersand, which is represented by "&-".
func encodeModifiedUTF7(value string) (string, error) {
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", errInvalidMailboxName
	}

	var encoded strings.Builder
	var unicodeRun []rune
	flushUnicode := func() {
		if len(unicodeRun) == 0 {
			return
		}
		units := utf16.Encode(unicodeRun)
		bytes := make([]byte, len(units)*2)
		for index, unit := range units {
			binary.BigEndian.PutUint16(bytes[index*2:], unit)
		}
		chunk := base64.RawStdEncoding.EncodeToString(bytes)
		encoded.WriteByte('&')
		encoded.WriteString(strings.ReplaceAll(chunk, "/", ","))
		encoded.WriteByte('-')
		unicodeRun = unicodeRun[:0]
	}

	for _, character := range value {
		if character >= 0x20 && character <= 0x7e {
			flushUnicode()
			if character == '&' {
				encoded.WriteString("&-")
			} else {
				encoded.WriteRune(character)
			}
			continue
		}
		unicodeRun = append(unicodeRun, character)
	}
	flushUnicode()
	return encoded.String(), nil
}

// decodeModifiedUTF7 accepts only canonical modified UTF-7. Rejecting encoded
// printable ASCII, padding, malformed UTF-16, and alternate encodings keeps
// mailbox identity unambiguous across clients.
func decodeModifiedUTF7(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errInvalidMailboxName
	}

	var decoded strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '&' {
			if value[index] < 0x20 || value[index] > 0x7e {
				return "", errInvalidMailboxName
			}
			decoded.WriteByte(value[index])
			index++
			continue
		}

		end := strings.IndexByte(value[index:], '-')
		if end < 0 {
			return "", errInvalidMailboxName
		}
		end += index
		chunk := value[index+1 : end]
		if chunk == "" {
			decoded.WriteByte('&')
			index = end + 1
			continue
		}
		if strings.ContainsRune(chunk, '=') {
			return "", errInvalidMailboxName
		}
		bytes, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(chunk, ",", "/"))
		if err != nil || len(bytes) == 0 || len(bytes)%2 != 0 {
			return "", errInvalidMailboxName
		}
		units := make([]uint16, len(bytes)/2)
		for unitIndex := range units {
			units[unitIndex] = binary.BigEndian.Uint16(bytes[unitIndex*2:])
		}
		if !validUTF16(units) {
			return "", errInvalidMailboxName
		}
		for _, character := range utf16.Decode(units) {
			if character >= 0x20 && character <= 0x7e {
				return "", errInvalidMailboxName
			}
			decoded.WriteRune(character)
		}
		index = end + 1
	}

	result := decoded.String()
	canonical, err := encodeModifiedUTF7(result)
	if err != nil || canonical != value {
		return "", errInvalidMailboxName
	}
	return result, nil
}

func validUTF16(units []uint16) bool {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 == len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return false
			}
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return false
		}
	}
	return true
}

func decodeUTF8Mailbox(value string) (string, error) {
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", errInvalidMailboxName
	}
	return norm.NFC.String(value), nil
}

func quoteIMAPString(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%w: unsafe quoted string", errInvalidMailboxName)
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`, nil
}

// utf8MailboxNames reports whether mailbox names travel as UTF-8 rather
// than modified UTF-7: under IMAP4rev2, or after ENABLE UTF8=ACCEPT
// (RFC 6855 3).
func (s *Session) utf8MailboxNames() bool {
	return s.rev2Enabled || s.utf8Accept
}

func (s *Session) mailboxFromWire(value string) (string, error) {
	if s.utf8MailboxNames() {
		return decodeUTF8Mailbox(value)
	}
	return decodeModifiedUTF7(value)
}

func (s *Session) mailboxToWire(value string) string {
	var encoded string
	var err error
	if s.utf8MailboxNames() {
		encoded, err = decodeUTF8Mailbox(value)
	} else {
		encoded, err = encodeModifiedUTF7(value)
	}
	if err != nil {
		return `""`
	}
	quoted, err := quoteIMAPString(encoded)
	if err != nil {
		return `""`
	}
	return quoted
}

// normalizeMailboxArguments is the single wire-to-folder boundary for IMAP.
// Command handlers and the folder abstraction only ever receive normalized
// Unicode paths, irrespective of the negotiated protocol revision.
func (s *Session) normalizeMailboxArguments(command string, args []string) ([]string, error) {
	var positions []int
	switch command {
	case "LSUB", "RENAME":
		positions = []int{0, 1}
	case "CREATE", "DELETE", "SUBSCRIBE", "UNSUBSCRIBE", "SELECT", "EXAMINE",
		"GETACL", "MYRIGHTS", "GETMETADATA", "SETMETADATA", "APPEND", "STATUS", "GETQUOTAROOT":
		positions = []int{0}
	case "SETACL", "DELETEACL":
		positions = []int{0}
	case "COPY", "MOVE":
		positions = []int{1}
	case "UID":
		if len(args) >= 3 && (strings.EqualFold(args[0], "COPY") || strings.EqualFold(args[0], "MOVE")) {
			positions = []int{2}
		}
	}
	if len(positions) == 0 {
		return args, nil
	}
	normalized := append([]string(nil), args...)
	for _, position := range positions {
		if position >= len(normalized) {
			continue
		}
		value, err := s.mailboxFromWire(normalized[position])
		if err != nil {
			return nil, err
		}
		normalized[position] = value
	}
	return normalized, nil
}
