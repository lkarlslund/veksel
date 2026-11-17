package imap

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxCommandLiteralSize bounds one literal in a command other than APPEND,
// whose message literals are streamed by their own bounded reader.
const maxCommandLiteralSize = 64 * 1024

// errLiteralProtocol reports a literal the client sent without waiting for a
// continuation that Veksel cannot accept; the rest of the stream cannot be
// interpreted, so the session ends.
var errLiteralProtocol = errors.New("non-synchronizing literal exceeds the server's limit")

// literalCommandError is a literal that was read but cannot be used; the
// command is answered BAD and the session continues.
type literalCommandError struct{ reason string }

func (e literalCommandError) Error() string { return e.reason }

// readCommandLiterals completes a command line that ends with a literal
// (RFC 3501 4.3, RFC 7888 LITERAL+): each literal is read, after a
// continuation request when it is synchronizing, and spliced back into the
// line as a quoted string, so the command parsers see one line. Clients send
// LOGIN this way whenever the password holds 8-bit or special characters
// (quoted strings are 7-bit), and use literals for mailbox names too.
// APPEND and SEARCH read their own literals.
func (s *Session) readCommandLiterals(line string) (string, error) {
	if !commandSplicesLiterals(line) {
		return line, nil
	}
	unusable := false
	for {
		marker, size, nonSynchronizing, err := trailingLiteral(line)
		if err != nil {
			if unusable {
				return "", literalCommandError{"literal contains CR, LF, or NUL"}
			}
			return line, nil
		}
		if size > maxCommandLiteralSize {
			if nonSynchronizing {
				return "", errLiteralProtocol
			}
			return "", literalCommandError{fmt.Sprintf("literal exceeds %d bytes", maxCommandLiteralSize)}
		}
		if !nonSynchronizing {
			s.sendContinuation("Ready for literal data")
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(s.rw, data); err != nil {
			return "", err
		}
		rest, err := s.readLine()
		if err != nil {
			return "", err
		}
		// Data that cannot be quoted is still consumed, with any further
		// literals of the command, before the command is refused.
		quoted, ok := quoteLiteralValue(data)
		if !ok {
			unusable, quoted = true, `""`
		}
		// Each literal is capped, but a command may chain them without
		// end; the spliced line is bounded like any command line.
		if len(line[:marker])+len(quoted)+len(rest) > maxCommandLineLength {
			return "", errCommandLineTooLong
		}
		line = line[:marker] + quoted + rest
	}
}

// trailingLiteral finds the literal announced at the end of line, if any,
// and returns the offset of its opening brace.
func trailingLiteral(line string) (marker int, size int64, nonSynchronizing bool, err error) {
	marker = strings.LastIndexByte(line, '{')
	if marker < 0 || !strings.HasSuffix(line, "}") {
		return -1, 0, false, errors.New("no literal")
	}
	// A literal8 (RFC 3516) opens with "~{"; its octets are read the same
	// way, and splicing one into a command other than APPEND leaves a
	// stray "~" that the command parser refuses.
	start := marker
	if start > 0 && line[start-1] == '~' {
		start--
	}
	if start > 0 && line[start-1] != ' ' && line[start-1] != '(' {
		return -1, 0, false, errors.New("no literal")
	}
	size, nonSynchronizing, err = parseLiteralSize(line[marker:])
	return marker, size, nonSynchronizing, err
}

// unreadLiteral is a literal a command announced but has not read yet.
type unreadLiteral struct {
	size             int64
	nonSynchronizing bool
	pending          bool
	// limit bounds the octets of the literal and the rest of its command
	// that may be skipped: the most the command itself would have read.
	limit int64
}

// expectLiteral records the literal announced at the end of a line of a
// command that reads its own literals (APPEND, SEARCH). The command clears
// it when it reads the literal; one it leaves unread is discarded before the
// next command, so literal content is never taken for a command. limit is
// the most the command would read of its literals (see unreadLiteral).
func (s *Session) expectLiteral(line string, limit int64) {
	s.unreadLiteral = unreadLiteral{}
	if _, size, nonSynchronizing, err := trailingLiteral(line); err == nil {
		s.unreadLiteral = unreadLiteral{size: size, nonSynchronizing: nonSynchronizing, pending: true, limit: max(limit, 0)}
	}
}

// literalLimit is the most a command that reads its own literals accepts of
// them: the APPEND message limit, or the SEARCH literal budget.
func (s *Session) literalLimit(line string) int64 {
	if commandName(line) == "APPEND" {
		return s.appendLiteralLimit() + maxCommandLineLength
	}
	return maxSearchLiteralSize
}

// appendLiteralLimit is the configured APPEND message size limit.
func (s *Session) appendLiteralLimit() int64 {
	if s.cfg.MaxLiteralSize > 0 {
		return s.cfg.MaxLiteralSize
	}
	return DefaultMaxLiteralSize
}

// discardUnreadLiteral skips the literal a refused command left in the
// input, and any literals the rest of its line chains to. A synchronizing
// literal was never sent, since the command was answered without a
// continuation request. A non-synchronizing literal is already on its way
// and must be skipped (RFC 7888 LITERAL+); one, or a chain of them, larger
// than the command would have read ends the session (errLiteralProtocol).
func (s *Session) discardUnreadLiteral() error {
	budget := s.unreadLiteral.limit
	for s.unreadLiteral.pending {
		literal := s.unreadLiteral
		s.unreadLiteral = unreadLiteral{}
		if !literal.nonSynchronizing {
			return nil
		}
		if literal.size > budget {
			return errLiteralProtocol
		}
		budget -= literal.size
		if _, err := io.CopyN(io.Discard, s.rw.Reader, literal.size); err != nil {
			return err
		}
		rest, err := s.readLine()
		if err != nil {
			return err
		}
		if budget -= int64(len(rest)); budget < 0 {
			return errLiteralProtocol
		}
		s.expectLiteral(rest, budget)
	}
	return nil
}

// commandSplicesLiterals reports whether the command on line takes its
// literals through readCommandLiterals.
func commandSplicesLiterals(line string) bool {
	command := commandName(line)
	return command != "" && command != "APPEND" && command != "SEARCH"
}

// commandName returns the upper-cased command of a tagged command line, the
// one after UID for UID commands, or "" when the line has none.
func commandName(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	command := strings.ToUpper(fields[1])
	if command == "UID" && len(fields) > 2 {
		command = strings.ToUpper(fields[2])
	}
	return command
}

// quoteLiteralValue renders literal data as an IMAP quoted string. Data with
// CR, LF, or NUL cannot be quoted and is not valid in the commands that use
// this path (credentials, mailbox names, annotation values).
func quoteLiteralValue(data []byte) (string, bool) {
	var quoted strings.Builder
	quoted.Grow(len(data) + 2)
	quoted.WriteByte('"')
	for _, character := range data {
		switch character {
		case '\r', '\n', 0:
			return "", false
		case '"', '\\':
			quoted.WriteByte('\\')
		}
		quoted.WriteByte(character)
	}
	quoted.WriteByte('"')
	return quoted.String(), true
}
