package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

// FuzzSMTPCommand feeds client command lines into the command splitter and
// the MAIL and RCPT path and parameter parsers.
func FuzzSMTPCommand(f *testing.F) {
	for _, seed := range []string{
		"EHLO example.com",
		"HELO example.com",
		"MAIL FROM:<sender@example.com>",
		"MAIL FROM:<sender@example.com> BODY=8BITMIME SMTPUTF8 SIZE=1024 RET=HDRS ENVID=a+2Bb",
		"MAIL FROM:<> REQUIRETLS",
		"RCPT TO:<recipient@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a+40b.example",
		"RCPT TO: <a@b> NOTIFY=NEVER,DELAY",
		"DATA",
		"BDAT 1024 LAST",
		"BDAT 9223372036854775808",
		"AUTH PLAIN AGVzZXIAcGFzc3dvcmQ=",
		"VRFY user@example.com",
		"",
		"\x00\xff\xfe",
		strings.Repeat("A", 10000),
		"MAIL FROM:",
		"RCPT TO:<unterminated",
		"MAIL FROM:<a@b> SIZE=-1 SIZE=2",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		s := &Session{}
		cmd, arg := s.parseCommand(input)
		_ = strings.ToUpper(cmd)
		_ = commandStartsMessageData(input)
		_ = endsPipelineGroup(strings.ToUpper(cmd))
		if size, _, err := parseBDATArgument(arg); err == nil && size < 0 {
			t.Fatalf("negative BDAT size %d from %q", size, arg)
		}
		path := arg
		if upper := strings.ToUpper(arg); strings.HasPrefix(upper, "FROM:") || strings.HasPrefix(upper, "TO:") {
			_, path, _ = strings.Cut(arg, ":")
		}
		if address, parameters, err := splitSMTPPathParameters(path); err == nil {
			_ = validateEmailAddress(address)
			_ = extractDomainFromAddress(address)
			_, _, _, _ = parseMailParameters(parameters, 1<<20)
			_, _ = parseRecipientParameters(parameters)
		}
		_, _ = parseReply(input)
	})
}

// FuzzDataBody feeds a client DATA stream into the dot-unstuffing reader. A
// decoded body must use CRLF line endings only, and re-encoding it must
// decode to the same bytes.
func FuzzDataBody(f *testing.F) {
	for _, seed := range []string{
		"Subject: x\r\n\r\nhello\r\n.\r\n",
		"..leading dot\r\n.\r\n",
		"bare\nlf\r\n.\r\n",
		"a\r\n.\nb\r\n.\r\n",
		"a\n.\r\n",
		".\r\n",
		"no terminator",
		"\r\r\n.\r\n",
		strings.Repeat("x", 100) + "\r\n.\r\n",
	} {
		f.Add([]byte(seed), int64(0))
		f.Add([]byte(seed), int64(16))
	}

	read := func(input []byte, limit int64) ([]byte, error) {
		s := &Session{cfg: &Config{MaxMessageSize: limit}}
		s.rw = bufio.NewReadWriter(bufio.NewReaderSize(bytes.NewReader(input), 16), bufio.NewWriter(&bytes.Buffer{}))
		return s.readDataBody()
	}
	f.Fuzz(func(t *testing.T, input []byte, limit int64) {
		body, err := read(input, limit)
		if errors.Is(err, errDataTooLarge) && limit <= 0 {
			t.Fatalf("size limit reported without a limit")
		}
		if err != nil {
			return
		}
		if limit > 0 && int64(len(body)) > 2*limit {
			t.Fatalf("decoded %d bytes past a %d byte limit", len(body), limit)
		}
		for index, character := range body {
			if character == '\n' && (index == 0 || body[index-1] != '\r') {
				t.Fatalf("decoded body has a bare LF at %d: %q", index, body)
			}
		}
		var encoded bytes.Buffer
		for line := range bytes.SplitSeq(bytes.TrimSuffix(body, []byte("\r\n")), []byte("\r\n")) {
			if len(body) == 0 {
				break
			}
			if bytes.HasPrefix(line, []byte(".")) {
				encoded.WriteByte('.')
			}
			encoded.Write(line)
			encoded.WriteString("\r\n")
		}
		encoded.WriteString(".\r\n")
		again, err := read(encoded.Bytes(), 0)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatalf("re-encoded body %q decoded to %q (%v)", body, again, err)
		}
	})
}
