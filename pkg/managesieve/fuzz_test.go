package managesieve

import (
	"bufio"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/service"
)

// FuzzCommandLine feeds client input through the bounded line reader, the
// command tokenizer and the literal-size parser. A literal may never be
// announced larger than the script size limit.
func FuzzCommandLine(f *testing.F) {
	for _, seed := range []string{
		"PUTSCRIPT \"vacation\" {42+}\r\n",
		"AUTHENTICATE \"PLAIN\" \"AGFsaWNlAHNlY3JldA==\"\r\n",
		"HAVESPACE \"x\\\"y\" 1000\r\n",
		"SETACTIVE \"\"\r\n",
		"\"unterminated\r\n",
		"{0+} {01+} {99999999999+}\r\n",
		strings.Repeat("A", 70000) + "\r\n",
		"no line ending",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		line, err := readProtocolLine(bufio.NewReader(strings.NewReader(input)))
		if err != nil {
			return
		}
		if len(line) > maxProtocolLineLength {
			t.Fatalf("read a %d byte line past the %d byte cap", len(line), maxProtocolLineLength)
		}
		args, err := parseLine(line)
		if err != nil {
			return
		}
		for _, arg := range args {
			if size, err := clientLiteralSize(arg); err == nil && (size < 0 || size > service.MaxScriptBytes) {
				t.Fatalf("literal %q announced %d bytes", arg, size)
			}
		}
	})
}
