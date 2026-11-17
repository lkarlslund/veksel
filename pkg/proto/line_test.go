package proto

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

type endlessReader struct{}

func (endlessReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}

// TestReadBoundedLine checks that an endless line fails at the cap instead
// of growing in memory, and that ordinary lines are returned whole.
func TestReadBoundedLine(t *testing.T) {
	reader := bufio.NewReaderSize(io.MultiReader(strings.NewReader("USER alice\r\n"), endlessReader{}), 16)
	line, err := ReadBoundedLine(reader, MaxLineLength)
	if err != nil || line != "USER alice\r\n" {
		t.Fatalf("first line %q, %v", line, err)
	}
	if _, err := ReadBoundedLine(reader, MaxLineLength); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("endless line returned %v", err)
	}
	if line, err := ReadBoundedLine(bufio.NewReader(strings.NewReader("tail")), MaxLineLength); line != "tail" || err != io.EOF {
		t.Fatalf("unterminated line %q, %v", line, err)
	}
}
