package imap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// TestDeeplyNestedMIMEStaysLinear guards against MIME nesting that made
// BODYSTRUCTURE, BODY[1.1...] and search extraction re-read the message once
// per level: 4000 levels in 280 KB once took seconds, growing quadratically.
func TestDeeplyNestedMIMEStaysLinear(t *testing.T) {
	const levels = 4000
	var builder strings.Builder
	for level := range levels {
		fmt.Fprintf(&builder, "Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n", level, level)
	}
	builder.WriteString("\r\nx\r\n")
	for level := levels - 1; level >= 0; level-- {
		fmt.Fprintf(&builder, "\r\n--b%d--\r\n", level)
	}
	data := []byte(builder.String())

	start := time.Now()
	structure := bodyStructure(model.Item{Data: data}, true)
	if _, err := bodySection(data, strings.Repeat("1.", levels)+"TEXT"); err == nil {
		t.Fatal("a part path deeper than the MIME depth limit was resolved")
	}
	if _, err := bodySection(data, strings.Repeat("1.", 3)+"TEXT"); err != nil {
		t.Fatalf("shallow part path: %v", err)
	}
	_ = searchableBody(data)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("rendering %d nested parts took %v", levels, elapsed)
	}
	// The opened levels plus the innermost one, shown as an opaque leaf.
	if depth := strings.Count(structure, `"MIXED"`); depth != maxMIMEDepth+1 {
		t.Fatalf("BODYSTRUCTURE opened %d multipart levels, want %d", depth, maxMIMEDepth+1)
	}
}

// TestCommandLineLengthIsBounded checks that an endless client line fails
// once it passes the cap instead of growing in memory.
func TestCommandLineLengthIsBounded(t *testing.T) {
	reader := bufio.NewReader(io.MultiReader(strings.NewReader("A1 NOOP\r\n"), endlessReader{}))
	line, err := appendLineChunk(reader, nil)
	if err != nil || string(line) != "A1 NOOP\r\n" {
		t.Fatalf("first line %q, %v", line, err)
	}
	if _, err := appendLineChunk(reader, nil); !errors.Is(err, errCommandLineTooLong) {
		t.Fatalf("endless line returned %v", err)
	}
}

type endlessReader struct{}

func (endlessReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}
