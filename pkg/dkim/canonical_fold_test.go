package dkim

import (
	"strings"
	"testing"
	"time"
)

// TestSplitMessageManyFoldedLines guards against quadratic header
// unfolding: a field folded over 400k short lines once took minutes.
func TestSplitMessageManyFoldedLines(t *testing.T) {
	message := "Subject: a\r\n" + strings.Repeat(" b\r\n", 400000) + "\r\nbody\r\n"
	start := time.Now()
	fields, body := splitMessage([]byte(message))
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("splitting a 1.6 MB folded header took %v", elapsed)
	}
	if len(fields) != 1 || len(fields[0].raw) != len(message)-len("\r\nbody\r\n") || string(body) != "body\r\n" {
		t.Fatalf("split into %d fields and body %q", len(fields), body)
	}
}
