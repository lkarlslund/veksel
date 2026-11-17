package main

import (
	"bytes"
	"testing"
)

func TestWriteBuildVersion(t *testing.T) {
	oldVersion, oldCommit, oldTime := buildVersion, buildCommit, buildTime
	t.Cleanup(func() { buildVersion, buildCommit, buildTime = oldVersion, oldCommit, oldTime })
	buildVersion, buildCommit, buildTime = "r0042", "0123456789abcdef", "2026-08-18T12:34:56Z"
	var output bytes.Buffer
	writeBuildVersion(&output)
	want := "veksel r0042\ncommit 0123456789abcdef\nbuilt 2026-08-18T12:34:56Z\n"
	if got := output.String(); got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
