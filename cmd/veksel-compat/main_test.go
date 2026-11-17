package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAndReportRepositoryMatrix(t *testing.T) {
	root, err := repositoryRoot(filepath.Join("..", "..", defaultMatrixPath))
	if err != nil {
		t.Fatal(err)
	}
	matrixPath := filepath.Join(root, defaultMatrixPath)
	var check bytes.Buffer
	if err := run(context.Background(), []string{"check", "--matrix", matrixPath}, &check); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(check.String(), "scenarios") {
		t.Fatalf("check output = %q", check.String())
	}
	var report bytes.Buffer
	if err := run(context.Background(), []string{"report", "--matrix", matrixPath}, &report); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(root, "docs", "compatibility.md"))
	if err != nil {
		t.Fatal(err)
	}
	if report.String() != string(want) {
		t.Fatal("generated compatibility report differs from docs/compatibility.md")
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run(context.Background(), []string{"unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command succeeded")
	}
}
