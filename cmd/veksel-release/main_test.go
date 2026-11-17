package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/releasebuild"
)

func TestRunMatrix(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"matrix", "--profile", "ci"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	var matrix releasebuild.Matrix
	if err := json.Unmarshal(output.Bytes(), &matrix); err != nil {
		t.Fatal(err)
	}
	if err := releasebuild.ValidateMatrix(matrix, false); err != nil {
		t.Fatal(err)
	}
}

func TestRunAllocate(t *testing.T) {
	input := strings.NewReader("r0001\tVeksel r0001; veksel-run-id=100\nr0009\tVeksel r0009; veksel-run-id=101\n")
	var output bytes.Buffer
	if err := run(context.Background(), []string{"allocate", "--run-id", "102"}, input, &output); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "r0010\n" {
		t.Fatalf("allocation = %q", got)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run(context.Background(), []string{"unknown"}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command succeeded")
	}
}
