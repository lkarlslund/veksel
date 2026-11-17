package releasebuild

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCIWorkflowRunsOneBoundedFastTestWithoutBuilds(t *testing.T) {
	workflow := readWorkflow(t, "ci.yml")
	for _, required := range []string{
		"pull_request:",
		"workflow_dispatch:",
		"fast-test:",
		"name: Format and fast unit tests",
		"timeout-minutes: 10",
		"./scripts/check-gofmt \"$BASE_SHA\" HEAD",
		"./scripts/test-unit",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("CI workflow does not contain %q", required)
		}
	}
	if got := strings.Count(workflow, "runs-on: ubuntu-latest"); got != 1 {
		t.Errorf("CI runner jobs = %d, want 1", got)
	}
	for _, forbidden := range []string{
		"\n  push:",
		"cross-build:",
		"build-matrix",
		"build_profile",
		"go vet ./...",
		"strategy:",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("CI workflow unexpectedly contains %q", forbidden)
		}
	}
}

func TestReleaseWorkflowGatesAndConsolidatesCompleteMatrix(t *testing.T) {
	workflow := readWorkflow(t, "release.yml")
	for _, required := range []string{
		"Compare with latest published release",
		"releases/latest",
		"should_run=false",
		"Scheduled release stopped before allocation and matrix build.",
		"prepare-validation:",
		"prepare-release:",
		"Build complete release matrix on one runner",
		"Run complete test suite",
		"go test ./...",
		"--profile release",
		"Assemble and verify without publishing",
		"name: release-parts",
		"Verify and publish GitHub release",
		"needs.build.result == 'success'",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow does not contain %q", required)
		}
	}
	if strings.Contains(workflow, "strategy:") {
		t.Error("release workflow still fans out a strategy matrix")
	}
	if got := strings.Count(workflow, "go run ./cmd/veksel-release build-matrix"); got != 1 {
		t.Errorf("release consolidated matrix invocations = %d, want 1", got)
	}
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
