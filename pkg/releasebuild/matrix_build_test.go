package releasebuild

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBuildMatrixBoundsConcurrencyAndRetainsOrder(t *testing.T) {
	matrix := CIMatrix()
	var active atomic.Int32
	var maximum atomic.Int32
	block := make(chan struct{})
	started := make(chan struct{}, len(matrix.Include))
	var releaseOnce sync.Once
	build := func(_ context.Context, options BuildOptions) (Fragment, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {
		}
		started <- struct{}{}
		if current == 3 {
			releaseOnce.Do(func() { close(block) })
		}
		<-block
		return Fragment{Artifact: Artifact{GOOS: options.GOOS, GOARCH: options.GOARCH, Variant: options.Variant}}, nil
	}
	results, err := buildMatrix(context.Background(), matrix, BuildOptions{}, 3, build)
	if err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 3 {
		t.Fatalf("maximum parallel builds = %d, want 3", maximum.Load())
	}
	if len(started) != len(matrix.Include) {
		t.Fatalf("started builds = %d, want %d", len(started), len(matrix.Include))
	}
	for index, entry := range matrix.Include {
		artifact := results[index].Artifact
		if artifact.GOOS != entry.GOOS || artifact.GOARCH != entry.GOARCH || artifact.Variant != entry.Variant {
			t.Fatalf("result %d = %#v, want %#v", index, artifact, entry)
		}
	}
}

func TestBuildMatrixCancelsAfterFailure(t *testing.T) {
	want := errors.New("compile failed")
	_, err := buildMatrix(context.Background(), CIMatrix(), BuildOptions{}, 1, func(_ context.Context, _ BuildOptions) (Fragment, error) {
		return Fragment{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("BuildMatrix error = %v, want %v", err, want)
	}
}

func TestBuildRelevantPaths(t *testing.T) {
	for _, path := range []string{"go.mod", "cmd/veksel/main.go", "pkg/static/css/app.css", "compatibility/matrix.toml", "scripts/check-gofmt", ".github/workflows/ci.yml"} {
		if !BuildRelevantPath(path) {
			t.Errorf("BuildRelevantPath(%q) = false", path)
		}
	}
	for _, path := range []string{"README.md", "docs/releases.md", "research/products/matrix.md", "AGENTS.md", ".gitignore", "e2e/inspect.mjs"} {
		if BuildRelevantPath(path) {
			t.Errorf("BuildRelevantPath(%q) = true", path)
		}
	}
	if HasBuildRelevantChanges([]string{"README.md", "docs/releases.md"}) {
		t.Fatal("documentation-only diff requires a build")
	}
	if !HasBuildRelevantChanges([]string{"docs/releases.md", "pkg/model/model.go"}) {
		t.Fatal("source diff does not require a build")
	}
}
