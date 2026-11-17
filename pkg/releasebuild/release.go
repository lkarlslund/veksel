// Package releasebuild defines and verifies Veksel standalone release artifacts.
package releasebuild

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	ManifestSchema = 1
	binaryName     = "veksel"
)

// Variant is one supported compile-time protocol feature set.
type Variant struct {
	Name      string   `json:"name"`
	BuildTags []string `json:"build_tags"`
	Features  []string `json:"features"`
}

// Target is one directly cross-compiled Go platform.
type Target struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

// MatrixEntry combines a target with a feature variant.
type MatrixEntry struct {
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
	Variant string `json:"variant"`
}

// Matrix is the JSON shape consumed by GitHub Actions strategy.matrix.
type Matrix struct {
	Include []MatrixEntry `json:"include"`
}

var variants = []Variant{
	{Name: "full", Features: []string{"Exchange ActiveSync (EAS)", "Exchange Web Services (EWS)"}},
	{Name: "noeas", BuildTags: []string{"noeas"}, Features: []string{"Exchange Web Services (EWS)"}},
	{Name: "noews", BuildTags: []string{"noews"}, Features: []string{"Exchange ActiveSync (EAS)"}},
	{Name: "noexchange", BuildTags: []string{"noeas", "noews"}, Features: []string{}},
}

var targets = []Target{
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
	{GOOS: "freebsd", GOARCH: "amd64"},
	{GOOS: "freebsd", GOARCH: "arm64"},
	{GOOS: "openbsd", GOARCH: "amd64"},
	{GOOS: "openbsd", GOARCH: "arm64"},
	{GOOS: "netbsd", GOARCH: "amd64"},
	{GOOS: "netbsd", GOARCH: "arm64"},
	{GOOS: "windows", GOARCH: "amd64"},
	{GOOS: "windows", GOARCH: "arm64"},
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
}

// Variants returns a defensive copy of the supported feature variants.
func Variants() []Variant {
	result := make([]Variant, len(variants))
	for index, variant := range variants {
		result[index] = Variant{Name: variant.Name, BuildTags: slices.Clone(variant.BuildTags), Features: slices.Clone(variant.Features)}
	}
	return result
}

// Targets returns a defensive copy of the supported release platforms.
func Targets() []Target { return slices.Clone(targets) }

// VariantByName resolves one canonical feature variant.
func VariantByName(name string) (Variant, error) {
	for _, variant := range variants {
		if variant.Name == name {
			return Variant{Name: variant.Name, BuildTags: slices.Clone(variant.BuildTags), Features: slices.Clone(variant.Features)}, nil
		}
	}
	return Variant{}, fmt.Errorf("unknown release variant %q", name)
}

// SupportsTarget reports whether a platform belongs to the release contract.
func SupportsTarget(goos, goarch string) bool {
	return slices.Contains(targets, Target{GOOS: goos, GOARCH: goarch})
}

// ReleaseMatrix returns every supported platform and feature combination.
func ReleaseMatrix() Matrix {
	entries := make([]MatrixEntry, 0, len(targets)*len(variants))
	for _, target := range targets {
		for _, variant := range variants {
			entries = append(entries, MatrixEntry{GOOS: target.GOOS, GOARCH: target.GOARCH, Variant: variant.Name})
		}
	}
	return Matrix{Include: entries}
}

// CIMatrix covers every release OS and every feature gate without rebuilding
// the entire release matrix on each pull request.
func CIMatrix() Matrix {
	entries := []MatrixEntry{
		{GOOS: "linux", GOARCH: "amd64", Variant: "full"},
		{GOOS: "linux", GOARCH: "arm64", Variant: "full"},
		{GOOS: "freebsd", GOARCH: "amd64", Variant: "full"},
		{GOOS: "openbsd", GOARCH: "amd64", Variant: "full"},
		{GOOS: "netbsd", GOARCH: "amd64", Variant: "full"},
		{GOOS: "windows", GOARCH: "amd64", Variant: "full"},
		{GOOS: "darwin", GOARCH: "amd64", Variant: "full"},
	}
	for _, name := range []string{"noeas", "noews", "noexchange"} {
		entries = append(entries, MatrixEntry{GOOS: "linux", GOARCH: "amd64", Variant: name})
	}
	return Matrix{Include: entries}
}

// BuildRelevantPath reports whether changing path can affect tests, compiled
// binaries, release artifacts, or the workflows that verify them. Documentation
// and developer-only supporting material intentionally do not trigger a
// scheduled release build.
func BuildRelevantPath(path string) bool {
	path = strings.TrimPrefix(strings.TrimSpace(path), "./")
	if path == "go.mod" || path == "go.sum" || path == "Makefile" {
		return true
	}
	for _, prefix := range []string{"cmd/", "pkg/", "compatibility/", "scripts/", ".github/workflows/", ".github/actions/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// HasBuildRelevantChanges classifies a git name-only diff.
func HasBuildRelevantChanges(paths []string) bool {
	for _, path := range paths {
		if BuildRelevantPath(path) {
			return true
		}
	}
	return false
}

var releaseTagPattern = regexp.MustCompile(`^r([0-9]{4,})$`)
var goVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?$`)

// TagRef describes one existing release tag and its annotation subject.
type TagRef struct {
	Name    string
	Subject string
}

// NextTag reuses the tag allocated to a rerun, or returns the next monotonic
// rNNNN tag. Non-release tags are ignored.
func NextTag(refs []TagRef, runID string) (tag string, reused bool, err error) {
	runID = strings.TrimSpace(runID)
	if runID == "" || strings.ContainsAny(runID, "\r\n\t") {
		return "", false, errors.New("workflow run ID is required")
	}
	maximum := uint64(0)
	for _, ref := range refs {
		match := releaseTagPattern.FindStringSubmatch(strings.TrimSpace(ref.Name))
		if match == nil {
			continue
		}
		value, parseErr := strconv.ParseUint(match[1], 10, 64)
		if parseErr != nil {
			return "", false, fmt.Errorf("parse release tag %q: %w", ref.Name, parseErr)
		}
		maximum = max(maximum, value)
		metadata := parseTagMetadata(ref.Subject)
		if metadata["veksel-run-id"] == runID {
			return ref.Name, true, nil
		}
	}
	if maximum == ^uint64(0) {
		return "", false, errors.New("release tag sequence is exhausted")
	}
	return fmt.Sprintf("r%04d", maximum+1), false, nil
}

// TagSubject creates the stable annotation used to recognize workflow reruns
// and pin their exact Go toolchain.
func TagSubject(tag, runID, goVersion string) (string, error) {
	if err := ValidateTag(tag); err != nil {
		return "", err
	}
	if strings.TrimSpace(runID) == "" || strings.ContainsAny(runID, "\r\n\t;=") {
		return "", errors.New("valid workflow run ID is required")
	}
	goVersion = strings.TrimPrefix(strings.TrimSpace(goVersion), "go")
	if !goVersionPattern.MatchString(goVersion) {
		return "", fmt.Errorf("invalid Go version %q", goVersion)
	}
	return fmt.Sprintf("Veksel %s; veksel-run-id=%s; veksel-go=%s", tag, runID, goVersion), nil
}

// TagGoVersion reads and validates the pinned Go version from an annotation.
func TagGoVersion(subject, runID string) (string, error) {
	metadata := parseTagMetadata(subject)
	if metadata["veksel-run-id"] != runID {
		return "", errors.New("tag annotation belongs to a different workflow run")
	}
	goVersion := metadata["veksel-go"]
	if !goVersionPattern.MatchString(goVersion) {
		return "", errors.New("tag annotation has no valid Go version")
	}
	return goVersion, nil
}

func parseTagMetadata(subject string) map[string]string {
	result := make(map[string]string)
	for _, field := range strings.Split(subject, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && key != "" {
			result[key] = value
		}
	}
	return result
}

// ValidateTag requires the canonical monotonic release-tag format.
func ValidateTag(tag string) error {
	if !releaseTagPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q; expected rNNNN", tag)
	}
	return nil
}

// ArtifactName returns the platform- and feature-explicit archive name.
func ArtifactName(tag, goos, goarch, variant string) (string, error) {
	if err := ValidateTag(tag); err != nil {
		return "", err
	}
	if !SupportsTarget(goos, goarch) {
		return "", fmt.Errorf("unsupported release target %s/%s", goos, goarch)
	}
	if _, err := VariantByName(variant); err != nil {
		return "", err
	}
	extension := ".tar.gz"
	if goos == "windows" {
		extension = ".zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s_%s%s", binaryName, tag, goos, goarch, variant, extension), nil
}

// ValidateMatrix rejects omissions, duplicates, and unknown combinations.
func ValidateMatrix(matrix Matrix, complete bool) error {
	seen := make(map[MatrixEntry]struct{}, len(matrix.Include))
	for _, entry := range matrix.Include {
		if !SupportsTarget(entry.GOOS, entry.GOARCH) {
			return fmt.Errorf("matrix contains unsupported target %s/%s", entry.GOOS, entry.GOARCH)
		}
		if _, err := VariantByName(entry.Variant); err != nil {
			return err
		}
		if _, duplicate := seen[entry]; duplicate {
			return fmt.Errorf("matrix contains duplicate %+v", entry)
		}
		seen[entry] = struct{}{}
	}
	if complete {
		want := ReleaseMatrix().Include
		if len(seen) != len(want) {
			return fmt.Errorf("release matrix has %d entries, want %d", len(seen), len(want))
		}
		for _, entry := range want {
			if _, ok := seen[entry]; !ok {
				return fmt.Errorf("release matrix omits %+v", entry)
			}
		}
	}
	return nil
}
