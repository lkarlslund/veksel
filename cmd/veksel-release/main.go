// Command veksel-release builds and verifies standalone Veksel release assets.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/releasebuild"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "veksel-release:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, input io.Reader, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("command is required: matrix, changes, allocate, tag-subject, tag-go-version, build-one, build-matrix, assemble, verify-assets, or verify-checksums")
	}
	switch arguments[0] {
	case "matrix":
		return matrixCommand(arguments[1:], output)
	case "changes":
		return changesCommand(arguments[1:], input, output)
	case "allocate":
		return allocateCommand(arguments[1:], input, output)
	case "tag-subject":
		return tagSubjectCommand(arguments[1:], output)
	case "tag-go-version":
		return tagGoVersionCommand(arguments[1:], input, output)
	case "build-one":
		return buildCommand(ctx, arguments[1:], output)
	case "build-matrix":
		return buildMatrixCommand(ctx, arguments[1:], output)
	case "assemble":
		return assembleCommand(arguments[1:], output)
	case "verify-assets":
		return verifyAssetsCommand(arguments[1:])
	case "verify-checksums":
		return verifyChecksumsCommand(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func tagSubjectCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("tag-subject", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tag := flags.String("tag", "", "release tag")
	runID := flags.String("run-id", "", "workflow run ID")
	goVersion := flags.String("go-version", "", "exact Go version")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("tag-subject accepts no positional arguments")
	}
	subject, err := releasebuild.TagSubject(*tag, *runID, *goVersion)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, subject)
	return err
}

func tagGoVersionCommand(arguments []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("tag-go-version", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runID := flags.String("run-id", "", "workflow run ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("tag-go-version accepts the annotation subject on stdin only")
	}
	subject, err := io.ReadAll(io.LimitReader(input, 4096))
	if err != nil {
		return err
	}
	goVersion, err := releasebuild.TagGoVersion(strings.TrimSpace(string(subject)), *runID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, goVersion)
	return err
}

func matrixCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("matrix", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "release", "release or ci")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("matrix accepts no positional arguments")
	}
	matrix, _, err := matrixForProfile(*profile)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(matrix)
}

func changesCommand(arguments []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("changes", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("changes accepts newline-delimited paths on stdin only")
	}
	var paths []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		paths = append(paths, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, releasebuild.HasBuildRelevantChanges(paths))
	return err
}

func matrixForProfile(profile string) (releasebuild.Matrix, bool, error) {
	switch profile {
	case "release":
		matrix := releasebuild.ReleaseMatrix()
		return matrix, true, releasebuild.ValidateMatrix(matrix, true)
	case "ci":
		matrix := releasebuild.CIMatrix()
		return matrix, false, releasebuild.ValidateMatrix(matrix, false)
	default:
		return releasebuild.Matrix{}, false, fmt.Errorf("unknown matrix profile %q", profile)
	}
}

func allocateCommand(arguments []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("allocate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runID := flags.String("run-id", "", "GitHub workflow run ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("allocate accepts tag records on stdin only")
	}
	var refs []releasebuild.TagRef
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		name, subject, _ := strings.Cut(scanner.Text(), "\t")
		refs = append(refs, releasebuild.TagRef{Name: name, Subject: subject})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	tag, _, err := releasebuild.NextTag(refs, *runID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, tag)
	return err
}

func buildCommand(ctx context.Context, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("build-one", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	out := flags.String("out", "", "artifact output directory")
	tag := flags.String("tag", "", "release tag")
	commit := flags.String("commit", "", "full source commit")
	builtAt := flags.String("built-at", "", "UTC RFC3339 build time")
	runID := flags.String("run-id", "", "workflow run ID")
	goos := flags.String("goos", "", "target operating system")
	goarch := flags.String("goarch", "", "target architecture")
	variant := flags.String("variant", "", "feature variant")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("build-one accepts no positional arguments")
	}
	timestamp, err := time.Parse(time.RFC3339, *builtAt)
	if err != nil {
		return fmt.Errorf("parse build time: %w", err)
	}
	timestamp = timestamp.UTC()
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	fragment, err := releasebuild.BuildOne(ctx, releasebuild.BuildOptions{
		Root: absoluteRoot, OutputDir: absoluteOutput, Tag: *tag, Commit: *commit,
		BuiltAt: timestamp, WorkflowRunID: *runID, GOOS: *goos, GOARCH: *goarch, Variant: *variant,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, fragment.Artifact.Name)
	return err
}

func buildMatrixCommand(ctx context.Context, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("build-matrix", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	out := flags.String("out", "", "artifact output directory")
	tag := flags.String("tag", "", "release tag")
	commit := flags.String("commit", "", "full source commit")
	builtAt := flags.String("built-at", "", "UTC RFC3339 build time")
	runID := flags.String("run-id", "", "workflow run ID")
	profile := flags.String("profile", "ci", "ci or release")
	parallel := flags.Int("parallel", 4, "maximum simultaneous builds")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("build-matrix accepts no positional arguments")
	}
	timestamp, err := time.Parse(time.RFC3339, *builtAt)
	if err != nil {
		return fmt.Errorf("parse build time: %w", err)
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	matrix, _, err := matrixForProfile(*profile)
	if err != nil {
		return err
	}
	fragments, err := releasebuild.BuildMatrix(ctx, matrix, releasebuild.BuildOptions{
		Root: absoluteRoot, OutputDir: absoluteOutput, Tag: *tag, Commit: *commit,
		BuiltAt: timestamp.UTC(), WorkflowRunID: *runID,
	}, *parallel)
	if err != nil {
		return err
	}
	for _, fragment := range fragments {
		if _, err := fmt.Fprintln(output, fragment.Artifact.Name); err != nil {
			return err
		}
	}
	return nil
}

func assembleCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("assemble", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "downloaded artifact-parts directory")
	out := flags.String("out", "", "public release-assets directory")
	notes := flags.String("notes", "", "generated release notes path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *out == "" || *notes == "" || flags.NArg() != 0 {
		return errors.New("assemble requires --input, --out, and --notes")
	}
	manifest, err := releasebuild.Assemble(*input, *out)
	if err != nil {
		return err
	}
	if err := releasebuild.ValidateChecksums(*out); err != nil {
		return err
	}
	if err := releasebuild.WriteReleaseNotes(*notes, manifest); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "%s: %d verified artifacts\n", manifest.Tag, len(manifest.Artifacts))
	return err
}

func verifyAssetsCommand(arguments []string) error {
	flags := flag.NewFlagSet("verify-assets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	expected := flags.String("expected", "", "expected asset directory")
	actual := flags.String("actual", "", "downloaded release asset directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *expected == "" || *actual == "" || flags.NArg() != 0 {
		return errors.New("verify-assets requires --expected and --actual")
	}
	return releasebuild.VerifyAssets(*expected, *actual)
}

func verifyChecksumsCommand(arguments []string) error {
	flags := flag.NewFlagSet("verify-checksums", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("dir", "", "release asset directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directory == "" || flags.NArg() != 0 {
		return errors.New("verify-checksums requires --dir")
	}
	return releasebuild.ValidateChecksums(*directory)
}
