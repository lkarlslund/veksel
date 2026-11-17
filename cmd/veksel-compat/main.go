// Command veksel-compat validates and executes Veksel client-compatibility evidence.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/lkarlslund/veksel/pkg/compatibility"
)

const defaultMatrixPath = "compatibility/matrix.toml"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "veksel-compat:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("command is required: check, report, verify, or thunderbird")
	}
	switch arguments[0] {
	case "check":
		matrix, _, err := loadMatrix(arguments[1:], "check")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "compatibility matrix valid: %d scenarios, %d retained results\n", len(matrix.Scenarios), len(matrix.Results))
		return err
	case "report":
		matrix, _, err := loadMatrix(arguments[1:], "report")
		if err != nil {
			return err
		}
		return matrix.Markdown(output)
	case "verify":
		matrix, path, err := loadMatrix(arguments[1:], "verify")
		if err != nil {
			return err
		}
		root, err := repositoryRoot(path)
		if err != nil {
			return err
		}
		results, err := matrix.Verify(ctx, root)
		retained := make(map[string]compatibility.Result, len(matrix.Results))
		for _, result := range matrix.Results {
			retained[result.ScenarioID] = result
		}
		for _, result := range results {
			status := "PASS"
			if !result.Passed {
				status = "FAIL"
			}
			evidence := retained[result.ScenarioID]
			if _, writeErr := fmt.Fprintf(output, "PROBE %s %s retained=%s evidence=%s\n", status, result.ScenarioID, evidence.Status, evidence.Evidence); writeErr != nil {
				return writeErr
			}
			if !result.Passed && result.Output != "" {
				if _, writeErr := fmt.Fprintln(output, result.Output); writeErr != nil {
					return writeErr
				}
			}
		}
		return err
	case "thunderbird":
		flags := flag.NewFlagSet("thunderbird", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		binary := flags.String("binary", "", "path to the Thunderbird executable")
		version := flags.String("version", "", "exact expected Thunderbird version")
		timeout := flags.Duration("timeout", 90*time.Second, "maximum workflow duration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("thunderbird accepts no positional arguments")
		}
		result, err := compatibility.RunThunderbirdProbe(ctx, compatibility.ThunderbirdProbeOptions{
			Binary: *binary, ExpectedVersion: *version, Timeout: *timeout,
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func loadMatrix(arguments []string, command string) (compatibility.Matrix, string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("matrix", defaultMatrixPath, "compatibility matrix path")
	if err := flags.Parse(arguments); err != nil {
		return compatibility.Matrix{}, "", err
	}
	if flags.NArg() != 0 {
		return compatibility.Matrix{}, "", fmt.Errorf("%s accepts no positional arguments", command)
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return compatibility.Matrix{}, "", fmt.Errorf("read matrix: %w", err)
	}
	matrix, err := compatibility.Load(data)
	if err != nil {
		return compatibility.Matrix{}, "", err
	}
	return matrix, *path, nil
}

func repositoryRoot(matrixPath string) (string, error) {
	absolute, err := filepath.Abs(matrixPath)
	if err != nil {
		return "", err
	}
	directory := filepath.Dir(absolute)
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("could not find repository root above matrix")
		}
		directory = parent
	}
}
