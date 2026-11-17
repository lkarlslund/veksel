// Package compatibility owns Veksel' retained client-interoperability evidence.
package compatibility

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const SchemaVersion = 1

var scenarioIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type EvidenceKind string

const (
	EvidenceRealClient        EvidenceKind = "real-client"
	EvidenceProtocolLibrary   EvidenceKind = "protocol-library"
	EvidenceModeledTranscript EvidenceKind = "modeled-transcript"
	EvidenceManual            EvidenceKind = "manual"
)

type Status string

const (
	StatusPass    Status = "pass"
	StatusLimited Status = "limited"
	StatusFail    Status = "fail"
	StatusPending Status = "pending"
)

type Matrix struct {
	Schema    int        `toml:"schema"`
	Scenarios []Scenario `toml:"scenarios"`
	Results   []Result   `toml:"results"`
}

type Scenario struct {
	ID        string   `toml:"id"`
	Client    string   `toml:"client"`
	Version   string   `toml:"version"`
	Platform  string   `toml:"platform"`
	Workflow  string   `toml:"workflow"`
	Owner     string   `toml:"owner"`
	Protocols []string `toml:"protocols"`
	SourceURL string   `toml:"source_url"`
	Required  bool     `toml:"required"`
	Runner    Runner   `toml:"runner"`
}

type Runner struct {
	Kind      string `toml:"kind"`
	Package   string `toml:"package"`
	TestRegex string `toml:"test_regex"`
}

type Result struct {
	ScenarioID     string       `toml:"scenario_id"`
	Status         Status       `toml:"status"`
	Evidence       EvidenceKind `toml:"evidence"`
	ClientVersion  string       `toml:"client_version"`
	Platform       string       `toml:"platform"`
	TestedAt       string       `toml:"tested_at"`
	TestedRevision string       `toml:"tested_revision"`
	Assertions     []string     `toml:"assertions"`
	Limitations    []string     `toml:"limitations"`
}

func Load(data []byte) (Matrix, error) {
	var matrix Matrix
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&matrix); err != nil {
		return Matrix{}, fmt.Errorf("decode compatibility matrix: %w", err)
	}
	if err := matrix.Validate(); err != nil {
		return Matrix{}, err
	}
	return matrix, nil
}

func (m Matrix) Validate() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("schema = %d, want %d", m.Schema, SchemaVersion)
	}
	if len(m.Scenarios) == 0 {
		return errors.New("at least one compatibility scenario is required")
	}
	knownProtocols := map[string]bool{
		"autodiscover": true, "imap": true, "smtp-submission": true, "pop3": true,
		"caldav": true, "carddav": true, "webdav": true, "jmap": true,
		"ews": true, "eas": true,
	}
	scenarios := make(map[string]Scenario, len(m.Scenarios))
	for index, scenario := range m.Scenarios {
		label := fmt.Sprintf("scenarios[%d]", index)
		if !scenarioIDPattern.MatchString(scenario.ID) {
			return fmt.Errorf("%s.id %q is not a lowercase slug", label, scenario.ID)
		}
		if _, duplicate := scenarios[scenario.ID]; duplicate {
			return fmt.Errorf("duplicate scenario %q", scenario.ID)
		}
		if strings.TrimSpace(scenario.Client) == "" || strings.TrimSpace(scenario.Version) == "" || strings.TrimSpace(scenario.Platform) == "" || strings.TrimSpace(scenario.Workflow) == "" || strings.TrimSpace(scenario.Owner) == "" {
			return fmt.Errorf("%s requires client, version, platform, workflow, and owner", label)
		}
		if len(scenario.Protocols) == 0 {
			return fmt.Errorf("%s requires at least one protocol", label)
		}
		for _, protocol := range scenario.Protocols {
			if !knownProtocols[protocol] {
				return fmt.Errorf("%s has unknown protocol %q", label, protocol)
			}
		}
		if scenario.SourceURL == "" {
			return fmt.Errorf("%s requires an authoritative version source", label)
		}
		if err := scenario.Runner.validate(label); err != nil {
			return err
		}
		scenarios[scenario.ID] = scenario
	}

	results := make(map[string]struct{}, len(m.Results))
	for index, result := range m.Results {
		label := fmt.Sprintf("results[%d]", index)
		scenario, exists := scenarios[result.ScenarioID]
		if !exists {
			return fmt.Errorf("%s references unknown scenario %q", label, result.ScenarioID)
		}
		if _, duplicate := results[result.ScenarioID]; duplicate {
			return fmt.Errorf("duplicate result for scenario %q", result.ScenarioID)
		}
		if err := result.validate(label, scenario); err != nil {
			return err
		}
		results[result.ScenarioID] = struct{}{}
	}
	for _, scenario := range m.Scenarios {
		if _, exists := results[scenario.ID]; !exists {
			return fmt.Errorf("scenario %q has no retained result", scenario.ID)
		}
	}
	return nil
}

func (r Runner) validate(label string) error {
	switch r.Kind {
	case "":
		if r.Package != "" || r.TestRegex != "" {
			return fmt.Errorf("%s runner fields require a kind", label)
		}
	case "go-test":
		if !strings.HasPrefix(r.Package, "./pkg/") || r.TestRegex == "" {
			return fmt.Errorf("%s go-test runner requires a ./pkg/ package and test_regex", label)
		}
		if _, err := regexp.Compile(r.TestRegex); err != nil {
			return fmt.Errorf("%s invalid test_regex: %w", label, err)
		}
	case "thunderbird":
		if r.Package != "" || r.TestRegex != "" {
			return fmt.Errorf("%s thunderbird runner does not accept go-test fields", label)
		}
	case "external":
		// A real client driven by an operator-run harness (for example
		// OfflineIMAP, vdirsyncer, or swaks against a disposable instance).
		// Verify never executes it; the retained result records the exact
		// client version, revision, and per-operation outcome.
		if r.Package != "" || r.TestRegex != "" {
			return fmt.Errorf("%s external runner does not accept go-test fields", label)
		}
	default:
		return fmt.Errorf("%s has unsupported runner kind %q", label, r.Kind)
	}
	return nil
}

func (r Result) validate(label string, scenario Scenario) error {
	if !slices.Contains([]Status{StatusPass, StatusLimited, StatusFail, StatusPending}, r.Status) {
		return fmt.Errorf("%s has invalid status %q", label, r.Status)
	}
	if !slices.Contains([]EvidenceKind{EvidenceRealClient, EvidenceProtocolLibrary, EvidenceModeledTranscript, EvidenceManual}, r.Evidence) {
		return fmt.Errorf("%s has invalid evidence %q", label, r.Evidence)
	}
	if r.Status == StatusPending {
		if len(r.Limitations) == 0 {
			return fmt.Errorf("%s pending result requires a limitation", label)
		}
		if r.TestedAt != "" || r.TestedRevision != "" || len(r.Assertions) != 0 {
			return fmt.Errorf("%s pending result cannot claim test evidence", label)
		}
		return nil
	}
	if r.ClientVersion == "" || r.Platform == "" || r.TestedAt == "" || r.TestedRevision == "" || len(r.Assertions) == 0 {
		return fmt.Errorf("%s non-pending result requires exact client version, platform, date, revision, and assertions", label)
	}
	if _, err := time.Parse("2006-01-02", r.TestedAt); err != nil {
		return fmt.Errorf("%s tested_at: %w", label, err)
	}
	if r.Status == StatusLimited && len(r.Limitations) == 0 {
		return fmt.Errorf("%s limited result requires limitations", label)
	}
	if r.Evidence == EvidenceRealClient && r.ClientVersion != scenario.Version {
		return fmt.Errorf("%s real-client version %q does not equal pinned scenario version %q", label, r.ClientVersion, scenario.Version)
	}
	if r.Evidence == EvidenceRealClient && scenario.Runner.Kind == "go-test" {
		return fmt.Errorf("%s real-client evidence cannot use a modeled go-test runner", label)
	}
	if r.Evidence != EvidenceManual && scenario.Runner.Kind == "" {
		return fmt.Errorf("%s automated evidence requires a scenario runner", label)
	}
	return nil
}

type Verification struct {
	ScenarioID string
	Passed     bool
	Output     string
}

// Verify runs every declared automated regression probe. Real-client and
// manual evidence without a hermetic runner remains visible in the report but
// is never silently treated as automated.
func (m Matrix) Verify(ctx context.Context, root string) ([]Verification, error) {
	var verifications []Verification
	for _, scenario := range m.Scenarios {
		if scenario.Runner.Kind != "go-test" {
			continue
		}
		command := exec.CommandContext(ctx, "go", "test", scenario.Runner.Package, "-run", scenario.Runner.TestRegex, "-count=1")
		command.Dir = root
		output, err := command.CombinedOutput()
		verification := Verification{ScenarioID: scenario.ID, Passed: err == nil, Output: strings.TrimSpace(string(output))}
		verifications = append(verifications, verification)
		if err != nil {
			return verifications, fmt.Errorf("verify %s: %w", scenario.ID, err)
		}
	}
	return verifications, nil
}

func (m Matrix) Markdown(output io.Writer) error {
	results := make(map[string]Result, len(m.Results))
	for _, result := range m.Results {
		results[result.ScenarioID] = result
	}
	scenarios := slices.Clone(m.Scenarios)
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].ID < scenarios[j].ID })
	if _, err := fmt.Fprintln(output, "# Client compatibility matrix"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "This report is generated from `compatibility/matrix.toml`. A pass applies only to the named evidence tier; modeled transcripts and protocol libraries are not real-client certification."); err != nil {
		return err
	}
	if _, err := fmt.Fprint(output, "\nRun declared Go probes with `go run ./cmd/veksel-compat verify`."); err != nil {
		return err
	}
	for _, scenario := range m.Scenarios {
		if scenario.Runner.Kind != "thunderbird" {
			continue
		}
		if _, err := fmt.Fprintf(output, " Native application runners are explicit; for example, `go run ./cmd/veksel-compat thunderbird --binary /path/to/thunderbird --version %s` uses an isolated profile, display, account, and store.\n", scenario.Version); err != nil {
			return err
		}
		break
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "| Client | Version / platform | Workflow | Protocols | Result | Evidence | Owner |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "|---|---|---|---|---|---|---|"); err != nil {
		return err
	}
	for _, scenario := range scenarios {
		result := results[scenario.ID]
		version := scenario.Version + " / " + scenario.Platform
		if result.ClientVersion != "" {
			version = result.ClientVersion + " / " + result.Platform
		}
		if _, err := fmt.Fprintf(output, "| %s | %s | %s | %s | %s | %s | %s |\n", escapeCell(scenario.Client), escapeCell(version), escapeCell(scenario.Workflow), strings.Join(scenario.Protocols, ", "), result.Status, result.Evidence, escapeCell(scenario.Owner)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output, "\n## Evidence and limitations"); err != nil {
		return err
	}
	for _, scenario := range scenarios {
		result := results[scenario.ID]
		if _, err := fmt.Fprintf(output, "\n### %s — %s\n\n", scenario.Client, scenario.Workflow); err != nil {
			return err
		}
		if result.TestedAt != "" {
			if _, err := fmt.Fprintf(output, "Tested %s at revision `%s`.\n", result.TestedAt, result.TestedRevision); err != nil {
				return err
			}
		}
		for _, assertion := range result.Assertions {
			if _, err := fmt.Fprintf(output, "- Verified: %s\n", assertion); err != nil {
				return err
			}
		}
		for _, limitation := range result.Limitations {
			if _, err := fmt.Fprintf(output, "- Limitation: %s\n", limitation); err != nil {
				return err
			}
		}
		if scenario.SourceURL != "" {
			if _, err := fmt.Fprintf(output, "- Version source: <%s>\n", scenario.SourceURL); err != nil {
				return err
			}
		}
	}
	return nil
}

func escapeCell(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}
