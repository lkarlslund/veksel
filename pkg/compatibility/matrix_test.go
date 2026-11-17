package compatibility

import (
	"bytes"
	"strings"
	"testing"
)

const validMatrix = `
schema = 1

[[scenarios]]
id = "client-mail"
client = "Client"
version = "1.2.3"
platform = "Linux"
workflow = "mail core"
owner = "protocols"
protocols = ["imap", "smtp-submission"]
source_url = "https://example.test/releases/1.2.3"
required = true

[scenarios.runner]
kind = "go-test"
package = "./pkg/imap"
test_regex = "^TestIntegration_Login$"

[[results]]
scenario_id = "client-mail"
status = "limited"
evidence = "modeled-transcript"
client_version = "1.2.3"
platform = "Linux"
tested_at = "2026-08-19"
tested_revision = "abc1234"
assertions = ["login succeeds"]
limitations = ["the real application was not executed"]
`

func TestLoadAndRender(t *testing.T) {
	matrix, err := Load([]byte(validMatrix))
	if err != nil {
		t.Fatal(err)
	}
	var report bytes.Buffer
	if err := matrix.Markdown(&report); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Client compatibility matrix", "limited", "modeled-transcript", "the real application was not executed"} {
		if !strings.Contains(report.String(), text) {
			t.Fatalf("report omitted %q:\n%s", text, report.String())
		}
	}
}

func TestValidateRejectsMisleadingOrIncompleteEvidence(t *testing.T) {
	if _, err := Load([]byte(strings.Replace(validMatrix, "schema = 1", "schema = 1\nextra = true", 1))); err == nil {
		t.Fatal("unknown TOML field was accepted")
	}
	base, err := Load([]byte(validMatrix))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Matrix)
		want   string
	}{
		{name: "duplicate scenario", mutate: func(matrix *Matrix) { matrix.Scenarios = append(matrix.Scenarios, matrix.Scenarios[0]) }, want: "duplicate scenario"},
		{name: "pending claims evidence", mutate: func(matrix *Matrix) { matrix.Results[0].Status = StatusPending }, want: "pending result cannot claim"},
		{name: "limited without limitation", mutate: func(matrix *Matrix) { matrix.Results[0].Limitations = nil }, want: "limited result requires"},
		{name: "real version mismatch", mutate: func(matrix *Matrix) {
			matrix.Results[0].Evidence = EvidenceRealClient
			matrix.Results[0].ClientVersion = "other"
		}, want: "real-client version"},
		{name: "real client with modeled runner", mutate: func(matrix *Matrix) {
			matrix.Results[0].Evidence = EvidenceRealClient
		}, want: "modeled go-test runner"},
		{name: "external runner with go-test fields", mutate: func(matrix *Matrix) {
			matrix.Scenarios[0].Runner = Runner{Kind: "external", Package: "./pkg/imap"}
		}, want: "external runner does not accept"},
		{name: "unknown protocol", mutate: func(matrix *Matrix) { matrix.Scenarios[0].Protocols[0] = "mapi" }, want: "unknown protocol"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matrix := base
			matrix.Scenarios = append([]Scenario(nil), base.Scenarios...)
			matrix.Scenarios[0].Protocols = append([]string(nil), base.Scenarios[0].Protocols...)
			matrix.Results = append([]Result(nil), base.Results...)
			test.mutate(&matrix)
			err := matrix.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestExternalRunnerRealClientEvidenceIsValidAndNotExecuted(t *testing.T) {
	matrix, err := Load([]byte(validMatrix))
	if err != nil {
		t.Fatal(err)
	}
	matrix.Scenarios[0].Runner = Runner{Kind: "external"}
	matrix.Results[0].Evidence = EvidenceRealClient
	if err := matrix.Validate(); err != nil {
		t.Fatalf("external real-client evidence rejected: %v", err)
	}
	verifications, err := matrix.Verify(t.Context(), t.TempDir())
	if err != nil || len(verifications) != 0 {
		t.Fatalf("verify must skip external runners, got %v, %v", verifications, err)
	}
}
