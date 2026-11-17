package tlsrpt

import (
	"strings"
	"testing"
)

// FuzzReportingPolicy feeds TLS-RPT TXT answers into the policy parser.
func FuzzReportingPolicy(f *testing.F) {
	for _, seed := range []string{
		"v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.com/v1",
		"v=TLSRPTv1;rua=mailto:a@b.c;ext=1",
		"v=TLSRPTv1; rua=ftp://x\nv=TLSRPTv1; rua=mailto:a@b",
		"v=TLSRPTv1;", "", "\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _, _ = ParseReportingPolicy("example.com", strings.Split(input, "\n"))
	})
}
