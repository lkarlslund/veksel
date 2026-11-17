package mtasts

import "testing"

// FuzzPolicy feeds fetched MTA-STS policy bodies and TXT records into their
// parsers.
func FuzzPolicy(f *testing.F) {
	for _, seed := range []string{
		"version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n",
		"version: STSv1\nmode: testing\nmx: a\nmax_age: 86400\n",
		"version: STSv1\nmode: none\nmax_age: 0",
		"version: STSv1\r\nmode: enforce\rmx: x\r\n",
		"v=STSv1; id=20240101T000000;",
		"", ":", "\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ParsePolicy([]byte(input))
		_, _ = parsePolicyID(input)
	})
}
