package virus

import (
	"bytes"
	"strings"
)

// EICARTestString is the standard antivirus test string defined by EICAR.
// Any compliant antivirus should detect this string as a test virus.
// See: https://www.eicar.org/standards/eicar_test_file/
const EICARTestString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

// BuiltinScanner detects the EICAR test file, so operators can confirm that
// scanning and its policy work end to end. It is not a malware scanner: file
// types that commonly carry malware are scored by the spam engine's MIME-aware
// attachment checks (ATTACH_DANGEROUS_EXT, ATTACH_MACRO), and real signature
// scanning comes from ClamAV.
type BuiltinScanner struct{}

// NewBuiltinScanner creates a new built-in signature scanner.
func NewBuiltinScanner() *BuiltinScanner {
	return &BuiltinScanner{}
}

// Scan checks the data for known virus signatures.
func (s *BuiltinScanner) Scan(data []byte) (name string, infected bool, err error) {
	// Check for EICAR test string
	if s.checkEICAR(data) {
		return "EICAR-AV-Test", true, nil
	}

	return "", false, nil
}

// Name returns "builtin" as the scanner identifier.
func (s *BuiltinScanner) Name() string {
	return "builtin"
}

// checkEICAR scans for the EICAR test string in various encodings.
func (s *BuiltinScanner) checkEICAR(data []byte) bool {
	// Direct byte match
	if bytes.Contains(data, []byte(EICARTestString)) {
		return true
	}

	// URL-encoded variant
	urlEncoded := "X5O%21P%25%40AP%5B4%5CPZX54%28P%5E%297CC%297%7D%24EICAR-STANDARD-ANTIVIRUS-TEST-FILE%21%24H%2BH%2A"
	if bytes.Contains(data, []byte(urlEncoded)) {
		return true
	}

	// Base64-encoded variant (check for the decoded content)
	// The EICAR string base64-encoded is:
	// TDVPIVBAMEFQW1wvUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFO
	// UVJJVVNULVRFU1QtRklMRTohJEgrSio=
	// We check for the key parts that would appear in base64
	eicarB64 := "TDVPIVBAMEFQW1wvUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFO"
	if bytes.Contains(data, []byte(eicarB64)) {
		return true
	}

	// Check for case-insensitive match (some clients may alter case)
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "eicar-standard-antivirus-test-file")
}
